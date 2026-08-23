//! Workspace-scoped rolling consumption ledger.
#![allow(dead_code)]
//!
//! Per-run in-memory ledgers draw down from this authenticated journal so an
//! unattended supervise/autopilot loop cannot spend an unbounded amount across
//! individually-within-budget runs. Corruption, a missing MAC chain, or an
//! unknown event kind fail closed. Provider rate-limit reports latch the pool
//! for the remainder of the configured window and do not retry.

use crate::{
    artifacts::{repository_auth_writer, state_auth::AuthenticationDomain},
    llm::ProviderError,
    state_journal::{AuthenticatedStateJournal, JournalRecord, JournalSpec},
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub const BUDGET_LEDGER_ROOT_NAME: &str = "authenticated-budget-ledger-v1";
pub const BUDGET_LEDGER_ROOT_LOCK: &str = ".authenticated-budget-ledger.lock";
pub const DEFAULT_ROLLING_WINDOW_SECONDS: u64 = 24 * 60 * 60;
pub const DEFAULT_RATE_LIMIT_POOL: &str = "workspace";

const LEDGER_FORMAT_VERSION: u32 = 1;
const INSTANCE_ID: &str = "workspace";
const INSTANCE_LOCK_NAME: &str = ".budget-ledger.lock";

enum BudgetLedgerJournalSpec {}

impl JournalSpec for BudgetLedgerJournalSpec {
    const FORMAT_VERSION: u32 = LEDGER_FORMAT_VERSION;
    const NAMESPACE: &'static str = "workspace_rolling_budget";
    const ROOT_NAME: &'static str = BUDGET_LEDGER_ROOT_NAME;
    const ROOT_LOCK_NAME: &'static str = BUDGET_LEDGER_ROOT_LOCK;
    const INSTANCE_LOCK_NAME: &'static str = INSTANCE_LOCK_NAME;
    const HEAD_FILE_NAME: &'static str = ".head.json";
    const RECORD_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0workspace-rolling-budget-record\0v1\0");
    const HEAD_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0workspace-rolling-budget-head\0v1\0");
    const MAX_RECORDS: usize = 4_096;
    const MAX_RECORD_BYTES: u64 = 64 * 1024;
    const MAX_TOTAL_BYTES: u64 = 16 * 1024 * 1024;
    const MAX_PHASE_BYTES: usize = 32;
    const MAX_SUBJECT_BYTES: usize = 128;
    const MAX_INSTANCE_ID_BYTES: usize = 64;
}

type BudgetJournal = AuthenticatedStateJournal<BudgetLedgerJournalSpec>;

thread_local! {
    static BINDING: RefCell<Option<RollingBudgetBinding>> = const { RefCell::new(None) };
}

/// Operator-configured rolling window and hard ceilings for one workspace.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RollingBudgetQuota {
    pub max_tokens: Option<usize>,
    pub max_cost_usd: Option<f64>,
    pub window_seconds: u64,
}

impl RollingBudgetQuota {
    pub fn validate(self) -> Result<Self> {
        if self.window_seconds == 0 {
            bail!("rolling budget window must be greater than zero seconds");
        }
        if self.max_tokens == Some(0) {
            bail!("rolling token quota must be greater than zero");
        }
        if self
            .max_cost_usd
            .is_some_and(|cost| !cost.is_finite() || cost <= 0.0)
        {
            bail!("rolling cost quota must be finite and greater than zero");
        }
        if self.max_tokens.is_none() && self.max_cost_usd.is_none() {
            bail!("rolling budget requires a token or cost ceiling");
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RollingBudgetBinding {
    pub repo: PathBuf,
    pub quota: RollingBudgetQuota,
    pub run_id: String,
}

/// Restores the previous thread-local rolling-budget bind on drop.
#[derive(Debug)]
pub struct RollingBudgetBindGuard {
    previous: Option<RollingBudgetBinding>,
}

impl Drop for RollingBudgetBindGuard {
    fn drop(&mut self) {
        BINDING.with(|slot| {
            *slot.borrow_mut() = self.previous.take();
        });
    }
}

pub fn bind_rolling_budget(
    repo: impl Into<PathBuf>,
    quota: RollingBudgetQuota,
    run_id: impl Into<String>,
) -> Result<RollingBudgetBindGuard> {
    let quota = quota.validate()?;
    let run_id = run_id.into();
    if run_id.is_empty() {
        bail!("rolling budget run id cannot be empty");
    }
    let binding = RollingBudgetBinding {
        repo: repo.into(),
        quota,
        run_id,
    };
    Ok(BINDING.with(|slot| RollingBudgetBindGuard {
        previous: slot.borrow_mut().replace(binding),
    }))
}

pub fn current_rolling_binding() -> Option<RollingBudgetBinding> {
    BINDING.with(|slot| slot.borrow().clone())
}

/// Returns true when a runtime surfaced a provider rate-limit.
pub fn provider_error_is_rate_limited(error: &ProviderError) -> bool {
    matches!(error, ProviderError::RateLimited(_))
}

/// Records a provider rate-limit on the bound workspace ledger.
///
/// Missing bind or a corrupt ledger fails closed so callers cannot retry
/// unbounded after `ProviderError::RateLimited`.
pub fn record_bound_provider_error(error: &ProviderError) -> Result<()> {
    let ProviderError::RateLimited(detail) = error else {
        return Ok(());
    };
    let binding = current_rolling_binding().context(
        "provider rate limit reported with no workspace rolling budget bound; refusing unbounded retry",
    )?;
    let mut ledger = WorkspaceBudgetLedger::open_or_create(&binding.repo)?;
    ledger.record_rate_limited(
        DEFAULT_RATE_LIMIT_POOL,
        detail,
        binding.quota.window_seconds,
        unix_now()?,
    )
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
enum BudgetLedgerEvent {
    Consume {
        version: u32,
        run_id: String,
        tokens: usize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cost_usd: Option<f64>,
        unix_seconds: u64,
    },
    RateLimited {
        version: u32,
        pool: String,
        detail: String,
        unix_seconds: u64,
        until_unix_seconds: u64,
    },
}

impl BudgetLedgerEvent {
    fn phase(&self) -> &'static str {
        match self {
            Self::Consume { .. } => "consume",
            Self::RateLimited { .. } => "rate_limited",
        }
    }

    fn subject(&self) -> Option<&str> {
        match self {
            Self::Consume { run_id, .. } if journal_subject_ok(run_id) => Some(run_id.as_str()),
            Self::RateLimited { pool, .. } if journal_subject_ok(pool) => Some(pool.as_str()),
            _ => None,
        }
    }

    fn unix_seconds(&self) -> u64 {
        match self {
            Self::Consume { unix_seconds, .. } | Self::RateLimited { unix_seconds, .. } => {
                *unix_seconds
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RollingBudgetUsage {
    pub tokens: usize,
    pub cost_usd: Option<f64>,
    pub rate_limited_pools: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RateLimitLatch {
    pub pool: String,
    pub detail: String,
    pub until_unix_seconds: u64,
}

pub struct WorkspaceBudgetLedger {
    journal: BudgetJournal,
    events: Vec<BudgetLedgerEvent>,
}

impl std::fmt::Debug for WorkspaceBudgetLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkspaceBudgetLedger")
            .field("events", &self.events.len())
            .finish_non_exhaustive()
    }
}

impl WorkspaceBudgetLedger {
    pub fn open_or_create(repo: impl AsRef<Path>) -> Result<Self> {
        let authenticator = repository_auth_writer(repo.as_ref())
            .context("failed to open repository authentication for the rolling budget ledger")?
            .into_authenticator()
            .context("failed to bind repository authentication for the rolling budget ledger")?;
        let journal = BudgetJournal::open_or_initialize(authenticator, INSTANCE_ID)
            .context("workspace rolling budget journal is corrupt or unavailable")?;
        let events = replay_events(journal.records())?;
        Ok(Self { journal, events })
    }

    pub fn record_consumption(
        &mut self,
        run_id: impl Into<String>,
        tokens: usize,
        cost_usd: Option<f64>,
        now_unix_seconds: u64,
    ) -> Result<()> {
        if tokens == 0 && cost_usd.is_none() {
            return Ok(());
        }
        if cost_usd.is_some_and(|cost| !cost.is_finite() || cost < 0.0) {
            bail!("rolling budget consumption cost must be finite and non-negative");
        }
        let event = BudgetLedgerEvent::Consume {
            version: LEDGER_FORMAT_VERSION,
            run_id: run_id.into(),
            tokens,
            cost_usd,
            unix_seconds: now_unix_seconds,
        };
        self.publish(event)
    }

    pub fn record_rate_limited(
        &mut self,
        pool: impl Into<String>,
        detail: impl Into<String>,
        window_seconds: u64,
        now_unix_seconds: u64,
    ) -> Result<()> {
        if window_seconds == 0 {
            bail!("rate-limit latch window must be greater than zero seconds");
        }
        let pool = pool.into();
        if pool.is_empty() {
            bail!("rate-limit pool cannot be empty");
        }
        let until_unix_seconds = now_unix_seconds
            .checked_add(window_seconds)
            .context("rate-limit latch window overflowed")?;
        let event = BudgetLedgerEvent::RateLimited {
            version: LEDGER_FORMAT_VERSION,
            pool,
            detail: detail.into(),
            unix_seconds: now_unix_seconds,
            until_unix_seconds,
        };
        self.publish(event)
    }

    pub fn usage_in_window(
        &self,
        window_seconds: u64,
        now_unix_seconds: u64,
    ) -> Result<RollingBudgetUsage> {
        if window_seconds == 0 {
            bail!("rolling budget window must be greater than zero seconds");
        }
        let start = now_unix_seconds.saturating_sub(window_seconds);
        let mut tokens = 0_usize;
        let mut cost_usd = 0.0_f64;
        let mut cost_complete = true;
        let mut rate_limited_pools = Vec::new();
        for event in &self.events {
            if event.unix_seconds() < start {
                continue;
            }
            match event {
                BudgetLedgerEvent::Consume {
                    tokens: consumed,
                    cost_usd: observed,
                    ..
                } => {
                    tokens = tokens
                        .checked_add(*consumed)
                        .context("rolling token consumption overflowed")?;
                    match observed {
                        Some(cost) => {
                            cost_usd = checked_cost_add(cost_usd, *cost)?;
                        }
                        None if *consumed > 0 => cost_complete = false,
                        None => {}
                    }
                }
                BudgetLedgerEvent::RateLimited {
                    pool,
                    until_unix_seconds,
                    ..
                } if *until_unix_seconds > now_unix_seconds
                    && !rate_limited_pools.iter().any(|seen| seen == pool) =>
                {
                    rate_limited_pools.push(pool.clone());
                }
                BudgetLedgerEvent::RateLimited { .. } => {}
            }
        }
        Ok(RollingBudgetUsage {
            tokens,
            cost_usd: cost_complete.then_some(cost_usd),
            rate_limited_pools,
        })
    }

    pub fn active_rate_limit(&self, pool: &str, now_unix_seconds: u64) -> Option<RateLimitLatch> {
        self.events.iter().rev().find_map(|event| match event {
            BudgetLedgerEvent::RateLimited {
                pool: event_pool,
                detail,
                until_unix_seconds,
                ..
            } if event_pool == pool && *until_unix_seconds > now_unix_seconds => {
                Some(RateLimitLatch {
                    pool: event_pool.clone(),
                    detail: detail.clone(),
                    until_unix_seconds: *until_unix_seconds,
                })
            }
            _ => None,
        })
    }

    pub fn any_active_rate_limit(&self, now_unix_seconds: u64) -> Option<RateLimitLatch> {
        self.events.iter().rev().find_map(|event| match event {
            BudgetLedgerEvent::RateLimited {
                pool,
                detail,
                until_unix_seconds,
                ..
            } if *until_unix_seconds > now_unix_seconds => Some(RateLimitLatch {
                pool: pool.clone(),
                detail: detail.clone(),
                until_unix_seconds: *until_unix_seconds,
            }),
            _ => None,
        })
    }

    fn publish(&mut self, event: BudgetLedgerEvent) -> Result<()> {
        self.journal
            .append(event.phase(), event.subject(), &event)
            .context("failed to persist a rolling budget journal record")?;
        self.events.push(event);
        Ok(())
    }
}

fn replay_events(records: &[JournalRecord]) -> Result<Vec<BudgetLedgerEvent>> {
    let mut events = Vec::with_capacity(records.len());
    for record in records {
        let event = serde_json::from_value::<BudgetLedgerEvent>(record.payload.clone())
            .context("workspace rolling budget journal contains an unknown or corrupt event")?;
        if record.phase != event.phase() {
            bail!("workspace rolling budget journal phase does not match its payload");
        }
        match &event {
            BudgetLedgerEvent::Consume {
                version,
                run_id,
                cost_usd,
                ..
            } => {
                if *version != LEDGER_FORMAT_VERSION {
                    bail!("unsupported rolling budget consume version {version}");
                }
                if run_id.is_empty() {
                    bail!("rolling budget consume event is missing a run id");
                }
                if cost_usd.is_some_and(|cost| !cost.is_finite() || cost < 0.0) {
                    bail!("rolling budget consume event has an invalid cost");
                }
            }
            BudgetLedgerEvent::RateLimited {
                version,
                pool,
                until_unix_seconds,
                unix_seconds,
                ..
            } => {
                if *version != LEDGER_FORMAT_VERSION {
                    bail!("unsupported rolling budget rate-limit version {version}");
                }
                if pool.is_empty() {
                    bail!("rolling budget rate-limit event is missing a pool");
                }
                if *until_unix_seconds < *unix_seconds {
                    bail!("rolling budget rate-limit latch ends before it starts");
                }
            }
        }
        events.push(event);
    }
    Ok(events)
}

fn journal_subject_ok(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= BudgetLedgerJournalSpec::MAX_SUBJECT_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
}

pub(crate) fn unix_now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the unix epoch")?
        .as_secs())
}

fn checked_cost_add(left: f64, right: f64) -> Result<f64> {
    let total = left + right;
    if total.is_finite() {
        Ok(total)
    } else {
        bail!("rolling cost consumption overflowed")
    }
}

pub(crate) fn rolling_cost_exceeds(value: f64, limit: f64) -> bool {
    value - limit > f64::EPSILON * value.abs().max(limit.abs()) * 8.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use git2::Repository;
    use std::fs;
    use tempfile::TempDir;

    fn repository() -> (TempDir, PathBuf) {
        let temp = TempDir::new().expect("temporary directory");
        let repo = temp.path().join("repo");
        Repository::init(&repo).expect("initialize repository");
        (temp, repo)
    }

    fn quota(max_tokens: usize) -> RollingBudgetQuota {
        RollingBudgetQuota {
            max_tokens: Some(max_tokens),
            max_cost_usd: None,
            window_seconds: DEFAULT_ROLLING_WINDOW_SECONDS,
        }
    }

    fn journal_record_paths(repo: &Path) -> Vec<PathBuf> {
        let dir = repo
            .join(".git")
            .join("maco")
            .join("state")
            .join(BUDGET_LEDGER_ROOT_NAME)
            .join(INSTANCE_ID);
        let mut paths = fs::read_dir(&dir)
            .unwrap_or_else(|error| panic!("read budget journal {}: {error}", dir.display()))
            .map(|entry| entry.expect("journal entry").path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.ends_with(".json")
                            && !name.starts_with('.')
                            && name
                                .trim_end_matches(".json")
                                .bytes()
                                .all(|byte| byte.is_ascii_digit())
                    })
            })
            .collect::<Vec<_>>();
        paths.sort();
        paths
    }

    #[test]
    fn persist_replay_preserves_consumption_across_reopen() {
        let (_temp, repo) = repository();
        {
            let mut ledger =
                WorkspaceBudgetLedger::open_or_create(&repo).expect("create rolling ledger");
            ledger
                .record_consumption("run-a", 40, Some(0.4), 1_000)
                .expect("persist consume");
            ledger
                .record_consumption("run-a", 25, Some(0.25), 1_010)
                .expect("persist second consume");
            let usage = ledger
                .usage_in_window(DEFAULT_ROLLING_WINDOW_SECONDS, 1_020)
                .expect("usage");
            assert_eq!(usage.tokens, 65);
            assert_eq!(usage.cost_usd, Some(0.65));
        }

        let reopened = WorkspaceBudgetLedger::open_or_create(&repo).expect("replay rolling ledger");
        let usage = reopened
            .usage_in_window(DEFAULT_ROLLING_WINDOW_SECONDS, 1_020)
            .expect("replayed usage");
        assert_eq!(usage.tokens, 65);
        assert_eq!(usage.cost_usd, Some(0.65));
        assert!(usage.rate_limited_pools.is_empty());
    }

    #[test]
    fn window_excludes_consumption_outside_the_rolling_horizon() {
        let (_temp, repo) = repository();
        let mut ledger = WorkspaceBudgetLedger::open_or_create(&repo).expect("ledger");
        ledger
            .record_consumption("run-old", 90, None, 100)
            .expect("old consume");
        ledger
            .record_consumption("run-new", 12, None, 10_000)
            .expect("new consume");
        let usage = ledger
            .usage_in_window(1_000, 10_000)
            .expect("windowed usage");
        assert_eq!(usage.tokens, 12);
    }

    #[test]
    fn corrupt_journal_fails_closed_on_replay() {
        let (_temp, repo) = repository();
        {
            let mut ledger = WorkspaceBudgetLedger::open_or_create(&repo).expect("create");
            ledger
                .record_consumption("run-a", 10, None, 50)
                .expect("persist");
        }
        let record = journal_record_paths(&repo)
            .into_iter()
            .next()
            .expect("published record");
        fs::write(&record, b"{\"version\":1}\n").expect("tamper record");
        let error = WorkspaceBudgetLedger::open_or_create(&repo)
            .expect_err("tampered journal must fail closed");
        let message = format!("{error:#}");
        assert!(
            message.contains("corrupt")
                || message.contains("malformed")
                || message.contains("truncated")
                || message.contains("unavailable")
                || message.contains("invalid"),
            "unexpected corruption error: {message}"
        );
    }

    #[test]
    fn rate_limit_latches_the_pool_until_the_window() {
        let (_temp, repo) = repository();
        {
            let mut ledger = WorkspaceBudgetLedger::open_or_create(&repo).expect("create");
            ledger
                .record_rate_limited(DEFAULT_RATE_LIMIT_POOL, "cooldown", 60, 500)
                .expect("latch");
            let latch = ledger
                .active_rate_limit(DEFAULT_RATE_LIMIT_POOL, 520)
                .expect("active latch");
            assert_eq!(latch.until_unix_seconds, 560);
            assert!(ledger
                .active_rate_limit(DEFAULT_RATE_LIMIT_POOL, 560)
                .is_none());
        }

        let reopened = WorkspaceBudgetLedger::open_or_create(&repo).expect("replay latch");
        assert!(reopened
            .active_rate_limit(DEFAULT_RATE_LIMIT_POOL, 559)
            .is_some());
        let usage = reopened.usage_in_window(60, 520).expect("usage");
        assert_eq!(usage.rate_limited_pools, vec![DEFAULT_RATE_LIMIT_POOL]);
    }

    #[test]
    fn bound_provider_rate_limit_records_and_unbound_rate_limit_fails_closed() {
        let (_temp, repo) = repository();
        let error = ProviderError::RateLimited("retry later".to_string());
        assert!(provider_error_is_rate_limited(&error));
        assert!(record_bound_provider_error(&error)
            .expect_err("unbound rate limit must fail closed")
            .to_string()
            .contains("no workspace rolling budget bound"));

        let _guard = bind_rolling_budget(&repo, quota(1_000), "run-bound").expect("bind");
        record_bound_provider_error(&error).expect("record bound rate limit");
        drop(_guard);

        let ledger = WorkspaceBudgetLedger::open_or_create(&repo).expect("reopen");
        assert!(ledger
            .active_rate_limit(DEFAULT_RATE_LIMIT_POOL, unix_now().expect("now"))
            .is_some());
    }

    #[test]
    fn quota_validation_rejects_nonsense() {
        assert!(RollingBudgetQuota {
            max_tokens: None,
            max_cost_usd: None,
            window_seconds: DEFAULT_ROLLING_WINDOW_SECONDS,
        }
        .validate()
        .is_err());
        assert!(RollingBudgetQuota {
            max_tokens: Some(0),
            max_cost_usd: None,
            window_seconds: 10,
        }
        .validate()
        .is_err());
        assert!(RollingBudgetQuota {
            max_tokens: None,
            max_cost_usd: Some(f64::NAN),
            window_seconds: 10,
        }
        .validate()
        .is_err());
    }
}
