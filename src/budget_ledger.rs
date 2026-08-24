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
    optimizer::quota_pools::{ConsumptionLedger, LedgerEntry, PoolKey, QuotaConfig, ResetWindow},
    state_journal::{AuthenticatedStateJournal, JournalRecord, JournalSpec},
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    collections::BTreeSet,
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
    PoolConsume {
        version: u32,
        completion_id: String,
        pool: PoolKey,
        tokens: u64,
        requests: u64,
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
            Self::PoolConsume { .. } => "pool_consume",
            Self::RateLimited { .. } => "rate_limited",
        }
    }

    fn subject(&self) -> Option<&str> {
        match self {
            Self::Consume { run_id, .. } if journal_subject_ok(run_id) => Some(run_id.as_str()),
            Self::PoolConsume { completion_id, .. } if journal_subject_ok(completion_id) => {
                Some(completion_id.as_str())
            }
            Self::RateLimited { pool, .. } if journal_subject_ok(pool) => Some(pool.as_str()),
            _ => None,
        }
    }

    fn unix_seconds(&self) -> u64 {
        match self {
            Self::Consume { unix_seconds, .. }
            | Self::PoolConsume { unix_seconds, .. }
            | Self::RateLimited { unix_seconds, .. } => *unix_seconds,
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

/// One completed local run-budget reconciliation attributed to a quota pool.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletedPoolConsumption {
    pub completion_id: String,
    pub pool: PoolKey,
    pub tokens: u64,
    pub requests: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
    pub unix_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolConsumptionRecordOutcome {
    Recorded,
    AlreadyRecorded,
}

/// Authenticated local consumption projected for one pool's declared window.
#[derive(Debug, Clone, PartialEq)]
pub struct PoolConsumptionUsage {
    pub tokens: u64,
    pub requests: u64,
    pub cost_usd: Option<f64>,
    pub observation_revision: String,
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

    /// Persist one completed run-budget reconciliation for a quota pool.
    ///
    /// Repeating the exact completion is a no-op. Reusing its stable ID with
    /// different pool or usage data fails closed instead of double-counting.
    pub fn record_completed_pool_consumption(
        &mut self,
        completion: CompletedPoolConsumption,
    ) -> Result<PoolConsumptionRecordOutcome> {
        validate_completed_pool_consumption(&completion)?;
        for event in &self.events {
            let BudgetLedgerEvent::PoolConsume {
                completion_id,
                pool,
                tokens,
                requests,
                cost_usd,
                ..
            } = event
            else {
                continue;
            };
            if completion_id != &completion.completion_id {
                continue;
            }
            if pool == &completion.pool
                && *tokens == completion.tokens
                && *requests == completion.requests
                && *cost_usd == completion.cost_usd
            {
                return Ok(PoolConsumptionRecordOutcome::AlreadyRecorded);
            }
            bail!(
                "workspace quota completion id '{}' was already recorded with different data",
                completion.completion_id
            );
        }
        self.publish(BudgetLedgerEvent::PoolConsume {
            version: LEDGER_FORMAT_VERSION,
            completion_id: completion.completion_id,
            pool: completion.pool,
            tokens: completion.tokens,
            requests: completion.requests,
            cost_usd: completion.cost_usd,
            unix_seconds: completion.unix_seconds,
        })?;
        Ok(PoolConsumptionRecordOutcome::Recorded)
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
                BudgetLedgerEvent::PoolConsume {
                    tokens: consumed,
                    cost_usd: observed,
                    ..
                } => {
                    let consumed = usize::try_from(*consumed)
                        .context("pool token consumption does not fit this platform")?;
                    tokens = tokens
                        .checked_add(consumed)
                        .context("rolling token consumption overflowed")?;
                    match observed {
                        Some(cost) => {
                            cost_usd = checked_cost_add(cost_usd, *cost)?;
                        }
                        None if consumed > 0 => cost_complete = false,
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

    /// Project authenticated completed usage for one exact quota-pool window.
    pub fn pool_usage(
        &self,
        pool: &PoolKey,
        now_unix_seconds: u64,
    ) -> Result<PoolConsumptionUsage> {
        let window_start = pool_window_start(pool.window, now_unix_seconds)?;
        let mut tokens = 0_u64;
        let mut requests = 0_u64;
        let mut cost_usd = 0.0_f64;
        let mut cost_complete = true;
        let mut observation_revision = "authenticated-workspace-ledger-empty".to_string();
        for event in &self.events {
            let BudgetLedgerEvent::PoolConsume {
                completion_id,
                pool: event_pool,
                tokens: event_tokens,
                requests: event_requests,
                cost_usd: event_cost,
                unix_seconds,
                ..
            } = event
            else {
                continue;
            };
            if event_pool != pool || window_start.is_some_and(|start| *unix_seconds < start) {
                continue;
            }
            tokens = tokens
                .checked_add(*event_tokens)
                .context("quota pool token consumption overflowed")?;
            requests = requests
                .checked_add(*event_requests)
                .context("quota pool request consumption overflowed")?;
            match event_cost {
                Some(cost) => cost_usd = checked_cost_add(cost_usd, *cost)?,
                None if *event_tokens > 0 || *event_requests > 0 => cost_complete = false,
                None => {}
            }
            observation_revision.clone_from(completion_id);
        }
        Ok(PoolConsumptionUsage {
            tokens,
            requests,
            cost_usd: cost_complete.then_some(cost_usd),
            observation_revision,
        })
    }

    /// Build the selector's local observation snapshot directly from this
    /// authenticated journal. No provider data or network operation is used.
    pub fn quota_consumption_ledger(
        &self,
        config: &QuotaConfig,
        now_unix_seconds: u64,
    ) -> Result<ConsumptionLedger> {
        config
            .validate()
            .map_err(|error| anyhow::anyhow!("operator quota config is invalid: {error}"))?;
        let mut projection = ConsumptionLedger::new();
        for entitlement in &config.pools {
            let usage = self.pool_usage(&entitlement.key(), now_unix_seconds)?;
            projection
                .insert_snapshot(
                    entitlement.key(),
                    LedgerEntry::local(usage.tokens, usage.requests, usage.observation_revision),
                )
                .map_err(|error| {
                    anyhow::anyhow!("failed to project authenticated quota consumption: {error}")
                })?;
        }
        Ok(projection)
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
    let mut pool_completion_ids = BTreeSet::new();
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
            BudgetLedgerEvent::PoolConsume {
                version,
                completion_id,
                pool,
                tokens,
                requests,
                cost_usd,
                unix_seconds,
            } => {
                let completion = CompletedPoolConsumption {
                    completion_id: completion_id.clone(),
                    pool: pool.clone(),
                    tokens: *tokens,
                    requests: *requests,
                    cost_usd: *cost_usd,
                    unix_seconds: *unix_seconds,
                };
                if *version != LEDGER_FORMAT_VERSION {
                    bail!("unsupported workspace quota pool consumption version {version}");
                }
                validate_completed_pool_consumption(&completion)?;
                if !pool_completion_ids.insert(completion_id.clone()) {
                    bail!(
                        "workspace quota pool ledger contains duplicate completion id '{}'",
                        completion_id
                    );
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

fn validate_completed_pool_consumption(completion: &CompletedPoolConsumption) -> Result<()> {
    if completion.completion_id.is_empty()
        || completion.completion_id.len() > 512
        || completion.completion_id.chars().any(char::is_control)
    {
        bail!("workspace quota completion id is invalid");
    }
    completion
        .pool
        .validate()
        .map_err(|error| anyhow::anyhow!("workspace quota pool key is invalid: {error}"))?;
    if completion.tokens == 0 && completion.requests == 0 && completion.cost_usd.is_none() {
        bail!("workspace quota completion must record tokens, requests, or cost");
    }
    if completion
        .cost_usd
        .is_some_and(|cost| !cost.is_finite() || cost < 0.0)
    {
        bail!("workspace quota completion cost must be finite and non-negative");
    }
    Ok(())
}

fn pool_window_start(window: ResetWindow, now_unix_seconds: u64) -> Result<Option<u64>> {
    match window {
        ResetWindow::None => Ok(None),
        ResetWindow::RollingHours { hours: 0 } => {
            bail!("rolling quota window hours must be greater than zero")
        }
        ResetWindow::RollingHours { hours } => {
            let seconds = u64::from(hours)
                .checked_mul(60 * 60)
                .context("rolling quota window overflowed")?;
            Ok(Some(now_unix_seconds.saturating_sub(seconds)))
        }
        ResetWindow::CalendarMonth => Ok(Some(calendar_month_start(now_unix_seconds)?)),
    }
}

fn calendar_month_start(now_unix_seconds: u64) -> Result<u64> {
    let days = i64::try_from(now_unix_seconds / 86_400)
        .context("calendar quota timestamp is outside the supported range")?;
    let (year, month) = civil_year_month_from_days(days);
    let first_day = days_from_civil(year, month, 1);
    u64::try_from(first_day)
        .context("calendar quota month starts before the unix epoch")?
        .checked_mul(86_400)
        .context("calendar quota month start overflowed")
}

// Gregorian civil-date conversions adapted from the public-domain algorithms
// by Howard Hinnant. Inputs and outputs are whole days relative to 1970-01-01.
fn civil_year_month_from_days(days: i64) -> (i64, i64) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    (year, month)
}

fn days_from_civil(mut year: i64, month: i64, day: i64) -> i64 {
    if month <= 2 {
        year -= 1;
    }
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
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

    fn pool(runtime: &str, window: ResetWindow) -> PoolKey {
        PoolKey {
            runtime: crate::optimizer::ids::RuntimeSlug::new(runtime).expect("runtime"),
            account: crate::optimizer::quota_pools::AccountId::new("operator").expect("account"),
            window,
        }
    }

    fn completion(id: &str, pool: PoolKey, tokens: u64, now: u64) -> CompletedPoolConsumption {
        CompletedPoolConsumption {
            completion_id: id.to_string(),
            pool,
            tokens,
            requests: 1,
            cost_usd: Some(tokens as f64 / 100.0),
            unix_seconds: now,
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
    fn completed_pool_consumption_is_idempotent_and_feeds_legacy_aggregate() {
        let (_temp, repo) = repository();
        let key = pool("gpt-5.6-sol", ResetWindow::RollingHours { hours: 1 });
        {
            let mut ledger = WorkspaceBudgetLedger::open_or_create(&repo).expect("create");
            assert_eq!(
                ledger
                    .record_completed_pool_consumption(completion(
                        "run-a/reservation/1",
                        key.clone(),
                        25,
                        10_000,
                    ))
                    .expect("record"),
                PoolConsumptionRecordOutcome::Recorded
            );
            let mut retried = completion("run-a/reservation/1", key.clone(), 25, 10_010);
            retried.unix_seconds = 10_010;
            assert_eq!(
                ledger
                    .record_completed_pool_consumption(retried)
                    .expect("idempotent retry"),
                PoolConsumptionRecordOutcome::AlreadyRecorded
            );
            let mismatch = completion("run-a/reservation/1", key.clone(), 26, 10_000);
            assert!(ledger
                .record_completed_pool_consumption(mismatch)
                .expect_err("mismatched retry")
                .to_string()
                .contains("different data"));
        }

        let reopened = WorkspaceBudgetLedger::open_or_create(&repo).expect("reopen");
        let usage = reopened.pool_usage(&key, 10_100).expect("pool usage");
        assert_eq!(usage.tokens, 25);
        assert_eq!(usage.requests, 1);
        assert_eq!(usage.cost_usd, Some(0.25));
        assert_eq!(usage.observation_revision, "run-a/reservation/1");
        let aggregate = reopened.usage_in_window(3_600, 10_100).expect("aggregate");
        assert_eq!(aggregate.tokens, 25);
        assert_eq!(aggregate.cost_usd, Some(0.25));
    }

    #[test]
    fn pool_windows_and_selector_projection_use_only_matching_completed_events() {
        let (_temp, repo) = repository();
        let rolling = pool("rolling", ResetWindow::RollingHours { hours: 1 });
        let monthly = pool("monthly", ResetWindow::CalendarMonth);
        let mut ledger = WorkspaceBudgetLedger::open_or_create(&repo).expect("create");
        ledger
            .record_completed_pool_consumption(completion(
                "old/reservation/1",
                rolling.clone(),
                40,
                1_000,
            ))
            .expect("old rolling");
        ledger
            .record_completed_pool_consumption(completion(
                "new/reservation/1",
                rolling.clone(),
                12,
                10_000,
            ))
            .expect("new rolling");
        ledger
            .record_completed_pool_consumption(completion(
                "month/reservation/1",
                monthly.clone(),
                9,
                2_700_000,
            ))
            .expect("monthly");
        assert_eq!(
            ledger.pool_usage(&rolling, 10_000).expect("rolling").tokens,
            12
        );
        assert_eq!(
            ledger
                .pool_usage(&monthly, 3_000_000)
                .expect("monthly")
                .tokens,
            9
        );
        assert_eq!(
            calendar_month_start(3_000_000).expect("February 1970"),
            2_678_400
        );

        let config = QuotaConfig {
            version: crate::optimizer::quota_pools::QUOTA_CONFIG_VERSION,
            pools: vec![crate::optimizer::quota_pools::EntitlementDescriptor {
                runtime: rolling.runtime.clone(),
                account: rolling.account.clone(),
                pool_kind: crate::optimizer::quota_pools::PoolKind::Metered,
                window: rolling.window,
                nominal_capacity: crate::optimizer::quota_pools::NominalCapacity::Unknown,
                rate_limits: crate::optimizer::quota_pools::RateLimits::default(),
                priority_tier: None,
                exhaustion_behavior: crate::optimizer::quota_pools::ExhaustionBehavior::FailClosed,
                authorized_alternatives: Vec::new(),
                declared_list_price_microunits: Some(1),
            }],
        };
        let projection = ledger
            .quota_consumption_ledger(&config, 10_000)
            .expect("authenticated projection");
        let entry = projection.entries.get(&rolling).expect("rolling entry");
        assert_eq!(entry.tokens, 12);
        assert_eq!(entry.requests, 1);
        assert_eq!(
            entry.source,
            crate::optimizer::quota_pools::ConsumptionSource::LocalObserved
        );
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
    fn corrupt_pool_journal_fails_closed_on_replay() {
        let (_temp, repo) = repository();
        {
            let mut ledger = WorkspaceBudgetLedger::open_or_create(&repo).expect("create");
            ledger
                .record_completed_pool_consumption(completion(
                    "run-a/reservation/1",
                    pool("codex", ResetWindow::None),
                    10,
                    50,
                ))
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
