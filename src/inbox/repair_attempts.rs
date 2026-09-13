//! Durable admission count for real GitHub pull-request repair invocations.
//!
//! The journal key is the provider repository identity and PR number. A new
//! head, review snapshot, or operator policy cannot erase a prior reservation.
//! A reservation remains spent after failure, refusal, or uncertain process
//! death; a local successful run is not verified `Addressed` feedback.

use super::{
    pr_needs_repair, review_loop::MAX_REVIEW_LOOP_ATTEMPTS, review_policy_input::BoundReviewPolicy,
    InboxItem, InboxItemKind, InboxSourceProvider,
};
use crate::{
    artifacts::{
        repository_auth_writer,
        state_auth::{sha256_hex, AuthenticationDomain},
    },
    orchestrator::RunId,
    state_journal::{AuthenticatedStateJournal, CheckpointJournalSpec, JournalSpec},
};
use anyhow::{bail, Context, Result};
use git2::Oid;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path};

const FORMAT_VERSION: u32 = 1;
const KEY_DOMAIN: &[u8] = b"MACO\0github-pr-repair-attempt-key\0v1\0";

enum RepairAttemptJournalSpec {}

impl JournalSpec for RepairAttemptJournalSpec {
    const FORMAT_VERSION: u32 = FORMAT_VERSION;
    const NAMESPACE: &'static str = "github_pr_repair_attempt";
    const ROOT_NAME: &'static str = "inbox-pr-repair-attempts-v1";
    const ROOT_LOCK_NAME: &'static str = ".inbox-pr-repair-attempts.lock";
    const INSTANCE_LOCK_NAME: &'static str = ".repair-attempt.lock";
    const HEAD_FILE_NAME: &'static str = ".head.json";
    const RECORD_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0github-pr-repair-attempt-record\0v1\0");
    const HEAD_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0github-pr-repair-attempt-head\0v1\0");
    // The only attempt quota is the existing strict ReviewLoopPolicy cap.
    // Reuse the authenticated checkpoint envelope's established size bounds;
    // replay additionally validates every fixed reservation field.
    const MAX_RECORDS: usize = MAX_REVIEW_LOOP_ATTEMPTS;
    const MAX_RECORD_BYTES: u64 = <CheckpointJournalSpec as JournalSpec>::MAX_RECORD_BYTES;
    const MAX_TOTAL_BYTES: u64 = Self::MAX_RECORD_BYTES * Self::MAX_RECORDS as u64;
    const MAX_PHASE_BYTES: usize = <CheckpointJournalSpec as JournalSpec>::MAX_PHASE_BYTES;
    const MAX_SUBJECT_BYTES: usize = <CheckpointJournalSpec as JournalSpec>::MAX_SUBJECT_BYTES;
    // SHA-256 hex is exactly 64 bytes and is the complete instance key.
    const MAX_INSTANCE_ID_BYTES: usize = 64;
}

type RepairAttemptJournal = AuthenticatedStateJournal<RepairAttemptJournalSpec>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RepairAttemptReceipt {
    pub(super) attempt_number: usize,
    pub(super) journal_id: String,
    pub(super) record_mac: String,
    pub(super) source_snapshot_sha256: String,
    pub(super) raw_policy_sha256: String,
    pub(super) policy_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RepairAttemptAdmission {
    NotApplicable,
    Reserved(RepairAttemptReceipt),
    Exhausted { spent: usize, max_attempts: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReservedAttempt {
    version: u32,
    provider_repository_id: String,
    pr_number: u64,
    attempt_number: usize,
    inbox_run_id: String,
    item_index: usize,
    source_snapshot_sha256: String,
    head_oid: String,
    base_oid: String,
    raw_policy_sha256: String,
    policy_sha256: String,
    policy_max_attempts: usize,
}

#[derive(Serialize)]
struct LogicalPrKey<'a> {
    provider_repository_id: &'a str,
    pr_number: u64,
}

struct RepairAttemptRequest<'a> {
    provider_repository_id: &'a str,
    pr_number: u64,
    run_id: &'a RunId,
    item_index: usize,
    source_snapshot_sha256: &'a str,
    head_oid: Oid,
    base_oid: &'a str,
    raw_policy_sha256: &'a str,
    policy_sha256: &'a str,
    max_attempts: usize,
}

fn instance_id(provider_repository_id: &str, pr_number: u64) -> Result<String> {
    let mut bytes = KEY_DOMAIN.to_vec();
    bytes.extend(
        serde_json::to_vec(&LogicalPrKey {
            provider_repository_id,
            pr_number,
        })
        .context("failed to encode logical PR repair identity")?,
    );
    Ok(sha256_hex(&bytes))
}

fn validate_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn validate_provider_repository_id(value: &str) -> bool {
    value
        .strip_prefix("node:sha256:")
        .is_some_and(validate_sha256)
}

fn replay_reservations(
    journal: &RepairAttemptJournal,
    provider_repository_id: &str,
    pr_number: u64,
) -> Result<BTreeSet<String>> {
    let mut seen = BTreeSet::new();
    for (zero_index, record) in journal.records().iter().enumerate() {
        if record.phase != "attempt_reserved" || record.subject.is_some() {
            bail!("authenticated PR repair journal contains an unknown event");
        }
        let event: ReservedAttempt = serde_json::from_value(record.payload.clone())
            .context("authenticated PR repair reservation is malformed")?;
        let expected_attempt = zero_index
            .checked_add(1)
            .context("PR repair attempt count overflowed")?;
        if event.version != FORMAT_VERSION
            || event.provider_repository_id != provider_repository_id
            || event.pr_number != pr_number
            || event.attempt_number != expected_attempt
            || event.item_index == 0
            || event.policy_max_attempts == 0
            || event.policy_max_attempts > MAX_REVIEW_LOOP_ATTEMPTS
            || event.attempt_number > event.policy_max_attempts
            || !validate_sha256(&event.source_snapshot_sha256)
            || !validate_sha256(&event.raw_policy_sha256)
            || !validate_sha256(&event.policy_sha256)
            || Oid::from_str(&event.head_oid).is_err()
            || Oid::from_str(&event.base_oid).is_err()
            || RunId::new(&event.inbox_run_id).is_err()
            || !seen.insert(event.inbox_run_id)
        {
            bail!("authenticated PR repair journal has inconsistent reservation evidence");
        }
    }
    Ok(seen)
}

fn reserve(repo: &Path, request: RepairAttemptRequest<'_>) -> Result<RepairAttemptAdmission> {
    let RepairAttemptRequest {
        provider_repository_id,
        pr_number,
        run_id,
        item_index,
        source_snapshot_sha256,
        head_oid,
        base_oid,
        raw_policy_sha256,
        policy_sha256,
        max_attempts,
    } = request;
    if !validate_provider_repository_id(provider_repository_id)
        || pr_number == 0
        || item_index == 0
        || max_attempts == 0
        || max_attempts > MAX_REVIEW_LOOP_ATTEMPTS
        || !validate_sha256(source_snapshot_sha256)
        || !validate_sha256(raw_policy_sha256)
        || !validate_sha256(policy_sha256)
        || Oid::from_str(base_oid).is_err()
    {
        bail!("PR repair reservation binding is malformed");
    }
    let authenticator = repository_auth_writer(repo)
        .context("failed to open repository authentication for PR repair attempts")?
        .into_authenticator()
        .context("failed to bind repository authentication for PR repair attempts")?;
    let mut journal = RepairAttemptJournal::open_or_initialize(
        authenticator,
        &instance_id(provider_repository_id, pr_number)?,
    )
    .context("authenticated PR repair attempt journal is unavailable")?;
    let seen_runs = replay_reservations(&journal, provider_repository_id, pr_number)?;
    let spent = seen_runs.len();
    if seen_runs.contains(run_id.as_str()) {
        bail!("Inbox PR repair run/item already has a durable attempt reservation");
    }
    if spent >= max_attempts {
        return Ok(RepairAttemptAdmission::Exhausted {
            spent,
            max_attempts,
        });
    }
    let event = ReservedAttempt {
        version: FORMAT_VERSION,
        provider_repository_id: provider_repository_id.to_string(),
        pr_number,
        attempt_number: spent + 1,
        inbox_run_id: run_id.as_str().to_string(),
        item_index,
        source_snapshot_sha256: source_snapshot_sha256.to_string(),
        head_oid: head_oid.to_string(),
        base_oid: base_oid.to_string(),
        raw_policy_sha256: raw_policy_sha256.to_string(),
        policy_sha256: policy_sha256.to_string(),
        policy_max_attempts: max_attempts,
    };
    let mac = journal
        .append("attempt_reserved", None, &event)
        .context("failed to durably reserve PR repair attempt")?
        .mac
        .as_str()
        .to_string();
    Ok(RepairAttemptAdmission::Reserved(RepairAttemptReceipt {
        attempt_number: event.attempt_number,
        journal_id: journal.identity().journal_id.clone(),
        record_mac: mac,
        source_snapshot_sha256: event.source_snapshot_sha256,
        raw_policy_sha256: event.raw_policy_sha256,
        policy_sha256: event.policy_sha256,
    }))
}

/// The caller has already frozen/verified the operator policy and revalidated
/// the selected source. Only the real GitHub PR repair launch receives a slot.
pub(super) fn reserve_if_applicable(
    repo: &Path,
    item: &InboxItem,
    policy: Option<&BoundReviewPolicy>,
    run_id: &RunId,
    item_index: usize,
    expected_source_head: Option<Oid>,
) -> Result<RepairAttemptAdmission> {
    let (Some(policy), Some(head)) = (policy, expected_source_head) else {
        return Ok(RepairAttemptAdmission::NotApplicable);
    };
    if item.kind != InboxItemKind::PullRequest
        || item.source_snapshot.provider() != InboxSourceProvider::Github
        || !item.pull_request.as_ref().is_some_and(pr_needs_repair)
    {
        return Ok(RepairAttemptAdmission::NotApplicable);
    }
    item.source_snapshot.validate()?;
    let head_string = head.to_string();
    if item.source_key != item.source_snapshot.source_key()
        || item.source_snapshot.repository_selector() != policy.repository().canonical_locator()
        || item.source_snapshot.head_oid() != Some(head_string.as_str())
    {
        bail!("PR repair attempt source or operator policy binding changed");
    }
    let source_snapshot_sha256 = sha256_hex(
        &serde_json::to_vec(&item.source_snapshot)
            .context("failed to serialize validated PR repair source snapshot")?,
    );
    let raw_policy_sha256 = sha256_hex(policy.raw());
    let policy_sha256 = policy.policy().canonical_sha256()?;
    reserve(
        repo,
        RepairAttemptRequest {
            provider_repository_id: policy.repository().provider_repository_id().stable_id(),
            pr_number: item.source_snapshot.number(),
            run_id,
            item_index,
            source_snapshot_sha256: &source_snapshot_sha256,
            head_oid: head,
            base_oid: item
                .source_snapshot
                .base_oid()
                .context("PR repair source has no base OID")?,
            raw_policy_sha256: &raw_policy_sha256,
            policy_sha256: &policy_sha256,
            max_attempts: policy.policy().max_attempts(),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worktree::WorktreeManager;
    use std::{
        fs,
        sync::{Arc, Barrier},
    };
    use tempfile::TempDir;

    fn fixture_repo() -> (TempDir, std::path::PathBuf) {
        let temp = TempDir::new().unwrap();
        let repo = temp.path().join("repo");
        WorktreeManager::init_repository(&repo, "main").unwrap();
        (temp, repo)
    }

    fn provider_repository_id() -> String {
        format!("node:sha256:{}", sha256_hex(b"repository-node"))
    }

    fn reserve_fixture(
        repo: &Path,
        pr_number: u64,
        run: &str,
        head: &str,
        policy: &str,
        limit: usize,
    ) -> Result<RepairAttemptAdmission> {
        let provider_repository_id = provider_repository_id();
        let run_id = RunId::new(run)?;
        let source_snapshot_sha256 = sha256_hex(head.as_bytes());
        let base_oid = "b".repeat(40);
        let raw_policy_sha256 = sha256_hex(policy.as_bytes());
        let policy_sha256 = sha256_hex(format!("effective:{policy}").as_bytes());
        reserve(
            repo,
            RepairAttemptRequest {
                provider_repository_id: &provider_repository_id,
                pr_number,
                run_id: &run_id,
                item_index: 1,
                source_snapshot_sha256: &source_snapshot_sha256,
                head_oid: Oid::from_str(head)?,
                base_oid: &base_oid,
                raw_policy_sha256: &raw_policy_sha256,
                policy_sha256: &policy_sha256,
                max_attempts: limit,
            },
        )
    }

    #[test]
    fn authenticated_reservations_survive_failed_runs_head_and_policy_refresh() {
        let (_temp, repo) = fixture_repo();
        let first =
            reserve_fixture(&repo, 17, "failed-run", &"a".repeat(40), "policy-a", 2).unwrap();
        assert!(
            matches!(first, RepairAttemptAdmission::Reserved(ref receipt) if receipt.attempt_number == 1)
        );
        let authenticator = repository_auth_writer(&repo)
            .unwrap()
            .into_authenticator()
            .unwrap();
        let journal = RepairAttemptJournal::open_instance(
            authenticator,
            &instance_id(&provider_repository_id(), 17).unwrap(),
        )
        .unwrap();
        let event: ReservedAttempt =
            serde_json::from_value(journal.records()[0].payload.clone()).unwrap();
        assert_eq!(event.inbox_run_id, "failed-run");
        assert_eq!(event.head_oid, "a".repeat(40));
        assert_eq!(event.policy_max_attempts, 2);
        if let RepairAttemptAdmission::Reserved(receipt) = &first {
            assert_eq!(receipt.journal_id, journal.identity().journal_id);
            assert_eq!(receipt.record_mac, journal.records()[0].mac.as_str());
        }
        drop(journal);
        let second =
            reserve_fixture(&repo, 17, "refused-run", &"c".repeat(40), "policy-b", 2).unwrap();
        assert!(
            matches!(second, RepairAttemptAdmission::Reserved(ref receipt) if receipt.attempt_number == 2)
        );
        assert_eq!(
            reserve_fixture(
                &repo,
                17,
                "interrupted-retry",
                &"d".repeat(40),
                "policy-c",
                2
            )
            .unwrap(),
            RepairAttemptAdmission::Exhausted {
                spent: 2,
                max_attempts: 2,
            }
        );
        // A stricter newly frozen operator policy cannot reset the logical PR.
        assert_eq!(
            reserve_fixture(&repo, 17, "lower-policy", &"e".repeat(40), "policy-d", 1).unwrap(),
            RepairAttemptAdmission::Exhausted {
                spent: 2,
                max_attempts: 1,
            }
        );
        // A different PR number is a different logical source.
        assert!(matches!(
            reserve_fixture(&repo, 18, "other-pr", &"e".repeat(40), "policy-d", 1).unwrap(),
            RepairAttemptAdmission::Reserved(_)
        ));
    }

    #[test]
    fn uncertain_or_replayed_run_remains_spent_without_an_outcome_claim() {
        let (_temp, repo) = fixture_repo();
        let first =
            reserve_fixture(&repo, 24, "interrupted", &"a".repeat(40), "policy", 2).unwrap();
        assert!(matches!(first, RepairAttemptAdmission::Reserved(_)));
        // The reservation has no finalized Inbox outcome. Its absence cannot
        // release the slot, and the same run ID cannot mint a second slot.
        assert!(reserve_fixture(&repo, 24, "interrupted", &"a".repeat(40), "policy", 2).is_err());
        let next = reserve_fixture(&repo, 24, "new-run", &"c".repeat(40), "policy", 2).unwrap();
        assert!(
            matches!(next, RepairAttemptAdmission::Reserved(ref receipt) if receipt.attempt_number == 2)
        );
    }

    #[test]
    fn foreign_repository_and_tampered_record_refuse_authenticated_replay() {
        let (_temp, repo) = fixture_repo();
        let (_other_temp, other_repo) = fixture_repo();
        reserve_fixture(&repo, 31, "first", &"a".repeat(40), "policy", 2).unwrap();
        let authenticator = repository_auth_writer(&repo)
            .unwrap()
            .into_authenticator()
            .unwrap();
        let journal = RepairAttemptJournal::open_instance(
            authenticator,
            &instance_id(&provider_repository_id(), 31).unwrap(),
        )
        .unwrap();
        let identity = journal.identity().clone();
        let record_path = journal
            .root()
            .path()
            .join(instance_id(&provider_repository_id(), 31).unwrap())
            .join("00000000000000000001.json");
        drop(journal);
        let foreign = repository_auth_writer(&other_repo)
            .unwrap()
            .into_authenticator()
            .unwrap();
        assert!(RepairAttemptJournal::open(foreign, &identity).is_err());
        let mut bytes = fs::read(&record_path).unwrap();
        let offset = bytes.iter().position(|byte| *byte == b'a').unwrap();
        bytes[offset] = b'f';
        fs::write(&record_path, bytes).unwrap();
        assert!(reserve_fixture(&repo, 31, "after-tamper", &"c".repeat(40), "policy", 2).is_err());
    }

    #[test]
    fn authenticated_unknown_event_refuses_before_another_reservation() {
        let (_temp, repo) = fixture_repo();
        reserve_fixture(&repo, 32, "first", &"a".repeat(40), "policy", 2).unwrap();
        let authenticator = repository_auth_writer(&repo)
            .unwrap()
            .into_authenticator()
            .unwrap();
        let mut journal = RepairAttemptJournal::open_instance(
            authenticator,
            &instance_id(&provider_repository_id(), 32).unwrap(),
        )
        .unwrap();
        journal
            .append("unknown", None, &serde_json::json!({"version": 1}))
            .unwrap();
        drop(journal);
        assert!(reserve_fixture(&repo, 32, "after-unknown", &"c".repeat(40), "policy", 2).is_err());
    }

    #[test]
    fn competing_reservations_never_exceed_one_operator_slot() {
        let (_temp, repo) = fixture_repo();
        // Initialize repository authentication before the competing openings.
        repository_auth_writer(&repo).unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let results = std::thread::scope(|scope| {
            let handles = (0..2)
                .map(|index| {
                    let barrier = Arc::clone(&barrier);
                    let repo = &repo;
                    scope.spawn(move || {
                        barrier.wait();
                        reserve_fixture(
                            repo,
                            44,
                            &format!("raced-{index}"),
                            &"a".repeat(40),
                            "policy",
                            1,
                        )
                    })
                })
                .collect::<Vec<_>>();
            barrier.wait();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Ok(RepairAttemptAdmission::Reserved(_))))
                .count(),
            1
        );
        assert_eq!(
            reserve_fixture(&repo, 44, "later", &"c".repeat(40), "policy", 1).unwrap(),
            RepairAttemptAdmission::Exhausted {
                spent: 1,
                max_attempts: 1
            }
        );
    }
}
