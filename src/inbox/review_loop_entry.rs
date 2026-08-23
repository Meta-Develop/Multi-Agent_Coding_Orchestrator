//! Inbox-facing caller for the #90 review-loop state machine.
//!
//! `maco inbox scan` and `maco inbox run` reach [`open_review_loop`] through
//! this module. The loop snapshots PR review state and emits readiness
//! evidence. It never grants merge permission and never performs a merge.

use super::review_loop::{
    open_review_loop, ReadinessBlocker, RequiredCheck, ReviewLoopPhase, ReviewLoopPolicy,
    ReviewLoopReadinessEvaluation, ReviewLoopState, TrustedActorBinding, TrustedActorIdentity,
    TrustedActorRole,
};
use super::{GithubCheckSummary, GithubPrCandidate, InboxItem, InboxItemKind, InboxSourceProvider};
use crate::publication::forge_transport::{
    FakeForgeTransport, ForgeActor, ForgeCheck, ForgeCheckConclusion, ForgeCheckStatus, ForgeItem,
    ForgeItemKind, ForgeObservation, ForgeObservationRequest, ForgeRepository, ForgeReview,
    ForgeReviewState, ForgeTimestamp, ProviderObjectId, ProviderObjectKind,
    PullRequestReviewSnapshot, ReportedActorKind,
};
use anyhow::{bail, Context, Result};
use serde::Serialize;

/// Compact public evidence that inbox scan/run attached a review loop to a PR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InboxReviewLoopReport {
    pub item_id: String,
    pub source_key: String,
    pub number: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<ReviewLoopPhase>,
    pub ready: bool,
    pub grants_merge_permission: bool,
    pub auto_merge_performed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocker_kinds: Vec<String>,
    pub next_action: String,
}

/// Evaluate every pull-request candidate through [`open_review_loop`].
///
/// Issues are skipped. Observation failures become blocked reports; they do
/// not abort inbox scan or run.
pub fn evaluate_inbox_scan_review_loops(items: &[InboxItem]) -> Vec<InboxReviewLoopReport> {
    items
        .iter()
        .filter_map(evaluate_inbox_item_review_loop)
        .collect()
}

/// Open the review loop for one inbox item when it is a pull request.
pub fn evaluate_inbox_item_review_loop(item: &InboxItem) -> Option<InboxReviewLoopReport> {
    if item.kind != InboxItemKind::PullRequest || item.pull_request.is_none() {
        return None;
    }
    Some(evaluate_pull_request_review_loop(item))
}

fn evaluate_pull_request_review_loop(item: &InboxItem) -> InboxReviewLoopReport {
    match open_inbox_item_review_loop(item) {
        Ok(state) => report_from_state(item, &state),
        Err(_) => InboxReviewLoopReport {
            item_id: item.item_id.clone(),
            source_key: item.source_key.clone(),
            number: item.source_snapshot.number(),
            phase: None,
            ready: false,
            grants_merge_permission: false,
            auto_merge_performed: false,
            state_sha256: None,
            snapshot_sha256: None,
            policy_sha256: None,
            blocker_kinds: vec!["observation_failed".to_string()],
            next_action: "repair review-loop observation inputs, then scan again".to_string(),
        },
    }
}

fn open_inbox_item_review_loop(item: &InboxItem) -> Result<ReviewLoopState> {
    let synthesized = synthesize_inbox_review_observation(item)?;
    let request = ForgeObservationRequest::pull_request_review_snapshot(synthesized.item.clone())
        .context("review-loop observation request")?;
    let mut transport = FakeForgeTransport::new();
    transport
        .register_observation(
            request,
            ForgeObservation::PullRequestReviewSnapshot(synthesized.snapshot),
        )
        .context("register inbox review-loop observation")?;
    open_review_loop(
        &transport,
        &synthesized.item,
        synthesized.policy,
        &synthesized.observed_at,
    )
}

struct SynthesizedReviewObservation {
    item: ForgeItem,
    snapshot: PullRequestReviewSnapshot,
    policy: ReviewLoopPolicy,
    observed_at: ForgeTimestamp,
}

fn synthesize_inbox_review_observation(item: &InboxItem) -> Result<SynthesizedReviewObservation> {
    let pull_request = item
        .pull_request
        .as_ref()
        .context("inbox review loop requires pull-request metadata")?;
    let provider_id = provider_id(item.source_snapshot.provider());
    let observed_at = ForgeTimestamp::new(item.source_snapshot.updated_at())
        .context("inbox review-loop observation timestamp")?;
    let head_oid = item
        .source_snapshot
        .head_oid()
        .context("inbox review loop requires a PR head OID")?
        .to_owned();
    let base_oid = item
        .source_snapshot
        .base_oid()
        .context("inbox review loop requires a PR base OID")?
        .to_owned();
    let repository = ForgeRepository::new(
        provider_id,
        repository_locator(item)?,
        object_id(
            provider_id,
            ProviderObjectKind::Repository,
            format!("repo:{}", item.source_snapshot.repository_identity()),
        )?,
    )?;
    let forge_item = ForgeItem::new(
        repository,
        ForgeItemKind::PullRequest,
        item.source_snapshot.number(),
        object_id(
            provider_id,
            ProviderObjectKind::Item,
            format!("pull:{}", item.source_snapshot.number()),
        )?,
        item.source_snapshot.action_revision_digest().to_owned(),
        Some(head_oid.clone()),
        Some(base_oid),
    )?;
    let reviewers = reviewer_handles(pull_request);
    let check_handle = check_actor_handle(&reviewers);
    let human_actors = reviewers
        .iter()
        .map(|handle| forge_actor(provider_id, handle, ReportedActorKind::Human))
        .collect::<Result<Vec<_>>>()?;
    let check_actor = forge_actor(provider_id, &check_handle, ReportedActorKind::Bot)?;
    let reviews = synthesize_reviews(
        provider_id,
        item.source_snapshot.number(),
        &head_oid,
        &observed_at,
        pull_request,
        &human_actors,
    )?;
    let checks = synthesize_checks(
        provider_id,
        item.source_snapshot.number(),
        &head_oid,
        &observed_at,
        pull_request,
        &check_actor,
    )?;
    let snapshot = PullRequestReviewSnapshot::new(
        forge_item.clone(),
        observed_at.clone(),
        reviews,
        Vec::new(),
        checks,
    )?;
    let policy = inbox_review_loop_policy(&human_actors, &check_actor, pull_request)?;
    Ok(SynthesizedReviewObservation {
        item: forge_item,
        snapshot,
        policy,
        observed_at,
    })
}

fn inbox_review_loop_policy(
    humans: &[ForgeActor],
    check_actor: &ForgeActor,
    pull_request: &GithubPrCandidate,
) -> Result<ReviewLoopPolicy> {
    let mut trusted = humans
        .iter()
        .map(|actor| {
            TrustedActorBinding::new(identity_from_actor(actor)?, TrustedActorRole::HumanBlocking)
        })
        .collect::<Result<Vec<_>>>()?;
    trusted.push(TrustedActorBinding::new(
        identity_from_actor(check_actor)?,
        TrustedActorRole::BotAdvisory,
    )?);
    let check_identity = identity_from_actor(check_actor)?;
    let mut required = pull_request
        .checks
        .iter()
        .filter_map(|check| canonical_check_name(&check.name))
        .map(|name| RequiredCheck::new(name, vec![check_identity.clone()]))
        .collect::<Result<Vec<_>>>()?;
    if required.is_empty() {
        required.push(RequiredCheck::new(
            "inbox-required-check",
            vec![check_identity],
        )?);
    }
    ReviewLoopPolicy::new(trusted, required, 1, 3)
}

fn synthesize_reviews(
    provider_id: &str,
    number: u64,
    head_oid: &str,
    observed_at: &ForgeTimestamp,
    pull_request: &GithubPrCandidate,
    humans: &[ForgeActor],
) -> Result<Vec<ForgeReview>> {
    if humans.is_empty() {
        return Ok(Vec::new());
    }
    let state = review_state(pull_request);
    humans
        .iter()
        .enumerate()
        .map(|(index, actor)| {
            let summary = pull_request
                .review_feedback
                .summaries
                .get(index)
                .cloned()
                .unwrap_or_else(|| "inbox review observation".to_string());
            ForgeReview::new(
                object_id(
                    provider_id,
                    ProviderObjectKind::Review,
                    format!("review:{number}:{}", index.saturating_add(1)),
                )?,
                actor.clone(),
                state,
                summary,
                observed_at.clone(),
                head_oid,
            )
        })
        .collect()
}

fn synthesize_checks(
    provider_id: &str,
    number: u64,
    head_oid: &str,
    observed_at: &ForgeTimestamp,
    pull_request: &GithubPrCandidate,
    check_actor: &ForgeActor,
) -> Result<Vec<ForgeCheck>> {
    pull_request
        .checks
        .iter()
        .enumerate()
        .filter_map(|(index, check)| {
            canonical_check_name(&check.name).map(|name| (index, name, check))
        })
        .map(|(index, name, check)| {
            let (status, conclusion) = check_status_and_conclusion(check);
            ForgeCheck::new(
                object_id(
                    provider_id,
                    ProviderObjectKind::Check,
                    format!("check:{number}:{}", index.saturating_add(1)),
                )?,
                check_actor.clone(),
                name,
                status,
                conclusion,
                head_oid,
                observed_at.clone(),
            )
        })
        .collect()
}

fn report_from_state(item: &InboxItem, state: &ReviewLoopState) -> InboxReviewLoopReport {
    let readiness = match state.readiness() {
        Ok(readiness) => readiness,
        Err(_) => {
            return InboxReviewLoopReport {
                item_id: item.item_id.clone(),
                source_key: item.source_key.clone(),
                number: item.source_snapshot.number(),
                phase: Some(state.phase()),
                ready: false,
                grants_merge_permission: false,
                auto_merge_performed: false,
                state_sha256: Some(state.state_sha256().to_owned()),
                snapshot_sha256: Some(state.current_snapshot().canonical_sha256().to_owned()),
                policy_sha256: Some(state.policy_sha256().to_owned()),
                blocker_kinds: vec!["readiness_evaluation_failed".to_string()],
                next_action: "inspect review-loop readiness evaluation failure; no automatic merge was performed".to_string(),
            };
        }
    };
    let (ready, blocker_kinds) = match &readiness {
        ReviewLoopReadinessEvaluation::Ready(proof) => {
            debug_assert!(
                !proof.grants_merge_permission(),
                "review-loop readiness must not grant merge permission"
            );
            (true, Vec::new())
        }
        ReviewLoopReadinessEvaluation::Blocked(blocked) => (
            false,
            blocked
                .blockers()
                .iter()
                .map(blocker_kind)
                .map(str::to_owned)
                .collect(),
        ),
    };
    InboxReviewLoopReport {
        item_id: item.item_id.clone(),
        source_key: item.source_key.clone(),
        number: item.source_snapshot.number(),
        phase: Some(state.phase()),
        ready,
        grants_merge_permission: false,
        auto_merge_performed: false,
        state_sha256: Some(state.state_sha256().to_owned()),
        snapshot_sha256: Some(state.current_snapshot().canonical_sha256().to_owned()),
        policy_sha256: Some(state.policy_sha256().to_owned()),
        blocker_kinds,
        next_action: if ready {
            "review-loop readiness evidence is available; it is not merge permission".to_string()
        } else {
            "review-loop readiness is blocked; no automatic merge was performed".to_string()
        },
    }
}

fn provider_id(provider: InboxSourceProvider) -> &'static str {
    match provider {
        InboxSourceProvider::Fake => "fake",
        InboxSourceProvider::Github => "github",
    }
}

fn repository_locator(item: &InboxItem) -> Result<String> {
    match item.source_snapshot.provider() {
        InboxSourceProvider::Fake => Ok("fake.local/maco/inbox".to_string()),
        InboxSourceProvider::Github => {
            let selector = item
                .source_snapshot
                .repository_selector()
                .to_ascii_lowercase();
            if forge_locator_is_canonical(&selector) {
                return Ok(selector);
            }
            let combined = format!(
                "{}/{}",
                item.source_snapshot.repository_host().to_ascii_lowercase(),
                item.source_snapshot
                    .repository_selector()
                    .to_ascii_lowercase()
            );
            if forge_locator_is_canonical(&combined) {
                Ok(combined)
            } else {
                bail!("inbox review loop requires a canonical forge repository locator")
            }
        }
    }
}

fn forge_locator_is_canonical(value: &str) -> bool {
    let components = value.split('/').collect::<Vec<_>>();
    components.len() >= 3
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains("//")
        && components.iter().all(|component| {
            !component.is_empty()
                && *component != "."
                && *component != ".."
                && component.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'_' | b'.')
                })
        })
}

fn reviewer_handles(pull_request: &GithubPrCandidate) -> Vec<String> {
    let mut handles = pull_request
        .review_feedback
        .reviewer_logins
        .iter()
        .filter_map(|login| canonicalize_handle(login))
        .collect::<Vec<_>>();
    if handles.is_empty()
        && (pull_request.review_feedback.requested_changes
            || pull_request.review_feedback.review_decision.is_some())
    {
        handles.push("inbox-reviewer".to_string());
    }
    handles.sort();
    handles.dedup();
    handles
}

fn check_actor_handle(reviewers: &[String]) -> String {
    if reviewers.iter().any(|handle| handle == "inbox-checks") {
        "inbox-check-actor".to_string()
    } else {
        "inbox-checks".to_string()
    }
}

fn canonicalize_handle(raw: &str) -> Option<String> {
    let handle = raw.trim().trim_start_matches('@').to_ascii_lowercase();
    if handle.is_empty()
        || handle.len() > 128
        || !handle.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
    {
        return None;
    }
    Some(handle)
}

fn canonical_check_name(name: &str) -> Option<String> {
    let name = name.trim();
    if name.is_empty()
        || name.len() > 256
        || name
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return None;
    }
    Some(name.to_owned())
}

fn review_state(pull_request: &GithubPrCandidate) -> ForgeReviewState {
    let decision = pull_request
        .review_feedback
        .review_decision
        .as_deref()
        .map(str::to_ascii_lowercase);
    if pull_request.review_feedback.requested_changes
        || decision.as_deref() == Some("changes_requested")
    {
        ForgeReviewState::ChangesRequested
    } else if decision.as_deref() == Some("approved") {
        ForgeReviewState::Approved
    } else {
        ForgeReviewState::Commented
    }
}

fn check_status_and_conclusion(
    check: &GithubCheckSummary,
) -> (ForgeCheckStatus, Option<ForgeCheckConclusion>) {
    let status = match check
        .status
        .as_deref()
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("queued") => ForgeCheckStatus::Queued,
        Some("in_progress" | "inprogress" | "pending") => ForgeCheckStatus::InProgress,
        _ => ForgeCheckStatus::Completed,
    };
    if status != ForgeCheckStatus::Completed {
        return (status, None);
    }
    let conclusion = match check
        .conclusion
        .as_deref()
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("success" | "successful" | "passed" | "pass") => ForgeCheckConclusion::Success,
        Some("neutral") => ForgeCheckConclusion::Neutral,
        Some("cancelled" | "canceled") => ForgeCheckConclusion::Cancelled,
        Some("skipped") => ForgeCheckConclusion::Skipped,
        Some("timed_out" | "timeout") => ForgeCheckConclusion::TimedOut,
        Some("action_required") => ForgeCheckConclusion::ActionRequired,
        Some("startup_failure") => ForgeCheckConclusion::StartupFailure,
        Some("stale") => ForgeCheckConclusion::Stale,
        _ => ForgeCheckConclusion::Failure,
    };
    (ForgeCheckStatus::Completed, Some(conclusion))
}

fn forge_actor(provider_id: &str, handle: &str, kind: ReportedActorKind) -> Result<ForgeActor> {
    ForgeActor::new(
        provider_id,
        object_id(
            provider_id,
            ProviderObjectKind::Actor,
            format!("actor:{handle}"),
        )?,
        handle,
        kind,
    )
}

fn identity_from_actor(actor: &ForgeActor) -> Result<TrustedActorIdentity> {
    TrustedActorIdentity::new(
        actor.provider_actor_id().clone(),
        actor.canonical_handle(),
        actor.reported_kind(),
    )
}

fn object_id(
    provider_id: &str,
    kind: ProviderObjectKind,
    stable_id: impl Into<String>,
) -> Result<ProviderObjectId> {
    ProviderObjectId::new(provider_id, kind, stable_id)
}

fn blocker_kind(blocker: &ReadinessBlocker) -> &'static str {
    match blocker {
        ReadinessBlocker::AttemptLimitExhausted { .. } => "attempt_limit_exhausted",
        ReadinessBlocker::UnsupportedThreadCurrencyMetadata => {
            "unsupported_thread_currency_metadata"
        }
        ReadinessBlocker::AmbiguousHumanReviewCurrency(_) => "ambiguous_human_review_currency",
        ReadinessBlocker::UntrustedActor(_) => "untrusted_actor",
        ReadinessBlocker::BlockingHumanFeedback(_) => "blocking_human_feedback",
        ReadinessBlocker::MissingCheck(_) => "missing_check",
        ReadinessBlocker::NonSuccessCheck(_) => "non_success_check",
        ReadinessBlocker::AmbiguousCheck(_) => "ambiguous_check",
        ReadinessBlocker::InsufficientApproval(_) => "insufficient_approval",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inbox::{
        run_inbox, scan_inbox, DuplicateDetectionResult, GithubReviewFeedbackSummary,
        InboxRunOptions, InboxScanOptions, InboxSourceSnapshotBinding, PrivacyScanResult,
    };
    use crate::llm::RedactionSummary;
    use crate::orchestrator::RunId;
    use crate::publication;
    use crate::worktree::WorktreeManager;
    use tempfile::TempDir;

    #[test]
    fn scan_inbox_opens_the_review_loop_for_the_fake_pull_request() {
        let (_temp, repo) = temp_repo();
        let report = scan_inbox(InboxScanOptions {
            repo,
            github: false,
            permission_mode: None,
            max_items: Some(4),
            action_policy_override: None,
        })
        .expect("scan inbox");

        let review_loop = report
            .review_loops
            .iter()
            .find(|entry| entry.number == 202)
            .expect("fake PR review loop");
        assert_eq!(review_loop.item_id, "pr-202");
        assert_eq!(review_loop.phase, Some(ReviewLoopPhase::Active));
        assert!(!review_loop.ready);
        assert!(!review_loop.grants_merge_permission);
        assert!(!review_loop.auto_merge_performed);
        assert!(review_loop.state_sha256.is_some());
        assert!(review_loop.snapshot_sha256.is_some());
        assert!(review_loop.policy_sha256.is_some());
        assert!(review_loop
            .blocker_kinds
            .iter()
            .any(|kind| kind == "blocking_human_feedback" || kind == "non_success_check"));
        assert!(review_loop
            .next_action
            .contains("no automatic merge was performed"));
    }

    #[test]
    fn run_inbox_dry_run_attaches_review_loop_to_the_fake_pull_request() {
        let (_temp, repo) = temp_repo();
        let report = run_inbox(InboxRunOptions {
            repo,
            run_id: RunId::new("review-loop-dry-run").expect("run id"),
            github: false,
            permission_mode: None,
            dry_run: true,
            max_items: Some(4),
            codex_bin: None,
            machine_global: None,
        })
        .expect("run inbox");

        let review_loop = report
            .item_reports
            .iter()
            .find_map(|item| item.review_loop.as_ref())
            .expect("PR review loop");
        assert_eq!(review_loop.item_id, "pr-202");
        assert_eq!(review_loop.phase, Some(ReviewLoopPhase::Active));
        assert!(!review_loop.ready);
        assert!(!review_loop.grants_merge_permission);
        assert!(!review_loop.auto_merge_performed);
        assert!(!report.auto_merge_performed);
    }

    #[test]
    fn issue_items_do_not_open_a_review_loop() {
        let item = InboxItem {
            item_id: "issue-7".to_string(),
            source_key: "github_issue:7".to_string(),
            source_snapshot: InboxSourceSnapshotBinding::for_issue(
                InboxSourceProvider::Fake,
                "fake",
                ".",
                publication::stable_external_digest(b"inbox-review-loop-issue"),
                7,
                "1970-01-01T00:00:00Z",
                "OPEN",
                "3".repeat(64),
                "4".repeat(64),
            )
            .expect("issue snapshot"),
            kind: InboxItemKind::Issue,
            title: "Issue".to_string(),
            url: None,
            issue: None,
            pull_request: None,
            privacy: safe_privacy(),
            duplicate: DuplicateDetectionResult {
                duplicate: false,
                key: "github_issue:7".to_string(),
                matched_run_id: None,
                reason: None,
            },
            selected: true,
            skip_reason: None,
        };
        assert!(evaluate_inbox_item_review_loop(&item).is_none());
    }

    #[test]
    fn ready_review_loop_still_refuses_merge_permission() {
        let item = ready_pr_item();
        let report = evaluate_inbox_item_review_loop(&item).expect("PR review loop");
        assert_eq!(report.phase, Some(ReviewLoopPhase::Ready));
        assert!(report.ready);
        assert!(!report.grants_merge_permission);
        assert!(!report.auto_merge_performed);
        assert_eq!(
            report.next_action,
            "review-loop readiness evidence is available; it is not merge permission"
        );
    }

    fn ready_pr_item() -> InboxItem {
        InboxItem {
            item_id: "pr-9".to_string(),
            source_key: "github_pr:9".to_string(),
            source_snapshot: InboxSourceSnapshotBinding::for_pull_request(
                InboxSourceProvider::Fake,
                "fake",
                ".",
                publication::stable_external_digest(b"inbox-review-loop-ready"),
                9,
                "1970-01-01T00:00:00Z",
                "OPEN",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
                "3".repeat(64),
                "4".repeat(64),
            )
            .expect("PR snapshot"),
            kind: InboxItemKind::PullRequest,
            title: "Ready PR".to_string(),
            url: None,
            issue: None,
            pull_request: Some(GithubPrCandidate {
                number: 9,
                title: "Ready PR".to_string(),
                url: None,
                author: Some("maco-fake".to_string()),
                labels: Vec::new(),
                updated_at: Some("1970-01-01T00:00:00Z".to_string()),
                head_ref: None,
                base_ref: None,
                changed_files: Vec::new(),
                checks: vec![GithubCheckSummary {
                    name: "fake-ci".to_string(),
                    status: Some("completed".to_string()),
                    conclusion: Some("success".to_string()),
                    details_url: None,
                    summary: "ok".to_string(),
                }],
                review_feedback: GithubReviewFeedbackSummary {
                    review_decision: Some("APPROVED".to_string()),
                    requested_changes: false,
                    unresolved_thread_count: None,
                    reviewer_logins: vec!["maco-fake-reviewer".to_string()],
                    summaries: vec!["approved".to_string()],
                },
                body_summary: String::new(),
                body_truncated: false,
            }),
            privacy: safe_privacy(),
            duplicate: DuplicateDetectionResult {
                duplicate: false,
                key: "github_pr:9".to_string(),
                matched_run_id: None,
                reason: None,
            },
            selected: true,
            skip_reason: None,
        }
    }

    fn safe_privacy() -> PrivacyScanResult {
        PrivacyScanResult {
            safe: true,
            reasons: Vec::new(),
            redactions: RedactionSummary::default(),
            body_summary: String::new(),
            body_truncated: false,
        }
    }

    fn temp_repo() -> (TempDir, std::path::PathBuf) {
        let temp = TempDir::new().expect("tempdir");
        let repo = temp.path().join("repo");
        WorktreeManager::init_repository(&repo, "main").expect("init repo");
        (temp, repo)
    }
}
