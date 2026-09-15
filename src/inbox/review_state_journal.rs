//! Repository-authenticated continuity for one provider PR's review state.
//!
//! This is deliberately separate from repair-attempt admission. An observation
//! records review evidence; it neither spends a repair slot nor grants merge.

use super::review_loop::{
    FrozenReviewSnapshot, ReviewLoopPhase, ReviewLoopPolicy, ReviewLoopState,
};
use crate::{
    artifacts::{repository_auth_writer, state_auth::sha256_hex},
    publication::forge_transport::ForgeTimestamp,
    state_journal::{CheckpointJournalSpec, JournalSpec, StateJournal},
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{fmt, path::Path};

const VERSION: u32 = 2;
const KEY_DOMAIN: &[u8] = b"MACO\0inbox-review-state-key\0v1\0";
const PHASE_STATE: &str = "review_state_observed";
const PHASE_WATERMARK: &str = "review_state_collection_watermark";

#[derive(Debug)]
pub(super) struct ReviewStateRefreshBlocked(pub(super) String);

impl fmt::Display for ReviewStateRefreshBlocked {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "review state requires verified dispositions: {}",
            self.0
        )
    }
}

impl std::error::Error for ReviewStateRefreshBlocked {}

#[derive(Serialize)]
struct LogicalPrKey<'a> {
    provider: &'a str,
    provider_repository_id: &'a str,
    number: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StateEvent {
    version: u32,
    provider: String,
    provider_repository_id: String,
    number: u64,
    previous_state_sha256: Option<String>,
    provider_observed_at: String,
    collection_started_at: String,
    state: serde_json::Value,
}

struct ReplayCursor {
    state: Option<ReviewLoopState>,
    last_collection_started_at: Option<ForgeTimestamp>,
}

fn same_pr(left: &FrozenReviewSnapshot, right: &FrozenReviewSnapshot) -> bool {
    left.item().repository() == right.item().repository()
        && left.item().number() == right.item().number()
        && left.item().provider_item_id() == right.item().provider_item_id()
}

fn same_provider_evidence(left: &FrozenReviewSnapshot, right: &FrozenReviewSnapshot) -> bool {
    let left = left.snapshot();
    let right = right.snapshot();
    left.item() == right.item()
        && left.reviews() == right.reviews()
        && left.threads() == right.threads()
        && left.checks() == right.checks()
}

fn parse_event_timestamp(label: &str, value: &str) -> Result<ForgeTimestamp> {
    ForgeTimestamp::new(value).with_context(|| format!("{label} is not a valid timestamp"))
}

fn validate_provider_collection_bounds(
    provider_observed_at: &ForgeTimestamp,
    collection_started_at: &ForgeTimestamp,
) -> Result<()> {
    if provider_observed_at > collection_started_at {
        bail!("provider review observation postdates trusted collection watermark");
    }
    Ok(())
}

fn instance_id(snapshot: &FrozenReviewSnapshot) -> Result<String> {
    let item = snapshot.item();
    let key = LogicalPrKey {
        provider: item.repository().provider_id(),
        provider_repository_id: item.repository().provider_repository_id().stable_id(),
        number: item.number(),
    };
    let mut key_bytes = KEY_DOMAIN.to_vec();
    key_bytes.extend(serde_json::to_vec(&key)?);
    Ok(format!("review-loop-{}", sha256_hex(&key_bytes)))
}

fn validate_replayed_state_event(
    prior: &ReviewLoopState,
    state: &ReviewLoopState,
    collection_started_at: &ForgeTimestamp,
    trusted_not_after: &ForgeTimestamp,
) -> Result<()> {
    if state.current_snapshot().observed_at() != collection_started_at {
        bail!("authenticated review-state snapshot timestamp does not match collection watermark");
    }
    if state.policy_sha256() != prior.policy_sha256() {
        bail!("authenticated review-state journal changed policy without migration");
    }
    if !same_pr(state.current_snapshot(), prior.current_snapshot()) {
        bail!("authenticated review-state record belongs to another PR");
    }
    match prior.phase() {
        ReviewLoopPhase::Active => {
            if state.predecessor_state_sha256() != Some(prior.state_sha256())
                || state.attempts().len() != prior.attempts().len() + 1
            {
                bail!("authenticated active review-state refresh lost continuity");
            }
        }
        ReviewLoopPhase::Ready | ReviewLoopPhase::Exhausted => {
            if prior.phase() == ReviewLoopPhase::Exhausted
                && !prior
                    .current_snapshot()
                    .triage(prior.policy())
                    .blocking_human_feedback()
                    .is_empty()
            {
                bail!("authenticated exhausted review state lost required dispositions");
            }
            if state.predecessor_state_sha256().is_some()
                || !state.attempts().is_empty()
                || !state.dispositions().is_empty()
            {
                bail!("authenticated terminal review-state reset retained old evidence");
            }
        }
    }
    state
        .current_snapshot()
        .validate_not_after(trusted_not_after)
        .context("authenticated review-state record failed structural validation")?;
    Ok(())
}

fn replay(
    journal: &StateJournal,
    snapshot: &FrozenReviewSnapshot,
    trusted_not_after: &ForgeTimestamp,
) -> Result<ReplayCursor> {
    let item = snapshot.item();
    let mut previous: Option<ReviewLoopState> = None;
    let mut last_collection_started_at: Option<ForgeTimestamp> = None;
    for record in journal.records() {
        if record.subject.is_some() {
            bail!("authenticated review-state journal contains an unknown event");
        }
        let event: StateEvent = serde_json::from_value(record.payload.clone())
            .context("authenticated review-state event is malformed")?;
        if event.version != VERSION {
            bail!("authenticated review-state event missing collection watermark evidence");
        }
        if event.provider != item.repository().provider_id()
            || event.provider_repository_id
                != item.repository().provider_repository_id().stable_id()
            || event.number != item.number()
            || event.previous_state_sha256.as_deref()
                != previous.as_ref().map(ReviewLoopState::state_sha256)
        {
            bail!("authenticated review-state event changed its logical PR or state chain");
        }
        let provider_observed_at =
            parse_event_timestamp("provider_observed_at", &event.provider_observed_at)?;
        let collection_started_at =
            parse_event_timestamp("collection_started_at", &event.collection_started_at)?;
        validate_provider_collection_bounds(&provider_observed_at, &collection_started_at)?;
        if let Some(last) = &last_collection_started_at {
            if collection_started_at <= *last {
                bail!("authenticated review-state collection watermark was replayed or reordered");
            }
        }
        let bytes = serde_json::to_vec(&event.state)?;
        let state = ReviewLoopState::restore_json(&bytes, trusted_not_after)
            .context("authenticated review-state record failed structural validation")?;
        if !same_pr(state.current_snapshot(), snapshot) {
            bail!("authenticated review-state record belongs to another PR");
        }
        match record.phase.as_str() {
            PHASE_WATERMARK => {
                let prior = previous.as_ref().context(
                    "authenticated review-state collection watermark precedes initial state",
                )?;
                if state.state_sha256() != prior.state_sha256() {
                    bail!("authenticated review-state collection watermark changed durable state");
                }
                if state.current_snapshot().observed_at() != prior.current_snapshot().observed_at()
                {
                    bail!(
                        "authenticated review-state collection watermark changed stamped snapshot"
                    );
                }
            }
            PHASE_STATE => {
                if state.current_snapshot().observed_at() != &collection_started_at {
                    bail!("authenticated review-state snapshot timestamp does not match collection watermark");
                }
                if let Some(prior) = &previous {
                    validate_replayed_state_event(
                        prior,
                        &state,
                        &collection_started_at,
                        trusted_not_after,
                    )?;
                } else if state.predecessor_state_sha256().is_some() || !state.attempts().is_empty()
                {
                    bail!("first authenticated review-state event is not an initial state");
                }
            }
            _ => bail!("authenticated review-state journal contains an unknown event"),
        }
        last_collection_started_at = Some(collection_started_at);
        previous = Some(state);
    }
    Ok(ReplayCursor {
        state: previous,
        last_collection_started_at,
    })
}

fn append_event(journal: &mut StateJournal, phase: &str, event: &StateEvent) -> Result<()> {
    journal
        .append(phase, None, event)
        .map(|_| ())
        .with_context(|| format!(
            "failed to persist authenticated review state before readiness (journal bounds: {} bytes per record, {} bytes total, {} records)",
            <CheckpointJournalSpec as JournalSpec>::MAX_RECORD_BYTES,
            <CheckpointJournalSpec as JournalSpec>::MAX_TOTAL_BYTES,
            <CheckpointJournalSpec as JournalSpec>::MAX_RECORDS,
        ))
}

fn build_event(
    key: &LogicalPrKey<'_>,
    prior: Option<&ReviewLoopState>,
    provider_snapshot: &FrozenReviewSnapshot,
    collection_started_at: &ForgeTimestamp,
    state: &ReviewLoopState,
) -> Result<StateEvent> {
    Ok(StateEvent {
        version: VERSION,
        provider: key.provider.to_string(),
        provider_repository_id: key.provider_repository_id.to_string(),
        number: key.number,
        previous_state_sha256: prior.map(|prior| prior.state_sha256().to_string()),
        provider_observed_at: provider_snapshot.observed_at().as_str().to_string(),
        collection_started_at: collection_started_at.as_str().to_string(),
        state: serde_json::to_value(state)?,
    })
}

pub(super) fn observe(
    repo: &Path,
    provider_snapshot: &FrozenReviewSnapshot,
    policy: &ReviewLoopPolicy,
    collection_started_at: &ForgeTimestamp,
) -> Result<ReviewLoopState> {
    provider_snapshot.validate_not_after(collection_started_at)?;
    let item = provider_snapshot.item();
    let key = LogicalPrKey {
        provider: item.repository().provider_id(),
        provider_repository_id: item.repository().provider_repository_id().stable_id(),
        number: item.number(),
    };
    let authenticator = repository_auth_writer(repo)?
        .into_authenticator()
        .context("failed to bind review-state repository authentication")?;
    let mut journal =
        StateJournal::open_or_initialize(authenticator, &instance_id(provider_snapshot)?)
            .context("authenticated review-state journal is unavailable")?;
    let replay = replay(&journal, provider_snapshot, collection_started_at)?;
    let stamped = provider_snapshot.stamp_for_durable_collection(collection_started_at)?;
    let state = match replay.state.as_ref() {
        None => ReviewLoopState::new(policy.clone(), stamped, collection_started_at)?,
        Some(prior) => {
            if prior.policy_sha256() != policy.canonical_sha256()? {
                bail!("review-state policy changed; explicit migration is required");
            }
            let last_collection = replay
                .last_collection_started_at
                .as_ref()
                .context("authenticated review-state journal missing collection watermark")?;
            if collection_started_at < last_collection {
                bail!("authenticated review collection is stale against persisted watermark");
            }
            let same_evidence = same_provider_evidence(prior.current_snapshot(), provider_snapshot);
            if collection_started_at == last_collection {
                if same_evidence {
                    return Ok(prior.clone());
                }
                bail!("authenticated review collection at equal watermark with changed provider evidence");
            }
            if same_evidence {
                let event = build_event(
                    &key,
                    Some(prior),
                    provider_snapshot,
                    collection_started_at,
                    prior,
                )?;
                append_event(&mut journal, PHASE_WATERMARK, &event)?;
                return Ok(prior.clone());
            }
            if prior.phase() != ReviewLoopPhase::Ready
                && !prior
                    .current_snapshot()
                    .triage(policy)
                    .blocking_human_feedback()
                    .is_empty()
            {
                return Err(ReviewStateRefreshBlocked(
                    "prior blocking human feedback has no verified disposition".to_string(),
                )
                .into());
            }
            match prior.phase() {
                ReviewLoopPhase::Active => prior
                    .refresh_with_snapshot(item, stamped, collection_started_at, Vec::new())
                    .context("authenticated review-state refresh failed")?,
                ReviewLoopPhase::Ready | ReviewLoopPhase::Exhausted => {
                    ReviewLoopState::new(policy.clone(), stamped, collection_started_at)?
                }
            }
        }
    };
    let event = build_event(
        &key,
        replay.state.as_ref(),
        provider_snapshot,
        collection_started_at,
        &state,
    )?;
    append_event(&mut journal, PHASE_STATE, &event)?;
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        inbox::review_loop::{
            RequiredCheck, TrustedActorBinding, TrustedActorIdentity, TrustedActorRole,
        },
        publication::forge_transport::{
            FakeForgeTransport, ForgeActor, ForgeCheck, ForgeCheckConclusion, ForgeCheckStatus,
            ForgeItem, ForgeItemKind, ForgeObservation, ForgeObservationRequest, ForgeRepository,
            ForgeReview, ForgeReviewState, ProviderObjectId, ProviderObjectKind,
            PullRequestReviewSnapshot, ReportedActorKind,
        },
        worktree::WorktreeManager,
    };
    use tempfile::TempDir;

    fn object(kind: ProviderObjectKind, id: &str) -> ProviderObjectId {
        ProviderObjectId::new("github", kind, id).unwrap()
    }

    fn fixture() -> (
        TempDir,
        std::path::PathBuf,
        ReviewLoopPolicy,
        ForgeActor,
        ForgeActor,
    ) {
        let temp = TempDir::new().unwrap();
        let repo = temp.path().join("repo");
        WorktreeManager::init_repository(&repo, "main").unwrap();
        let human = ForgeActor::new(
            "github",
            object(ProviderObjectKind::Actor, "human:1"),
            "reviewer",
            ReportedActorKind::Human,
        )
        .unwrap();
        let bot = ForgeActor::new(
            "github",
            object(ProviderObjectKind::Actor, "bot:1"),
            "checks",
            ReportedActorKind::Bot,
        )
        .unwrap();
        let human_id = TrustedActorIdentity::new(
            human.provider_actor_id().clone(),
            human.canonical_handle(),
            human.reported_kind(),
        )
        .unwrap();
        let bot_id = TrustedActorIdentity::new(
            bot.provider_actor_id().clone(),
            bot.canonical_handle(),
            bot.reported_kind(),
        )
        .unwrap();
        let policy = ReviewLoopPolicy::new(
            vec![TrustedActorBinding::new(human_id, TrustedActorRole::HumanBlocking).unwrap()],
            vec![RequiredCheck::new("ci", vec![bot_id]).unwrap()],
            1,
            3,
        )
        .unwrap();
        (temp, repo, policy, human, bot)
    }

    // Test fixtures expose the two clocks and each independent provider state explicitly.
    #[allow(clippy::too_many_arguments)]
    fn observe_provider(
        provider_observed_at: &str,
        collection_started_at: &ForgeTimestamp,
        head: &str,
        revision: &str,
        approved: bool,
        blocking: bool,
        check_status: ForgeCheckStatus,
        check_conclusion: Option<ForgeCheckConclusion>,
        human: &ForgeActor,
        bot: &ForgeActor,
    ) -> FrozenReviewSnapshot {
        let provider_time = ForgeTimestamp::new(provider_observed_at).unwrap();
        let repository = ForgeRepository::new(
            "github",
            "github.com/acme/example",
            object(ProviderObjectKind::Repository, "repo:1"),
        )
        .unwrap();
        let item = ForgeItem::new(
            repository,
            ForgeItemKind::PullRequest,
            90,
            object(ProviderObjectKind::Item, "pull:90"),
            revision,
            Some(head.to_string()),
            Some("b".repeat(40)),
        )
        .unwrap();
        let reviews = if approved || blocking {
            vec![ForgeReview::new(
                object(
                    ProviderObjectKind::Review,
                    if approved {
                        "review:approved"
                    } else {
                        "review:blocking"
                    },
                ),
                human.clone(),
                if approved {
                    ForgeReviewState::Approved
                } else {
                    ForgeReviewState::ChangesRequested
                },
                "review",
                provider_time.clone(),
                head,
            )
            .unwrap()]
        } else {
            Vec::new()
        };
        let checks = vec![ForgeCheck::new(
            object(ProviderObjectKind::Check, "check:ci"),
            bot.clone(),
            "ci",
            check_status,
            check_conclusion,
            head,
            provider_time.clone(),
        )
        .unwrap()];
        let raw = PullRequestReviewSnapshot::new(
            item.clone(),
            provider_time.clone(),
            reviews,
            Vec::new(),
            checks,
        )
        .unwrap();
        let mut transport = FakeForgeTransport::new();
        transport
            .register_observation(
                ForgeObservationRequest::pull_request_review_snapshot(item.clone()).unwrap(),
                ForgeObservation::PullRequestReviewSnapshot(raw),
            )
            .unwrap();
        FrozenReviewSnapshot::observe(&transport, &item, collection_started_at).unwrap()
    }

    fn ts(value: &str) -> ForgeTimestamp {
        ForgeTimestamp::new(value).unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn authenticated_journal_restores_and_refreshes_one_logical_pr() {
        let (_temp, repo, policy, human, bot) = fixture();
        let collection_t1 = ts("2026-08-16T01:02:03Z");
        let collection_t2 = ts("2026-08-16T01:03:03Z");
        let first = observe_provider(
            "2026-08-16T01:02:03Z",
            &collection_t1,
            &"a".repeat(40),
            "revision:1",
            false,
            false,
            ForgeCheckStatus::Completed,
            Some(ForgeCheckConclusion::Success),
            &human,
            &bot,
        );
        let second = observe_provider(
            "2026-08-16T01:03:03Z",
            &collection_t2,
            &"c".repeat(40),
            "revision:2",
            true,
            false,
            ForgeCheckStatus::Completed,
            Some(ForgeCheckConclusion::Success),
            &human,
            &bot,
        );
        let initial = super::observe(&repo, &first, &policy, &collection_t1).unwrap();
        assert_eq!(initial.phase(), ReviewLoopPhase::Active);
        assert_eq!(
            super::observe(&repo, &first, &policy, &collection_t1).unwrap(),
            initial
        );
        let refreshed = super::observe(&repo, &second, &policy, &collection_t2).unwrap();
        assert_eq!(refreshed.phase(), ReviewLoopPhase::Ready);
        assert_eq!(refreshed.attempts().len(), 1);
        assert_eq!(
            refreshed.predecessor_state_sha256(),
            Some(initial.state_sha256())
        );
        assert_eq!(
            super::observe(&repo, &second, &policy, &collection_t2).unwrap(),
            refreshed
        );
        let auth = repository_auth_writer(&repo)
            .unwrap()
            .into_authenticator()
            .unwrap();
        let journal = StateJournal::open_instance(auth, &instance_id(&second).unwrap()).unwrap();
        assert_eq!(journal.records().len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn identical_provider_evidence_on_later_collection_watermark_without_attempt() {
        let (_temp, repo, policy, human, bot) = fixture();
        let collection_t1 = ts("2026-08-16T01:02:03Z");
        let collection_t3 = ts("2026-08-16T01:04:03Z");
        let first = observe_provider(
            "2026-08-16T01:02:03Z",
            &collection_t1,
            &"a".repeat(40),
            "revision:1",
            false,
            false,
            ForgeCheckStatus::Completed,
            Some(ForgeCheckConclusion::Success),
            &human,
            &bot,
        );
        let rescan = observe_provider(
            "2026-08-16T01:02:03Z",
            &collection_t3,
            &"a".repeat(40),
            "revision:1",
            false,
            false,
            ForgeCheckStatus::Completed,
            Some(ForgeCheckConclusion::Success),
            &human,
            &bot,
        );
        let initial = super::observe(&repo, &first, &policy, &collection_t1).unwrap();
        let later = super::observe(&repo, &rescan, &policy, &collection_t3).unwrap();
        assert_eq!(later, initial);
        assert_eq!(later.attempts().len(), initial.attempts().len());
        let auth = repository_auth_writer(&repo)
            .unwrap()
            .into_authenticator()
            .unwrap();
        let journal = StateJournal::open_instance(auth, &instance_id(&first).unwrap()).unwrap();
        assert_eq!(journal.records().len(), 2);
        assert_eq!(journal.records()[1].phase, PHASE_WATERMARK);
        drop(journal);
        let stale = observe_provider(
            "2026-08-16T01:02:03Z",
            &ts("2026-08-16T01:03:03Z"),
            &"a".repeat(40),
            "revision:1",
            false,
            false,
            ForgeCheckStatus::Completed,
            Some(ForgeCheckConclusion::Success),
            &human,
            &bot,
        );
        assert!(super::observe(&repo, &stale, &policy, &ts("2026-08-16T01:03:03Z")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn production_shaped_check_transition_with_unchanged_provider_observed_at() {
        let (_temp, repo, policy, human, bot) = fixture();
        let provider_time = "2026-08-16T01:02:03Z";
        let collection_t1 = ts("2026-08-16T01:02:03Z");
        let collection_t2 = ts("2026-08-16T01:05:03Z");
        let running = observe_provider(
            provider_time,
            &collection_t1,
            &"a".repeat(40),
            "revision:1",
            false,
            false,
            ForgeCheckStatus::InProgress,
            None,
            &human,
            &bot,
        );
        let success = observe_provider(
            provider_time,
            &collection_t2,
            &"a".repeat(40),
            "revision:1",
            true,
            false,
            ForgeCheckStatus::Completed,
            Some(ForgeCheckConclusion::Success),
            &human,
            &bot,
        );
        assert_eq!(
            running.observed_at().as_str(),
            success.observed_at().as_str()
        );
        let initial = super::observe(&repo, &running, &policy, &collection_t1).unwrap();
        assert_eq!(initial.phase(), ReviewLoopPhase::Active);
        let ready = super::observe(&repo, &success, &policy, &collection_t2).unwrap();
        assert_eq!(ready.phase(), ReviewLoopPhase::Ready);
        assert_eq!(ready.attempts().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn equal_collection_different_evidence_rejected_then_later_collection_recovers() {
        let (_temp, repo, policy, human, bot) = fixture();
        let collection_t1 = ts("2026-08-16T01:02:03Z");
        let collection_t2 = ts("2026-08-16T01:03:03Z");
        let first = observe_provider(
            "2026-08-16T01:02:03Z",
            &collection_t1,
            &"a".repeat(40),
            "revision:1",
            false,
            false,
            ForgeCheckStatus::Completed,
            Some(ForgeCheckConclusion::Success),
            &human,
            &bot,
        );
        super::observe(&repo, &first, &policy, &collection_t1).unwrap();
        let conflicting = observe_provider(
            "2026-08-16T01:02:03Z",
            &collection_t1,
            &"c".repeat(40),
            "revision:2",
            true,
            false,
            ForgeCheckStatus::Completed,
            Some(ForgeCheckConclusion::Success),
            &human,
            &bot,
        );
        assert!(super::observe(&repo, &conflicting, &policy, &collection_t1).is_err());
        let recovered = observe_provider(
            "2026-08-16T01:03:03Z",
            &collection_t2,
            &"c".repeat(40),
            "revision:2",
            true,
            false,
            ForgeCheckStatus::Completed,
            Some(ForgeCheckConclusion::Success),
            &human,
            &bot,
        );
        assert_eq!(
            super::observe(&repo, &recovered, &policy, &collection_t2)
                .unwrap()
                .phase(),
            ReviewLoopPhase::Ready
        );
    }

    #[cfg(unix)]
    #[test]
    fn future_provider_observed_at_rejected_before_stamping() {
        let (_temp, repo, policy, human, bot) = fixture();
        let collection = ts("2026-08-16T01:02:03Z");
        let future = observe_provider(
            "2026-08-16T01:03:03Z",
            &ts("2026-08-16T01:04:03Z"),
            &"a".repeat(40),
            "revision:1",
            false,
            false,
            ForgeCheckStatus::Completed,
            Some(ForgeCheckConclusion::Success),
            &human,
            &bot,
        );
        assert!(super::observe(&repo, &future, &policy, &collection).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn old_head_readiness_does_not_carry_into_new_head() {
        let (_temp, repo, policy, human, bot) = fixture();
        let collection_t1 = ts("2026-08-16T01:02:03Z");
        let collection_t2 = ts("2026-08-16T01:03:03Z");
        let first = observe_provider(
            "2026-08-16T01:02:03Z",
            &collection_t1,
            &"a".repeat(40),
            "revision:1",
            true,
            false,
            ForgeCheckStatus::Completed,
            Some(ForgeCheckConclusion::Success),
            &human,
            &bot,
        );
        let second = observe_provider(
            "2026-08-16T01:03:03Z",
            &collection_t2,
            &"c".repeat(40),
            "revision:2",
            false,
            false,
            ForgeCheckStatus::Completed,
            Some(ForgeCheckConclusion::Success),
            &human,
            &bot,
        );
        assert_eq!(
            super::observe(&repo, &first, &policy, &collection_t1)
                .unwrap()
                .phase(),
            ReviewLoopPhase::Ready
        );
        let current = super::observe(&repo, &second, &policy, &collection_t2).unwrap();
        assert_eq!(current.phase(), ReviewLoopPhase::Active);
        assert!(current.attempts().is_empty());
        assert!(current.dispositions().is_empty());
        assert!(super::observe(&repo, &first, &policy, &collection_t2).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn exhausted_blocking_feedback_cannot_reset_into_readiness() {
        let (_temp, repo, policy, human, bot) = fixture();
        let policy = ReviewLoopPolicy::new(
            policy.trusted_feedback_actors().to_vec(),
            policy.required_checks().to_vec(),
            policy.minimum_approvals(),
            1,
        )
        .unwrap();
        let collection_t1 = ts("2026-08-16T01:02:03Z");
        let collection_t2 = ts("2026-08-16T01:03:03Z");
        let collection_t3 = ts("2026-08-16T01:04:03Z");
        let first = observe_provider(
            "2026-08-16T01:02:03Z",
            &collection_t1,
            &"a".repeat(40),
            "revision:1",
            false,
            false,
            ForgeCheckStatus::Completed,
            Some(ForgeCheckConclusion::Success),
            &human,
            &bot,
        );
        let blocked = observe_provider(
            "2026-08-16T01:03:03Z",
            &collection_t2,
            &"c".repeat(40),
            "revision:2",
            false,
            true,
            ForgeCheckStatus::Completed,
            Some(ForgeCheckConclusion::Success),
            &human,
            &bot,
        );
        let apparently_ready = observe_provider(
            "2026-08-16T01:04:03Z",
            &collection_t3,
            &"d".repeat(40),
            "revision:3",
            true,
            false,
            ForgeCheckStatus::Completed,
            Some(ForgeCheckConclusion::Success),
            &human,
            &bot,
        );
        assert_eq!(
            super::observe(&repo, &first, &policy, &collection_t1)
                .unwrap()
                .phase(),
            ReviewLoopPhase::Active
        );
        assert_eq!(
            super::observe(&repo, &blocked, &policy, &collection_t2)
                .unwrap()
                .phase(),
            ReviewLoopPhase::Exhausted
        );
        let refusal =
            super::observe(&repo, &apparently_ready, &policy, &collection_t3).unwrap_err();
        assert!(refusal.is::<ReviewStateRefreshBlocked>());
        let auth = repository_auth_writer(&repo)
            .unwrap()
            .into_authenticator()
            .unwrap();
        let journal = StateJournal::open_instance(auth, &instance_id(&first).unwrap()).unwrap();
        assert_eq!(journal.records().len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn unresolved_feedback_blocks_refresh_and_tampering_refuses_replay() {
        let (_temp, repo, policy, human, bot) = fixture();
        let collection_t1 = ts("2026-08-16T01:02:03Z");
        let collection_t2 = ts("2026-08-16T01:03:03Z");
        let first = observe_provider(
            "2026-08-16T01:02:03Z",
            &collection_t1,
            &"a".repeat(40),
            "revision:1",
            false,
            true,
            ForgeCheckStatus::Completed,
            Some(ForgeCheckConclusion::Success),
            &human,
            &bot,
        );
        let second = observe_provider(
            "2026-08-16T01:03:03Z",
            &collection_t2,
            &"c".repeat(40),
            "revision:2",
            true,
            false,
            ForgeCheckStatus::Completed,
            Some(ForgeCheckConclusion::Success),
            &human,
            &bot,
        );
        super::observe(&repo, &first, &policy, &collection_t1).unwrap();
        let blocked = super::observe(&repo, &second, &policy, &collection_t2).unwrap_err();
        assert!(blocked.is::<ReviewStateRefreshBlocked>());
        let auth = repository_auth_writer(&repo)
            .unwrap()
            .into_authenticator()
            .unwrap();
        let journal = StateJournal::open_instance(auth, &instance_id(&first).unwrap()).unwrap();
        assert_eq!(journal.records().len(), 1);
        let record_path = journal
            .root()
            .path()
            .join(instance_id(&first).unwrap())
            .join("00000000000000000001.json");
        drop(journal);
        let mut bytes = std::fs::read(&record_path).unwrap();
        let offset = bytes.iter().position(|byte| *byte == b'a').unwrap();
        bytes[offset] = b'f';
        std::fs::write(record_path, bytes).unwrap();
        assert!(super::observe(&repo, &first, &policy, &collection_t1).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn watermark_tamper_and_collection_reorder_fail_closed() {
        let (_temp, repo, policy, human, bot) = fixture();
        let collection_t1 = ts("2026-08-16T01:02:03Z");
        let collection_t3 = ts("2026-08-16T01:04:03Z");
        let first = observe_provider(
            "2026-08-16T01:02:03Z",
            &collection_t1,
            &"a".repeat(40),
            "revision:1",
            false,
            false,
            ForgeCheckStatus::Completed,
            Some(ForgeCheckConclusion::Success),
            &human,
            &bot,
        );
        let rescan = observe_provider(
            "2026-08-16T01:02:03Z",
            &collection_t3,
            &"a".repeat(40),
            "revision:1",
            false,
            false,
            ForgeCheckStatus::Completed,
            Some(ForgeCheckConclusion::Success),
            &human,
            &bot,
        );
        super::observe(&repo, &first, &policy, &collection_t1).unwrap();
        super::observe(&repo, &rescan, &policy, &collection_t3).unwrap();
        let auth = repository_auth_writer(&repo)
            .unwrap()
            .into_authenticator()
            .unwrap();
        let journal = StateJournal::open_instance(auth, &instance_id(&first).unwrap()).unwrap();
        let watermark_path = journal
            .root()
            .path()
            .join(instance_id(&first).unwrap())
            .join("00000000000000000002.json");
        drop(journal);
        let mut bytes = std::fs::read(&watermark_path).unwrap();
        let marker = br#""collection_started_at""#;
        let start = bytes
            .windows(marker.len())
            .position(|window| window == marker)
            .unwrap();
        bytes[start + marker.len()] = b'X';
        std::fs::write(&watermark_path, bytes).unwrap();
        assert!(super::observe(&repo, &rescan, &policy, &collection_t3).is_err());
    }
}
