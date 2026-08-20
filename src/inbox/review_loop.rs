//! Provider-neutral review-loop observation, trust policy, and readiness triage.
//!
//! It freezes exact forge observations, records verified feedback
//! dispositions, advances a digest-chained bounded state machine, emits
//! conservative readiness evidence, and constructs one typed PR-comment
//! publication effect. A readiness proof is deliberately not merge authority.
//!
//! [`open_review_loop`] is the production entry: observe a pull request through
//! a [`ForgeTransport`], construct [`ReviewLoopState`], and evaluate readiness.
//! Callers that want a user-facing path still have to wire that function from
//! `maco review`, a supervisor role, or a workflow. This module does not merge.

use crate::{
    artifacts::state_auth::sha256_hex,
    publication::forge_transport::{
        AppendCommentEffect, ForgeActor, ForgeCheck, ForgeCheckConclusion, ForgeCheckStatus,
        ForgeEffectRequest, ForgeItem, ForgeItemKind, ForgeObservation, ForgeObservationRequest,
        ForgeReview, ForgeReviewState, ForgeReviewThread, ForgeTimestamp, ForgeTransport,
        ProviderObjectId, ProviderObjectKind, PullRequestReviewSnapshot, ReportedActorKind,
    },
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};

const MAX_REVIEW_LOOP_ATTEMPTS: usize = 8;
const MAX_CHECK_NAME_BYTES: usize = 256;
const MAX_ATTEMPT_ID_BYTES: usize = 128;
const MAX_DISPOSITION_SUMMARY_BYTES: usize = 8 * 1024;
const MAX_DISPOSITION_RECORD_BYTES: usize = 16 * 1024;
const MAX_FROZEN_SNAPSHOT_RECORD_BYTES: usize = 768 * 1024;
const MAX_REVIEW_LOOP_STATE_RECORD_BYTES: usize = 16 * 1024 * 1024;
const REVIEW_SNAPSHOT_DIGEST_DOMAIN: &[u8] = b"MACO\0review-loop-snapshot\0v1\0";
const POLICY_DIGEST_DOMAIN: &[u8] = b"MACO\0review-loop-policy\0v1\0";
const DISPOSITION_DIGEST_DOMAIN: &[u8] = b"MACO\0review-disposition\0v1\0";
const READINESS_DIGEST_DOMAIN: &[u8] = b"MACO\0review-readiness\0v1\0";
const REVIEW_LOOP_STATE_DIGEST_DOMAIN: &[u8] = b"MACO\0review-loop-state\0v1\0";
const REVIEW_LOOP_ATTEMPT_ID_DOMAIN: &[u8] = b"MACO\0review-loop-attempt-id\0v1\0";
const PUBLICATION_EFFECT_DIGEST_DOMAIN: &[u8] = b"MACO\0review-disposition-publication\0v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustedActorRole {
    HumanBlocking,
    BotAdvisory,
}

/// An exact provider identity. A reported actor kind is trusted only when all
/// three fields match a policy entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedActorIdentity {
    provider_actor_id: ProviderObjectId,
    canonical_handle: String,
    expected_kind: ReportedActorKind,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedActorIdentityWire {
    provider_actor_id: ProviderObjectId,
    canonical_handle: String,
    expected_kind: ReportedActorKind,
}

impl Ord for TrustedActorIdentity {
    fn cmp(&self, other: &Self) -> Ordering {
        self.provider_actor_id
            .cmp(&other.provider_actor_id)
            .then_with(|| self.canonical_handle.cmp(&other.canonical_handle))
            .then_with(|| {
                actor_kind_rank(self.expected_kind).cmp(&actor_kind_rank(other.expected_kind))
            })
    }
}

impl PartialOrd for TrustedActorIdentity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn actor_kind_rank(kind: ReportedActorKind) -> u8 {
    match kind {
        ReportedActorKind::Human => 0,
        ReportedActorKind::Bot => 1,
        ReportedActorKind::Organization => 2,
        ReportedActorKind::Unknown => 3,
    }
}

impl TrustedActorIdentity {
    pub fn new(
        provider_actor_id: ProviderObjectId,
        canonical_handle: impl Into<String>,
        expected_kind: ReportedActorKind,
    ) -> Result<Self> {
        if provider_actor_id.kind() != ProviderObjectKind::Actor {
            bail!("trusted actor identity requires a provider actor id");
        }
        let canonical_handle = canonical_handle.into();
        ForgeActor::new(
            provider_actor_id.provider_id().to_owned(),
            provider_actor_id.clone(),
            canonical_handle.clone(),
            expected_kind,
        )?;
        Ok(Self {
            provider_actor_id,
            canonical_handle,
            expected_kind,
        })
    }

    pub fn provider_actor_id(&self) -> &ProviderObjectId {
        &self.provider_actor_id
    }

    pub fn canonical_handle(&self) -> &str {
        &self.canonical_handle
    }

    pub fn expected_kind(&self) -> ReportedActorKind {
        self.expected_kind
    }

    fn from_observed(actor: &ForgeActor) -> Self {
        Self {
            provider_actor_id: actor.provider_actor_id().clone(),
            canonical_handle: actor.canonical_handle().to_owned(),
            expected_kind: actor.reported_kind(),
        }
    }

    fn matches(&self, actor: &ForgeActor) -> bool {
        self.provider_actor_id == *actor.provider_actor_id()
            && self.canonical_handle == actor.canonical_handle()
            && self.expected_kind == actor.reported_kind()
    }

    fn validate(&self) -> Result<()> {
        let rebuilt = Self::new(
            self.provider_actor_id.clone(),
            self.canonical_handle.clone(),
            self.expected_kind,
        )?;
        if rebuilt != *self {
            bail!("trusted actor identity is not canonical");
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for TrustedActorIdentity {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = TrustedActorIdentityWire::deserialize(deserializer)?;
        Self::new(
            wire.provider_actor_id,
            wire.canonical_handle,
            wire.expected_kind,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedActorBinding {
    identity: TrustedActorIdentity,
    role: TrustedActorRole,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedActorBindingWire {
    identity: TrustedActorIdentity,
    role: TrustedActorRole,
}

impl TrustedActorBinding {
    pub fn new(identity: TrustedActorIdentity, role: TrustedActorRole) -> Result<Self> {
        let role_matches_kind = matches!(
            (role, identity.expected_kind()),
            (TrustedActorRole::HumanBlocking, ReportedActorKind::Human)
                | (TrustedActorRole::BotAdvisory, ReportedActorKind::Bot)
        );
        if !role_matches_kind {
            bail!("trusted actor role conflicts with its expected reported actor kind");
        }
        Ok(Self { identity, role })
    }

    pub fn identity(&self) -> &TrustedActorIdentity {
        &self.identity
    }

    pub fn role(&self) -> TrustedActorRole {
        self.role
    }

    fn validate(&self) -> Result<()> {
        self.identity.validate()?;
        Self::new(self.identity.clone(), self.role).map(|_| ())
    }
}

impl<'de> Deserialize<'de> for TrustedActorBinding {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = TrustedActorBindingWire::deserialize(deserializer)?;
        Self::new(wire.identity, wire.role).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredCheck {
    name: String,
    trusted_actors: Vec<TrustedActorIdentity>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequiredCheckWire {
    name: String,
    trusted_actors: Vec<TrustedActorIdentity>,
}

impl RequiredCheck {
    pub fn new(
        name: impl Into<String>,
        mut trusted_actors: Vec<TrustedActorIdentity>,
    ) -> Result<Self> {
        let name = name.into();
        if name.trim().is_empty()
            || name.trim() != name
            || name.len() > MAX_CHECK_NAME_BYTES
            || name
                .bytes()
                .any(|byte| byte == 0 || byte.is_ascii_control())
        {
            bail!("required check name must be nonempty, canonical, and bounded");
        }
        if trusted_actors.is_empty() {
            bail!("required check must bind at least one exact trusted actor");
        }
        trusted_actors.sort();
        if trusted_actors
            .windows(2)
            .any(|pair| pair[0].provider_actor_id() == pair[1].provider_actor_id())
        {
            bail!("required check contains duplicate provider actor ids");
        }
        Ok(Self {
            name,
            trusted_actors,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn trusted_actors(&self) -> &[TrustedActorIdentity] {
        &self.trusted_actors
    }

    fn trusts(&self, actor: &ForgeActor) -> bool {
        self.trusted_actors
            .iter()
            .any(|trusted| trusted.matches(actor))
    }

    fn validate(&self) -> Result<()> {
        for actor in &self.trusted_actors {
            actor.validate()?;
        }
        let rebuilt = Self::new(self.name.clone(), self.trusted_actors.clone())?;
        if rebuilt != *self {
            bail!("required check is not canonical");
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for RequiredCheck {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = RequiredCheckWire::deserialize(deserializer)?;
        Self::new(wire.name, wire.trusted_actors).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewLoopPolicy {
    trusted_feedback_actors: Vec<TrustedActorBinding>,
    required_checks: Vec<RequiredCheck>,
    minimum_approvals: usize,
    max_attempts: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewLoopPolicyWire {
    trusted_feedback_actors: Vec<TrustedActorBinding>,
    required_checks: Vec<RequiredCheck>,
    minimum_approvals: usize,
    max_attempts: usize,
}

impl ReviewLoopPolicy {
    pub fn new(
        mut trusted_feedback_actors: Vec<TrustedActorBinding>,
        mut required_checks: Vec<RequiredCheck>,
        minimum_approvals: usize,
        max_attempts: usize,
    ) -> Result<Self> {
        for binding in &trusted_feedback_actors {
            binding.validate()?;
        }
        for required_check in &required_checks {
            required_check.validate()?;
        }
        if trusted_feedback_actors.is_empty() {
            bail!("review-loop policy requires at least one trusted feedback actor");
        }
        trusted_feedback_actors.sort_by(|left, right| left.identity.cmp(&right.identity));
        if trusted_feedback_actors.windows(2).any(|pair| {
            pair[0].identity.provider_actor_id() == pair[1].identity.provider_actor_id()
        }) {
            bail!("review-loop policy contains duplicate trusted provider actor ids");
        }
        if required_checks.is_empty() {
            bail!("review-loop policy requires at least one named check");
        }
        required_checks.sort_by(|left, right| left.name.cmp(&right.name));
        if required_checks
            .windows(2)
            .any(|pair| pair[0].name == pair[1].name)
        {
            bail!("review-loop policy contains duplicate required check names");
        }
        if minimum_approvals == 0 {
            bail!("review-loop policy minimum approvals must be positive");
        }
        if !(1..=MAX_REVIEW_LOOP_ATTEMPTS).contains(&max_attempts) {
            bail!("review-loop policy max attempts must be between 1 and 8");
        }
        Ok(Self {
            trusted_feedback_actors,
            required_checks,
            minimum_approvals,
            max_attempts,
        })
    }

    pub fn trusted_feedback_actors(&self) -> &[TrustedActorBinding] {
        &self.trusted_feedback_actors
    }

    pub fn required_checks(&self) -> &[RequiredCheck] {
        &self.required_checks
    }

    pub fn minimum_approvals(&self) -> usize {
        self.minimum_approvals
    }

    pub fn max_attempts(&self) -> usize {
        self.max_attempts
    }

    pub fn canonical_sha256(&self) -> Result<String> {
        canonical_digest(POLICY_DIGEST_DOMAIN, self, "review-loop policy")
    }

    pub fn triage(&self, snapshot: &FrozenReviewSnapshot) -> ReviewTriage {
        snapshot.triage(self)
    }

    fn feedback_role(&self, actor: &ForgeActor) -> Option<TrustedActorRole> {
        self.trusted_feedback_actors
            .iter()
            .find(|binding| binding.identity.matches(actor))
            .map(TrustedActorBinding::role)
    }
}

impl<'de> Deserialize<'de> for ReviewLoopPolicy {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ReviewLoopPolicyWire::deserialize(deserializer)?;
        Self::new(
            wire.trusted_feedback_actors,
            wire.required_checks,
            wire.minimum_approvals,
            wire.max_attempts,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// A review observation bound to the exact item, base OID, and head OID used in
/// the transport request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FrozenReviewSnapshot {
    snapshot: PullRequestReviewSnapshot,
    canonical_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenReviewSnapshotWire {
    snapshot: PullRequestReviewSnapshot,
    canonical_sha256: String,
}

impl FrozenReviewSnapshot {
    pub fn observe<T>(
        transport: &T,
        item: &ForgeItem,
        trusted_not_after: &ForgeTimestamp,
    ) -> Result<Self>
    where
        T: ForgeTransport + ?Sized,
    {
        if item.kind() != ForgeItemKind::PullRequest {
            bail!("review-loop observation requires a pull-request item");
        }
        let request = ForgeObservationRequest::pull_request_review_snapshot(item.clone())?;
        let observation = transport.observe(&request)?;
        let snapshot = match observation {
            ForgeObservation::PullRequestReviewSnapshot(snapshot) => snapshot,
            ForgeObservation::ItemThread(_) => {
                bail!("forge transport returned the wrong observation kind")
            }
        };
        Self::freeze(item, snapshot, trusted_not_after)
    }

    fn freeze(
        item: &ForgeItem,
        snapshot: PullRequestReviewSnapshot,
        trusted_not_after: &ForgeTimestamp,
    ) -> Result<Self> {
        if item.kind() != ForgeItemKind::PullRequest
            || snapshot.item() != item
            || snapshot.item().provider_item_id() != item.provider_item_id()
            || snapshot.item().head_oid() != item.head_oid()
            || snapshot.item().base_oid() != item.base_oid()
        {
            bail!("review snapshot does not bind the exact requested PR item, head, and base");
        }
        if snapshot.observed_at() > trusted_not_after {
            bail!("review snapshot observation is later than its trusted cutoff");
        }
        let snapshot = canonicalize_snapshot(snapshot)?;
        Ok(Self {
            canonical_sha256: canonical_digest(
                REVIEW_SNAPSHOT_DIGEST_DOMAIN,
                &snapshot,
                "canonical review snapshot",
            )?,
            snapshot,
        })
    }

    pub fn snapshot(&self) -> &PullRequestReviewSnapshot {
        &self.snapshot
    }

    pub fn item(&self) -> &ForgeItem {
        self.snapshot.item()
    }

    pub fn observed_at(&self) -> &ForgeTimestamp {
        self.snapshot.observed_at()
    }

    pub fn canonical_sha256(&self) -> &str {
        &self.canonical_sha256
    }

    pub fn restore_json(encoded: &[u8], trusted_not_after: &ForgeTimestamp) -> Result<Self> {
        if encoded.len() > MAX_FROZEN_SNAPSHOT_RECORD_BYTES || encoded.contains(&0) {
            bail!("serialized frozen snapshot is malformed or exceeds its byte bound");
        }
        let wire = serde_json::from_slice::<FrozenReviewSnapshotWire>(encoded)
            .context("serialized frozen snapshot is not strict valid JSON")?;
        Self::from_wire(wire, trusted_not_after)
    }

    pub fn validate_not_after(&self, trusted_not_after: &ForgeTimestamp) -> Result<()> {
        if self.observed_at() > trusted_not_after {
            bail!("frozen review snapshot is later than its trusted cutoff");
        }
        Ok(())
    }

    pub fn triage(&self, policy: &ReviewLoopPolicy) -> ReviewTriage {
        let mut blockers = Vec::new();
        let mut blocking_human_feedback = Vec::new();
        let mut bot_advisories = Vec::new();
        let mut approving_humans = BTreeSet::new();
        let mut approval_review_ids = BTreeSet::new();
        let mut trusted_human_reviews = BTreeMap::<TrustedActorIdentity, Vec<&ForgeReview>>::new();

        if !self.snapshot.threads().is_empty() {
            blockers.push(ReadinessBlocker::UnsupportedThreadCurrencyMetadata);
        }

        for review in self.snapshot.reviews() {
            let identity = ReviewFeedbackIdentity::review(review.provider_review_id().clone());
            let feedback = TriagedFeedback::new(
                identity.clone(),
                TrustedActorIdentity::from_observed(review.author()),
                FeedbackKind::Review {
                    state: review.state(),
                },
            );
            match policy.feedback_role(review.author()) {
                None => blockers.push(ReadinessBlocker::UntrustedActor(
                    UntrustedActorBlocker::new(
                        ActorEvidenceIdentity::Feedback(identity),
                        TrustedActorIdentity::from_observed(review.author()),
                    ),
                )),
                Some(TrustedActorRole::HumanBlocking) => trusted_human_reviews
                    .entry(TrustedActorIdentity::from_observed(review.author()))
                    .or_default()
                    .push(review),
                Some(TrustedActorRole::BotAdvisory) => bot_advisories.push(feedback),
            }
        }

        for (actor, reviews) in trusted_human_reviews {
            let Some(latest_submitted_at) = reviews
                .iter()
                .map(|review| review.submitted_at().clone())
                .max()
            else {
                continue;
            };
            let latest = reviews
                .into_iter()
                .filter(|review| review.submitted_at() == &latest_submitted_at)
                .collect::<Vec<_>>();
            let Some(latest_state) = latest.first().map(|review| review.state()) else {
                continue;
            };
            if latest.iter().any(|review| review.state() != latest_state) {
                blockers.push(ReadinessBlocker::AmbiguousHumanReviewCurrency(
                    AmbiguousHumanReviewCurrency::new(
                        actor,
                        latest_submitted_at,
                        latest
                            .iter()
                            .map(|review| review.provider_review_id().clone())
                            .collect(),
                    ),
                ));
                continue;
            }
            match latest_state {
                ForgeReviewState::Approved => {
                    approving_humans.insert(actor.provider_actor_id().clone());
                    approval_review_ids.extend(
                        latest
                            .iter()
                            .map(|review| review.provider_review_id().clone()),
                    );
                }
                ForgeReviewState::ChangesRequested | ForgeReviewState::Commented => {
                    for review in latest {
                        let identity =
                            ReviewFeedbackIdentity::review(review.provider_review_id().clone());
                        blockers.push(ReadinessBlocker::BlockingHumanFeedback(identity.clone()));
                        blocking_human_feedback.push(TriagedFeedback::new(
                            identity,
                            actor.clone(),
                            FeedbackKind::Review {
                                state: review.state(),
                            },
                        ));
                    }
                }
                ForgeReviewState::Dismissed | ForgeReviewState::Pending => {}
            }
        }

        for thread in self.snapshot.threads() {
            triage_thread(
                policy,
                thread,
                &mut blockers,
                &mut blocking_human_feedback,
                &mut bot_advisories,
            );
        }

        triage_checks(policy, self.snapshot.checks(), &mut blockers);

        let approval_count = approving_humans.len();
        if approval_count < policy.minimum_approvals {
            blockers.push(ReadinessBlocker::InsufficientApproval(
                ApprovalShortfall::new(policy.minimum_approvals, approval_count),
            ));
        }

        ReviewTriage {
            blockers,
            blocking_human_feedback,
            bot_advisories,
            approval_count,
            approval_review_ids: approval_review_ids.into_iter().collect(),
        }
    }

    fn from_wire(
        wire: FrozenReviewSnapshotWire,
        trusted_not_after: &ForgeTimestamp,
    ) -> Result<Self> {
        let item = wire.snapshot.item().clone();
        let frozen = Self::freeze(&item, wire.snapshot, trusted_not_after)?;
        if frozen.canonical_sha256 != wire.canonical_sha256 {
            bail!("frozen review snapshot canonical digest does not match");
        }
        Ok(frozen)
    }
}

fn canonical_digest<T>(domain: &[u8], value: &T, label: &str) -> Result<String>
where
    T: Serialize + ?Sized,
{
    let canonical_json =
        serde_json::to_vec(value).with_context(|| format!("failed to serialize {label}"))?;
    let length = u64::try_from(canonical_json.len())
        .with_context(|| format!("{label} serialized length does not fit u64"))?;
    let mut digest_input =
        Vec::with_capacity(domain.len() + std::mem::size_of::<u64>() + canonical_json.len());
    digest_input.extend_from_slice(domain);
    digest_input.extend_from_slice(&length.to_be_bytes());
    digest_input.extend_from_slice(&canonical_json);
    Ok(sha256_hex(&digest_input))
}

fn canonicalize_snapshot(snapshot: PullRequestReviewSnapshot) -> Result<PullRequestReviewSnapshot> {
    let mut reviews = snapshot.reviews().to_vec();
    reviews.sort_by(|left, right| left.provider_review_id().cmp(right.provider_review_id()));

    let mut threads = Vec::with_capacity(snapshot.threads().len());
    for thread in snapshot.threads() {
        let mut comments = thread.comments().to_vec();
        comments.sort_by(|left, right| left.provider_comment_id().cmp(right.provider_comment_id()));
        threads.push(ForgeReviewThread::new(
            thread.provider_thread_id().clone(),
            thread.is_resolved(),
            comments,
        )?);
    }
    threads.sort_by(|left, right| left.provider_thread_id().cmp(right.provider_thread_id()));

    let mut checks = snapshot.checks().to_vec();
    checks.sort_by(|left, right| left.provider_check_id().cmp(right.provider_check_id()));

    PullRequestReviewSnapshot::new(
        snapshot.item().clone(),
        snapshot.observed_at().clone(),
        reviews,
        threads,
        checks,
    )
}

fn triage_thread(
    policy: &ReviewLoopPolicy,
    thread: &ForgeReviewThread,
    blockers: &mut Vec<ReadinessBlocker>,
    blocking_human_feedback: &mut Vec<TriagedFeedback>,
    bot_advisories: &mut Vec<TriagedFeedback>,
) {
    for comment in thread.comments() {
        let identity = ReviewFeedbackIdentity::thread_comment(
            thread.provider_thread_id().clone(),
            comment.provider_comment_id().clone(),
        );
        let feedback = TriagedFeedback::new(
            identity.clone(),
            TrustedActorIdentity::from_observed(comment.author()),
            FeedbackKind::ThreadComment {
                thread_resolved: thread.is_resolved(),
            },
        );
        match policy.feedback_role(comment.author()) {
            None => blockers.push(ReadinessBlocker::UntrustedActor(
                UntrustedActorBlocker::new(
                    ActorEvidenceIdentity::Feedback(identity),
                    TrustedActorIdentity::from_observed(comment.author()),
                ),
            )),
            Some(TrustedActorRole::HumanBlocking) if !thread.is_resolved() => {
                blockers.push(ReadinessBlocker::BlockingHumanFeedback(identity.clone()));
                blocking_human_feedback.push(feedback);
            }
            Some(TrustedActorRole::HumanBlocking) => {}
            Some(TrustedActorRole::BotAdvisory) => bot_advisories.push(feedback),
        }
    }
}

fn triage_checks(
    policy: &ReviewLoopPolicy,
    checks: &[ForgeCheck],
    blockers: &mut Vec<ReadinessBlocker>,
) {
    for required in policy.required_checks() {
        let matching = checks
            .iter()
            .filter(|check| check.name() == required.name())
            .collect::<Vec<_>>();
        if matching.is_empty() {
            blockers.push(ReadinessBlocker::MissingCheck(required.name().to_owned()));
            continue;
        }

        for check in &matching {
            if !required.trusts(check.actor()) {
                blockers.push(ReadinessBlocker::UntrustedActor(
                    UntrustedActorBlocker::new(
                        ActorEvidenceIdentity::Check(check.provider_check_id().clone()),
                        TrustedActorIdentity::from_observed(check.actor()),
                    ),
                ));
            }
        }

        if matching.len() != 1 {
            blockers.push(ReadinessBlocker::AmbiguousCheck(AmbiguousCheck::new(
                required.name().to_owned(),
                matching
                    .iter()
                    .map(|check| check.provider_check_id().clone())
                    .collect(),
            )));
            continue;
        }

        let check = matching[0];
        if required.trusts(check.actor())
            && (check.status() != ForgeCheckStatus::Completed
                || check.conclusion() != Some(ForgeCheckConclusion::Success))
        {
            blockers.push(ReadinessBlocker::NonSuccessCheck(CheckFailure::new(
                required.name().to_owned(),
                check.provider_check_id().clone(),
                check.status(),
                check.conclusion(),
            )));
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "feedback", rename_all = "snake_case")]
pub enum ReviewFeedbackIdentity {
    Review {
        provider_review_id: ProviderObjectId,
    },
    ThreadComment {
        provider_thread_id: ProviderObjectId,
        provider_comment_id: ProviderObjectId,
    },
}

impl ReviewFeedbackIdentity {
    pub fn review(provider_review_id: ProviderObjectId) -> Self {
        Self::Review { provider_review_id }
    }

    pub fn thread_comment(
        provider_thread_id: ProviderObjectId,
        provider_comment_id: ProviderObjectId,
    ) -> Self {
        Self::ThreadComment {
            provider_thread_id,
            provider_comment_id,
        }
    }

    pub fn provider_review_id(&self) -> Option<&ProviderObjectId> {
        match self {
            Self::Review { provider_review_id } => Some(provider_review_id),
            Self::ThreadComment { .. } => None,
        }
    }

    pub fn provider_thread_id(&self) -> Option<&ProviderObjectId> {
        match self {
            Self::ThreadComment {
                provider_thread_id, ..
            } => Some(provider_thread_id),
            Self::Review { .. } => None,
        }
    }

    pub fn provider_comment_id(&self) -> Option<&ProviderObjectId> {
        match self {
            Self::ThreadComment {
                provider_comment_id,
                ..
            } => Some(provider_comment_id),
            Self::Review { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "source", content = "identity", rename_all = "snake_case")]
pub enum ActorEvidenceIdentity {
    Feedback(ReviewFeedbackIdentity),
    Check(ProviderObjectId),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FeedbackKind {
    Review { state: ForgeReviewState },
    ThreadComment { thread_resolved: bool },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TriagedFeedback {
    identity: ReviewFeedbackIdentity,
    actor: TrustedActorIdentity,
    kind: FeedbackKind,
}

impl TriagedFeedback {
    fn new(
        identity: ReviewFeedbackIdentity,
        actor: TrustedActorIdentity,
        kind: FeedbackKind,
    ) -> Self {
        Self {
            identity,
            actor,
            kind,
        }
    }

    pub fn identity(&self) -> &ReviewFeedbackIdentity {
        &self.identity
    }

    pub fn actor(&self) -> &TrustedActorIdentity {
        &self.actor
    }

    pub fn kind(&self) -> &FeedbackKind {
        &self.kind
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UntrustedActorBlocker {
    source: ActorEvidenceIdentity,
    observed_actor: TrustedActorIdentity,
}

impl UntrustedActorBlocker {
    fn new(source: ActorEvidenceIdentity, observed_actor: TrustedActorIdentity) -> Self {
        Self {
            source,
            observed_actor,
        }
    }

    pub fn source(&self) -> &ActorEvidenceIdentity {
        &self.source
    }

    pub fn observed_actor(&self) -> &TrustedActorIdentity {
        &self.observed_actor
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckFailure {
    name: String,
    provider_check_id: ProviderObjectId,
    status: ForgeCheckStatus,
    conclusion: Option<ForgeCheckConclusion>,
}

impl CheckFailure {
    fn new(
        name: String,
        provider_check_id: ProviderObjectId,
        status: ForgeCheckStatus,
        conclusion: Option<ForgeCheckConclusion>,
    ) -> Self {
        Self {
            name,
            provider_check_id,
            status,
            conclusion,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn provider_check_id(&self) -> &ProviderObjectId {
        &self.provider_check_id
    }

    pub fn status(&self) -> ForgeCheckStatus {
        self.status
    }

    pub fn conclusion(&self) -> Option<ForgeCheckConclusion> {
        self.conclusion
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AmbiguousCheck {
    name: String,
    provider_check_ids: Vec<ProviderObjectId>,
}

impl AmbiguousCheck {
    fn new(name: String, provider_check_ids: Vec<ProviderObjectId>) -> Self {
        Self {
            name,
            provider_check_ids,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn provider_check_ids(&self) -> &[ProviderObjectId] {
        &self.provider_check_ids
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AmbiguousHumanReviewCurrency {
    actor: TrustedActorIdentity,
    submitted_at: ForgeTimestamp,
    provider_review_ids: Vec<ProviderObjectId>,
}

impl AmbiguousHumanReviewCurrency {
    fn new(
        actor: TrustedActorIdentity,
        submitted_at: ForgeTimestamp,
        mut provider_review_ids: Vec<ProviderObjectId>,
    ) -> Self {
        provider_review_ids.sort();
        Self {
            actor,
            submitted_at,
            provider_review_ids,
        }
    }

    pub fn actor(&self) -> &TrustedActorIdentity {
        &self.actor
    }

    pub fn submitted_at(&self) -> &ForgeTimestamp {
        &self.submitted_at
    }

    pub fn provider_review_ids(&self) -> &[ProviderObjectId] {
        &self.provider_review_ids
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalShortfall {
    required: usize,
    observed: usize,
}

impl ApprovalShortfall {
    fn new(required: usize, observed: usize) -> Self {
        Self { required, observed }
    }

    pub fn required(&self) -> usize {
        self.required
    }

    pub fn observed(&self) -> usize {
        self.observed
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "blocker", content = "details", rename_all = "snake_case")]
pub enum ReadinessBlocker {
    AttemptLimitExhausted { max_attempts: usize },
    UnsupportedThreadCurrencyMetadata,
    AmbiguousHumanReviewCurrency(AmbiguousHumanReviewCurrency),
    UntrustedActor(UntrustedActorBlocker),
    BlockingHumanFeedback(ReviewFeedbackIdentity),
    MissingCheck(String),
    NonSuccessCheck(CheckFailure),
    AmbiguousCheck(AmbiguousCheck),
    InsufficientApproval(ApprovalShortfall),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewTriage {
    blockers: Vec<ReadinessBlocker>,
    blocking_human_feedback: Vec<TriagedFeedback>,
    bot_advisories: Vec<TriagedFeedback>,
    approval_count: usize,
    approval_review_ids: Vec<ProviderObjectId>,
}

impl ReviewTriage {
    pub fn blockers(&self) -> &[ReadinessBlocker] {
        &self.blockers
    }

    pub fn blocking_human_feedback(&self) -> &[TriagedFeedback] {
        &self.blocking_human_feedback
    }

    pub fn bot_advisories(&self) -> &[TriagedFeedback] {
        &self.bot_advisories
    }

    pub fn approval_count(&self) -> usize {
        self.approval_count
    }

    pub fn approval_review_ids(&self) -> &[ProviderObjectId] {
        &self.approval_review_ids
    }

    pub fn is_ready(&self) -> bool {
        self.blockers.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispositionDecision {
    Addressed,
    Acknowledged,
    Deferred,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedDisposition {
    snapshot_sha256: String,
    head_oid: String,
    base_oid: String,
    feedback_identity: ReviewFeedbackIdentity,
    actor: TrustedActorIdentity,
    decision: DispositionDecision,
    summary: String,
    record_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifiedDispositionWire {
    snapshot_sha256: String,
    head_oid: String,
    base_oid: String,
    feedback_identity: ReviewFeedbackIdentity,
    actor: TrustedActorIdentity,
    decision: DispositionDecision,
    summary: String,
    record_sha256: String,
}

#[derive(Serialize)]
struct DispositionDigestPayload<'a> {
    snapshot_sha256: &'a str,
    head_oid: &'a str,
    base_oid: &'a str,
    feedback_identity: &'a ReviewFeedbackIdentity,
    actor: &'a TrustedActorIdentity,
    decision: DispositionDecision,
    summary: &'a str,
}

impl VerifiedDisposition {
    pub fn new(
        snapshot: &FrozenReviewSnapshot,
        feedback_identity: ReviewFeedbackIdentity,
        actor: TrustedActorIdentity,
        decision: DispositionDecision,
        summary: impl Into<String>,
    ) -> Result<Self> {
        let summary = summary.into();
        validate_disposition_summary(&summary)?;
        let observed_actor = actor_for_feedback(snapshot, &feedback_identity)?;
        if !actor.matches(observed_actor) {
            bail!("disposition actor does not exactly match the frozen feedback actor");
        }
        let mut value = Self {
            snapshot_sha256: snapshot.canonical_sha256().to_owned(),
            head_oid: snapshot
                .item()
                .head_oid()
                .context("frozen review snapshot omitted its PR head")?
                .to_owned(),
            base_oid: snapshot
                .item()
                .base_oid()
                .context("frozen review snapshot omitted its PR base")?
                .to_owned(),
            feedback_identity,
            actor,
            decision,
            summary,
            record_sha256: String::new(),
        };
        value.record_sha256 = value.compute_record_sha256()?;
        value.validate_against(snapshot)?;
        Ok(value)
    }

    pub fn snapshot_sha256(&self) -> &str {
        &self.snapshot_sha256
    }

    pub fn head_oid(&self) -> &str {
        &self.head_oid
    }

    pub fn base_oid(&self) -> &str {
        &self.base_oid
    }

    pub fn feedback_identity(&self) -> &ReviewFeedbackIdentity {
        &self.feedback_identity
    }

    pub fn actor(&self) -> &TrustedActorIdentity {
        &self.actor
    }

    pub fn decision(&self) -> DispositionDecision {
        self.decision
    }

    pub fn summary(&self) -> &str {
        &self.summary
    }

    pub fn record_sha256(&self) -> &str {
        &self.record_sha256
    }

    /// Restores a durable disposition only when its exact frozen source is
    /// supplied again. Standalone serde deserialization is deliberately not
    /// implemented because a self-hash cannot prove source membership.
    pub fn restore_json(snapshot: &FrozenReviewSnapshot, encoded: &[u8]) -> Result<Self> {
        if encoded.len() > MAX_DISPOSITION_RECORD_BYTES || encoded.contains(&0) {
            bail!("serialized disposition is malformed or exceeds its byte bound");
        }
        let wire = serde_json::from_slice::<VerifiedDispositionWire>(encoded)
            .context("serialized disposition is not strict valid JSON")?;
        let value = Self::from_wire(wire)?;
        value.validate_against(snapshot)?;
        Ok(value)
    }

    pub fn validate_against(&self, snapshot: &FrozenReviewSnapshot) -> Result<()> {
        self.validate_record()?;
        if self.snapshot_sha256 != snapshot.canonical_sha256()
            || Some(self.head_oid.as_str()) != snapshot.item().head_oid()
            || Some(self.base_oid.as_str()) != snapshot.item().base_oid()
        {
            bail!("disposition is not bound to the frozen snapshot head and base");
        }
        let observed_actor = actor_for_feedback(snapshot, &self.feedback_identity)?;
        if !self.actor.matches(observed_actor) {
            bail!("disposition actor does not exactly match the frozen feedback actor");
        }
        Ok(())
    }

    fn validate_record(&self) -> Result<()> {
        validate_sha256(&self.snapshot_sha256, "disposition snapshot digest")?;
        validate_git_oid(&self.head_oid, "disposition head OID")?;
        validate_git_oid(&self.base_oid, "disposition base OID")?;
        self.feedback_identity.validate()?;
        self.actor.validate()?;
        if self.feedback_identity.provider_id() != self.actor.provider_actor_id().provider_id() {
            bail!("disposition feedback and actor providers do not match");
        }
        validate_disposition_summary(&self.summary)?;
        validate_sha256(&self.record_sha256, "disposition record digest")?;
        if self.record_sha256 != self.compute_record_sha256()? {
            bail!("disposition record digest does not match its canonical fields");
        }
        Ok(())
    }

    fn compute_record_sha256(&self) -> Result<String> {
        canonical_digest(
            DISPOSITION_DIGEST_DOMAIN,
            &DispositionDigestPayload {
                snapshot_sha256: &self.snapshot_sha256,
                head_oid: &self.head_oid,
                base_oid: &self.base_oid,
                feedback_identity: &self.feedback_identity,
                actor: &self.actor,
                decision: self.decision,
                summary: &self.summary,
            },
            "verified review disposition",
        )
    }

    fn from_wire(wire: VerifiedDispositionWire) -> Result<Self> {
        let value = Self {
            snapshot_sha256: wire.snapshot_sha256,
            head_oid: wire.head_oid,
            base_oid: wire.base_oid,
            feedback_identity: wire.feedback_identity,
            actor: wire.actor,
            decision: wire.decision,
            summary: wire.summary,
            record_sha256: wire.record_sha256,
        };
        value.validate_record()?;
        Ok(value)
    }
}

impl ReviewFeedbackIdentity {
    fn provider_id(&self) -> &str {
        match self {
            Self::Review { provider_review_id } => provider_review_id.provider_id(),
            Self::ThreadComment {
                provider_thread_id, ..
            } => provider_thread_id.provider_id(),
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::Review { provider_review_id }
                if provider_review_id.kind() == ProviderObjectKind::Review =>
            {
                Ok(())
            }
            Self::ThreadComment {
                provider_thread_id,
                provider_comment_id,
            } if provider_thread_id.kind() == ProviderObjectKind::ReviewThread
                && provider_comment_id.kind() == ProviderObjectKind::Comment
                && provider_thread_id.provider_id() == provider_comment_id.provider_id() =>
            {
                Ok(())
            }
            Self::Review { .. } => bail!("disposition review identity has the wrong object kind"),
            Self::ThreadComment { .. } => {
                bail!("disposition thread/comment identity is malformed or provider-mismatched")
            }
        }
    }
}

fn validate_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} must be an exact lowercase SHA-256 digest");
    }
    Ok(())
}

fn validate_git_oid(value: &str, label: &str) -> Result<()> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} must be an exact lowercase 40- or 64-hex OID");
    }
    Ok(())
}

fn validate_disposition_summary(summary: &str) -> Result<()> {
    if summary.trim().is_empty()
        || summary.len() > MAX_DISPOSITION_SUMMARY_BYTES
        || summary
            .bytes()
            .any(|byte| byte == 0 || (byte.is_ascii_control() && byte != b'\n' && byte != b'\t'))
    {
        bail!("disposition summary must be nonempty, well formed, and bounded");
    }
    Ok(())
}

fn actor_for_feedback<'a>(
    snapshot: &'a FrozenReviewSnapshot,
    identity: &ReviewFeedbackIdentity,
) -> Result<&'a ForgeActor> {
    match identity {
        ReviewFeedbackIdentity::Review { provider_review_id } => snapshot
            .snapshot()
            .reviews()
            .iter()
            .find(|review| review.provider_review_id() == provider_review_id)
            .map(ForgeReview::author)
            .context("disposition review identity is absent from the frozen snapshot"),
        ReviewFeedbackIdentity::ThreadComment {
            provider_thread_id,
            provider_comment_id,
        } => snapshot
            .snapshot()
            .threads()
            .iter()
            .find(|thread| thread.provider_thread_id() == provider_thread_id)
            .and_then(|thread| {
                thread
                    .comments()
                    .iter()
                    .find(|comment| comment.provider_comment_id() == provider_comment_id)
            })
            .map(|comment| comment.author())
            .context("disposition thread/comment identity is absent from the frozen snapshot"),
    }
}

fn validate_disposition_set(
    snapshot: &FrozenReviewSnapshot,
    dispositions: &[VerifiedDisposition],
) -> Result<()> {
    let mut identities = BTreeSet::new();
    let mut digests = BTreeSet::new();
    for disposition in dispositions {
        disposition.validate_against(snapshot)?;
        if !identities.insert(disposition.feedback_identity().clone())
            || !digests.insert(disposition.record_sha256())
        {
            bail!("review-loop disposition was duplicated or replayed");
        }
    }
    Ok(())
}

fn validate_blocking_feedback_coverage(
    snapshot: &FrozenReviewSnapshot,
    policy: &ReviewLoopPolicy,
    dispositions: &[VerifiedDisposition],
) -> Result<()> {
    let triage = validate_actionable_disposition_set(snapshot, policy, dispositions)?;
    let disposition_by_identity = dispositions
        .iter()
        .map(|disposition| (disposition.feedback_identity(), disposition))
        .collect::<std::collections::BTreeMap<_, _>>();
    for feedback in triage.blocking_human_feedback() {
        let disposition = disposition_by_identity
            .get(feedback.identity())
            .context("blocking human feedback omitted its required verified disposition")?;
        if disposition.decision() != DispositionDecision::Addressed {
            bail!("blocking human feedback must be addressed before refresh");
        }
    }
    Ok(())
}

fn validate_actionable_disposition_set(
    snapshot: &FrozenReviewSnapshot,
    policy: &ReviewLoopPolicy,
    dispositions: &[VerifiedDisposition],
) -> Result<ReviewTriage> {
    validate_disposition_set(snapshot, dispositions)?;
    let triage = snapshot.triage(policy);
    let allowed_identities = triage
        .blocking_human_feedback()
        .iter()
        .chain(triage.bot_advisories())
        .map(|feedback| feedback.identity())
        .collect::<BTreeSet<_>>();
    if dispositions
        .iter()
        .any(|disposition| !allowed_identities.contains(disposition.feedback_identity()))
    {
        bail!("disposition does not identify actionable blocking-human or advisory-bot feedback");
    }
    Ok(triage)
}

/// Builds the only mutation emitted by the review loop: one deterministic,
/// PR-level append-comment effect containing verified dispositions.
pub fn build_pull_request_disposition_publication(
    snapshot: &FrozenReviewSnapshot,
    policy: &ReviewLoopPolicy,
    publisher: ForgeActor,
    dispositions: &[VerifiedDisposition],
) -> Result<ForgeEffectRequest> {
    if snapshot.item().kind() != ForgeItemKind::PullRequest || dispositions.is_empty() {
        bail!("PR disposition publication requires a PR and at least one disposition");
    }
    if publisher.provider_id() != snapshot.item().repository().provider_id() {
        bail!("disposition publisher is not bound to the PR provider");
    }
    let mut ordered = dispositions.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.record_sha256.cmp(&right.record_sha256));
    validate_actionable_disposition_set(snapshot, policy, dispositions)?;

    let mut body = format!(
        "Review-loop dispositions for head `{}` (snapshot `{}`):\n",
        snapshot
            .item()
            .head_oid()
            .context("frozen PR snapshot omitted its head")?,
        snapshot.canonical_sha256()
    );
    for disposition in &ordered {
        body.push_str("\n- ");
        body.push_str(&format_feedback_identity(&disposition.feedback_identity));
        body.push_str(": **");
        body.push_str(disposition_decision_name(disposition.decision));
        body.push_str("** — ");
        body.push_str(&disposition.summary);
        body.push_str(" (`");
        body.push_str(&disposition.record_sha256);
        body.push_str("`)");
    }

    #[derive(Serialize)]
    struct PublicationIdentity<'a> {
        snapshot_sha256: &'a str,
        publisher: &'a ForgeActor,
        disposition_sha256s: Vec<&'a str>,
        body: &'a str,
    }
    let publication_sha256 = canonical_digest(
        PUBLICATION_EFFECT_DIGEST_DOMAIN,
        &PublicationIdentity {
            snapshot_sha256: snapshot.canonical_sha256(),
            publisher: &publisher,
            disposition_sha256s: ordered
                .iter()
                .map(|disposition| disposition.record_sha256())
                .collect(),
            body: &body,
        },
        "PR disposition publication",
    )?;
    let effect = AppendCommentEffect::new(
        format!("review-dispositions:{publication_sha256}"),
        snapshot.item().clone(),
        publisher,
        body,
    )?;
    ForgeEffectRequest::append_comment(effect)
}

fn disposition_decision_name(decision: DispositionDecision) -> &'static str {
    match decision {
        DispositionDecision::Addressed => "addressed",
        DispositionDecision::Acknowledged => "acknowledged",
        DispositionDecision::Deferred => "deferred",
        DispositionDecision::NotApplicable => "not applicable",
    }
}

fn format_feedback_identity(identity: &ReviewFeedbackIdentity) -> String {
    match identity {
        ReviewFeedbackIdentity::Review { provider_review_id } => {
            format!("review `{}`", provider_review_id.stable_id())
        }
        ReviewFeedbackIdentity::ThreadComment {
            provider_thread_id,
            provider_comment_id,
        } => format!(
            "thread `{}` comment `{}`",
            provider_thread_id.stable_id(),
            provider_comment_id.stable_id()
        ),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessEvidence {
    snapshot_sha256: String,
    observed_at: ForgeTimestamp,
    head_oid: String,
    base_oid: String,
    policy_sha256: String,
    disposition_sha256s: Vec<String>,
    successful_check_ids: Vec<ProviderObjectId>,
    approval_review_ids: Vec<ProviderObjectId>,
}

impl ReadinessEvidence {
    pub fn snapshot_sha256(&self) -> &str {
        &self.snapshot_sha256
    }

    pub fn observed_at(&self) -> &ForgeTimestamp {
        &self.observed_at
    }

    pub fn head_oid(&self) -> &str {
        &self.head_oid
    }

    pub fn base_oid(&self) -> &str {
        &self.base_oid
    }

    pub fn policy_sha256(&self) -> &str {
        &self.policy_sha256
    }

    pub fn disposition_sha256s(&self) -> &[String] {
        &self.disposition_sha256s
    }

    pub fn successful_check_ids(&self) -> &[ProviderObjectId] {
        &self.successful_check_ids
    }

    pub fn approval_review_ids(&self) -> &[ProviderObjectId] {
        &self.approval_review_ids
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessAuthority {
    ReviewLoopOnlyNotMergePermission,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewLoopReadinessProof {
    evidence: ReadinessEvidence,
    authority: ReadinessAuthority,
    proof_sha256: String,
}

#[derive(Serialize)]
struct ReadinessProofDigestPayload<'a> {
    evidence: &'a ReadinessEvidence,
    authority: ReadinessAuthority,
}

impl ReviewLoopReadinessProof {
    pub fn evidence(&self) -> &ReadinessEvidence {
        &self.evidence
    }

    pub fn authority(&self) -> ReadinessAuthority {
        self.authority
    }

    pub fn proof_sha256(&self) -> &str {
        &self.proof_sha256
    }

    /// This proof covers only the review-loop policy represented by its
    /// digest. Repository rules and merge authorization remain out of scope.
    pub fn grants_merge_permission(&self) -> bool {
        false
    }

    pub fn validate_against(
        &self,
        snapshot: &FrozenReviewSnapshot,
        policy: &ReviewLoopPolicy,
        dispositions: &[VerifiedDisposition],
    ) -> Result<()> {
        let evaluation = evaluate_review_loop_readiness(snapshot, policy, dispositions)?;
        match evaluation {
            ReviewLoopReadinessEvaluation::Ready(current) if current == *self => Ok(()),
            ReviewLoopReadinessEvaluation::Ready(_) => {
                bail!("readiness proof does not match the current evidence")
            }
            ReviewLoopReadinessEvaluation::Blocked(_) => {
                bail!("current review-loop evidence is blocked")
            }
        }
    }

    /// Validates a proof produced after one or more head-changing refreshes.
    /// Historical dispositions are checked through the state's retained
    /// frozen-source chain rather than against the current snapshot.
    pub fn validate_against_state(&self, state: &ReviewLoopState) -> Result<()> {
        state.validate_record()?;
        match state.readiness()? {
            ReviewLoopReadinessEvaluation::Ready(current) if current == *self => Ok(()),
            ReviewLoopReadinessEvaluation::Ready(_) => {
                bail!("readiness proof does not match the durable review-loop state")
            }
            ReviewLoopReadinessEvaluation::Blocked(_) => {
                bail!("durable review-loop state is blocked")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewLoopReadinessBlockers {
    evidence: ReadinessEvidence,
    blockers: Vec<ReadinessBlocker>,
}

impl ReviewLoopReadinessBlockers {
    pub fn evidence(&self) -> &ReadinessEvidence {
        &self.evidence
    }

    pub fn blockers(&self) -> &[ReadinessBlocker] {
        &self.blockers
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "readiness", content = "evidence", rename_all = "snake_case")]
pub enum ReviewLoopReadinessEvaluation {
    Ready(ReviewLoopReadinessProof),
    Blocked(ReviewLoopReadinessBlockers),
}

pub fn evaluate_review_loop_readiness(
    snapshot: &FrozenReviewSnapshot,
    policy: &ReviewLoopPolicy,
    dispositions: &[VerifiedDisposition],
) -> Result<ReviewLoopReadinessEvaluation> {
    validate_actionable_disposition_set(snapshot, policy, dispositions)?;
    evaluate_readiness_with_disposition_digests(
        snapshot,
        policy,
        dispositions
            .iter()
            .map(|disposition| disposition.record_sha256().to_owned())
            .collect(),
    )
}

fn evaluate_readiness_with_disposition_digests(
    snapshot: &FrozenReviewSnapshot,
    policy: &ReviewLoopPolicy,
    mut disposition_sha256s: Vec<String>,
) -> Result<ReviewLoopReadinessEvaluation> {
    disposition_sha256s.sort();
    if disposition_sha256s
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        bail!("readiness evidence contains duplicate disposition digests");
    }
    let triage = snapshot.triage(policy);
    let mut successful_check_ids = Vec::new();
    for required in policy.required_checks() {
        let matching = snapshot
            .snapshot()
            .checks()
            .iter()
            .filter(|check| check.name() == required.name())
            .collect::<Vec<_>>();
        if matching.len() == 1
            && required.trusts(matching[0].actor())
            && matching[0].status() == ForgeCheckStatus::Completed
            && matching[0].conclusion() == Some(ForgeCheckConclusion::Success)
        {
            successful_check_ids.push(matching[0].provider_check_id().clone());
        }
    }
    successful_check_ids.sort();

    let approval_review_ids = triage.approval_review_ids().to_vec();

    let evidence = ReadinessEvidence {
        snapshot_sha256: snapshot.canonical_sha256().to_owned(),
        observed_at: snapshot.observed_at().clone(),
        head_oid: snapshot
            .item()
            .head_oid()
            .context("readiness snapshot omitted its PR head")?
            .to_owned(),
        base_oid: snapshot
            .item()
            .base_oid()
            .context("readiness snapshot omitted its PR base")?
            .to_owned(),
        policy_sha256: policy.canonical_sha256()?,
        disposition_sha256s,
        successful_check_ids,
        approval_review_ids,
    };
    if triage.is_ready() {
        let authority = ReadinessAuthority::ReviewLoopOnlyNotMergePermission;
        let proof_sha256 = canonical_digest(
            READINESS_DIGEST_DOMAIN,
            &ReadinessProofDigestPayload {
                evidence: &evidence,
                authority,
            },
            "review-loop readiness proof",
        )?;
        Ok(ReviewLoopReadinessEvaluation::Ready(
            ReviewLoopReadinessProof {
                evidence,
                authority,
                proof_sha256,
            },
        ))
    } else {
        Ok(ReviewLoopReadinessEvaluation::Blocked(
            ReviewLoopReadinessBlockers {
                evidence,
                blockers: triage.blockers,
            },
        ))
    }
}

fn phase_for_evidence(
    snapshot: &FrozenReviewSnapshot,
    policy: &ReviewLoopPolicy,
    attempt_count: usize,
    disposition_sha256s: Vec<String>,
) -> Result<ReviewLoopPhase> {
    match evaluate_readiness_with_disposition_digests(snapshot, policy, disposition_sha256s)? {
        ReviewLoopReadinessEvaluation::Ready(_) => Ok(ReviewLoopPhase::Ready),
        ReviewLoopReadinessEvaluation::Blocked(_) if attempt_count >= policy.max_attempts() => {
            Ok(ReviewLoopPhase::Exhausted)
        }
        ReviewLoopReadinessEvaluation::Blocked(_) => Ok(ReviewLoopPhase::Active),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewLoopPhase {
    Active,
    Ready,
    Exhausted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewLoopAttempt {
    sequence: usize,
    attempt_id: String,
    prior_snapshot: FrozenReviewSnapshot,
    refreshed_snapshot_sha256: String,
    disposition_sha256s: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewLoopAttemptWire {
    sequence: usize,
    attempt_id: String,
    prior_snapshot: FrozenReviewSnapshotWire,
    refreshed_snapshot_sha256: String,
    disposition_sha256s: Vec<String>,
}

impl ReviewLoopAttempt {
    pub fn sequence(&self) -> usize {
        self.sequence
    }

    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    pub fn prior_snapshot_sha256(&self) -> &str {
        self.prior_snapshot.canonical_sha256()
    }

    pub fn refreshed_snapshot_sha256(&self) -> &str {
        &self.refreshed_snapshot_sha256
    }

    pub fn disposition_sha256s(&self) -> &[String] {
        &self.disposition_sha256s
    }

    fn validate_record(&self) -> Result<()> {
        if self.sequence == 0 || self.sequence > MAX_REVIEW_LOOP_ATTEMPTS {
            bail!("review-loop attempt sequence is outside its bounded range");
        }
        validate_attempt_id(&self.attempt_id)?;
        validate_sha256(
            &self.refreshed_snapshot_sha256,
            "refreshed review snapshot digest",
        )?;
        let mut prior = None;
        for digest in &self.disposition_sha256s {
            validate_sha256(digest, "attempt disposition digest")?;
            if prior.as_ref().is_some_and(|previous| *previous >= digest) {
                bail!("attempt disposition digests are duplicated or non-canonical");
            }
            prior = Some(digest);
        }
        Ok(())
    }
}

impl ReviewLoopAttempt {
    fn from_wire(wire: ReviewLoopAttemptWire, trusted_not_after: &ForgeTimestamp) -> Result<Self> {
        let value = Self {
            sequence: wire.sequence,
            attempt_id: wire.attempt_id,
            prior_snapshot: FrozenReviewSnapshot::from_wire(
                wire.prior_snapshot,
                trusted_not_after,
            )?,
            refreshed_snapshot_sha256: wire.refreshed_snapshot_sha256,
            disposition_sha256s: wire.disposition_sha256s,
        };
        value.validate_record()?;
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewLoopState {
    policy: ReviewLoopPolicy,
    policy_sha256: String,
    current_snapshot: FrozenReviewSnapshot,
    attempts: Vec<ReviewLoopAttempt>,
    dispositions: Vec<VerifiedDisposition>,
    phase: ReviewLoopPhase,
    predecessor_state_sha256: Option<String>,
    state_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewLoopStateWire {
    policy: ReviewLoopPolicy,
    policy_sha256: String,
    current_snapshot: FrozenReviewSnapshotWire,
    attempts: Vec<ReviewLoopAttemptWire>,
    dispositions: Vec<VerifiedDispositionWire>,
    phase: ReviewLoopPhase,
    predecessor_state_sha256: Option<String>,
    state_sha256: String,
}

#[derive(Serialize)]
struct ReviewLoopStateDigestPayload<'a> {
    policy_sha256: &'a str,
    current_snapshot_sha256: &'a str,
    attempts: &'a [ReviewLoopAttempt],
    disposition_sha256s: Vec<&'a str>,
    phase: ReviewLoopPhase,
    predecessor_state_sha256: Option<&'a str>,
}

fn compute_review_loop_state_sha256(
    policy_sha256: &str,
    current_snapshot: &FrozenReviewSnapshot,
    attempts: &[ReviewLoopAttempt],
    disposition_sha256s: Vec<&str>,
    phase: ReviewLoopPhase,
    predecessor_state_sha256: Option<&str>,
) -> Result<String> {
    canonical_digest(
        REVIEW_LOOP_STATE_DIGEST_DOMAIN,
        &ReviewLoopStateDigestPayload {
            policy_sha256,
            current_snapshot_sha256: current_snapshot.canonical_sha256(),
            attempts,
            disposition_sha256s,
            phase,
            predecessor_state_sha256,
        },
        "review-loop state",
    )
}

#[derive(Serialize)]
struct ReviewLoopAttemptIdPayload<'a> {
    policy_sha256: &'a str,
    prior_snapshot_sha256: &'a str,
    refreshed_snapshot_sha256: &'a str,
    sequence: usize,
    disposition_sha256s: &'a [String],
}

fn derive_attempt_id(
    policy_sha256: &str,
    prior_snapshot: &FrozenReviewSnapshot,
    refreshed_snapshot: &FrozenReviewSnapshot,
    sequence: usize,
    disposition_sha256s: &[String],
) -> Result<String> {
    let digest = canonical_digest(
        REVIEW_LOOP_ATTEMPT_ID_DOMAIN,
        &ReviewLoopAttemptIdPayload {
            policy_sha256,
            prior_snapshot_sha256: prior_snapshot.canonical_sha256(),
            refreshed_snapshot_sha256: refreshed_snapshot.canonical_sha256(),
            sequence,
            disposition_sha256s,
        },
        "review-loop attempt identity",
    )?;
    Ok(format!("attempt:{digest}"))
}

/// Observe a pull request and construct the initial review-loop state.
///
/// This is the production entry a CLI subcommand, supervisor role, or
/// workflow should call. It does not persist state, dispatch fix work,
/// or grant merge authority.
/// [`ReviewLoopReadinessProof::grants_merge_permission`] stays false.
pub fn open_review_loop<T>(
    transport: &T,
    item: &ForgeItem,
    policy: ReviewLoopPolicy,
    trusted_not_after: &ForgeTimestamp,
) -> Result<ReviewLoopState>
where
    T: ForgeTransport + ?Sized,
{
    let snapshot = FrozenReviewSnapshot::observe(transport, item, trusted_not_after)?;
    ReviewLoopState::new(policy, snapshot, trusted_not_after)
}

impl ReviewLoopState {
    pub fn new(
        policy: ReviewLoopPolicy,
        current_snapshot: FrozenReviewSnapshot,
        trusted_not_after: &ForgeTimestamp,
    ) -> Result<Self> {
        current_snapshot.validate_not_after(trusted_not_after)?;
        let policy_sha256 = policy.canonical_sha256()?;
        let phase = phase_for_evidence(&current_snapshot, &policy, 0, Vec::new())?;
        let mut value = Self {
            policy,
            policy_sha256,
            current_snapshot,
            attempts: Vec::new(),
            dispositions: Vec::new(),
            phase,
            predecessor_state_sha256: None,
            state_sha256: String::new(),
        };
        value.state_sha256 = value.compute_state_sha256()?;
        value.validate_record()?;
        Ok(value)
    }

    pub fn restore_json(encoded: &[u8], trusted_not_after: &ForgeTimestamp) -> Result<Self> {
        if encoded.len() > MAX_REVIEW_LOOP_STATE_RECORD_BYTES || encoded.contains(&0) {
            bail!("serialized review-loop state is malformed or exceeds its byte bound");
        }
        let wire = serde_json::from_slice::<ReviewLoopStateWire>(encoded)
            .context("serialized review-loop state is not strict valid JSON")?;
        Self::from_wire(wire, trusted_not_after)
    }

    pub fn policy(&self) -> &ReviewLoopPolicy {
        &self.policy
    }

    pub fn policy_sha256(&self) -> &str {
        &self.policy_sha256
    }

    pub fn current_snapshot(&self) -> &FrozenReviewSnapshot {
        &self.current_snapshot
    }

    pub fn attempts(&self) -> &[ReviewLoopAttempt] {
        &self.attempts
    }

    pub fn dispositions(&self) -> &[VerifiedDisposition] {
        &self.dispositions
    }

    pub fn phase(&self) -> ReviewLoopPhase {
        self.phase
    }

    pub fn predecessor_state_sha256(&self) -> Option<&str> {
        self.predecessor_state_sha256.as_deref()
    }

    pub fn state_sha256(&self) -> &str {
        &self.state_sha256
    }

    pub fn readiness(&self) -> Result<ReviewLoopReadinessEvaluation> {
        let mut evaluation = evaluate_readiness_with_disposition_digests(
            &self.current_snapshot,
            &self.policy,
            self.dispositions
                .iter()
                .map(|disposition| disposition.record_sha256().to_owned())
                .collect(),
        )?;
        if self.phase == ReviewLoopPhase::Exhausted {
            match &mut evaluation {
                ReviewLoopReadinessEvaluation::Blocked(blocked) => {
                    blocked
                        .blockers
                        .push(ReadinessBlocker::AttemptLimitExhausted {
                            max_attempts: self.policy.max_attempts(),
                        });
                }
                ReviewLoopReadinessEvaluation::Ready(_) => {
                    bail!("exhausted review-loop state contains ready evidence")
                }
            }
        }
        Ok(evaluation)
    }

    pub fn refresh<T>(
        &self,
        transport: &T,
        current_item: &ForgeItem,
        trusted_not_after: &ForgeTimestamp,
        dispositions: Vec<VerifiedDisposition>,
    ) -> Result<Self>
    where
        T: ForgeTransport + ?Sized,
    {
        let refreshed = FrozenReviewSnapshot::observe(transport, current_item, trusted_not_after)?;
        self.refresh_with_snapshot(current_item, refreshed, trusted_not_after, dispositions)
    }

    fn refresh_with_snapshot(
        &self,
        current_item: &ForgeItem,
        refreshed: FrozenReviewSnapshot,
        trusted_not_after: &ForgeTimestamp,
        mut dispositions: Vec<VerifiedDisposition>,
    ) -> Result<Self> {
        if self.phase != ReviewLoopPhase::Active {
            bail!("terminal review-loop state cannot be refreshed");
        }
        let sequence = self
            .attempts
            .len()
            .checked_add(1)
            .context("review-loop attempt sequence overflowed")?;
        refreshed.validate_not_after(trusted_not_after)?;
        if refreshed.item() != current_item {
            bail!("refreshed snapshot is not bound to the declared current PR head and base");
        }
        if !same_logical_pull_request(self.current_snapshot.item(), current_item) {
            bail!("review-loop refresh changed the logical pull request");
        }
        if refreshed.observed_at() <= self.current_snapshot.observed_at() {
            bail!("review-loop refresh observation is not strictly later");
        }

        dispositions.sort_by(|left, right| left.record_sha256.cmp(&right.record_sha256));
        validate_blocking_feedback_coverage(&self.current_snapshot, &self.policy, &dispositions)?;
        let mut all_feedback_identities = self
            .dispositions
            .iter()
            .map(|disposition| disposition.feedback_identity().clone())
            .collect::<BTreeSet<_>>();
        let mut all_disposition_digests = self
            .dispositions
            .iter()
            .map(|disposition| disposition.record_sha256())
            .collect::<BTreeSet<_>>();
        if dispositions.iter().any(|candidate| {
            !all_feedback_identities.insert(candidate.feedback_identity().clone())
                || !all_disposition_digests.insert(candidate.record_sha256())
        }) {
            bail!("review-loop disposition was duplicated or replayed");
        }

        let disposition_sha256s = dispositions
            .iter()
            .map(|disposition| disposition.record_sha256().to_owned())
            .collect::<Vec<_>>();
        let attempt_id = derive_attempt_id(
            &self.policy_sha256,
            &self.current_snapshot,
            &refreshed,
            sequence,
            &disposition_sha256s,
        )?;
        if self
            .attempts
            .iter()
            .any(|attempt| attempt.attempt_id == attempt_id)
        {
            bail!("review-loop attempt id was replayed");
        }
        let attempt = ReviewLoopAttempt {
            sequence,
            attempt_id,
            prior_snapshot: self.current_snapshot.clone(),
            refreshed_snapshot_sha256: refreshed.canonical_sha256().to_owned(),
            disposition_sha256s,
        };
        let mut attempts = self.attempts.clone();
        attempts.push(attempt);
        let mut all_dispositions = self.dispositions.clone();
        all_dispositions.extend(dispositions);
        all_dispositions.sort_by(|left, right| left.record_sha256.cmp(&right.record_sha256));

        let phase = phase_for_evidence(
            &refreshed,
            &self.policy,
            attempts.len(),
            all_dispositions
                .iter()
                .map(|disposition| disposition.record_sha256().to_owned())
                .collect(),
        )?;
        let mut next = Self {
            policy: self.policy.clone(),
            policy_sha256: self.policy_sha256.clone(),
            current_snapshot: refreshed,
            attempts,
            dispositions: all_dispositions,
            phase,
            predecessor_state_sha256: Some(self.state_sha256.clone()),
            state_sha256: String::new(),
        };
        next.state_sha256 = next.compute_state_sha256()?;
        next.validate_record()?;
        Ok(next)
    }

    fn validate_record(&self) -> Result<()> {
        validate_sha256(&self.policy_sha256, "review-loop policy digest")?;
        if self.policy_sha256 != self.policy.canonical_sha256()? {
            bail!("review-loop state policy digest does not match its policy");
        }
        if self.attempts.len() > self.policy.max_attempts() {
            bail!("review-loop state exceeds its configured attempt bound");
        }
        match (self.attempts.is_empty(), &self.predecessor_state_sha256) {
            (true, None) => {}
            (false, Some(digest)) => {
                validate_sha256(digest, "predecessor review-loop state digest")?
            }
            _ => bail!("review-loop state predecessor linkage conflicts with its attempts"),
        }

        let mut disposition_by_digest = std::collections::BTreeMap::new();
        let mut feedback_identities = BTreeSet::new();
        let mut previous_disposition_digest: Option<&str> = None;
        for disposition in &self.dispositions {
            disposition.validate_record()?;
            if previous_disposition_digest
                .as_ref()
                .is_some_and(|previous| *previous >= disposition.record_sha256())
                || disposition_by_digest
                    .insert(disposition.record_sha256(), disposition)
                    .is_some()
                || !feedback_identities.insert(disposition.feedback_identity())
            {
                bail!("review-loop state dispositions are duplicated or non-canonical");
            }
            previous_disposition_digest = Some(disposition.record_sha256());
        }

        let mut attempt_ids = BTreeSet::new();
        let mut assigned_disposition_digests = BTreeSet::new();
        for (index, attempt) in self.attempts.iter().enumerate() {
            attempt.validate_record()?;
            if attempt.sequence != index + 1 || !attempt_ids.insert(attempt.attempt_id()) {
                bail!("review-loop attempt sequence or stable identity was replayed");
            }
            if !same_logical_pull_request(
                attempt.prior_snapshot.item(),
                self.current_snapshot.item(),
            ) {
                bail!("durable review-loop history changed the logical pull request");
            }
            if let Some(previous) = index
                .checked_sub(1)
                .and_then(|previous_index| self.attempts.get(previous_index))
            {
                if previous.refreshed_snapshot_sha256 != attempt.prior_snapshot.canonical_sha256() {
                    bail!("durable review-loop snapshot digest chain is broken");
                }
            }
            let refreshed = self
                .attempts
                .get(index + 1)
                .map(|next| &next.prior_snapshot)
                .unwrap_or(&self.current_snapshot);
            if attempt.refreshed_snapshot_sha256 != refreshed.canonical_sha256()
                || refreshed.observed_at() <= attempt.prior_snapshot.observed_at()
                || !same_logical_pull_request(attempt.prior_snapshot.item(), refreshed.item())
            {
                bail!("durable review-loop refresh evidence is stale or chain-mismatched");
            }
            let expected_attempt_id = derive_attempt_id(
                &self.policy_sha256,
                &attempt.prior_snapshot,
                refreshed,
                attempt.sequence,
                &attempt.disposition_sha256s,
            )?;
            if attempt.attempt_id != expected_attempt_id {
                bail!("review-loop attempt identity is not deterministically bound");
            }

            let mut attempt_dispositions = Vec::new();
            for digest in attempt.disposition_sha256s() {
                if !assigned_disposition_digests.insert(digest.as_str()) {
                    bail!("durable review-loop disposition digest was replayed");
                }
                let disposition = disposition_by_digest
                    .get(digest.as_str())
                    .context("review-loop attempt references an absent disposition")?;
                disposition.validate_against(&attempt.prior_snapshot)?;
                attempt_dispositions.push((*disposition).clone());
            }
            validate_blocking_feedback_coverage(
                &attempt.prior_snapshot,
                &self.policy,
                &attempt_dispositions,
            )?;
        }
        if assigned_disposition_digests.len() != disposition_by_digest.len() {
            bail!("review-loop state contains a disposition outside its attempt history");
        }

        validate_sha256(&self.state_sha256, "review-loop state digest")?;

        let initial_snapshot = self
            .attempts
            .first()
            .map(|attempt| &attempt.prior_snapshot)
            .unwrap_or(&self.current_snapshot);
        let initial_phase = phase_for_evidence(initial_snapshot, &self.policy, 0, Vec::new())?;
        let mut reconstructed_digest = compute_review_loop_state_sha256(
            &self.policy_sha256,
            initial_snapshot,
            &[],
            Vec::new(),
            initial_phase,
            None,
        )?;
        if self.attempts.is_empty() {
            if self.phase != initial_phase || self.state_sha256 != reconstructed_digest {
                bail!("initial review-loop state conflicts with its reconstructed evidence");
            }
            self.validate_serialized_size()?;
            return Ok(());
        }

        let mut accumulated_dispositions = Vec::new();
        let mut predecessor_phase = initial_phase;
        for (index, attempt) in self.attempts.iter().enumerate() {
            if predecessor_phase != ReviewLoopPhase::Active {
                bail!("terminal review-loop prefix cannot have a successor attempt");
            }
            for digest in attempt.disposition_sha256s() {
                let disposition = disposition_by_digest
                    .get(digest.as_str())
                    .context("review-loop reconstruction omitted an attempt disposition")?;
                accumulated_dispositions.push(*disposition);
            }
            accumulated_dispositions
                .sort_by(|left, right| left.record_sha256().cmp(right.record_sha256()));
            let refreshed = self
                .attempts
                .get(index + 1)
                .map(|next| &next.prior_snapshot)
                .unwrap_or(&self.current_snapshot);
            let reconstructed_phase = phase_for_evidence(
                refreshed,
                &self.policy,
                index + 1,
                accumulated_dispositions
                    .iter()
                    .map(|disposition| disposition.record_sha256().to_owned())
                    .collect(),
            )?;
            let predecessor = reconstructed_digest;
            reconstructed_digest = compute_review_loop_state_sha256(
                &self.policy_sha256,
                refreshed,
                &self.attempts[..=index],
                accumulated_dispositions
                    .iter()
                    .map(|disposition| disposition.record_sha256())
                    .collect(),
                reconstructed_phase,
                Some(&predecessor),
            )?;
            predecessor_phase = reconstructed_phase;
            if index + 1 == self.attempts.len()
                && (self.predecessor_state_sha256.as_deref() != Some(predecessor.as_str())
                    || self.phase != reconstructed_phase
                    || self.state_sha256 != reconstructed_digest)
            {
                bail!("review-loop predecessor or final state digest chain is not reconstructible");
            }
        }
        self.validate_serialized_size()?;
        Ok(())
    }

    fn validate_serialized_size(&self) -> Result<()> {
        let encoded =
            serde_json::to_vec(self).context("failed to size durable review-loop state")?;
        if encoded.len() > MAX_REVIEW_LOOP_STATE_RECORD_BYTES {
            bail!("durable review-loop state exceeds its serialized byte bound");
        }
        Ok(())
    }

    fn compute_state_sha256(&self) -> Result<String> {
        compute_review_loop_state_sha256(
            &self.policy_sha256,
            &self.current_snapshot,
            &self.attempts,
            self.dispositions
                .iter()
                .map(|disposition| disposition.record_sha256())
                .collect(),
            self.phase,
            self.predecessor_state_sha256.as_deref(),
        )
    }

    fn from_wire(wire: ReviewLoopStateWire, trusted_not_after: &ForgeTimestamp) -> Result<Self> {
        let current_snapshot =
            FrozenReviewSnapshot::from_wire(wire.current_snapshot, trusted_not_after)?;
        let attempts = wire
            .attempts
            .into_iter()
            .map(|attempt| ReviewLoopAttempt::from_wire(attempt, trusted_not_after))
            .collect::<Result<Vec<_>>>()?;
        let dispositions = wire
            .dispositions
            .into_iter()
            .map(VerifiedDisposition::from_wire)
            .collect::<Result<Vec<_>>>()?;
        let value = Self {
            policy: wire.policy,
            policy_sha256: wire.policy_sha256,
            current_snapshot,
            attempts,
            dispositions,
            phase: wire.phase,
            predecessor_state_sha256: wire.predecessor_state_sha256,
            state_sha256: wire.state_sha256,
        };
        value.validate_record()?;
        Ok(value)
    }
}

fn validate_attempt_id(attempt_id: &str) -> Result<()> {
    if attempt_id.is_empty()
        || attempt_id.len() > MAX_ATTEMPT_ID_BYTES
        || !attempt_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        bail!("review-loop attempt id is not a bounded stable identifier");
    }
    Ok(())
}

fn same_logical_pull_request(previous: &ForgeItem, current: &ForgeItem) -> bool {
    previous.kind() == ForgeItemKind::PullRequest
        && current.kind() == ForgeItemKind::PullRequest
        && previous.repository() == current.repository()
        && previous.number() == current.number()
        && previous.provider_item_id() == current.provider_item_id()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::publication::forge_transport::{FakeForgeTransport, ForgeComment, ForgeRepository};

    const HEAD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const BASE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const HEAD_2: &str = "cccccccccccccccccccccccccccccccccccccccc";
    const BASE_2: &str = "dddddddddddddddddddddddddddddddddddddddd";

    fn object(kind: ProviderObjectKind, stable_id: &str) -> ProviderObjectId {
        ProviderObjectId::new("github", kind, stable_id).expect("valid provider object id")
    }

    fn actor(stable_id: &str, handle: &str, kind: ReportedActorKind) -> ForgeActor {
        ForgeActor::new(
            "github",
            object(ProviderObjectKind::Actor, stable_id),
            handle,
            kind,
        )
        .expect("valid actor")
    }

    fn identity(actor: &ForgeActor) -> TrustedActorIdentity {
        TrustedActorIdentity::new(
            actor.provider_actor_id().clone(),
            actor.canonical_handle(),
            actor.reported_kind(),
        )
        .expect("valid trusted identity")
    }

    fn item() -> ForgeItem {
        item_at(HEAD, BASE, "revision:1")
    }

    fn item_at(head: &str, base: &str, revision: &str) -> ForgeItem {
        let repository = ForgeRepository::new(
            "github",
            "github.com/acme/example",
            object(ProviderObjectKind::Repository, "repo:1"),
        )
        .expect("valid repository");
        ForgeItem::new(
            repository,
            ForgeItemKind::PullRequest,
            90,
            object(ProviderObjectKind::Item, "pull:90"),
            revision,
            Some(head.to_owned()),
            Some(base.to_owned()),
        )
        .expect("valid PR item")
    }

    fn timestamp() -> ForgeTimestamp {
        timestamp_at("2026-08-16T01:02:03Z")
    }

    fn timestamp_at(value: &str) -> ForgeTimestamp {
        ForgeTimestamp::new(value).expect("valid timestamp")
    }

    fn review(stable_id: &str, author: ForgeActor, state: ForgeReviewState) -> ForgeReview {
        review_at(stable_id, author, state, HEAD, timestamp())
    }

    fn review_at(
        stable_id: &str,
        author: ForgeActor,
        state: ForgeReviewState,
        head: &str,
        submitted_at: ForgeTimestamp,
    ) -> ForgeReview {
        ForgeReview::new(
            object(ProviderObjectKind::Review, stable_id),
            author,
            state,
            "review body",
            submitted_at,
            head,
        )
        .expect("valid review")
    }

    fn comment(stable_id: &str, author: ForgeActor) -> ForgeComment {
        ForgeComment::new(
            object(ProviderObjectKind::Comment, stable_id),
            author,
            "thread comment",
            format!("https://github.com/acme/example/pull/90#discussion_r{stable_id}"),
            timestamp(),
        )
        .expect("valid comment")
    }

    fn check(stable_id: &str, author: ForgeActor) -> ForgeCheck {
        check_at(stable_id, author, HEAD, timestamp())
    }

    fn check_at(
        stable_id: &str,
        author: ForgeActor,
        head: &str,
        updated_at: ForgeTimestamp,
    ) -> ForgeCheck {
        ForgeCheck::new(
            object(ProviderObjectKind::Check, stable_id),
            author,
            "ci/test",
            ForgeCheckStatus::Completed,
            Some(ForgeCheckConclusion::Success),
            head,
            updated_at,
        )
        .expect("valid check")
    }

    fn policy(human: &ForgeActor, bot: &ForgeActor, check_actor: &ForgeActor) -> ReviewLoopPolicy {
        policy_with_max(human, bot, check_actor, 3)
    }

    fn policy_with_max(
        human: &ForgeActor,
        bot: &ForgeActor,
        check_actor: &ForgeActor,
        max_attempts: usize,
    ) -> ReviewLoopPolicy {
        ReviewLoopPolicy::new(
            vec![
                TrustedActorBinding::new(identity(human), TrustedActorRole::HumanBlocking)
                    .expect("valid human binding"),
                TrustedActorBinding::new(identity(bot), TrustedActorRole::BotAdvisory)
                    .expect("valid bot binding"),
            ],
            vec![RequiredCheck::new("ci/test", vec![identity(check_actor)])
                .expect("valid required check")],
            1,
            max_attempts,
        )
        .expect("valid review-loop policy")
    }

    fn observe(snapshot: PullRequestReviewSnapshot) -> FrozenReviewSnapshot {
        let item = snapshot.item().clone();
        let trusted_not_after = snapshot.observed_at().clone();
        let request = ForgeObservationRequest::pull_request_review_snapshot(item.clone())
            .expect("valid observation request");
        let mut transport = FakeForgeTransport::new();
        transport
            .register_observation(
                request,
                ForgeObservation::PullRequestReviewSnapshot(snapshot),
            )
            .expect("register exact observation");
        FrozenReviewSnapshot::observe(&transport, &item, &trusted_not_after)
            .expect("freeze observed snapshot")
    }

    fn blocking_frozen_at(
        item: ForgeItem,
        observed_at: ForgeTimestamp,
        human: &ForgeActor,
        check_actor: &ForgeActor,
        suffix: &str,
    ) -> FrozenReviewSnapshot {
        let head = item.head_oid().expect("PR head").to_owned();
        let snapshot = PullRequestReviewSnapshot::new(
            item,
            observed_at.clone(),
            vec![review_at(
                &format!("review:{suffix}"),
                human.clone(),
                ForgeReviewState::ChangesRequested,
                &head,
                observed_at.clone(),
            )],
            Vec::new(),
            vec![check_at(
                &format!("check:{suffix}"),
                check_actor.clone(),
                &head,
                observed_at,
            )],
        )
        .expect("valid blocking snapshot");
        observe(snapshot)
    }

    fn ready_frozen_at(
        item: ForgeItem,
        observed_at: ForgeTimestamp,
        human: &ForgeActor,
        check_actor: &ForgeActor,
        suffix: &str,
    ) -> FrozenReviewSnapshot {
        let head = item.head_oid().expect("PR head").to_owned();
        let snapshot = PullRequestReviewSnapshot::new(
            item,
            observed_at.clone(),
            vec![review_at(
                &format!("review:{suffix}"),
                human.clone(),
                ForgeReviewState::Approved,
                &head,
                observed_at.clone(),
            )],
            Vec::new(),
            vec![check_at(
                &format!("check:{suffix}"),
                check_actor.clone(),
                &head,
                observed_at,
            )],
        )
        .expect("valid ready snapshot");
        observe(snapshot)
    }

    #[test]
    fn canonical_digest_is_stable_across_collection_order() {
        let human = actor("actor:human", "alice", ReportedActorKind::Human);
        let bot = actor("actor:bot", "review-bot", ReportedActorKind::Bot);
        let check_actor = actor("actor:checks", "checks-bot", ReportedActorKind::Bot);
        let reviews = vec![
            review("review:2", bot.clone(), ForgeReviewState::Commented),
            review("review:1", human.clone(), ForgeReviewState::Approved),
        ];
        let comments = vec![
            comment("comment:2", bot.clone()),
            comment("comment:1", human.clone()),
        ];
        let threads = vec![
            ForgeReviewThread::new(
                object(ProviderObjectKind::ReviewThread, "thread:2"),
                true,
                comments.clone(),
            )
            .expect("valid thread"),
            ForgeReviewThread::new(
                object(ProviderObjectKind::ReviewThread, "thread:1"),
                true,
                Vec::new(),
            )
            .expect("valid thread"),
        ];
        let checks = vec![
            check("check:2", check_actor.clone()),
            ForgeCheck::new(
                object(ProviderObjectKind::Check, "check:1"),
                check_actor,
                "ci/lint",
                ForgeCheckStatus::Completed,
                Some(ForgeCheckConclusion::Success),
                HEAD,
                timestamp(),
            )
            .expect("valid check"),
        ];
        let first = PullRequestReviewSnapshot::new(
            item(),
            timestamp(),
            reviews.clone(),
            threads.clone(),
            checks.clone(),
        )
        .expect("valid snapshot");

        let mut reversed_reviews = reviews;
        reversed_reviews.reverse();
        let mut reversed_threads = threads;
        reversed_threads.reverse();
        let reversed_first_thread = ForgeReviewThread::new(
            reversed_threads[1].provider_thread_id().clone(),
            reversed_threads[1].is_resolved(),
            comments.into_iter().rev().collect(),
        )
        .expect("valid reordered thread");
        reversed_threads[1] = reversed_first_thread;
        let mut reversed_checks = checks;
        reversed_checks.reverse();
        let second = PullRequestReviewSnapshot::new(
            item(),
            timestamp(),
            reversed_reviews,
            reversed_threads,
            reversed_checks,
        )
        .expect("valid reordered snapshot");

        assert_eq!(
            observe(first).canonical_sha256(),
            observe(second).canonical_sha256()
        );
    }

    #[test]
    fn human_changes_requested_is_a_blocker() {
        let human = actor("actor:human", "alice", ReportedActorKind::Human);
        let bot = actor("actor:bot", "review-bot", ReportedActorKind::Bot);
        let check_actor = actor("actor:checks", "checks-bot", ReportedActorKind::Bot);
        let snapshot = PullRequestReviewSnapshot::new(
            item(),
            timestamp(),
            vec![review(
                "review:1",
                human.clone(),
                ForgeReviewState::ChangesRequested,
            )],
            Vec::new(),
            vec![check("check:1", check_actor.clone())],
        )
        .expect("valid snapshot");

        let triage = policy(&human, &bot, &check_actor).triage(&observe(snapshot));
        assert!(triage
            .blockers()
            .iter()
            .any(|blocker| matches!(blocker, ReadinessBlocker::BlockingHumanFeedback(_))));
        assert_eq!(triage.blocking_human_feedback().len(), 1);
    }

    #[test]
    fn trusted_bot_feedback_is_tracked_as_advisory() {
        let human = actor("actor:human", "alice", ReportedActorKind::Human);
        let bot = actor("actor:bot", "review-bot", ReportedActorKind::Bot);
        let check_actor = actor("actor:checks", "checks-bot", ReportedActorKind::Bot);
        let snapshot = PullRequestReviewSnapshot::new(
            item(),
            timestamp(),
            vec![
                review("review:1", human.clone(), ForgeReviewState::Approved),
                review("review:2", bot.clone(), ForgeReviewState::Commented),
            ],
            Vec::new(),
            vec![check("check:1", check_actor.clone())],
        )
        .expect("valid snapshot");

        let triage = policy(&human, &bot, &check_actor).triage(&observe(snapshot));
        assert_eq!(triage.bot_advisories().len(), 1);
        assert!(triage.is_ready());
    }

    #[test]
    fn actor_kind_mismatch_fails_closed() {
        let human = actor("actor:human", "alice", ReportedActorKind::Human);
        let policy_bot = actor("actor:bot", "review-bot", ReportedActorKind::Bot);
        let mismatched_bot = actor("actor:bot", "review-bot", ReportedActorKind::Human);
        let check_actor = actor("actor:checks", "checks-bot", ReportedActorKind::Bot);
        let snapshot = PullRequestReviewSnapshot::new(
            item(),
            timestamp(),
            vec![
                review("review:1", human.clone(), ForgeReviewState::Approved),
                review("review:2", mismatched_bot, ForgeReviewState::Commented),
            ],
            Vec::new(),
            vec![check("check:1", check_actor.clone())],
        )
        .expect("valid snapshot");

        let triage = policy(&human, &policy_bot, &check_actor).triage(&observe(snapshot));
        assert!(triage
            .blockers()
            .iter()
            .any(|blocker| matches!(blocker, ReadinessBlocker::UntrustedActor(_))));
        assert!(triage.bot_advisories().is_empty());
    }

    #[test]
    fn latest_trusted_human_review_wins_and_equal_time_conflict_is_ambiguous() {
        let human = actor("actor:human", "alice", ReportedActorKind::Human);
        let bot = actor("actor:bot", "review-bot", ReportedActorKind::Bot);
        let check_actor = actor("actor:checks", "checks-bot", ReportedActorKind::Bot);
        let policy = policy(&human, &bot, &check_actor);
        let observed_at = timestamp_at("2026-08-16T06:02:00Z");
        let snapshot_for = |reviews: Vec<ForgeReview>| {
            observe(
                PullRequestReviewSnapshot::new(
                    item(),
                    observed_at.clone(),
                    reviews,
                    Vec::new(),
                    vec![check_at(
                        "check:currency",
                        check_actor.clone(),
                        HEAD,
                        observed_at.clone(),
                    )],
                )
                .expect("valid review-currency snapshot"),
            )
        };

        let later_approval = snapshot_for(vec![
            review_at(
                "review:older-change",
                human.clone(),
                ForgeReviewState::ChangesRequested,
                HEAD,
                timestamp_at("2026-08-16T06:00:00Z"),
            ),
            review_at(
                "review:latest-approval",
                human.clone(),
                ForgeReviewState::Approved,
                HEAD,
                timestamp_at("2026-08-16T06:01:00Z"),
            ),
        ]);
        let approval_triage = later_approval.triage(&policy);
        assert!(approval_triage.is_ready());
        assert_eq!(
            approval_triage.approval_review_ids(),
            &[object(ProviderObjectKind::Review, "review:latest-approval")]
        );

        let later_change = snapshot_for(vec![
            review_at(
                "review:older-approval",
                human.clone(),
                ForgeReviewState::Approved,
                HEAD,
                timestamp_at("2026-08-16T06:00:00Z"),
            ),
            review_at(
                "review:latest-change",
                human.clone(),
                ForgeReviewState::ChangesRequested,
                HEAD,
                timestamp_at("2026-08-16T06:01:00Z"),
            ),
        ]);
        assert!(later_change.triage(&policy).blockers().iter().any(|blocker| {
            matches!(blocker, ReadinessBlocker::BlockingHumanFeedback(identity)
                if identity.provider_review_id().is_some_and(|id| id.stable_id() == "review:latest-change"))
        }));

        let equal_time_conflict = snapshot_for(vec![
            review_at(
                "review:equal-approval",
                human.clone(),
                ForgeReviewState::Approved,
                HEAD,
                timestamp_at("2026-08-16T06:01:00Z"),
            ),
            review_at(
                "review:equal-change",
                human,
                ForgeReviewState::ChangesRequested,
                HEAD,
                timestamp_at("2026-08-16T06:01:00Z"),
            ),
        ]);
        let ambiguous = equal_time_conflict.triage(&policy);
        assert_eq!(ambiguous.approval_count(), 0);
        assert!(ambiguous.blockers().iter().any(|blocker| matches!(
            blocker,
            ReadinessBlocker::AmbiguousHumanReviewCurrency(details)
                if details.provider_review_ids().len() == 2
        )));
    }

    #[test]
    fn publication_and_readiness_reject_non_actionable_feedback_dispositions() {
        let human = actor("actor:human", "alice", ReportedActorKind::Human);
        let publisher = actor("actor:bot", "review-loop", ReportedActorKind::Bot);
        let check_actor = actor("actor:checks", "checks-bot", ReportedActorKind::Bot);
        let policy = policy(&human, &publisher, &check_actor);
        for (state, suffix) in [
            (ForgeReviewState::Approved, "approved"),
            (ForgeReviewState::Dismissed, "dismissed"),
            (ForgeReviewState::Pending, "pending"),
        ] {
            let frozen = observe(
                PullRequestReviewSnapshot::new(
                    item(),
                    timestamp(),
                    vec![review(&format!("review:{suffix}"), human.clone(), state)],
                    Vec::new(),
                    vec![check("check:actionable", check_actor.clone())],
                )
                .expect("valid non-actionable review snapshot"),
            );
            let disposition = VerifiedDisposition::new(
                &frozen,
                ReviewFeedbackIdentity::review(object(
                    ProviderObjectKind::Review,
                    &format!("review:{suffix}"),
                )),
                identity(&human),
                DispositionDecision::Addressed,
                "This review state is not actionable feedback.",
            )
            .expect("source-bound but non-actionable disposition");
            assert!(evaluate_review_loop_readiness(
                &frozen,
                &policy,
                std::slice::from_ref(&disposition),
            )
            .is_err());
            assert!(build_pull_request_disposition_publication(
                &frozen,
                &policy,
                publisher.clone(),
                &[disposition],
            )
            .is_err());
        }

        let resolved_comment = comment("comment:resolved", human.clone());
        let resolved = observe(
            PullRequestReviewSnapshot::new(
                item(),
                timestamp(),
                vec![review(
                    "review:resolved-approval",
                    human.clone(),
                    ForgeReviewState::Approved,
                )],
                vec![ForgeReviewThread::new(
                    object(ProviderObjectKind::ReviewThread, "thread:resolved"),
                    true,
                    vec![resolved_comment],
                )
                .expect("valid resolved thread")],
                vec![check("check:resolved", check_actor)],
            )
            .expect("valid resolved-thread snapshot"),
        );
        let resolved_disposition = VerifiedDisposition::new(
            &resolved,
            ReviewFeedbackIdentity::thread_comment(
                object(ProviderObjectKind::ReviewThread, "thread:resolved"),
                object(ProviderObjectKind::Comment, "comment:resolved"),
            ),
            identity(&human),
            DispositionDecision::Addressed,
            "Resolved human comments are not actionable.",
        )
        .expect("source-bound resolved disposition");
        assert!(evaluate_review_loop_readiness(
            &resolved,
            &policy,
            std::slice::from_ref(&resolved_disposition),
        )
        .is_err());
        assert!(build_pull_request_disposition_publication(
            &resolved,
            &policy,
            publisher,
            &[resolved_disposition],
        )
        .is_err());
    }

    #[test]
    fn any_thread_emits_unsupported_currency_metadata_blocker() {
        let human = actor("actor:human", "alice", ReportedActorKind::Human);
        let bot = actor("actor:bot", "review-bot", ReportedActorKind::Bot);
        let check_actor = actor("actor:checks", "checks-bot", ReportedActorKind::Bot);
        let thread = ForgeReviewThread::new(
            object(ProviderObjectKind::ReviewThread, "thread:1"),
            true,
            Vec::new(),
        )
        .expect("valid thread");
        let snapshot = PullRequestReviewSnapshot::new(
            item(),
            timestamp(),
            vec![review(
                "review:1",
                human.clone(),
                ForgeReviewState::Approved,
            )],
            vec![thread],
            vec![check("check:1", check_actor.clone())],
        )
        .expect("valid snapshot");

        let triage = policy(&human, &bot, &check_actor).triage(&observe(snapshot));
        assert!(triage
            .blockers()
            .iter()
            .any(|blocker| matches!(blocker, ReadinessBlocker::UnsupportedThreadCurrencyMetadata)));
    }

    #[test]
    fn unresolved_trusted_human_thread_is_blocking_and_requires_exact_addressed_coverage() {
        let human = actor("actor:human", "alice", ReportedActorKind::Human);
        let bot = actor("actor:bot", "review-bot", ReportedActorKind::Bot);
        let check_actor = actor("actor:checks", "checks-bot", ReportedActorKind::Bot);
        let thread_id = object(ProviderObjectKind::ReviewThread, "thread:unresolved-human");
        let comment_id = object(ProviderObjectKind::Comment, "comment:unresolved-human");
        let feedback_identity =
            ReviewFeedbackIdentity::thread_comment(thread_id.clone(), comment_id.clone());
        let frozen = observe(
            PullRequestReviewSnapshot::new(
                item(),
                timestamp(),
                vec![review(
                    "review:thread-approval",
                    human.clone(),
                    ForgeReviewState::Approved,
                )],
                vec![ForgeReviewThread::new(
                    thread_id,
                    false,
                    vec![comment("comment:unresolved-human", human.clone())],
                )
                .expect("valid unresolved human thread")],
                vec![check("check:unresolved-human", check_actor.clone())],
            )
            .expect("valid unresolved-human snapshot"),
        );
        let policy = policy(&human, &bot, &check_actor);
        let triage = frozen.triage(&policy);
        assert!(triage
            .blockers()
            .iter()
            .any(|blocker| matches!(blocker, ReadinessBlocker::UnsupportedThreadCurrencyMetadata)));
        assert!(triage.blockers().iter().any(|blocker| matches!(
            blocker,
            ReadinessBlocker::BlockingHumanFeedback(identity) if identity == &feedback_identity
        )));
        assert_eq!(triage.blocking_human_feedback().len(), 1);
        assert_eq!(
            triage.blocking_human_feedback()[0].identity(),
            &feedback_identity
        );

        let state = ReviewLoopState::new(policy, frozen.clone(), &timestamp())
            .expect("active unresolved-thread state");
        let refreshed = ready_frozen_at(
            item(),
            timestamp_at("2026-08-16T01:03:00Z"),
            &human,
            &check_actor,
            "thread-resolved-refresh",
        );
        let refreshed_item = refreshed.item().clone();
        let deferred = VerifiedDisposition::new(
            &frozen,
            feedback_identity.clone(),
            identity(&human),
            DispositionDecision::Deferred,
            "Deferred is not trusted human coverage.",
        )
        .expect("source-bound deferred disposition");
        assert!(state
            .refresh_with_snapshot(
                &refreshed_item,
                refreshed.clone(),
                &timestamp_at("2026-08-16T01:03:00Z"),
                vec![deferred],
            )
            .is_err());
        let addressed = VerifiedDisposition::new(
            &frozen,
            feedback_identity,
            identity(&human),
            DispositionDecision::Addressed,
            "Addressed the exact unresolved thread comment.",
        )
        .expect("source-bound addressed disposition");
        let ready = state
            .refresh_with_snapshot(
                &refreshed_item,
                refreshed,
                &timestamp_at("2026-08-16T01:03:00Z"),
                vec![addressed],
            )
            .expect("exact addressed coverage permits refresh");
        assert_eq!(ready.phase(), ReviewLoopPhase::Ready);
    }

    #[test]
    fn durable_deserialization_rejects_unknown_fields_and_tampered_snapshot_digest() {
        let human = actor("actor:human", "alice", ReportedActorKind::Human);
        let bot = actor("actor:bot", "review-bot", ReportedActorKind::Bot);
        let check_actor = actor("actor:checks", "checks-bot", ReportedActorKind::Bot);
        let policy = policy(&human, &bot, &check_actor);
        let mut policy_json = serde_json::to_value(&policy).expect("serialize policy");
        policy_json
            .as_object_mut()
            .expect("policy object")
            .insert("unexpected".to_owned(), serde_json::json!(true));
        assert!(serde_json::from_value::<ReviewLoopPolicy>(policy_json).is_err());

        let frozen = ready_frozen_at(item(), timestamp(), &human, &check_actor, "ready");
        let mut tampered = serde_json::to_value(&frozen).expect("serialize frozen snapshot");
        tampered["canonical_sha256"] = serde_json::json!("0".repeat(64));
        assert!(FrozenReviewSnapshot::restore_json(
            &serde_json::to_vec(&tampered).expect("serialize tampered snapshot"),
            &timestamp(),
        )
        .is_err());

        let mut unknown = serde_json::to_value(&frozen).expect("serialize frozen snapshot");
        unknown
            .as_object_mut()
            .expect("frozen object")
            .insert("unexpected".to_owned(), serde_json::json!(true));
        assert!(FrozenReviewSnapshot::restore_json(
            &serde_json::to_vec(&unknown).expect("serialize unknown-field snapshot"),
            &timestamp(),
        )
        .is_err());

        let mut malformed_identity =
            serde_json::to_value(identity(&human)).expect("serialize trusted identity");
        malformed_identity["provider_actor_id"]["kind"] = serde_json::json!("comment");
        assert!(serde_json::from_value::<TrustedActorIdentity>(malformed_identity).is_err());
        let valid_binding =
            TrustedActorBinding::new(identity(&human), TrustedActorRole::HumanBlocking)
                .expect("valid direct binding");
        let mut malformed_binding =
            serde_json::to_value(valid_binding).expect("serialize trusted binding");
        malformed_binding["role"] = serde_json::json!("bot_advisory");
        assert!(serde_json::from_value::<TrustedActorBinding>(malformed_binding).is_err());
        let valid_required = RequiredCheck::new("ci/direct", vec![identity(&check_actor)])
            .expect("valid direct required check");
        let mut malformed_required =
            serde_json::to_value(valid_required).expect("serialize required check");
        let duplicate_actor = malformed_required["trusted_actors"][0].clone();
        malformed_required["trusted_actors"]
            .as_array_mut()
            .expect("trusted actor array")
            .push(duplicate_actor);
        assert!(serde_json::from_value::<RequiredCheck>(malformed_required).is_err());

        let future = ready_frozen_at(
            item(),
            timestamp_at("2099-08-16T01:02:03Z"),
            &human,
            &check_actor,
            "future",
        );
        let future_encoded = serde_json::to_vec(&future).expect("serialize future snapshot");
        assert!(FrozenReviewSnapshot::restore_json(&future_encoded, &timestamp()).is_err());
        assert!(ReviewLoopState::new(policy, future, &timestamp()).is_err());
        assert!(FrozenReviewSnapshot::restore_json(
            &vec![b' '; MAX_FROZEN_SNAPSHOT_RECORD_BYTES + 1],
            &timestamp(),
        )
        .is_err());
    }

    #[test]
    fn disposition_rejects_invalid_identity_head_and_record_digest() {
        let human = actor("actor:human", "alice", ReportedActorKind::Human);
        let check_actor = actor("actor:checks", "checks-bot", ReportedActorKind::Bot);
        let frozen = blocking_frozen_at(item(), timestamp(), &human, &check_actor, "old");
        let disposition = VerifiedDisposition::new(
            &frozen,
            ReviewFeedbackIdentity::review(object(ProviderObjectKind::Review, "review:old")),
            identity(&human),
            DispositionDecision::Addressed,
            "Applied the requested correction.",
        )
        .expect("valid disposition");

        let mut invalid_identity = disposition.clone();
        invalid_identity.feedback_identity =
            ReviewFeedbackIdentity::review(object(ProviderObjectKind::Review, "review:absent"));
        assert!(invalid_identity.validate_against(&frozen).is_err());

        let mut invalid_head = disposition.clone();
        invalid_head.head_oid = HEAD_2.to_owned();
        assert!(invalid_head.validate_against(&frozen).is_err());

        let mut invalid_digest = disposition;
        invalid_digest.record_sha256 = "0".repeat(64);
        assert!(invalid_digest.validate_against(&frozen).is_err());
    }

    #[test]
    fn disposition_restore_is_contextual_and_duplicate_identities_fail_closed() {
        let human = actor("actor:human", "alice", ReportedActorKind::Human);
        let publisher = actor("actor:publisher", "review-loop", ReportedActorKind::Bot);
        let check_actor = actor("actor:checks", "checks-bot", ReportedActorKind::Bot);
        let frozen = blocking_frozen_at(item(), timestamp(), &human, &check_actor, "durable");
        let feedback_identity =
            ReviewFeedbackIdentity::review(object(ProviderObjectKind::Review, "review:durable"));
        let first = VerifiedDisposition::new(
            &frozen,
            feedback_identity.clone(),
            identity(&human),
            DispositionDecision::Addressed,
            "Applied the requested correction.",
        )
        .expect("valid first disposition");
        let second = VerifiedDisposition::new(
            &frozen,
            feedback_identity,
            identity(&human),
            DispositionDecision::Deferred,
            "Conflicting record for the same feedback identity.",
        )
        .expect("individually valid colliding disposition");

        let encoded = serde_json::to_vec(&first).expect("serialize disposition");
        assert_eq!(
            VerifiedDisposition::restore_json(&frozen, &encoded)
                .expect("restore against exact frozen source"),
            first
        );
        let other = blocking_frozen_at(
            item(),
            timestamp_at("2026-08-16T01:02:04Z"),
            &human,
            &check_actor,
            "other",
        );
        assert!(VerifiedDisposition::restore_json(&other, &encoded).is_err());

        let mut tampered = serde_json::to_value(&first).expect("serialize disposition value");
        tampered["record_sha256"] = serde_json::json!("0".repeat(64));
        assert!(VerifiedDisposition::restore_json(
            &frozen,
            &serde_json::to_vec(&tampered).expect("serialize tampered disposition"),
        )
        .is_err());
        let policy = policy(&human, &publisher, &check_actor);
        assert!(
            evaluate_review_loop_readiness(&frozen, &policy, &[first.clone(), second.clone()])
                .is_err()
        );
        assert!(build_pull_request_disposition_publication(
            &frozen,
            &policy,
            publisher,
            &[first, second],
        )
        .is_err());
    }

    #[test]
    fn state_requires_complete_addressed_coverage_and_rejects_duplicate_dispositions() {
        let human = actor("actor:human", "alice", ReportedActorKind::Human);
        let bot = actor("actor:bot", "review-bot", ReportedActorKind::Bot);
        let check_actor = actor("actor:checks", "checks-bot", ReportedActorKind::Bot);
        let first = blocking_frozen_at(
            item(),
            timestamp_at("2026-08-16T01:00:00Z"),
            &human,
            &check_actor,
            "one",
        );
        let disposition = VerifiedDisposition::new(
            &first,
            ReviewFeedbackIdentity::review(object(ProviderObjectKind::Review, "review:one")),
            identity(&human),
            DispositionDecision::Addressed,
            "Implemented the requested change.",
        )
        .expect("valid disposition");
        let state = ReviewLoopState::new(
            policy(&human, &bot, &check_actor),
            first,
            &timestamp_at("2026-08-16T01:00:00Z"),
        )
        .expect("active review loop");
        let second = blocking_frozen_at(
            item(),
            timestamp_at("2026-08-16T01:01:00Z"),
            &human,
            &check_actor,
            "two",
        );
        let second_item = second.item().clone();
        let cutoff = timestamp_at("2026-08-16T01:01:01Z");

        assert!(state
            .refresh_with_snapshot(&second_item, second.clone(), &cutoff, Vec::new())
            .is_err());
        let not_addressed = VerifiedDisposition::new(
            state.current_snapshot(),
            ReviewFeedbackIdentity::review(object(ProviderObjectKind::Review, "review:one")),
            identity(&human),
            DispositionDecision::Deferred,
            "This cannot waive trusted human-blocking feedback.",
        )
        .expect("valid but non-addressing disposition");
        assert!(state
            .refresh_with_snapshot(&second_item, second.clone(), &cutoff, vec![not_addressed],)
            .is_err());
        assert!(state
            .refresh_with_snapshot(
                &second_item,
                second.clone(),
                &cutoff,
                vec![disposition.clone(), disposition.clone()],
            )
            .is_err());

        let next = state
            .refresh_with_snapshot(&second_item, second, &cutoff, vec![disposition])
            .expect("first sequential refresh");
        assert_eq!(next.attempts()[0].sequence(), 1);
        assert_eq!(next.predecessor_state_sha256(), Some(state.state_sha256()));
        let third = blocking_frozen_at(
            item(),
            timestamp_at("2026-08-16T01:02:00Z"),
            &human,
            &check_actor,
            "three",
        );
        let third_item = third.item().clone();
        assert!(next
            .refresh_with_snapshot(
                &third_item,
                third,
                &timestamp_at("2026-08-16T01:02:01Z"),
                Vec::new(),
            )
            .is_err());
    }

    #[test]
    fn bounded_attempts_end_in_terminal_exhausted_state() {
        let human = actor("actor:human", "alice", ReportedActorKind::Human);
        let bot = actor("actor:bot", "review-bot", ReportedActorKind::Bot);
        let check_actor = actor("actor:checks", "checks-bot", ReportedActorKind::Bot);
        let first = blocking_frozen_at(
            item(),
            timestamp_at("2026-08-16T02:00:00Z"),
            &human,
            &check_actor,
            "exhaust-one",
        );
        let disposition = VerifiedDisposition::new(
            &first,
            ReviewFeedbackIdentity::review(object(
                ProviderObjectKind::Review,
                "review:exhaust-one",
            )),
            identity(&human),
            DispositionDecision::Addressed,
            "Applied the final bounded attempt.",
        )
        .expect("valid final disposition");
        let state = ReviewLoopState::new(
            policy_with_max(&human, &bot, &check_actor, 1),
            first,
            &timestamp_at("2026-08-16T02:00:00Z"),
        )
        .expect("active review loop");
        let second = blocking_frozen_at(
            item(),
            timestamp_at("2026-08-16T02:01:00Z"),
            &human,
            &check_actor,
            "exhaust-two",
        );
        let second_item = second.item().clone();
        let exhausted = state
            .refresh_with_snapshot(
                &second_item,
                second.clone(),
                &timestamp_at("2026-08-16T02:01:01Z"),
                vec![disposition],
            )
            .expect("bounded refresh");
        assert_eq!(exhausted.phase(), ReviewLoopPhase::Exhausted);
        assert!(matches!(
            exhausted.readiness().expect("typed exhausted readiness"),
            ReviewLoopReadinessEvaluation::Blocked(blocked)
                if blocked.blockers().iter().any(|blocker| matches!(
                    blocker,
                    ReadinessBlocker::AttemptLimitExhausted { max_attempts: 1 }
                ))
        ));
        assert!(exhausted
            .refresh_with_snapshot(
                &second_item,
                second,
                &timestamp_at("2026-08-16T02:01:01Z"),
                Vec::new(),
            )
            .is_err());
    }

    #[test]
    fn refresh_binds_current_head_base_and_strictly_later_observation() {
        let human = actor("actor:human", "alice", ReportedActorKind::Human);
        let bot = actor("actor:bot", "review-bot", ReportedActorKind::Bot);
        let check_actor = actor("actor:checks", "checks-bot", ReportedActorKind::Bot);
        let first = blocking_frozen_at(
            item(),
            timestamp_at("2026-08-16T03:00:00Z"),
            &human,
            &check_actor,
            "head-one",
        );
        let disposition = VerifiedDisposition::new(
            &first,
            ReviewFeedbackIdentity::review(object(ProviderObjectKind::Review, "review:head-one")),
            identity(&human),
            DispositionDecision::Addressed,
            "Updated the implementation for the new head.",
        )
        .expect("valid disposition");
        let state = ReviewLoopState::new(
            policy(&human, &bot, &check_actor),
            first,
            &timestamp_at("2026-08-16T03:00:00Z"),
        )
        .expect("active review loop");
        let current_item = item_at(HEAD_2, BASE_2, "revision:2");
        let current = ready_frozen_at(
            current_item.clone(),
            timestamp_at("2026-08-16T03:01:00Z"),
            &human,
            &check_actor,
            "head-two",
        );
        let next = state
            .refresh_with_snapshot(
                &current_item,
                current.clone(),
                &timestamp_at("2026-08-16T03:01:01Z"),
                vec![disposition],
            )
            .expect("exact current refresh");
        assert_eq!(next.phase(), ReviewLoopPhase::Ready);
        assert_eq!(next.current_snapshot().item().head_oid(), Some(HEAD_2));
        assert_eq!(next.current_snapshot().item().base_oid(), Some(BASE_2));
        let expected_attempt_id = derive_attempt_id(
            next.policy_sha256(),
            state.current_snapshot(),
            next.current_snapshot(),
            1,
            next.attempts()[0].disposition_sha256s(),
        )
        .expect("deterministic attempt identity");
        assert_eq!(next.attempts()[0].attempt_id(), expected_attempt_id);
        let proof = match next.readiness().expect("ready state evaluation") {
            ReviewLoopReadinessEvaluation::Ready(proof) => proof,
            ReviewLoopReadinessEvaluation::Blocked(_) => panic!("refreshed evidence is ready"),
        };
        proof
            .validate_against_state(&next)
            .expect("proof validates through retained history");
        assert!(proof
            .validate_against(next.current_snapshot(), next.policy(), next.dispositions(),)
            .is_err());

        assert!(state
            .refresh_with_snapshot(
                state.current_snapshot().item(),
                current.clone(),
                &timestamp_at("2026-08-16T03:01:01Z"),
                Vec::new(),
            )
            .is_err());
        let not_later = ready_frozen_at(
            current_item.clone(),
            timestamp_at("2026-08-16T03:00:00Z"),
            &human,
            &check_actor,
            "same-time",
        );
        assert!(state
            .refresh_with_snapshot(
                &current_item,
                not_later,
                &timestamp_at("2026-08-16T03:01:01Z"),
                Vec::new(),
            )
            .is_err());
    }

    #[test]
    fn state_round_trip_revalidates_history_and_transport_refresh_rejects_future_observation() {
        let human = actor("actor:human", "alice", ReportedActorKind::Human);
        let bot = actor("actor:bot", "review-bot", ReportedActorKind::Bot);
        let check_actor = actor("actor:checks", "checks-bot", ReportedActorKind::Bot);
        let first = blocking_frozen_at(
            item(),
            timestamp_at("2026-08-16T05:00:00Z"),
            &human,
            &check_actor,
            "transport-one",
        );
        let disposition = VerifiedDisposition::new(
            &first,
            ReviewFeedbackIdentity::review(object(
                ProviderObjectKind::Review,
                "review:transport-one",
            )),
            identity(&human),
            DispositionDecision::Addressed,
            "Addressed before transport-backed refresh.",
        )
        .expect("valid transport disposition");
        let state = ReviewLoopState::new(
            policy(&human, &bot, &check_actor),
            first,
            &timestamp_at("2026-08-16T05:00:00Z"),
        )
        .expect("active transport state");
        let current_item = item_at(HEAD_2, BASE_2, "revision:transport-two");
        let refreshed = ready_frozen_at(
            current_item.clone(),
            timestamp_at("2026-08-16T05:01:00Z"),
            &human,
            &check_actor,
            "transport-two",
        );
        let request = ForgeObservationRequest::pull_request_review_snapshot(current_item.clone())
            .expect("transport observation request");
        let mut transport = FakeForgeTransport::new();
        transport
            .register_observation(
                request,
                ForgeObservation::PullRequestReviewSnapshot(refreshed.snapshot().clone()),
            )
            .expect("register transport refresh");

        assert!(state
            .refresh(
                &transport,
                &current_item,
                &timestamp_at("2026-08-16T05:00:59Z"),
                vec![disposition.clone()],
            )
            .is_err());
        let ready = state
            .refresh(
                &transport,
                &current_item,
                &timestamp_at("2026-08-16T05:01:00Z"),
                vec![disposition],
            )
            .expect("transport-backed refresh at trusted cutoff");

        let encoded_bytes = serde_json::to_vec(&ready).expect("serialize durable state");
        let restored =
            ReviewLoopState::restore_json(&encoded_bytes, &timestamp_at("2026-08-16T05:01:00Z"))
                .expect("restore validated state history");
        assert_eq!(restored, ready);
        assert!(ReviewLoopState::restore_json(
            &encoded_bytes,
            &timestamp_at("2026-08-16T05:00:59Z"),
        )
        .is_err());

        let encoded = serde_json::to_value(&ready).expect("serialize state value");
        let mut tampered_attempt = encoded.clone();
        tampered_attempt["attempts"][0]["attempt_id"] =
            serde_json::json!(format!("attempt:{}", "0".repeat(64)));
        assert!(ReviewLoopState::restore_json(
            &serde_json::to_vec(&tampered_attempt).expect("serialize tampered attempt"),
            &timestamp_at("2026-08-16T05:01:00Z"),
        )
        .is_err());
        let mut tampered_chain = encoded.clone();
        tampered_chain["attempts"][0]["refreshed_snapshot_sha256"] =
            serde_json::json!("0".repeat(64));
        assert!(ReviewLoopState::restore_json(
            &serde_json::to_vec(&tampered_chain).expect("serialize tampered chain"),
            &timestamp_at("2026-08-16T05:01:00Z"),
        )
        .is_err());

        let mut tampered_predecessor = ready.clone();
        tampered_predecessor.predecessor_state_sha256 = Some("0".repeat(64));
        tampered_predecessor.state_sha256 = tampered_predecessor
            .compute_state_sha256()
            .expect("recompute self-consistent final digest");
        assert!(ReviewLoopState::restore_json(
            &serde_json::to_vec(&tampered_predecessor)
                .expect("serialize predecessor-tampered state"),
            &timestamp_at("2026-08-16T05:01:00Z"),
        )
        .is_err());
        assert!(ReviewLoopState::restore_json(
            &vec![b' '; MAX_REVIEW_LOOP_STATE_RECORD_BYTES + 1],
            &timestamp_at("2026-08-16T05:01:00Z"),
        )
        .is_err());
    }

    #[test]
    fn durable_restore_rejects_successors_after_ready_prefixes() {
        let human = actor("actor:human", "alice", ReportedActorKind::Human);
        let bot = actor("actor:bot", "review-bot", ReportedActorKind::Bot);
        let check_actor = actor("actor:checks", "checks-bot", ReportedActorKind::Bot);
        let policy = policy(&human, &bot, &check_actor);

        let initially_ready = ready_frozen_at(
            item(),
            timestamp_at("2026-08-16T07:10:00Z"),
            &human,
            &check_actor,
            "initially-ready",
        );
        let initial_state = ReviewLoopState::new(
            policy.clone(),
            initially_ready.clone(),
            &timestamp_at("2026-08-16T07:10:00Z"),
        )
        .expect("valid initially ready state");
        assert_eq!(initial_state.phase(), ReviewLoopPhase::Ready);
        let successor = ready_frozen_at(
            item(),
            timestamp_at("2026-08-16T07:11:00Z"),
            &human,
            &check_actor,
            "illegal-ready-successor",
        );
        let attempt_id = derive_attempt_id(
            initial_state.policy_sha256(),
            &initially_ready,
            &successor,
            1,
            &[],
        )
        .expect("deterministic illegal attempt id");
        let attempt = ReviewLoopAttempt {
            sequence: 1,
            attempt_id,
            prior_snapshot: initially_ready,
            refreshed_snapshot_sha256: successor.canonical_sha256().to_owned(),
            disposition_sha256s: Vec::new(),
        };
        let mut crafted = ReviewLoopState {
            policy: policy.clone(),
            policy_sha256: initial_state.policy_sha256().to_owned(),
            current_snapshot: successor,
            attempts: vec![attempt],
            dispositions: Vec::new(),
            phase: ReviewLoopPhase::Ready,
            predecessor_state_sha256: Some(initial_state.state_sha256().to_owned()),
            state_sha256: String::new(),
        };
        crafted.state_sha256 = crafted
            .compute_state_sha256()
            .expect("recompute crafted final digest");
        assert!(ReviewLoopState::restore_json(
            &serde_json::to_vec(&crafted).expect("serialize crafted ready successor"),
            &timestamp_at("2026-08-16T07:11:00Z"),
        )
        .is_err());

        let blocking = blocking_frozen_at(
            item(),
            timestamp_at("2026-08-16T07:00:00Z"),
            &human,
            &check_actor,
            "active-before-ready",
        );
        let disposition = VerifiedDisposition::new(
            &blocking,
            ReviewFeedbackIdentity::review(object(
                ProviderObjectKind::Review,
                "review:active-before-ready",
            )),
            identity(&human),
            DispositionDecision::Addressed,
            "Addressed before the valid ready transition.",
        )
        .expect("valid prefix disposition");
        let active = ReviewLoopState::new(policy, blocking, &timestamp_at("2026-08-16T07:00:00Z"))
            .expect("valid active prefix");
        let middle = ready_frozen_at(
            item(),
            timestamp_at("2026-08-16T07:01:00Z"),
            &human,
            &check_actor,
            "middle-ready",
        );
        let middle_item = middle.item().clone();
        let middle_state = active
            .refresh_with_snapshot(
                &middle_item,
                middle,
                &timestamp_at("2026-08-16T07:01:00Z"),
                vec![disposition],
            )
            .expect("valid transition into ready prefix");
        let final_snapshot = ready_frozen_at(
            item(),
            timestamp_at("2026-08-16T07:02:00Z"),
            &human,
            &check_actor,
            "illegal-middle-successor",
        );
        let second_attempt_id = derive_attempt_id(
            middle_state.policy_sha256(),
            middle_state.current_snapshot(),
            &final_snapshot,
            2,
            &[],
        )
        .expect("deterministic second illegal attempt id");
        let second_attempt = ReviewLoopAttempt {
            sequence: 2,
            attempt_id: second_attempt_id,
            prior_snapshot: middle_state.current_snapshot().clone(),
            refreshed_snapshot_sha256: final_snapshot.canonical_sha256().to_owned(),
            disposition_sha256s: Vec::new(),
        };
        let mut attempts = middle_state.attempts().to_vec();
        attempts.push(second_attempt);
        let mut crafted_after_middle = ReviewLoopState {
            policy: middle_state.policy().clone(),
            policy_sha256: middle_state.policy_sha256().to_owned(),
            current_snapshot: final_snapshot,
            attempts,
            dispositions: middle_state.dispositions().to_vec(),
            phase: ReviewLoopPhase::Ready,
            predecessor_state_sha256: Some(middle_state.state_sha256().to_owned()),
            state_sha256: String::new(),
        };
        crafted_after_middle.state_sha256 = crafted_after_middle
            .compute_state_sha256()
            .expect("recompute crafted intermediate-successor digest");
        assert!(ReviewLoopState::restore_json(
            &serde_json::to_vec(&crafted_after_middle)
                .expect("serialize crafted intermediate successor"),
            &timestamp_at("2026-08-16T07:02:00Z"),
        )
        .is_err());
    }

    #[test]
    fn stale_review_and_check_cannot_form_a_snapshot() {
        let human = actor("actor:human", "alice", ReportedActorKind::Human);
        let check_actor = actor("actor:checks", "checks-bot", ReportedActorKind::Bot);
        let stale_review = review_at(
            "review:stale",
            human.clone(),
            ForgeReviewState::Approved,
            BASE,
            timestamp(),
        );
        assert!(PullRequestReviewSnapshot::new(
            item(),
            timestamp(),
            vec![stale_review],
            Vec::new(),
            vec![check("check:fresh", check_actor.clone())],
        )
        .is_err());

        let stale_check = check_at("check:stale", check_actor, BASE, timestamp());
        assert!(PullRequestReviewSnapshot::new(
            item(),
            timestamp(),
            vec![review("review:fresh", human, ForgeReviewState::Approved)],
            Vec::new(),
            vec![stale_check],
        )
        .is_err());
    }

    #[test]
    fn thread_free_readiness_proof_binds_evidence_and_invalidates_on_refresh() {
        let human = actor("actor:human", "alice", ReportedActorKind::Human);
        let bot = actor("actor:bot", "review-bot", ReportedActorKind::Bot);
        let check_actor = actor("actor:checks", "checks-bot", ReportedActorKind::Bot);
        let policy = policy(&human, &bot, &check_actor);
        let frozen = ready_frozen_at(
            item(),
            timestamp_at("2026-08-16T04:00:00Z"),
            &human,
            &check_actor,
            "proof-one",
        );
        let proof = match evaluate_review_loop_readiness(&frozen, &policy, &[])
            .expect("readiness evaluation")
        {
            ReviewLoopReadinessEvaluation::Ready(proof) => proof,
            ReviewLoopReadinessEvaluation::Blocked(_) => panic!("thread-free evidence is ready"),
        };
        assert_eq!(proof.evidence().successful_check_ids().len(), 1);
        assert_eq!(proof.evidence().approval_review_ids().len(), 1);
        assert_eq!(
            proof.evidence().observed_at().as_str(),
            "2026-08-16T04:00:00Z"
        );
        assert!(!proof.grants_merge_permission());

        let refreshed = ready_frozen_at(
            item(),
            timestamp_at("2026-08-16T04:01:00Z"),
            &human,
            &check_actor,
            "proof-two",
        );
        assert!(proof.validate_against(&refreshed, &policy, &[]).is_err());
    }

    #[test]
    fn typed_disposition_effect_is_idempotent_and_rejects_effect_id_collision() {
        let human = actor("actor:human", "alice", ReportedActorKind::Human);
        let publisher = actor("actor:bot", "review-bot", ReportedActorKind::Bot);
        let check_actor = actor("actor:checks", "checks-bot", ReportedActorKind::Bot);
        let frozen = blocking_frozen_at(item(), timestamp(), &human, &check_actor, "publish");
        let disposition = VerifiedDisposition::new(
            &frozen,
            ReviewFeedbackIdentity::review(object(ProviderObjectKind::Review, "review:publish")),
            identity(&human),
            DispositionDecision::Addressed,
            "Applied and validated the requested change.",
        )
        .expect("valid disposition");
        let policy = policy(&human, &publisher, &check_actor);
        let request = build_pull_request_disposition_publication(
            &frozen,
            &policy,
            publisher.clone(),
            &[disposition],
        )
        .expect("typed PR comment effect");
        assert!(matches!(request, ForgeEffectRequest::AppendComment(_)));

        let transport = FakeForgeTransport::new();
        let first = transport.execute(&request).expect("first publication");
        let replay = transport.execute(&request).expect("idempotent replay");
        assert_eq!(first, replay);

        let colliding_effect = AppendCommentEffect::new(
            request.as_append_comment().effect_id(),
            frozen.item().clone(),
            publisher,
            "different publication body",
        )
        .expect("well-formed colliding effect");
        let colliding_request =
            ForgeEffectRequest::append_comment(colliding_effect).expect("typed collision request");
        assert!(transport.execute(&colliding_request).is_err());
    }

    #[test]
    fn open_review_loop_observes_through_the_transport_and_does_not_grant_merge() {
        let human = actor("actor:human", "alice", ReportedActorKind::Human);
        let bot = actor("actor:bot", "review-bot", ReportedActorKind::Bot);
        let check_actor = actor("actor:checks", "checks-bot", ReportedActorKind::Bot);
        let policy = policy(&human, &bot, &check_actor);
        let current = item();
        let snapshot = PullRequestReviewSnapshot::new(
            current.clone(),
            timestamp(),
            vec![review(
                "review:open",
                human.clone(),
                ForgeReviewState::Approved,
            )],
            Vec::new(),
            vec![check("check:open", check_actor.clone())],
        )
        .expect("valid ready snapshot");
        let request = ForgeObservationRequest::pull_request_review_snapshot(current.clone())
            .expect("valid observation request");
        let mut transport = FakeForgeTransport::new();
        transport
            .register_observation(
                request,
                ForgeObservation::PullRequestReviewSnapshot(snapshot),
            )
            .expect("register exact observation");

        let state = open_review_loop(&transport, &current, policy, &timestamp())
            .expect("open review loop from transport");
        assert_eq!(state.phase(), ReviewLoopPhase::Ready);
        match state.readiness().expect("readiness") {
            ReviewLoopReadinessEvaluation::Ready(proof) => {
                assert!(!proof.grants_merge_permission());
            }
            ReviewLoopReadinessEvaluation::Blocked(blocked) => {
                panic!("expected ready observation, got blockers {blocked:?}");
            }
        }
    }
}
