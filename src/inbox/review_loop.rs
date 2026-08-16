//! Provider-neutral review-loop observation, trust policy, and readiness triage.
//!
//! It freezes exact forge observations, records verified feedback
//! dispositions, advances a digest-chained bounded state machine, emits
//! conservative readiness evidence, and constructs one typed PR-comment
//! publication effect. A readiness proof is deliberately not merge authority.

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
use std::{cmp::Ordering, collections::BTreeSet};

const MAX_REVIEW_LOOP_ATTEMPTS: usize = 8;
const MAX_CHECK_NAME_BYTES: usize = 256;
const MAX_ATTEMPT_ID_BYTES: usize = 128;
const MAX_DISPOSITION_SUMMARY_BYTES: usize = 8 * 1024;
const REVIEW_SNAPSHOT_DIGEST_DOMAIN: &[u8] = b"MACO\0review-loop-snapshot\0v1\0";
const POLICY_DIGEST_DOMAIN: &[u8] = b"MACO\0review-loop-policy\0v1\0";
const DISPOSITION_DIGEST_DOMAIN: &[u8] = b"MACO\0review-disposition\0v1\0";
const READINESS_DIGEST_DOMAIN: &[u8] = b"MACO\0review-readiness\0v1\0";
const REVIEW_LOOP_STATE_DIGEST_DOMAIN: &[u8] = b"MACO\0review-loop-state\0v1\0";
const PUBLICATION_EFFECT_DIGEST_DOMAIN: &[u8] = b"MACO\0review-disposition-publication\0v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustedActorRole {
    HumanBlocking,
    BotAdvisory,
}

/// An exact provider identity. A reported actor kind is trusted only when all
/// three fields match a policy entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedActorIdentity {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedActorBinding {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredCheck {
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
    pub fn observe<T>(transport: &T, item: &ForgeItem) -> Result<Self>
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
        Self::freeze(item, snapshot)
    }

    pub fn freeze(item: &ForgeItem, snapshot: PullRequestReviewSnapshot) -> Result<Self> {
        if item.kind() != ForgeItemKind::PullRequest
            || snapshot.item() != item
            || snapshot.item().provider_item_id() != item.provider_item_id()
            || snapshot.item().head_oid() != item.head_oid()
            || snapshot.item().base_oid() != item.base_oid()
        {
            bail!("review snapshot does not bind the exact requested PR item, head, and base");
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

    pub fn triage(&self, policy: &ReviewLoopPolicy) -> ReviewTriage {
        let mut blockers = Vec::new();
        let mut blocking_human_feedback = Vec::new();
        let mut bot_advisories = Vec::new();
        let mut approving_humans = BTreeSet::new();

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
                Some(TrustedActorRole::HumanBlocking) => match review.state() {
                    ForgeReviewState::Approved => {
                        approving_humans.insert(review.author().provider_actor_id().clone());
                    }
                    ForgeReviewState::ChangesRequested | ForgeReviewState::Commented => {
                        blockers.push(ReadinessBlocker::BlockingHumanFeedback(identity.clone()));
                        blocking_human_feedback.push(feedback);
                    }
                    ForgeReviewState::Dismissed | ForgeReviewState::Pending => {}
                },
                Some(TrustedActorRole::BotAdvisory) => bot_advisories.push(feedback),
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
        }
    }
}

impl<'de> Deserialize<'de> for FrozenReviewSnapshot {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = FrozenReviewSnapshotWire::deserialize(deserializer)?;
        let item = wire.snapshot.item().clone();
        let frozen = Self::freeze(&item, wire.snapshot).map_err(serde::de::Error::custom)?;
        if frozen.canonical_sha256 != wire.canonical_sha256 {
            return Err(serde::de::Error::custom(
                "frozen review snapshot canonical digest does not match",
            ));
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", content = "identity", rename_all = "snake_case")]
pub enum ActorEvidenceIdentity {
    Feedback(ReviewFeedbackIdentity),
    Check(ProviderObjectId),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FeedbackKind {
    Review { state: ForgeReviewState },
    ThreadComment { thread_resolved: bool },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "blocker", content = "details", rename_all = "snake_case")]
pub enum ReadinessBlocker {
    UnsupportedThreadCurrencyMetadata,
    UntrustedActor(UntrustedActorBlocker),
    BlockingHumanFeedback(ReviewFeedbackIdentity),
    MissingCheck(String),
    NonSuccessCheck(CheckFailure),
    AmbiguousCheck(AmbiguousCheck),
    InsufficientApproval(ApprovalShortfall),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewTriage {
    blockers: Vec<ReadinessBlocker>,
    blocking_human_feedback: Vec<TriagedFeedback>,
    bot_advisories: Vec<TriagedFeedback>,
    approval_count: usize,
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

    pub fn validate_against(&self, snapshot: &FrozenReviewSnapshot) -> Result<()> {
        validate_disposition_summary(&self.summary)?;
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

/// Builds the only mutation emitted by the review loop: one deterministic,
/// PR-level append-comment effect containing verified dispositions.
pub fn build_pull_request_disposition_publication(
    snapshot: &FrozenReviewSnapshot,
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
    if ordered
        .windows(2)
        .any(|pair| pair[0].feedback_identity == pair[1].feedback_identity)
    {
        bail!("PR disposition publication contains duplicate feedback identities");
    }
    for disposition in &ordered {
        disposition.validate_against(snapshot)?;
    }

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    for disposition in dispositions {
        disposition.validate_against(snapshot)?;
    }
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

    let mut approval_review_ids = snapshot
        .snapshot()
        .reviews()
        .iter()
        .filter(|review| {
            review.state() == ForgeReviewState::Approved
                && policy.feedback_role(review.author()) == Some(TrustedActorRole::HumanBlocking)
        })
        .map(|review| review.provider_review_id().clone())
        .collect::<Vec<_>>();
    approval_review_ids.sort();

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
    prior_snapshot_sha256: String,
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
        &self.prior_snapshot_sha256
    }

    pub fn refreshed_snapshot_sha256(&self) -> &str {
        &self.refreshed_snapshot_sha256
    }

    pub fn disposition_sha256s(&self) -> &[String] {
        &self.disposition_sha256s
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

#[derive(Serialize)]
struct ReviewLoopStateDigestPayload<'a> {
    policy_sha256: &'a str,
    current_snapshot_sha256: &'a str,
    attempts: &'a [ReviewLoopAttempt],
    disposition_sha256s: Vec<&'a str>,
    phase: ReviewLoopPhase,
    predecessor_state_sha256: Option<&'a str>,
}

impl ReviewLoopState {
    pub fn new(policy: ReviewLoopPolicy, current_snapshot: FrozenReviewSnapshot) -> Result<Self> {
        let policy_sha256 = policy.canonical_sha256()?;
        let phase = match evaluate_readiness_with_disposition_digests(
            &current_snapshot,
            &policy,
            Vec::new(),
        )? {
            ReviewLoopReadinessEvaluation::Ready(_) => ReviewLoopPhase::Ready,
            ReviewLoopReadinessEvaluation::Blocked(_) => ReviewLoopPhase::Active,
        };
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
        Ok(value)
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
        evaluate_readiness_with_disposition_digests(
            &self.current_snapshot,
            &self.policy,
            self.dispositions
                .iter()
                .map(|disposition| disposition.record_sha256().to_owned())
                .collect(),
        )
    }

    pub fn refresh<T>(
        &self,
        transport: &T,
        current_item: &ForgeItem,
        sequence: usize,
        attempt_id: impl Into<String>,
        dispositions: Vec<VerifiedDisposition>,
    ) -> Result<Self>
    where
        T: ForgeTransport + ?Sized,
    {
        let refreshed = FrozenReviewSnapshot::observe(transport, current_item)?;
        self.refresh_with_snapshot(current_item, refreshed, sequence, attempt_id, dispositions)
    }

    pub fn refresh_with_snapshot(
        &self,
        current_item: &ForgeItem,
        refreshed: FrozenReviewSnapshot,
        sequence: usize,
        attempt_id: impl Into<String>,
        mut dispositions: Vec<VerifiedDisposition>,
    ) -> Result<Self> {
        if self.phase != ReviewLoopPhase::Active {
            bail!("terminal review-loop state cannot be refreshed");
        }
        if sequence != self.attempts.len() + 1 {
            bail!("review-loop attempt sequence is not the next sequential value");
        }
        let attempt_id = attempt_id.into();
        validate_attempt_id(&attempt_id)?;
        if self
            .attempts
            .iter()
            .any(|attempt| attempt.attempt_id == attempt_id)
        {
            bail!("review-loop attempt id was replayed");
        }
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
        for disposition in &dispositions {
            disposition.validate_against(&self.current_snapshot)?;
        }
        if dispositions
            .windows(2)
            .any(|pair| pair[0].feedback_identity == pair[1].feedback_identity)
            || dispositions.iter().any(|candidate| {
                self.dispositions.iter().any(|existing| {
                    existing.feedback_identity == candidate.feedback_identity
                        || existing.record_sha256 == candidate.record_sha256
                })
            })
        {
            bail!("review-loop disposition was duplicated or replayed");
        }

        let disposition_sha256s = dispositions
            .iter()
            .map(|disposition| disposition.record_sha256().to_owned())
            .collect::<Vec<_>>();
        let attempt = ReviewLoopAttempt {
            sequence,
            attempt_id,
            prior_snapshot_sha256: self.current_snapshot.canonical_sha256().to_owned(),
            refreshed_snapshot_sha256: refreshed.canonical_sha256().to_owned(),
            disposition_sha256s,
        };
        let mut attempts = self.attempts.clone();
        attempts.push(attempt);
        let mut all_dispositions = self.dispositions.clone();
        all_dispositions.extend(dispositions);
        all_dispositions.sort_by(|left, right| left.record_sha256.cmp(&right.record_sha256));

        let current_readiness = evaluate_readiness_with_disposition_digests(
            &refreshed,
            &self.policy,
            all_dispositions
                .iter()
                .map(|disposition| disposition.record_sha256().to_owned())
                .collect(),
        )?;
        let phase = match current_readiness {
            ReviewLoopReadinessEvaluation::Ready(_) => ReviewLoopPhase::Ready,
            ReviewLoopReadinessEvaluation::Blocked(_)
                if attempts.len() >= self.policy.max_attempts() =>
            {
                ReviewLoopPhase::Exhausted
            }
            ReviewLoopReadinessEvaluation::Blocked(_) => ReviewLoopPhase::Active,
        };
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
        Ok(next)
    }

    fn compute_state_sha256(&self) -> Result<String> {
        canonical_digest(
            REVIEW_LOOP_STATE_DIGEST_DOMAIN,
            &ReviewLoopStateDigestPayload {
                policy_sha256: &self.policy_sha256,
                current_snapshot_sha256: self.current_snapshot.canonical_sha256(),
                attempts: &self.attempts,
                disposition_sha256s: self
                    .dispositions
                    .iter()
                    .map(|disposition| disposition.record_sha256())
                    .collect(),
                phase: self.phase,
                predecessor_state_sha256: self.predecessor_state_sha256.as_deref(),
            },
            "review-loop state",
        )
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
        let request = ForgeObservationRequest::pull_request_review_snapshot(item.clone())
            .expect("valid observation request");
        let mut transport = FakeForgeTransport::new();
        transport
            .register_observation(
                request,
                ForgeObservation::PullRequestReviewSnapshot(snapshot),
            )
            .expect("register exact observation");
        FrozenReviewSnapshot::observe(&transport, &item).expect("freeze observed snapshot")
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
        assert!(serde_json::from_value::<FrozenReviewSnapshot>(tampered).is_err());

        let mut unknown = serde_json::to_value(&frozen).expect("serialize frozen snapshot");
        unknown
            .as_object_mut()
            .expect("frozen object")
            .insert("unexpected".to_owned(), serde_json::json!(true));
        assert!(serde_json::from_value::<FrozenReviewSnapshot>(unknown).is_err());
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
    fn state_rejects_duplicate_dispositions_nonsequential_attempts_and_replay() {
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
        let state = ReviewLoopState::new(policy(&human, &bot, &check_actor), first)
            .expect("active review loop");
        let second = blocking_frozen_at(
            item(),
            timestamp_at("2026-08-16T01:01:00Z"),
            &human,
            &check_actor,
            "two",
        );
        let second_item = second.item().clone();

        assert!(state
            .refresh_with_snapshot(
                &second_item,
                second.clone(),
                2,
                "attempt:wrong-sequence",
                Vec::new(),
            )
            .is_err());
        assert!(state
            .refresh_with_snapshot(
                &second_item,
                second.clone(),
                1,
                "attempt:duplicate-disposition",
                vec![disposition.clone(), disposition.clone()],
            )
            .is_err());

        let next = state
            .refresh_with_snapshot(&second_item, second, 1, "attempt:one", vec![disposition])
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
            .refresh_with_snapshot(&third_item, third, 2, "attempt:one", Vec::new())
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
        let state = ReviewLoopState::new(policy_with_max(&human, &bot, &check_actor, 1), first)
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
            .refresh_with_snapshot(&second_item, second.clone(), 1, "attempt:final", Vec::new())
            .expect("bounded refresh");
        assert_eq!(exhausted.phase(), ReviewLoopPhase::Exhausted);
        assert!(exhausted
            .refresh_with_snapshot(
                &second_item,
                second,
                2,
                "attempt:after-terminal",
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
        let state = ReviewLoopState::new(policy(&human, &bot, &check_actor), first)
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
                1,
                "attempt:new-head",
                vec![disposition],
            )
            .expect("exact current refresh");
        assert_eq!(next.phase(), ReviewLoopPhase::Ready);
        assert_eq!(next.current_snapshot().item().head_oid(), Some(HEAD_2));
        assert_eq!(next.current_snapshot().item().base_oid(), Some(BASE_2));

        assert!(state
            .refresh_with_snapshot(
                state.current_snapshot().item(),
                current.clone(),
                1,
                "attempt:wrong-current",
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
            .refresh_with_snapshot(&current_item, not_later, 1, "attempt:not-later", Vec::new())
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
        let request =
            build_pull_request_disposition_publication(&frozen, publisher.clone(), &[disposition])
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
}
