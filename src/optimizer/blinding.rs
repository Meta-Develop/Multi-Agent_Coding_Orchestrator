//! Blinded reviewer, auditor, and label-producer handoffs (issue #203).
//!
//! Producer runtime, model, effort, and provider are preserved in provenance
//! records and never appear on the evaluator-facing type. Unblinding is an
//! explicit, recorded operation. Human surfaces default to hidden.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

use super::action::CanonicalEffort;
use super::catalog::ModelCatalogSnapshot;
use super::error::OptimizerError;
use super::ids::{
    BackendId, CandidateId, ModelFamilyId, ProviderId, RuntimeSlug, TaskId, TimestampMillis,
};
use super::quality::ReviewLens;

/// Stable producing agent. Changing model or session does not mint a new one.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProducerIdentity {
    pub agent_id: String,
    pub provider: ProviderId,
    pub backend: BackendId,
    pub model: RuntimeSlug,
    pub family: ModelFamilyId,
    pub effort: CanonicalEffort,
    pub session_id: String,
}

/// Evaluator-facing review lens. Independent-provider is a constraint, not a
/// disclosed producer name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlindedLens {
    SpecificationVsResult,
    DiffOnly,
    RepositoryOnly,
    TestsOnly,
    PerformanceOnly,
    SecurityOnly,
    IndependentProvider,
}

impl BlindedLens {
    pub fn from_review_lens(lens: &ReviewLens) -> Self {
        match lens {
            ReviewLens::SpecificationVsResult => Self::SpecificationVsResult,
            ReviewLens::DiffOnly => Self::DiffOnly,
            ReviewLens::RepositoryOnly => Self::RepositoryOnly,
            ReviewLens::TestsOnly => Self::TestsOnly,
            ReviewLens::PerformanceOnly => Self::PerformanceOnly,
            ReviewLens::SecurityOnly => Self::SecurityOnly,
            ReviewLens::IndependentProvider { .. } => Self::IndependentProvider,
        }
    }
}

/// Handoff given to a reviewer, auditor, or label producer.
///
/// There is no field for the producing runtime, model, effort, or provider.
/// Adding one is a type-level regression of this issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindedReviewHandoff {
    pub task_id: TaskId,
    pub candidate_id: CandidateId,
    pub specification_digest: String,
    pub evidence_digest: String,
    pub required_lenses: Vec<BlindedLens>,
    pub independent_provider_required: bool,
}

impl BlindedReviewHandoff {
    pub fn new(
        task_id: TaskId,
        candidate_id: CandidateId,
        specification_digest: String,
        evidence_digest: String,
    ) -> Self {
        Self {
            task_id,
            candidate_id,
            specification_digest,
            evidence_digest,
            required_lenses: Vec::new(),
            independent_provider_required: false,
        }
    }
}

/// Provenance kept off the evaluator view. #159 still knows who produced what.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceRecord {
    pub producer: ProducerIdentity,
    pub handoff: BlindedReviewHandoff,
}

/// Recorded unblinding. No other function returns producer identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnblindingEvent {
    pub recorded_at: TimestampMillis,
    pub actor: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlindingState {
    Blinded,
    Unblinded { event: UnblindingEvent },
}

impl BlindingState {
    pub fn is_blinded(&self) -> bool {
        matches!(self, Self::Blinded)
    }
}

/// Decision or derived label that carries the blinding state it was made under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindedDecisionRecord {
    pub candidate_id: CandidateId,
    pub blinding: BlindingState,
    pub derived_labels: Vec<DerivedLabel>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedLabel {
    pub kind: String,
    pub value: String,
    pub blinding: BlindingState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProducerVisibility {
    Hidden,
    Revealed,
}

impl Default for ProducerVisibility {
    fn default() -> Self {
        Self::Hidden
    }
}

/// Human review/approval payload. Producer identity is absent unless toggled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanSurfaceView {
    pub visibility: ProducerVisibility,
    pub handoff: BlindedReviewHandoff,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub producer: Option<ProducerIdentity>,
    pub blinding: BlindingState,
}

pub fn render_human_surface(
    provenance: &ProvenanceRecord,
    visibility: ProducerVisibility,
    now: TimestampMillis,
    actor: &str,
) -> Result<HumanSurfaceView, OptimizerError> {
    match visibility {
        ProducerVisibility::Hidden => Ok(HumanSurfaceView {
            visibility,
            handoff: provenance.handoff.clone(),
            producer: None,
            blinding: BlindingState::Blinded,
        }),
        ProducerVisibility::Revealed => {
            let (_identity, event) = unblind(provenance, now, actor, "operator-toggle")?;
            Ok(HumanSurfaceView {
                visibility,
                handoff: provenance.handoff.clone(),
                producer: Some(provenance.producer.clone()),
                blinding: BlindingState::Unblinded { event },
            })
        }
    }
}

/// Explicit unblinding. This is the only function that returns producer identity.
pub fn unblind(
    provenance: &ProvenanceRecord,
    now: TimestampMillis,
    actor: &str,
    reason: &str,
) -> Result<(ProducerIdentity, UnblindingEvent), OptimizerError> {
    let actor = actor.trim();
    let reason = reason.trim();
    if actor.is_empty() || reason.is_empty() {
        return Err(OptimizerError::invalid(
            "unblinding requires a recorded actor and reason",
        ));
    }
    Ok((
        provenance.producer.clone(),
        UnblindingEvent {
            recorded_at: now,
            actor: actor.to_string(),
            reason: reason.to_string(),
        },
    ))
}

/// Enforce the independent-provider lens without disclosing the producer.
pub fn assign_independent_reviewer<'a>(
    producer: &ProducerIdentity,
    candidates: &'a [ReviewerCandidate],
) -> Result<&'a ReviewerCandidate, OptimizerError> {
    candidates
        .iter()
        .find(|candidate| candidate.provider != producer.provider)
        .ok_or_else(|| {
            OptimizerError::invalid(
                "no reviewer from a different provider is available; constraint is enforced without disclosing the producer",
            )
        })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewerCandidate {
    pub reviewer_id: String,
    pub provider: ProviderId,
}

/// Tokens that must not appear in anything handed to a reviewer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LeakLexicon {
    tokens: BTreeSet<String>,
}

impl LeakLexicon {
    pub fn from_catalog(snapshot: &ModelCatalogSnapshot) -> Self {
        let mut tokens = BTreeSet::new();
        for identity in snapshot.identities() {
            insert_token(&mut tokens, identity.runtime_slug.as_str());
            insert_token(&mut tokens, identity.model_family.as_str());
            insert_token(&mut tokens, identity.provider.as_str());
            insert_token(&mut tokens, identity.backend.as_str());
        }
        Self { tokens }
    }

    pub fn insert_runtime_marker(&mut self, marker: &str) {
        insert_token(&mut self.tokens, marker);
    }

    pub fn tokens(&self) -> impl Iterator<Item = &str> {
        self.tokens.iter().map(String::as_str)
    }
}

fn insert_token(tokens: &mut BTreeSet<String>, raw: &str) {
    let token = raw.trim().to_ascii_lowercase();
    if token.len() >= 4 {
        tokens.insert(token);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeakChannel {
    ReviewerPayload,
    Transcript,
    ToolBanner,
    CommitTrailer,
    BranchName,
    WorktreeName,
    RunPath,
    UserAgent,
}

/// Side channels that must be scrubbed before a reviewer sees them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SideChannelSet {
    pub transcripts: Vec<String>,
    pub tool_banners: Vec<String>,
    pub commit_trailers: Vec<String>,
    pub branch_names: Vec<String>,
    pub worktree_names: Vec<String>,
    pub run_paths: Vec<String>,
    pub user_agents: Vec<String>,
}

pub fn assert_reviewer_view_is_blind(
    handoff: &BlindedReviewHandoff,
    lexicon: &LeakLexicon,
    channels: &SideChannelSet,
) -> Result<(), OptimizerError> {
    let payload = serde_json::to_string(handoff).map_err(|error| {
        OptimizerError::invalid(format!("failed to serialize blinded handoff: {error}"))
    })?;
    scan_channel(LeakChannel::ReviewerPayload, &payload, lexicon)?;
    for transcript in &channels.transcripts {
        scan_channel(LeakChannel::Transcript, transcript, lexicon)?;
    }
    for banner in &channels.tool_banners {
        scan_channel(LeakChannel::ToolBanner, banner, lexicon)?;
    }
    for trailer in &channels.commit_trailers {
        scan_channel(LeakChannel::CommitTrailer, trailer, lexicon)?;
    }
    for branch in &channels.branch_names {
        scan_channel(LeakChannel::BranchName, branch, lexicon)?;
    }
    for worktree in &channels.worktree_names {
        scan_channel(LeakChannel::WorktreeName, worktree, lexicon)?;
    }
    for path in &channels.run_paths {
        scan_channel(LeakChannel::RunPath, path, lexicon)?;
        if Path::new(path)
            .components()
            .any(|component| lexicon_contains(lexicon, &component.as_os_str().to_string_lossy()))
        {
            return Err(leak_error(LeakChannel::RunPath, path));
        }
    }
    for agent in &channels.user_agents {
        scan_channel(LeakChannel::UserAgent, agent, lexicon)?;
    }
    Ok(())
}

fn scan_channel(
    channel: LeakChannel,
    text: &str,
    lexicon: &LeakLexicon,
) -> Result<(), OptimizerError> {
    if lexicon_contains(lexicon, text) {
        return Err(leak_error(channel, text));
    }
    Ok(())
}

fn lexicon_contains(lexicon: &LeakLexicon, text: &str) -> bool {
    let haystack = text.to_ascii_lowercase();
    lexicon
        .tokens
        .iter()
        .any(|token| haystack.contains(token.as_str()))
}

fn leak_error(channel: LeakChannel, excerpt: &str) -> OptimizerError {
    OptimizerError::invalid(format!(
        "producer identity leaked through {channel:?}: {}",
        excerpt.chars().take(80).collect::<String>()
    ))
}

pub fn decision_from_blinded_handoff(
    handoff: &BlindedReviewHandoff,
    labels: Vec<DerivedLabel>,
) -> BlindedDecisionRecord {
    BlindedDecisionRecord {
        candidate_id: handoff.candidate_id.clone(),
        blinding: BlindingState::Blinded,
        derived_labels: labels
            .into_iter()
            .map(|mut label| {
                label.blinding = BlindingState::Blinded;
                label
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::action::RuntimeModelId;
    use crate::optimizer::catalog::CatalogEntry;
    use crate::optimizer::ids::CatalogVersion;

    fn producer() -> ProducerIdentity {
        ProducerIdentity {
            agent_id: "producer-agent".to_string(),
            provider: ProviderId::new("provider-a").expect("provider"),
            backend: BackendId::new("runtime-alpha").expect("backend"),
            model: RuntimeSlug::new("worker-alpha-slug").expect("slug"),
            family: ModelFamilyId::new("family-one").expect("family"),
            effort: CanonicalEffort::Medium,
            session_id: "session-1".to_string(),
        }
    }

    fn handoff() -> BlindedReviewHandoff {
        let mut handoff = BlindedReviewHandoff::new(
            TaskId::new("task-1").expect("task"),
            CandidateId::new("cand-1").expect("candidate"),
            "spec-digest".to_string(),
            "evidence-digest".to_string(),
        );
        handoff.required_lenses = vec![BlindedLens::DiffOnly, BlindedLens::IndependentProvider];
        handoff.independent_provider_required = true;
        handoff
    }

    fn catalog() -> ModelCatalogSnapshot {
        ModelCatalogSnapshot {
            catalog_version: CatalogVersion::new("cat-1").expect("catalog"),
            observed_at: TimestampMillis::from_millis(1),
            models: vec![CatalogEntry {
                identity: RuntimeModelId {
                    provider: ProviderId::new("provider-a").expect("provider"),
                    backend: BackendId::new("runtime-alpha").expect("backend"),
                    model_family: ModelFamilyId::new("family-one").expect("family"),
                    runtime_slug: RuntimeSlug::new("worker-alpha-slug").expect("slug"),
                    catalog_version: CatalogVersion::new("cat-1").expect("catalog"),
                    observation_timestamp: TimestampMillis::from_millis(1),
                },
                supported_efforts: vec![CanonicalEffort::Medium],
            }],
        }
    }

    fn provenance() -> ProvenanceRecord {
        ProvenanceRecord {
            producer: producer(),
            handoff: handoff(),
        }
    }

    #[test]
    fn handoff_json_has_no_producer_identity_fields() {
        let json = serde_json::to_value(handoff()).expect("json");
        let keys: BTreeSet<&str> = json
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        for forbidden in [
            "producer",
            "runtime",
            "model",
            "effort",
            "provider",
            "backend",
            "family",
            "session_id",
            "agent_id",
        ] {
            assert!(
                !keys.contains(forbidden),
                "blinded handoff must not expose {forbidden}"
            );
        }
    }

    #[test]
    fn independent_provider_lens_does_not_name_the_producer() {
        let lens = BlindedLens::from_review_lens(&ReviewLens::IndependentProvider {
            provider: "provider-a".to_string(),
        });
        let json = serde_json::to_string(&lens).expect("json");
        assert!(!json.contains("provider-a"));
        assert_eq!(lens, BlindedLens::IndependentProvider);
    }

    #[test]
    fn independent_provider_constraint_holds_without_disclosure() {
        let producer = producer();
        let same = ReviewerCandidate {
            reviewer_id: "r-same".to_string(),
            provider: ProviderId::new("provider-a").expect("provider"),
        };
        let other = ReviewerCandidate {
            reviewer_id: "r-other".to_string(),
            provider: ProviderId::new("provider-b").expect("provider"),
        };
        let candidates = [same, other];
        let assigned = assign_independent_reviewer(&producer, &candidates).expect("assign");
        assert_eq!(assigned.reviewer_id, "r-other");
        let handoff_json = serde_json::to_string(&handoff()).expect("json");
        assert!(!handoff_json.contains(producer.provider.as_str()));
        assert!(!handoff_json.contains("provider-a"));
    }

    #[test]
    fn human_surface_defaults_to_hidden() {
        let view = render_human_surface(
            &provenance(),
            ProducerVisibility::default(),
            TimestampMillis::from_millis(10),
            "operator",
        )
        .expect("render");
        assert_eq!(view.visibility, ProducerVisibility::Hidden);
        assert!(view.producer.is_none());
        assert!(view.blinding.is_blinded());
    }

    #[test]
    fn unblinding_is_explicit_and_recorded() {
        let (identity, event) = unblind(
            &provenance(),
            TimestampMillis::from_millis(11),
            "analyst",
            "post-hoc analysis",
        )
        .expect("unblind");
        assert_eq!(identity.model.as_str(), "worker-alpha-slug");
        assert_eq!(event.actor, "analyst");
        assert_eq!(event.reason, "post-hoc analysis");
        let revealed = render_human_surface(
            &provenance(),
            ProducerVisibility::Revealed,
            TimestampMillis::from_millis(12),
            "operator",
        )
        .expect("reveal");
        assert!(matches!(revealed.blinding, BlindingState::Unblinded { .. }));
        assert!(revealed.producer.is_some());
    }

    #[test]
    fn unblinding_without_reason_is_refused() {
        let error = unblind(
            &provenance(),
            TimestampMillis::from_millis(13),
            "analyst",
            "  ",
        )
        .expect_err("blank reason");
        assert!(error.to_string().contains("unblinding"));
    }

    #[test]
    fn derived_labels_record_blinding_state() {
        let record = decision_from_blinded_handoff(
            &handoff(),
            vec![DerivedLabel {
                kind: "rework".to_string(),
                value: "incomplete-tests".to_string(),
                blinding: BlindingState::Blinded,
            }],
        );
        assert!(record.blinding.is_blinded());
        assert!(record
            .derived_labels
            .iter()
            .all(|label| label.blinding.is_blinded()));
    }

    #[test]
    fn scrubbing_rejects_catalog_slugs_and_side_channels() {
        let lexicon = LeakLexicon::from_catalog(&catalog());
        assert_reviewer_view_is_blind(&handoff(), &lexicon, &SideChannelSet::default())
            .expect("clean payload");

        let leaky = SideChannelSet {
            transcripts: vec!["produced by worker-alpha-slug".to_string()],
            ..SideChannelSet::default()
        };
        let transcript = assert_reviewer_view_is_blind(&handoff(), &lexicon, &leaky)
            .expect_err("slug in transcript");
        assert!(transcript.to_string().contains("Transcript"));

        let trailers = SideChannelSet {
            commit_trailers: vec!["Co-Authored-By: worker-alpha-slug".to_string()],
            ..SideChannelSet::default()
        };
        assert!(assert_reviewer_view_is_blind(&handoff(), &lexicon, &trailers).is_err());

        let banners = SideChannelSet {
            tool_banners: vec!["runtime-alpha ready".to_string()],
            ..SideChannelSet::default()
        };
        assert!(assert_reviewer_view_is_blind(&handoff(), &lexicon, &banners).is_err());

        let branches = SideChannelSet {
            branch_names: vec!["maco/family-one-fix".to_string()],
            worktree_names: vec!["wt-family-one".to_string()],
            run_paths: vec![".maco/runs/worker-alpha-slug/1".to_string()],
            user_agents: vec!["agent/runtime-alpha".to_string()],
            ..SideChannelSet::default()
        };
        assert!(assert_reviewer_view_is_blind(&handoff(), &lexicon, &branches).is_err());
    }
}
