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
use super::{
    GithubCheckSummary, GithubPrCandidate, GithubPrSourceTrust, InboxIndependentAuditMergeLaneTask,
    InboxItem, InboxItemKind, InboxSourceProvider,
};
use crate::objective_profile::default_resolved_objective_profile;
use crate::optimizer::merge_authority::{
    aggregate_lenses, assess_independence, AgentIdentity, LensDecision, LensVerdict, MergeActor,
    ProducerFingerprint, SessionId,
};
use crate::publication::forge_transport::{
    FakeForgeTransport, ForgeActor, ForgeCheck, ForgeCheckConclusion, ForgeCheckStatus, ForgeItem,
    ForgeItemKind, ForgeObservation, ForgeObservationRequest, ForgeRepository, ForgeReview,
    ForgeReviewState, ForgeTimestamp, ProviderObjectId, ProviderObjectKind,
    PullRequestAuditorEvidence, PullRequestReviewSnapshot, ReportedActorKind,
};
use crate::selection::{
    self, AuthorityRole, Boundedness, BudgetSignal, CandidateCapabilities, CatalogModel,
    ContextSize, DecisionStatus, DynamicSignals, OperatorConstraints, ReasoningEffort, RiskLevel,
    RuntimeCatalog, RuntimePoolState, SelectionInput, SelectionProvenance, SelectorCalibrationRef,
    TaskHorizon, TaskProfile,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const INDEPENDENT_AUDIT_LANE_VERSION: u32 = 1;
const INDEPENDENT_AUDITOR_STABLE_ID: &str = "maco-independent-pr-auditor";
const INDEPENDENT_AUDITOR_TASK_CLASS: &str = "review_gate";
const INDEPENDENT_AUDITOR_PERMISSION_PROFILE: &str = "maco_external_codex";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InboxIndependentAuditLaneStatus {
    Accepted,
    Blocked,
}

/// Closed reasons why the independent-audit lane did not produce accepted
/// head-bound evidence. Downstream merge authority must never infer success
/// from a human-readable message.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum InboxIndependentAuditLaneBlocker {
    MissingEligibility {
        evidence: Vec<String>,
    },
    DraftPullRequest,
    StaleHead {
        expected_head_oid: String,
    },
    UnavailableEligibleAuditor {
        detail: String,
    },
    ForkSource,
    UntrustedSource,
    MissingEvidence {
        evidence: Vec<String>,
    },
    ProducerAuditorIdentityConflict {
        producer_identity: String,
        auditor_identity: String,
    },
    SelectorRejected {
        detail: String,
    },
    LaunchFailed {
        detail: String,
    },
    MissingAuditEvidence {
        evidence: Vec<String>,
    },
    AuditEvidenceMismatch {
        field: String,
    },
    AuditRejected {
        summary: String,
    },
}

/// Compact selector proof retained with the durable lane result. The complete
/// normalized decision remains reproducible from its digest and the built-in
/// dated priors; these are the fields the launch adapter actually consumed.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InboxIndependentAuditorSelectionEvidence {
    pub selector_schema_version: u32,
    pub runtime: String,
    pub model: String,
    pub effort: ReasoningEffort,
    pub objective_profile_id: String,
    pub objective_profile_version: u32,
    pub objective_profile_sha256: String,
    pub selector_input_sha256: String,
    pub total_score_microunits: u64,
    pub decision_reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InboxIndependentAuditLaunchEvidence {
    pub adapter: String,
    pub permission_profile: String,
    pub auditor_identity: String,
    pub auditor_session_id: String,
    pub prompt_sha256: String,
    pub report_sha256: Option<String>,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub timed_out: bool,
    pub safely_executed: bool,
    pub publishable: bool,
}

/// Durable, source/head-bound lane result. `Accepted` is audit evidence only:
/// it grants no merge permission and performs no merge.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InboxIndependentAuditLaneResult {
    pub version: u32,
    pub item_id: String,
    pub source_key: String,
    pub number: u64,
    pub source_snapshot_digest: String,
    pub head_oid: String,
    pub status: InboxIndependentAuditLaneStatus,
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selection: Option<InboxIndependentAuditorSelectionEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch: Option<InboxIndependentAuditLaunchEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auditor_evidence: Option<PullRequestAuditorEvidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blockers: Vec<InboxIndependentAuditLaneBlocker>,
    pub grants_merge_permission: bool,
    pub auto_merge_performed: bool,
    pub next_action: String,
}

/// Strict model-produced evidence. Identity, runtime, model, effort, and
/// permission profile are parent-controlled launch facts and are deliberately
/// not accepted from this untrusted payload.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InboxIndependentAuditorOutput {
    pub version: u32,
    pub item_id: String,
    pub source_snapshot_digest: String,
    pub head_oid: String,
    pub accepted: bool,
    pub lenses: Vec<LensVerdict>,
    pub summary: String,
    pub no_further_delegation: bool,
    pub read_only: bool,
}

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

pub fn independent_auditor_stable_id() -> &'static str {
    INDEPENDENT_AUDITOR_STABLE_ID
}

pub fn independent_auditor_permission_profile() -> &'static str {
    INDEPENDENT_AUDITOR_PERMISSION_PROFILE
}

/// Run MACO's replayable evaluation selector for the critical read-only
/// auditor role. `available_models` is a trusted runtime-catalog observation,
/// not model output.
pub fn select_critical_independent_auditor(
    available_models: &BTreeSet<String>,
) -> Result<SelectionProvenance> {
    let priors = selection::built_in_prior_dataset()
        .context("load built-in selector priors for independent auditor")?;
    let task = TaskProfile {
        task_class: INDEPENDENT_AUDITOR_TASK_CLASS.to_string(),
        risk: RiskLevel::Critical,
        boundedness: Boundedness::CrossCutting,
        context: ContextSize::Long,
        horizon: TaskHorizon::Long,
        authority_role: AuthorityRole::ReviewAuditor,
    };
    let mut models = Vec::new();
    for prior in priors
        .models
        .iter()
        .filter(|prior| prior.runtime == "codex")
    {
        let mut supported_efforts = prior
            .class_fit
            .iter()
            .filter(|evidence| evidence.task_class == task.task_class)
            .map(|evidence| evidence.effort)
            .chain(prior.strong_gate_fallback_efforts.iter().copied())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        supported_efforts.sort();
        if supported_efforts.is_empty() {
            continue;
        }
        let mut authority_roles = BTreeSet::new();
        if !prior.prohibited
            && !prior
                .prohibited_authority_roles
                .contains(&AuthorityRole::ReviewAuditor)
            && (!prior.strong_gate_fallback_efforts.is_empty()
                || prior
                    .authority_evidence
                    .iter()
                    .any(|evidence| evidence.role == AuthorityRole::ReviewAuditor))
        {
            authority_roles.insert(AuthorityRole::ReviewAuditor);
        }
        models.push(CatalogModel {
            model: prior.model.clone(),
            available: available_models.contains(&prior.model),
            supported_efforts,
            capabilities: CandidateCapabilities {
                task_classes: prior
                    .class_fit
                    .iter()
                    .map(|evidence| evidence.task_class.clone())
                    .collect(),
                authority_roles,
                boundedness: [
                    Boundedness::TightlyBounded,
                    Boundedness::Bounded,
                    Boundedness::CrossCutting,
                ]
                .into_iter()
                .collect(),
                maximum_risk: RiskLevel::Critical,
                maximum_context: ContextSize::Long,
                maximum_horizon: TaskHorizon::Long,
                long_context: prior.long_context_eligible,
            },
        });
    }
    models.sort_by(|left, right| left.model.cmp(&right.model));
    let catalog_sha256 = crate::artifacts::state_auth::sha256_hex(
        &serde_json::to_vec(&models).context("serialize independent-auditor catalog")?,
    );
    let calibration = priors
        .objective_profiles
        .first()
        .context("built-in selector priors omitted calibration")?;
    let input = SelectionInput {
        task,
        catalogs: vec![RuntimeCatalog {
            runtime: "codex".to_string(),
            revision: format!("independent-auditor-catalog-sha256:{catalog_sha256}"),
            advertised_at: "runtime-catalog-observation".to_string(),
            models,
        }],
        pools: vec![RuntimePoolState {
            runtime: "codex".to_string(),
            admission_open: true,
            pool_reference: None,
            pool_kind: None,
            entitlement_bounded: true,
            entitlement_capacity_units: 1,
            entitlement_remaining_units: 1,
            pool_pressure_basis_points: 0,
            observed_consumption_units: 0,
            marginal_cost_microunits: 0,
            exhausted: false,
            exhaustion_behavior: None,
            authorized_alternatives: Vec::new(),
            observation_revision: "independent-auditor-admission-v1".to_string(),
            observation_source: None,
            admission_provenance:
                "the inbox launch adapter admits one non-interactive read-only auditor".to_string(),
            failover_provenance: None,
        }],
        quota_source: None,
        constraints: OperatorConstraints {
            allowed_runtimes: ["codex".to_string()].into_iter().collect(),
            allowed_models: BTreeSet::new(),
            forbidden_runtimes: BTreeSet::new(),
            forbidden_models: BTreeSet::new(),
            forbidden_candidates: BTreeSet::new(),
            allow_debug_override: false,
        },
        objective_profile: SelectorCalibrationRef {
            name: calibration.name.clone(),
            version: calibration.version,
            expected_digest: None,
        },
        resolved_objective_profile: default_resolved_objective_profile()
            .context("resolve independent-auditor objective profile")?,
        priors,
        outcomes: Vec::new(),
        signals: DynamicSignals {
            retry_count: 0,
            budget_signal: BudgetSignal::Continue,
            previous_choice: None,
            previous_catalog_digest: None,
            environment_rejections: Vec::new(),
        },
        debug_override: None,
        operational_observations: None,
    };
    selection::select(&input).context("select critical independent auditor")
}

pub fn compact_independent_auditor_selection(
    decision: &SelectionProvenance,
) -> Result<InboxIndependentAuditorSelectionEvidence> {
    if decision.status != DecisionStatus::Selected {
        bail!("critical independent-auditor selector failed closed");
    }
    let choice = decision
        .choice
        .as_ref()
        .context("selected independent-auditor decision omitted its choice")?;
    Ok(InboxIndependentAuditorSelectionEvidence {
        selector_schema_version: decision.schema_version,
        runtime: choice.candidate.runtime.clone(),
        model: choice.candidate.model.clone(),
        effort: choice.candidate.effort,
        objective_profile_id: decision.resolved_objective_profile.profile.id.clone(),
        objective_profile_version: decision.resolved_objective_profile.profile.version,
        objective_profile_sha256: decision
            .resolved_objective_profile
            .profile
            .content_hash
            .clone(),
        selector_input_sha256: decision.input_digests.normalized_input.value.clone(),
        total_score_microunits: choice.total_score_microunits,
        decision_reason: decision.decision_reason.clone(),
    })
}

pub fn independent_audit_task_blockers(
    item: &InboxItem,
    task: &InboxIndependentAuditMergeLaneTask,
) -> Vec<InboxIndependentAuditLaneBlocker> {
    let Some(pull_request) = item.pull_request.as_ref() else {
        return vec![InboxIndependentAuditLaneBlocker::MissingEligibility {
            evidence: vec!["pull_request_metadata".to_string()],
        }];
    };
    let mut blockers = Vec::new();
    let mut missing_eligibility = Vec::new();
    let mut missing_evidence = Vec::new();
    if item.kind != InboxItemKind::PullRequest || !item.selected {
        missing_eligibility.push("selected_pull_request".to_string());
    }
    if pull_request.is_draft {
        blockers.push(InboxIndependentAuditLaneBlocker::DraftPullRequest);
    }
    match pull_request.source_trust {
        GithubPrSourceTrust::TrustedTargetRepository => {}
        GithubPrSourceTrust::Fork => blockers.push(InboxIndependentAuditLaneBlocker::ForkSource),
        GithubPrSourceTrust::Untrusted => {
            blockers.push(InboxIndependentAuditLaneBlocker::UntrustedSource)
        }
    }
    if item.source_snapshot.state() != "OPEN" {
        missing_eligibility.push("open_pull_request".to_string());
    }
    if pull_request.review_feedback.requested_changes {
        missing_eligibility.push("no_requested_changes".to_string());
    }
    if pull_request
        .review_feedback
        .unresolved_thread_count
        .is_some_and(|count| count > 0)
    {
        missing_eligibility.push("resolved_review_threads".to_string());
    }
    if pull_request.checks.is_empty() {
        missing_evidence.push("ci_checks".to_string());
    }
    for check in &pull_request.checks {
        if canonical_check_name(&check.name).is_none() {
            missing_evidence.push("ci_check_name".to_string());
        }
        if !check
            .status
            .as_deref()
            .is_some_and(|status| status.eq_ignore_ascii_case("completed"))
            || !check
                .conclusion
                .as_deref()
                .is_some_and(|conclusion| conclusion.eq_ignore_ascii_case("success"))
        {
            missing_eligibility.push("passing_completed_ci".to_string());
        }
    }
    if pull_request.changed_files.is_empty() {
        missing_evidence.push("changed_files".to_string());
    }
    if pull_request.author.as_deref().is_none_or(str::is_empty) {
        missing_evidence.push("producer_identity".to_string());
    }
    if item.source_snapshot.digest() != task.source_snapshot_digest {
        missing_evidence.push("source_snapshot_binding".to_string());
    }
    if item.source_snapshot.head_oid() != Some(task.head_oid.as_str()) {
        missing_evidence.push("head_oid_binding".to_string());
    }
    if item.source_snapshot.base_oid() != Some(task.base_oid.as_str()) {
        missing_evidence.push("base_oid_binding".to_string());
    }
    if pull_request.author.as_deref() != Some(task.producer_login.as_str()) {
        missing_evidence.push("producer_identity_binding".to_string());
    }
    if pull_request.is_draft != task.is_draft
        || pull_request.source_trust != task.source_trust
        || pull_request.head_repository != task.head_repository
        || pull_request.changed_files != task.changed_files
        || pull_request.checks != task.checks
    {
        missing_evidence.push("candidate_evidence_binding".to_string());
    }
    if !(task.requires_trusted_actor_binding
        && task.requires_fresh_source_revalidation
        && task.requires_passing_ci
        && task.requires_independent_auditor)
        || task.grants_merge_permission
        || task.auto_merge_performed
    {
        missing_evidence.push("fail_closed_task_policy".to_string());
    }
    missing_eligibility.sort();
    missing_eligibility.dedup();
    missing_evidence.sort();
    missing_evidence.dedup();
    if !missing_eligibility.is_empty() {
        blockers.push(InboxIndependentAuditLaneBlocker::MissingEligibility {
            evidence: missing_eligibility,
        });
    }
    if !missing_evidence.is_empty() {
        blockers.push(InboxIndependentAuditLaneBlocker::MissingEvidence {
            evidence: missing_evidence,
        });
    }
    blockers
}

pub fn independent_auditor_actor(session_id: &str, model: &str) -> MergeActor {
    MergeActor {
        agent: AgentIdentity {
            stable_id: INDEPENDENT_AUDITOR_STABLE_ID.to_string(),
        },
        session: SessionId {
            id: session_id.to_string(),
        },
        model_label: model.to_string(),
    }
}

pub fn producer_auditor_separation_blocker(
    producer_login: &str,
    auditor: &MergeActor,
    head_oid: &str,
) -> Option<InboxIndependentAuditLaneBlocker> {
    let producer = ProducerFingerprint {
        actor: MergeActor {
            agent: AgentIdentity {
                stable_id: producer_login.to_string(),
            },
            session: SessionId {
                id: format!("github-pr-head:{head_oid}"),
            },
            model_label: "github-pr-producer".to_string(),
        },
        commit_authors: vec![producer_login.to_string()],
        commit_committers: vec![producer_login.to_string()],
    };
    let separation = assess_independence(&producer, auditor);
    (!separation.independent).then(|| {
        InboxIndependentAuditLaneBlocker::ProducerAuditorIdentityConflict {
            producer_identity: producer_login.to_string(),
            auditor_identity: auditor.agent.stable_id.clone(),
        }
    })
}

pub fn independent_auditor_prompt(
    item: &InboxItem,
    task: &InboxIndependentAuditMergeLaneTask,
    selection: &InboxIndependentAuditorSelectionEvidence,
) -> Result<String> {
    let task_json = serde_json::to_string_pretty(task)
        .context("serialize source-bound independent-audit task")?;
    Ok(format!(
        "You are the terminal critical independent auditor for one pull-request candidate.\n\
Stay read-only, non-interactive, and offline. Do not delegate, modify files, comment, approve, or merge.\n\
Review only the exact source/head-bound task below. Return exactly one strict JSON object and no prose.\n\
The object must contain: version=1, item_id, source_snapshot_digest, head_oid, accepted, lenses, summary, no_further_delegation=true, read_only=true.\n\
Each lens must contain lens_id, model_label, framing, information_scope, and decision. Decisions are accept, reject, uncertain, cannot_verify, or lacks_context.\n\
Acceptance requires at least two decorrelated accepted lenses; uncertainty or missing evidence must set accepted=false.\n\
Selected runtime/model/effort: {}/{}/{:?}.\n\
Expected item_id: {}\nExpected source_snapshot_digest: {}\nExpected head_oid: {}\n\
Source-bound task:\n{}",
        selection.runtime,
        selection.model,
        selection.effort,
        item.item_id,
        task.source_snapshot_digest,
        task.head_oid,
        task_json
    ))
}

pub fn validate_independent_auditor_output(
    output: InboxIndependentAuditorOutput,
    item: &InboxItem,
    task: &InboxIndependentAuditMergeLaneTask,
    auditor: MergeActor,
) -> std::result::Result<PullRequestAuditorEvidence, InboxIndependentAuditLaneBlocker> {
    if output.version != INDEPENDENT_AUDIT_LANE_VERSION {
        return Err(InboxIndependentAuditLaneBlocker::AuditEvidenceMismatch {
            field: "version".to_string(),
        });
    }
    for (field, matched) in [
        ("item_id", output.item_id == item.item_id),
        (
            "source_snapshot_digest",
            output.source_snapshot_digest == task.source_snapshot_digest,
        ),
        ("head_oid", output.head_oid == task.head_oid),
    ] {
        if !matched {
            return Err(InboxIndependentAuditLaneBlocker::AuditEvidenceMismatch {
                field: field.to_string(),
            });
        }
    }
    let mut missing = Vec::new();
    if !output.no_further_delegation {
        missing.push("no_further_delegation".to_string());
    }
    if !output.read_only {
        missing.push("read_only".to_string());
    }
    if output.summary.trim().is_empty() {
        missing.push("summary".to_string());
    }
    if output.lenses.is_empty() {
        missing.push("lenses".to_string());
    }
    if !missing.is_empty() {
        return Err(InboxIndependentAuditLaneBlocker::MissingAuditEvidence { evidence: missing });
    }
    if !output.accepted {
        return Err(InboxIndependentAuditLaneBlocker::AuditRejected {
            summary: output.summary,
        });
    }
    if output
        .lenses
        .iter()
        .any(|lens| lens.decision != LensDecision::Accept)
    {
        return Err(InboxIndependentAuditLaneBlocker::AuditRejected {
            summary: "one or more independent audit lenses did not accept".to_string(),
        });
    }
    let agreement = aggregate_lenses(&output.lenses);
    if agreement.distinct_lenses < agreement.required_distinct || !agreement.unanimous_accept {
        return Err(InboxIndependentAuditLaneBlocker::MissingAuditEvidence {
            evidence: vec!["two_decorrelated_accepted_lenses".to_string()],
        });
    }
    if let Some(blocker) =
        producer_auditor_separation_blocker(&task.producer_login, &auditor, &task.head_oid)
    {
        return Err(blocker);
    }
    let observed_at = ForgeTimestamp::new(&task.source_updated_at).map_err(|_| {
        InboxIndependentAuditLaneBlocker::MissingAuditEvidence {
            evidence: vec!["source_observation_timestamp".to_string()],
        }
    })?;
    Ok(PullRequestAuditorEvidence {
        head_oid: task.head_oid.clone(),
        snapshot_observed_at: observed_at,
        auditor,
        lenses: output.lenses,
    })
}

pub fn blocked_independent_audit_lane_result(
    item: &InboxItem,
    head_oid: impl Into<String>,
    blockers: Vec<InboxIndependentAuditLaneBlocker>,
    selection: Option<InboxIndependentAuditorSelectionEvidence>,
    launch: Option<InboxIndependentAuditLaunchEvidence>,
) -> InboxIndependentAuditLaneResult {
    InboxIndependentAuditLaneResult {
        version: INDEPENDENT_AUDIT_LANE_VERSION,
        item_id: item.item_id.clone(),
        source_key: item.source_key.clone(),
        number: item.source_snapshot.number(),
        source_snapshot_digest: item.source_snapshot.digest().to_string(),
        head_oid: head_oid.into(),
        status: InboxIndependentAuditLaneStatus::Blocked,
        success: false,
        selection,
        launch,
        auditor_evidence: None,
        blockers,
        grants_merge_permission: false,
        auto_merge_performed: false,
        next_action:
            "repair the typed independent-audit blockers and rerun against a fresh PR head; do not merge"
                .to_string(),
    }
}

pub fn accepted_independent_audit_lane_result(
    item: &InboxItem,
    selection: InboxIndependentAuditorSelectionEvidence,
    launch: InboxIndependentAuditLaunchEvidence,
    auditor_evidence: PullRequestAuditorEvidence,
) -> InboxIndependentAuditLaneResult {
    InboxIndependentAuditLaneResult {
        version: INDEPENDENT_AUDIT_LANE_VERSION,
        item_id: item.item_id.clone(),
        source_key: item.source_key.clone(),
        number: item.source_snapshot.number(),
        source_snapshot_digest: item.source_snapshot.digest().to_string(),
        head_oid: auditor_evidence.head_oid.clone(),
        status: InboxIndependentAuditLaneStatus::Accepted,
        success: true,
        selection: Some(selection),
        launch: Some(launch),
        auditor_evidence: Some(auditor_evidence),
        blockers: Vec::new(),
        grants_merge_permission: false,
        auto_merge_performed: false,
        next_action:
            "submit this authenticated candidate/head-bound audit evidence to the separate merge executor; this lane did not merge"
                .to_string(),
    }
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

    #[test]
    fn critical_independent_auditor_selection_records_profile_and_score() {
        let available = ["gpt-5.6-sol".to_string(), "gpt-5.6-luna".to_string()]
            .into_iter()
            .collect();
        let decision =
            select_critical_independent_auditor(&available).expect("critical auditor selection");
        let evidence =
            compact_independent_auditor_selection(&decision).expect("selected auditor evidence");

        assert_eq!(decision.status, DecisionStatus::Selected);
        assert_eq!(evidence.runtime, "codex");
        assert_eq!(evidence.model, "gpt-5.6-sol");
        assert_eq!(evidence.effort, ReasoningEffort::Xhigh);
        assert!(!evidence.objective_profile_id.is_empty());
        assert!(!evidence.objective_profile_sha256.is_empty());
        assert!(!evidence.selector_input_sha256.is_empty());

        let unavailable = select_critical_independent_auditor(&BTreeSet::new())
            .expect("fail-closed selection decision");
        assert_eq!(unavailable.status, DecisionStatus::FailClosed);
        assert!(compact_independent_auditor_selection(&unavailable).is_err());
    }

    #[test]
    fn strict_auditor_output_is_head_bound_and_requires_two_accepted_lenses() {
        let mut item = ready_pr_item();
        item.pull_request.as_mut().expect("PR").changed_files =
            vec![std::path::PathBuf::from("src/inbox.rs")];
        let intake = crate::inbox::pr_intake_report_for_item(&item).expect("clean PR intake");
        let task = intake.task.expect("source-bound audit task");
        let auditor = independent_auditor_actor("audit-session", "gpt-5.6-sol");
        let output = InboxIndependentAuditorOutput {
            version: 1,
            item_id: item.item_id.clone(),
            source_snapshot_digest: task.source_snapshot_digest.clone(),
            head_oid: task.head_oid.clone(),
            accepted: true,
            lenses: vec![
                LensVerdict {
                    lens_id: "diff".to_string(),
                    model_label: "gpt-5.6-sol/diff".to_string(),
                    framing: "adversarial-diff".to_string(),
                    information_scope: "diff-only".to_string(),
                    decision: LensDecision::Accept,
                },
                LensVerdict {
                    lens_id: "tests".to_string(),
                    model_label: "gpt-5.6-sol/tests".to_string(),
                    framing: "tests-as-contract".to_string(),
                    information_scope: "tests-only".to_string(),
                    decision: LensDecision::Accept,
                },
            ],
            summary: "accepted exact candidate".to_string(),
            no_further_delegation: true,
            read_only: true,
        };
        let evidence = validate_independent_auditor_output(output.clone(), &item, &task, auditor)
            .expect("accepted head-bound evidence");
        assert_eq!(evidence.head_oid, task.head_oid);
        assert_eq!(evidence.lenses.len(), 2);

        let mut stale = output;
        stale.head_oid = "f".repeat(40);
        assert!(matches!(
            validate_independent_auditor_output(
                stale,
                &item,
                &task,
                independent_auditor_actor("audit-session", "gpt-5.6-sol")
            ),
            Err(InboxIndependentAuditLaneBlocker::AuditEvidenceMismatch { field })
                if field == "head_oid"
        ));
    }

    #[test]
    fn draft_fork_and_untrusted_candidates_fail_closed_before_selection() {
        let mut item = ready_pr_item();
        let pull_request = item.pull_request.as_mut().expect("PR");
        pull_request.changed_files = vec![std::path::PathBuf::from("src/inbox.rs")];
        let intake = crate::inbox::pr_intake_report_for_item(&item).expect("clean PR intake");
        let task = intake.task.expect("audit task");

        item.pull_request.as_mut().expect("PR").is_draft = true;
        assert!(independent_audit_task_blockers(&item, &task)
            .iter()
            .any(|blocker| matches!(blocker, InboxIndependentAuditLaneBlocker::DraftPullRequest)));
        item.pull_request.as_mut().expect("PR").is_draft = false;
        item.pull_request.as_mut().expect("PR").source_trust = GithubPrSourceTrust::Fork;
        assert!(independent_audit_task_blockers(&item, &task)
            .iter()
            .any(|blocker| matches!(blocker, InboxIndependentAuditLaneBlocker::ForkSource)));
        item.pull_request.as_mut().expect("PR").source_trust = GithubPrSourceTrust::Untrusted;
        assert!(independent_audit_task_blockers(&item, &task)
            .iter()
            .any(|blocker| matches!(blocker, InboxIndependentAuditLaneBlocker::UntrustedSource)));
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
                is_draft: false,
                source_trust: GithubPrSourceTrust::TrustedTargetRepository,
                head_repository: Some("fake/maco/inbox".to_string()),
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
