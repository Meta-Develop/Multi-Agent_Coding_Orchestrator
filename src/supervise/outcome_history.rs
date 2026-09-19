//! Parent-owned attempt evidence and a frozen, authenticated selector history.
//! The artifact store supplies the only authenticity boundary. A digest here is
//! replay provenance, not an independent signature or a source of authority.

use super::environment_observation::{
    environment_cost_microunits_from_account_observe, AccountObserveOutcomeKind,
};
use super::*;
use crate::external_agent::{
    CodexParentEvidence, CodexParentResolutionStatus, CodexParentTurnUsage, ExternalAgentRun,
};
use crate::llm::provider::ModelPricing;
use crate::runtime_adapter::grok::{
    GrokAcpNativeCostEquivalent, GrokAcpParentEvidence, GrokAcpParentResolvedField,
};
use crate::selection::{
    CandidateKey, FailureClass, OutcomeRecord, OutcomeResult, ReasoningEffort, RuntimeCatalog,
    TaskProfile,
};
use std::collections::BTreeMap;
use std::sync::Mutex;

const ATTEMPT_EVIDENCE_VERSION: u32 = 1;
const ATTEMPT_EVIDENCE_DIR: &str = "selection-attempts";
const DATED_PLAN_COST_MICROUNITS_PER_USD: f64 = 100_000.0;
const DATED_PLAN_TOKENS_PER_MILLION: f64 = 1_000_000.0;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AttemptSelectionBinding {
    pub role: AgentRole,
    pub event_assignment_id: Option<String>,
    pub event_attempt: usize,
    pub normalized_input_sha256: String,
    pub task: TaskProfile,
    pub requested_candidate: CandidateKey,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::supervise) struct AttemptAttributableCosts {
    pub execution_cost_microunits: Option<u64>,
    pub review_cost_microunits: Option<u64>,
    pub rework_cost_microunits: Option<u64>,
    pub rereview_cost_microunits: Option<u64>,
    pub environment_cost_microunits: Option<u64>,
}

impl AttemptAttributableCosts {
    pub(in crate::supervise) fn complete(&self) -> Option<[u64; 5]> {
        Some([
            self.execution_cost_microunits?,
            self.review_cost_microunits?,
            self.rework_cost_microunits?,
            self.rereview_cost_microunits?,
            self.environment_cost_microunits?,
        ])
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AttemptOutcomeEvidence {
    pub version: u32,
    pub run_id: String,
    pub assignment_id: String,
    pub attempt: usize,
    pub verified_execution: bool,
    pub selection: Option<AttemptSelectionBinding>,
    pub requested_runtime: String,
    pub requested_model: Option<String>,
    pub requested_effort: Option<String>,
    /// A configured launch is a request. Only provider/session evidence may set
    /// this field; current supervisor telemetry cannot resolve it.
    pub observed_candidate: Option<CandidateKey>,
    /// A retry is a parent decision. Terminal acceptance is established from
    /// the authenticated final assignment report when history is loaded.
    pub parent_result: Option<OutcomeResult>,
    pub parent_cause: Option<String>,
    pub failure_class: Option<FailureClass>,
    pub costs: AttemptAttributableCosts,
    /// Parent-owned continuation proof for review-cycle attribution across gate
    /// retries. Absent on legacy rows and when the parent cannot reconstruct
    /// earlier dispatched review cycles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_phase_continuation: Option<AttemptParentPhaseContinuation>,
}

/// Authenticated parent control-flow proof carried on attempt evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AttemptParentPhaseContinuation {
    pub prior_dispatched_review_cycles: ParentPriorDispatchedReviewCycleProof,
}

/// Whether the parent can prove how many review cycles actually dispatched before
/// this worker attempt began.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub(super) enum ParentPriorDispatchedReviewCycleProof {
    KnownNone,
    KnownPrior {
        completed_dispatched_review_cycles: usize,
    },
    Unknown,
}

impl<'de> Deserialize<'de> for AttemptParentPhaseContinuation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Current {
            prior_dispatched_review_cycles: ParentPriorDispatchedReviewCycleProof,
        }
        #[derive(Deserialize)]
        struct Legacy {
            completed_dispatched_review_cycles: usize,
        }
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Helper {
            Current(Current),
            Legacy(Legacy),
        }
        match Helper::deserialize(deserializer)? {
            Helper::Current(current) => Ok(Self {
                prior_dispatched_review_cycles: current.prior_dispatched_review_cycles,
            }),
            Helper::Legacy(legacy) => Ok(Self {
                prior_dispatched_review_cycles: if legacy.completed_dispatched_review_cycles == 0 {
                    ParentPriorDispatchedReviewCycleProof::KnownNone
                } else {
                    ParentPriorDispatchedReviewCycleProof::KnownPrior {
                        completed_dispatched_review_cycles: legacy
                            .completed_dispatched_review_cycles,
                    }
                },
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ParentDispatchedReviewCycleSlot {
    FirstCycle,
    SubsequentCycle,
    Unknown,
}

/// True when the attempt is nonpublishable simulation or deterministic fake
/// runtime, the collected run has no verified external child process tree, and
/// parent-observed Grok ACP or Codex spend is absent (environment-native spend
/// unproven).
pub(super) fn worker_attempt_proven_no_environment_native_spend(
    execution_runtime: SupervisorExecutionRuntime,
    requested_runtime: &str,
    external_run: Option<&ExternalAgentRun>,
    environment_cost_microunits: Option<u64>,
) -> bool {
    if environment_cost_microunits.is_some() {
        return false;
    }
    if execution_runtime != SupervisorExecutionRuntime::NonpublishableSimulation
        && requested_runtime != "fake"
    {
        return false;
    }
    match external_run {
        None => requested_runtime == "fake",
        Some(run) => {
            if run.grok_acp_parent_evidence.is_some() || run.codex_parent_evidence.is_some() {
                return false;
            }
            run.process_tree.is_none()
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn record_child_attempt_outcome(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    run_id: &RunId,
    assignment_id: &str,
    attempt: usize,
    role: AgentRole,
    events: &[SupervisorSelectionEvent],
    initial_events: &[SupervisorSelectionEvent],
    requested_runtime: &str,
    requested_model: Option<&str>,
    requested_effort: Option<&str>,
    verified_execution: bool,
    retried: bool,
    execution_runtime: SupervisorExecutionRuntime,
    external_run: Option<&ExternalAgentRun>,
    dated_plan_pricing: &BTreeMap<String, ModelPricing>,
    parent_phase_continuation: Option<AttemptParentPhaseContinuation>,
) -> Result<AttemptOutcomeEvidence> {
    record_child_attempt_outcome_with_account_observe(
        artifacts,
        run_id,
        assignment_id,
        attempt,
        role,
        events,
        initial_events,
        requested_runtime,
        requested_model,
        requested_effort,
        verified_execution,
        retried,
        execution_runtime,
        external_run,
        dated_plan_pricing,
        parent_phase_continuation,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn record_child_attempt_outcome_with_account_observe(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    run_id: &RunId,
    assignment_id: &str,
    attempt: usize,
    role: AgentRole,
    events: &[SupervisorSelectionEvent],
    initial_events: &[SupervisorSelectionEvent],
    requested_runtime: &str,
    requested_model: Option<&str>,
    requested_effort: Option<&str>,
    verified_execution: bool,
    retried: bool,
    execution_runtime: SupervisorExecutionRuntime,
    external_run: Option<&ExternalAgentRun>,
    dated_plan_pricing: &BTreeMap<String, ModelPricing>,
    parent_phase_continuation: Option<AttemptParentPhaseContinuation>,
    account_observe: Option<(AccountObserveOutcomeKind, Option<u64>)>,
) -> Result<AttemptOutcomeEvidence> {
    let selection =
        selection_binding_for_attempt(role, assignment_id, attempt, events, initial_events);
    let frozen_catalogs =
        selection_event_for_attempt(role, assignment_id, attempt, events, initial_events)
            .map(|event| event.provenance.normalized_input.catalogs.as_slice());
    let (observed_candidate, worker_observed_microunits) =
        parent_attempt_observation(external_run, frozen_catalogs, dated_plan_pricing);
    let (execution_cost_microunits, rework_cost_microunits) =
        classify_worker_observed_spend(attempt, worker_observed_microunits);
    let environment_cost_microunits = account_observe.and_then(|(kind, microunits)| {
        environment_cost_microunits_from_account_observe(kind, microunits)
    });
    let mut evidence = AttemptOutcomeEvidence {
        version: ATTEMPT_EVIDENCE_VERSION,
        run_id: run_id.as_str().to_string(),
        assignment_id: assignment_id.to_string(),
        attempt,
        verified_execution,
        selection,
        requested_runtime: requested_runtime.to_string(),
        requested_model: requested_model.map(str::to_string),
        requested_effort: requested_effort.map(str::to_string),
        observed_candidate,
        parent_result: retried.then_some(OutcomeResult::Rejected),
        parent_cause: retried.then(|| "parent_authorized_retry".to_string()),
        failure_class: None,
        costs: AttemptAttributableCosts {
            execution_cost_microunits,
            rework_cost_microunits,
            environment_cost_microunits,
            ..AttemptAttributableCosts::default()
        },
        parent_phase_continuation,
    };
    write_attempt_evidence(artifacts, &evidence)?;
    if worker_attempt_proven_no_environment_native_spend(
        execution_runtime,
        requested_runtime,
        external_run,
        evidence.costs.environment_cost_microunits,
    ) {
        persist_proven_no_environment_attributable_cost(artifacts, &mut evidence)?;
    }
    Ok(evidence)
}

fn classify_worker_observed_spend(
    attempt: usize,
    observed_microunits: Option<u64>,
) -> (Option<u64>, Option<u64>) {
    match attempt {
        1 => (observed_microunits, Some(0)),
        _ => (Some(0), observed_microunits),
    }
}

fn selection_event_for_attempt<'a>(
    role: AgentRole,
    assignment_id: &str,
    attempt: usize,
    events: &'a [SupervisorSelectionEvent],
    initial_events: &'a [SupervisorSelectionEvent],
) -> Option<&'a SupervisorSelectionEvent> {
    events
        .iter()
        .rev()
        .find(|event| {
            event.role == role
                && event.assignment_id.as_deref() == Some(assignment_id)
                && (event.attempt == attempt || attempt == 1 && event.attempt == 0)
        })
        .or_else(|| {
            initial_events.iter().find(|event| {
                event.role == role && event.assignment_id.is_none() && event.attempt == 0
            })
        })
}

fn parent_attempt_observation(
    external_run: Option<&ExternalAgentRun>,
    frozen_catalogs: Option<&[RuntimeCatalog]>,
    dated_plan_pricing: &BTreeMap<String, ModelPricing>,
) -> (Option<CandidateKey>, Option<u64>) {
    let Some(external_run) = external_run else {
        return (None, None);
    };
    match (
        external_run.grok_acp_parent_evidence.as_ref(),
        external_run.codex_parent_evidence.as_ref(),
    ) {
        (Some(_), Some(_)) => (None, None),
        (Some(parent_evidence), None) => {
            let observed_candidate =
                complete_grok_acp_session(parent_evidence).and_then(|(model, effort)| {
                    frozen_catalogs.and_then(|catalogs| {
                        candidate_key_from_admitted_catalogs(catalogs, model, effort)
                    })
                });
            let execution_cost_microunits = attributable_execution_cost_microunits(parent_evidence);
            (observed_candidate, execution_cost_microunits)
        }
        (None, Some(parent_evidence)) => {
            let observed_candidate =
                complete_codex_session(parent_evidence).and_then(|(model, effort)| {
                    frozen_catalogs.and_then(|catalogs| {
                        candidate_key_from_admitted_catalogs(catalogs, model, effort)
                    })
                });
            let execution_cost_microunits =
                attributable_codex_execution_cost_microunits(parent_evidence, dated_plan_pricing);
            (observed_candidate, execution_cost_microunits)
        }
        (None, None) => (None, None),
    }
}

fn complete_codex_session(evidence: &CodexParentEvidence) -> Option<(&str, ReasoningEffort)> {
    if evidence.resolution_status != CodexParentResolutionStatus::Complete.label() {
        return None;
    }
    let model = evidence.observed_model.known()?;
    let effort_label = evidence.observed_effort.known()?;
    let effort = reasoning_effort_from_observed_label(effort_label)?;
    Some((model, effort))
}

fn complete_grok_acp_session(evidence: &GrokAcpParentEvidence) -> Option<(&str, ReasoningEffort)> {
    if evidence.resolution_status != "complete" || evidence.permission_escalation_refused {
        return None;
    }
    let model = resolved_field_known(&evidence.client_resolved_model)?;
    let effort_label = resolved_field_known(&evidence.client_resolved_effort)?;
    let effort = reasoning_effort_from_observed_label(effort_label)?;
    Some((model, effort))
}

fn resolved_field_known(field: &GrokAcpParentResolvedField) -> Option<&str> {
    match field {
        GrokAcpParentResolvedField::Known(value) => Some(value.as_str()),
        GrokAcpParentResolvedField::Unknown => None,
    }
}

fn reasoning_effort_from_observed_label(label: &str) -> Option<ReasoningEffort> {
    Some(match label {
        "minimal" | "low" => ReasoningEffort::Low,
        "medium" => ReasoningEffort::Medium,
        "high" => ReasoningEffort::High,
        "xhigh" => ReasoningEffort::Xhigh,
        "max" => ReasoningEffort::Max,
        "ultra" => ReasoningEffort::Ultra,
        _ => return None,
    })
}

fn candidate_key_from_admitted_catalogs(
    catalogs: &[RuntimeCatalog],
    model: &str,
    effort: ReasoningEffort,
) -> Option<CandidateKey> {
    for catalog in catalogs {
        for listed in &catalog.models {
            if listed.model == model && listed.supported_efforts.contains(&effort) {
                return Some(CandidateKey {
                    runtime: catalog.runtime.clone(),
                    model: model.to_string(),
                    effort,
                });
            }
        }
    }
    None
}

fn attributable_execution_cost_microunits(evidence: &GrokAcpParentEvidence) -> Option<u64> {
    complete_grok_acp_session(evidence)?;
    match &evidence.native_cost_equivalent_microunits {
        GrokAcpNativeCostEquivalent::Known { microunits, .. } => Some(*microunits),
        GrokAcpNativeCostEquivalent::Unknown { .. } => None,
    }
}

fn attributable_codex_execution_cost_microunits(
    evidence: &CodexParentEvidence,
    dated_plan_pricing: &BTreeMap<String, ModelPricing>,
) -> Option<u64> {
    let (model, _) = complete_codex_session(evidence)?;
    let CodexParentTurnUsage::Known {
        input_tokens,
        output_tokens,
        ..
    } = &evidence.turn_usage
    else {
        return None;
    };
    let pricing = dated_plan_pricing.get(model).copied()?;
    if !pricing.is_valid() {
        return None;
    }
    dated_plan_token_cost_microunits(pricing, *input_tokens, *output_tokens)
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn dated_plan_token_cost_microunits(
    pricing: ModelPricing,
    input_tokens: u64,
    output_tokens: u64,
) -> Option<u64> {
    let usd = (input_tokens as f64 * pricing.input_usd_per_million_tokens
        + output_tokens as f64 * pricing.output_usd_per_million_tokens)
        / DATED_PLAN_TOKENS_PER_MILLION;
    if !usd.is_finite() || usd < 0.0 {
        return None;
    }
    let microunits = usd * DATED_PLAN_COST_MICROUNITS_PER_USD;
    if !microunits.is_finite() || microunits < 0.0 {
        return None;
    }
    let rounded = microunits.round();
    if !rounded.is_finite() || rounded < 0.0 || rounded > u64::MAX as f64 {
        return None;
    }
    Some(rounded as u64)
}

fn attributable_parent_auditor_cost_microunits(external_run: &ExternalAgentRun) -> Option<u64> {
    external_run
        .grok_acp_parent_evidence
        .as_ref()
        .and_then(attributable_execution_cost_microunits)
}

/// Parent-owned review dispatch costs for one worker attempt on one assignment.
///
/// A stacked-lens pass is persistable only when every planned lens either
/// executed a parent auditor dispatch or the pass short-circuited before any
/// dispatch (see `parent_review_dispatch_set_is_complete`). Partial stacks after
/// at least one dispatch retain `None` rather than a partial sum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ParentWorkerAttemptReviewCostBinding {
    assignment_id: String,
    worker_attempt: usize,
    review_cycle_slot: ParentDispatchedReviewCycleSlot,
    total_microunits: Option<u64>,
    parent_auditor_invocations: usize,
    planned_lens_count: usize,
    lenses_undispatched_without_run: usize,
    parent_review_stack_short_circuited: bool,
}

impl ParentWorkerAttemptReviewCostBinding {
    pub(super) fn bind(
        assignment_id: &str,
        worker_attempt: usize,
        review_cycle_slot: ParentDispatchedReviewCycleSlot,
    ) -> Self {
        Self {
            assignment_id: assignment_id.to_string(),
            worker_attempt,
            review_cycle_slot,
            total_microunits: None,
            parent_auditor_invocations: 0,
            planned_lens_count: 0,
            lenses_undispatched_without_run: 0,
            parent_review_stack_short_circuited: false,
        }
    }

    pub(super) fn review_cycle_slot(&self) -> ParentDispatchedReviewCycleSlot {
        self.review_cycle_slot
    }

    /// True when at least one parent auditor process actually dispatched in this
    /// stacked review cycle (independent of complete lens telemetry).
    pub(super) fn parent_review_cycle_actually_dispatched(&self) -> bool {
        self.parent_auditor_invocations > 0
    }

    pub(super) fn begin_stacked_parent_review_lenses(&mut self, planned_lens_count: usize) {
        self.planned_lens_count = planned_lens_count;
        self.lenses_undispatched_without_run = 0;
        self.parent_review_stack_short_circuited = false;
    }

    pub(super) fn record_parent_auditor_lens_undispatched(&mut self) {
        self.lenses_undispatched_without_run += 1;
    }

    pub(super) fn mark_parent_review_stack_short_circuited(&mut self) {
        self.parent_review_stack_short_circuited = true;
    }

    pub(super) fn parent_review_dispatch_set_is_complete(&self) -> bool {
        if self.parent_review_stack_short_circuited {
            return false;
        }
        if self.planned_lens_count == 0 {
            return true;
        }
        self.lenses_undispatched_without_run == 0
            && self.parent_auditor_invocations == self.planned_lens_count
    }

    pub(super) fn observe_parent_auditor_external_run(&mut self, external_run: &ExternalAgentRun) {
        self.parent_auditor_invocations += 1;
        let addend = attributable_parent_auditor_cost_microunits(external_run);
        self.total_microunits = match (self.total_microunits, addend) {
            (_, None) => None,
            (None, Some(microunits)) if self.parent_auditor_invocations == 1 => Some(microunits),
            (None, Some(_)) => None,
            (Some(current), Some(microunits)) => current.checked_add(microunits),
        };
    }

    fn persistable_review_phase_cost_microunits(&self) -> Option<Option<u64>> {
        if self.parent_auditor_invocations == 0 {
            return None;
        }
        if self.review_cycle_slot == ParentDispatchedReviewCycleSlot::Unknown {
            return None;
        }
        Some(if self.parent_review_dispatch_set_is_complete() {
            self.total_microunits
        } else {
            None
        })
    }
}

#[cfg(test)]
impl ParentWorkerAttemptReviewCostBinding {
    pub(super) fn review_total_microunits(&self) -> Option<u64> {
        self.total_microunits
    }

    pub(super) fn parent_auditor_invocation_count(&self) -> usize {
        self.parent_auditor_invocations
    }

    pub(super) fn parent_review_dispatch_set_complete_for_test(&self) -> bool {
        self.parent_review_dispatch_set_is_complete()
    }
}

pub(super) fn persist_worker_attempt_review_cost(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    binding: &ParentWorkerAttemptReviewCostBinding,
    attempt_record: &mut AttemptOutcomeEvidence,
) -> Result<()> {
    if attempt_record.assignment_id != binding.assignment_id
        || attempt_record.attempt != binding.worker_attempt
    {
        bail!(
            "review cost binding {}/{} does not match attempt record {}/{}",
            binding.assignment_id,
            binding.worker_attempt,
            attempt_record.assignment_id,
            attempt_record.attempt
        );
    }
    let Some(microunits) = binding.persistable_review_phase_cost_microunits() else {
        return Ok(());
    };
    match binding.review_cycle_slot() {
        ParentDispatchedReviewCycleSlot::FirstCycle => {
            attempt_record.costs.review_cost_microunits = microunits;
            if microunits.is_some() {
                attempt_record.costs.rereview_cost_microunits = Some(0);
            }
        }
        ParentDispatchedReviewCycleSlot::SubsequentCycle => {
            attempt_record.costs.rereview_cost_microunits = microunits;
            if microunits.is_some() {
                attempt_record.costs.review_cost_microunits = Some(0);
            }
        }
        ParentDispatchedReviewCycleSlot::Unknown => {}
    }
    write_attempt_evidence(artifacts, attempt_record)?;
    Ok(())
}

/// Proven zero only when the attempt path cannot incur environment-native spend
/// (no real external launch). Callers must establish that proof separately.
pub(super) fn persist_proven_no_environment_attributable_cost(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    attempt_record: &mut AttemptOutcomeEvidence,
) -> Result<()> {
    if attempt_record.costs.environment_cost_microunits.is_some() {
        return Ok(());
    }
    attempt_record.costs.environment_cost_microunits = Some(0);
    write_attempt_evidence(artifacts, attempt_record)?;
    Ok(())
}

pub(super) fn persist_proven_no_parent_review_cycle_costs(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    attempt_record: &mut AttemptOutcomeEvidence,
) -> Result<()> {
    attempt_record.costs.review_cost_microunits = Some(0);
    attempt_record.costs.rereview_cost_microunits = Some(0);
    write_attempt_evidence(artifacts, attempt_record)?;
    Ok(())
}

pub(super) fn persist_proven_worker_attempt_bypassed_parent_review(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    attempt_record: &mut AttemptOutcomeEvidence,
) -> Result<()> {
    persist_proven_no_parent_review_cycle_costs(artifacts, attempt_record)
}

pub(super) fn prior_dispatched_review_cycle_count(
    proof: &ParentPriorDispatchedReviewCycleProof,
) -> Option<usize> {
    match proof {
        ParentPriorDispatchedReviewCycleProof::KnownNone => Some(0),
        ParentPriorDispatchedReviewCycleProof::KnownPrior {
            completed_dispatched_review_cycles,
        } => Some(*completed_dispatched_review_cycles),
        ParentPriorDispatchedReviewCycleProof::Unknown => None,
    }
}

pub(super) fn attempt_parent_phase_continuation_from_count(
    completed_parent_review_cycles: Option<usize>,
) -> AttemptParentPhaseContinuation {
    AttemptParentPhaseContinuation {
        prior_dispatched_review_cycles: match completed_parent_review_cycles {
            None => ParentPriorDispatchedReviewCycleProof::Unknown,
            Some(0) => ParentPriorDispatchedReviewCycleProof::KnownNone,
            Some(completed_dispatched_review_cycles) => {
                ParentPriorDispatchedReviewCycleProof::KnownPrior {
                    completed_dispatched_review_cycles,
                }
            }
        },
    }
}

pub(super) fn sync_attempt_parent_phase_continuation(
    attempt_record: &mut AttemptOutcomeEvidence,
    completed_parent_review_cycles: Option<usize>,
) {
    attempt_record.parent_phase_continuation = Some(attempt_parent_phase_continuation_from_count(
        completed_parent_review_cycles,
    ));
}

pub(super) fn persist_attempt_parent_phase_continuation(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    attempt_record: &mut AttemptOutcomeEvidence,
    completed_parent_review_cycles: Option<usize>,
) -> Result<()> {
    sync_attempt_parent_phase_continuation(attempt_record, completed_parent_review_cycles);
    write_attempt_evidence(artifacts, attempt_record)?;
    Ok(())
}

pub(super) fn review_cycle_slot_for_completed_dispatched_cycles(
    completed_parent_review_cycles: Option<usize>,
) -> ParentDispatchedReviewCycleSlot {
    match completed_parent_review_cycles {
        Some(0) => ParentDispatchedReviewCycleSlot::FirstCycle,
        Some(_) => ParentDispatchedReviewCycleSlot::SubsequentCycle,
        None => ParentDispatchedReviewCycleSlot::Unknown,
    }
}

#[cfg(test)]
pub(super) fn review_cycle_slot_from_continuation(
    continuation: Option<&AttemptParentPhaseContinuation>,
) -> ParentDispatchedReviewCycleSlot {
    review_cycle_slot_for_completed_dispatched_cycles(continuation.and_then(|proof| {
        prior_dispatched_review_cycle_count(&proof.prior_dispatched_review_cycles)
    }))
}

pub(super) fn authenticated_prior_dispatched_review_cycle_proof(
    repo: &Path,
    source_run_id: &RunId,
    assignment_id: &str,
) -> Result<ParentPriorDispatchedReviewCycleProof> {
    let reader = ArtifactRunReader::open(repo, RunArtifactFamily::Supervise, source_run_id)
        .with_context(|| {
            format!(
                "phase continuation source run '{}' is not authenticated",
                source_run_id.as_str()
            )
        })?;
    let mut latest_attempt = 0usize;
    let mut latest_continuation = None;
    for file in &reader.finalization().files {
        if !file.path.starts_with(ATTEMPT_EVIDENCE_DIR)
            || file.path.extension().and_then(|ext| ext.to_str()) != Some("json")
        {
            continue;
        }
        let name = file
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .with_context(|| {
                format!("attempt evidence path '{}' is invalid", file.path.display())
            })?;
        let (assignment, attempt_label) = name
            .strip_suffix(".json")
            .and_then(|name| name.rsplit_once(".attempt-"))
            .with_context(|| format!("attempt evidence filename '{}' is invalid", name))?;
        if assignment != assignment_id {
            continue;
        }
        let attempt = attempt_label
            .parse::<usize>()
            .with_context(|| format!("attempt evidence ordinal '{}' is invalid", attempt_label))?;
        if attempt <= latest_attempt {
            continue;
        }
        let bytes = reader
            .read(&file.path)
            .with_context(|| format!("attempt evidence '{}' is unreadable", file.path.display()))?;
        let evidence =
            serde_json::from_slice::<AttemptOutcomeEvidence>(&bytes).with_context(|| {
                format!("attempt evidence '{}' is invalid JSON", file.path.display())
            })?;
        if evidence.assignment_id != assignment_id || evidence.attempt != attempt {
            continue;
        }
        latest_attempt = attempt;
        latest_continuation = evidence.parent_phase_continuation;
    }
    if latest_attempt == 0 {
        return Ok(ParentPriorDispatchedReviewCycleProof::Unknown);
    }
    Ok(latest_continuation
        .map(|continuation| continuation.prior_dispatched_review_cycles)
        .unwrap_or(ParentPriorDispatchedReviewCycleProof::Unknown))
}

pub(super) fn advance_completed_parent_review_cycles_after_actual_dispatch(
    completed_parent_review_cycles: &mut Option<usize>,
    binding: &ParentWorkerAttemptReviewCostBinding,
) {
    if binding.parent_review_cycle_actually_dispatched() {
        *completed_parent_review_cycles = Some(completed_parent_review_cycles.unwrap_or(0) + 1);
    }
}

/// Single production seam: persist review/rereview phase costs (partial stacks stay
/// `None`), advance the dispatched-cycle counter only after actual auditor dispatch,
/// and persist authenticated continuation proof.
pub(super) fn finalize_parent_review_cycle_attribution_for_worker_attempt(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    binding: &ParentWorkerAttemptReviewCostBinding,
    attempt_record: &mut AttemptOutcomeEvidence,
    completed_parent_review_cycles: &mut Option<usize>,
) -> Result<()> {
    persist_worker_attempt_review_cost(artifacts, binding, attempt_record)?;
    advance_completed_parent_review_cycles_after_actual_dispatch(
        completed_parent_review_cycles,
        binding,
    );
    if binding.parent_review_cycle_actually_dispatched() {
        persist_attempt_parent_phase_continuation(
            artifacts,
            attempt_record,
            *completed_parent_review_cycles,
        )?;
    }
    Ok(())
}

pub(super) fn persist_review_cycle_attribution_or_chain_primary(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    binding: &ParentWorkerAttemptReviewCostBinding,
    attempt_record: &mut AttemptOutcomeEvidence,
    completed_parent_review_cycles: &mut Option<usize>,
    primary_error: Option<anyhow::Error>,
) -> Result<()> {
    match finalize_parent_review_cycle_attribution_for_worker_attempt(
        artifacts,
        binding,
        attempt_record,
        completed_parent_review_cycles,
    ) {
        Ok(()) => {
            if let Some(primary_error) = primary_error {
                return Err(primary_error);
            }
            Ok(())
        }
        Err(finalize_error) => {
            if let Some(primary_error) = primary_error {
                return Err(primary_error).context(format!(
                    "review cycle attribution persistence failed: {finalize_error:#}"
                ));
            }
            Err(finalize_error)
        }
    }
}

fn selection_binding_for_attempt(
    role: AgentRole,
    assignment_id: &str,
    attempt: usize,
    events: &[SupervisorSelectionEvent],
    initial_events: &[SupervisorSelectionEvent],
) -> Option<AttemptSelectionBinding> {
    selection_event_for_attempt(role, assignment_id, attempt, events, initial_events).and_then(
        |event| {
            let choice = event.provenance.choice.as_ref()?;
            Some(AttemptSelectionBinding {
                role,
                event_assignment_id: event.assignment_id.clone(),
                event_attempt: event.attempt,
                normalized_input_sha256: event
                    .provenance
                    .input_digests
                    .normalized_input
                    .value
                    .clone(),
                task: event.provenance.normalized_task.clone(),
                requested_candidate: choice.candidate.clone(),
            })
        },
    )
}

fn write_attempt_evidence(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    evidence: &AttemptOutcomeEvidence,
) -> Result<()> {
    let relative = PathBuf::from(ATTEMPT_EVIDENCE_DIR).join(format!(
        "{}.attempt-{}.json",
        evidence.assignment_id, evidence.attempt
    ));
    with_supervisor_artifacts(artifacts, |writer, _| {
        writer.write_json(
            &relative,
            evidence,
            ArtifactFileDisposition::PrivateEvidence,
        )?;
        Ok(())
    })
}

pub(super) fn record_parent_auditor_retry(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    original: &AttemptOutcomeEvidence,
) -> Result<()> {
    let mut rejected = original.clone();
    rejected.parent_result = Some(OutcomeResult::Rejected);
    rejected.parent_cause = Some("parent_auditor_authorized_retry".to_string());
    write_attempt_evidence(artifacts, &rejected)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FrozenOutcomeHistory {
    pub provenance: crate::selection::AuthenticatedOutcomeHistoryProvenance,
    rows: Vec<OutcomeRecord>,
}

impl FrozenOutcomeHistory {
    pub fn outcomes_for(&self, task: &TaskProfile) -> Vec<OutcomeRecord> {
        self.rows
            .iter()
            .filter(|row| &row.task == task)
            .cloned()
            .collect()
    }
}

pub(super) fn load_frozen_outcome_history(
    repo: &Path,
    current_run: &RunId,
) -> Result<FrozenOutcomeHistory> {
    let mut sources = Vec::new();
    let mut exclusions = Vec::new();
    let mut candidates: BTreeMap<(String, String, usize), Vec<Option<OutcomeRecord>>> =
        BTreeMap::new();
    for summary in crate::artifacts::list_runs(repo, RunArtifactFamily::Supervise)?.runs {
        if summary.run_id == current_run.as_str() {
            continue;
        }
        let Ok(run_id) = RunId::new(&summary.run_id) else {
            exclusions.push(format!("{}:invalid_run_id", summary.run_id));
            continue;
        };
        let Ok(reader) = ArtifactRunReader::open(repo, RunArtifactFamily::Supervise, &run_id)
        else {
            exclusions.push(format!("{}:unfinalized_or_unauthenticated", summary.run_id));
            continue;
        };
        let final_relative = RunArtifactFamily::Supervise.final_report_relative_path();
        let Ok(final_bytes) = reader.read(&final_relative) else {
            exclusions.push(format!("{}:missing_final_report", summary.run_id));
            continue;
        };
        let Ok(report) = serde_json::from_slice::<SupervisorFinalReport>(&final_bytes) else {
            exclusions.push(format!("{}:invalid_final_report", summary.run_id));
            continue;
        };
        if report.run_id != run_id
            || report.repo != Path::new(".")
            || report.run_dir
                != RunArtifactFamily::Supervise
                    .run_root()
                    .join(run_id.as_str())
            || report.run_lifecycle != SupervisorRunLifecycle::Finalized
            || report.runtime == SupervisorRuntime::Fake
            || report.evidence_only_reaudit.is_some()
        {
            exclusions.push(format!("{}:invalid_or_simulation_source", summary.run_id));
            continue;
        }
        let final_sha = crate::artifacts::state_auth::sha256_hex(&final_bytes);
        let mut last_attempt_by_assignment = BTreeMap::<String, usize>::new();
        let mut manifest_attempt_counts = BTreeMap::<(String, String, usize), usize>::new();
        for file in &reader.finalization().files {
            if !file.path.starts_with(ATTEMPT_EVIDENCE_DIR)
                || file
                    .path
                    .extension()
                    .and_then(|extension| extension.to_str())
                    != Some("json")
            {
                continue;
            }
            if let Ok(bytes) = reader.read(&file.path) {
                if let Ok(attempt) = serde_json::from_slice::<AttemptOutcomeEvidence>(&bytes) {
                    if attempt.run_id == run_id.as_str() && attempt.attempt > 0 {
                        *manifest_attempt_counts
                            .entry((attempt.run_id, attempt.assignment_id, attempt.attempt))
                            .or_default() += 1;
                    }
                }
            }
            let Some(name) = file.path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let Some((assignment, ordinal)) = name
                .strip_suffix(".json")
                .and_then(|name| name.rsplit_once(".attempt-"))
            else {
                continue;
            };
            if let Ok(ordinal) = ordinal.parse::<usize>() {
                last_attempt_by_assignment
                    .entry(assignment.to_string())
                    .and_modify(|last| *last = (*last).max(ordinal))
                    .or_insert(ordinal);
            }
        }
        for file in &reader.finalization().files {
            if !file.path.starts_with(ATTEMPT_EVIDENCE_DIR)
                || file.path.extension().and_then(|s| s.to_str()) != Some("json")
            {
                continue;
            }
            let source = format!(
                "{}:{}:{}:{}",
                run_id.as_str(),
                file.path.display(),
                final_sha,
                file.sha256
            );
            let Ok(bytes) = reader.read(&file.path) else {
                exclusions.push(format!("{}:unreadable_attempt", source));
                continue;
            };
            let Ok(mut row) = serde_json::from_slice::<AttemptOutcomeEvidence>(&bytes) else {
                exclusions.push(format!("{}:invalid_attempt", source));
                continue;
            };
            if row.version != ATTEMPT_EVIDENCE_VERSION
                || row.run_id != run_id.as_str()
                || row.attempt == 0
            {
                exclusions.push(format!("{}:invalid_attempt_binding", source));
                continue;
            }
            if manifest_attempt_counts
                .get(&(row.run_id.clone(), row.assignment_id.clone(), row.attempt))
                .copied()
                .unwrap_or(0)
                != 1
            {
                exclusions.push(format!("{}:duplicate_attempt", source));
                continue;
            }
            if !row.verified_execution {
                exclusions.push(format!("{}:synthetic_execution", source));
                continue;
            }
            let expected_path = PathBuf::from(ATTEMPT_EVIDENCE_DIR).join(format!(
                "{}.attempt-{}.json",
                row.assignment_id, row.attempt
            ));
            if file.path != expected_path {
                exclusions.push(format!("{}:path_binding_mismatch", source));
                continue;
            }
            let Some(binding) = row.selection.as_ref() else {
                exclusions.push(format!("{}:missing_selection", source));
                continue;
            };
            let matching_event_count = report
                .role_economics_profile
                .as_ref()
                .and_then(|profile| profile.execution.as_ref())
                .into_iter()
                .flat_map(|execution| &execution.selection_decisions)
                .filter(|event| {
                    event.role == binding.role
                        && event.assignment_id == binding.event_assignment_id
                        && event.attempt == binding.event_attempt
                        && event.provenance.input_digests.normalized_input.value
                            == binding.normalized_input_sha256
                        && event.provenance.normalized_task == binding.task
                        && event
                            .provenance
                            .choice
                            .as_ref()
                            .map(|choice| &choice.candidate)
                            == Some(&binding.requested_candidate)
                })
                .count();
            if matching_event_count != 1
                || !(binding.event_attempt == 0 && binding.event_assignment_id.is_none()
                    || row.attempt == 1
                        && binding.event_attempt == 0
                        && binding.event_assignment_id.as_deref()
                            == Some(row.assignment_id.as_str())
                    || binding.event_attempt == row.attempt
                        && binding.event_assignment_id.as_deref()
                            == Some(row.assignment_id.as_str()))
            {
                exclusions.push(format!("{}:selection_binding_mismatch", source));
                continue;
            }
            let final_assignments = report
                .orchestrator_reports
                .iter()
                .filter(|item| item.id == row.assignment_id)
                .collect::<Vec<_>>();
            if final_assignments.len() > 1
                || final_assignments
                    .first()
                    .is_some_and(|item| item.role != binding.role)
                || (row.parent_result.is_some()
                    && (row.parent_result != Some(OutcomeResult::Rejected)
                        || !matches!(
                            row.parent_cause.as_deref(),
                            Some("parent_authorized_retry" | "parent_auditor_authorized_retry")
                        )))
            {
                exclusions.push(format!("{}:ambiguous_or_unreviewed_result", source));
                continue;
            }
            if row.parent_result.is_none() {
                if last_attempt_by_assignment.get(&row.assignment_id) != Some(&row.attempt) {
                    exclusions.push(format!("{}:superseded_attempt", source));
                    continue;
                }
                row.parent_result = final_assignments.first().and_then(|item| {
                    if item.accepted && !item.rejected {
                        Some(OutcomeResult::Accepted)
                    } else if item.rejected && !item.accepted {
                        Some(OutcomeResult::Rejected)
                    } else {
                        None
                    }
                });
                row.parent_cause = row
                    .parent_result
                    .map(|_| "final_parent_assignment_review".to_string());
            }
            sources.push(source.clone());
            let key = (row.run_id.clone(), row.assignment_id.clone(), row.attempt);
            let projected = project_numeric_row(&row);
            if projected.is_none() {
                exclusions.push(format!("{}:unknown_or_ineligible_numeric_evidence", source));
            }
            candidates.entry(key).or_default().push(projected);
        }
    }
    let mut rows = Vec::new();
    for (key, mut group) in candidates {
        if group.len() == 1 {
            if let Some(row) = group.remove(0) {
                rows.push(row);
            }
        } else {
            exclusions.push(format!("{}:{}:{}:duplicate_attempt", key.0, key.1, key.2));
        }
    }
    rows.sort_by(|a, b| a.attempt_id.cmp(&b.attempt_id));
    sources.sort();
    exclusions.sort();
    let snapshot_bytes =
        serde_json::to_vec(&(sources.as_slice(), exclusions.as_slice(), rows.as_slice()))?;
    Ok(FrozenOutcomeHistory {
        provenance: crate::selection::AuthenticatedOutcomeHistoryProvenance {
            snapshot_sha256: crate::artifacts::state_auth::sha256_hex(&snapshot_bytes),
            source_digests: sources,
            exclusions,
            projected_attempt_count: rows.len(),
        },
        rows,
    })
}

fn project_numeric_row(row: &AttemptOutcomeEvidence) -> Option<OutcomeRecord> {
    let binding = row.selection.as_ref()?;
    let observed = row.observed_candidate.as_ref()?;
    if observed != &binding.requested_candidate {
        return None;
    }
    let requested_effort = match binding.requested_candidate.effort {
        crate::selection::ReasoningEffort::Low => "low",
        crate::selection::ReasoningEffort::Medium => "medium",
        crate::selection::ReasoningEffort::High => "high",
        crate::selection::ReasoningEffort::Xhigh => "xhigh",
        crate::selection::ReasoningEffort::Max => "max",
        crate::selection::ReasoningEffort::Ultra => "ultra",
    };
    if row.requested_runtime != binding.requested_candidate.runtime
        || row.requested_model.as_deref() != Some(binding.requested_candidate.model.as_str())
        || row.requested_effort.as_deref() != Some(requested_effort)
    {
        return None;
    }
    let result = row.parent_result?;
    let [execution, review, rework, rereview, environment] = row.costs.complete()?;
    let attempt_id = format!("{}:{}:{}", row.run_id, row.assignment_id, row.attempt);
    Some(OutcomeRecord {
        attempt_id,
        task: binding.task.clone(),
        candidate: observed.clone(),
        result,
        failure_class: row.failure_class,
        execution_cost_microunits: execution,
        review_cost_microunits: review,
        rework_cost_microunits: rework,
        rereview_cost_microunits: rereview,
        environment_cost_microunits: environment,
        environment_failures: Vec::new(),
        fixed_cause_relaunch: None,
    })
}

#[cfg(test)]
pub(super) fn test_trusted_grok_parent_auditor_external_run(
    command: &crate::external_agent::ExternalAgentCommand,
    microunits: u64,
    cost_usd_ticks: u64,
) -> ExternalAgentRun {
    let mut external_run = super::tests::injected_verified_run(command);
    external_run.grok_acp_parent_evidence = Some(GrokAcpParentEvidence {
        protocol: "grok_acp_stdio".to_string(),
        session_id: "trusted-parent-auditor-session".to_string(),
        requested_model: None,
        requested_effort: None,
        client_resolved_model: GrokAcpParentResolvedField::Known("grok-code-fast-1".to_string()),
        client_resolved_effort: GrokAcpParentResolvedField::Known("high".to_string()),
        resolution_status: "complete".to_string(),
        terminal_usage: None,
        native_cost_equivalent_microunits: GrokAcpNativeCostEquivalent::Known {
            cost_usd_ticks,
            microunits,
        },
        permission_escalation_refused: false,
        structured_output: None,
        structured_output_error: None,
        final_text: None,
        stop_reason: None,
    });
    external_run
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::external_agent::{
        CodexParentEvidence, CodexParentResolvedField, CodexParentTurnUsage,
        CodexServerRerouteEvidence,
    };
    use crate::selection::{
        AuthorityRole, Boundedness, ContextSize, ReasoningEffort, RiskLevel, TaskHorizon,
    };

    fn fixture() -> AttemptOutcomeEvidence {
        let candidate = CandidateKey {
            runtime: "codex".to_string(),
            model: "fixture-model".to_string(),
            effort: ReasoningEffort::High,
        };
        AttemptOutcomeEvidence {
            version: ATTEMPT_EVIDENCE_VERSION,
            run_id: "run-1".to_string(),
            assignment_id: "assignment-1".to_string(),
            attempt: 1,
            verified_execution: true,
            selection: Some(AttemptSelectionBinding {
                role: AgentRole::Worker,
                event_assignment_id: None,
                event_attempt: 0,
                normalized_input_sha256: "fixture-digest".to_string(),
                task: TaskProfile {
                    task_class: "localized_code_change".to_string(),
                    risk: RiskLevel::Medium,
                    boundedness: Boundedness::Bounded,
                    context: ContextSize::Medium,
                    horizon: TaskHorizon::Medium,
                    authority_role: AuthorityRole::TerminalLeaf,
                },
                requested_candidate: candidate.clone(),
            }),
            requested_runtime: "codex".to_string(),
            requested_model: Some("fixture-model".to_string()),
            requested_effort: Some("high".to_string()),
            observed_candidate: Some(candidate),
            parent_result: Some(OutcomeResult::Accepted),
            parent_cause: Some("final_parent_assignment_review".to_string()),
            failure_class: None,
            costs: AttemptAttributableCosts {
                execution_cost_microunits: Some(5),
                review_cost_microunits: Some(2),
                rework_cost_microunits: Some(0),
                rereview_cost_microunits: Some(0),
                environment_cost_microunits: Some(0),
            },
            parent_phase_continuation: None,
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum AuthenticatedFixtureMode {
        Initial,
        DebugOverride,
        AssignmentDegrade,
        AuditorRetry,
    }

    fn write_authenticated_fixture(
        repo: &Path,
        run_name: &str,
        accepted: bool,
        duplicate: bool,
        synthetic: bool,
        foreign_report: bool,
        mode: AuthenticatedFixtureMode,
    ) -> Result<()> {
        let run_id = RunId::new(run_name)?;
        let decision = crate::selection::select(&crate::selection::selection_test_base_input())?;
        let selected = decision
            .choice
            .as_ref()
            .context("fixture selector choice")?;
        let mut evidence = fixture();
        evidence.run_id = run_name.to_string();
        evidence.verified_execution = !synthetic;
        evidence.selection = Some(AttemptSelectionBinding {
            role: AgentRole::Worker,
            event_assignment_id: None,
            event_attempt: 0,
            normalized_input_sha256: decision.input_digests.normalized_input.value.clone(),
            task: decision.normalized_task.clone(),
            requested_candidate: selected.candidate.clone(),
        });
        evidence.requested_runtime = selected.candidate.runtime.clone();
        evidence.requested_model = Some(selected.candidate.model.clone());
        evidence.requested_effort = Some(
            match selected.candidate.effort {
                ReasoningEffort::Low => "low",
                ReasoningEffort::Medium => "medium",
                ReasoningEffort::High => "high",
                ReasoningEffort::Xhigh => "xhigh",
                ReasoningEffort::Max => "max",
                ReasoningEffort::Ultra => "ultra",
            }
            .to_string(),
        );
        evidence.observed_candidate = Some(selected.candidate.clone());
        evidence.parent_result = None;
        evidence.parent_cause = None;
        let mut profile: RoleEconomicsProfile = serde_json::from_str(include_str!(
            "../../tests/fixtures/supervise/supervisor-final-economics-v4.json"
        ))?;
        let initial_event = SupervisorSelectionEvent {
            assignment_id: (mode == AuthenticatedFixtureMode::AssignmentDegrade)
                .then(|| "assignment-1".to_string()),
            attempt: 0,
            role: AgentRole::Worker,
            primary_cause: match mode {
                AuthenticatedFixtureMode::Initial | AuthenticatedFixtureMode::AuditorRetry => {
                    SupervisorSelectionEventCause::Initial
                }
                AuthenticatedFixtureMode::DebugOverride => {
                    SupervisorSelectionEventCause::DebugOverride
                }
                AuthenticatedFixtureMode::AssignmentDegrade => {
                    SupervisorSelectionEventCause::BudgetDegrade
                }
            },
            provenance: decision,
        };
        evidence.selection = selection_binding_for_attempt(
            AgentRole::Worker,
            "assignment-1",
            1,
            if mode == AuthenticatedFixtureMode::AssignmentDegrade {
                std::slice::from_ref(&initial_event)
            } else {
                &[]
            },
            std::slice::from_ref(&initial_event),
        );
        profile
            .execution
            .as_mut()
            .context("fixture execution")?
            .selection_decisions = vec![initial_event];
        if mode == AuthenticatedFixtureMode::AuditorRetry {
            let execution = profile.execution.as_mut().context("fixture execution")?;
            let mut retry_event = execution.selection_decisions[0].clone();
            retry_event.assignment_id = Some("assignment-1".to_string());
            retry_event.attempt = 2;
            retry_event.primary_cause = SupervisorSelectionEventCause::Retry;
            execution.selection_decisions.push(retry_event);
        }
        let mut assignment: OrchestratorReviewReport = serde_json::from_str(
            &super::super::tests::sample_child_report_json("assignment-1"),
        )?;
        assignment.role = AgentRole::Worker;
        assignment.accepted = accepted;
        assignment.rejected = !accepted;
        assignment.status = if accepted {
            ReviewStatus::Succeeded
        } else {
            ReviewStatus::Failed
        };
        let mut report = super::super::tests::artifact_test_final_report(&run_id);
        report.runtime = SupervisorRuntime::Codex;
        report.publishable = accepted;
        report.success = accepted;
        report.accepted = accepted;
        report.rejected = !accepted;
        report.status = assignment.status;
        report.role_economics_profile = Some(profile);
        report.orchestrator_reports = vec![assignment];
        if foreign_report {
            report.repo = PathBuf::from("foreign-repository");
        }
        let mut writer = ArtifactRunWriter::reserve(
            repo,
            RunArtifactFamily::Supervise,
            run_id,
            "maco-supervise",
        )?;
        if mode == AuthenticatedFixtureMode::AuditorRetry {
            evidence.parent_result = Some(OutcomeResult::Rejected);
            evidence.parent_cause = Some("parent_auditor_authorized_retry".to_string());
        }
        writer.write_json(
            Path::new("selection-attempts/assignment-1.attempt-1.json"),
            &evidence,
            ArtifactFileDisposition::PrivateEvidence,
        )?;
        if mode == AuthenticatedFixtureMode::AuditorRetry {
            let mut second = evidence.clone();
            second.attempt = 2;
            second.selection = selection_binding_for_attempt(
                AgentRole::Worker,
                "assignment-1",
                2,
                &report
                    .role_economics_profile
                    .as_ref()
                    .and_then(|profile| profile.execution.as_ref())
                    .context("fixture execution")?
                    .selection_decisions,
                &[],
            );
            second.parent_result = None;
            second.parent_cause = None;
            writer.write_json(
                Path::new("selection-attempts/assignment-1.attempt-2.json"),
                &second,
                ArtifactFileDisposition::PrivateEvidence,
            )?;
        }
        if duplicate {
            writer.write_json(
                Path::new("selection-attempts/duplicate.json"),
                &evidence,
                ArtifactFileDisposition::PrivateEvidence,
            )?;
        }
        let final_relative = RunArtifactFamily::Supervise.final_report_relative_path();
        writer.write_json(
            &final_relative,
            &report,
            ArtifactFileDisposition::Publishable,
        )?;
        writer.finalize(&final_relative, false)?;
        Ok(())
    }

    #[test]
    fn authenticated_accepted_and_rejected_attempts_project_and_freeze() -> Result<()> {
        let (_temp, repo) = super::super::tests::injected_repository();
        write_authenticated_fixture(
            &repo,
            "accepted-history",
            true,
            false,
            false,
            false,
            AuthenticatedFixtureMode::Initial,
        )?;
        write_authenticated_fixture(
            &repo,
            "rejected-history",
            false,
            false,
            false,
            false,
            AuthenticatedFixtureMode::Initial,
        )?;
        let current = RunId::new("next-run")?;
        let frozen = load_frozen_outcome_history(&repo, &current)?;
        assert_eq!(frozen.rows.len(), 2);
        assert!(frozen
            .rows
            .iter()
            .any(|row| row.result == OutcomeResult::Accepted));
        assert!(frozen
            .rows
            .iter()
            .any(|row| row.result == OutcomeResult::Rejected));
        assert_eq!(frozen.provenance.projected_attempt_count, 2);
        assert_eq!(frozen.provenance.source_digests.len(), 2);
        write_authenticated_fixture(
            &repo,
            "later-history",
            true,
            false,
            false,
            false,
            AuthenticatedFixtureMode::Initial,
        )?;
        assert_eq!(frozen.rows.len(), 2);
        let later = load_frozen_outcome_history(&repo, &current)?;
        assert_eq!(later.rows.len(), 3);
        assert_ne!(
            frozen.provenance.snapshot_sha256,
            later.provenance.snapshot_sha256
        );
        Ok(())
    }

    #[test]
    fn authenticated_exact_bound_outcome_changes_existing_selector_score() -> Result<()> {
        let (_temp, repo) = super::super::tests::injected_repository();
        write_authenticated_fixture(
            &repo,
            "selector-influence-history",
            true,
            false,
            false,
            false,
            AuthenticatedFixtureMode::Initial,
        )?;
        let frozen = load_frozen_outcome_history(&repo, &RunId::new("next-run")?)?;
        let mut input = crate::selection::selection_test_base_input();
        let baseline = crate::selection::select(&input)?;
        let candidate = baseline
            .choice
            .as_ref()
            .context("baseline choice")?
            .candidate
            .clone();
        input.outcomes = frozen.outcomes_for(&input.task);
        assert_eq!(input.outcomes.len(), 1);
        assert_eq!(input.outcomes[0].candidate, candidate);
        let with_history = crate::selection::select(&input)?;
        let score_for = |decision: &crate::selection::SelectionProvenance| {
            decision
                .candidate_set
                .iter()
                .find(|item| item.candidate == candidate)
                .and_then(|item| item.score.as_ref())
                .map(|score| score.expected_total_cost_per_accepted_task_microunits)
        };
        assert_ne!(score_for(&baseline), score_for(&with_history));
        assert_ne!(
            baseline.input_digests.normalized_input.value,
            with_history.input_digests.normalized_input.value
        );
        Ok(())
    }

    #[test]
    fn authenticated_auditor_retry_keeps_original_rejected_attempt() -> Result<()> {
        let (_temp, repo) = super::super::tests::injected_repository();
        write_authenticated_fixture(
            &repo,
            "auditor-retry-history",
            true,
            false,
            false,
            false,
            AuthenticatedFixtureMode::AuditorRetry,
        )?;
        let frozen = load_frozen_outcome_history(&repo, &RunId::new("next-run")?)?;
        assert_eq!(frozen.rows.len(), 2);
        assert_eq!(
            frozen.rows[0].attempt_id,
            "auditor-retry-history:assignment-1:1"
        );
        assert_eq!(frozen.rows[0].result, OutcomeResult::Rejected);
        assert_eq!(
            frozen.rows[1].attempt_id,
            "auditor-retry-history:assignment-1:2"
        );
        assert_eq!(frozen.rows[1].result, OutcomeResult::Accepted);
        assert!(!frozen
            .provenance
            .exclusions
            .iter()
            .any(|item| item.contains("superseded_attempt")));
        let reader = ArtifactRunReader::open(
            &repo,
            RunArtifactFamily::Supervise,
            &RunId::new("auditor-retry-history")?,
        )?;
        let first: AttemptOutcomeEvidence = serde_json::from_slice(
            &reader.read(Path::new("selection-attempts/assignment-1.attempt-1.json"))?,
        )?;
        assert_eq!(
            first.parent_cause.as_deref(),
            Some("parent_auditor_authorized_retry")
        );
        assert_eq!(first.selection, fixture_selection_for_row(&reader, &first)?);
        let second: AttemptOutcomeEvidence = serde_json::from_slice(
            &reader.read(Path::new("selection-attempts/assignment-1.attempt-2.json"))?,
        )?;
        assert_ne!(first.selection, second.selection);
        Ok(())
    }

    fn fixture_selection_for_row(
        reader: &ArtifactRunReader,
        row: &AttemptOutcomeEvidence,
    ) -> Result<Option<AttemptSelectionBinding>> {
        let report: SupervisorFinalReport = serde_json::from_slice(
            &reader.read(RunArtifactFamily::Supervise.final_report_relative_path())?,
        )?;
        let events = &report
            .role_economics_profile
            .as_ref()
            .and_then(|profile| profile.execution.as_ref())
            .context("fixture execution")?
            .selection_decisions;
        Ok(selection_binding_for_attempt(
            AgentRole::Worker,
            &row.assignment_id,
            row.attempt,
            events,
            events,
        ))
    }

    #[test]
    fn authenticated_degraded_first_attempt_uses_assignment_event_zero() -> Result<()> {
        let (_temp, repo) = super::super::tests::injected_repository();
        write_authenticated_fixture(
            &repo,
            "degraded-first-history",
            true,
            false,
            false,
            false,
            AuthenticatedFixtureMode::AssignmentDegrade,
        )?;
        let frozen = load_frozen_outcome_history(&repo, &RunId::new("next-run")?)?;
        assert_eq!(frozen.rows.len(), 1);
        assert_eq!(
            frozen.rows[0].attempt_id,
            "degraded-first-history:assignment-1:1"
        );
        assert!(!frozen
            .provenance
            .exclusions
            .iter()
            .any(|item| item.contains("selection_binding_mismatch")));
        Ok(())
    }

    #[test]
    fn authenticated_debug_override_binds_initial_choice() -> Result<()> {
        let (_temp, repo) = super::super::tests::injected_repository();
        write_authenticated_fixture(
            &repo,
            "debug-override-history",
            true,
            false,
            false,
            false,
            AuthenticatedFixtureMode::DebugOverride,
        )?;
        let frozen = load_frozen_outcome_history(&repo, &RunId::new("next-run")?)?;
        assert_eq!(frozen.rows.len(), 1);
        assert_eq!(
            frozen.rows[0].attempt_id,
            "debug-override-history:assignment-1:1"
        );
        assert_eq!(frozen.provenance.projected_attempt_count, 1);
        Ok(())
    }

    #[test]
    fn duplicate_synthetic_and_foreign_rows_cannot_enter_numeric_history() -> Result<()> {
        let (_temp, repo) = super::super::tests::injected_repository();
        write_authenticated_fixture(
            &repo,
            "duplicate-history",
            true,
            true,
            false,
            false,
            AuthenticatedFixtureMode::Initial,
        )?;
        write_authenticated_fixture(
            &repo,
            "synthetic-history",
            true,
            false,
            true,
            false,
            AuthenticatedFixtureMode::Initial,
        )?;
        write_authenticated_fixture(
            &repo,
            "foreign-history",
            true,
            false,
            false,
            true,
            AuthenticatedFixtureMode::Initial,
        )?;
        let frozen = load_frozen_outcome_history(&repo, &RunId::new("next-run")?)?;
        assert!(frozen.rows.is_empty());
        for reason in [
            "duplicate_attempt",
            "synthetic_execution",
            "invalid_or_simulation_source",
        ] {
            assert!(frozen
                .provenance
                .exclusions
                .iter()
                .any(|item| item.contains(reason)));
        }
        Ok(())
    }

    #[test]
    fn unfinalized_attempt_source_is_excluded() -> Result<()> {
        let (_temp, repo) = super::super::tests::injected_repository();
        let run_id = RunId::new("unfinalized-history")?;
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            run_id,
            "maco-supervise",
        )?;
        writer.write_json(
            Path::new("selection-attempts/assignment-1.attempt-1.json"),
            &fixture(),
            ArtifactFileDisposition::PrivateEvidence,
        )?;
        drop(writer);
        let frozen = load_frozen_outcome_history(&repo, &RunId::new("next-run")?)?;
        assert!(frozen.rows.is_empty());
        assert!(frozen
            .provenance
            .exclusions
            .iter()
            .any(|reason| reason.contains("unfinalized_or_unauthenticated")));
        Ok(())
    }

    #[test]
    fn numeric_projection_requires_observed_identity_and_every_attempt_cost() {
        let mut evidence = fixture();
        assert_eq!(
            project_numeric_row(&evidence)
                .unwrap()
                .execution_cost_microunits,
            5
        );
        evidence.costs.review_cost_microunits = None;
        assert!(project_numeric_row(&evidence).is_none());
        evidence.costs.review_cost_microunits = Some(0);
        evidence.costs.environment_cost_microunits = None;
        assert!(project_numeric_row(&evidence).is_none());
        evidence.costs.environment_cost_microunits = Some(0);
        evidence.observed_candidate = None;
        assert!(project_numeric_row(&evidence).is_none());
        evidence.observed_candidate = Some(CandidateKey {
            model: "different-model".to_string(),
            ..fixture().observed_candidate.unwrap()
        });
        assert!(project_numeric_row(&evidence).is_none());
        evidence.observed_candidate = fixture().observed_candidate;
        evidence.requested_model = Some("different-request".to_string());
        assert!(project_numeric_row(&evidence).is_none());
        evidence.requested_model = Some("fixture-model".to_string());
        evidence.parent_result = Some(OutcomeResult::Rejected);
        let rejected = project_numeric_row(&evidence).unwrap();
        assert_eq!(rejected.failure_class, None);
    }

    #[test]
    fn authenticated_fake_run_is_excluded_and_tamper_is_refused() -> Result<()> {
        let (_temp, repo) = super::super::tests::injected_repository();
        let run_id = RunId::new("fake-history-source")?;
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            run_id.clone(),
            "maco-supervise",
        )?;
        let final_relative = RunArtifactFamily::Supervise.final_report_relative_path();
        writer.write_json(
            &final_relative,
            &super::super::tests::artifact_test_final_report(&run_id),
            ArtifactFileDisposition::Publishable,
        )?;
        writer.finalize(&final_relative, false)?;
        ArtifactRunReader::open(&repo, RunArtifactFamily::Supervise, &run_id)?;
        let before = load_frozen_outcome_history(&repo, &RunId::new("next-run")?)?;
        assert!(before.rows.is_empty());
        assert!(before
            .provenance
            .exclusions
            .iter()
            .any(|reason| reason.contains("invalid_or_simulation_source")));
        std::fs::write(
            repo.join(RunArtifactFamily::Supervise.run_root())
                .join(run_id.as_str())
                .join(&final_relative),
            b"tampered",
        )?;
        let after = load_frozen_outcome_history(&repo, &RunId::new("next-run")?)?;
        assert!(after.rows.is_empty());
        assert!(after
            .provenance
            .exclusions
            .iter()
            .any(|reason| reason.contains("unfinalized_or_unauthenticated")));
        Ok(())
    }

    #[test]
    fn frozen_projection_filters_exact_task_without_mutating_source() {
        let row = project_numeric_row(&fixture()).unwrap();
        let snapshot = FrozenOutcomeHistory {
            provenance: crate::selection::AuthenticatedOutcomeHistoryProvenance {
                snapshot_sha256: "fixture".to_string(),
                source_digests: Vec::new(),
                exclusions: Vec::new(),
                projected_attempt_count: 1,
            },
            rows: vec![row.clone()],
        };
        assert_eq!(snapshot.outcomes_for(&row.task), vec![row]);
        let mut other = snapshot.rows[0].task.clone();
        other.task_class = "other".to_string();
        assert!(snapshot.outcomes_for(&other).is_empty());
        assert_eq!(snapshot.provenance.snapshot_sha256, "fixture");
    }

    fn trusted_grok_acp_parent_evidence(
        model: &str,
        effort: &str,
        cost: GrokAcpNativeCostEquivalent,
    ) -> GrokAcpParentEvidence {
        GrokAcpParentEvidence {
            protocol: "grok_acp_stdio".to_string(),
            session_id: "trusted-parent-session".to_string(),
            requested_model: None,
            requested_effort: None,
            client_resolved_model: GrokAcpParentResolvedField::Known(model.to_string()),
            client_resolved_effort: GrokAcpParentResolvedField::Known(effort.to_string()),
            resolution_status: "complete".to_string(),
            terminal_usage: None,
            native_cost_equivalent_microunits: cost,
            permission_escalation_refused: false,
            structured_output: None,
            structured_output_error: None,
            final_text: None,
            stop_reason: None,
        }
    }

    fn grok_worker_selection_event() -> SupervisorSelectionEvent {
        let decision = crate::selection::select(&crate::selection::selection_test_base_input())
            .expect("fixture selector decision");
        let grok_candidate = CandidateKey {
            runtime: "grok".to_string(),
            model: "grok-code-fast-1".to_string(),
            effort: ReasoningEffort::High,
        };
        let mut provenance = decision;
        if let Some(choice) = provenance.choice.as_mut() {
            choice.candidate = grok_candidate.clone();
        }
        SupervisorSelectionEvent {
            assignment_id: None,
            attempt: 0,
            role: AgentRole::Worker,
            primary_cause: SupervisorSelectionEventCause::Initial,
            provenance,
        }
    }

    fn codex_worker_selection_event() -> SupervisorSelectionEvent {
        let decision = crate::selection::select(&crate::selection::selection_test_base_input())
            .expect("fixture selector decision");
        let codex_candidate = CandidateKey {
            runtime: "codex".to_string(),
            model: "gpt-5.6-sol".to_string(),
            effort: ReasoningEffort::High,
        };
        let mut provenance = decision;
        if let Some(choice) = provenance.choice.as_mut() {
            choice.candidate = codex_candidate.clone();
        }
        SupervisorSelectionEvent {
            assignment_id: None,
            attempt: 0,
            role: AgentRole::Worker,
            primary_cause: SupervisorSelectionEventCause::Initial,
            provenance,
        }
    }

    fn known_codex_usage(input_tokens: u64, output_tokens: u64) -> CodexParentTurnUsage {
        CodexParentTurnUsage::Known {
            input_tokens,
            output_tokens,
            cached_input_tokens: 400_000,
            reasoning_output_tokens: 200_000,
        }
    }

    fn dated_codex_plan_pricing() -> BTreeMap<String, ModelPricing> {
        BTreeMap::from([
            (
                "gpt-5.6-sol".to_string(),
                ModelPricing {
                    input_usd_per_million_tokens: 10.0,
                    output_usd_per_million_tokens: 40.0,
                },
            ),
            (
                "gpt-5.6-luna".to_string(),
                ModelPricing {
                    input_usd_per_million_tokens: 2.0,
                    output_usd_per_million_tokens: 8.0,
                },
            ),
            (
                "gpt-5-codex".to_string(),
                ModelPricing {
                    input_usd_per_million_tokens: 1.0,
                    output_usd_per_million_tokens: 1.0,
                },
            ),
        ])
    }

    struct TrustedCodexParentEvidenceInput<'a> {
        requested_model: Option<&'a str>,
        requested_effort: Option<&'a str>,
        rollout_model: &'a str,
        rollout_effort: &'a str,
        observed_model: &'a str,
        observed_effort: &'a str,
        server_rerouted: Option<CodexServerRerouteEvidence>,
        usage: CodexParentTurnUsage,
        resolution_status: &'a str,
    }

    fn trusted_codex_parent_evidence(
        input: TrustedCodexParentEvidenceInput<'_>,
    ) -> CodexParentEvidence {
        let model_mismatch = input
            .requested_model
            .map(|requested| requested != input.observed_model)
            .unwrap_or(false);
        CodexParentEvidence {
            codex_version: Some("0.144.4".to_string()),
            thread_id: Some("parent-codex-thread".to_string()),
            requested_model: input.requested_model.map(str::to_string),
            requested_effort: input.requested_effort.map(str::to_string),
            rollout_model: CodexParentResolvedField::Known(input.rollout_model.to_string()),
            rollout_effort: CodexParentResolvedField::Known(input.rollout_effort.to_string()),
            observed_model: CodexParentResolvedField::Known(input.observed_model.to_string()),
            observed_effort: CodexParentResolvedField::Known(input.observed_effort.to_string()),
            server_rerouted_model: input.server_rerouted,
            model_mismatch,
            turn_usage: input.usage,
            resolution_status: input.resolution_status.to_string(),
        }
    }

    fn parent_run_with_codex_evidence(
        temp: &tempfile::TempDir,
        repo: &Path,
        evidence: CodexParentEvidence,
    ) -> ExternalAgentRun {
        let mut external_run =
            super::super::tests::injected_verified_run(&injected_parent_command(temp, repo));
        external_run.codex_parent_evidence = Some(evidence);
        external_run
    }

    fn record_codex_attempt(
        external_run: ExternalAgentRun,
        run_name: &str,
        attempt: usize,
        requested_model: &str,
        dated_plan_pricing: &BTreeMap<String, ModelPricing>,
        parent_phase_continuation: Option<AttemptParentPhaseContinuation>,
    ) -> Result<AttemptOutcomeEvidence> {
        let (_temp, repo) = super::super::tests::injected_repository();
        let run_id = RunId::new(run_name)?;
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            run_id.clone(),
            "maco-supervise",
        )?;
        let mut journal = None;
        let mut autonomy_kpis = AutonomyKpiCollector::default();
        let artifacts = Mutex::new(SharedSupervisorArtifacts {
            writer: &mut writer,
            journal: &mut journal,
            autonomy_kpis: &mut autonomy_kpis,
            checkpoint: None,
        });
        let initial = codex_worker_selection_event();
        let recorded = record_child_attempt_outcome(
            &artifacts,
            &run_id,
            "assignment-1",
            attempt,
            AgentRole::Worker,
            &[],
            std::slice::from_ref(&initial),
            "codex",
            Some(requested_model),
            Some("high"),
            true,
            false,
            SupervisorExecutionRuntime::Verified,
            Some(&external_run),
            dated_plan_pricing,
            parent_phase_continuation,
        )?;
        let relative = PathBuf::from(format!(
            "selection-attempts/assignment-1.attempt-{attempt}.json"
        ));
        let stored: AttemptOutcomeEvidence = serde_json::from_slice(&std::fs::read(
            repo.join(RunArtifactFamily::Supervise.run_root())
                .join(run_id.as_str())
                .join(&relative),
        )?)?;
        assert_eq!(stored, recorded);
        Ok(recorded)
    }

    fn injected_parent_command(
        temp: &tempfile::TempDir,
        repo: &Path,
    ) -> crate::external_agent::ExternalAgentCommand {
        crate::external_agent::ExternalAgentCommand::codex(
            "codex",
            repo,
            temp.path().join("parent-acp-prompt.md"),
            temp.path().join("parent-acp-events.jsonl"),
            temp.path().join("parent-acp-report.json"),
            std::time::Duration::from_secs(1),
        )
    }

    fn record_attempt_with_parent_run(
        external_run: Option<ExternalAgentRun>,
        run_name: &str,
    ) -> Result<(AttemptOutcomeEvidence, tempfile::TempDir, PathBuf, RunId)> {
        let (temp, repo) = super::super::tests::injected_repository();
        let run_id = RunId::new(run_name)?;
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            run_id.clone(),
            "maco-supervise",
        )?;
        let mut journal = None;
        let mut autonomy_kpis = AutonomyKpiCollector::default();
        let artifacts = Mutex::new(SharedSupervisorArtifacts {
            writer: &mut writer,
            journal: &mut journal,
            autonomy_kpis: &mut autonomy_kpis,
            checkpoint: None,
        });
        let initial = grok_worker_selection_event();
        let recorded = record_child_attempt_outcome(
            &artifacts,
            &run_id,
            "assignment-1",
            1,
            AgentRole::Worker,
            &[],
            std::slice::from_ref(&initial),
            "grok",
            Some("grok-code-fast-1"),
            Some("high"),
            true,
            false,
            SupervisorExecutionRuntime::Verified,
            external_run.as_ref(),
            &BTreeMap::new(),
            None,
        )?;
        let relative = PathBuf::from("selection-attempts/assignment-1.attempt-1.json");
        let stored_path = repo
            .join(RunArtifactFamily::Supervise.run_root())
            .join(run_id.as_str())
            .join(&relative);
        let stored: AttemptOutcomeEvidence = serde_json::from_slice(&std::fs::read(&stored_path)?)?;
        assert_eq!(stored, recorded);
        Ok((recorded, temp, repo, run_id))
    }

    fn parent_run_with_trusted_acp(
        temp: &tempfile::TempDir,
        repo: &Path,
        model: &str,
        cost: GrokAcpNativeCostEquivalent,
    ) -> ExternalAgentRun {
        let mut external_run =
            super::super::tests::injected_verified_run(&injected_parent_command(temp, repo));
        external_run.grok_acp_parent_evidence =
            Some(trusted_grok_acp_parent_evidence(model, "high", cost));
        external_run
    }

    #[test]
    fn record_child_attempt_outcome_retains_parent_acp_identity_and_execution_cost() -> Result<()> {
        let (temp, repo) = super::super::tests::injected_repository();
        let external_run = parent_run_with_trusted_acp(
            &temp,
            &repo,
            "grok-code-fast-1",
            GrokAcpNativeCostEquivalent::Known {
                cost_usd_ticks: 20_000_000,
                microunits: 200,
            },
        );
        let (recorded, _, _, _) =
            record_attempt_with_parent_run(Some(external_run), "parent-acp-outcome-record")?;
        let observed = recorded
            .observed_candidate
            .as_ref()
            .expect("mapped observed candidate");
        assert_eq!(observed.runtime, "grok");
        assert_eq!(observed.model, "grok-code-fast-1");
        assert_eq!(observed.effort, ReasoningEffort::High);
        assert_eq!(recorded.costs.execution_cost_microunits, Some(200));
        assert_eq!(recorded.costs.rework_cost_microunits, Some(0));
        assert!(recorded.costs.environment_cost_microunits.is_none());
        assert!(project_numeric_row(&recorded).is_none());
        Ok(())
    }

    #[test]
    fn worker_retry_observed_spend_attributes_to_rework_not_execution() -> Result<()> {
        let (temp, repo) = super::super::tests::injected_repository();
        let external_run = parent_run_with_trusted_acp(
            &temp,
            &repo,
            "grok-code-fast-1",
            GrokAcpNativeCostEquivalent::Known {
                cost_usd_ticks: 10_000_000,
                microunits: 88,
            },
        );
        let run_id = RunId::new("worker-rework-phase")?;
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            run_id.clone(),
            "maco-supervise",
        )?;
        let mut journal = None;
        let mut autonomy_kpis = AutonomyKpiCollector::default();
        let artifacts = Mutex::new(SharedSupervisorArtifacts {
            writer: &mut writer,
            journal: &mut journal,
            autonomy_kpis: &mut autonomy_kpis,
            checkpoint: None,
        });
        let initial = grok_worker_selection_event();
        let recorded = record_child_attempt_outcome(
            &artifacts,
            &run_id,
            "assignment-1",
            2,
            AgentRole::Worker,
            &[],
            std::slice::from_ref(&initial),
            "grok",
            Some("grok-code-fast-1"),
            Some("high"),
            true,
            false,
            SupervisorExecutionRuntime::Verified,
            Some(&external_run),
            &BTreeMap::new(),
            Some(attempt_parent_phase_continuation_from_count(Some(0))),
        )?;
        assert_eq!(recorded.costs.execution_cost_microunits, Some(0));
        assert_eq!(recorded.costs.rework_cost_microunits, Some(88));
        assert!(recorded.costs.environment_cost_microunits.is_none());
        Ok(())
    }

    #[test]
    fn observed_requested_mismatch_is_recorded_but_not_numeric_eligible() -> Result<()> {
        let (temp, repo) = super::super::tests::injected_repository();
        let external_run = parent_run_with_trusted_acp(
            &temp,
            &repo,
            "gpt-5.6-sol",
            GrokAcpNativeCostEquivalent::Known {
                cost_usd_ticks: 10_000_000,
                microunits: 100,
            },
        );
        let (recorded, _, _, _) =
            record_attempt_with_parent_run(Some(external_run), "parent-acp-mismatch-record")?;
        assert_eq!(
            recorded
                .observed_candidate
                .as_ref()
                .map(|key| key.model.as_str()),
            Some("gpt-5.6-sol")
        );
        assert!(project_numeric_row(&recorded).is_none());
        Ok(())
    }

    #[test]
    fn incomplete_parent_acp_observation_cannot_promote_identity_or_cost() -> Result<()> {
        let (temp, repo) = super::super::tests::injected_repository();
        let mut external_run = parent_run_with_trusted_acp(
            &temp,
            &repo,
            "grok-code-fast-1",
            GrokAcpNativeCostEquivalent::Known {
                cost_usd_ticks: 1,
                microunits: 0,
            },
        );
        external_run
            .grok_acp_parent_evidence
            .as_mut()
            .expect("parent evidence")
            .resolution_status = "incomplete".to_string();
        let (recorded, _, _, _) =
            record_attempt_with_parent_run(Some(external_run), "parent-acp-incomplete-record")?;
        assert!(recorded.observed_candidate.is_none());
        assert!(recorded.costs.execution_cost_microunits.is_none());
        Ok(())
    }

    #[test]
    fn missing_parent_run_cannot_fabricate_observation() -> Result<()> {
        let (recorded, _, _, _) =
            record_attempt_with_parent_run(None, "parent-acp-missing-run-record")?;
        assert!(recorded.observed_candidate.is_none());
        assert!(recorded.costs.execution_cost_microunits.is_none());
        Ok(())
    }

    #[test]
    fn partial_parent_execution_cost_excludes_numeric_projection() -> Result<()> {
        let (temp, repo) = super::super::tests::injected_repository();
        let external_run = parent_run_with_trusted_acp(
            &temp,
            &repo,
            "grok-code-fast-1",
            GrokAcpNativeCostEquivalent::Unknown {
                reason: "terminal usage marked incomplete or cost partial".to_string(),
            },
        );
        let (recorded, _, _, _) =
            record_attempt_with_parent_run(Some(external_run), "parent-acp-partial-cost-record")?;
        assert!(recorded.observed_candidate.is_some());
        assert!(recorded.costs.execution_cost_microunits.is_none());
        assert!(project_numeric_row(&recorded).is_none());
        Ok(())
    }

    fn parent_auditor_run_with_trusted_acp_on(
        temp: &tempfile::TempDir,
        repo: &Path,
        microunits: u64,
        cost_usd_ticks: u64,
    ) -> ExternalAgentRun {
        let mut external_run =
            super::super::tests::injected_verified_run(&injected_parent_command(temp, repo));
        external_run.grok_acp_parent_evidence = Some(trusted_grok_acp_parent_evidence(
            "grok-code-fast-1",
            "high",
            GrokAcpNativeCostEquivalent::Known {
                cost_usd_ticks,
                microunits,
            },
        ));
        external_run
    }

    #[test]
    fn parent_review_cost_binding_sums_stacked_auditor_dispatches() {
        let (temp, repo) = super::super::tests::injected_repository();
        let mut binding = ParentWorkerAttemptReviewCostBinding::bind(
            "assignment-a",
            1,
            ParentDispatchedReviewCycleSlot::FirstCycle,
        );
        binding.begin_stacked_parent_review_lenses(2);
        binding.observe_parent_auditor_external_run(&parent_auditor_run_with_trusted_acp_on(
            &temp, &repo, 11, 1_100_000,
        ));
        binding.observe_parent_auditor_external_run(&parent_auditor_run_with_trusted_acp_on(
            &temp, &repo, 29, 2_900_000,
        ));
        assert_eq!(binding.parent_auditor_invocation_count(), 2);
        assert_eq!(binding.review_total_microunits(), Some(40));
        assert!(binding.parent_review_dispatch_set_complete_for_test());
        assert!(binding.parent_review_cycle_actually_dispatched());
    }

    #[test]
    fn partial_lens_dispatch_advances_cycle_counter_without_complete_telemetry() {
        let (temp, repo) = super::super::tests::injected_repository();
        let mut binding = ParentWorkerAttemptReviewCostBinding::bind(
            "assignment-a",
            1,
            ParentDispatchedReviewCycleSlot::FirstCycle,
        );
        binding.begin_stacked_parent_review_lenses(2);
        binding.observe_parent_auditor_external_run(&parent_auditor_run_with_trusted_acp_on(
            &temp, &repo, 7, 700_000,
        ));
        binding.record_parent_auditor_lens_undispatched();
        assert!(binding.parent_review_cycle_actually_dispatched());
        assert!(!binding.parent_review_dispatch_set_complete_for_test());
        let mut completed_parent_review_cycles = Some(0usize);
        advance_completed_parent_review_cycles_after_actual_dispatch(
            &mut completed_parent_review_cycles,
            &binding,
        );
        assert_eq!(completed_parent_review_cycles, Some(1));
        assert_eq!(
            review_cycle_slot_for_completed_dispatched_cycles(completed_parent_review_cycles),
            ParentDispatchedReviewCycleSlot::SubsequentCycle
        );
        assert_eq!(
            binding.persistable_review_phase_cost_microunits(),
            Some(None)
        );
    }

    #[test]
    fn parent_review_cost_binding_unknown_contaminates_total() {
        let (temp, repo) = super::super::tests::injected_repository();
        let mut binding = ParentWorkerAttemptReviewCostBinding::bind(
            "assignment-a",
            1,
            ParentDispatchedReviewCycleSlot::FirstCycle,
        );
        binding.begin_stacked_parent_review_lenses(2);
        binding.observe_parent_auditor_external_run(&parent_auditor_run_with_trusted_acp_on(
            &temp, &repo, 5, 500_000,
        ));
        let mut incomplete = parent_auditor_run_with_trusted_acp_on(&temp, &repo, 0, 0);
        incomplete
            .grok_acp_parent_evidence
            .as_mut()
            .expect("parent evidence")
            .resolution_status = "incomplete".to_string();
        binding.observe_parent_auditor_external_run(&incomplete);
        assert_eq!(binding.parent_auditor_invocation_count(), 2);
        assert!(binding.review_total_microunits().is_none());
    }

    #[test]
    fn parent_review_cost_binding_overflow_makes_total_unknown() {
        let (temp, repo) = super::super::tests::injected_repository();
        let ticks_per_microunit = 100_000;
        let microunits = u64::MAX / ticks_per_microunit;
        let run = parent_auditor_run_with_trusted_acp_on(
            &temp,
            &repo,
            microunits,
            microunits * ticks_per_microunit,
        );
        let dispatch_count =
            usize::try_from(u64::MAX / microunits + 1).expect("overflow dispatch count fits usize");
        let mut binding = ParentWorkerAttemptReviewCostBinding::bind(
            "assignment-a",
            1,
            ParentDispatchedReviewCycleSlot::FirstCycle,
        );
        binding.begin_stacked_parent_review_lenses(dispatch_count);
        for _ in 0..dispatch_count {
            binding.observe_parent_auditor_external_run(&run);
        }
        assert_eq!(binding.parent_auditor_invocation_count(), dispatch_count);
        assert!(binding.review_total_microunits().is_none());
    }

    #[test]
    fn parent_review_cost_binding_isolated_per_assignment_attempt() {
        let (temp, repo) = super::super::tests::injected_repository();
        let mut first = ParentWorkerAttemptReviewCostBinding::bind(
            "assignment-a",
            1,
            ParentDispatchedReviewCycleSlot::FirstCycle,
        );
        let mut second = ParentWorkerAttemptReviewCostBinding::bind(
            "assignment-a",
            2,
            ParentDispatchedReviewCycleSlot::SubsequentCycle,
        );
        let mut other = ParentWorkerAttemptReviewCostBinding::bind(
            "assignment-b",
            1,
            ParentDispatchedReviewCycleSlot::FirstCycle,
        );
        first.begin_stacked_parent_review_lenses(1);
        second.begin_stacked_parent_review_lenses(1);
        other.begin_stacked_parent_review_lenses(1);
        first.observe_parent_auditor_external_run(&parent_auditor_run_with_trusted_acp_on(
            &temp, &repo, 11, 1_100_000,
        ));
        second.observe_parent_auditor_external_run(&parent_auditor_run_with_trusted_acp_on(
            &temp, &repo, 22, 2_200_000,
        ));
        other.observe_parent_auditor_external_run(&parent_auditor_run_with_trusted_acp_on(
            &temp, &repo, 33, 3_300_000,
        ));
        assert_eq!(first.review_total_microunits(), Some(11));
        assert_eq!(second.review_total_microunits(), Some(22));
        assert_eq!(other.review_total_microunits(), Some(33));
    }

    #[test]
    fn persist_worker_attempt_review_cost_rejects_partial_stacked_lens_sum() -> Result<()> {
        let (temp, repo) = super::super::tests::injected_repository();
        let run_id = RunId::new("review-cost-partial-stack")?;
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            run_id.clone(),
            "maco-supervise",
        )?;
        let mut journal = None;
        let mut autonomy_kpis = AutonomyKpiCollector::default();
        let artifacts = Mutex::new(SharedSupervisorArtifacts {
            writer: &mut writer,
            journal: &mut journal,
            autonomy_kpis: &mut autonomy_kpis,
            checkpoint: None,
        });
        let initial = grok_worker_selection_event();
        let mut recorded = record_child_attempt_outcome(
            &artifacts,
            &run_id,
            "assignment-1",
            1,
            AgentRole::Worker,
            &[],
            std::slice::from_ref(&initial),
            "grok",
            Some("grok-code-fast-1"),
            Some("high"),
            true,
            false,
            SupervisorExecutionRuntime::Verified,
            None,
            &BTreeMap::new(),
            None,
        )?;
        let mut binding = ParentWorkerAttemptReviewCostBinding::bind(
            "assignment-1",
            1,
            ParentDispatchedReviewCycleSlot::FirstCycle,
        );
        binding.begin_stacked_parent_review_lenses(2);
        binding.observe_parent_auditor_external_run(&parent_auditor_run_with_trusted_acp_on(
            &temp, &repo, 50, 5_000_000,
        ));
        binding.record_parent_auditor_lens_undispatched();
        assert!(!binding.parent_review_dispatch_set_complete_for_test());
        persist_worker_attempt_review_cost(&artifacts, &binding, &mut recorded)?;
        assert!(recorded.costs.review_cost_microunits.is_none());
        let stored: AttemptOutcomeEvidence = serde_json::from_slice(&std::fs::read(
            repo.join(RunArtifactFamily::Supervise.run_root())
                .join(run_id.as_str())
                .join("selection-attempts/assignment-1.attempt-1.json"),
        )?)?;
        assert!(stored.costs.review_cost_microunits.is_none());
        Ok(())
    }

    #[test]
    fn persist_worker_attempt_review_cost_rejects_assignment_attempt_mismatch() -> Result<()> {
        let (temp, repo) = super::super::tests::injected_repository();
        let run_id = RunId::new("review-cost-binding-mismatch")?;
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            run_id.clone(),
            "maco-supervise",
        )?;
        let mut journal = None;
        let mut autonomy_kpis = AutonomyKpiCollector::default();
        let artifacts = Mutex::new(SharedSupervisorArtifacts {
            writer: &mut writer,
            journal: &mut journal,
            autonomy_kpis: &mut autonomy_kpis,
            checkpoint: None,
        });
        let initial = grok_worker_selection_event();
        let mut recorded = record_child_attempt_outcome(
            &artifacts,
            &run_id,
            "assignment-1",
            1,
            AgentRole::Worker,
            &[],
            std::slice::from_ref(&initial),
            "grok",
            Some("grok-code-fast-1"),
            Some("high"),
            true,
            false,
            SupervisorExecutionRuntime::Verified,
            None,
            &BTreeMap::new(),
            None,
        )?;
        let mut binding = ParentWorkerAttemptReviewCostBinding::bind(
            "other-assignment",
            1,
            ParentDispatchedReviewCycleSlot::FirstCycle,
        );
        binding.begin_stacked_parent_review_lenses(1);
        binding.observe_parent_auditor_external_run(&parent_auditor_run_with_trusted_acp_on(
            &temp, &repo, 1, 100_000,
        ));
        let error = persist_worker_attempt_review_cost(&artifacts, &binding, &mut recorded)
            .expect_err("binding mismatch must fail closed");
        assert!(error.to_string().contains("does not match attempt record"));
        drop(temp);
        Ok(())
    }

    #[test]
    fn persist_worker_attempt_review_cost_preserves_execution_and_identity() -> Result<()> {
        let (temp, repo) = super::super::tests::injected_repository();
        let run_id = RunId::new("review-cost-persist-record")?;
        let external_run = parent_run_with_trusted_acp(
            &temp,
            &repo,
            "grok-code-fast-1",
            GrokAcpNativeCostEquivalent::Known {
                cost_usd_ticks: 20_000_000,
                microunits: 200,
            },
        );
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            run_id.clone(),
            "maco-supervise",
        )?;
        let mut journal = None;
        let mut autonomy_kpis = AutonomyKpiCollector::default();
        let artifacts = Mutex::new(SharedSupervisorArtifacts {
            writer: &mut writer,
            journal: &mut journal,
            autonomy_kpis: &mut autonomy_kpis,
            checkpoint: None,
        });
        let initial = grok_worker_selection_event();
        let mut recorded = record_child_attempt_outcome(
            &artifacts,
            &run_id,
            "assignment-1",
            1,
            AgentRole::Worker,
            &[],
            std::slice::from_ref(&initial),
            "grok",
            Some("grok-code-fast-1"),
            Some("high"),
            true,
            false,
            SupervisorExecutionRuntime::Verified,
            Some(&external_run),
            &BTreeMap::new(),
            None,
        )?;
        let mut binding = ParentWorkerAttemptReviewCostBinding::bind(
            "assignment-1",
            1,
            ParentDispatchedReviewCycleSlot::FirstCycle,
        );
        binding.begin_stacked_parent_review_lenses(1);
        binding.observe_parent_auditor_external_run(&parent_auditor_run_with_trusted_acp_on(
            &temp, &repo, 17, 1_700_000,
        ));
        persist_worker_attempt_review_cost(&artifacts, &binding, &mut recorded)?;
        let stored: AttemptOutcomeEvidence = serde_json::from_slice(&std::fs::read(
            repo.join(RunArtifactFamily::Supervise.run_root())
                .join(run_id.as_str())
                .join("selection-attempts/assignment-1.attempt-1.json"),
        )?)?;
        assert_eq!(stored.costs.review_cost_microunits, Some(17));
        assert_eq!(stored.costs.rereview_cost_microunits, Some(0));
        assert_eq!(stored.costs.execution_cost_microunits, Some(200));
        assert_eq!(stored.observed_candidate, recorded.observed_candidate);
        Ok(())
    }

    #[test]
    fn parent_auditor_retry_preserves_parent_acp_observation() -> Result<()> {
        let (temp, repo) = super::super::tests::injected_repository();
        let run_id = RunId::new("parent-acp-auditor-retry-record")?;
        let external_run = parent_run_with_trusted_acp(
            &temp,
            &repo,
            "grok-code-fast-1",
            GrokAcpNativeCostEquivalent::Known {
                cost_usd_ticks: 20_000_000,
                microunits: 200,
            },
        );
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            run_id.clone(),
            "maco-supervise",
        )?;
        let mut journal = None;
        let mut autonomy_kpis = AutonomyKpiCollector::default();
        let artifacts = Mutex::new(SharedSupervisorArtifacts {
            writer: &mut writer,
            journal: &mut journal,
            autonomy_kpis: &mut autonomy_kpis,
            checkpoint: None,
        });
        let initial = grok_worker_selection_event();
        let mut recorded = record_child_attempt_outcome(
            &artifacts,
            &run_id,
            "assignment-1",
            1,
            AgentRole::Worker,
            &[],
            std::slice::from_ref(&initial),
            "grok",
            Some("grok-code-fast-1"),
            Some("high"),
            true,
            false,
            SupervisorExecutionRuntime::Verified,
            Some(&external_run),
            &BTreeMap::new(),
            None,
        )?;
        let mut review_binding = ParentWorkerAttemptReviewCostBinding::bind(
            "assignment-1",
            1,
            ParentDispatchedReviewCycleSlot::FirstCycle,
        );
        review_binding.begin_stacked_parent_review_lenses(1);
        review_binding.observe_parent_auditor_external_run(
            &parent_auditor_run_with_trusted_acp_on(&temp, &repo, 9, 900_000),
        );
        persist_worker_attempt_review_cost(&artifacts, &review_binding, &mut recorded)?;
        record_parent_auditor_retry(&artifacts, &recorded)?;
        let stored: AttemptOutcomeEvidence = serde_json::from_slice(&std::fs::read(
            repo.join(RunArtifactFamily::Supervise.run_root())
                .join(run_id.as_str())
                .join("selection-attempts/assignment-1.attempt-1.json"),
        )?)?;
        assert_eq!(stored.observed_candidate, recorded.observed_candidate);
        assert_eq!(
            stored.costs.execution_cost_microunits,
            recorded.costs.execution_cost_microunits
        );
        assert_eq!(stored.costs.review_cost_microunits, Some(9));
        assert_eq!(
            stored.parent_cause.as_deref(),
            Some("parent_auditor_authorized_retry")
        );
        Ok(())
    }

    #[test]
    fn subsequent_review_cycle_persists_rereview_not_review() -> Result<()> {
        let (temp, repo) = super::super::tests::injected_repository();
        let run_id = RunId::new("rereview-phase-slot")?;
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            run_id.clone(),
            "maco-supervise",
        )?;
        let mut journal = None;
        let mut autonomy_kpis = AutonomyKpiCollector::default();
        let artifacts = Mutex::new(SharedSupervisorArtifacts {
            writer: &mut writer,
            journal: &mut journal,
            autonomy_kpis: &mut autonomy_kpis,
            checkpoint: None,
        });
        let initial = grok_worker_selection_event();
        let mut recorded = record_child_attempt_outcome(
            &artifacts,
            &run_id,
            "assignment-1",
            2,
            AgentRole::Worker,
            &[],
            std::slice::from_ref(&initial),
            "grok",
            Some("grok-code-fast-1"),
            Some("high"),
            true,
            false,
            SupervisorExecutionRuntime::Verified,
            None,
            &BTreeMap::new(),
            Some(attempt_parent_phase_continuation_from_count(Some(1))),
        )?;
        let mut binding = ParentWorkerAttemptReviewCostBinding::bind(
            "assignment-1",
            2,
            ParentDispatchedReviewCycleSlot::SubsequentCycle,
        );
        binding.begin_stacked_parent_review_lenses(1);
        binding.observe_parent_auditor_external_run(&parent_auditor_run_with_trusted_acp_on(
            &temp, &repo, 31, 3_100_000,
        ));
        persist_worker_attempt_review_cost(&artifacts, &binding, &mut recorded)?;
        assert_eq!(recorded.costs.review_cost_microunits, Some(0));
        assert_eq!(recorded.costs.rereview_cost_microunits, Some(31));
        Ok(())
    }

    #[test]
    fn unknown_review_cycle_slot_withholds_review_phase_costs() -> Result<()> {
        let (temp, repo) = super::super::tests::injected_repository();
        let run_id = RunId::new("unknown-review-cycle")?;
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            run_id.clone(),
            "maco-supervise",
        )?;
        let mut journal = None;
        let mut autonomy_kpis = AutonomyKpiCollector::default();
        let artifacts = Mutex::new(SharedSupervisorArtifacts {
            writer: &mut writer,
            journal: &mut journal,
            autonomy_kpis: &mut autonomy_kpis,
            checkpoint: None,
        });
        let initial = grok_worker_selection_event();
        let mut recorded = record_child_attempt_outcome(
            &artifacts,
            &run_id,
            "assignment-1",
            2,
            AgentRole::Worker,
            &[],
            std::slice::from_ref(&initial),
            "grok",
            Some("grok-code-fast-1"),
            Some("high"),
            true,
            false,
            SupervisorExecutionRuntime::Verified,
            None,
            &BTreeMap::new(),
            None,
        )?;
        let mut binding = ParentWorkerAttemptReviewCostBinding::bind(
            "assignment-1",
            2,
            review_cycle_slot_from_continuation(recorded.parent_phase_continuation.as_ref()),
        );
        binding.begin_stacked_parent_review_lenses(1);
        binding.observe_parent_auditor_external_run(&parent_auditor_run_with_trusted_acp_on(
            &temp, &repo, 9, 900_000,
        ));
        persist_worker_attempt_review_cost(&artifacts, &binding, &mut recorded)?;
        assert!(recorded.costs.review_cost_microunits.is_none());
        assert!(recorded.costs.rereview_cost_microunits.is_none());
        Ok(())
    }

    #[test]
    fn proven_no_review_cycle_records_zero_review_and_rereview() -> Result<()> {
        let run_id = RunId::new("no-review-phase")?;
        let (_temp, repo) = super::super::tests::injected_repository();
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            run_id.clone(),
            "maco-supervise",
        )?;
        let mut journal = None;
        let mut autonomy_kpis = AutonomyKpiCollector::default();
        let artifacts = Mutex::new(SharedSupervisorArtifacts {
            writer: &mut writer,
            journal: &mut journal,
            autonomy_kpis: &mut autonomy_kpis,
            checkpoint: None,
        });
        let mut recorded = fixture();
        recorded.run_id = run_id.as_str().to_string();
        recorded.costs.environment_cost_microunits = None;
        persist_proven_no_parent_review_cycle_costs(&artifacts, &mut recorded)?;
        assert_eq!(recorded.costs.review_cost_microunits, Some(0));
        assert_eq!(recorded.costs.rereview_cost_microunits, Some(0));
        assert!(recorded.costs.environment_cost_microunits.is_none());
        Ok(())
    }

    fn minimal_external_run_for_proven_environment_helper() -> ExternalAgentRun {
        use crate::external_agent::{CapturedOutput, ExternalProgramTrust};
        ExternalAgentRun {
            command: vec!["test".into()],
            cwd: std::path::PathBuf::from("/"),
            timeout_seconds: 1,
            exit_code: Some(0),
            duration_ms: 1,
            timed_out: false,
            process_tree: None,
            side_effects: None,
            publishable: false,
            program_trust: ExternalProgramTrust::ExplicitCustom,
            codex_permissions: None,
            stdout: CapturedOutput::default(),
            stderr: CapturedOutput::default(),
            error: None,
            output_last_message: None,
            grok_stream_usage_evidence: None,
            grok_acp_parent_evidence: None,
            codex_parent_evidence: None,
        }
    }

    #[test]
    fn worker_attempt_proven_no_environment_native_spend() {
        assert!(super::worker_attempt_proven_no_environment_native_spend(
            SupervisorExecutionRuntime::NonpublishableSimulation,
            "fake",
            None,
            None,
        ));

        assert!(!super::worker_attempt_proven_no_environment_native_spend(
            SupervisorExecutionRuntime::Verified,
            "codex",
            None,
            None,
        ));

        assert!(!super::worker_attempt_proven_no_environment_native_spend(
            SupervisorExecutionRuntime::NonpublishableSimulation,
            "fake",
            None,
            Some(0),
        ));

        let mut grok_parent_run = minimal_external_run_for_proven_environment_helper();
        grok_parent_run.grok_acp_parent_evidence = Some(trusted_grok_acp_parent_evidence(
            "grok-code-fast-1",
            "high",
            GrokAcpNativeCostEquivalent::Known {
                cost_usd_ticks: 1,
                microunits: 1,
            },
        ));
        assert!(!super::worker_attempt_proven_no_environment_native_spend(
            SupervisorExecutionRuntime::NonpublishableSimulation,
            "fake",
            Some(&grok_parent_run),
            None,
        ));

        let mut codex_parent_run = minimal_external_run_for_proven_environment_helper();
        codex_parent_run.codex_parent_evidence = Some(trusted_codex_parent_evidence(
            TrustedCodexParentEvidenceInput {
                requested_model: Some("gpt-5.6-sol"),
                requested_effort: Some("high"),
                rollout_model: "gpt-5.6-sol",
                rollout_effort: "high",
                observed_model: "gpt-5.6-sol",
                observed_effort: "high",
                server_rerouted: None,
                usage: known_codex_usage(1_000_000, 1_000_000),
                resolution_status: "complete",
            },
        ));
        assert!(!super::worker_attempt_proven_no_environment_native_spend(
            SupervisorExecutionRuntime::NonpublishableSimulation,
            "fake",
            Some(&codex_parent_run),
            None,
        ));
    }

    #[test]
    fn persist_proven_no_environment_attributable_cost_stamps_zero_when_unset() -> Result<()> {
        let run_id = RunId::new("proven-no-environment")?;
        let (_temp, repo) = super::super::tests::injected_repository();
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            run_id.clone(),
            "maco-supervise",
        )?;
        let mut journal = None;
        let mut autonomy_kpis = AutonomyKpiCollector::default();
        let artifacts = Mutex::new(SharedSupervisorArtifacts {
            writer: &mut writer,
            journal: &mut journal,
            autonomy_kpis: &mut autonomy_kpis,
            checkpoint: None,
        });
        let mut recorded = fixture();
        recorded.run_id = run_id.as_str().to_string();
        recorded.costs.environment_cost_microunits = None;
        persist_proven_no_environment_attributable_cost(&artifacts, &mut recorded)?;
        assert_eq!(recorded.costs.environment_cost_microunits, Some(0));
        Ok(())
    }

    #[test]
    fn record_child_attempt_outcome_stamps_environment_zero_for_fake_nonpublishable_simulation(
    ) -> Result<()> {
        let (temp, repo) = super::super::tests::injected_repository();
        let command = injected_parent_command(&temp, &repo);
        let fake_run = super::super::reporting::deterministic_fake_run(
            &command,
            br#"{"accepted":true}"#.to_vec(),
        );
        assert!(fake_run.process_tree.is_none());
        let run_id = RunId::new("fake-nonpublishable-environment")?;
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            run_id.clone(),
            "maco-supervise",
        )?;
        let mut journal = None;
        let mut autonomy_kpis = AutonomyKpiCollector::default();
        let artifacts = Mutex::new(SharedSupervisorArtifacts {
            writer: &mut writer,
            journal: &mut journal,
            autonomy_kpis: &mut autonomy_kpis,
            checkpoint: None,
        });
        let recorded = record_child_attempt_outcome(
            &artifacts,
            &run_id,
            "assignment-1",
            1,
            AgentRole::Worker,
            &[],
            &[],
            "fake",
            None,
            None,
            false,
            false,
            SupervisorExecutionRuntime::NonpublishableSimulation,
            Some(&fake_run),
            &BTreeMap::new(),
            None,
        )?;
        assert_eq!(recorded.costs.environment_cost_microunits, Some(0));
        Ok(())
    }

    fn record_verified_attempt_with_account_observe(
        run_name: &str,
        account_observe: Option<(AccountObserveOutcomeKind, Option<u64>)>,
    ) -> Result<AttemptOutcomeEvidence> {
        let (_temp, repo) = super::super::tests::injected_repository();
        let run_id = RunId::new(run_name)?;
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            run_id.clone(),
            "maco-supervise",
        )?;
        let mut journal = None;
        let mut autonomy_kpis = AutonomyKpiCollector::default();
        let artifacts = Mutex::new(SharedSupervisorArtifacts {
            writer: &mut writer,
            journal: &mut journal,
            autonomy_kpis: &mut autonomy_kpis,
            checkpoint: None,
        });
        record_child_attempt_outcome_with_account_observe(
            &artifacts,
            &run_id,
            "assignment-1",
            1,
            AgentRole::Worker,
            &[],
            &[],
            "grok",
            Some("grok-code-fast-1"),
            Some("high"),
            true,
            false,
            SupervisorExecutionRuntime::Verified,
            None,
            &BTreeMap::new(),
            None,
            account_observe,
        )
    }

    #[test]
    fn failed_or_unknown_account_observe_cannot_become_environment_zero() -> Result<()> {
        for (run_name, kind, number) in [
            (
                "failed-observe-supplied-zero",
                AccountObserveOutcomeKind::Failed,
                Some(0),
            ),
            (
                "unknown-observe-supplied-zero",
                AccountObserveOutcomeKind::Unknown,
                Some(0),
            ),
        ] {
            let recorded =
                record_verified_attempt_with_account_observe(run_name, Some((kind, number)))?;
            assert!(
                recorded.costs.environment_cost_microunits.is_none(),
                "{kind:?} with {number:?} must stay None"
            );
        }
        Ok(())
    }

    #[test]
    fn observed_account_observe_without_a_number_stays_none() -> Result<()> {
        let recorded = record_verified_attempt_with_account_observe(
            "observed-observe-missing-number",
            Some((AccountObserveOutcomeKind::Observed, None)),
        )?;
        assert!(recorded.costs.environment_cost_microunits.is_none());
        Ok(())
    }

    #[test]
    fn record_child_attempt_outcome_leaves_environment_none_for_trusted_grok_parent_run(
    ) -> Result<()> {
        let (temp, repo) = super::super::tests::injected_repository();
        let external_run = parent_run_with_trusted_acp(
            &temp,
            &repo,
            "grok-code-fast-1",
            GrokAcpNativeCostEquivalent::Known {
                cost_usd_ticks: 1,
                microunits: 1,
            },
        );
        let (recorded, ..) =
            record_attempt_with_parent_run(Some(external_run), "trusted-grok-environment-none")?;
        assert!(recorded.costs.environment_cost_microunits.is_none());
        Ok(())
    }

    #[test]
    fn rejected_and_accepted_attempt_rows_sum_without_double_counting() -> Result<()> {
        let (temp, repo) = super::super::tests::injected_repository();
        let first_run = parent_run_with_trusted_acp(
            &temp,
            &repo,
            "grok-code-fast-1",
            GrokAcpNativeCostEquivalent::Known {
                cost_usd_ticks: 1,
                microunits: 10,
            },
        );
        let second_run = parent_run_with_trusted_acp(
            &temp,
            &repo,
            "grok-code-fast-1",
            GrokAcpNativeCostEquivalent::Known {
                cost_usd_ticks: 1,
                microunits: 20,
            },
        );
        let run_id = RunId::new("sum-phase-rows")?;
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            run_id.clone(),
            "maco-supervise",
        )?;
        let mut journal = None;
        let mut autonomy_kpis = AutonomyKpiCollector::default();
        let artifacts = Mutex::new(SharedSupervisorArtifacts {
            writer: &mut writer,
            journal: &mut journal,
            autonomy_kpis: &mut autonomy_kpis,
            checkpoint: None,
        });
        let initial = grok_worker_selection_event();
        let rejected = record_child_attempt_outcome(
            &artifacts,
            &run_id,
            "assignment-1",
            1,
            AgentRole::Worker,
            &[],
            std::slice::from_ref(&initial),
            "grok",
            Some("grok-code-fast-1"),
            Some("high"),
            true,
            true,
            SupervisorExecutionRuntime::Verified,
            Some(&first_run),
            &BTreeMap::new(),
            Some(attempt_parent_phase_continuation_from_count(Some(0))),
        )?;
        let accepted = record_child_attempt_outcome(
            &artifacts,
            &run_id,
            "assignment-1",
            2,
            AgentRole::Worker,
            &[],
            std::slice::from_ref(&initial),
            "grok",
            Some("grok-code-fast-1"),
            Some("high"),
            true,
            false,
            SupervisorExecutionRuntime::Verified,
            Some(&second_run),
            &BTreeMap::new(),
            Some(attempt_parent_phase_continuation_from_count(Some(1))),
        )?;
        let execution_total = rejected.costs.execution_cost_microunits.unwrap()
            + accepted.costs.execution_cost_microunits.unwrap();
        let rework_total = rejected.costs.rework_cost_microunits.unwrap()
            + accepted.costs.rework_cost_microunits.unwrap();
        assert_eq!(execution_total + rework_total, 30);
        assert_eq!(execution_total, 10);
        assert_eq!(rework_total, 20);
        assert_eq!(accepted.costs.rework_cost_microunits, Some(20));
        Ok(())
    }

    #[test]
    fn authenticated_reaudit_source_without_attempt_evidence_yields_unknown_history() -> Result<()>
    {
        let (_temp, repo) = super::super::tests::injected_repository();
        let run_id = RunId::new("reaudit-source-missing-proof")?;
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            run_id.clone(),
            "maco-supervise",
        )?;
        let final_relative = RunArtifactFamily::Supervise.final_report_relative_path();
        writer.write_json(
            &final_relative,
            &super::super::tests::artifact_test_final_report(&run_id),
            ArtifactFileDisposition::Publishable,
        )?;
        writer.finalize(&final_relative, false)?;
        let proof =
            authenticated_prior_dispatched_review_cycle_proof(&repo, &run_id, "assignment-1")?;
        assert_eq!(proof, ParentPriorDispatchedReviewCycleProof::Unknown);
        assert_eq!(
            review_cycle_slot_for_completed_dispatched_cycles(prior_dispatched_review_cycle_count(
                &proof
            ),),
            ParentDispatchedReviewCycleSlot::Unknown
        );
        Ok(())
    }

    #[test]
    fn child_retry_bypass_persists_proven_no_review_zeros() -> Result<()> {
        let run_id = RunId::new("child-retry-no-review")?;
        let (_temp, repo) = super::super::tests::injected_repository();
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            run_id.clone(),
            "maco-supervise",
        )?;
        let mut journal = None;
        let mut autonomy_kpis = AutonomyKpiCollector::default();
        let artifacts = Mutex::new(SharedSupervisorArtifacts {
            writer: &mut writer,
            journal: &mut journal,
            autonomy_kpis: &mut autonomy_kpis,
            checkpoint: None,
        });
        let mut recorded = fixture();
        recorded.run_id = run_id.as_str().to_string();
        recorded.costs.environment_cost_microunits = None;
        recorded.costs.review_cost_microunits = None;
        recorded.costs.rereview_cost_microunits = None;
        persist_proven_worker_attempt_bypassed_parent_review(&artifacts, &mut recorded)?;
        assert_eq!(recorded.costs.review_cost_microunits, Some(0));
        assert_eq!(recorded.costs.rereview_cost_microunits, Some(0));
        assert!(recorded.costs.environment_cost_microunits.is_none());
        Ok(())
    }

    #[test]
    fn record_child_attempt_outcome_retains_parent_codex_identity_and_execution_cost() -> Result<()>
    {
        let (temp, repo) = super::super::tests::injected_repository();
        let external_run = parent_run_with_codex_evidence(
            &temp,
            &repo,
            trusted_codex_parent_evidence(TrustedCodexParentEvidenceInput {
                requested_model: Some("gpt-5.6-sol"),
                requested_effort: Some("high"),
                rollout_model: "gpt-5.6-sol",
                rollout_effort: "high",
                observed_model: "gpt-5.6-sol",
                observed_effort: "high",
                server_rerouted: None,
                usage: known_codex_usage(1_000_000, 1_000_000),
                resolution_status: "complete",
            }),
        );
        let recorded = record_codex_attempt(
            external_run,
            "parent-codex-outcome-record",
            1,
            "gpt-5.6-sol",
            &dated_codex_plan_pricing(),
            None,
        )?;
        let observed = recorded
            .observed_candidate
            .as_ref()
            .expect("mapped observed Codex candidate");
        assert_eq!(observed.runtime, "codex");
        assert_eq!(observed.model, "gpt-5.6-sol");
        assert_eq!(observed.effort, ReasoningEffort::High);
        assert_eq!(recorded.costs.execution_cost_microunits, Some(5_000_000));
        assert_eq!(recorded.costs.rework_cost_microunits, Some(0));
        assert!(recorded.costs.environment_cost_microunits.is_none());
        assert!(project_numeric_row(&recorded).is_none());
        Ok(())
    }

    #[test]
    fn incomplete_parent_codex_rollout_missing_cannot_promote_identity_or_cost() -> Result<()> {
        let (temp, repo) = super::super::tests::injected_repository();
        let external_run = parent_run_with_codex_evidence(
            &temp,
            &repo,
            trusted_codex_parent_evidence(TrustedCodexParentEvidenceInput {
                requested_model: Some("gpt-5.6-sol"),
                requested_effort: Some("high"),
                rollout_model: "gpt-5.6-sol",
                rollout_effort: "high",
                observed_model: "gpt-5.6-sol",
                observed_effort: "high",
                server_rerouted: None,
                usage: known_codex_usage(1_000_000, 1_000_000),
                resolution_status: "rollout_missing",
            }),
        );
        let recorded = record_codex_attempt(
            external_run,
            "parent-codex-rollout-missing-record",
            1,
            "gpt-5.6-sol",
            &dated_codex_plan_pricing(),
            None,
        )?;
        assert!(recorded.observed_candidate.is_none());
        assert!(recorded.costs.execution_cost_microunits.is_none());
        Ok(())
    }

    #[test]
    fn observed_requested_codex_mismatch_is_recorded_but_not_numeric_eligible() -> Result<()> {
        let (temp, repo) = super::super::tests::injected_repository();
        let external_run = parent_run_with_codex_evidence(
            &temp,
            &repo,
            trusted_codex_parent_evidence(TrustedCodexParentEvidenceInput {
                requested_model: Some("gpt-5.6-sol"),
                requested_effort: Some("high"),
                rollout_model: "gpt-5.6-sol",
                rollout_effort: "high",
                observed_model: "gpt-5.6-luna",
                observed_effort: "high",
                server_rerouted: None,
                usage: known_codex_usage(1_000_000, 1_000_000),
                resolution_status: "complete",
            }),
        );
        let recorded = record_codex_attempt(
            external_run,
            "parent-codex-mismatch-record",
            1,
            "gpt-5.6-sol",
            &dated_codex_plan_pricing(),
            None,
        )?;
        assert_eq!(
            recorded
                .observed_candidate
                .as_ref()
                .map(|key| key.model.as_str()),
            Some("gpt-5.6-luna")
        );
        assert_eq!(recorded.costs.execution_cost_microunits, Some(1_000_000));
        assert!(project_numeric_row(&recorded).is_none());
        Ok(())
    }

    #[test]
    fn parent_codex_reroute_prices_observed_target_not_requested_or_rollout() -> Result<()> {
        let (temp, repo) = super::super::tests::injected_repository();
        let external_run = parent_run_with_codex_evidence(
            &temp,
            &repo,
            trusted_codex_parent_evidence(TrustedCodexParentEvidenceInput {
                requested_model: Some("gpt-5.6-sol"),
                requested_effort: Some("high"),
                rollout_model: "gpt-5-codex",
                rollout_effort: "high",
                observed_model: "gpt-5.6-luna",
                observed_effort: "high",
                server_rerouted: Some(CodexServerRerouteEvidence {
                    from: "gpt-5.6-sol".to_string(),
                    to: "gpt-5.6-luna".to_string(),
                }),
                usage: known_codex_usage(1_000_000, 1_000_000),
                resolution_status: "complete",
            }),
        );
        let recorded = record_codex_attempt(
            external_run,
            "parent-codex-reroute-record",
            1,
            "gpt-5.6-sol",
            &dated_codex_plan_pricing(),
            None,
        )?;
        assert_eq!(
            recorded
                .observed_candidate
                .as_ref()
                .map(|key| key.model.as_str()),
            Some("gpt-5.6-luna")
        );
        assert_eq!(recorded.costs.execution_cost_microunits, Some(1_000_000));
        assert_ne!(recorded.costs.execution_cost_microunits, Some(5_000_000));
        assert_ne!(recorded.costs.execution_cost_microunits, Some(200_000));
        Ok(())
    }

    #[test]
    fn unpriced_parent_codex_model_leaves_execution_cost_none() -> Result<()> {
        let (temp, repo) = super::super::tests::injected_repository();
        let external_run = parent_run_with_codex_evidence(
            &temp,
            &repo,
            trusted_codex_parent_evidence(TrustedCodexParentEvidenceInput {
                requested_model: Some("gpt-5.6-sol"),
                requested_effort: Some("high"),
                rollout_model: "gpt-5.6-sol",
                rollout_effort: "high",
                observed_model: "gpt-5.6-sol",
                observed_effort: "high",
                server_rerouted: None,
                usage: known_codex_usage(1_000_000, 1_000_000),
                resolution_status: "complete",
            }),
        );
        let luna_only = BTreeMap::from([(
            "gpt-5.6-luna".to_string(),
            ModelPricing {
                input_usd_per_million_tokens: 2.0,
                output_usd_per_million_tokens: 8.0,
            },
        )]);
        let recorded = record_codex_attempt(
            external_run,
            "parent-codex-unpriced-record",
            1,
            "gpt-5.6-sol",
            &luna_only,
            None,
        )?;
        assert_eq!(
            recorded
                .observed_candidate
                .as_ref()
                .map(|key| key.model.as_str()),
            Some("gpt-5.6-sol")
        );
        assert!(recorded.costs.execution_cost_microunits.is_none());
        Ok(())
    }

    #[test]
    fn zero_zero_codex_usage_is_unknown_not_zero_cost() -> Result<()> {
        let (temp, repo) = super::super::tests::injected_repository();
        let external_run = parent_run_with_codex_evidence(
            &temp,
            &repo,
            trusted_codex_parent_evidence(TrustedCodexParentEvidenceInput {
                requested_model: Some("gpt-5.6-sol"),
                requested_effort: Some("high"),
                rollout_model: "gpt-5.6-sol",
                rollout_effort: "high",
                observed_model: "gpt-5.6-sol",
                observed_effort: "high",
                server_rerouted: None,
                usage: CodexParentTurnUsage::Unknown {
                    reason: "turn.completed usage was 0/0".to_string(),
                },
                resolution_status: "complete",
            }),
        );
        let recorded = record_codex_attempt(
            external_run,
            "parent-codex-zero-zero-usage-record",
            1,
            "gpt-5.6-sol",
            &dated_codex_plan_pricing(),
            None,
        )?;
        assert!(recorded.observed_candidate.is_some());
        assert!(recorded.costs.execution_cost_microunits.is_none());
        assert_ne!(recorded.costs.execution_cost_microunits, Some(0));
        Ok(())
    }

    #[test]
    fn record_child_attempt_outcome_leaves_environment_none_for_trusted_codex_parent_run(
    ) -> Result<()> {
        let (temp, repo) = super::super::tests::injected_repository();
        let external_run = parent_run_with_codex_evidence(
            &temp,
            &repo,
            trusted_codex_parent_evidence(TrustedCodexParentEvidenceInput {
                requested_model: Some("gpt-5.6-sol"),
                requested_effort: Some("high"),
                rollout_model: "gpt-5.6-sol",
                rollout_effort: "high",
                observed_model: "gpt-5.6-sol",
                observed_effort: "high",
                server_rerouted: None,
                usage: known_codex_usage(1_000_000, 1_000_000),
                resolution_status: "complete",
            }),
        );
        let recorded = record_codex_attempt(
            external_run,
            "trusted-codex-environment-none",
            1,
            "gpt-5.6-sol",
            &dated_codex_plan_pricing(),
            None,
        )?;
        assert_eq!(recorded.costs.execution_cost_microunits, Some(5_000_000));
        assert!(recorded.costs.environment_cost_microunits.is_none());
        Ok(())
    }

    #[test]
    fn worker_retry_codex_observed_spend_attributes_to_rework_not_execution() -> Result<()> {
        let (temp, repo) = super::super::tests::injected_repository();
        let external_run = parent_run_with_codex_evidence(
            &temp,
            &repo,
            trusted_codex_parent_evidence(TrustedCodexParentEvidenceInput {
                requested_model: Some("gpt-5.6-sol"),
                requested_effort: Some("high"),
                rollout_model: "gpt-5.6-sol",
                rollout_effort: "high",
                observed_model: "gpt-5.6-sol",
                observed_effort: "high",
                server_rerouted: None,
                usage: known_codex_usage(1_000_000, 1_000_000),
                resolution_status: "complete",
            }),
        );
        let recorded = record_codex_attempt(
            external_run,
            "worker-codex-rework-phase",
            2,
            "gpt-5.6-sol",
            &dated_codex_plan_pricing(),
            Some(attempt_parent_phase_continuation_from_count(Some(0))),
        )?;
        assert_eq!(recorded.costs.execution_cost_microunits, Some(0));
        assert_eq!(recorded.costs.rework_cost_microunits, Some(5_000_000));
        assert!(recorded.costs.environment_cost_microunits.is_none());
        Ok(())
    }
}
