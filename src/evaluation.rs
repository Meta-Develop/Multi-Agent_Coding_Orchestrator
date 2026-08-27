//! Provisional, deterministic model-mix evaluation over hand-authored plans.
//!
//! Phase A deliberately executes only synthetic fixtures. The resulting documents are useful for
//! developing comparison tooling, but their schema makes them ineligible as production model
//! economics or as evidence for a named default.

use crate::{
    artifacts::state_auth::sha256_hex,
    autopilot::{AutopilotProfileBindingReport, AutopilotProfileBindingStatus},
    llm::provider::Usage,
    objective_profile::{
        default_resolved_objective_profile, select_from_frontier, FrontierAxes,
        ObjectiveProfileBinding, ObjectiveSelection, ResolvedObjectiveProfile,
    },
    supervise::{
        AgentRole, Finding, FindingSeverity, ProcessObservation, RoleBindingObservation,
        RoleEconomicsProfile, RoleModelSelection, RoleUsageObservation, RoleUsageReport,
        RuntimeModelCatalogObservation, UnavailableModelFallback,
    },
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::PathBuf,
};
use thiserror::Error;

pub const EVALUATION_MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const EVALUATION_RESULTS_SCHEMA_VERSION: u32 = 4;
pub const LEGACY_EVALUATION_RESULTS_SCHEMA_VERSION: u32 = 2;
pub const PRE_OBJECTIVE_SELECTION_RESULTS_SCHEMA_VERSION: u32 = 3;
pub const CONSUMED_SUPERVISOR_EXECUTION_TELEMETRY_SCHEMA_VERSION: u32 = 2;
pub const MAX_EVALUATION_HELD_OUT_VALIDATIONS: usize = 32;
pub const MAX_EVALUATION_PROFILES: usize = 32;
pub const MAX_EVALUATION_REPETITIONS: u32 = 100;
pub const MAX_EXECUTION_ERROR_EVIDENCE_BYTES: usize = 256;
pub const COMMITTED_FIXTURE_FAKE_SEED: u64 = 26;
pub const PROVISIONAL_FAKE_EVIDENCE_NOTICE: &str = "provisional deterministic fake evidence over \
     a hand-authored plan; no isolated repository state was observed, so Issue #26 requirement-4 \
     comparability is not established and is deferred to Phase B; ineligible for production or \
     default decisions";
pub const DISPATCH_COMPARABILITY_NOTICE: &str = "comparison is scoped to MACO-dispatched model \
     selections; it does not establish that the provider executed profiles differently";

const BASIS_POINTS: u32 = 10_000;

/// A reproducible target for an early evaluation over a hand-authored supervisor plan.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationTarget {
    /// Stable human-readable identifier for the spec or goal.
    pub spec_or_goal_id: String,
    /// Digest of the immutable spec/goal content used by every run.
    pub spec_or_goal_digest: String,
    /// Digest of the hand-authored plan used by every run.
    pub hand_authored_plan_digest: String,
}

/// Declared limits used consistently by every synthetic run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationLimits {
    pub wall_time_seconds: u64,
    pub max_dispatches: u32,
}

/// A held-out command binding. Phase A records deterministic fake observations and never executes
/// this command.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeldOutValidation {
    pub id: String,
    pub command: Vec<String>,
}

/// A candidate role/model mix.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationProfile {
    pub id: String,
    #[serde(deserialize_with = "deserialize_role_models")]
    pub role_models: BTreeMap<AgentRole, RoleModelSelection>,
}

/// Versioned input schema for a controlled model-mix experiment.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationManifest {
    pub version: u32,
    pub experiment_id: String,
    pub evidence: EvaluationEvidence,
    pub target: EvaluationTarget,
    /// A full Git object id (SHA-1 or SHA-256) for the common repository base.
    pub repository_base_snapshot: String,
    pub limits: EvaluationLimits,
    pub held_out_validation: Vec<HeldOutValidation>,
    pub repetitions: u32,
    pub profiles: Vec<EvaluationProfile>,
    /// One canonical resolved objective consumed by quality scoring and the
    /// post-frontier selection policy. Historical manifests omit it and use
    /// the built-in 50/25/25 profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub objective_profile: Option<ResolvedObjectiveProfile>,
}

impl EvaluationManifest {
    /// Validate the declared Phase-A fake-fixture inputs.
    pub fn validate(&self) -> Result<(), EvaluationError> {
        if self.version != EVALUATION_MANIFEST_SCHEMA_VERSION {
            return Err(EvaluationError::UnsupportedManifestVersion {
                found: self.version,
                supported: EVALUATION_MANIFEST_SCHEMA_VERSION,
            });
        }
        require_nonempty("experiment_id", &self.experiment_id)?;
        if self.evidence != EvaluationEvidence::provisional_fake_only() {
            return Err(invalid_manifest(
                "evidence",
                "manifest must carry the exact provisional fake-only, hand-authored-plan, \
                 Phase-B-deferred declaration",
            ));
        }
        require_nonempty("target.spec_or_goal_id", &self.target.spec_or_goal_id)?;
        require_digest(
            "target.spec_or_goal_digest",
            &self.target.spec_or_goal_digest,
        )?;
        require_digest(
            "target.hand_authored_plan_digest",
            &self.target.hand_authored_plan_digest,
        )?;
        require_git_object_id("repository_base_snapshot", &self.repository_base_snapshot)?;
        if self.limits.wall_time_seconds == 0 {
            return Err(invalid_manifest(
                "limits.wall_time_seconds",
                "must be greater than zero",
            ));
        }
        if self.limits.max_dispatches == 0 {
            return Err(invalid_manifest(
                "limits.max_dispatches",
                "must be greater than zero",
            ));
        }
        if self.repetitions == 0 || self.repetitions > MAX_EVALUATION_REPETITIONS {
            return Err(invalid_manifest(
                "repetitions",
                format!(
                    "must be between 1 and {MAX_EVALUATION_REPETITIONS}, got {}",
                    self.repetitions
                ),
            ));
        }
        if self.profiles.len() > MAX_EVALUATION_PROFILES {
            return Err(invalid_manifest(
                "profiles",
                format!(
                    "must contain at most {MAX_EVALUATION_PROFILES} profiles, got {}",
                    self.profiles.len()
                ),
            ));
        }
        if self.held_out_validation.len() > MAX_EVALUATION_HELD_OUT_VALIDATIONS {
            return Err(invalid_manifest(
                "held_out_validation",
                format!(
                    "must contain at most {MAX_EVALUATION_HELD_OUT_VALIDATIONS} validations, got {}",
                    self.held_out_validation.len()
                ),
            ));
        }
        validate_held_out_bindings(&self.held_out_validation)?;
        validate_profiles(&self.profiles)?;
        self.resolved_objective_profile()?;
        Ok(())
    }

    fn resolved_objective_profile(&self) -> Result<ResolvedObjectiveProfile, EvaluationError> {
        let profile = match &self.objective_profile {
            Some(profile) => profile.clone(),
            None => default_resolved_objective_profile()
                .map_err(|error| invalid_manifest("objective_profile", error.to_string()))?,
        };
        profile
            .profile
            .validate()
            .map_err(|error| invalid_manifest("objective_profile", error.to_string()))?;
        Ok(profile)
    }

    /// Verify that supplied bytes are a labelled hand-authored plan exactly bound by this
    /// manifest.
    fn validate_hand_authored_plan(&self, plan: &[u8]) -> Result<(), EvaluationError> {
        let observed = format!("sha256:{}", sha256_hex(plan));
        if self.target.hand_authored_plan_digest != observed {
            return Err(EvaluationError::HandAuthoredPlanBindingMismatch {
                expected: self.target.hand_authored_plan_digest.clone(),
                observed,
            });
        }

        let document = serde_json::from_slice::<Value>(plan).map_err(|error| {
            EvaluationError::InvalidHandAuthoredPlan {
                message: format!("must be valid JSON: {error}"),
            }
        })?;
        let object =
            document
                .as_object()
                .ok_or_else(|| EvaluationError::InvalidHandAuthoredPlan {
                    message: "must be a JSON object".to_string(),
                })?;
        let evidence =
            object
                .get("evidence")
                .ok_or_else(|| EvaluationError::InvalidHandAuthoredPlan {
                    message: "must contain an evidence declaration".to_string(),
                })?;
        let evidence =
            serde_json::from_value::<EvaluationEvidence>(evidence.clone()).map_err(|error| {
                EvaluationError::InvalidHandAuthoredPlan {
                    message: format!("contains an invalid evidence declaration: {error}"),
                }
            })?;
        if evidence != EvaluationEvidence::provisional_fake_only() {
            return Err(EvaluationError::InvalidHandAuthoredPlan {
                message: "must carry the exact provisional fake-only, hand-authored-plan, \
                          Phase-B-deferred declaration"
                    .to_string(),
            });
        }
        Ok(())
    }

    fn declared_inputs_binding(
        &self,
        objective_profile: Option<ResolvedObjectiveProfile>,
    ) -> DeclaredInputsBinding {
        DeclaredInputsBinding {
            target: self.target.clone(),
            repository_base_snapshot: self.repository_base_snapshot.clone(),
            limits: self.limits,
            held_out_validation: self.held_out_validation.clone(),
            profiles: self.profiles.clone(),
            objective_profile,
        }
    }
}

/// Execution request. Real-provider execution has two separate fail-closed gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationRunRequest {
    pub execution: EvaluationExecution,
    /// Must be true before any future implementation may enter a real-provider path.
    pub allow_real_provider: bool,
    /// Stable seed for deterministic fake fixtures.
    pub fake_seed: u64,
}

impl Default for EvaluationRunRequest {
    fn default() -> Self {
        Self {
            execution: EvaluationExecution::DeterministicFake,
            allow_real_provider: false,
            fake_seed: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationExecution {
    #[default]
    DeterministicFake,
    RealProvider,
}

/// Schema-level evidence classification. No phase-A result can represent real-provider evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationEvidenceKind {
    ProvisionalDeterministicFakeOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationPlanBasis {
    HandAuthored,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequirementFourComparability {
    NotEstablishedDeferredToPhaseB,
    DispatchGroundedSelectionsDiffer,
    DispatchGroundedSelectionsEquivalent,
    Incomparable,
}

/// The strongest claim supported by the landed profile-observation channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationComparabilityScope {
    Dispatch,
}

/// Mandatory claim boundary carried by every result and summary document.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchComparabilityClaim {
    pub scope: EvaluationComparabilityScope,
    pub provider_execution_difference_established: bool,
    pub notice: String,
}

impl DispatchComparabilityClaim {
    fn dispatch_only() -> Self {
        Self {
            scope: EvaluationComparabilityScope::Dispatch,
            provider_execution_difference_established: false,
            notice: DISPATCH_COMPARABILITY_NOTICE.to_string(),
        }
    }

    fn validate(&self) -> Result<(), EvaluationError> {
        if self != &Self::dispatch_only() {
            return Err(invalid_results(
                "dispatch_comparability_claim",
                "must state the exact dispatch-only claim and must not claim provider-execution differentiation",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationEvidence {
    pub kind: EvaluationEvidenceKind,
    pub plan_basis: EvaluationPlanBasis,
    pub real_provider_executed: bool,
    pub observed_isolated_repository_state: bool,
    pub requirement_four_comparability: RequirementFourComparability,
    pub eligible_for_production_economics: bool,
    pub eligible_to_justify_named_default: bool,
    pub eligible_for_production_or_default_decisions: bool,
    pub notice: String,
}

impl EvaluationEvidence {
    fn provisional_fake_only() -> Self {
        Self {
            kind: EvaluationEvidenceKind::ProvisionalDeterministicFakeOnly,
            plan_basis: EvaluationPlanBasis::HandAuthored,
            real_provider_executed: false,
            observed_isolated_repository_state: false,
            requirement_four_comparability:
                RequirementFourComparability::NotEstablishedDeferredToPhaseB,
            eligible_for_production_economics: false,
            eligible_to_justify_named_default: false,
            eligible_for_production_or_default_decisions: false,
            notice: PROVISIONAL_FAKE_EVIDENCE_NOTICE.to_string(),
        }
    }

    fn validate(&self) -> Result<(), EvaluationError> {
        let expected = Self::provisional_fake_only();
        if self != &expected {
            return Err(invalid_results(
                "evidence",
                "phase-A results must carry the exact provisional fake-only, hand-authored-plan, \
                 Phase-B-deferred evidence declaration",
            ));
        }
        Ok(())
    }
}

/// Declared inputs which must remain internally consistent across the synthetic fixture.
///
/// This is not an observed repository-state fingerprint and does not establish Issue #26
/// requirement-4 comparability.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredInputsBinding {
    pub target: EvaluationTarget,
    pub repository_base_snapshot: String,
    pub limits: EvaluationLimits,
    pub held_out_validation: Vec<HeldOutValidation>,
    pub profiles: Vec<EvaluationProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub objective_profile: Option<ResolvedObjectiveProfile>,
}

/// A unique identity for one synthetic repetition.
///
/// This identity does not claim that a repository or isolated workspace existed.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SyntheticRunIdentity {
    /// Unique deterministic fixture identity. Reusing one identity across repetitions fails
    /// validation.
    pub fake_run_id: String,
}

/// A dispatch-observed role selection copied from the A4 execution binding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedRoleDispatch {
    pub role: AgentRole,
    pub models: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<String>,
}

/// A dispatch-observed review-lens selection copied from parent-recorded argv evidence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedReviewLensDispatch {
    pub lens_id: String,
    pub backend_id: String,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<String>,
    pub dispatch_count: usize,
}

/// Canonical role binding retained from supervisor execution telemetry.
///
/// Configured selections are deliberately excluded: an unresolved runtime selection must remain
/// unresolved rather than being reconstructed from the plan.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedSupervisorRoleBinding {
    pub role: AgentRole,
    pub resolved_model: Option<String>,
    pub resolved_reasoning_effort: Option<String>,
    pub observation: RoleBindingObservation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
}

/// Scheduler-observed fan-out for one supervisor run.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedSupervisorConcurrency {
    pub configured_max_concurrent_children: usize,
    pub policy_input_observation: ProcessObservation,
    pub policy_input: Option<String>,
    pub policy_input_unavailable_reason: Option<String>,
    pub achieved_max_concurrent_children: usize,
    pub achieved_mean_concurrent_children: Option<f64>,
    pub achieved_mean_observation: ProcessObservation,
    pub achieved_mean_unavailable_reason: Option<String>,
}

/// Aggregate process usage retained by the supervisor.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedSupervisorUsage {
    #[serde(default, deserialize_with = "deserialize_optional_usage")]
    pub total_usage: Option<Usage>,
    pub total_cost_usd: Option<f64>,
    pub usage_complete: bool,
    pub observation: RoleUsageObservation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
}

/// Normalized execution metadata consumed from `supervisor-final.json` economics schema v2.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedSupervisorExecution {
    pub schema_version: u32,
    pub model_catalog_observation: RuntimeModelCatalogObservation,
    pub assignment_count: usize,
    pub started_assignment_count: usize,
    pub completed_assignment_count: usize,
    pub concurrency: ObservedSupervisorConcurrency,
    pub role_bindings: Vec<ObservedSupervisorRoleBinding>,
    pub usage: ObservedSupervisorUsage,
}

/// Comparison of the supervisor-recorded execution/economics axis.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionTelemetryComparability {
    Equivalent,
    Different,
    #[default]
    Incomparable,
}

/// Normalized observed dispatch record for one profile repetition.
///
/// No requested, effective, or manifest selection is copied into this record.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedDispatchRecord {
    pub roles: Vec<ObservedRoleDispatch>,
    pub review_lenses: Vec<ObservedReviewLensDispatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supervisor_execution: Option<ObservedSupervisorExecution>,
}

/// Same-repetition comparison between two profile runs.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchComparison {
    pub left_profile_id: String,
    pub right_profile_id: String,
    pub repetition: u32,
    pub comparability: RequirementFourComparability,
    #[serde(default)]
    pub execution_telemetry_comparability: ExecutionTelemetryComparability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
}

/// Direct Phase-A comparison of two supervisor run artifacts.
///
/// This is execution-provenance plumbing only. It carries the existing dispatch-only claim
/// boundary and does not make a real-provider or isolated-repository evidence claim.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorArtifactComparison {
    pub dispatch_comparability_claim: DispatchComparabilityClaim,
    pub comparability: RequirementFourComparability,
    pub execution_telemetry_comparability: ExecutionTelemetryComparability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
}

/// Whether a cost-versus-quality Pareto conclusion is licensed by the evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ParetoConclusionStatus {
    Available,
    RefusedIncomparableDispatchEvidence,
    RefusedNoDispatchDifference,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ParetoConclusion {
    pub status: ParetoConclusionStatus,
    pub claim: DispatchComparabilityClaim,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeldOutValidationResult {
    pub id: String,
    pub assertions_run: u32,
    pub assertions_passed: u32,
    pub passed: bool,
}

/// Counted evidence for one indispensable quality dimension.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewDimension {
    pub checks_run: u32,
    pub checks_passed: u32,
}

/// Review signals deliberately separate breadth and anti-shortcut checks.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewQuality {
    pub breadth: ReviewDimension,
    pub anti_shortcut: ReviewDimension,
    #[serde(deserialize_with = "deserialize_findings")]
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualityScore {
    pub held_out_basis_points: u32,
    pub breadth_basis_points: u32,
    pub anti_shortcut_basis_points: u32,
    pub overall_basis_points: u32,
}

/// An exact arithmetic mean represented as a rational value.
///
/// JSON consumers can compare or render `total / count` without relying on lossy integer division
/// or binary floating-point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreciseMean {
    pub total: u64,
    pub count: u32,
}

impl PreciseMean {
    pub(crate) fn new(total: u64, count: u32) -> Result<Self, EvaluationError> {
        if count == 0 {
            return Err(invalid_results(
                "profile_summaries",
                "precise mean count must be greater than zero",
            ));
        }
        Ok(Self { total, count })
    }

    fn cmp_value(&self, other: &Self) -> std::cmp::Ordering {
        (u128::from(self.total) * u128::from(other.count))
            .cmp(&(u128::from(other.total) * u128::from(self.count)))
    }
}

/// Exact per-component mean quality over all repetitions, including unsuccessful ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreciseQualityScore {
    pub held_out_basis_points: PreciseMean,
    pub breadth_basis_points: PreciseMean,
    pub anti_shortcut_basis_points: PreciseMean,
    pub overall_basis_points: PreciseMean,
}

/// Outcome of one phase-A deterministic fake repetition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationExecutionOutcome {
    Success,
    Failure,
    Timeout,
}

/// Bounded, synthetic error evidence for an unsuccessful repetition.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionErrorEvidence {
    pub message: String,
    /// True when the producer omitted trailing detail to satisfy the schema's byte bound.
    pub truncated: bool,
}

/// Observable execution state retained for every repetition, successful or otherwise.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepetitionExecution {
    pub observed_dispatch_count: u32,
    pub outcome: EvaluationExecutionOutcome,
    pub error_evidence: Option<ExecutionErrorEvidence>,
}

/// Complete observation for one profile repetition.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationMetrics {
    #[serde(deserialize_with = "deserialize_role_usage")]
    pub role_usage: BTreeMap<AgentRole, RoleUsageReport>,
    #[serde(deserialize_with = "deserialize_usage")]
    pub total_usage: Usage,
    pub total_cost_usd: f64,
    pub wall_time_ms: u64,
    pub churn_count: u64,
    pub conflict_count: u64,
    pub loc_added: u64,
    pub loc_deleted: u64,
    pub diff_bytes: u64,
    pub held_out_validation: Vec<HeldOutValidationResult>,
    pub review: ReviewQuality,
    pub quality: QualityScore,
}

/// One synthetic fixture repetition with no repository-isolation claim.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationRepetitionResult {
    pub profile_id: String,
    pub repetition: u32,
    pub declared_inputs_digest: String,
    pub synthetic_run_identity: SyntheticRunIdentity,
    pub execution: RepetitionExecution,
    pub metrics: EvaluationMetrics,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_dispatch: Option<ObservedDispatchRecord>,
}

/// Per-profile aggregate. Role usage and cost are totals; other numeric fields are arithmetic
/// means over repetitions.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSummary {
    pub profile_id: String,
    pub repetitions: u32,
    #[serde(deserialize_with = "deserialize_role_usage")]
    pub aggregate_role_usage: BTreeMap<AgentRole, RoleUsageReport>,
    #[serde(deserialize_with = "deserialize_usage")]
    pub aggregate_usage: Usage,
    pub aggregate_cost_usd: f64,
    pub mean_cost_usd: f64,
    pub mean_wall_time_ms: PreciseMean,
    pub mean_churn_count: PreciseMean,
    pub mean_conflict_count: PreciseMean,
    /// Typed human-review-load observation (finding count) recorded from live
    /// evaluation runs. Historical summaries omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mean_review_findings: Option<PreciseMean>,
    pub mean_loc_added: PreciseMean,
    pub mean_loc_deleted: PreciseMean,
    pub mean_diff_bytes: PreciseMean,
    pub mean_quality: PreciseQualityScore,
    pub pareto_optimal: bool,
}

/// Durable raw quality and typed operational coordinates for a non-dominated profile.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ParetoPoint {
    pub profile_id: String,
    pub mean_cost_usd: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mean_quota_consumption_tokens: Option<PreciseMean>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mean_wall_time_ms: Option<PreciseMean>,
    pub quality_basis_points: PreciseMean,
    pub held_out_basis_points: PreciseMean,
    pub breadth_basis_points: PreciseMean,
    pub anti_shortcut_basis_points: PreciseMean,
}

/// The applied objective is the experiment's original policy. Historical
/// rescoring requires an owned CLI/API consumer and is intentionally not
/// represented until that end-to-end path exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectiveScoringKind {
    Original,
}

/// Durable scoring provenance for one evaluation document.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectiveScoringProvenance {
    pub kind: ObjectiveScoringKind,
    pub applied_profile: ResolvedObjectiveProfile,
}

impl ObjectiveScoringProvenance {
    fn original(applied_profile: ResolvedObjectiveProfile) -> Self {
        Self {
            kind: ObjectiveScoringKind::Original,
            applied_profile,
        }
    }

    fn validate(&self) -> Result<(), EvaluationError> {
        self.applied_profile
            .profile
            .validate()
            .map_err(|error| invalid_results("objective_scoring", error.to_string()))?;
        Ok(())
    }
}

/// Versioned objective evidence. Schema v4 writes `Scored`; v2/v3 fixtures
/// remain readable through the single legacy alternative.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EvaluationObjectiveEvidence {
    Scored(ObjectiveScoringProvenance),
    Legacy(Option<ObjectiveProfileBinding>),
}

impl Default for EvaluationObjectiveEvidence {
    fn default() -> Self {
        Self::Legacy(None)
    }
}

/// Versioned, machine-readable result schema.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationResults {
    pub version: u32,
    pub manifest_version: u32,
    pub experiment_id: String,
    /// Stable seed used by the deterministic fake harness.
    pub fake_seed: u64,
    pub evidence: EvaluationEvidence,
    pub declared_inputs: DeclaredInputsBinding,
    pub declared_inputs_digest: String,
    pub dispatch_comparability_claim: DispatchComparabilityClaim,
    pub runs: Vec<EvaluationRepetitionResult>,
    pub dispatch_comparisons: Vec<DispatchComparison>,
    pub profile_summaries: Vec<ProfileSummary>,
    pub pareto_conclusion: ParetoConclusion,
    pub pareto_frontier: Vec<ParetoPoint>,
    #[serde(default, alias = "objective_profile")]
    pub objective_scoring: EvaluationObjectiveEvidence,
    #[serde(default)]
    pub objective_selection: Option<ObjectiveSelection>,
}

impl EvaluationResults {
    /// Revalidate declared-input consistency, synthetic observations, aggregates, and the Pareto
    /// projection against the manifest.
    pub fn validate_against(&self, manifest: &EvaluationManifest) -> Result<(), EvaluationError> {
        validate_results_against_manifest(manifest, self)
    }

    /// Build the strict aggregate projection stored beside committed run fixtures.
    pub fn summary(&self) -> EvaluationSummary {
        EvaluationSummary {
            version: self.version,
            manifest_version: self.manifest_version,
            experiment_id: self.experiment_id.clone(),
            fake_seed: self.fake_seed,
            evidence: self.evidence.clone(),
            declared_inputs_digest: self.declared_inputs_digest.clone(),
            dispatch_comparability_claim: self.dispatch_comparability_claim.clone(),
            dispatch_comparisons: self.dispatch_comparisons.clone(),
            profile_summaries: self.profile_summaries.clone(),
            pareto_conclusion: self.pareto_conclusion.clone(),
            pareto_frontier: self.pareto_frontier.clone(),
            objective_scoring: self.objective_scoring.clone(),
            objective_selection: self.objective_selection.clone(),
        }
    }
}

/// Strict aggregate projection of one evaluation result set.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationSummary {
    pub version: u32,
    pub manifest_version: u32,
    pub experiment_id: String,
    pub fake_seed: u64,
    pub evidence: EvaluationEvidence,
    pub declared_inputs_digest: String,
    pub dispatch_comparability_claim: DispatchComparabilityClaim,
    pub dispatch_comparisons: Vec<DispatchComparison>,
    pub profile_summaries: Vec<ProfileSummary>,
    pub pareto_conclusion: ParetoConclusion,
    pub pareto_frontier: Vec<ParetoPoint>,
    #[serde(default, alias = "objective_profile")]
    pub objective_scoring: EvaluationObjectiveEvidence,
    #[serde(default)]
    pub objective_selection: Option<ObjectiveSelection>,
}

impl EvaluationSummary {
    /// Verify that this summary is the exact aggregate projection of validated results.
    pub fn validate_against(
        &self,
        manifest: &EvaluationManifest,
        results: &EvaluationResults,
    ) -> Result<(), EvaluationError> {
        results.validate_against(manifest)?;
        self.evidence.validate()?;
        if !evaluation_summaries_equivalent(self, &results.summary()) {
            return Err(invalid_results(
                "summary",
                "does not exactly project the validated result aggregates and Pareto frontier",
            ));
        }
        Ok(())
    }
}

// Shared supervision/accounting types intentionally remain backward-compatible and permissive.
// Evaluation documents use strict local wire boundaries so their nested schemas still fail closed
// without changing those shared APIs.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictRoleModelSelection {
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    reasoning_effort: Option<String>,
    #[serde(default)]
    unavailable_model_fallback: UnavailableModelFallback,
}

impl From<StrictRoleModelSelection> for RoleModelSelection {
    fn from(selection: StrictRoleModelSelection) -> Self {
        Self {
            model: selection.model,
            reasoning_effort: selection.reasoning_effort,
            unavailable_model_fallback: selection.unavailable_model_fallback,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictUsage {
    input_tokens: usize,
    output_tokens: usize,
    total_tokens: usize,
}

impl From<StrictUsage> for Usage {
    fn from(usage: StrictUsage) -> Self {
        Self {
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
            total_tokens: usage.total_tokens,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictRoleUsageReport {
    #[serde(default)]
    models: Vec<String>,
    #[serde(default)]
    usage: Option<StrictUsage>,
    #[serde(default)]
    cost_usd: Option<f64>,
    #[serde(default)]
    observation: RoleUsageObservation,
    #[serde(default)]
    unavailable_reason: Option<String>,
}

impl From<StrictRoleUsageReport> for RoleUsageReport {
    fn from(report: StrictRoleUsageReport) -> Self {
        Self {
            models: report.models,
            usage: report.usage.map(Usage::from),
            cost_usd: report.cost_usd,
            observation: report.observation,
            unavailable_reason: report.unavailable_reason,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictFinding {
    severity: FindingSeverity,
    message: String,
    #[serde(default)]
    paths: Vec<PathBuf>,
}

impl From<StrictFinding> for Finding {
    fn from(finding: StrictFinding) -> Self {
        Self {
            severity: finding.severity,
            message: finding.message,
            paths: finding.paths,
        }
    }
}

fn deserialize_role_models<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<AgentRole, RoleModelSelection>, D::Error>
where
    D: Deserializer<'de>,
{
    BTreeMap::<AgentRole, StrictRoleModelSelection>::deserialize(deserializer).map(|selections| {
        selections
            .into_iter()
            .map(|(role, selection)| (role, selection.into()))
            .collect()
    })
}

fn deserialize_usage<'de, D>(deserializer: D) -> Result<Usage, D::Error>
where
    D: Deserializer<'de>,
{
    StrictUsage::deserialize(deserializer).map(Usage::from)
}

fn deserialize_optional_usage<'de, D>(deserializer: D) -> Result<Option<Usage>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<StrictUsage>::deserialize(deserializer).map(|usage| usage.map(Usage::from))
}

fn deserialize_role_usage<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<AgentRole, RoleUsageReport>, D::Error>
where
    D: Deserializer<'de>,
{
    BTreeMap::<AgentRole, StrictRoleUsageReport>::deserialize(deserializer).map(|reports| {
        reports
            .into_iter()
            .map(|(role, report)| (role, report.into()))
            .collect()
    })
}

fn deserialize_findings<'de, D>(deserializer: D) -> Result<Vec<Finding>, D::Error>
where
    D: Deserializer<'de>,
{
    Vec::<StrictFinding>::deserialize(deserializer)
        .map(|findings| findings.into_iter().map(Finding::from).collect())
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EvaluationError {
    #[error("unsupported evaluation manifest version {found}; supported version is {supported}")]
    UnsupportedManifestVersion { found: u32, supported: u32 },
    #[error("unsupported evaluation results version {found}; supported version is {supported}")]
    UnsupportedResultsVersion { found: u32, supported: u32 },
    #[error("invalid evaluation manifest field '{field}': {message}")]
    InvalidManifest { field: String, message: String },
    #[error("invalid evaluation results field '{field}': {message}")]
    InvalidResults { field: String, message: String },
    #[error(
        "supplied hand-authored plan bytes do not match the manifest binding; expected {expected}, observed {observed}"
    )]
    HandAuthoredPlanBindingMismatch { expected: String, observed: String },
    #[error("invalid supplied hand-authored plan: {message}")]
    InvalidHandAuthoredPlan { message: String },
    #[error(
        "real-provider evaluation requires explicit allow_real_provider=true; no provider was run"
    )]
    RealProviderOptInRequired,
    #[error(
        "real-provider evaluation is unavailable in phase A even with explicit opt-in; use deterministic_fake or a later real-provider harness"
    )]
    RealProviderUnavailableInPhaseA,
    #[error("evaluation arithmetic overflow while aggregating {context}")]
    ArithmeticOverflow { context: String },
    #[error("failed to serialize the declared-input binding: {message}")]
    DeclaredInputsSerialization { message: String },
    #[error("invalid gate-policy corpus field '{field}': {message}")]
    InvalidGatePolicyCorpus { field: String, message: String },
    #[error("unsupported evaluation experiment manifest version {found}; supported version is {supported}")]
    UnsupportedExperimentManifestVersion { found: u32, supported: u32 },
    #[error("fake supervise experiment failed: {message}")]
    FakeSuperviseExperiment { message: String },
}

/// Run a manifest-bound evaluation request.
///
/// The supplied plan bytes are parsed, checked for the exact provisional declaration, and matched
/// to the manifest digest before either fake or future real-provider dispatch can be selected.
/// Phase A only permits deterministic fake execution.
pub fn run_evaluation(
    manifest: &EvaluationManifest,
    hand_authored_plan: &[u8],
    request: EvaluationRunRequest,
) -> Result<EvaluationResults, EvaluationError> {
    manifest.validate()?;
    manifest.validate_hand_authored_plan(hand_authored_plan)?;
    match request.execution {
        EvaluationExecution::DeterministicFake => {
            run_deterministic_fake(manifest, request.fake_seed)
        }
        EvaluationExecution::RealProvider if !request.allow_real_provider => {
            Err(EvaluationError::RealProviderOptInRequired)
        }
        EvaluationExecution::RealProvider => Err(EvaluationError::RealProviderUnavailableInPhaseA),
    }
}

/// Execute deterministic fake repetitions after the public runner has bound the supplied plan.
/// This function never invokes a provider or a command.
fn run_deterministic_fake(
    manifest: &EvaluationManifest,
    seed: u64,
) -> Result<EvaluationResults, EvaluationError> {
    let objective_profile = manifest.resolved_objective_profile()?;
    let declared_inputs = manifest.declared_inputs_binding(Some(objective_profile.clone()));
    let declared_inputs_digest = digest_serializable(&declared_inputs)?;
    let mut runs = Vec::with_capacity(
        manifest
            .profiles
            .len()
            .checked_mul(manifest.repetitions as usize)
            .ok_or_else(|| overflow("run capacity"))?,
    );

    for profile in &manifest.profiles {
        let profile_fingerprint = profile_fingerprint(profile);
        for repetition in 0..manifest.repetitions {
            let (execution, metrics) = fake_metrics(
                manifest,
                profile,
                &objective_profile,
                &profile_fingerprint,
                repetition,
                seed,
            )?;
            runs.push(EvaluationRepetitionResult {
                profile_id: profile.id.clone(),
                repetition,
                declared_inputs_digest: declared_inputs_digest.clone(),
                synthetic_run_identity: SyntheticRunIdentity {
                    fake_run_id: format!(
                        "fake-{}-{}-{:016x}-{}",
                        sanitize_identifier(&manifest.experiment_id),
                        sanitize_identifier(&profile.id),
                        stable_hash(0x8ebc_6af0_9c88_c6e3, profile.id.as_bytes()),
                        repetition
                    ),
                },
                execution,
                metrics,
                observed_dispatch: None,
            });
        }
    }

    let dispatch_comparisons = compare_same_repetition_dispatches(manifest, &runs)?;
    let pareto_conclusion = pareto_conclusion(&dispatch_comparisons);
    let pareto_allowed = pareto_conclusion.status == ParetoConclusionStatus::Available;
    let (profile_summaries, pareto_frontier) =
        summarize_profiles_with_pareto(manifest, &runs, pareto_allowed)?;
    let objective_selection =
        select_evaluation_frontier(&objective_profile, &profile_summaries, &pareto_frontier)?;
    let results = EvaluationResults {
        version: EVALUATION_RESULTS_SCHEMA_VERSION,
        manifest_version: manifest.version,
        experiment_id: manifest.experiment_id.clone(),
        fake_seed: seed,
        evidence: EvaluationEvidence::provisional_fake_only(),
        declared_inputs,
        declared_inputs_digest,
        dispatch_comparability_claim: DispatchComparabilityClaim::dispatch_only(),
        runs,
        dispatch_comparisons,
        profile_summaries,
        pareto_conclusion,
        pareto_frontier,
        objective_scoring: EvaluationObjectiveEvidence::Scored(
            ObjectiveScoringProvenance::original(objective_profile),
        ),
        objective_selection,
    };
    validate_results_against_manifest(manifest, &results)?;
    Ok(results)
}

/// Normalize the A4 dispatch-observation channel without reading requested/effective profile data.
pub fn observed_dispatch_record_from_profile_binding(
    binding: &AutopilotProfileBindingReport,
) -> Result<ObservedDispatchRecord, String> {
    if binding.configuration_status != AutopilotProfileBindingStatus::Matched
        || binding.status != AutopilotProfileBindingStatus::Matched
        || binding.failure.is_some()
    {
        return Err(
            "not_process_observable: profile execution binding is not fully matched".to_string(),
        );
    }
    let execution = binding
        .execution
        .as_ref()
        .ok_or_else(|| "not_process_observable: profile execution binding is absent".to_string())?;
    if execution.unavailable_reason.is_some() {
        return Err(
            "not_process_observable: profile execution binding reports unavailable evidence"
                .to_string(),
        );
    }

    let mut roles = Vec::with_capacity(execution.role_models.len());
    for observed in &execution.role_models {
        if observed.status != AutopilotProfileBindingStatus::Matched
            || observed.observation != RoleUsageObservation::ProcessObserved
            || observed.observed_models.is_empty()
            || observed
                .observed_models
                .iter()
                .any(|model| model.trim().is_empty())
        {
            return Err(format!(
                "not_process_observable: role '{}' lacks a complete process-observed dispatch selection",
                role_name(observed.role)
            ));
        }
        let mut models = observed.observed_models.clone();
        models.sort();
        roles.push(ObservedRoleDispatch {
            role: observed.role,
            models,
            reasoning_effort: None,
        });
    }
    roles.sort();

    let mut review_lenses = Vec::with_capacity(execution.review_lenses.len());
    for observed in &execution.review_lenses {
        let backend_id = observed.observed_backend_id.as_deref().ok_or_else(|| {
            format!(
                "not_process_observable: review lens '{}' lacks an observed backend",
                observed.lens_id
            )
        })?;
        let model = observed.observed_model.as_deref().ok_or_else(|| {
            format!(
                "not_process_observable: review lens '{}' lacks an observed model",
                observed.lens_id
            )
        })?;
        if observed.status != AutopilotProfileBindingStatus::Matched
            || observed.observation != RoleUsageObservation::ProcessObserved
            || observed.dispatch_count == 0
            || observed.lens_id.trim().is_empty()
            || backend_id.trim().is_empty()
            || model.trim().is_empty()
        {
            return Err(format!(
                "not_process_observable: review lens '{}' lacks a complete process-observed dispatch selection",
                observed.lens_id
            ));
        }
        review_lenses.push(ObservedReviewLensDispatch {
            lens_id: observed.lens_id.clone(),
            backend_id: backend_id.to_string(),
            model: model.to_string(),
            reasoning_effort: observed.observed_reasoning_effort.clone(),
            dispatch_count: observed.dispatch_count,
        });
    }
    review_lenses.sort();
    if roles.is_empty() && review_lenses.is_empty() {
        return Err(
            "not_process_observable: profile contained no observed dispatch selection".to_string(),
        );
    }
    Ok(ObservedDispatchRecord {
        roles,
        review_lenses,
        supervisor_execution: None,
    })
}

/// Consume the execution/economics block from a serialized `supervisor-final.json` artifact.
///
/// The outer supervisor report has a much broader schema. This adapter deliberately reads only
/// its version and `role_economics_profile`, then applies the same fail-closed normalization used
/// by the typed adapter below.
pub fn observed_dispatch_record_from_supervisor_final_json(
    artifact: &[u8],
) -> Result<ObservedDispatchRecord, String> {
    let document = serde_json::from_slice::<Value>(artifact)
        .map_err(|error| format!("invalid_supervisor_artifact: {error}"))?;
    let object = document.as_object().ok_or_else(|| {
        "invalid_supervisor_artifact: supervisor-final.json must be an object".to_string()
    })?;
    let report_version = object
        .get("version")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            "not_process_observable: supervisor-final.json lacks an integer version".to_string()
        })?;
    if report_version != 1 {
        return Err(format!(
            "not_process_observable: unsupported supervisor-final.json version {report_version}"
        ));
    }
    let profile_value = object.get("role_economics_profile").ok_or_else(|| {
        "not_process_observable: supervisor-final.json lacks role_economics_profile".to_string()
    })?;
    let profile =
        serde_json::from_value::<RoleEconomicsProfile>(profile_value.clone()).map_err(|error| {
            format!("invalid_supervisor_artifact: invalid role_economics_profile: {error}")
        })?;
    observed_dispatch_record_from_role_economics_profile(&profile)
}

/// Normalize supervisor execution telemetry without substituting configured values for
/// unresolved runtime observations.
pub fn observed_dispatch_record_from_role_economics_profile(
    profile: &RoleEconomicsProfile,
) -> Result<ObservedDispatchRecord, String> {
    if profile.schema_version != CONSUMED_SUPERVISOR_EXECUTION_TELEMETRY_SCHEMA_VERSION {
        return Err(format!(
            "not_process_observable: unsupported supervisor execution telemetry schema {}; expected {}",
            profile.schema_version, CONSUMED_SUPERVISOR_EXECUTION_TELEMETRY_SCHEMA_VERSION
        ));
    }
    let execution = profile.execution.as_ref().ok_or_else(|| {
        "not_process_observable: supervisor execution telemetry schema v2 is absent".to_string()
    })?;
    validate_supervisor_execution_metadata(execution)?;

    let mut role_bindings = execution
        .role_bindings
        .iter()
        .map(|(role, binding)| ObservedSupervisorRoleBinding {
            role: *role,
            resolved_model: binding.resolved_model.clone(),
            resolved_reasoning_effort: binding.resolved_reasoning_effort.clone(),
            observation: binding.observation,
            unavailable_reason: binding.unavailable_reason.clone(),
        })
        .collect::<Vec<_>>();
    role_bindings.sort_by_key(|binding| binding.role);

    let roles = role_bindings
        .iter()
        .filter_map(|binding| {
            if binding.observation == RoleBindingObservation::RuntimeCatalogResolved {
                binding
                    .resolved_model
                    .as_ref()
                    .map(|model| ObservedRoleDispatch {
                        role: binding.role,
                        models: vec![model.clone()],
                        reasoning_effort: binding.resolved_reasoning_effort.clone(),
                    })
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    Ok(ObservedDispatchRecord {
        roles,
        review_lenses: Vec::new(),
        supervisor_execution: Some(ObservedSupervisorExecution {
            schema_version: profile.schema_version,
            model_catalog_observation: profile.model_catalog_observation,
            assignment_count: execution.assignment_count,
            started_assignment_count: execution.started_assignment_count,
            completed_assignment_count: execution.completed_assignment_count,
            concurrency: ObservedSupervisorConcurrency {
                configured_max_concurrent_children: execution
                    .concurrency
                    .configured_max_concurrent_children,
                policy_input_observation: execution.concurrency.policy_input_observation,
                policy_input: execution.concurrency.policy_input.clone(),
                policy_input_unavailable_reason: execution
                    .concurrency
                    .policy_input_unavailable_reason
                    .clone(),
                achieved_max_concurrent_children: execution
                    .concurrency
                    .achieved_max_concurrent_children,
                achieved_mean_concurrent_children: execution
                    .concurrency
                    .achieved_mean_concurrent_children,
                achieved_mean_observation: execution.concurrency.achieved_mean_observation,
                achieved_mean_unavailable_reason: execution
                    .concurrency
                    .achieved_mean_unavailable_reason
                    .clone(),
            },
            role_bindings,
            usage: ObservedSupervisorUsage {
                total_usage: execution.usage.total_usage,
                total_cost_usd: execution.usage.total_cost_usd,
                usage_complete: execution.usage.usage_complete,
                observation: execution.usage.observation,
                unavailable_reason: execution.usage.unavailable_reason.clone(),
            },
        }),
    })
}

fn validate_supervisor_execution_metadata(
    execution: &crate::supervise::SupervisorExecutionMetadata,
) -> Result<(), String> {
    if execution.started_assignment_count > execution.assignment_count {
        return Err(
            "invalid_supervisor_artifact: started_assignment_count exceeds assignment_count"
                .to_string(),
        );
    }
    if execution.completed_assignment_count > execution.started_assignment_count {
        return Err(
            "invalid_supervisor_artifact: completed_assignment_count exceeds started_assignment_count"
                .to_string(),
        );
    }
    let concurrency = &execution.concurrency;
    if concurrency.configured_max_concurrent_children == 0 {
        return Err(
            "invalid_supervisor_artifact: configured_max_concurrent_children must be positive"
                .to_string(),
        );
    }
    if concurrency.achieved_max_concurrent_children > concurrency.configured_max_concurrent_children
        || concurrency.achieved_max_concurrent_children > execution.started_assignment_count
    {
        return Err(
            "invalid_supervisor_artifact: achieved concurrency exceeds the configured or started assignment bound"
                .to_string(),
        );
    }
    if (execution.started_assignment_count == 0)
        != (concurrency.achieved_max_concurrent_children == 0)
    {
        return Err(
            "invalid_supervisor_artifact: achieved concurrency is inconsistent with started assignments"
                .to_string(),
        );
    }
    validate_observed_value_marker(
        "policy_input",
        concurrency.policy_input_observation,
        concurrency.policy_input.as_deref(),
        concurrency.policy_input_unavailable_reason.as_deref(),
    )?;
    match (
        concurrency.achieved_mean_observation,
        concurrency.achieved_mean_concurrent_children,
        concurrency.achieved_mean_unavailable_reason.as_deref(),
    ) {
        (ProcessObservation::SchedulerObserved, Some(mean), None)
            if mean.is_finite()
                && mean > 0.0
                && mean <= concurrency.achieved_max_concurrent_children as f64 => {}
        (
            ProcessObservation::NotRetained | ProcessObservation::NotProcessObservable,
            None,
            Some(reason),
        ) if !reason.trim().is_empty() => {}
        _ => {
            return Err(
                "invalid_supervisor_artifact: achieved mean value, observation, and unavailable reason are inconsistent"
                    .to_string(),
            );
        }
    }

    let expected_roles = [
        AgentRole::Supervisor,
        AgentRole::ChildOrchestrator,
        AgentRole::Worker,
        AgentRole::GateClassifier,
        AgentRole::Auditor,
    ];
    if execution.role_bindings.len() != expected_roles.len()
        || expected_roles
            .iter()
            .any(|role| !execution.role_bindings.contains_key(role))
    {
        return Err(
            "invalid_supervisor_artifact: role_bindings must explicitly cover every supervisor role"
                .to_string(),
        );
    }
    for (role, binding) in &execution.role_bindings {
        validate_optional_observed_text(
            &format!("role_bindings.{}.resolved_model", role_name(*role)),
            binding.resolved_model.as_deref(),
        )?;
        validate_optional_observed_text(
            &format!(
                "role_bindings.{}.resolved_reasoning_effort",
                role_name(*role)
            ),
            binding.resolved_reasoning_effort.as_deref(),
        )?;
        match binding.observation {
            RoleBindingObservation::RuntimeCatalogResolved if binding.resolved_model.is_none() => {
                return Err(format!(
                    "invalid_supervisor_artifact: role '{}' is marked runtime_catalog_resolved without a resolved model",
                    role_name(*role)
                ));
            }
            RoleBindingObservation::RuntimeCatalogResolved => {}
            _ if binding.resolved_model.is_none()
                && binding
                    .unavailable_reason
                    .as_deref()
                    .is_none_or(|reason| reason.trim().is_empty()) =>
            {
                return Err(format!(
                    "invalid_supervisor_artifact: unresolved role '{}' lacks an explicit unavailable reason",
                    role_name(*role)
                ));
            }
            _ => {}
        }
    }

    if let Some(usage) = execution.usage.total_usage {
        if usage.input_tokens.checked_add(usage.output_tokens) != Some(usage.total_tokens) {
            return Err(
                "invalid_supervisor_artifact: total_usage does not equal input plus output tokens"
                    .to_string(),
            );
        }
    }
    if execution
        .usage
        .total_cost_usd
        .is_some_and(|cost| !cost.is_finite() || cost < 0.0)
    {
        return Err(
            "invalid_supervisor_artifact: total_cost_usd must be finite and nonnegative"
                .to_string(),
        );
    }
    if execution.usage.total_usage.is_none()
        && execution
            .usage
            .unavailable_reason
            .as_deref()
            .is_none_or(|reason| reason.trim().is_empty())
    {
        return Err(
            "invalid_supervisor_artifact: unobserved aggregate usage lacks an explicit unavailable reason"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_observed_value_marker(
    field: &str,
    observation: ProcessObservation,
    value: Option<&str>,
    unavailable_reason: Option<&str>,
) -> Result<(), String> {
    match (observation, value, unavailable_reason) {
        (ProcessObservation::SchedulerObserved, Some(value), None) if !value.trim().is_empty() => {
            Ok(())
        }
        (
            ProcessObservation::NotRetained | ProcessObservation::NotProcessObservable,
            None,
            Some(reason),
        ) if !reason.trim().is_empty() => Ok(()),
        _ => Err(format!(
            "invalid_supervisor_artifact: {field} value, observation, and unavailable reason are inconsistent"
        )),
    }
}

fn validate_optional_observed_text(field: &str, value: Option<&str>) -> Result<(), String> {
    if value.is_some_and(|value| value.trim().is_empty()) {
        return Err(format!(
            "invalid_supervisor_artifact: {field} must not be empty when present"
        ));
    }
    Ok(())
}

fn has_complete_resolved_role_bindings(execution: &ObservedSupervisorExecution) -> bool {
    let expected_roles = [
        AgentRole::Supervisor,
        AgentRole::ChildOrchestrator,
        AgentRole::Worker,
        AgentRole::GateClassifier,
        AgentRole::Auditor,
    ];
    execution.model_catalog_observation == RuntimeModelCatalogObservation::Consulted
        && validate_normalized_supervisor_execution(execution, "comparison").is_ok()
        && execution
            .role_bindings
            .iter()
            .zip(expected_roles)
            .all(|(binding, role)| {
                binding.role == role
                    && binding.observation == RoleBindingObservation::RuntimeCatalogResolved
                    && binding
                        .resolved_model
                        .as_deref()
                        .is_some_and(|model| !model.trim().is_empty())
                    && binding
                        .resolved_reasoning_effort
                        .as_deref()
                        .is_some_and(|effort| !effort.trim().is_empty())
            })
}

fn has_complete_execution_economics(execution: &ObservedSupervisorExecution) -> bool {
    has_complete_resolved_role_bindings(execution)
        && execution.concurrency.achieved_mean_observation == ProcessObservation::SchedulerObserved
        && execution
            .concurrency
            .achieved_mean_concurrent_children
            .is_some()
        && execution.usage.usage_complete
        && execution.usage.total_usage.is_some()
        && execution.usage.total_cost_usd.is_some()
        && execution.usage.observation == RoleUsageObservation::SupervisorAggregate
}

fn optional_float_equal(left: Option<f64>, right: Option<f64>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => approximately_equal(left, right),
        (None, None) => true,
        _ => false,
    }
}

fn supervisor_execution_equivalent(
    left: &ObservedSupervisorExecution,
    right: &ObservedSupervisorExecution,
) -> bool {
    left.schema_version == right.schema_version
        && left.model_catalog_observation == right.model_catalog_observation
        && left.assignment_count == right.assignment_count
        && left.started_assignment_count == right.started_assignment_count
        && left.completed_assignment_count == right.completed_assignment_count
        && left.concurrency.configured_max_concurrent_children
            == right.concurrency.configured_max_concurrent_children
        && left.concurrency.policy_input_observation == right.concurrency.policy_input_observation
        && left.concurrency.policy_input == right.concurrency.policy_input
        && left.concurrency.achieved_max_concurrent_children
            == right.concurrency.achieved_max_concurrent_children
        && optional_float_equal(
            left.concurrency.achieved_mean_concurrent_children,
            right.concurrency.achieved_mean_concurrent_children,
        )
        && left.concurrency.achieved_mean_observation == right.concurrency.achieved_mean_observation
        && left.role_bindings == right.role_bindings
        && left.usage.total_usage == right.usage.total_usage
        && optional_float_equal(left.usage.total_cost_usd, right.usage.total_cost_usd)
        && left.usage.usage_complete == right.usage.usage_complete
        && left.usage.observation == right.usage.observation
}

/// Compare the execution/economics axis without claiming provider execution identity.
pub fn compare_observed_supervisor_execution(
    left: Option<&ObservedSupervisorExecution>,
    right: Option<&ObservedSupervisorExecution>,
) -> ExecutionTelemetryComparability {
    match (left, right) {
        (Some(left), Some(right))
            if has_complete_execution_economics(left)
                && has_complete_execution_economics(right) =>
        {
            if supervisor_execution_equivalent(left, right) {
                ExecutionTelemetryComparability::Equivalent
            } else {
                ExecutionTelemetryComparability::Different
            }
        }
        _ => ExecutionTelemetryComparability::Incomparable,
    }
}

/// Comparator seam used by Phase-B fail-capability tests and source-neuter checks.
pub fn compare_observed_dispatch_records(
    left: Option<&ObservedDispatchRecord>,
    right: Option<&ObservedDispatchRecord>,
) -> RequirementFourComparability {
    match (left, right) {
        (Some(left), Some(right))
            if has_complete_dispatch_record(left)
                && has_complete_dispatch_record(right)
                && (left.roles != right.roles || left.review_lenses != right.review_lenses) =>
        {
            RequirementFourComparability::DispatchGroundedSelectionsDiffer
        }
        (Some(left), Some(right))
            if has_complete_dispatch_record(left) && has_complete_dispatch_record(right) =>
        {
            RequirementFourComparability::DispatchGroundedSelectionsEquivalent
        }
        _ => RequirementFourComparability::Incomparable,
    }
}

fn has_complete_dispatch_record(record: &ObservedDispatchRecord) -> bool {
    record
        .supervisor_execution
        .as_ref()
        .is_some_and(has_complete_resolved_role_bindings)
        && validate_observed_dispatch_record(record, 0).is_ok()
}

/// Ingest and compare two `supervisor-final.json` artifacts in one fail-closed operation.
pub fn compare_supervisor_final_artifacts(
    left_artifact: &[u8],
    right_artifact: &[u8],
) -> SupervisorArtifactComparison {
    let left = observed_dispatch_record_from_supervisor_final_json(left_artifact);
    let right = observed_dispatch_record_from_supervisor_final_json(right_artifact);
    let comparability = compare_observed_dispatch_records(left.as_ref().ok(), right.as_ref().ok());
    let execution_telemetry_comparability = compare_observed_supervisor_execution(
        left.as_ref()
            .ok()
            .and_then(|record| record.supervisor_execution.as_ref()),
        right
            .as_ref()
            .ok()
            .and_then(|record| record.supervisor_execution.as_ref()),
    );
    let mut reasons = Vec::new();
    if let Err(reason) = &left {
        reasons.push(format!("left: {reason}"));
    }
    if let Err(reason) = &right {
        reasons.push(format!("right: {reason}"));
    }
    if reasons.is_empty()
        && (comparability == RequirementFourComparability::Incomparable
            || execution_telemetry_comparability == ExecutionTelemetryComparability::Incomparable)
    {
        reasons.push(
            "one or both runs contain explicit unavailable role, concurrency, or usage observations"
                .to_string(),
        );
    }
    SupervisorArtifactComparison {
        dispatch_comparability_claim: DispatchComparabilityClaim::dispatch_only(),
        comparability,
        execution_telemetry_comparability,
        unavailable_reason: (!reasons.is_empty()).then(|| reasons.join("; ")),
    }
}

fn compare_same_repetition_dispatches(
    manifest: &EvaluationManifest,
    runs: &[EvaluationRepetitionResult],
) -> Result<Vec<DispatchComparison>, EvaluationError> {
    let mut comparisons = Vec::new();
    for repetition in 0..manifest.repetitions {
        for left_index in 0..manifest.profiles.len() {
            for right_index in (left_index + 1)..manifest.profiles.len() {
                let left_profile = &manifest.profiles[left_index];
                let right_profile = &manifest.profiles[right_index];
                let left = runs
                    .iter()
                    .find(|run| run.profile_id == left_profile.id && run.repetition == repetition)
                    .ok_or_else(|| invalid_results("runs", "missing left comparison run"))?;
                let right = runs
                    .iter()
                    .find(|run| run.profile_id == right_profile.id && run.repetition == repetition)
                    .ok_or_else(|| invalid_results("runs", "missing right comparison run"))?;
                let comparability = compare_observed_dispatch_records(
                    left.observed_dispatch.as_ref(),
                    right.observed_dispatch.as_ref(),
                );
                let execution_telemetry_comparability = compare_observed_supervisor_execution(
                    left.observed_dispatch
                        .as_ref()
                        .and_then(|record| record.supervisor_execution.as_ref()),
                    right
                        .observed_dispatch
                        .as_ref()
                        .and_then(|record| record.supervisor_execution.as_ref()),
                );
                comparisons.push(DispatchComparison {
                    left_profile_id: left_profile.id.clone(),
                    right_profile_id: right_profile.id.clone(),
                    repetition,
                    comparability,
                    execution_telemetry_comparability,
                    unavailable_reason: (comparability
                        == RequirementFourComparability::Incomparable
                        || execution_telemetry_comparability
                            == ExecutionTelemetryComparability::Incomparable)
                        .then(|| {
                            "not_process_observable: one or both runs lack complete supervisor execution telemetry schema v2, resolved role bindings, achieved concurrency, or aggregate usage"
                                .to_string()
                        }),
                });
            }
        }
    }
    Ok(comparisons)
}

fn pareto_conclusion(comparisons: &[DispatchComparison]) -> ParetoConclusion {
    let status = if comparisons.is_empty()
        || comparisons.iter().any(|comparison| {
            comparison.comparability == RequirementFourComparability::Incomparable
                || comparison.execution_telemetry_comparability
                    == ExecutionTelemetryComparability::Incomparable
        }) {
        ParetoConclusionStatus::RefusedIncomparableDispatchEvidence
    } else if !comparisons.iter().any(|comparison| {
        comparison.comparability == RequirementFourComparability::DispatchGroundedSelectionsDiffer
    }) {
        ParetoConclusionStatus::RefusedNoDispatchDifference
    } else {
        ParetoConclusionStatus::Available
    };
    ParetoConclusion {
        status,
        claim: DispatchComparabilityClaim::dispatch_only(),
    }
}

/// Check that every synthetic result is internally consistent with the manifest's declared target,
/// snapshot string, limits, and held-out validations.
///
/// This validates declared inputs only. It does not observe repository state or establish Issue
/// #26 requirement-4 comparability, which remains deferred to Phase B.
pub fn validate_results_against_manifest(
    manifest: &EvaluationManifest,
    results: &EvaluationResults,
) -> Result<(), EvaluationError> {
    manifest.validate()?;
    if ![
        LEGACY_EVALUATION_RESULTS_SCHEMA_VERSION,
        PRE_OBJECTIVE_SELECTION_RESULTS_SCHEMA_VERSION,
        EVALUATION_RESULTS_SCHEMA_VERSION,
    ]
    .contains(&results.version)
    {
        return Err(EvaluationError::UnsupportedResultsVersion {
            found: results.version,
            supported: EVALUATION_RESULTS_SCHEMA_VERSION,
        });
    }
    if results.manifest_version != manifest.version {
        return Err(invalid_results(
            "manifest_version",
            format!(
                "expected {}, got {}",
                manifest.version, results.manifest_version
            ),
        ));
    }
    if results.experiment_id != manifest.experiment_id {
        return Err(invalid_results(
            "experiment_id",
            format!(
                "expected '{}', got '{}'",
                manifest.experiment_id, results.experiment_id
            ),
        ));
    }
    results.evidence.validate()?;
    results.dispatch_comparability_claim.validate()?;
    let manifest_objective_profile = manifest.resolved_objective_profile()?;
    let applied_objective_profile = match (&results.objective_scoring, results.version) {
        (
            EvaluationObjectiveEvidence::Scored(objective_scoring),
            EVALUATION_RESULTS_SCHEMA_VERSION,
        ) => {
            objective_scoring.validate()?;
            if objective_scoring.applied_profile != manifest_objective_profile {
                return Err(invalid_results(
                    "objective_scoring.applied_profile",
                    "does not match the resolved objective bound by the manifest",
                ));
            }
            objective_scoring.applied_profile.clone()
        }
        (EvaluationObjectiveEvidence::Scored(_), _) => {
            return Err(invalid_results(
                "objective_scoring",
                "scored objective evidence requires evaluation results schema v4",
            ));
        }
        (
            EvaluationObjectiveEvidence::Legacy(objective_profile),
            LEGACY_EVALUATION_RESULTS_SCHEMA_VERSION
            | PRE_OBJECTIVE_SELECTION_RESULTS_SCHEMA_VERSION,
        ) => {
            if let Some(binding) = objective_profile {
                binding
                    .validate()
                    .map_err(|error| invalid_results("objective_profile", error.to_string()))?;
                if binding != &manifest_objective_profile.profile {
                    return Err(invalid_results(
                        "objective_profile",
                        "does not match the objective resolved for the manifest",
                    ));
                }
            } else if manifest.objective_profile.is_some() {
                return Err(invalid_results(
                    "objective_profile",
                    "legacy results may omit only the historical built-in objective",
                ));
            }
            manifest_objective_profile.clone()
        }
        (EvaluationObjectiveEvidence::Legacy(_), EVALUATION_RESULTS_SCHEMA_VERSION) => {
            return Err(invalid_results(
                "objective_scoring",
                "evaluation results schema v4 requires canonical scoring provenance",
            ));
        }
        _ => {
            return Err(invalid_results(
                "objective_scoring",
                "objective evidence does not match the results schema version",
            ));
        }
    };
    if results.evidence.kind == EvaluationEvidenceKind::ProvisionalDeterministicFakeOnly
        && results
            .runs
            .iter()
            .any(|run| run.observed_dispatch.is_some())
    {
        return Err(invalid_results(
            "runs.observed_dispatch",
            "provisional deterministic Fake evidence cannot retain an observed dispatch record; \
             grounded dispatch comparisons require separately retained A4 runtime provenance",
        ));
    }

    let expected_binding = manifest.declared_inputs_binding(
        (results.version == EVALUATION_RESULTS_SCHEMA_VERSION)
            .then(|| applied_objective_profile.clone()),
    );
    if results.declared_inputs != expected_binding {
        return Err(invalid_results(
            "declared_inputs",
            "target, base snapshot, limits, held-out validation, or full role/model profile set \
             differ from the manifest",
        ));
    }
    let expected_digest = digest_serializable(&expected_binding)?;
    if results.declared_inputs_digest != expected_digest {
        return Err(invalid_results(
            "declared_inputs_digest",
            format!(
                "expected declared-input digest '{expected_digest}', got '{}'",
                results.declared_inputs_digest
            ),
        ));
    }

    let expected_run_count = manifest
        .profiles
        .len()
        .checked_mul(manifest.repetitions as usize)
        .ok_or_else(|| overflow("expected run count"))?;
    if results.runs.len() != expected_run_count {
        return Err(invalid_results(
            "runs",
            format!(
                "expected {expected_run_count} profile repetitions, got {}",
                results.runs.len()
            ),
        ));
    }

    let profiles = manifest
        .profiles
        .iter()
        .map(|profile| (profile.id.as_str(), profile))
        .collect::<BTreeMap<_, _>>();
    let mut seen_repetitions = BTreeSet::new();
    let mut seen_fake_run_ids = BTreeSet::new();
    for (run_index, run) in results.runs.iter().enumerate() {
        let field = |suffix: &str| format!("runs[{run_index}].{suffix}");
        let profile = profiles.get(run.profile_id.as_str()).ok_or_else(|| {
            invalid_results(
                field("profile_id"),
                format!("unknown profile '{}'", run.profile_id),
            )
        })?;
        if run.repetition >= manifest.repetitions {
            return Err(invalid_results(
                field("repetition"),
                format!(
                    "must be less than manifest repetitions {}, got {}",
                    manifest.repetitions, run.repetition
                ),
            ));
        }
        if !seen_repetitions.insert((run.profile_id.as_str(), run.repetition)) {
            return Err(invalid_results(
                field("repetition"),
                format!(
                    "duplicate repetition {} for profile '{}'",
                    run.repetition, run.profile_id
                ),
            ));
        }
        if run.declared_inputs_digest != expected_digest {
            return Err(invalid_results(
                field("declared_inputs_digest"),
                "synthetic run is not bound to the manifest's declared inputs",
            ));
        }
        require_result_nonempty(
            &field("synthetic_run_identity.fake_run_id"),
            &run.synthetic_run_identity.fake_run_id,
        )?;
        if !seen_fake_run_ids.insert(run.synthetic_run_identity.fake_run_id.as_str()) {
            return Err(invalid_results(
                field("synthetic_run_identity.fake_run_id"),
                format!(
                    "synthetic run identity '{}' was reused; repetitions need distinct fixture \
                     identities",
                    run.synthetic_run_identity.fake_run_id
                ),
            ));
        }
        validate_execution(
            manifest,
            &run.execution,
            run.metrics.wall_time_ms,
            run_index,
        )?;
        validate_metrics(
            manifest,
            profile,
            &applied_objective_profile,
            &run.metrics,
            run_index,
        )?;
        if let Some(observed_dispatch) = &run.observed_dispatch {
            validate_observed_dispatch_record(observed_dispatch, run_index)?;
        }
    }

    let expected_comparisons = compare_same_repetition_dispatches(manifest, &results.runs)?;
    let comparisons_match = if results.version == LEGACY_EVALUATION_RESULTS_SCHEMA_VERSION {
        legacy_dispatch_comparisons_equivalent(&results.dispatch_comparisons, &expected_comparisons)
    } else {
        results.dispatch_comparisons == expected_comparisons
    };
    if !comparisons_match {
        return Err(invalid_results(
            "dispatch_comparisons",
            "comparisons do not match same-repetition observed dispatch records",
        ));
    }
    let expected_conclusion = pareto_conclusion(&expected_comparisons);
    if results.pareto_conclusion != expected_conclusion {
        return Err(invalid_results(
            "pareto_conclusion",
            "does not match dispatch comparability and cost evidence",
        ));
    }
    let pareto_allowed = expected_conclusion.status == ParetoConclusionStatus::Available;
    let (expected_summaries, expected_frontier) =
        summarize_profiles_with_pareto(manifest, &results.runs, pareto_allowed)?;
    if !profile_summaries_equivalent(&results.profile_summaries, &expected_summaries) {
        return Err(invalid_results(
            "profile_summaries",
            "aggregates do not match the repetition observations",
        ));
    }
    if !pareto_frontiers_equivalent(
        &results.pareto_frontier,
        &expected_frontier,
        results.version != EVALUATION_RESULTS_SCHEMA_VERSION,
    ) {
        return Err(invalid_results(
            "pareto_frontier",
            "frontier does not match raw typed evidence dominance over profile summaries",
        ));
    }
    if matches!(
        &results.objective_scoring,
        EvaluationObjectiveEvidence::Scored(_)
    ) {
        let expected_selection = select_evaluation_frontier(
            &applied_objective_profile,
            &expected_summaries,
            &expected_frontier,
        )?;
        if results.objective_selection != expected_selection {
            return Err(invalid_results(
                "objective_selection",
                "does not match the explicit profile policy applied after frontier construction",
            ));
        }
    }
    Ok(())
}

fn legacy_dispatch_comparisons_equivalent(
    observed: &[DispatchComparison],
    expected: &[DispatchComparison],
) -> bool {
    observed.len() == expected.len()
        && observed.iter().zip(expected).all(|(observed, expected)| {
            observed.left_profile_id == expected.left_profile_id
                && observed.right_profile_id == expected.right_profile_id
                && observed.repetition == expected.repetition
                && observed.comparability == expected.comparability
                && observed.execution_telemetry_comparability
                    == ExecutionTelemetryComparability::Incomparable
                && observed
                    .unavailable_reason
                    .as_deref()
                    .is_some_and(|reason| reason.starts_with("not_process_observable:"))
        })
}

fn validate_observed_dispatch_record(
    record: &ObservedDispatchRecord,
    run_index: usize,
) -> Result<(), EvaluationError> {
    let field = format!("runs[{run_index}].observed_dispatch");
    if record.roles.is_empty()
        && record.review_lenses.is_empty()
        && record.supervisor_execution.is_none()
    {
        return Err(invalid_results(
            field,
            "must contain at least one observed role, review-lens selection, or supervisor execution record",
        ));
    }
    if !is_strictly_sorted(&record.roles) {
        return Err(invalid_results(
            &field,
            "role observations must be in canonical sorted order without duplicates",
        ));
    }
    if !is_strictly_sorted(&record.review_lenses) {
        return Err(invalid_results(
            &field,
            "review-lens observations must be in canonical sorted order without duplicates",
        ));
    }
    let mut roles = BTreeSet::new();
    for role in &record.roles {
        if !roles.insert(role.role) || role.models.is_empty() {
            return Err(invalid_results(
                &field,
                "role observations must be unique and contain at least one model",
            ));
        }
        if !is_strictly_sorted(&role.models) {
            return Err(invalid_results(
                &field,
                "observed role models must be in canonical sorted order without duplicates",
            ));
        }
        for model in &role.models {
            require_result_nonempty(&format!("{field}.roles.models"), model)?;
        }
        if let Some(reasoning_effort) = &role.reasoning_effort {
            require_result_nonempty(&format!("{field}.roles.reasoning_effort"), reasoning_effort)?;
        }
    }
    let mut lens_ids = BTreeSet::new();
    for lens in &record.review_lenses {
        if !lens_ids.insert(lens.lens_id.as_str()) || lens.dispatch_count == 0 {
            return Err(invalid_results(
                &field,
                "review-lens observations must be unique and have a nonzero dispatch count",
            ));
        }
        require_result_nonempty(&format!("{field}.review_lenses.lens_id"), &lens.lens_id)?;
        require_result_nonempty(
            &format!("{field}.review_lenses.backend_id"),
            &lens.backend_id,
        )?;
        require_result_nonempty(&format!("{field}.review_lenses.model"), &lens.model)?;
    }
    if let Some(execution) = &record.supervisor_execution {
        validate_normalized_supervisor_execution(execution, &field)?;
        let expected_roles = execution
            .role_bindings
            .iter()
            .filter_map(|binding| {
                if binding.observation == RoleBindingObservation::RuntimeCatalogResolved {
                    binding
                        .resolved_model
                        .as_ref()
                        .map(|model| ObservedRoleDispatch {
                            role: binding.role,
                            models: vec![model.clone()],
                            reasoning_effort: binding.resolved_reasoning_effort.clone(),
                        })
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        if record.roles != expected_roles {
            return Err(invalid_results(
                format!("{field}.roles"),
                "must exactly project runtime_catalog_resolved supervisor role bindings",
            ));
        }
    }
    Ok(())
}

fn validate_normalized_supervisor_execution(
    execution: &ObservedSupervisorExecution,
    field: &str,
) -> Result<(), EvaluationError> {
    if execution.schema_version != CONSUMED_SUPERVISOR_EXECUTION_TELEMETRY_SCHEMA_VERSION {
        return Err(invalid_results(
            format!("{field}.supervisor_execution.schema_version"),
            format!(
                "expected {}, got {}",
                CONSUMED_SUPERVISOR_EXECUTION_TELEMETRY_SCHEMA_VERSION, execution.schema_version
            ),
        ));
    }
    if execution.started_assignment_count > execution.assignment_count
        || execution.completed_assignment_count > execution.started_assignment_count
    {
        return Err(invalid_results(
            format!("{field}.supervisor_execution"),
            "assignment lifecycle counts are inconsistent",
        ));
    }
    let concurrency = &execution.concurrency;
    if concurrency.configured_max_concurrent_children == 0
        || concurrency.achieved_max_concurrent_children
            > concurrency.configured_max_concurrent_children
        || concurrency.achieved_max_concurrent_children > execution.started_assignment_count
        || (execution.started_assignment_count == 0)
            != (concurrency.achieved_max_concurrent_children == 0)
    {
        return Err(invalid_results(
            format!("{field}.supervisor_execution.concurrency"),
            "configured, achieved, and started concurrency counts are inconsistent",
        ));
    }
    validate_observed_value_marker(
        "policy_input",
        concurrency.policy_input_observation,
        concurrency.policy_input.as_deref(),
        concurrency.policy_input_unavailable_reason.as_deref(),
    )
    .map_err(|message| {
        invalid_results(format!("{field}.supervisor_execution.concurrency"), message)
    })?;
    match (
        concurrency.achieved_mean_observation,
        concurrency.achieved_mean_concurrent_children,
        concurrency.achieved_mean_unavailable_reason.as_deref(),
    ) {
        (ProcessObservation::SchedulerObserved, Some(mean), None)
            if mean.is_finite()
                && mean > 0.0
                && mean <= concurrency.achieved_max_concurrent_children as f64 => {}
        (
            ProcessObservation::NotRetained | ProcessObservation::NotProcessObservable,
            None,
            Some(reason),
        ) if !reason.trim().is_empty() => {}
        _ => {
            return Err(invalid_results(
                format!("{field}.supervisor_execution.concurrency"),
                "achieved mean value, observation, and unavailable reason are inconsistent",
            ));
        }
    }
    let expected_roles = [
        AgentRole::Supervisor,
        AgentRole::ChildOrchestrator,
        AgentRole::Worker,
        AgentRole::GateClassifier,
        AgentRole::Auditor,
    ];
    if execution.role_bindings.len() != expected_roles.len()
        || execution
            .role_bindings
            .iter()
            .zip(expected_roles)
            .any(|(binding, role)| binding.role != role)
    {
        return Err(invalid_results(
            format!("{field}.supervisor_execution.role_bindings"),
            "must cover every role once in canonical order",
        ));
    }
    for binding in &execution.role_bindings {
        if binding
            .resolved_model
            .as_deref()
            .is_some_and(|model| model.trim().is_empty())
            || binding
                .resolved_reasoning_effort
                .as_deref()
                .is_some_and(|effort| effort.trim().is_empty())
        {
            return Err(invalid_results(
                format!("{field}.supervisor_execution.role_bindings"),
                "resolved model and reasoning effort must not be empty when present",
            ));
        }
        if binding.observation == RoleBindingObservation::RuntimeCatalogResolved
            && binding.resolved_model.is_none()
        {
            return Err(invalid_results(
                format!("{field}.supervisor_execution.role_bindings"),
                "runtime_catalog_resolved bindings require a resolved model",
            ));
        }
    }
    if let Some(usage) = execution.usage.total_usage {
        if usage.input_tokens.checked_add(usage.output_tokens) != Some(usage.total_tokens) {
            return Err(invalid_results(
                format!("{field}.supervisor_execution.usage.total_usage"),
                "total tokens must equal input plus output tokens",
            ));
        }
    }
    if let Some(cost) = execution.usage.total_cost_usd {
        require_finite_nonnegative(
            &format!("{field}.supervisor_execution.usage.total_cost_usd"),
            cost,
        )?;
    }
    Ok(())
}

fn is_strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn validate_execution(
    manifest: &EvaluationManifest,
    execution: &RepetitionExecution,
    wall_time_ms: u64,
    run_index: usize,
) -> Result<(), EvaluationError> {
    let field = |suffix: &str| format!("runs[{run_index}].execution.{suffix}");
    if execution.observed_dispatch_count > manifest.limits.max_dispatches {
        return Err(invalid_results(
            field("observed_dispatch_count"),
            format!(
                "exceeds manifest limit {}; observed {}",
                manifest.limits.max_dispatches, execution.observed_dispatch_count
            ),
        ));
    }

    let wall_time_limit_ms = evaluation_wall_time_limit_ms(manifest)?;
    if wall_time_ms > wall_time_limit_ms {
        return Err(invalid_results(
            format!("runs[{run_index}].metrics.wall_time_ms"),
            format!("exceeds manifest limit {wall_time_limit_ms} ms; observed {wall_time_ms} ms"),
        ));
    }

    match (execution.outcome, &execution.error_evidence) {
        (EvaluationExecutionOutcome::Success, None) => {}
        (EvaluationExecutionOutcome::Success, Some(_)) => {
            return Err(invalid_results(
                field("error_evidence"),
                "must be absent when outcome is success",
            ));
        }
        (EvaluationExecutionOutcome::Failure | EvaluationExecutionOutcome::Timeout, None) => {
            return Err(invalid_results(
                field("error_evidence"),
                "is required when outcome is failure or timeout",
            ));
        }
        (
            EvaluationExecutionOutcome::Failure | EvaluationExecutionOutcome::Timeout,
            Some(error),
        ) => {
            require_result_nonempty(&field("error_evidence.message"), &error.message)?;
            if error.message.len() > MAX_EXECUTION_ERROR_EVIDENCE_BYTES {
                return Err(invalid_results(
                    field("error_evidence.message"),
                    format!(
                        "must be at most {MAX_EXECUTION_ERROR_EVIDENCE_BYTES} UTF-8 bytes; got {}",
                        error.message.len()
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn validate_held_out_bindings(
    held_out_validation: &[HeldOutValidation],
) -> Result<(), EvaluationError> {
    if held_out_validation.is_empty() {
        return Err(invalid_manifest(
            "held_out_validation",
            "must contain at least one validation which is not exposed to the evaluated plan",
        ));
    }
    let mut ids = BTreeSet::new();
    for (index, validation) in held_out_validation.iter().enumerate() {
        require_nonempty(&format!("held_out_validation[{index}].id"), &validation.id)?;
        if !ids.insert(validation.id.as_str()) {
            return Err(invalid_manifest(
                format!("held_out_validation[{index}].id"),
                format!("duplicate held-out validation id '{}'", validation.id),
            ));
        }
        if validation.command.is_empty() {
            return Err(invalid_manifest(
                format!("held_out_validation[{index}].command"),
                "must contain an executable and may not be empty",
            ));
        }
        for (argument_index, argument) in validation.command.iter().enumerate() {
            if argument.trim().is_empty() {
                return Err(invalid_manifest(
                    format!("held_out_validation[{index}].command[{argument_index}]"),
                    "command arguments may not be empty or whitespace-only",
                ));
            }
        }
    }
    Ok(())
}

fn validate_profiles(profiles: &[EvaluationProfile]) -> Result<(), EvaluationError> {
    if profiles.len() < 2 {
        return Err(invalid_manifest(
            "profiles",
            "must contain at least two role/model profiles for a comparison",
        ));
    }
    let mut ids = BTreeSet::new();
    let mut configurations = BTreeSet::new();
    let mut expected_roles: Option<BTreeSet<AgentRole>> = None;

    for (profile_index, profile) in profiles.iter().enumerate() {
        require_nonempty(&format!("profiles[{profile_index}].id"), &profile.id)?;
        if !ids.insert(profile.id.as_str()) {
            return Err(invalid_manifest(
                format!("profiles[{profile_index}].id"),
                format!("duplicate profile id '{}'", profile.id),
            ));
        }
        if profile.role_models.len() < 2 {
            return Err(invalid_manifest(
                format!("profiles[{profile_index}].role_models"),
                "must explicitly bind at least a worker role and an orchestration role",
            ));
        }
        if !profile.role_models.contains_key(&AgentRole::Worker) {
            return Err(invalid_manifest(
                format!("profiles[{profile_index}].role_models"),
                "must explicitly bind the worker role",
            ));
        }
        if !profile.role_models.contains_key(&AgentRole::Supervisor)
            && !profile
                .role_models
                .contains_key(&AgentRole::ChildOrchestrator)
        {
            return Err(invalid_manifest(
                format!("profiles[{profile_index}].role_models"),
                "must explicitly bind supervisor or child_orchestrator as an orchestration role",
            ));
        }
        for (role, selection) in &profile.role_models {
            let role_field = format!("profiles[{profile_index}].role_models.{}", role_name(*role));
            match selection.model.as_deref() {
                Some(model) if !model.trim().is_empty() => {}
                _ => {
                    return Err(invalid_manifest(
                        format!("{role_field}.model"),
                        "must explicitly name a model; ambient provider defaults are not reproducible",
                    ));
                }
            }
            if selection
                .reasoning_effort
                .as_deref()
                .is_some_and(|effort| effort.trim().is_empty())
            {
                return Err(invalid_manifest(
                    format!("{role_field}.reasoning_effort"),
                    "must be omitted or contain a non-whitespace value",
                ));
            }
        }

        let roles = profile.role_models.keys().copied().collect::<BTreeSet<_>>();
        if let Some(expected) = &expected_roles {
            if &roles != expected {
                return Err(invalid_manifest(
                    format!("profiles[{profile_index}].role_models"),
                    format!(
                        "role set differs from the first profile; expected [{}], got [{}]",
                        display_roles(expected),
                        display_roles(&roles)
                    ),
                ));
            }
        } else {
            expected_roles = Some(roles);
        }

        let fingerprint = profile_fingerprint(profile);
        if !configurations.insert(fingerprint) {
            return Err(invalid_manifest(
                format!("profiles[{profile_index}].role_models"),
                "duplicates another role/model configuration; duplicate mixes do not form a useful comparison",
            ));
        }
    }
    Ok(())
}

fn fake_metrics(
    manifest: &EvaluationManifest,
    profile: &EvaluationProfile,
    objective_profile: &ResolvedObjectiveProfile,
    profile_fingerprint: &str,
    repetition: u32,
    seed: u64,
) -> Result<(RepetitionExecution, EvaluationMetrics), EvaluationError> {
    let run_material = format!(
        "{}:{}:{}:{}",
        manifest.target.spec_or_goal_digest,
        manifest.repository_base_snapshot,
        profile_fingerprint,
        repetition
    );
    let run_hash = stable_hash(seed, run_material.as_bytes());
    let outcome = match repetition % 3 {
        0 => EvaluationExecutionOutcome::Success,
        1 => EvaluationExecutionOutcome::Failure,
        _ => EvaluationExecutionOutcome::Timeout,
    };
    let observed_dispatch_count =
        1 + ((run_hash >> 41) % u64::from(manifest.limits.max_dispatches)) as u32;
    let error_evidence = match outcome {
        EvaluationExecutionOutcome::Success => None,
        EvaluationExecutionOutcome::Failure => Some(ExecutionErrorEvidence {
            message: "deterministic fake repetition reported a synthetic failure".to_string(),
            truncated: false,
        }),
        EvaluationExecutionOutcome::Timeout => Some(ExecutionErrorEvidence {
            message: "deterministic fake repetition reached its synthetic timeout".to_string(),
            truncated: false,
        }),
    };
    let wall_time_limit_ms = evaluation_wall_time_limit_ms(manifest)?;
    let wall_time_ms = match outcome {
        EvaluationExecutionOutcome::Timeout => wall_time_limit_ms,
        EvaluationExecutionOutcome::Success | EvaluationExecutionOutcome::Failure => {
            1 + ((run_hash >> 5) % wall_time_limit_ms)
        }
    };
    let execution = RepetitionExecution {
        observed_dispatch_count,
        outcome,
        error_evidence,
    };
    let mut role_usage = BTreeMap::new();
    let mut total_usage = Usage::default();
    let mut total_cost_usd = 0.0;

    for (role, selection) in &profile.role_models {
        let model = selection
            .model
            .as_deref()
            .ok_or_else(|| invalid_manifest("profiles.role_models.model", "model is missing"))?;
        let role_material = format!(
            "{}:{}:{}:{}",
            run_material,
            role_name(*role),
            model,
            selection.reasoning_effort.as_deref().unwrap_or("")
        );
        let role_hash = stable_hash(seed ^ 0x9e37_79b9_7f4a_7c15, role_material.as_bytes());
        let input_tokens = 700usize
            .checked_add((role_hash % 1_301) as usize)
            .ok_or_else(|| overflow("fake input tokens"))?;
        let output_tokens = 250usize
            .checked_add(((role_hash >> 11) % 751) as usize)
            .ok_or_else(|| overflow("fake output tokens"))?;
        let usage = Usage {
            input_tokens,
            output_tokens,
            total_tokens: input_tokens
                .checked_add(output_tokens)
                .ok_or_else(|| overflow("fake role total tokens"))?,
        };

        // The rates are deterministic fixture data, not model prices. The result evidence block
        // makes that limitation machine-readable.
        let model_hash = stable_hash(seed ^ 0xa076_1d64_78bd_642f, model.as_bytes());
        let fake_input_usd_per_million = 0.25 + (model_hash % 1_000) as f64 / 100.0;
        let fake_output_usd_per_million = 0.50 + ((model_hash >> 13) % 2_000) as f64 / 100.0;
        let cost_usd = (input_tokens as f64 * fake_input_usd_per_million
            + output_tokens as f64 * fake_output_usd_per_million)
            / 1_000_000.0;

        total_usage = checked_add_usage(total_usage, usage, "fake total role usage")?;
        total_cost_usd += cost_usd;
        role_usage.insert(
            *role,
            RoleUsageReport {
                models: vec![model.to_string()],
                usage: Some(usage),
                cost_usd: Some(cost_usd),
                observation: RoleUsageObservation::SyntheticFake,
                unavailable_reason: None,
            },
        );
    }

    let held_out_validation = manifest
        .held_out_validation
        .iter()
        .map(|validation| {
            let validation_hash = stable_hash(
                seed ^ 0xe703_7ed1_a0b4_28db,
                format!("{}:{}", run_material, validation.id).as_bytes(),
            );
            let assertions_run = 5 + (validation_hash % 4) as u32;
            let missed = ((validation_hash >> 9) % 3) as u32;
            let assertions_passed = assertions_run - missed;
            HeldOutValidationResult {
                id: validation.id.clone(),
                assertions_run,
                assertions_passed,
                passed: assertions_run == assertions_passed,
            }
        })
        .collect::<Vec<_>>();

    let breadth_checks = 8;
    let breadth_passed = 5 + ((run_hash >> 17) % 4) as u32;
    let anti_shortcut_checks = 6;
    let anti_shortcut_passed = 3 + ((run_hash >> 23) % 4) as u32;
    let mut findings = Vec::new();
    if breadth_passed < breadth_checks {
        findings.push(Finding {
            severity: FindingSeverity::Warning,
            message: format!(
                "deterministic fake breadth review missed {} of {breadth_checks} checks",
                breadth_checks - breadth_passed
            ),
            paths: Vec::new(),
        });
    }
    if anti_shortcut_passed < anti_shortcut_checks {
        findings.push(Finding {
            severity: FindingSeverity::Warning,
            message: format!(
                "deterministic fake anti-shortcut review missed {} of {anti_shortcut_checks} checks",
                anti_shortcut_checks - anti_shortcut_passed
            ),
            paths: Vec::new(),
        });
    }
    let review = ReviewQuality {
        breadth: ReviewDimension {
            checks_run: breadth_checks,
            checks_passed: breadth_passed,
        },
        anti_shortcut: ReviewDimension {
            checks_run: anti_shortcut_checks,
            checks_passed: anti_shortcut_passed,
        },
        findings,
    };
    let quality = calculate_quality(objective_profile, &held_out_validation, &review)?;
    let loc_added = 40 + (run_hash % 461);
    let loc_deleted = (run_hash >> 7) % 181;
    let changed_lines = loc_added
        .checked_add(loc_deleted)
        .ok_or_else(|| overflow("fake changed lines"))?;
    let diff_bytes = changed_lines
        .checked_mul(37)
        .and_then(|value| value.checked_add((run_hash >> 29) % 997))
        .ok_or_else(|| overflow("fake diff bytes"))?;

    Ok((
        execution,
        EvaluationMetrics {
            role_usage,
            total_usage,
            total_cost_usd,
            wall_time_ms,
            churn_count: 1 + ((run_hash >> 13) % 12),
            conflict_count: (run_hash >> 19) % 4,
            loc_added,
            loc_deleted,
            diff_bytes,
            held_out_validation,
            review,
            quality,
        },
    ))
}

fn validate_metrics(
    manifest: &EvaluationManifest,
    profile: &EvaluationProfile,
    objective_profile: &ResolvedObjectiveProfile,
    metrics: &EvaluationMetrics,
    run_index: usize,
) -> Result<(), EvaluationError> {
    let field = |suffix: &str| format!("runs[{run_index}].metrics.{suffix}");
    if metrics.role_usage.len() != profile.role_models.len() {
        return Err(invalid_results(
            field("role_usage"),
            format!(
                "expected observations for {} configured roles, got {}",
                profile.role_models.len(),
                metrics.role_usage.len()
            ),
        ));
    }

    let mut total_usage = Usage::default();
    let mut total_cost_usd = 0.0;
    for (role, selection) in &profile.role_models {
        let report = metrics.role_usage.get(role).ok_or_else(|| {
            invalid_results(
                field("role_usage"),
                format!("missing usage for configured role '{}'", role_name(*role)),
            )
        })?;
        let expected_model = selection.model.as_deref().unwrap_or_default();
        if report.models != [expected_model] {
            return Err(invalid_results(
                field(&format!("role_usage.{}.models", role_name(*role))),
                format!(
                    "expected the configured model '{expected_model}', got {:?}",
                    report.models
                ),
            ));
        }
        if report.observation != RoleUsageObservation::SyntheticFake {
            return Err(invalid_results(
                field(&format!("role_usage.{}.observation", role_name(*role))),
                "fake fixture usage must be explicitly classified as synthetic_fake",
            ));
        }
        if report.unavailable_reason.is_some() {
            return Err(invalid_results(
                field(&format!(
                    "role_usage.{}.unavailable_reason",
                    role_name(*role)
                )),
                "must be absent when usage and cost are observed",
            ));
        }
        let usage = report.usage.ok_or_else(|| {
            invalid_results(
                field(&format!("role_usage.{}.usage", role_name(*role))),
                "per-role token usage is required",
            )
        })?;
        validate_usage(
            usage,
            &field(&format!("role_usage.{}.usage", role_name(*role))),
        )?;
        let cost = report.cost_usd.ok_or_else(|| {
            invalid_results(
                field(&format!("role_usage.{}.cost_usd", role_name(*role))),
                "per-role cost is required",
            )
        })?;
        require_finite_nonnegative(
            &field(&format!("role_usage.{}.cost_usd", role_name(*role))),
            cost,
        )?;
        total_usage = checked_add_usage(total_usage, usage, "validated role usage")?;
        total_cost_usd += cost;
    }
    validate_usage(metrics.total_usage, &field("total_usage"))?;
    if metrics.total_usage != total_usage {
        return Err(invalid_results(
            field("total_usage"),
            format!(
                "does not equal the sum of per-role usage; expected {:?}, got {:?}",
                total_usage, metrics.total_usage
            ),
        ));
    }
    require_finite_nonnegative(&field("total_cost_usd"), metrics.total_cost_usd)?;
    if !approximately_equal(metrics.total_cost_usd, total_cost_usd) {
        return Err(invalid_results(
            field("total_cost_usd"),
            format!(
                "does not equal the sum of per-role costs; expected {total_cost_usd}, got {}",
                metrics.total_cost_usd
            ),
        ));
    }
    if metrics.held_out_validation.len() != manifest.held_out_validation.len() {
        return Err(invalid_results(
            field("held_out_validation"),
            format!(
                "expected {} held-out results, got {}",
                manifest.held_out_validation.len(),
                metrics.held_out_validation.len()
            ),
        ));
    }
    for (validation_index, (binding, observation)) in manifest
        .held_out_validation
        .iter()
        .zip(&metrics.held_out_validation)
        .enumerate()
    {
        let validation_field = field(&format!("held_out_validation[{validation_index}]"));
        if observation.id != binding.id {
            return Err(invalid_results(
                format!("{validation_field}.id"),
                format!("expected '{}', got '{}'", binding.id, observation.id),
            ));
        }
        if observation.assertions_run == 0 {
            return Err(invalid_results(
                format!("{validation_field}.assertions_run"),
                "must be greater than zero",
            ));
        }
        if observation.assertions_passed > observation.assertions_run {
            return Err(invalid_results(
                format!("{validation_field}.assertions_passed"),
                "cannot exceed assertions_run",
            ));
        }
        if observation.passed != (observation.assertions_passed == observation.assertions_run) {
            return Err(invalid_results(
                format!("{validation_field}.passed"),
                "must be true exactly when every assertion passed",
            ));
        }
    }
    validate_review_dimension(&metrics.review.breadth, &field("review.breadth"))?;
    validate_review_dimension(
        &metrics.review.anti_shortcut,
        &field("review.anti_shortcut"),
    )?;
    for (finding_index, finding) in metrics.review.findings.iter().enumerate() {
        if finding.message.trim().is_empty() {
            return Err(invalid_results(
                field(&format!("review.findings[{finding_index}].message")),
                "must not be empty or whitespace-only",
            ));
        }
    }
    let expected_quality = calculate_quality(
        objective_profile,
        &metrics.held_out_validation,
        &metrics.review,
    )?;
    if metrics.quality != expected_quality {
        return Err(invalid_results(
            field("quality"),
            format!(
                "does not match held-out, breadth, and anti-shortcut evidence; expected {:?}, got {:?}",
                expected_quality, metrics.quality
            ),
        ));
    }
    Ok(())
}

fn validate_review_dimension(
    dimension: &ReviewDimension,
    field: &str,
) -> Result<(), EvaluationError> {
    if dimension.checks_run == 0 {
        return Err(invalid_results(
            format!("{field}.checks_run"),
            "must be greater than zero; quality cannot omit this dimension",
        ));
    }
    if dimension.checks_passed > dimension.checks_run {
        return Err(invalid_results(
            format!("{field}.checks_passed"),
            "cannot exceed checks_run",
        ));
    }
    Ok(())
}

pub(crate) fn calculate_quality(
    objective_profile: &ResolvedObjectiveProfile,
    held_out: &[HeldOutValidationResult],
    review: &ReviewQuality,
) -> Result<QualityScore, EvaluationError> {
    validate_review_dimension(&review.breadth, "review.breadth")?;
    validate_review_dimension(&review.anti_shortcut, "review.anti_shortcut")?;
    let held_out_run = held_out.iter().try_fold(0u64, |total, result| {
        total
            .checked_add(u64::from(result.assertions_run))
            .ok_or_else(|| overflow("held-out assertions run"))
    })?;
    let held_out_passed = held_out.iter().try_fold(0u64, |total, result| {
        total
            .checked_add(u64::from(result.assertions_passed))
            .ok_or_else(|| overflow("held-out assertions passed"))
    })?;
    if held_out_run == 0 {
        return Err(invalid_results(
            "metrics.held_out_validation",
            "must contain at least one executed assertion",
        ));
    }
    if held_out_passed > held_out_run {
        return Err(invalid_results(
            "metrics.held_out_validation",
            "passed assertions cannot exceed executed assertions",
        ));
    }

    let held_out_basis_points = ratio_basis_points(held_out_passed, held_out_run);
    let breadth_basis_points = ratio_basis_points(
        u64::from(review.breadth.checks_passed),
        u64::from(review.breadth.checks_run),
    );
    let anti_shortcut_basis_points = ratio_basis_points(
        u64::from(review.anti_shortcut.checks_passed),
        u64::from(review.anti_shortcut.checks_run),
    );
    objective_profile
        .profile
        .validate()
        .map_err(|error| invalid_results("objective_profile", error.to_string()))?;
    let quality = &objective_profile.profile.quality;
    let weighted = u64::from(held_out_basis_points) * u64::from(quality.held_out_percent)
        + u64::from(breadth_basis_points) * u64::from(quality.breadth_percent)
        + u64::from(anti_shortcut_basis_points) * u64::from(quality.anti_shortcut_percent);
    let overall_basis_points = u32::try_from(weighted / 100)
        .map_err(|_| overflow("objective-weighted quality basis points"))?;
    Ok(QualityScore {
        held_out_basis_points,
        breadth_basis_points,
        anti_shortcut_basis_points,
        overall_basis_points,
    })
}

#[cfg(test)]
fn summarize_profiles(
    manifest: &EvaluationManifest,
    runs: &[EvaluationRepetitionResult],
) -> Result<(Vec<ProfileSummary>, Vec<ParetoPoint>), EvaluationError> {
    summarize_profiles_with_pareto(manifest, runs, true)
}

fn summarize_profiles_with_pareto(
    manifest: &EvaluationManifest,
    runs: &[EvaluationRepetitionResult],
    pareto_allowed: bool,
) -> Result<(Vec<ProfileSummary>, Vec<ParetoPoint>), EvaluationError> {
    let mut summaries = Vec::with_capacity(manifest.profiles.len());
    for profile in &manifest.profiles {
        let profile_runs = runs
            .iter()
            .filter(|run| run.profile_id == profile.id)
            .collect::<Vec<_>>();
        if profile_runs.len() != manifest.repetitions as usize {
            return Err(invalid_results(
                "runs",
                format!(
                    "profile '{}' has {} repetitions, expected {}",
                    profile.id,
                    profile_runs.len(),
                    manifest.repetitions
                ),
            ));
        }

        let mut aggregate_role_usage = BTreeMap::new();
        for (role, selection) in &profile.role_models {
            let mut usage = Usage::default();
            let mut cost_usd = 0.0;
            for run in &profile_runs {
                let report = run.metrics.role_usage.get(role).ok_or_else(|| {
                    invalid_results(
                        "runs.metrics.role_usage",
                        format!(
                            "profile '{}' repetition {} is missing role '{}'",
                            profile.id,
                            run.repetition,
                            role_name(*role)
                        ),
                    )
                })?;
                usage = checked_add_usage(
                    usage,
                    report.usage.ok_or_else(|| {
                        invalid_results(
                            "runs.metrics.role_usage.usage",
                            "cannot aggregate missing usage",
                        )
                    })?,
                    "profile role usage",
                )?;
                cost_usd += report.cost_usd.ok_or_else(|| {
                    invalid_results(
                        "runs.metrics.role_usage.cost_usd",
                        "cannot aggregate missing cost",
                    )
                })?;
            }
            aggregate_role_usage.insert(
                *role,
                RoleUsageReport {
                    models: vec![selection.model.clone().unwrap_or_default()],
                    usage: Some(usage),
                    cost_usd: Some(cost_usd),
                    observation: RoleUsageObservation::SyntheticFake,
                    unavailable_reason: None,
                },
            );
        }

        let mut aggregate_usage = Usage::default();
        let mut aggregate_cost_usd = 0.0;
        let mut wall_time_ms = 0u64;
        let mut churn_count = 0u64;
        let mut conflict_count = 0u64;
        let mut review_findings = 0u64;
        let mut loc_added = 0u64;
        let mut loc_deleted = 0u64;
        let mut diff_bytes = 0u64;
        let mut held_out_quality = 0u64;
        let mut breadth_quality = 0u64;
        let mut anti_shortcut_quality = 0u64;
        let mut overall_quality = 0u64;
        for run in &profile_runs {
            aggregate_usage = checked_add_usage(
                aggregate_usage,
                run.metrics.total_usage,
                "profile total usage",
            )?;
            aggregate_cost_usd += run.metrics.total_cost_usd;
            wall_time_ms =
                checked_add_u64(wall_time_ms, run.metrics.wall_time_ms, "profile wall time")?;
            churn_count =
                checked_add_u64(churn_count, run.metrics.churn_count, "profile churn count")?;
            conflict_count = checked_add_u64(
                conflict_count,
                run.metrics.conflict_count,
                "profile conflict count",
            )?;
            review_findings = checked_add_u64(
                review_findings,
                u64::try_from(run.metrics.review.findings.len())
                    .map_err(|_| overflow("profile review findings"))?,
                "profile review findings",
            )?;
            loc_added = checked_add_u64(loc_added, run.metrics.loc_added, "profile added lines")?;
            loc_deleted = checked_add_u64(
                loc_deleted,
                run.metrics.loc_deleted,
                "profile deleted lines",
            )?;
            diff_bytes = checked_add_u64(diff_bytes, run.metrics.diff_bytes, "profile diff bytes")?;
            held_out_quality = checked_add_u64(
                held_out_quality,
                u64::from(run.metrics.quality.held_out_basis_points),
                "profile held-out quality",
            )?;
            breadth_quality = checked_add_u64(
                breadth_quality,
                u64::from(run.metrics.quality.breadth_basis_points),
                "profile breadth quality",
            )?;
            anti_shortcut_quality = checked_add_u64(
                anti_shortcut_quality,
                u64::from(run.metrics.quality.anti_shortcut_basis_points),
                "profile anti-shortcut quality",
            )?;
            overall_quality = checked_add_u64(
                overall_quality,
                u64::from(run.metrics.quality.overall_basis_points),
                "profile overall quality",
            )?;
        }
        require_finite_nonnegative("profile_summaries.aggregate_cost_usd", aggregate_cost_usd)?;
        let repetitions_f64 = f64::from(manifest.repetitions);
        summaries.push(ProfileSummary {
            profile_id: profile.id.clone(),
            repetitions: manifest.repetitions,
            aggregate_role_usage,
            aggregate_usage,
            aggregate_cost_usd,
            mean_cost_usd: aggregate_cost_usd / repetitions_f64,
            mean_wall_time_ms: PreciseMean::new(wall_time_ms, manifest.repetitions)?,
            mean_churn_count: PreciseMean::new(churn_count, manifest.repetitions)?,
            mean_conflict_count: PreciseMean::new(conflict_count, manifest.repetitions)?,
            mean_review_findings: Some(PreciseMean::new(review_findings, manifest.repetitions)?),
            mean_loc_added: PreciseMean::new(loc_added, manifest.repetitions)?,
            mean_loc_deleted: PreciseMean::new(loc_deleted, manifest.repetitions)?,
            mean_diff_bytes: PreciseMean::new(diff_bytes, manifest.repetitions)?,
            mean_quality: PreciseQualityScore {
                held_out_basis_points: PreciseMean::new(held_out_quality, manifest.repetitions)?,
                breadth_basis_points: PreciseMean::new(breadth_quality, manifest.repetitions)?,
                anti_shortcut_basis_points: PreciseMean::new(
                    anti_shortcut_quality,
                    manifest.repetitions,
                )?,
                overall_basis_points: PreciseMean::new(overall_quality, manifest.repetitions)?,
            },
            pareto_optimal: false,
        });
    }

    if pareto_allowed {
        for index in 0..summaries.len() {
            let dominated = summaries.iter().enumerate().any(|(other_index, other)| {
                other_index != index && dominates(other, &summaries[index])
            });
            summaries[index].pareto_optimal = !dominated;
        }
    }
    let mut frontier = summaries
        .iter()
        .filter(|summary| summary.pareto_optimal)
        .map(|summary| {
            Ok(ParetoPoint {
                profile_id: summary.profile_id.clone(),
                mean_cost_usd: summary.mean_cost_usd,
                mean_quota_consumption_tokens: Some(PreciseMean::new(
                    u64::try_from(summary.aggregate_usage.total_tokens)
                        .map_err(|_| overflow("frontier quota consumption"))?,
                    summary.repetitions,
                )?),
                mean_wall_time_ms: Some(summary.mean_wall_time_ms),
                quality_basis_points: summary.mean_quality.overall_basis_points,
                held_out_basis_points: summary.mean_quality.held_out_basis_points,
                breadth_basis_points: summary.mean_quality.breadth_basis_points,
                anti_shortcut_basis_points: summary.mean_quality.anti_shortcut_basis_points,
            })
        })
        .collect::<Result<Vec<_>, EvaluationError>>()?;
    frontier.sort_by(|left, right| {
        left.mean_cost_usd
            .total_cmp(&right.mean_cost_usd)
            .then_with(|| {
                right
                    .quality_basis_points
                    .cmp_value(&left.quality_basis_points)
            })
            .then_with(|| left.profile_id.cmp(&right.profile_id))
    });
    Ok((summaries, frontier))
}

fn dominates(candidate: &ProfileSummary, other: &ProfileSummary) -> bool {
    let no_more_expensive = candidate.mean_cost_usd <= other.mean_cost_usd;
    let quota_order = compare_usage_means(
        candidate.aggregate_usage.total_tokens,
        candidate.repetitions,
        other.aggregate_usage.total_tokens,
        other.repetitions,
    );
    let latency_order = candidate
        .mean_wall_time_ms
        .cmp_value(&other.mean_wall_time_ms);
    let held_out_order = candidate
        .mean_quality
        .held_out_basis_points
        .cmp_value(&other.mean_quality.held_out_basis_points);
    let breadth_order = candidate
        .mean_quality
        .breadth_basis_points
        .cmp_value(&other.mean_quality.breadth_basis_points);
    let anti_shortcut_order = candidate
        .mean_quality
        .anti_shortcut_basis_points
        .cmp_value(&other.mean_quality.anti_shortcut_basis_points);
    let no_more_quota = quota_order.is_le();
    let no_slower = latency_order.is_le();
    let no_lower_raw_quality =
        held_out_order.is_ge() && breadth_order.is_ge() && anti_shortcut_order.is_ge();
    let strictly_better = candidate.mean_cost_usd < other.mean_cost_usd
        || quota_order.is_lt()
        || latency_order.is_lt()
        || held_out_order.is_gt()
        || breadth_order.is_gt()
        || anti_shortcut_order.is_gt();
    no_more_expensive && no_more_quota && no_slower && no_lower_raw_quality && strictly_better
}

fn compare_usage_means(
    left_total: usize,
    left_count: u32,
    right_total: usize,
    right_count: u32,
) -> std::cmp::Ordering {
    ((left_total as u128) * u128::from(right_count))
        .cmp(&((right_total as u128) * u128::from(left_count)))
}

fn select_evaluation_frontier(
    objective_profile: &ResolvedObjectiveProfile,
    summaries: &[ProfileSummary],
    frontier: &[ParetoPoint],
) -> Result<Option<ObjectiveSelection>, EvaluationError> {
    if frontier.is_empty() {
        return Ok(None);
    }
    let frontier_ids = frontier
        .iter()
        .map(|point| point.profile_id.as_str())
        .collect::<BTreeSet<_>>();
    let candidates = summaries
        .iter()
        .filter(|summary| frontier_ids.contains(summary.profile_id.as_str()))
        .collect::<Vec<_>>();
    if candidates.len() != frontier.len() {
        return Err(invalid_results(
            "objective_selection",
            "every Pareto point must have exactly one profile summary",
        ));
    }
    require_supported_evaluation_tradeoffs(
        objective_profile,
        true,
        candidates
            .iter()
            .all(|summary| summary.mean_review_findings.is_some()),
    )?;
    let max_cost = candidates
        .iter()
        .map(|summary| summary.mean_cost_usd)
        .fold(0.0_f64, f64::max);
    let max_quota = candidates
        .iter()
        .map(|summary| summary.aggregate_usage.total_tokens as f64 / f64::from(summary.repetitions))
        .fold(0.0_f64, f64::max);
    let max_latency = candidates
        .iter()
        .map(|summary| precise_mean_as_f64(summary.mean_wall_time_ms))
        .fold(0.0_f64, f64::max);
    let max_retry = candidates
        .iter()
        .map(|summary| precise_mean_as_f64(summary.mean_churn_count))
        .fold(0.0_f64, f64::max);
    let max_review = candidates
        .iter()
        .map(|summary| {
            summary
                .mean_review_findings
                .map(precise_mean_as_f64)
                .unwrap_or(0.0)
        })
        .fold(0.0_f64, f64::max);
    let points = candidates
        .iter()
        .map(|summary| {
            Ok((
                summary.profile_id.clone(),
                FrontierAxes {
                    held_out_quality_basis_points: precise_mean_as_u32(
                        summary.mean_quality.held_out_basis_points,
                    )?,
                    breadth_quality_basis_points: precise_mean_as_u32(
                        summary.mean_quality.breadth_basis_points,
                    )?,
                    anti_shortcut_quality_basis_points: precise_mean_as_u32(
                        summary.mean_quality.anti_shortcut_basis_points,
                    )?,
                    monetary_cost: normalize_axis(summary.mean_cost_usd, max_cost),
                    quota_consumption: normalize_axis(
                        summary.aggregate_usage.total_tokens as f64
                            / f64::from(summary.repetitions),
                        max_quota,
                    ),
                    latency: normalize_axis(
                        precise_mean_as_f64(summary.mean_wall_time_ms),
                        max_latency,
                    ),
                    retry_rework: normalize_axis(
                        precise_mean_as_f64(summary.mean_churn_count),
                        max_retry,
                    ),
                    human_review: normalize_axis(
                        summary
                            .mean_review_findings
                            .map(precise_mean_as_f64)
                            .unwrap_or(0.0),
                        max_review,
                    ),
                },
            ))
        })
        .collect::<Result<Vec<_>, EvaluationError>>()?;
    select_from_frontier(objective_profile, &points)
        .map_err(|error| invalid_results("objective_selection", error.to_string()))
}

pub(super) fn select_experiment_frontier(
    objective_profile: &ResolvedObjectiveProfile,
    summaries: &[ExperimentProfileSummary],
    frontier: &[ParetoPoint],
) -> Result<Option<ObjectiveSelection>, EvaluationError> {
    if frontier.is_empty() {
        return Ok(None);
    }
    require_supported_evaluation_tradeoffs(objective_profile, false, false)?;
    let frontier_ids = frontier
        .iter()
        .map(|point| point.profile_id.as_str())
        .collect::<BTreeSet<_>>();
    let candidates = summaries
        .iter()
        .filter(|summary| frontier_ids.contains(summary.profile_id.as_str()))
        .collect::<Vec<_>>();
    if candidates.len() != frontier.len() {
        return Err(invalid_results(
            "objective_selection",
            "every Pareto point must have exactly one experiment profile summary",
        ));
    }
    if objective_profile.profile.tradeoffs.monetary_cost_percent > 0
        && candidates
            .iter()
            .any(|summary| summary.aggregate_cost_usd.is_none())
    {
        return Ok(None);
    }
    if objective_profile
        .profile
        .tradeoffs
        .quota_consumption_percent
        > 0
        && candidates
            .iter()
            .any(|summary| summary.aggregate_usage.is_none())
    {
        return Ok(None);
    }
    let max_cost = candidates
        .iter()
        .map(|summary| summary.mean_cost_usd)
        .fold(0.0_f64, f64::max);
    let quota = |summary: &ExperimentProfileSummary| {
        summary
            .aggregate_usage
            .map(|usage| usage.total_tokens as f64 / f64::from(summary.repetitions))
            .unwrap_or(0.0)
    };
    let max_quota = candidates
        .iter()
        .map(|summary| quota(summary))
        .fold(0.0_f64, f64::max);
    let max_latency = candidates
        .iter()
        .map(|summary| precise_mean_as_f64(summary.mean_wall_time_ms))
        .fold(0.0_f64, f64::max);
    let points = candidates
        .iter()
        .map(|summary| {
            Ok((
                summary.profile_id.clone(),
                FrontierAxes {
                    held_out_quality_basis_points: precise_mean_as_u32(
                        summary.mean_quality.held_out_basis_points,
                    )?,
                    breadth_quality_basis_points: precise_mean_as_u32(
                        summary.mean_quality.breadth_basis_points,
                    )?,
                    anti_shortcut_quality_basis_points: precise_mean_as_u32(
                        summary.mean_quality.anti_shortcut_basis_points,
                    )?,
                    monetary_cost: normalize_axis(summary.mean_cost_usd, max_cost),
                    quota_consumption: normalize_axis(quota(summary), max_quota),
                    latency: normalize_axis(
                        precise_mean_as_f64(summary.mean_wall_time_ms),
                        max_latency,
                    ),
                    retry_rework: 0.0,
                    human_review: 0.0,
                },
            ))
        })
        .collect::<Result<Vec<_>, EvaluationError>>()?;
    select_from_frontier(objective_profile, &points)
        .map_err(|error| invalid_results("objective_selection", error.to_string()))
}

fn require_supported_evaluation_tradeoffs(
    objective_profile: &ResolvedObjectiveProfile,
    retry_observed: bool,
    review_observed: bool,
) -> Result<(), EvaluationError> {
    let tradeoffs = &objective_profile.profile.tradeoffs;
    if tradeoffs.retry_rework_percent > 0 && !retry_observed {
        return Err(invalid_results(
            "objective_profile.tradeoffs.retry_rework_percent",
            "evaluation has no typed retry/rework observation and will not substitute churn",
        ));
    }
    if tradeoffs.human_review_percent > 0 && !review_observed {
        return Err(invalid_results(
            "objective_profile.tradeoffs.human_review_percent",
            "evaluation has no typed human-review-load observation and will not substitute findings",
        ));
    }
    Ok(())
}

fn precise_mean_as_f64(mean: PreciseMean) -> f64 {
    mean.total as f64 / f64::from(mean.count)
}

fn precise_mean_as_u32(mean: PreciseMean) -> Result<u32, EvaluationError> {
    let rounded = mean
        .total
        .checked_add(u64::from(mean.count / 2))
        .ok_or_else(|| overflow("rounded objective quality mean"))?
        / u64::from(mean.count);
    u32::try_from(rounded).map_err(|_| overflow("objective quality mean"))
}

fn normalize_axis(value: f64, maximum: f64) -> f64 {
    if maximum > 0.0 {
        (value / maximum).clamp(0.0, 1.0)
    } else {
        0.0
    }
}

fn profile_summaries_equivalent(left: &[ProfileSummary], right: &[ProfileSummary]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            left.profile_id == right.profile_id
                && left.repetitions == right.repetitions
                && role_usage_maps_equivalent(
                    &left.aggregate_role_usage,
                    &right.aggregate_role_usage,
                )
                && left.aggregate_usage == right.aggregate_usage
                && approximately_equal(left.aggregate_cost_usd, right.aggregate_cost_usd)
                && approximately_equal(left.mean_cost_usd, right.mean_cost_usd)
                && left.mean_wall_time_ms == right.mean_wall_time_ms
                && left.mean_churn_count == right.mean_churn_count
                && left.mean_conflict_count == right.mean_conflict_count
                && left.mean_loc_added == right.mean_loc_added
                && left.mean_loc_deleted == right.mean_loc_deleted
                && left.mean_diff_bytes == right.mean_diff_bytes
                && left.mean_quality == right.mean_quality
                && left.pareto_optimal == right.pareto_optimal
        })
}

fn evaluation_summaries_equivalent(left: &EvaluationSummary, right: &EvaluationSummary) -> bool {
    left.version == right.version
        && left.manifest_version == right.manifest_version
        && left.experiment_id == right.experiment_id
        && left.fake_seed == right.fake_seed
        && left.evidence == right.evidence
        && left.declared_inputs_digest == right.declared_inputs_digest
        && left.dispatch_comparability_claim == right.dispatch_comparability_claim
        && left.dispatch_comparisons == right.dispatch_comparisons
        && profile_summaries_equivalent(&left.profile_summaries, &right.profile_summaries)
        && left.pareto_conclusion == right.pareto_conclusion
        && pareto_frontiers_equivalent(&left.pareto_frontier, &right.pareto_frontier, false)
        && left.objective_scoring == right.objective_scoring
        && left.objective_selection == right.objective_selection
}

fn role_usage_maps_equivalent(
    left: &BTreeMap<AgentRole, RoleUsageReport>,
    right: &BTreeMap<AgentRole, RoleUsageReport>,
) -> bool {
    left.len() == right.len()
        && left.iter().all(|(role, left)| {
            right.get(role).is_some_and(|right| {
                left.models == right.models
                    && left.usage == right.usage
                    && match (left.cost_usd, right.cost_usd) {
                        (Some(left), Some(right)) => approximately_equal(left, right),
                        (None, None) => true,
                        _ => false,
                    }
                    && left.observation == right.observation
                    && left.unavailable_reason == right.unavailable_reason
            })
        })
}

fn pareto_frontiers_equivalent(
    left: &[ParetoPoint],
    right: &[ParetoPoint],
    allow_missing_legacy_operational_axes: bool,
) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            left.profile_id == right.profile_id
                && approximately_equal(left.mean_cost_usd, right.mean_cost_usd)
                && optional_pareto_axis_equivalent(
                    left.mean_quota_consumption_tokens,
                    right.mean_quota_consumption_tokens,
                    allow_missing_legacy_operational_axes,
                )
                && optional_pareto_axis_equivalent(
                    left.mean_wall_time_ms,
                    right.mean_wall_time_ms,
                    allow_missing_legacy_operational_axes,
                )
                && left.quality_basis_points == right.quality_basis_points
                && left.held_out_basis_points == right.held_out_basis_points
                && left.breadth_basis_points == right.breadth_basis_points
                && left.anti_shortcut_basis_points == right.anti_shortcut_basis_points
        })
}

fn optional_pareto_axis_equivalent(
    observed: Option<PreciseMean>,
    expected: Option<PreciseMean>,
    allow_missing_legacy_axis: bool,
) -> bool {
    observed == expected || (allow_missing_legacy_axis && observed.is_none())
}

fn validate_usage(usage: Usage, field: &str) -> Result<(), EvaluationError> {
    let expected = usage
        .input_tokens
        .checked_add(usage.output_tokens)
        .ok_or_else(|| overflow(format!("{field}.total_tokens")))?;
    if usage.total_tokens != expected {
        return Err(invalid_results(
            format!("{field}.total_tokens"),
            format!(
                "must equal input_tokens + output_tokens ({expected}), got {}",
                usage.total_tokens
            ),
        ));
    }
    Ok(())
}

fn checked_add_usage(
    left: Usage,
    right: Usage,
    context: impl Into<String>,
) -> Result<Usage, EvaluationError> {
    let context = context.into();
    let input_tokens = left
        .input_tokens
        .checked_add(right.input_tokens)
        .ok_or_else(|| overflow(format!("{context} input tokens")))?;
    let output_tokens = left
        .output_tokens
        .checked_add(right.output_tokens)
        .ok_or_else(|| overflow(format!("{context} output tokens")))?;
    let total_tokens = input_tokens
        .checked_add(output_tokens)
        .ok_or_else(|| overflow(format!("{context} total tokens")))?;
    Ok(Usage {
        input_tokens,
        output_tokens,
        total_tokens,
    })
}

fn checked_add_u64(
    left: u64,
    right: u64,
    context: impl Into<String>,
) -> Result<u64, EvaluationError> {
    let context = context.into();
    left.checked_add(right).ok_or_else(|| overflow(context))
}

fn evaluation_wall_time_limit_ms(manifest: &EvaluationManifest) -> Result<u64, EvaluationError> {
    manifest
        .limits
        .wall_time_seconds
        .checked_mul(1_000)
        .ok_or_else(|| overflow("manifest wall-time limit in milliseconds"))
}

fn ratio_basis_points(passed: u64, total: u64) -> u32 {
    ((passed * u64::from(BASIS_POINTS)) / total) as u32
}

fn approximately_equal(left: f64, right: f64) -> bool {
    let scale = left.abs().max(right.abs()).max(1.0);
    (left - right).abs() <= f64::EPSILON * scale * 8.0
}

fn require_finite_nonnegative(field: &str, value: f64) -> Result<(), EvaluationError> {
    if !value.is_finite() || value < 0.0 {
        return Err(invalid_results(
            field,
            format!("must be finite and nonnegative, got {value}"),
        ));
    }
    Ok(())
}

fn require_nonempty(field: &str, value: &str) -> Result<(), EvaluationError> {
    if value.trim().is_empty() {
        return Err(invalid_manifest(
            field,
            "must not be empty or whitespace-only",
        ));
    }
    Ok(())
}

fn require_result_nonempty(field: &str, value: &str) -> Result<(), EvaluationError> {
    if value.trim().is_empty() {
        return Err(invalid_results(
            field,
            "must not be empty or whitespace-only",
        ));
    }
    Ok(())
}

fn require_digest(field: &str, value: &str) -> Result<(), EvaluationError> {
    require_nonempty(field, value)?;
    if value.chars().any(char::is_whitespace) {
        return Err(invalid_manifest(
            field,
            "must be a single digest token without whitespace",
        ));
    }
    if value.len() < 8 {
        return Err(invalid_manifest(
            field,
            "must contain at least eight characters to avoid an ambiguous content binding",
        ));
    }
    Ok(())
}

fn require_git_object_id(field: &str, value: &str) -> Result<(), EvaluationError> {
    let is_supported_length = value.len() == 40 || value.len() == 64;
    if !is_supported_length || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid_manifest(
            field,
            "must be a full 40- or 64-character hexadecimal Git object id",
        ));
    }
    Ok(())
}

fn profile_fingerprint(profile: &EvaluationProfile) -> String {
    let mut material = String::new();
    for (role, selection) in &profile.role_models {
        material.push_str(role_name(*role));
        material.push('\0');
        material.push_str(selection.model.as_deref().unwrap_or(""));
        material.push('\0');
        material.push_str(selection.reasoning_effort.as_deref().unwrap_or(""));
        material.push('\0');
    }
    stable_digest(&material)
}

fn digest_serializable(value: &impl Serialize) -> Result<String, EvaluationError> {
    let bytes = serde_json::to_vec(value).map_err(|error| {
        EvaluationError::DeclaredInputsSerialization {
            message: error.to_string(),
        }
    })?;
    Ok(stable_digest_bytes(&bytes))
}

fn stable_digest(value: &str) -> String {
    stable_digest_bytes(value.as_bytes())
}

fn stable_digest_bytes(value: &[u8]) -> String {
    format!("fnv1a64:{:016x}", stable_hash(0, value))
}

fn stable_hash(seed: u64, value: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64 ^ seed;
    for byte in value {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn sanitize_identifier(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '-'
            }
        })
        .collect()
}

fn role_name(role: AgentRole) -> &'static str {
    match role {
        AgentRole::Supervisor => "supervisor",
        AgentRole::ChildOrchestrator => "child_orchestrator",
        AgentRole::Worker => "worker",
        AgentRole::GateClassifier => "gate_classifier",
        AgentRole::Auditor => "auditor",
    }
}

fn display_roles(roles: &BTreeSet<AgentRole>) -> String {
    roles
        .iter()
        .map(|role| role_name(*role))
        .collect::<Vec<_>>()
        .join(", ")
}

fn invalid_manifest(field: impl Into<String>, message: impl Into<String>) -> EvaluationError {
    EvaluationError::InvalidManifest {
        field: field.into(),
        message: message.into(),
    }
}

pub(crate) fn invalid_results(
    field: impl Into<String>,
    message: impl Into<String>,
) -> EvaluationError {
    EvaluationError::InvalidResults {
        field: field.into(),
        message: message.into(),
    }
}

fn overflow(context: impl Into<String>) -> EvaluationError {
    EvaluationError::ArithmeticOverflow {
        context: context.into(),
    }
}

impl fmt::Display for EvaluationEvidenceKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProvisionalDeterministicFakeOnly => {
                formatter.write_str("provisional_deterministic_fake_only")
            }
        }
    }
}

mod experiment;
pub mod rescore;
pub use experiment::{
    parse_experiment_manifest, run_fake_supervise_experiment, ExperimentEvidence,
    ExperimentEvidenceKind, ExperimentManifest, ExperimentProfileSummary, ExperimentResults,
    ExperimentRun, ExperimentRunRequest, EXPERIMENT_MANIFEST_SCHEMA_VERSION,
    EXPERIMENT_RESULTS_SCHEMA_VERSION, EXPERIMENT_RESULT_SCHEMA,
    LEGACY_EXPERIMENT_RESULTS_SCHEMA_VERSION, LEGACY_EXPERIMENT_RESULT_SCHEMA,
};

#[cfg(test)]
mod tests;
