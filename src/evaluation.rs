//! Provisional, deterministic model-mix evaluation over hand-authored plans.
//!
//! Phase A deliberately executes only synthetic fixtures. The resulting documents are useful for
//! developing comparison tooling, but their schema makes them ineligible as production model
//! economics or as evidence for a named default.

use crate::{
    artifacts::state_auth::sha256_hex,
    llm::provider::Usage,
    supervise::{
        AgentRole, Finding, FindingSeverity, RoleModelSelection, RoleUsageObservation,
        RoleUsageReport,
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
pub const EVALUATION_RESULTS_SCHEMA_VERSION: u32 = 1;
pub const MAX_EVALUATION_REPETITIONS: u32 = 100;
pub const MAX_EXECUTION_ERROR_EVIDENCE_BYTES: usize = 256;
pub const COMMITTED_FIXTURE_FAKE_SEED: u64 = 26;
pub const PROVISIONAL_FAKE_EVIDENCE_NOTICE: &str = "provisional deterministic fake evidence over \
     a hand-authored plan; no isolated repository state was observed, so Issue #26 requirement-4 \
     comparability is not established and is deferred to Phase B; ineligible for production or \
     default decisions";

const BASIS_POINTS: u32 = 10_000;
const HELD_OUT_WEIGHT_PERCENT: u32 = 50;
const BREADTH_WEIGHT_PERCENT: u32 = 25;
const ANTI_SHORTCUT_WEIGHT_PERCENT: u32 = 25;

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
        validate_held_out_bindings(&self.held_out_validation)?;
        validate_profiles(&self.profiles)?;
        Ok(())
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

    fn declared_inputs_binding(&self) -> DeclaredInputsBinding {
        DeclaredInputsBinding {
            target: self.target.clone(),
            repository_base_snapshot: self.repository_base_snapshot.clone(),
            limits: self.limits,
            held_out_validation: self.held_out_validation.clone(),
            profiles: self.profiles.clone(),
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
    fn new(total: u64, count: u32) -> Result<Self, EvaluationError> {
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
    pub mean_loc_added: PreciseMean,
    pub mean_loc_deleted: PreciseMean,
    pub mean_diff_bytes: PreciseMean,
    pub mean_quality: PreciseQualityScore,
    pub pareto_optimal: bool,
}

/// Cost-versus-quality projection for a non-dominated profile.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ParetoPoint {
    pub profile_id: String,
    pub mean_cost_usd: f64,
    pub quality_basis_points: PreciseMean,
    pub held_out_basis_points: PreciseMean,
    pub breadth_basis_points: PreciseMean,
    pub anti_shortcut_basis_points: PreciseMean,
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
    pub runs: Vec<EvaluationRepetitionResult>,
    pub profile_summaries: Vec<ProfileSummary>,
    pub pareto_frontier: Vec<ParetoPoint>,
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
            profile_summaries: self.profile_summaries.clone(),
            pareto_frontier: self.pareto_frontier.clone(),
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
    pub profile_summaries: Vec<ProfileSummary>,
    pub pareto_frontier: Vec<ParetoPoint>,
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
}

impl From<StrictRoleModelSelection> for RoleModelSelection {
    fn from(selection: StrictRoleModelSelection) -> Self {
        Self {
            model: selection.model,
            reasoning_effort: selection.reasoning_effort,
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
    let declared_inputs = manifest.declared_inputs_binding();
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
            let (execution, metrics) =
                fake_metrics(manifest, profile, &profile_fingerprint, repetition, seed)?;
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
            });
        }
    }

    let (profile_summaries, pareto_frontier) = summarize_profiles(manifest, &runs)?;
    let results = EvaluationResults {
        version: EVALUATION_RESULTS_SCHEMA_VERSION,
        manifest_version: manifest.version,
        experiment_id: manifest.experiment_id.clone(),
        fake_seed: seed,
        evidence: EvaluationEvidence::provisional_fake_only(),
        declared_inputs,
        declared_inputs_digest,
        runs,
        profile_summaries,
        pareto_frontier,
    };
    validate_results_against_manifest(manifest, &results)?;
    Ok(results)
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
    if results.version != EVALUATION_RESULTS_SCHEMA_VERSION {
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

    let expected_binding = manifest.declared_inputs_binding();
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
        validate_metrics(manifest, profile, &run.metrics, run_index)?;
    }

    let (expected_summaries, expected_frontier) = summarize_profiles(manifest, &results.runs)?;
    if !profile_summaries_equivalent(&results.profile_summaries, &expected_summaries) {
        return Err(invalid_results(
            "profile_summaries",
            "aggregates do not match the repetition observations",
        ));
    }
    if !pareto_frontiers_equivalent(&results.pareto_frontier, &expected_frontier) {
        return Err(invalid_results(
            "pareto_frontier",
            "frontier does not match cost-versus-quality dominance over profile summaries",
        ));
    }
    Ok(())
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
    let quality = calculate_quality(&held_out_validation, &review)?;
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
    let expected_quality = calculate_quality(&metrics.held_out_validation, &metrics.review)?;
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

fn calculate_quality(
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
    let weighted = held_out_basis_points * HELD_OUT_WEIGHT_PERCENT
        + breadth_basis_points * BREADTH_WEIGHT_PERCENT
        + anti_shortcut_basis_points * ANTI_SHORTCUT_WEIGHT_PERCENT;
    Ok(QualityScore {
        held_out_basis_points,
        breadth_basis_points,
        anti_shortcut_basis_points,
        overall_basis_points: weighted / 100,
    })
}

fn summarize_profiles(
    manifest: &EvaluationManifest,
    runs: &[EvaluationRepetitionResult],
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

    for index in 0..summaries.len() {
        let dominated = summaries.iter().enumerate().any(|(other_index, other)| {
            other_index != index && dominates(other, &summaries[index])
        });
        summaries[index].pareto_optimal = !dominated;
    }
    let mut frontier = summaries
        .iter()
        .filter(|summary| summary.pareto_optimal)
        .map(|summary| ParetoPoint {
            profile_id: summary.profile_id.clone(),
            mean_cost_usd: summary.mean_cost_usd,
            quality_basis_points: summary.mean_quality.overall_basis_points,
            held_out_basis_points: summary.mean_quality.held_out_basis_points,
            breadth_basis_points: summary.mean_quality.breadth_basis_points,
            anti_shortcut_basis_points: summary.mean_quality.anti_shortcut_basis_points,
        })
        .collect::<Vec<_>>();
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
    let quality_order = candidate
        .mean_quality
        .overall_basis_points
        .cmp_value(&other.mean_quality.overall_basis_points);
    let no_lower_quality = quality_order.is_ge();
    let strictly_better = candidate.mean_cost_usd < other.mean_cost_usd || quality_order.is_gt();
    no_more_expensive && no_lower_quality && strictly_better
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
        && profile_summaries_equivalent(&left.profile_summaries, &right.profile_summaries)
        && pareto_frontiers_equivalent(&left.pareto_frontier, &right.pareto_frontier)
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

fn pareto_frontiers_equivalent(left: &[ParetoPoint], right: &[ParetoPoint]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            left.profile_id == right.profile_id
                && approximately_equal(left.mean_cost_usd, right.mean_cost_usd)
                && left.quality_basis_points == right.quality_basis_points
                && left.held_out_basis_points == right.held_out_basis_points
                && left.breadth_basis_points == right.breadth_basis_points
                && left.anti_shortcut_basis_points == right.anti_shortcut_basis_points
        })
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

fn invalid_results(field: impl Into<String>, message: impl Into<String>) -> EvaluationError {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const FIXTURE_PLAN: &[u8] =
        include_bytes!("../tests/fixtures/model_mix_evaluation/hand-authored-plan-v1.json");
    const FIXTURE_MANIFEST: &str =
        include_str!("../tests/fixtures/model_mix_evaluation/manifest-v1.json");
    const FIXTURE_RESULTS: &str =
        include_str!("../tests/fixtures/model_mix_evaluation/runs-v1.json");
    const FIXTURE_SUMMARY: &str =
        include_str!("../tests/fixtures/model_mix_evaluation/summary-v1.json");

    fn model(model: &str, reasoning_effort: &str) -> RoleModelSelection {
        RoleModelSelection {
            model: Some(model.to_string()),
            reasoning_effort: Some(reasoning_effort.to_string()),
        }
    }

    fn profile(id: &str, orchestrator_model: &str, worker_model: &str) -> EvaluationProfile {
        EvaluationProfile {
            id: id.to_string(),
            role_models: BTreeMap::from([
                (
                    AgentRole::ChildOrchestrator,
                    model(orchestrator_model, "high"),
                ),
                (AgentRole::Worker, model(worker_model, "medium")),
            ]),
        }
    }

    fn labelled_test_plan() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "version": 1,
            "evidence": EvaluationEvidence::provisional_fake_only(),
            "task": "deterministic fake evaluation test plan",
            "assignments": []
        }))
        .expect("serialize labelled test plan")
    }

    fn manifest() -> EvaluationManifest {
        let plan = labelled_test_plan();
        EvaluationManifest {
            version: EVALUATION_MANIFEST_SCHEMA_VERSION,
            experiment_id: "issue-26-phase-a".to_string(),
            evidence: EvaluationEvidence::provisional_fake_only(),
            target: EvaluationTarget {
                spec_or_goal_id: "issue-26".to_string(),
                spec_or_goal_digest:
                    "sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e1bca75d84e1400c421b321"
                        .to_string(),
                hand_authored_plan_digest: format!("sha256:{}", sha256_hex(&plan)),
            },
            repository_base_snapshot: "a".repeat(40),
            limits: EvaluationLimits {
                wall_time_seconds: 600,
                max_dispatches: 8,
            },
            held_out_validation: vec![
                HeldOutValidation {
                    id: "unit".to_string(),
                    command: vec![
                        "cargo".to_string(),
                        "test".to_string(),
                        "held_out_unit".to_string(),
                    ],
                },
                HeldOutValidation {
                    id: "integration".to_string(),
                    command: vec![
                        "cargo".to_string(),
                        "test".to_string(),
                        "held_out_integration".to_string(),
                    ],
                },
            ],
            repetitions: 3,
            profiles: vec![
                profile("frontier-workers", "frontier-v1", "fast-v1"),
                profile("all-frontier", "frontier-v1", "frontier-v1"),
            ],
        }
    }

    fn run_fake(
        manifest: &EvaluationManifest,
        seed: u64,
    ) -> Result<EvaluationResults, EvaluationError> {
        run_evaluation(
            manifest,
            &labelled_test_plan(),
            EvaluationRunRequest {
                fake_seed: seed,
                ..EvaluationRunRequest::default()
            },
        )
    }

    fn committed_manifest() -> EvaluationManifest {
        serde_json::from_str(FIXTURE_MANIFEST).expect("deserialize committed evaluation manifest")
    }

    fn committed_results() -> EvaluationResults {
        serde_json::from_str(FIXTURE_RESULTS).expect("deserialize committed evaluation results")
    }

    fn committed_summary() -> EvaluationSummary {
        serde_json::from_str(FIXTURE_SUMMARY).expect("deserialize committed evaluation summary")
    }

    fn precise_quality(score: QualityScore) -> PreciseQualityScore {
        PreciseQualityScore {
            held_out_basis_points: PreciseMean {
                total: u64::from(score.held_out_basis_points),
                count: 1,
            },
            breadth_basis_points: PreciseMean {
                total: u64::from(score.breadth_basis_points),
                count: 1,
            },
            anti_shortcut_basis_points: PreciseMean {
                total: u64::from(score.anti_shortcut_basis_points),
                count: 1,
            },
            overall_basis_points: PreciseMean {
                total: u64::from(score.overall_basis_points),
                count: 1,
            },
        }
    }

    #[test]
    fn committed_fixtures_match_the_deterministic_harness() {
        let manifest = committed_manifest();
        manifest.validate().expect("validate committed manifest");
        manifest
            .validate_hand_authored_plan(FIXTURE_PLAN)
            .expect("manifest binds the exact committed plan bytes");

        let results = committed_results();
        assert_eq!(results.fake_seed, COMMITTED_FIXTURE_FAKE_SEED);
        results
            .validate_against(&manifest)
            .expect("committed results validate against their manifest");
        let reproduced = run_evaluation(
            &manifest,
            FIXTURE_PLAN,
            EvaluationRunRequest {
                fake_seed: COMMITTED_FIXTURE_FAKE_SEED,
                ..EvaluationRunRequest::default()
            },
        )
        .expect("reproduce committed deterministic results");
        assert_eq!(
            FIXTURE_RESULTS,
            format!(
                "{}\n",
                serde_json::to_string_pretty(&reproduced)
                    .expect("serialize reproduced deterministic results")
            )
        );

        let summary = committed_summary();
        summary
            .validate_against(&manifest, &results)
            .expect("committed summary is an exact validated projection");
        assert_eq!(
            FIXTURE_SUMMARY,
            format!(
                "{}\n",
                serde_json::to_string_pretty(&reproduced.summary())
                    .expect("serialize reproduced deterministic summary")
            )
        );
    }

    #[test]
    fn committed_fixtures_use_unique_synthetic_ids_without_comparability_claims() {
        let manifest = committed_manifest();
        let results = committed_results();
        results
            .validate_against(&manifest)
            .expect("fixture declared-input consistency validation");

        let expected_runs = manifest.profiles.len() * manifest.repetitions as usize;
        assert_eq!(results.runs.len(), expected_runs);
        for profile in &manifest.profiles {
            let repetitions = results
                .runs
                .iter()
                .filter(|run| run.profile_id == profile.id)
                .map(|run| run.repetition)
                .collect::<BTreeSet<_>>();
            assert_eq!(
                repetitions,
                (0..manifest.repetitions).collect::<BTreeSet<_>>()
            );
        }

        let fake_run_ids = results
            .runs
            .iter()
            .map(|run| run.synthetic_run_identity.fake_run_id.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(fake_run_ids.len(), expected_runs);
        assert!(!results.evidence.observed_isolated_repository_state);
        assert_eq!(
            results.evidence.requirement_four_comparability,
            RequirementFourComparability::NotEstablishedDeferredToPhaseB
        );
        assert!(results
            .runs
            .iter()
            .all(|run| run.declared_inputs_digest == results.declared_inputs_digest));
    }

    #[test]
    fn committed_fixtures_have_complete_metrics_and_anti_shortcut_aware_pareto_results() {
        let manifest = committed_manifest();
        let results = committed_results();
        results
            .validate_against(&manifest)
            .expect("fixture metric and Pareto validation");

        for run in &results.runs {
            let profile = manifest
                .profiles
                .iter()
                .find(|profile| profile.id == run.profile_id)
                .expect("run profile is manifest-bound");
            assert_eq!(run.metrics.role_usage.len(), profile.role_models.len());
            assert!(run.metrics.role_usage.values().all(|report| {
                report.usage.is_some()
                    && report.cost_usd.is_some()
                    && report.observation == RoleUsageObservation::SyntheticFake
            }));
            assert_eq!(
                run.metrics.held_out_validation.len(),
                manifest.held_out_validation.len()
            );
            assert!(run.metrics.review.breadth.checks_run > 0);
            assert!(run.metrics.review.anti_shortcut.checks_run > 0);
            assert!(run.metrics.quality.held_out_basis_points <= BASIS_POINTS);
            assert!(run.metrics.quality.breadth_basis_points <= BASIS_POINTS);
            assert!(run.metrics.quality.anti_shortcut_basis_points <= BASIS_POINTS);
        }

        assert!(!results.pareto_frontier.is_empty());
        assert!(results.profile_summaries.iter().all(|summary| {
            summary
                .aggregate_role_usage
                .values()
                .all(|report| report.observation == RoleUsageObservation::SyntheticFake)
        }));
        assert!(results.pareto_frontier.iter().all(|point| {
            point.quality_basis_points.total > 0
                && point.held_out_basis_points.total > 0
                && point.breadth_basis_points.total > 0
                && point.anti_shortcut_basis_points.total > 0
        }));
        let frontier_profiles = results
            .pareto_frontier
            .iter()
            .map(|point| point.profile_id.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            frontier_profiles,
            results
                .profile_summaries
                .iter()
                .filter(|summary| summary.pareto_optimal)
                .map(|summary| summary.profile_id.as_str())
                .collect()
        );
    }

    #[test]
    fn committed_fixtures_are_schema_labeled_provisional_fake_only() {
        let manifest = committed_manifest();
        let results = committed_results();
        let summary = committed_summary();
        let plan: Value = serde_json::from_slice(FIXTURE_PLAN).expect("parse committed plan");
        let plan_evidence: EvaluationEvidence =
            serde_json::from_value(plan["evidence"].clone()).expect("parse plan evidence");
        for evidence in [
            &manifest.evidence,
            &plan_evidence,
            &results.evidence,
            &summary.evidence,
        ] {
            assert_eq!(
                evidence.kind,
                EvaluationEvidenceKind::ProvisionalDeterministicFakeOnly
            );
            assert_eq!(evidence.plan_basis, EvaluationPlanBasis::HandAuthored);
            assert!(!evidence.real_provider_executed);
            assert!(!evidence.observed_isolated_repository_state);
            assert_eq!(
                evidence.requirement_four_comparability,
                RequirementFourComparability::NotEstablishedDeferredToPhaseB
            );
            assert!(!evidence.eligible_for_production_economics);
            assert!(!evidence.eligible_to_justify_named_default);
            assert!(!evidence.eligible_for_production_or_default_decisions);
            assert_eq!(evidence.notice, PROVISIONAL_FAKE_EVIDENCE_NOTICE);
        }
    }

    #[test]
    #[ignore = "explicit snapshot regeneration only"]
    fn regenerate_committed_evaluation_fixtures() {
        let manifest = committed_manifest();
        manifest.validate().expect("validate committed manifest");
        manifest
            .validate_hand_authored_plan(FIXTURE_PLAN)
            .expect("manifest binds committed plan");
        let results = run_evaluation(
            &manifest,
            FIXTURE_PLAN,
            EvaluationRunRequest {
                fake_seed: COMMITTED_FIXTURE_FAKE_SEED,
                ..EvaluationRunRequest::default()
            },
        )
        .expect("generate deterministic fixture results");
        let summary = results.summary();
        let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/model_mix_evaluation");

        std::fs::write(
            fixture_root.join("runs-v1.json"),
            format!(
                "{}\n",
                serde_json::to_string_pretty(&results).expect("serialize fixture results")
            ),
        )
        .expect("write fixture results");
        std::fs::write(
            fixture_root.join("summary-v1.json"),
            format!(
                "{}\n",
                serde_json::to_string_pretty(&summary).expect("serialize fixture summary")
            ),
        )
        .expect("write fixture summary");
    }

    #[test]
    fn deterministic_fake_results_are_reproducible_complete_and_provisional() {
        let manifest = manifest();
        let request = EvaluationRunRequest {
            fake_seed: 42,
            ..EvaluationRunRequest::default()
        };
        let plan = labelled_test_plan();
        let first =
            run_evaluation(&manifest, &plan, request).expect("first deterministic fake run");
        let second =
            run_evaluation(&manifest, &plan, request).expect("second deterministic fake run");

        assert_eq!(first, second);
        assert_eq!(
            first.evidence.kind,
            EvaluationEvidenceKind::ProvisionalDeterministicFakeOnly
        );
        assert!(!first.evidence.real_provider_executed);
        assert!(!first.evidence.observed_isolated_repository_state);
        assert!(!first.evidence.eligible_for_production_economics);
        assert!(!first.evidence.eligible_to_justify_named_default);
        assert_eq!(first.runs.len(), 6);
        assert_eq!(first.profile_summaries.len(), 2);
        assert!(!first.pareto_frontier.is_empty());

        let fake_run_ids = first
            .runs
            .iter()
            .map(|run| run.synthetic_run_identity.fake_run_id.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(fake_run_ids.len(), first.runs.len());
        for run in &first.runs {
            assert_eq!(run.metrics.role_usage.len(), 2);
            assert!(run
                .metrics
                .role_usage
                .values()
                .all(|usage| usage.usage.is_some() && usage.cost_usd.is_some()));
            assert_eq!(run.metrics.held_out_validation.len(), 2);
            assert!(run.metrics.review.breadth.checks_run > 0);
            assert!(run.metrics.review.anti_shortcut.checks_run > 0);
        }
        first
            .validate_against(&manifest)
            .expect("generated results remain consistent with declared inputs");
    }

    #[test]
    fn deterministic_fake_retains_all_outcomes_and_obeys_execution_limits() {
        let mut manifest = manifest();
        manifest.limits = EvaluationLimits {
            wall_time_seconds: 1,
            max_dispatches: 1,
        };
        let results = run_fake(&manifest, 31).expect("bounded fake results");

        assert_eq!(
            results.runs.len(),
            manifest.profiles.len() * manifest.repetitions as usize
        );
        let outcomes = results
            .runs
            .iter()
            .map(|run| run.execution.outcome)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            outcomes,
            BTreeSet::from([
                EvaluationExecutionOutcome::Success,
                EvaluationExecutionOutcome::Failure,
                EvaluationExecutionOutcome::Timeout,
            ])
        );
        assert_eq!(
            results
                .runs
                .iter()
                .filter(|run| run.execution.outcome != EvaluationExecutionOutcome::Success)
                .count(),
            manifest.profiles.len() * 2
        );

        for run in &results.runs {
            assert!(run.execution.observed_dispatch_count <= manifest.limits.max_dispatches);
            assert!(run.metrics.wall_time_ms <= manifest.limits.wall_time_seconds * 1_000);
            match run.execution.outcome {
                EvaluationExecutionOutcome::Success => {
                    assert!(run.execution.error_evidence.is_none());
                }
                EvaluationExecutionOutcome::Failure | EvaluationExecutionOutcome::Timeout => {
                    let error = run
                        .execution
                        .error_evidence
                        .as_ref()
                        .expect("unsuccessful fake run retains bounded error evidence");
                    assert!(!error.message.trim().is_empty());
                    assert!(error.message.len() <= MAX_EXECUTION_ERROR_EVIDENCE_BYTES);
                }
            }
        }
        assert!(results
            .profile_summaries
            .iter()
            .all(|summary| summary.repetitions == manifest.repetitions));
        results
            .validate_against(&manifest)
            .expect("successes and retained unsuccessful runs validate together");
    }

    #[test]
    fn execution_validation_enforces_limits_and_bounded_outcome_evidence() {
        let manifest = manifest();

        let mut results = run_fake(&manifest, 37).expect("fake results");
        results.runs[0].execution.observed_dispatch_count = manifest.limits.max_dispatches + 1;
        let error = results
            .validate_against(&manifest)
            .expect_err("dispatch limit must be enforced");
        assert!(error.to_string().contains("exceeds manifest limit"));
        assert!(error.to_string().contains("observed_dispatch_count"));

        let mut results = run_fake(&manifest, 37).expect("fake results");
        results.runs[0].metrics.wall_time_ms = manifest.limits.wall_time_seconds * 1_000 + 1;
        let error = results
            .validate_against(&manifest)
            .expect_err("wall-time limit must be enforced");
        assert!(error.to_string().contains("exceeds manifest limit"));
        assert!(error.to_string().contains("wall_time_ms"));

        let mut results = run_fake(&manifest, 37).expect("fake results");
        let failed = results
            .runs
            .iter_mut()
            .find(|run| run.execution.outcome == EvaluationExecutionOutcome::Failure)
            .expect("fake failure");
        failed.execution.error_evidence = None;
        let error = results
            .validate_against(&manifest)
            .expect_err("failure evidence is required");
        assert!(error
            .to_string()
            .contains("required when outcome is failure"));

        let mut results = run_fake(&manifest, 37).expect("fake results");
        let successful = results
            .runs
            .iter_mut()
            .find(|run| run.execution.outcome == EvaluationExecutionOutcome::Success)
            .expect("fake success");
        successful.execution.error_evidence = Some(ExecutionErrorEvidence {
            message: "unexpected evidence".to_string(),
            truncated: false,
        });
        let error = results
            .validate_against(&manifest)
            .expect_err("success cannot carry error evidence");
        assert!(error.to_string().contains("must be absent"));

        let mut results = run_fake(&manifest, 37).expect("fake results");
        let timed_out = results
            .runs
            .iter_mut()
            .find(|run| run.execution.outcome == EvaluationExecutionOutcome::Timeout)
            .expect("fake timeout");
        timed_out
            .execution
            .error_evidence
            .as_mut()
            .expect("timeout evidence")
            .message = "x".repeat(MAX_EXECUTION_ERROR_EVIDENCE_BYTES + 1);
        let error = results
            .validate_against(&manifest)
            .expect_err("oversized error evidence must fail closed");
        assert!(error
            .to_string()
            .contains("must be at most 256 UTF-8 bytes"));
    }

    #[test]
    fn precise_profile_means_retain_non_divisible_totals() {
        let manifest = manifest();
        let mut results = run_fake(&manifest, 41).expect("fake results");
        let profile_id = manifest.profiles[0].id.as_str();
        for (index, run) in results
            .runs
            .iter_mut()
            .filter(|run| run.profile_id == profile_id)
            .enumerate()
        {
            let value = if index == 0 { 1 } else { 2 };
            run.metrics.wall_time_ms = value;
            run.metrics.churn_count = value;
            run.metrics.conflict_count = value;
            run.metrics.loc_added = value;
            run.metrics.loc_deleted = value;
            run.metrics.diff_bytes = value;
            run.metrics.quality = QualityScore {
                held_out_basis_points: value as u32,
                breadth_basis_points: value as u32,
                anti_shortcut_basis_points: value as u32,
                overall_basis_points: value as u32,
            };
        }

        let (summaries, _) =
            summarize_profiles(&manifest, &results.runs).expect("summarize exact totals");
        let summary = summaries
            .iter()
            .find(|summary| summary.profile_id == profile_id)
            .expect("profile summary");
        let five_thirds = PreciseMean { total: 5, count: 3 };
        assert_eq!(summary.mean_wall_time_ms, five_thirds);
        assert_eq!(summary.mean_churn_count, five_thirds);
        assert_eq!(summary.mean_conflict_count, five_thirds);
        assert_eq!(summary.mean_loc_added, five_thirds);
        assert_eq!(summary.mean_loc_deleted, five_thirds);
        assert_eq!(summary.mean_diff_bytes, five_thirds);
        assert_eq!(summary.mean_quality.held_out_basis_points, five_thirds);
        assert_eq!(summary.mean_quality.breadth_basis_points, five_thirds);
        assert_eq!(summary.mean_quality.anti_shortcut_basis_points, five_thirds);
        assert_eq!(summary.mean_quality.overall_basis_points, five_thirds);
    }

    #[test]
    fn versioned_schemas_round_trip_and_reject_unknown_fields() {
        let manifest = manifest();
        let manifest_json = serde_json::to_value(&manifest).expect("serialize manifest");
        assert_eq!(
            manifest_json["version"],
            json!(EVALUATION_MANIFEST_SCHEMA_VERSION)
        );
        assert_eq!(
            serde_json::from_value::<EvaluationManifest>(manifest_json).expect("read manifest"),
            manifest
        );

        let results = run_fake(&manifest, 7).expect("fake results");
        let results_json = serde_json::to_value(&results).expect("serialize results");
        assert_eq!(
            results_json["version"],
            json!(EVALUATION_RESULTS_SCHEMA_VERSION)
        );
        assert_eq!(
            results_json["evidence"]["kind"],
            json!("provisional_deterministic_fake_only")
        );
        let decoded =
            serde_json::from_value::<EvaluationResults>(results_json).expect("read results");
        decoded
            .validate_against(&manifest)
            .expect("valid round trip");

        let mut invalid_manifest = serde_json::to_value(&manifest).expect("serialize manifest");
        invalid_manifest["unversioned_extension"] = json!(true);
        let error = serde_json::from_value::<EvaluationManifest>(invalid_manifest)
            .expect_err("unknown manifest fields fail closed");
        assert!(error.to_string().contains("unknown field"));

        let mut invalid_manifest_evidence =
            serde_json::to_value(&manifest).expect("serialize manifest");
        invalid_manifest_evidence["evidence"]["unversioned_extension"] = json!(true);
        let error = serde_json::from_value::<EvaluationManifest>(invalid_manifest_evidence)
            .expect_err("unknown manifest evidence fields fail closed");
        assert!(error.to_string().contains("unknown field"));

        let mut invalid_selection = serde_json::to_value(&manifest).expect("serialize manifest");
        invalid_selection["profiles"][0]["role_models"]["worker"]["unexpected_selection_field"] =
            json!(true);
        let error = serde_json::from_value::<EvaluationManifest>(invalid_selection)
            .expect_err("unknown RoleModelSelection fields fail closed");
        assert!(error.to_string().contains("unknown field"));

        let results = run_fake(&manifest, 7).expect("fake results");
        let mut invalid_total_usage = serde_json::to_value(&results).expect("serialize results");
        invalid_total_usage["runs"][0]["metrics"]["total_usage"]["unexpected_usage_field"] =
            json!(true);
        let error = serde_json::from_value::<EvaluationResults>(invalid_total_usage)
            .expect_err("unknown Usage fields fail closed");
        assert!(error.to_string().contains("unknown field"));

        let mut invalid_role_report = serde_json::to_value(&results).expect("serialize results");
        invalid_role_report["runs"][0]["metrics"]["role_usage"]["worker"]
            ["unexpected_role_usage_field"] = json!(true);
        let error = serde_json::from_value::<EvaluationResults>(invalid_role_report)
            .expect_err("unknown RoleUsageReport fields fail closed");
        assert!(error.to_string().contains("unknown field"));

        let mut invalid_nested_usage = serde_json::to_value(&results).expect("serialize results");
        invalid_nested_usage["profile_summaries"][0]["aggregate_role_usage"]["worker"]["usage"]
            ["unexpected_nested_usage_field"] = json!(true);
        let error = serde_json::from_value::<EvaluationResults>(invalid_nested_usage)
            .expect_err("nested unknown Usage fields in summaries fail closed");
        assert!(error.to_string().contains("unknown field"));

        let mut invalid_finding = serde_json::to_value(&results).expect("serialize results");
        invalid_finding["runs"][0]["metrics"]["review"]["findings"] = json!([{
            "severity": "warning",
            "message": "representative review finding",
            "paths": [],
            "unexpected_finding_field": true
        }]);
        let error = serde_json::from_value::<EvaluationResults>(invalid_finding)
            .expect_err("unknown Finding fields fail closed");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn public_runner_binds_and_validates_supplied_plan_bytes_before_dispatch() {
        let manifest = manifest();
        for request in [
            EvaluationRunRequest::default(),
            EvaluationRunRequest {
                execution: EvaluationExecution::RealProvider,
                allow_real_provider: true,
                fake_seed: 0,
            },
        ] {
            let mismatch = run_evaluation(&manifest, br#"{"evidence":{}}"#, request)
                .expect_err("mismatched bytes must fail before execution selection");
            assert!(matches!(
                mismatch,
                EvaluationError::HandAuthoredPlanBindingMismatch { .. }
            ));
        }

        let invalid_json = b"not-json";
        let mut invalid_manifest = manifest.clone();
        invalid_manifest.target.hand_authored_plan_digest =
            format!("sha256:{}", sha256_hex(invalid_json));
        let invalid = run_evaluation(
            &invalid_manifest,
            invalid_json,
            EvaluationRunRequest::default(),
        )
        .expect_err("digest-matched invalid JSON must fail before fake execution");
        assert!(matches!(
            invalid,
            EvaluationError::InvalidHandAuthoredPlan { .. }
        ));

        let unlabelled = br#"{"version":1,"task":"unlabelled"}"#;
        let mut unlabelled_manifest = manifest;
        unlabelled_manifest.target.hand_authored_plan_digest =
            format!("sha256:{}", sha256_hex(unlabelled));
        let unlabelled_error = run_evaluation(
            &unlabelled_manifest,
            unlabelled,
            EvaluationRunRequest::default(),
        )
        .expect_err("digest-matched unlabelled JSON must fail before fake execution");
        assert!(matches!(
            unlabelled_error,
            EvaluationError::InvalidHandAuthoredPlan { .. }
        ));
    }

    #[test]
    fn real_provider_execution_has_opt_in_and_phase_a_refusal_gates() {
        let manifest = manifest();
        let plan = labelled_test_plan();
        let without_opt_in = run_evaluation(
            &manifest,
            &plan,
            EvaluationRunRequest {
                execution: EvaluationExecution::RealProvider,
                allow_real_provider: false,
                fake_seed: 0,
            },
        );
        assert_eq!(
            without_opt_in,
            Err(EvaluationError::RealProviderOptInRequired)
        );

        let explicitly_opted_in = run_evaluation(
            &manifest,
            &plan,
            EvaluationRunRequest {
                execution: EvaluationExecution::RealProvider,
                allow_real_provider: true,
                fake_seed: 0,
            },
        );
        assert_eq!(
            explicitly_opted_in,
            Err(EvaluationError::RealProviderUnavailableInPhaseA)
        );
    }

    #[test]
    fn manifest_rejects_hidden_or_inconsistent_profile_inputs() {
        let mut candidate = manifest();
        candidate.repository_base_snapshot = "main".to_string();
        let error = candidate
            .validate()
            .expect_err("symbolic Git refs are not immutable");
        assert!(matches!(
            error,
            EvaluationError::InvalidManifest { ref field, .. }
                if field == "repository_base_snapshot"
        ));

        let mut candidate = manifest();
        candidate.profiles[1].role_models = candidate.profiles[0].role_models.clone();
        let error = candidate
            .validate()
            .expect_err("duplicate mixes are rejected");
        assert!(error.to_string().contains("duplicates another"));

        let mut candidate = manifest();
        candidate.profiles[1]
            .role_models
            .insert(AgentRole::Auditor, model("review-v1", "high"));
        let error = candidate
            .validate()
            .expect_err("profile role sets must match");
        assert!(error.to_string().contains("role set differs"));

        let mut candidate = manifest();
        candidate.profiles[0]
            .role_models
            .get_mut(&AgentRole::Worker)
            .expect("worker selection")
            .model = None;
        let error = candidate
            .validate()
            .expect_err("ambient model defaults are not reproducible");
        assert!(error.to_string().contains("explicitly name a model"));
    }

    #[test]
    fn declared_input_validation_rejects_reused_ids_or_changed_bindings() {
        let manifest = manifest();
        let mut results = run_fake(&manifest, 11).expect("fake results");
        results.runs[1].synthetic_run_identity.fake_run_id =
            results.runs[0].synthetic_run_identity.fake_run_id.clone();
        let error = results
            .validate_against(&manifest)
            .expect_err("a synthetic run identity cannot be reused");
        assert!(error.to_string().contains("was reused"));

        let mut results = run_fake(&manifest, 11).expect("fake results");
        results.declared_inputs.limits.max_dispatches += 1;
        let error = results
            .validate_against(&manifest)
            .expect_err("changed dispatch limits break declared-input consistency");
        assert!(error
            .to_string()
            .contains("full role/model profile set differ"));

        let results = run_fake(&manifest, 11).expect("fake results");
        let mut changed_manifest = manifest.clone();
        changed_manifest.profiles[0]
            .role_models
            .get_mut(&AgentRole::Worker)
            .expect("worker selection")
            .reasoning_effort = Some("low".to_string());
        changed_manifest
            .validate()
            .expect("reasoning-effort variant remains a valid manifest");
        let error = results
            .validate_against(&changed_manifest)
            .expect_err("reasoning-effort drift changes the full profile binding");
        assert!(error
            .to_string()
            .contains("full role/model profile set differ"));
    }

    #[test]
    fn metric_validation_requires_complete_accounting_and_quality_evidence() {
        let manifest = manifest();
        let mut results = run_fake(&manifest, 19).expect("fake results");
        results.runs[0]
            .metrics
            .role_usage
            .get_mut(&AgentRole::Worker)
            .expect("worker usage")
            .cost_usd = None;
        let error = results
            .validate_against(&manifest)
            .expect_err("per-role cost is required");
        assert!(error.to_string().contains("per-role cost is required"));

        let mut results = run_fake(&manifest, 19).expect("fake results");
        results.runs[0]
            .metrics
            .role_usage
            .get_mut(&AgentRole::Worker)
            .expect("worker usage")
            .observation = RoleUsageObservation::ProcessObserved;
        let error = results
            .validate_against(&manifest)
            .expect_err("synthetic usage cannot be labelled process-observed");
        assert!(error.to_string().contains("synthetic_fake"));

        let mut results = run_fake(&manifest, 19).expect("fake results");
        results.runs[0].metrics.review.anti_shortcut.checks_run = 0;
        let error = results
            .validate_against(&manifest)
            .expect_err("anti-shortcut evidence cannot be omitted");
        assert!(error.to_string().contains("must be greater than zero"));

        let mut results = run_fake(&manifest, 19).expect("fake results");
        results.runs[0].metrics.total_usage.total_tokens += 1;
        let error = results
            .validate_against(&manifest)
            .expect_err("incoherent token accounting is rejected");
        assert!(error.to_string().contains("input_tokens + output_tokens"));
    }

    #[test]
    fn quality_and_pareto_retain_breadth_and_anti_shortcut_signals() {
        let held_out = vec![HeldOutValidationResult {
            id: "held-out".to_string(),
            assertions_run: 10,
            assertions_passed: 10,
            passed: true,
        }];
        let full_review = ReviewQuality {
            breadth: ReviewDimension {
                checks_run: 10,
                checks_passed: 10,
            },
            anti_shortcut: ReviewDimension {
                checks_run: 10,
                checks_passed: 10,
            },
            findings: Vec::new(),
        };
        let shortcut_review = ReviewQuality {
            breadth: ReviewDimension {
                checks_run: 10,
                checks_passed: 10,
            },
            anti_shortcut: ReviewDimension {
                checks_run: 10,
                checks_passed: 0,
            },
            findings: Vec::new(),
        };
        let full_quality = calculate_quality(&held_out, &full_review).expect("full quality");
        let shortcut_quality =
            calculate_quality(&held_out, &shortcut_review).expect("shortcut quality");
        assert_eq!(full_quality.overall_basis_points, BASIS_POINTS);
        assert_eq!(shortcut_quality.overall_basis_points, 7_500);

        let results = run_fake(&manifest(), 23).expect("fake results");
        let mut high_quality = results.profile_summaries[0].clone();
        high_quality.mean_cost_usd = 1.0;
        high_quality.mean_loc_added = PreciseMean {
            total: 1_000,
            count: 1,
        };
        high_quality.mean_quality = precise_quality(full_quality);
        let mut shortcut = results.profile_summaries[1].clone();
        shortcut.mean_cost_usd = 1.0;
        shortcut.mean_loc_added = PreciseMean { total: 1, count: 1 };
        shortcut.mean_quality = precise_quality(shortcut_quality);

        assert!(dominates(&high_quality, &shortcut));
        assert!(!dominates(&shortcut, &high_quality));

        shortcut.mean_cost_usd = 0.5;
        assert!(!dominates(&high_quality, &shortcut));
        assert!(!dominates(&shortcut, &high_quality));
    }
}
