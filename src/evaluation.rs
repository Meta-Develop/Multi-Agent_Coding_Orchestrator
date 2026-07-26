//! Provisional, deterministic model-mix evaluation over hand-authored plans.
//!
//! Phase A deliberately executes only synthetic fixtures. The resulting documents are useful for
//! developing comparison tooling, but their schema makes them ineligible as production model
//! economics or as evidence for a named default.

use crate::{
    llm::provider::Usage,
    supervise::{
        AgentRole, Finding, FindingSeverity, RoleModelSelection, RoleUsageObservation,
        RoleUsageReport,
    },
};
use serde::{Deserialize, Deserializer, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::PathBuf,
};
use thiserror::Error;

pub const EVALUATION_MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const EVALUATION_RESULTS_SCHEMA_VERSION: u32 = 1;
pub const MAX_EVALUATION_REPETITIONS: u32 = 100;
pub const PROVISIONAL_FAKE_EVIDENCE_NOTICE: &str = "deterministic fake-provider evidence only; \
     not eligible to justify production model economics or a named default";

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

/// Limits which must remain identical for runs to be comparable.
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
    pub target: EvaluationTarget,
    /// A full Git object id (SHA-1 or SHA-256) for the common repository base.
    pub repository_base_snapshot: String,
    pub limits: EvaluationLimits,
    pub held_out_validation: Vec<HeldOutValidation>,
    pub repetitions: u32,
    pub profiles: Vec<EvaluationProfile>,
}

impl EvaluationManifest {
    /// Validate all invariants that make phase-A repetitions comparable.
    pub fn validate(&self) -> Result<(), EvaluationError> {
        if self.version != EVALUATION_MANIFEST_SCHEMA_VERSION {
            return Err(EvaluationError::UnsupportedManifestVersion {
                found: self.version,
                supported: EVALUATION_MANIFEST_SCHEMA_VERSION,
            });
        }
        require_nonempty("experiment_id", &self.experiment_id)?;
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

    fn comparability_binding(&self) -> ComparabilityBinding {
        ComparabilityBinding {
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationEvidence {
    pub kind: EvaluationEvidenceKind,
    pub real_provider_executed: bool,
    pub eligible_for_production_economics: bool,
    pub eligible_to_justify_named_default: bool,
    pub notice: String,
}

impl EvaluationEvidence {
    fn provisional_fake_only() -> Self {
        Self {
            kind: EvaluationEvidenceKind::ProvisionalDeterministicFakeOnly,
            real_provider_executed: false,
            eligible_for_production_economics: false,
            eligible_to_justify_named_default: false,
            notice: PROVISIONAL_FAKE_EVIDENCE_NOTICE.to_string(),
        }
    }

    fn validate(&self) -> Result<(), EvaluationError> {
        let expected = Self::provisional_fake_only();
        if self != &expected {
            return Err(invalid_results(
                "evidence",
                "phase-A results must carry the exact provisional fake-only evidence declaration",
            ));
        }
        Ok(())
    }
}

/// Fields which must be identical across every repetition and profile.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComparabilityBinding {
    pub target: EvaluationTarget,
    pub repository_base_snapshot: String,
    pub limits: EvaluationLimits,
    pub held_out_validation: Vec<HeldOutValidation>,
    pub profiles: Vec<EvaluationProfile>,
}

/// Isolation evidence for one synthetic repetition.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IsolatedRunState {
    /// Unique workspace identity. Reusing one identity across repetitions fails validation.
    pub isolation_id: String,
    /// Equivalent starting-state fingerprint shared by every run.
    pub starting_state_fingerprint: String,
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

/// One independently isolated fake repetition.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationRepetitionResult {
    pub profile_id: String,
    pub repetition: u32,
    pub comparability_digest: String,
    pub isolated_state: IsolatedRunState,
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
    pub mean_wall_time_ms: u64,
    pub mean_churn_count: u64,
    pub mean_conflict_count: u64,
    pub mean_loc_added: u64,
    pub mean_loc_deleted: u64,
    pub mean_diff_bytes: u64,
    pub mean_quality: QualityScore,
    pub pareto_optimal: bool,
}

/// Cost-versus-quality projection for a non-dominated profile.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ParetoPoint {
    pub profile_id: String,
    pub mean_cost_usd: f64,
    pub quality_basis_points: u32,
    pub held_out_basis_points: u32,
    pub breadth_basis_points: u32,
    pub anti_shortcut_basis_points: u32,
}

/// Versioned, machine-readable result schema.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationResults {
    pub version: u32,
    pub manifest_version: u32,
    pub experiment_id: String,
    pub evidence: EvaluationEvidence,
    pub comparability: ComparabilityBinding,
    pub comparability_digest: String,
    pub runs: Vec<EvaluationRepetitionResult>,
    pub profile_summaries: Vec<ProfileSummary>,
    pub pareto_frontier: Vec<ParetoPoint>,
}

impl EvaluationResults {
    /// Revalidate isolation, run bindings, observations, aggregates, and the Pareto projection
    /// against the manifest.
    pub fn validate_against(&self, manifest: &EvaluationManifest) -> Result<(), EvaluationError> {
        validate_run_comparability(manifest, self)
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
        "real-provider evaluation requires explicit allow_real_provider=true; no provider was run"
    )]
    RealProviderOptInRequired,
    #[error(
        "real-provider evaluation is unavailable in phase A even with explicit opt-in; use deterministic_fake or a later real-provider harness"
    )]
    RealProviderUnavailableInPhaseA,
    #[error("evaluation arithmetic overflow while aggregating {context}")]
    ArithmeticOverflow { context: String },
    #[error("failed to serialize the comparability binding: {message}")]
    ComparabilitySerialization { message: String },
}

/// Run a validated evaluation request. Phase A only permits deterministic fake execution.
pub fn run_evaluation(
    manifest: &EvaluationManifest,
    request: EvaluationRunRequest,
) -> Result<EvaluationResults, EvaluationError> {
    manifest.validate()?;
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

/// Execute deterministic fake repetitions. This function never invokes a provider or a command.
pub fn run_deterministic_fake(
    manifest: &EvaluationManifest,
    seed: u64,
) -> Result<EvaluationResults, EvaluationError> {
    manifest.validate()?;
    let comparability = manifest.comparability_binding();
    let comparability_digest = digest_serializable(&comparability)?;
    let starting_state_fingerprint = stable_digest(&format!(
        "phase-a-starting-state:{}:{comparability_digest}",
        manifest.repository_base_snapshot
    ));
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
            let metrics = fake_metrics(manifest, profile, &profile_fingerprint, repetition, seed)?;
            runs.push(EvaluationRepetitionResult {
                profile_id: profile.id.clone(),
                repetition,
                comparability_digest: comparability_digest.clone(),
                isolated_state: IsolatedRunState {
                    isolation_id: format!(
                        "fake-{}-{}-{:016x}-{}",
                        sanitize_identifier(&manifest.experiment_id),
                        sanitize_identifier(&profile.id),
                        stable_hash(0x8ebc_6af0_9c88_c6e3, profile.id.as_bytes()),
                        repetition
                    ),
                    starting_state_fingerprint: starting_state_fingerprint.clone(),
                },
                metrics,
            });
        }
    }

    let (profile_summaries, pareto_frontier) = summarize_profiles(manifest, &runs)?;
    let results = EvaluationResults {
        version: EVALUATION_RESULTS_SCHEMA_VERSION,
        manifest_version: manifest.version,
        experiment_id: manifest.experiment_id.clone(),
        evidence: EvaluationEvidence::provisional_fake_only(),
        comparability,
        comparability_digest,
        runs,
        profile_summaries,
        pareto_frontier,
    };
    validate_run_comparability(manifest, &results)?;
    Ok(results)
}

/// Check that every result starts from equivalent isolated state and is bound to the same target,
/// snapshot, limits, and held-out validations.
pub fn validate_run_comparability(
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

    let expected_binding = manifest.comparability_binding();
    if results.comparability != expected_binding {
        return Err(invalid_results(
            "comparability",
            "target, base snapshot, limits, held-out validation, or full role/model profile set \
             differ from the manifest",
        ));
    }
    let expected_digest = digest_serializable(&expected_binding)?;
    if results.comparability_digest != expected_digest {
        return Err(invalid_results(
            "comparability_digest",
            format!(
                "expected manifest binding digest '{expected_digest}', got '{}'",
                results.comparability_digest
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
    let mut seen_isolation_ids = BTreeSet::new();
    let expected_starting_state_fingerprint = stable_digest(&format!(
        "phase-a-starting-state:{}:{expected_digest}",
        manifest.repository_base_snapshot
    ));
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
        if run.comparability_digest != expected_digest {
            return Err(invalid_results(
                field("comparability_digest"),
                "run is not bound to the manifest target and constraints",
            ));
        }
        require_result_nonempty(
            &field("isolated_state.isolation_id"),
            &run.isolated_state.isolation_id,
        )?;
        if !seen_isolation_ids.insert(run.isolated_state.isolation_id.as_str()) {
            return Err(invalid_results(
                field("isolated_state.isolation_id"),
                format!(
                    "isolation identity '{}' was reused; repetitions must use independent state",
                    run.isolated_state.isolation_id
                ),
            ));
        }
        require_result_nonempty(
            &field("isolated_state.starting_state_fingerprint"),
            &run.isolated_state.starting_state_fingerprint,
        )?;
        if run.isolated_state.starting_state_fingerprint != expected_starting_state_fingerprint {
            return Err(invalid_results(
                field("isolated_state.starting_state_fingerprint"),
                format!(
                    "starting state is not equivalent to the bound repository snapshot; expected \
                     '{expected_starting_state_fingerprint}', got '{}'",
                    run.isolated_state.starting_state_fingerprint
                ),
            ));
        }
        validate_metrics(manifest, profile, &run.metrics, run_index)?;
    }

    let (expected_summaries, expected_frontier) = summarize_profiles(manifest, &results.runs)?;
    if results.profile_summaries != expected_summaries {
        return Err(invalid_results(
            "profile_summaries",
            "aggregates do not match the repetition observations",
        ));
    }
    if results.pareto_frontier != expected_frontier {
        return Err(invalid_results(
            "pareto_frontier",
            "frontier does not match cost-versus-quality dominance over profile summaries",
        ));
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
) -> Result<EvaluationMetrics, EvaluationError> {
    let run_material = format!(
        "{}:{}:{}:{}",
        manifest.target.spec_or_goal_digest,
        manifest.repository_base_snapshot,
        profile_fingerprint,
        repetition
    );
    let run_hash = stable_hash(seed, run_material.as_bytes());
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
                observation: RoleUsageObservation::ProcessObserved,
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

    Ok(EvaluationMetrics {
        role_usage,
        total_usage,
        total_cost_usd,
        wall_time_ms: 1_000 + ((run_hash >> 5) % 9_001),
        churn_count: 1 + ((run_hash >> 13) % 12),
        conflict_count: (run_hash >> 19) % 4,
        loc_added,
        loc_deleted,
        diff_bytes,
        held_out_validation,
        review,
        quality,
    })
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
        if report.observation != RoleUsageObservation::ProcessObserved {
            return Err(invalid_results(
                field(&format!("role_usage.{}.observation", role_name(*role))),
                "fake fixture must contain an explicit per-role observation",
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
                    observation: RoleUsageObservation::ProcessObserved,
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
        let repetitions_u64 = u64::from(manifest.repetitions);
        let repetitions_f64 = f64::from(manifest.repetitions);
        summaries.push(ProfileSummary {
            profile_id: profile.id.clone(),
            repetitions: manifest.repetitions,
            aggregate_role_usage,
            aggregate_usage,
            aggregate_cost_usd,
            mean_cost_usd: aggregate_cost_usd / repetitions_f64,
            mean_wall_time_ms: wall_time_ms / repetitions_u64,
            mean_churn_count: churn_count / repetitions_u64,
            mean_conflict_count: conflict_count / repetitions_u64,
            mean_loc_added: loc_added / repetitions_u64,
            mean_loc_deleted: loc_deleted / repetitions_u64,
            mean_diff_bytes: diff_bytes / repetitions_u64,
            mean_quality: QualityScore {
                held_out_basis_points: average_basis_points(held_out_quality, repetitions_u64)?,
                breadth_basis_points: average_basis_points(breadth_quality, repetitions_u64)?,
                anti_shortcut_basis_points: average_basis_points(
                    anti_shortcut_quality,
                    repetitions_u64,
                )?,
                overall_basis_points: average_basis_points(overall_quality, repetitions_u64)?,
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
            .then_with(|| right.quality_basis_points.cmp(&left.quality_basis_points))
            .then_with(|| left.profile_id.cmp(&right.profile_id))
    });
    Ok((summaries, frontier))
}

fn dominates(candidate: &ProfileSummary, other: &ProfileSummary) -> bool {
    let no_more_expensive = candidate.mean_cost_usd <= other.mean_cost_usd;
    let no_lower_quality =
        candidate.mean_quality.overall_basis_points >= other.mean_quality.overall_basis_points;
    let strictly_better = candidate.mean_cost_usd < other.mean_cost_usd
        || candidate.mean_quality.overall_basis_points > other.mean_quality.overall_basis_points;
    no_more_expensive && no_lower_quality && strictly_better
}

fn average_basis_points(total: u64, count: u64) -> Result<u32, EvaluationError> {
    let average = total / count;
    u32::try_from(average).map_err(|_| overflow("mean quality basis points"))
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
    let bytes =
        serde_json::to_vec(value).map_err(|error| EvaluationError::ComparabilitySerialization {
            message: error.to_string(),
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

    fn manifest() -> EvaluationManifest {
        EvaluationManifest {
            version: EVALUATION_MANIFEST_SCHEMA_VERSION,
            experiment_id: "issue-26-phase-a".to_string(),
            target: EvaluationTarget {
                spec_or_goal_id: "issue-26".to_string(),
                spec_or_goal_digest:
                    "sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e1bca75d84e1400c421b321"
                        .to_string(),
                hand_authored_plan_digest:
                    "sha256:908a9d30f280908a3d153f21b3e401797f22cfb43a27c2a08fc2e76d715a8084"
                        .to_string(),
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

    #[test]
    fn deterministic_fake_results_are_reproducible_complete_and_provisional() {
        let manifest = manifest();
        let request = EvaluationRunRequest {
            fake_seed: 42,
            ..EvaluationRunRequest::default()
        };
        let first = run_evaluation(&manifest, request).expect("first deterministic fake run");
        let second = run_evaluation(&manifest, request).expect("second deterministic fake run");

        assert_eq!(first, second);
        assert_eq!(
            first.evidence.kind,
            EvaluationEvidenceKind::ProvisionalDeterministicFakeOnly
        );
        assert!(!first.evidence.real_provider_executed);
        assert!(!first.evidence.eligible_for_production_economics);
        assert!(!first.evidence.eligible_to_justify_named_default);
        assert_eq!(first.runs.len(), 6);
        assert_eq!(first.profile_summaries.len(), 2);
        assert!(!first.pareto_frontier.is_empty());

        let isolation_ids = first
            .runs
            .iter()
            .map(|run| run.isolated_state.isolation_id.as_str())
            .collect::<BTreeSet<_>>();
        let state_fingerprints = first
            .runs
            .iter()
            .map(|run| run.isolated_state.starting_state_fingerprint.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(isolation_ids.len(), first.runs.len());
        assert_eq!(state_fingerprints.len(), 1);
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
            .expect("generated results remain comparable");
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

        let results = run_deterministic_fake(&manifest, 7).expect("fake results");
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

        let mut invalid_selection = serde_json::to_value(&manifest).expect("serialize manifest");
        invalid_selection["profiles"][0]["role_models"]["worker"]["unexpected_selection_field"] =
            json!(true);
        let error = serde_json::from_value::<EvaluationManifest>(invalid_selection)
            .expect_err("unknown RoleModelSelection fields fail closed");
        assert!(error.to_string().contains("unknown field"));

        let results = run_deterministic_fake(&manifest, 7).expect("fake results");
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
    fn real_provider_execution_has_opt_in_and_phase_a_refusal_gates() {
        let manifest = manifest();
        let without_opt_in = run_evaluation(
            &manifest,
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
    fn manifest_rejects_hidden_or_noncomparable_profile_inputs() {
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
    fn comparability_validation_rejects_reused_or_changed_state() {
        let manifest = manifest();
        let mut results = run_deterministic_fake(&manifest, 11).expect("fake results");
        results.runs[1].isolated_state.isolation_id =
            results.runs[0].isolated_state.isolation_id.clone();
        let error = results
            .validate_against(&manifest)
            .expect_err("an isolation identity cannot be reused");
        assert!(error.to_string().contains("was reused"));

        let mut results = run_deterministic_fake(&manifest, 11).expect("fake results");
        results.runs[1]
            .isolated_state
            .starting_state_fingerprint
            .push_str("-different");
        let error = results
            .validate_against(&manifest)
            .expect_err("starting state must be equivalent");
        assert!(error
            .to_string()
            .contains("starting state is not equivalent"));

        let mut results = run_deterministic_fake(&manifest, 11).expect("fake results");
        for run in &mut results.runs {
            run.isolated_state.starting_state_fingerprint = "same-but-unbound".to_string();
        }
        let error = results
            .validate_against(&manifest)
            .expect_err("uniform but unbound state is not equivalent to the base snapshot");
        assert!(error.to_string().contains("bound repository snapshot"));

        let mut results = run_deterministic_fake(&manifest, 11).expect("fake results");
        results.comparability.limits.max_dispatches += 1;
        let error = results
            .validate_against(&manifest)
            .expect_err("changed dispatch limits break comparability");
        assert!(error
            .to_string()
            .contains("full role/model profile set differ"));

        let results = run_deterministic_fake(&manifest, 11).expect("fake results");
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
        let mut results = run_deterministic_fake(&manifest, 19).expect("fake results");
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

        let mut results = run_deterministic_fake(&manifest, 19).expect("fake results");
        results.runs[0].metrics.review.anti_shortcut.checks_run = 0;
        let error = results
            .validate_against(&manifest)
            .expect_err("anti-shortcut evidence cannot be omitted");
        assert!(error.to_string().contains("must be greater than zero"));

        let mut results = run_deterministic_fake(&manifest, 19).expect("fake results");
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

        let results = run_deterministic_fake(&manifest(), 23).expect("fake results");
        let mut high_quality = results.profile_summaries[0].clone();
        high_quality.mean_cost_usd = 1.0;
        high_quality.mean_loc_added = 1_000;
        high_quality.mean_quality = full_quality;
        let mut shortcut = results.profile_summaries[1].clone();
        shortcut.mean_cost_usd = 1.0;
        shortcut.mean_loc_added = 1;
        shortcut.mean_quality = shortcut_quality;

        assert!(dominates(&high_quality, &shortcut));
        assert!(!dominates(&shortcut, &high_quality));

        shortcut.mean_cost_usd = 0.5;
        assert!(!dominates(&high_quality, &shortcut));
        assert!(!dominates(&shortcut, &high_quality));
    }
}
