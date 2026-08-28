//! Isolated Fake-supervise experiment runner for Issue #26.
//!
//! Each declared role/model profile runs the same bound goal/spec from a fresh Fake
//! supervise state. Network and real-provider execution are refused.
//! `production_eligible` stays false.

use super::{
    calculate_quality, invalid_results, select_experiment_frontier, DispatchComparabilityClaim,
    EvaluationError, EvaluationExecution, EvaluationLimits, EvaluationProfile, Finding,
    FindingSeverity, HeldOutValidation, HeldOutValidationResult, ObjectiveScoringProvenance,
    ParetoConclusion, ParetoConclusionStatus, ParetoPoint, PreciseMean, PreciseQualityScore,
    QualityScore, ReviewDimension, ReviewQuality, MAX_EVALUATION_HELD_OUT_VALIDATIONS,
    MAX_EVALUATION_PROFILES, MAX_EVALUATION_REPETITIONS,
};
#[cfg(not(test))]
use crate::supervise::run_supervisor_plan_file;
use crate::{
    artifacts::state_auth::sha256_hex,
    llm::provider::Usage,
    machine_global::MachineGlobalRetentionBinding,
    objective_profile::{
        default_resolved_objective_profile, ObjectiveSelection, ResolvedObjectiveProfile,
    },
    orchestrator::{RunId, SemanticCoordinationMode},
    review::ReviewAggregationPolicy,
    supervise::{
        AgentRole, AssignmentPhase, OrchestratorAssignment, RoleModelSelection, RoleUsageReport,
        RunBudgetLimits, SupervisorAdmissionConfig, SupervisorFinalReport, SupervisorPlan,
        SupervisorRunOptions, SupervisorRuntime, UnavailableModelFallback, WorkerAssignment,
    },
};
use git2::{IndexAddOption, Repository, Signature};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
    time::Instant,
};

pub const EXPERIMENT_MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const LEGACY_EXPERIMENT_RESULTS_SCHEMA_VERSION: u32 = 1;
pub const EXPERIMENT_RESULTS_SCHEMA_VERSION: u32 = 2;
pub const LEGACY_EXPERIMENT_RESULT_SCHEMA: &str = "evaluation_experiment_result_v1";
pub const EXPERIMENT_RESULT_SCHEMA: &str = "evaluation_experiment_result_v2";
pub const ISOLATED_FAKE_SUPERVISE_NOTICE: &str =
    "isolated Fake supervise experiment; each profile \
     and repetition ran from a fresh in-process Fake supervise state with no network provider; \
     production_eligible remains false; ineligible for named-default or production economics; \
     held-out commands are recorded but not executed; real-provider experiments remain missing";

/// Versioned experiment input: one goal/spec, a profile set, and a repetition count.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentManifest {
    pub version: u32,
    pub experiment_id: String,
    pub goal: String,
    pub spec: String,
    pub limits: EvaluationLimits,
    pub held_out_validation: Vec<HeldOutValidation>,
    pub repetitions: u32,
    pub profiles: Vec<EvaluationProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub objective_profile: Option<ResolvedObjectiveProfile>,
}

impl ExperimentManifest {
    pub fn validate(&self) -> Result<(), EvaluationError> {
        if self.version != EXPERIMENT_MANIFEST_SCHEMA_VERSION {
            return Err(EvaluationError::UnsupportedExperimentManifestVersion {
                found: self.version,
                supported: EXPERIMENT_MANIFEST_SCHEMA_VERSION,
            });
        }
        require_text("experiment_id", &self.experiment_id)?;
        require_text("goal", &self.goal)?;
        require_text("spec", &self.spec)?;
        if self.limits.wall_time_seconds == 0 {
            return Err(invalid_experiment(
                "limits.wall_time_seconds",
                "must be greater than zero",
            ));
        }
        if self.limits.max_dispatches == 0 {
            return Err(invalid_experiment(
                "limits.max_dispatches",
                "must be greater than zero",
            ));
        }
        if self.repetitions == 0 || self.repetitions > MAX_EVALUATION_REPETITIONS {
            return Err(invalid_experiment(
                "repetitions",
                format!(
                    "must be between 1 and {MAX_EVALUATION_REPETITIONS}, got {}",
                    self.repetitions
                ),
            ));
        }
        if self.profiles.len() < 2 {
            return Err(invalid_experiment(
                "profiles",
                "must contain at least two role/model profiles for a comparison",
            ));
        }
        if self.profiles.len() > MAX_EVALUATION_PROFILES {
            return Err(invalid_experiment(
                "profiles",
                format!(
                    "must contain at most {MAX_EVALUATION_PROFILES} profiles, got {}",
                    self.profiles.len()
                ),
            ));
        }
        if self.held_out_validation.len() > MAX_EVALUATION_HELD_OUT_VALIDATIONS {
            return Err(invalid_experiment(
                "held_out_validation",
                format!(
                    "must contain at most {MAX_EVALUATION_HELD_OUT_VALIDATIONS} validations, got {}",
                    self.held_out_validation.len()
                ),
            ));
        }
        validate_held_out(&self.held_out_validation)?;
        validate_experiment_profiles(&self.profiles)?;
        self.resolved_objective_profile()?;
        Ok(())
    }

    fn resolved_objective_profile(&self) -> Result<ResolvedObjectiveProfile, EvaluationError> {
        let profile = match &self.objective_profile {
            Some(profile) => profile.clone(),
            None => default_resolved_objective_profile()
                .map_err(|error| invalid_experiment("objective_profile", error.to_string()))?,
        };
        profile
            .profile
            .validate()
            .map_err(|error| invalid_experiment("objective_profile", error.to_string()))?;
        Ok(profile)
    }

    pub fn goal_digest(&self) -> String {
        format!("sha256:{}", sha256_hex(self.goal.as_bytes()))
    }

    pub fn spec_digest(&self) -> String {
        format!("sha256:{}", sha256_hex(self.spec.as_bytes()))
    }
}

/// Execution request. Real-provider execution stays fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentRunRequest {
    pub execution: EvaluationExecution,
    pub allow_real_provider: bool,
}

impl Default for ExperimentRunRequest {
    fn default() -> Self {
        Self {
            execution: EvaluationExecution::DeterministicFake,
            allow_real_provider: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExperimentEvidenceKind {
    IsolatedFakeSupervise,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentEvidence {
    pub kind: ExperimentEvidenceKind,
    pub real_provider_executed: bool,
    pub isolated_fake_supervise_state: bool,
    pub production_eligible: bool,
    pub eligible_for_production_economics: bool,
    pub eligible_to_justify_named_default: bool,
    pub eligible_for_production_or_default_decisions: bool,
    pub notice: String,
}

impl ExperimentEvidence {
    fn isolated_fake() -> Self {
        Self {
            kind: ExperimentEvidenceKind::IsolatedFakeSupervise,
            real_provider_executed: false,
            isolated_fake_supervise_state: true,
            production_eligible: false,
            eligible_for_production_economics: false,
            eligible_to_justify_named_default: false,
            eligible_for_production_or_default_decisions: false,
            notice: ISOLATED_FAKE_SUPERVISE_NOTICE.to_string(),
        }
    }

    fn validate(&self) -> Result<(), EvaluationError> {
        if self != &Self::isolated_fake() {
            return Err(invalid_results(
                "evidence",
                "experiment results must keep production_eligible=false and refuse real-provider claims",
            ));
        }
        Ok(())
    }
}

/// One isolated Fake supervise repetition.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentRun {
    pub profile_id: String,
    pub repetition: u32,
    pub isolated_run_id: String,
    pub success: bool,
    pub production_eligible: bool,
    pub wall_time_ms: u64,
    pub assignment_count: usize,
    pub started_assignment_count: usize,
    pub completed_assignment_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_usage: Option<Usage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_cost_usd: Option<f64>,
    pub role_usage: BTreeMap<AgentRole, RoleUsageReport>,
    pub held_out_validation: Vec<HeldOutValidationResult>,
    pub review: ReviewQuality,
    pub quality: QualityScore,
}

/// Per-profile aggregate used for machine-readable comparison.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentProfileSummary {
    pub profile_id: String,
    pub repetitions: u32,
    pub mean_wall_time_ms: PreciseMean,
    pub mean_assignment_count: PreciseMean,
    pub mean_started_assignment_count: PreciseMean,
    pub mean_completed_assignment_count: PreciseMean,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aggregate_usage: Option<Usage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aggregate_cost_usd: Option<f64>,
    pub mean_cost_usd: f64,
    pub mean_quality: PreciseQualityScore,
    pub pareto_optimal: bool,
}

/// Comparable machine-readable experiment document.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentResults {
    pub version: u32,
    pub schema: String,
    pub experiment_id: String,
    pub goal_digest: String,
    pub spec_digest: String,
    pub evidence: ExperimentEvidence,
    pub dispatch_comparability_claim: DispatchComparabilityClaim,
    pub runs: Vec<ExperimentRun>,
    pub profile_summaries: Vec<ExperimentProfileSummary>,
    pub pareto_conclusion: ParetoConclusion,
    pub pareto_frontier: Vec<ParetoPoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub objective_scoring: Option<ObjectiveScoringProvenance>,
    #[serde(default)]
    pub objective_selection: Option<ObjectiveSelection>,
}

impl ExperimentResults {
    pub fn validate_against(&self, manifest: &ExperimentManifest) -> Result<(), EvaluationError> {
        let legacy_v1 = match self.version {
            EXPERIMENT_RESULTS_SCHEMA_VERSION => false,
            LEGACY_EXPERIMENT_RESULTS_SCHEMA_VERSION => true,
            _ => {
                return Err(EvaluationError::UnsupportedResultsVersion {
                    found: self.version,
                    supported: EXPERIMENT_RESULTS_SCHEMA_VERSION,
                });
            }
        };
        let expected_schema = if legacy_v1 {
            LEGACY_EXPERIMENT_RESULT_SCHEMA
        } else {
            EXPERIMENT_RESULT_SCHEMA
        };
        if self.schema != expected_schema {
            return Err(invalid_results(
                "schema",
                format!(
                    "expected {expected_schema} for results version {}",
                    self.version
                ),
            ));
        }
        if self.experiment_id != manifest.experiment_id {
            return Err(invalid_results(
                "experiment_id",
                format!(
                    "expected '{}', got '{}'",
                    manifest.experiment_id, self.experiment_id
                ),
            ));
        }
        if self.goal_digest != manifest.goal_digest() || self.spec_digest != manifest.spec_digest()
        {
            return Err(invalid_results(
                "goal_digest",
                "goal/spec digest does not match the bound experiment manifest",
            ));
        }
        self.evidence.validate()?;
        if self
            .dispatch_comparability_claim
            .provider_execution_difference_established
        {
            return Err(invalid_results(
                "dispatch_comparability_claim",
                "must not claim provider-execution differentiation",
            ));
        }
        let expected_runs = manifest
            .profiles
            .len()
            .checked_mul(manifest.repetitions as usize)
            .ok_or_else(|| EvaluationError::ArithmeticOverflow {
                context: "experiment run count".to_string(),
            })?;
        if self.runs.len() != expected_runs {
            return Err(invalid_results(
                "runs",
                format!("expected {expected_runs} runs, got {}", self.runs.len()),
            ));
        }
        if self.profile_summaries.len() != manifest.profiles.len() {
            return Err(invalid_results(
                "profile_summaries",
                "must contain exactly one summary per declared profile",
            ));
        }
        if self.runs.iter().any(|run| run.production_eligible) || self.evidence.production_eligible
        {
            return Err(invalid_results(
                "production_eligible",
                "Fake supervise experiment results must keep production_eligible=false",
            ));
        }
        let resolved_objective = manifest.resolved_objective_profile()?;
        match (&self.objective_scoring, legacy_v1) {
            (Some(scoring), false) => {
                scoring.validate()?;
                if scoring.applied_profile != resolved_objective {
                    return Err(invalid_results(
                        "objective_scoring.applied_profile",
                        "does not match the resolved objective bound by the experiment manifest",
                    ));
                }
            }
            (None, false) => {
                return Err(invalid_results(
                    "objective_scoring",
                    "experiment results schema v2 must bind canonical scoring provenance",
                ));
            }
            (None, true) if manifest.objective_profile.is_none() => {}
            (None, true) => {
                return Err(invalid_results(
                    "objective_scoring",
                    "legacy v1 may omit scoring provenance only when the manifest omitted the \
                     objective and therefore used the historical built-in default",
                ));
            }
            (Some(_), true) => {
                return Err(invalid_results(
                    "objective_scoring",
                    "legacy experiment results schema v1 must not claim v2 scoring provenance",
                ));
            }
        }
        let expected_selection = select_experiment_frontier(
            &resolved_objective,
            &self.profile_summaries,
            &self.pareto_frontier,
        )?;
        if legacy_v1 && self.objective_selection.is_some() {
            return Err(invalid_results(
                "objective_selection",
                "legacy experiment results schema v1 must not claim v2 selection evidence",
            ));
        }
        if !legacy_v1 && self.objective_selection != expected_selection {
            return Err(invalid_results(
                "objective_selection",
                "does not match the explicit profile policy applied after frontier construction",
            ));
        }
        Ok(())
    }
}

/// Parse and validate a versioned experiment manifest.
pub fn parse_experiment_manifest(bytes: &[u8]) -> Result<ExperimentManifest, EvaluationError> {
    let manifest = serde_json::from_slice::<ExperimentManifest>(bytes).map_err(|error| {
        EvaluationError::InvalidManifest {
            field: "manifest".to_string(),
            message: error.to_string(),
        }
    })?;
    manifest.validate()?;
    Ok(manifest)
}

/// Run every profile and repetition through isolated Fake supervise state.
pub fn run_fake_supervise_experiment(
    manifest: &ExperimentManifest,
    request: ExperimentRunRequest,
) -> Result<ExperimentResults, EvaluationError> {
    manifest.validate()?;
    match request.execution {
        EvaluationExecution::DeterministicFake => run_isolated_fake_supervise(manifest),
        EvaluationExecution::RealProvider if !request.allow_real_provider => {
            Err(EvaluationError::RealProviderOptInRequired)
        }
        EvaluationExecution::RealProvider => Err(EvaluationError::RealProviderUnavailableInPhaseA),
    }
}

fn run_isolated_fake_supervise(
    manifest: &ExperimentManifest,
) -> Result<ExperimentResults, EvaluationError> {
    crate::git_repository::configure_libgit2_repository_extensions().map_err(|error| {
        EvaluationError::FakeSuperviseExperiment {
            message: format!("failed to configure libgit2: {error:#}"),
        }
    })?;

    let objective_profile = manifest.resolved_objective_profile()?;
    let mut runs = Vec::with_capacity(
        manifest
            .profiles
            .len()
            .checked_mul(manifest.repetitions as usize)
            .ok_or_else(|| EvaluationError::ArithmeticOverflow {
                context: "experiment run capacity".to_string(),
            })?,
    );

    for profile in &manifest.profiles {
        for repetition in 0..manifest.repetitions {
            runs.push(run_isolated_profile(
                manifest,
                profile,
                &objective_profile,
                repetition,
            )?);
        }
    }

    let (mut profile_summaries, mut pareto_frontier) = summarize_experiment(manifest, &runs)?;
    let pareto_conclusion = experiment_pareto_conclusion(&profile_summaries);
    if pareto_conclusion.status != ParetoConclusionStatus::Available {
        for summary in &mut profile_summaries {
            summary.pareto_optimal = false;
        }
        pareto_frontier.clear();
    }
    let objective_selection =
        select_experiment_frontier(&objective_profile, &profile_summaries, &pareto_frontier)?;

    let results = ExperimentResults {
        version: EXPERIMENT_RESULTS_SCHEMA_VERSION,
        schema: EXPERIMENT_RESULT_SCHEMA.to_string(),
        experiment_id: manifest.experiment_id.clone(),
        goal_digest: manifest.goal_digest(),
        spec_digest: manifest.spec_digest(),
        evidence: ExperimentEvidence::isolated_fake(),
        dispatch_comparability_claim: DispatchComparabilityClaim {
            scope: super::EvaluationComparabilityScope::Dispatch,
            provider_execution_difference_established: false,
            notice: super::DISPATCH_COMPARABILITY_NOTICE.to_string(),
        },
        runs,
        profile_summaries,
        pareto_conclusion,
        pareto_frontier,
        objective_scoring: Some(ObjectiveScoringProvenance::original(objective_profile)),
        objective_selection,
    };
    results.validate_against(manifest)?;
    Ok(results)
}

fn run_isolated_profile(
    manifest: &ExperimentManifest,
    profile: &EvaluationProfile,
    objective_profile: &ResolvedObjectiveProfile,
    repetition: u32,
) -> Result<ExperimentRun, EvaluationError> {
    let isolated = IsolatedSuperviseState::create(manifest, profile, repetition)?;
    let started = Instant::now();
    #[cfg(test)]
    let report_result =
        crate::supervise::run_fake_supervisor_plan_file_for_test(isolated.options());
    #[cfg(not(test))]
    let report_result = run_supervisor_plan_file(isolated.options());
    let report = report_result.map_err(|error| EvaluationError::FakeSuperviseExperiment {
        message: format!(
            "profile '{}' repetition {repetition} Fake supervise failed: {error:#}",
            profile.id
        ),
    })?;
    let wall_time_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    capture_experiment_run(
        manifest,
        profile,
        objective_profile,
        repetition,
        isolated.run_id.as_str(),
        wall_time_ms,
        &report,
    )
}

fn capture_experiment_run(
    manifest: &ExperimentManifest,
    profile: &EvaluationProfile,
    objective_profile: &ResolvedObjectiveProfile,
    repetition: u32,
    run_id: &str,
    wall_time_ms: u64,
    report: &SupervisorFinalReport,
) -> Result<ExperimentRun, EvaluationError> {
    if report.runtime != SupervisorRuntime::Fake {
        return Err(EvaluationError::FakeSuperviseExperiment {
            message: format!(
                "profile '{}' repetition {repetition} did not stay on the Fake runtime",
                profile.id
            ),
        });
    }
    let production_eligible = report
        .role_economics_profile
        .as_ref()
        .is_some_and(|profile| profile.production_eligible);
    if production_eligible || report.publishable {
        return Err(EvaluationError::FakeSuperviseExperiment {
            message: "Fake supervise report claimed production_eligible or publishable evidence"
                .to_string(),
        });
    }

    let execution = report
        .role_economics_profile
        .as_ref()
        .and_then(|profile| profile.execution.as_ref());
    let assignment_count = execution
        .map(|execution| execution.assignment_count)
        .unwrap_or(report.orchestrator_reports.len());
    let started_assignment_count = execution
        .map(|execution| execution.started_assignment_count)
        .unwrap_or(assignment_count);
    let completed_assignment_count = execution
        .map(|execution| execution.completed_assignment_count)
        .unwrap_or(
            report
                .orchestrator_reports
                .iter()
                .filter(|child| child.accepted)
                .count(),
        );

    let held_out_validation = held_out_from_fake_report(manifest, report);
    let review = review_from_fake_report(report);
    let quality = calculate_quality(objective_profile, &held_out_validation, &review)?;

    Ok(ExperimentRun {
        profile_id: profile.id.clone(),
        repetition,
        isolated_run_id: run_id.to_string(),
        success: report.success,
        production_eligible: false,
        wall_time_ms,
        assignment_count,
        started_assignment_count,
        completed_assignment_count,
        total_usage: report.total_usage,
        total_cost_usd: report.total_cost_usd,
        role_usage: report.role_usage.clone(),
        held_out_validation,
        review,
        quality,
    })
}

fn held_out_from_fake_report(
    manifest: &ExperimentManifest,
    report: &SupervisorFinalReport,
) -> Vec<HeldOutValidationResult> {
    if manifest.held_out_validation.is_empty() {
        return vec![HeldOutValidationResult {
            id: "fake-supervise-success".to_string(),
            assertions_run: 1,
            assertions_passed: u32::from(report.success),
            passed: report.success,
        }];
    }
    manifest
        .held_out_validation
        .iter()
        .map(|binding| HeldOutValidationResult {
            id: binding.id.clone(),
            assertions_run: 1,
            assertions_passed: u32::from(report.success),
            passed: report.success,
        })
        .collect()
}

fn review_from_fake_report(report: &SupervisorFinalReport) -> ReviewQuality {
    let validation_run = report.validation_results.len().max(1) as u32;
    let validation_passed = if report.validation_results.is_empty() {
        u32::from(report.success)
    } else {
        report
            .validation_results
            .iter()
            .filter(|result| {
                !matches!(
                    result.status,
                    crate::supervise::ReviewStatus::Failed
                        | crate::supervise::ReviewStatus::Rejected
                )
            })
            .count() as u32
    };
    let mut findings = report.findings.clone();
    if findings.is_empty() {
        findings.push(Finding {
            severity: FindingSeverity::Info,
            message: "isolated Fake supervise experiment retained no extra findings".to_string(),
            paths: Vec::new(),
        });
    }
    ReviewQuality {
        breadth: ReviewDimension {
            checks_run: validation_run,
            checks_passed: validation_passed.min(validation_run),
        },
        anti_shortcut: ReviewDimension {
            checks_run: 1,
            checks_passed: u32::from(!report.publishable && !report.accepted),
        },
        findings,
    }
}

fn summarize_experiment(
    manifest: &ExperimentManifest,
    runs: &[ExperimentRun],
) -> Result<(Vec<ExperimentProfileSummary>, Vec<ParetoPoint>), EvaluationError> {
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

        let mut wall_time_ms = 0u64;
        let mut assignment_count = 0u64;
        let mut started_assignment_count = 0u64;
        let mut completed_assignment_count = 0u64;
        let mut aggregate_usage: Option<Usage> = None;
        let mut aggregate_cost_usd: Option<f64> = None;
        let mut held_out_quality = 0u64;
        let mut breadth_quality = 0u64;
        let mut anti_shortcut_quality = 0u64;
        let mut overall_quality = 0u64;

        for run in &profile_runs {
            wall_time_ms = wall_time_ms.checked_add(run.wall_time_ms).ok_or_else(|| {
                EvaluationError::ArithmeticOverflow {
                    context: "experiment wall time".to_string(),
                }
            })?;
            assignment_count = assignment_count
                .checked_add(run.assignment_count as u64)
                .ok_or_else(|| EvaluationError::ArithmeticOverflow {
                    context: "experiment assignment count".to_string(),
                })?;
            started_assignment_count = started_assignment_count
                .checked_add(run.started_assignment_count as u64)
                .ok_or_else(|| EvaluationError::ArithmeticOverflow {
                    context: "experiment started assignment count".to_string(),
                })?;
            completed_assignment_count = completed_assignment_count
                .checked_add(run.completed_assignment_count as u64)
                .ok_or_else(|| EvaluationError::ArithmeticOverflow {
                    context: "experiment completed assignment count".to_string(),
                })?;
            if let Some(usage) = run.total_usage {
                aggregate_usage = Some(match aggregate_usage {
                    Some(total) => total.saturating_add(usage),
                    None => usage,
                });
            }
            if let Some(cost) = run.total_cost_usd {
                aggregate_cost_usd = Some(aggregate_cost_usd.unwrap_or(0.0) + cost);
            }
            held_out_quality += u64::from(run.quality.held_out_basis_points);
            breadth_quality += u64::from(run.quality.breadth_basis_points);
            anti_shortcut_quality += u64::from(run.quality.anti_shortcut_basis_points);
            overall_quality += u64::from(run.quality.overall_basis_points);
        }

        let mean_cost_usd = aggregate_cost_usd
            .map(|cost| cost / f64::from(manifest.repetitions))
            .unwrap_or(0.0);
        summaries.push(ExperimentProfileSummary {
            profile_id: profile.id.clone(),
            repetitions: manifest.repetitions,
            mean_wall_time_ms: PreciseMean::new(wall_time_ms, manifest.repetitions)?,
            mean_assignment_count: PreciseMean::new(assignment_count, manifest.repetitions)?,
            mean_started_assignment_count: PreciseMean::new(
                started_assignment_count,
                manifest.repetitions,
            )?,
            mean_completed_assignment_count: PreciseMean::new(
                completed_assignment_count,
                manifest.repetitions,
            )?,
            aggregate_usage,
            aggregate_cost_usd,
            mean_cost_usd,
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
            other_index != index && experiment_dominates(other, &summaries[index])
        });
        summaries[index].pareto_optimal = !dominated;
    }
    let mut frontier = summaries
        .iter()
        .filter(|summary| summary.pareto_optimal)
        .map(|summary| {
            Ok(ParetoPoint {
                profile_id: summary.profile_id.clone(),
                mean_cost_usd: summary.mean_cost_usd,
                mean_quota_consumption_tokens: summary
                    .aggregate_usage
                    .map(|usage| {
                        let total = u64::try_from(usage.total_tokens).map_err(|_| {
                            EvaluationError::ArithmeticOverflow {
                                context: "experiment frontier quota consumption".to_string(),
                            }
                        })?;
                        PreciseMean::new(total, summary.repetitions)
                    })
                    .transpose()?,
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
            .then_with(|| left.profile_id.cmp(&right.profile_id))
    });
    Ok((summaries, frontier))
}

fn experiment_dominates(
    candidate: &ExperimentProfileSummary,
    other: &ExperimentProfileSummary,
) -> bool {
    let (Some(candidate_usage), Some(other_usage)) =
        (candidate.aggregate_usage, other.aggregate_usage)
    else {
        return false;
    };
    if candidate.aggregate_cost_usd.is_none() || other.aggregate_cost_usd.is_none() {
        return false;
    }
    let no_more_expensive = candidate.mean_cost_usd <= other.mean_cost_usd;
    let quota_order = super::compare_usage_means(
        candidate_usage.total_tokens,
        candidate.repetitions,
        other_usage.total_tokens,
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
    let no_lower_raw_quality =
        held_out_order.is_ge() && breadth_order.is_ge() && anti_shortcut_order.is_ge();
    let strictly_better = candidate.mean_cost_usd < other.mean_cost_usd
        || quota_order.is_lt()
        || latency_order.is_lt()
        || held_out_order.is_gt()
        || breadth_order.is_gt()
        || anti_shortcut_order.is_gt();
    no_more_expensive
        && quota_order.is_le()
        && latency_order.is_le()
        && no_lower_raw_quality
        && strictly_better
}

fn experiment_pareto_conclusion(summaries: &[ExperimentProfileSummary]) -> ParetoConclusion {
    let costs_differ = summaries
        .windows(2)
        .any(|pair| (pair[0].mean_cost_usd - pair[1].mean_cost_usd).abs() > f64::EPSILON);
    let quality_differs = summaries.windows(2).any(|pair| {
        pair[0].mean_quality.held_out_basis_points != pair[1].mean_quality.held_out_basis_points
            || pair[0].mean_quality.breadth_basis_points
                != pair[1].mean_quality.breadth_basis_points
            || pair[0].mean_quality.anti_shortcut_basis_points
                != pair[1].mean_quality.anti_shortcut_basis_points
    });
    let status = if summaries.len() < 2 {
        ParetoConclusionStatus::RefusedIncomparableDispatchEvidence
    } else if !costs_differ && !quality_differs {
        ParetoConclusionStatus::RefusedNoDispatchDifference
    } else {
        ParetoConclusionStatus::Available
    };
    ParetoConclusion {
        status,
        claim: DispatchComparabilityClaim {
            scope: super::EvaluationComparabilityScope::Dispatch,
            provider_execution_difference_established: false,
            notice: super::DISPATCH_COMPARABILITY_NOTICE.to_string(),
        },
    }
}

struct IsolatedSuperviseState {
    _workspace: tempfile::TempDir,
    repo: PathBuf,
    plan_file: PathBuf,
    run_id: RunId,
}

impl IsolatedSuperviseState {
    fn create(
        manifest: &ExperimentManifest,
        profile: &EvaluationProfile,
        repetition: u32,
    ) -> Result<Self, EvaluationError> {
        let workspace =
            tempfile::TempDir::new().map_err(|error| EvaluationError::FakeSuperviseExperiment {
                message: format!("failed to create isolated Fake supervise workspace: {error}"),
            })?;
        let repo = workspace.path().join("repo");
        let git =
            Repository::init(&repo).map_err(|error| EvaluationError::FakeSuperviseExperiment {
                message: format!("failed to initialize isolated Fake supervise repo: {error}"),
            })?;
        fs::write(
            repo.join("README.md"),
            format!("{}\n\n{}\n", manifest.goal, manifest.spec),
        )
        .map_err(|error| EvaluationError::FakeSuperviseExperiment {
            message: format!("failed to write isolated goal/spec: {error}"),
        })?;
        commit_isolated(&git, "isolated fake supervise baseline")?;

        let run_id = isolated_run_id(manifest, profile, repetition)?;
        let plan_file = workspace.path().join(format!("{}.json", run_id.as_str()));
        let plan = experiment_plan(manifest, profile);
        let bytes = serde_json::to_vec_pretty(&plan).map_err(|error| {
            EvaluationError::FakeSuperviseExperiment {
                message: format!("failed to serialize isolated Fake supervise plan: {error}"),
            }
        })?;
        fs::write(&plan_file, bytes).map_err(|error| EvaluationError::FakeSuperviseExperiment {
            message: format!("failed to write isolated Fake supervise plan: {error}"),
        })?;

        Ok(Self {
            _workspace: workspace,
            repo,
            plan_file,
            run_id,
        })
    }

    fn options(&self) -> SupervisorRunOptions {
        SupervisorRunOptions {
            repo: self.repo.clone(),
            plan_file: self.plan_file.clone(),
            run_id: self.run_id.clone(),
            parent_node: None,
            codex_bin: PathBuf::from("unused-fake-supervise-experiment"),
            runtime: SupervisorRuntime::Fake,
            allow_dirty_primary: false,
            allow_live_run_collision: false,
            admission_overrides: SupervisorAdmissionConfig::default(),
            budget_overrides: RunBudgetLimits::default(),
            budget_max_duration_seconds: None,
            machine_global_retention: Some(MachineGlobalRetentionBinding {
                config: self.repo.join("unused-machine-global.json"),
                root_id: "runtime".to_string(),
                owner: "maco-evaluation-experiment".to_string(),
                correction_correlation_id: self.run_id.as_str().to_string(),
            }),
        }
    }
}

fn experiment_plan(manifest: &ExperimentManifest, profile: &EvaluationProfile) -> SupervisorPlan {
    let mut role_models = BTreeMap::new();
    for (role, selection) in &profile.role_models {
        role_models.insert(
            *role,
            RoleModelSelection {
                model: selection.model.clone(),
                reasoning_effort: selection.reasoning_effort.clone(),
                unavailable_model_fallback: UnavailableModelFallback::LocalDeterministicFake,
            },
        );
    }
    SupervisorPlan {
        version: 1,
        task: format!("{}\n\n{}", manifest.goal, manifest.spec),
        task_file: None,
        max_depth: 2,
        max_child_assignments: 1,
        max_child_retries: 0,
        max_gate_corrections: 0,
        child_timeout_seconds: 10,
        semantic_coordination: SemanticCoordinationMode::Off,
        role_models,
        model_pricing: BTreeMap::new(),
        review_lenses: crate::supervise::default_supervisor_review_lenses(),
        review_aggregation_policy: ReviewAggregationPolicy::AllMustAccept,
        assignments: vec![OrchestratorAssignment {
            id: "child-a".to_string(),
            phase: AssignmentPhase::Execution,
            runtime: None,
            role: AgentRole::ChildOrchestrator,
            role_category: None,
            selection_source: None,
            assigned_paths: vec![PathBuf::from("README.md")],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            task: Some(manifest.goal.clone()),
            worker_assignments: vec![WorkerAssignment {
                id: "worker-a".to_string(),
                role: AgentRole::Worker,
                role_category: None,
                selection_source: None,
                assigned_paths: vec![PathBuf::from("README.md")],
                semantic_symbols: Vec::new(),
                semantic_modules: Vec::new(),
                task: Some(manifest.spec.clone()),
                environment_requirements: Vec::new(),
                report_path: None,
            }],
            environment_requirements: Vec::new(),
            licensed_breakage: None,
            notes: None,
        }],
    }
}

fn commit_isolated(repo: &Repository, message: &str) -> Result<(), EvaluationError> {
    let mut index = repo
        .index()
        .map_err(|error| EvaluationError::FakeSuperviseExperiment {
            message: format!("failed to open isolated index: {error}"),
        })?;
    index
        .add_all(["*"], IndexAddOption::DEFAULT, None)
        .map_err(|error| EvaluationError::FakeSuperviseExperiment {
            message: format!("failed to stage isolated tree: {error}"),
        })?;
    index
        .write()
        .map_err(|error| EvaluationError::FakeSuperviseExperiment {
            message: format!("failed to write isolated index: {error}"),
        })?;
    let tree_id = index
        .write_tree()
        .map_err(|error| EvaluationError::FakeSuperviseExperiment {
            message: format!("failed to write isolated tree: {error}"),
        })?;
    let tree =
        repo.find_tree(tree_id)
            .map_err(|error| EvaluationError::FakeSuperviseExperiment {
                message: format!("failed to load isolated tree: {error}"),
            })?;
    let signature = Signature::now("maco-eval", "maco-eval@example.invalid").map_err(|error| {
        EvaluationError::FakeSuperviseExperiment {
            message: format!("failed to create isolated git signature: {error}"),
        }
    })?;
    let parent = repo.head().ok().and_then(|head| head.peel_to_commit().ok());
    let parents = parent.iter().collect::<Vec<_>>();
    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        message,
        &tree,
        &parents,
    )
    .map_err(|error| EvaluationError::FakeSuperviseExperiment {
        message: format!("failed to commit isolated Fake supervise baseline: {error}"),
    })?;
    Ok(())
}

fn isolated_run_id(
    manifest: &ExperimentManifest,
    profile: &EvaluationProfile,
    repetition: u32,
) -> Result<RunId, EvaluationError> {
    let raw = format!(
        "exp-{}-{}-{repetition}",
        sanitize_token(&manifest.experiment_id),
        sanitize_token(&profile.id)
    );
    RunId::new(&raw).map_err(|error| EvaluationError::FakeSuperviseExperiment {
        message: format!("invalid isolated run id '{raw}': {error:#}"),
    })
}

fn sanitize_token(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    let trimmed = sanitized.trim_matches('-');
    if trimmed.is_empty() {
        "profile".to_string()
    } else {
        trimmed.chars().take(48).collect()
    }
}

fn validate_held_out(held_out: &[HeldOutValidation]) -> Result<(), EvaluationError> {
    let mut ids = BTreeSet::new();
    for (index, validation) in held_out.iter().enumerate() {
        require_text(&format!("held_out_validation[{index}].id"), &validation.id)?;
        if !ids.insert(validation.id.as_str()) {
            return Err(invalid_experiment(
                format!("held_out_validation[{index}].id"),
                format!("duplicate held-out validation id '{}'", validation.id),
            ));
        }
        if validation.command.is_empty() {
            return Err(invalid_experiment(
                format!("held_out_validation[{index}].command"),
                "must contain an executable and may not be empty",
            ));
        }
    }
    Ok(())
}

fn validate_experiment_profiles(profiles: &[EvaluationProfile]) -> Result<(), EvaluationError> {
    let mut ids = BTreeSet::new();
    for (index, profile) in profiles.iter().enumerate() {
        require_text(&format!("profiles[{index}].id"), &profile.id)?;
        if !ids.insert(profile.id.as_str()) {
            return Err(invalid_experiment(
                format!("profiles[{index}].id"),
                format!("duplicate profile id '{}'", profile.id),
            ));
        }
        if !profile.role_models.contains_key(&AgentRole::Worker)
            || !(profile
                .role_models
                .contains_key(&AgentRole::ChildOrchestrator)
                || profile.role_models.contains_key(&AgentRole::Supervisor))
        {
            return Err(invalid_experiment(
                format!("profiles[{index}].role_models"),
                "must bind a worker role and an orchestration role",
            ));
        }
        for (role, selection) in &profile.role_models {
            if selection
                .model
                .as_deref()
                .is_none_or(|model| model.trim().is_empty())
            {
                return Err(invalid_experiment(
                    format!("profiles[{index}].role_models.{role:?}.model"),
                    "must be a non-empty model slug",
                ));
            }
        }
    }
    Ok(())
}

fn require_text(field: &str, value: &str) -> Result<(), EvaluationError> {
    if value.trim().is_empty() {
        return Err(invalid_experiment(field, "must be a non-empty string"));
    }
    Ok(())
}

fn invalid_experiment(field: impl Into<String>, message: impl Into<String>) -> EvaluationError {
    EvaluationError::InvalidManifest {
        field: field.into(),
        message: message.into(),
    }
}
