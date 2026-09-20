//! Machine-readable profile summaries for parent-retained held-out experiment runs.

use super::EvaluationProfile;
use super::{
    compare_observed_dispatch_records, compare_observed_supervisor_execution,
    executed_experiment::ObservedExperimentRun,
    executed_measurements::{
        parent_review_capture_proof_binding_invalid, parent_review_capture_proven,
    },
    experiment::ExperimentManifest,
    DispatchComparabilityClaim, DispatchComparison, ExecutionTelemetryComparability,
    ParetoConclusion, ParetoConclusionStatus, PreciseMean, RequirementFourComparability,
};
use crate::{artifacts::state_auth::sha256_hex, llm::provider::Usage, supervise::AgentRole};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const EXECUTED_SUMMARY_SCHEMA_VERSION: u32 = 1;
pub const QUALIFIED_ACCEPTED_TASK_FRACTION_LABEL: &str =
    "qualified_accepted_task_fraction_mean_not_calibrated_quality";
/// Root-owned follow-up: parent `review_lens_aggregate` must be produced during held-out
/// supervisor execution before this consumer can license Pareto over accepted-task fraction.
pub const MISSING_PARENT_REVIEW_PRODUCER_NOTICE: &str =
    "held-out supervisor execution must retain parent-computed review_lens_aggregate, matching auditor acceptance, and full required coverage on the bound orchestrator report";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutedExperimentSummary {
    pub version: u32,
    pub profile_summaries: Vec<ExecutedProfileSummary>,
    pub dispatch_comparisons: Vec<DispatchComparison>,
    pub pareto_conclusion: ExecutedObservationParetoConclusion,
    pub pareto_frontier: Vec<ExecutedParetoPoint>,
    pub total_reported_cost_usd: Option<f64>,
    pub labelled_quality_proxy: Option<f64>,
    pub quality_proxy_label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutedProfileSummary {
    pub profile_id: String,
    pub profile_sha256: String,
    pub repetitions: u32,
    pub mean_wall_time_ms: PreciseMean,
    pub aggregate_reported_usage: Option<Usage>,
    pub aggregate_reported_cost_usd: Option<f64>,
    pub mean_reported_cost_usd: Option<f64>,
    pub mean_lines_added: Option<PreciseMean>,
    pub mean_lines_deleted: Option<PreciseMean>,
    pub mean_bytes_added: Option<PreciseMean>,
    pub mean_bytes_deleted: Option<PreciseMean>,
    pub outcome_counts: ExecutedOutcomeCounts,
    pub accepted_quality: ExecutedAcceptedQualitySummary,
    pub pareto_optimal: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutedOutcomeCounts {
    pub accepted: ExecutedOutcomeCount,
    pub rejected: ExecutedOutcomeCount,
    pub unknown: ExecutedOutcomeCount,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutedOutcomeCount {
    pub count: u32,
    pub reason_label: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutedAcceptedQualitySummary {
    pub status: ExecutedAcceptedQualityStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qualified_accepted_fraction: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutedAcceptedQualityStatus {
    Known,
    Unknown,
    RefusedMissingReviewCoverage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutedObservationParetoConclusion {
    pub status: ExecutedObservationParetoStatus,
    pub dispatch: ParetoConclusion,
    pub claim: DispatchComparabilityClaim,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutedObservationParetoStatus {
    Available,
    RefusedIncomparableDispatchEvidence,
    RefusedNoDispatchDifference,
    RefusedMissingReviewCoverage,
    RefusedIncompleteReportedCost,
    RefusedIncompleteAcceptedQuality,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutedParetoPoint {
    pub profile_id: String,
    pub mean_reported_cost_usd: Option<f64>,
    pub qualified_accepted_fraction: Option<f64>,
}

/// Bind, validate, and aggregate executed observation runs for profile comparison.
pub fn summarize_executed_observation_runs(
    manifest: &ExperimentManifest,
    manifest_sha256: &str,
    runs: &[ObservedExperimentRun],
) -> Result<ExecutedExperimentSummary> {
    validate_run_bindings(manifest, manifest_sha256, runs)?;
    let dispatch_comparisons = compare_executed_runs(manifest, runs)?;
    let dispatch_pareto = pareto_conclusion(&dispatch_comparisons);
    let profile_summaries = aggregate_profiles(manifest, runs)?;
    let (pareto_conclusion, pareto_frontier) =
        executed_pareto(&profile_summaries, &dispatch_comparisons, dispatch_pareto)?;
    let total_reported_cost_usd = total_reported_cost(&profile_summaries);
    let (labelled_quality_proxy, quality_proxy_label) =
        experiment_quality_proxy(&profile_summaries);
    Ok(ExecutedExperimentSummary {
        version: EXECUTED_SUMMARY_SCHEMA_VERSION,
        profile_summaries,
        dispatch_comparisons,
        pareto_conclusion,
        pareto_frontier,
        total_reported_cost_usd,
        labelled_quality_proxy,
        quality_proxy_label,
    })
}

fn validate_run_bindings(
    manifest: &ExperimentManifest,
    manifest_sha256: &str,
    runs: &[ObservedExperimentRun],
) -> Result<()> {
    let mut seen = BTreeSet::new();
    let mut profile_baselines: BTreeMap<String, (String, String)> = BTreeMap::new();
    for run in runs {
        let binding = &run.held_out.run;
        if binding.manifest_sha256 != manifest_sha256 {
            bail!("run binding manifest_sha256 does not match the experiment manifest digest");
        }
        let profile = manifest
            .profiles
            .iter()
            .find(|profile| profile.id == binding.profile_id)
            .with_context(|| format!("run references unknown profile '{}'", binding.profile_id))?;
        let expected_profile_sha256 = sha256_hex(&serde_json::to_vec(profile)?);
        if binding.profile_sha256 != expected_profile_sha256 {
            bail!(
                "run binding profile_sha256 does not match manifest profile '{}'",
                binding.profile_id
            );
        }
        if binding.repetition >= manifest.repetitions {
            bail!(
                "run repetition {} exceeds manifest repetitions {}",
                binding.repetition,
                manifest.repetitions
            );
        }
        let cell = (binding.profile_id.clone(), binding.repetition);
        if !seen.insert(cell) {
            bail!(
                "duplicate executed observation cell for profile '{}' repetition {}",
                binding.profile_id,
                binding.repetition
            );
        }
        if let Some(measurements) = &run.measurements {
            if measurements.manifest_sha256 != binding.manifest_sha256
                || measurements.profile_sha256 != binding.profile_sha256
                || measurements.profile_id != binding.profile_id
                || measurements.repetition != binding.repetition
                || measurements.baseline_head != binding.baseline_head
                || measurements.baseline_tree != binding.baseline_tree
            {
                bail!("run measurements binding does not match held-out run binding");
            }
            if parent_review_capture_proof_binding_invalid(measurements) {
                bail!("parent review capture proof does not match retained report digest");
            }
        }
        match profile_baselines.get(&binding.profile_id) {
            None => {
                profile_baselines.insert(
                    binding.profile_id.clone(),
                    (binding.baseline_head.clone(), binding.baseline_tree.clone()),
                );
            }
            Some((head, tree))
                if head == &binding.baseline_head && tree == &binding.baseline_tree => {}
            Some(_) => {
                bail!(
                    "pinned baseline differs across repetitions for profile '{}'",
                    binding.profile_id
                );
            }
        }
    }
    for profile in &manifest.profiles {
        for repetition in 0..manifest.repetitions {
            if !seen.contains(&(profile.id.clone(), repetition)) {
                bail!(
                    "missing executed observation cell for profile '{}' repetition {}",
                    profile.id,
                    repetition
                );
            }
        }
    }
    let mut experiment_baseline: Option<(String, String)> = None;
    for (head, tree) in profile_baselines.values() {
        match &experiment_baseline {
            None => experiment_baseline = Some((head.clone(), tree.clone())),
            Some(expected) if expected == &(head.clone(), tree.clone()) => {}
            Some(_) => bail!("pinned baseline differs across experiment profiles"),
        }
    }
    Ok(())
}

fn compare_executed_runs(
    manifest: &ExperimentManifest,
    runs: &[ObservedExperimentRun],
) -> Result<Vec<DispatchComparison>> {
    let mut comparisons = Vec::new();
    for repetition in 0..manifest.repetitions {
        for left_index in 0..manifest.profiles.len() {
            for right_index in (left_index + 1)..manifest.profiles.len() {
                let left_profile = &manifest.profiles[left_index];
                let right_profile = &manifest.profiles[right_index];
                let left = runs
                    .iter()
                    .find(|run| {
                        run.held_out.run.profile_id == left_profile.id
                            && run.held_out.run.repetition == repetition
                    })
                    .context("missing left executed comparison run")?;
                let right = runs
                    .iter()
                    .find(|run| {
                        run.held_out.run.profile_id == right_profile.id
                            && run.held_out.run.repetition == repetition
                    })
                    .context("missing right executed comparison run")?;
                let left_dispatch = left
                    .measurements
                    .as_ref()
                    .and_then(|measurements| measurements.observed_dispatch.as_ref());
                let right_dispatch = right
                    .measurements
                    .as_ref()
                    .and_then(|measurements| measurements.observed_dispatch.as_ref());
                let comparability =
                    compare_observed_dispatch_records(left_dispatch, right_dispatch);
                let execution_telemetry_comparability = compare_observed_supervisor_execution(
                    left_dispatch.and_then(|record| record.supervisor_execution.as_ref()),
                    right_dispatch.and_then(|record| record.supervisor_execution.as_ref()),
                );
                comparisons.push(DispatchComparison {
                    left_profile_id: left_profile.id.clone(),
                    right_profile_id: right_profile.id.clone(),
                    repetition,
                    comparability,
                    execution_telemetry_comparability,
                    unavailable_reason: (comparability == RequirementFourComparability::Incomparable
                        || execution_telemetry_comparability
                            == ExecutionTelemetryComparability::Incomparable)
                        .then(|| {
                            "not_process_observable: one or both runs lack complete supervisor execution telemetry"
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

fn aggregate_profiles(
    manifest: &ExperimentManifest,
    runs: &[ObservedExperimentRun],
) -> Result<Vec<ExecutedProfileSummary>> {
    let mut summaries = Vec::with_capacity(manifest.profiles.len());
    for profile in &manifest.profiles {
        let profile_sha256 = sha256_hex(&serde_json::to_vec(profile)?);
        let profile_runs = runs
            .iter()
            .filter(|run| run.held_out.run.profile_id == profile.id)
            .collect::<Vec<_>>();
        let mut wall_time_ms = 0u64;
        let mut aggregate_usage: Option<Usage> = None;
        let mut aggregate_cost: Option<f64> = None;
        let mut cost_complete = true;
        let mut usage_complete = true;
        let mut footprint_complete = true;
        let mut lines_added: Option<u64> = None;
        let mut lines_deleted: Option<u64> = None;
        let mut bytes_added: Option<u64> = None;
        let mut bytes_deleted: Option<u64> = None;
        let mut accepted = 0u32;
        let mut rejected = 0u32;
        let mut unknown = 0u32;
        let mut unknown_reason = "outcome_or_review_evidence_unavailable".to_string();
        let mut qualified_accepted = 0u32;
        let mut qualified_total = 0u32;
        let mut quality_refusal: Option<String> = None;
        for run in profile_runs {
            wall_time_ms = wall_time_ms
                .checked_add(run.wall_time_ms)
                .ok_or_else(|| anyhow!("profile wall-time aggregate overflowed"))?;
            let measurements = run.measurements.as_ref();
            if cost_complete {
                match measurements.and_then(|measurements| measurements.total_cost_usd) {
                    Some(cost) if cost.is_finite() && cost >= 0.0 => {
                        let total = aggregate_cost.unwrap_or(0.0);
                        let next = total + cost;
                        if next.is_finite() {
                            aggregate_cost = Some(next);
                        } else {
                            cost_complete = false;
                            aggregate_cost = None;
                        }
                    }
                    _ => {
                        cost_complete = false;
                        aggregate_cost = None;
                    }
                }
            }
            if usage_complete {
                match measurements.and_then(|measurements| measurements.total_usage) {
                    Some(usage) => {
                        aggregate_usage = match aggregate_usage {
                            Some(total) => checked_add_reported_usage(total, usage),
                            None => Some(usage),
                        };
                        if aggregate_usage.is_none() {
                            usage_complete = false;
                        }
                    }
                    None => {
                        usage_complete = false;
                        aggregate_usage = None;
                    }
                }
            }
            if footprint_complete {
                if let Some(footprint) =
                    measurements.map(|measurements| &measurements.candidate_footprint)
                {
                    if let (Some(added), Some(deleted), Some(bytes_add), Some(bytes_del)) = (
                        footprint.lines_added,
                        footprint.lines_deleted,
                        footprint.bytes_added,
                        footprint.bytes_deleted,
                    ) {
                        lines_added = Some(
                            lines_added
                                .unwrap_or(0)
                                .checked_add(u64::from(added))
                                .ok_or_else(|| anyhow!("lines_added aggregate overflowed"))?,
                        );
                        lines_deleted = Some(
                            lines_deleted
                                .unwrap_or(0)
                                .checked_add(u64::from(deleted))
                                .ok_or_else(|| anyhow!("lines_deleted aggregate overflowed"))?,
                        );
                        bytes_added = Some(
                            bytes_added
                                .unwrap_or(0)
                                .checked_add(bytes_add)
                                .ok_or_else(|| anyhow!("bytes_added aggregate overflowed"))?,
                        );
                        bytes_deleted = Some(
                            bytes_deleted
                                .unwrap_or(0)
                                .checked_add(bytes_del)
                                .ok_or_else(|| anyhow!("bytes_deleted aggregate overflowed"))?,
                        );
                    } else {
                        footprint_complete = false;
                        lines_added = None;
                        lines_deleted = None;
                        bytes_added = None;
                        bytes_deleted = None;
                    }
                } else {
                    footprint_complete = false;
                    lines_added = None;
                    lines_deleted = None;
                    bytes_added = None;
                    bytes_deleted = None;
                }
            }
            match classify_run_outcome(run) {
                RunOutcomeClass::Accepted { .. } => accepted += 1,
                RunOutcomeClass::Rejected { .. } => rejected += 1,
                RunOutcomeClass::Unknown { reason } => {
                    unknown += 1;
                    unknown_reason = reason;
                }
            }
            match classify_accepted_quality(profile, run) {
                AcceptedQualityCell::Qualified { accepted_outcome } => {
                    qualified_total += 1;
                    if accepted_outcome {
                        qualified_accepted += 1;
                    }
                }
                AcceptedQualityCell::RefusedMissingReviewCoverage { reason } => {
                    quality_refusal = Some(reason);
                }
                AcceptedQualityCell::OutcomeUnknown { reason } => {
                    quality_refusal = Some(reason);
                }
            }
        }
        let mean_reported_cost_usd = if cost_complete {
            aggregate_cost
                .map(|cost| cost / f64::from(manifest.repetitions))
                .filter(|cost| cost.is_finite())
        } else {
            None
        };
        let accepted_quality = if let Some(reason) = quality_refusal {
            ExecutedAcceptedQualitySummary {
                status: ExecutedAcceptedQualityStatus::RefusedMissingReviewCoverage,
                qualified_accepted_fraction: None,
                refusal_reason: Some(reason),
            }
        } else if qualified_total == manifest.repetitions {
            ExecutedAcceptedQualitySummary {
                status: ExecutedAcceptedQualityStatus::Known,
                qualified_accepted_fraction: Some(
                    f64::from(qualified_accepted) / f64::from(manifest.repetitions),
                ),
                refusal_reason: None,
            }
        } else {
            ExecutedAcceptedQualitySummary {
                status: ExecutedAcceptedQualityStatus::Unknown,
                qualified_accepted_fraction: None,
                refusal_reason: Some(
                    "not every repetition established qualified accepted-quality evidence"
                        .to_string(),
                ),
            }
        };
        summaries.push(ExecutedProfileSummary {
            profile_id: profile.id.clone(),
            profile_sha256,
            repetitions: manifest.repetitions,
            mean_wall_time_ms: precise_mean(wall_time_ms, manifest.repetitions)?,
            aggregate_reported_usage: aggregate_usage,
            aggregate_reported_cost_usd: aggregate_cost,
            mean_reported_cost_usd,
            mean_lines_added: lines_added
                .map(|total| precise_mean(total, manifest.repetitions))
                .transpose()?,
            mean_lines_deleted: lines_deleted
                .map(|total| precise_mean(total, manifest.repetitions))
                .transpose()?,
            mean_bytes_added: bytes_added
                .map(|total| precise_mean(total, manifest.repetitions))
                .transpose()?,
            mean_bytes_deleted: bytes_deleted
                .map(|total| precise_mean(total, manifest.repetitions))
                .transpose()?,
            outcome_counts: ExecutedOutcomeCounts {
                accepted: ExecutedOutcomeCount {
                    count: accepted,
                    reason_label: "parent_final_accepted_outcome".to_string(),
                },
                rejected: ExecutedOutcomeCount {
                    count: rejected,
                    reason_label: "parent_final_rejected_outcome".to_string(),
                },
                unknown: ExecutedOutcomeCount {
                    count: unknown,
                    reason_label: unknown_reason,
                },
            },
            accepted_quality,
            pareto_optimal: false,
        });
    }
    mark_pareto_optimal(&mut summaries);
    Ok(summaries)
}

#[allow(dead_code)]
enum RunOutcomeClass {
    Accepted { reason: String },
    Rejected { reason: String },
    Unknown { reason: String },
}

enum AcceptedQualityCell {
    Qualified { accepted_outcome: bool },
    RefusedMissingReviewCoverage { reason: String },
    OutcomeUnknown { reason: String },
}

fn classify_run_outcome(run: &ObservedExperimentRun) -> RunOutcomeClass {
    let measurements = run.measurements.as_ref();
    let Some(measurements) = measurements else {
        return RunOutcomeClass::Unknown {
            reason: "supervisor-final measurements were not retained".to_string(),
        };
    };
    if measurements.retained_supervisor_report_sha256.is_none() {
        return RunOutcomeClass::Unknown {
            reason: measurements
                .retained_supervisor_report_unavailable_reason
                .clone()
                .unwrap_or_else(|| "supervisor-final report digest is unavailable".to_string()),
        };
    }
    match measurements.supervisor_final_accepted {
        Some(true) => RunOutcomeClass::Accepted {
            reason: "parent_final_accepted_outcome".to_string(),
        },
        Some(false) if measurements.supervisor_final_rejected == Some(true) => {
            RunOutcomeClass::Rejected {
                reason: "parent_final_rejected_outcome".to_string(),
            }
        }
        Some(false) => RunOutcomeClass::Rejected {
            reason: "parent_final_not_accepted".to_string(),
        },
        None => RunOutcomeClass::Unknown {
            reason: "parent final accepted outcome is unavailable".to_string(),
        },
    }
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

fn checked_add_reported_usage(left: Usage, right: Usage) -> Option<Usage> {
    let input_tokens = left.input_tokens.checked_add(right.input_tokens)?;
    let output_tokens = left.output_tokens.checked_add(right.output_tokens)?;
    let total_tokens = input_tokens.checked_add(output_tokens)?;
    Some(Usage {
        input_tokens,
        output_tokens,
        total_tokens,
    })
}

fn observed_role_models_match_profile(
    profile: &EvaluationProfile,
    measurements: &super::executed_measurements::ObservedRunMeasurements,
) -> Result<(), String> {
    for (role, selection) in &profile.role_models {
        let expected_model: &str = match selection.model.as_deref() {
            None => continue,
            Some(model) if model.trim().is_empty() => continue,
            Some(model) => model,
        };
        if let Some(dispatch) = measurements.observed_dispatch.as_ref() {
            if let Some(observed) = dispatch
                .roles
                .iter()
                .find(|observed| observed.role == *role)
            {
                if observed.models != [expected_model.to_string()] {
                    return Err(format!(
                        "observed dispatch for role '{}' does not match the profile-declared model",
                        role_name(*role)
                    ));
                }
                continue;
            }
        }
        if let Some(report) = measurements.role_usage.get(role) {
            if report.models != [expected_model.to_string()] {
                return Err(format!(
                    "observed role usage for '{}' does not match the profile-declared model",
                    role_name(*role)
                ));
            }
            continue;
        }
        return Err(format!(
            "supervisor-final measurements lack process-observable role usage for configured role '{}'",
            role_name(*role)
        ));
    }
    Ok(())
}

fn classify_accepted_quality(
    profile: &EvaluationProfile,
    run: &ObservedExperimentRun,
) -> AcceptedQualityCell {
    if !run.held_out.passed() {
        return AcceptedQualityCell::RefusedMissingReviewCoverage {
            reason: "held-out candidate validation did not pass".to_string(),
        };
    }
    let measurements = match run.measurements.as_ref() {
        Some(measurements) => measurements,
        None => {
            return AcceptedQualityCell::OutcomeUnknown {
                reason: "supervisor-final measurements were not retained".to_string(),
            };
        }
    };
    if measurements.retained_supervisor_report_sha256.is_none() {
        return AcceptedQualityCell::OutcomeUnknown {
            reason: "retained supervisor-final report digest is unavailable".to_string(),
        };
    }
    if let Err(reason) = observed_role_models_match_profile(profile, measurements) {
        return AcceptedQualityCell::OutcomeUnknown { reason };
    }
    if !parent_review_capture_proven(measurements, &run.held_out) {
        let reason = measurements
            .parent_review_capture_unavailable_reason
            .clone()
            .unwrap_or_else(|| {
                "parent review capture was not proven in-process at supervisor-final retention"
                    .to_string()
            });
        return AcceptedQualityCell::RefusedMissingReviewCoverage { reason };
    }
    let accepted_outcome = measurements.supervisor_final_accepted == Some(true);
    AcceptedQualityCell::Qualified { accepted_outcome }
}

fn precise_mean(total: u64, count: u32) -> Result<PreciseMean> {
    if count == 0 {
        bail!("precise mean count must be greater than zero");
    }
    Ok(PreciseMean { total, count })
}

fn mark_pareto_optimal(summaries: &mut [ExecutedProfileSummary]) {
    for index in 0..summaries.len() {
        let dominated = summaries.iter().enumerate().any(|(other_index, other)| {
            other_index != index && profile_dominates(other, &summaries[index])
        });
        summaries[index].pareto_optimal = !dominated;
    }
}

fn profile_dominates(candidate: &ExecutedProfileSummary, other: &ExecutedProfileSummary) -> bool {
    let (Some(candidate_cost), Some(other_cost)) = (
        candidate.mean_reported_cost_usd,
        other.mean_reported_cost_usd,
    ) else {
        return false;
    };
    let (Some(candidate_quality), Some(other_quality)) = (
        candidate.accepted_quality.qualified_accepted_fraction,
        other.accepted_quality.qualified_accepted_fraction,
    ) else {
        return false;
    };
    let no_more_expensive = candidate_cost <= other_cost;
    let no_lower_quality = candidate_quality >= other_quality;
    let strictly_better = candidate_cost < other_cost || candidate_quality > other_quality;
    no_more_expensive && no_lower_quality && strictly_better
}

fn executed_pareto(
    summaries: &[ExecutedProfileSummary],
    _comparisons: &[DispatchComparison],
    dispatch: ParetoConclusion,
) -> Result<(
    ExecutedObservationParetoConclusion,
    Vec<ExecutedParetoPoint>,
)> {
    let mut unavailable_reason = None;
    let status = if dispatch.status == ParetoConclusionStatus::RefusedIncomparableDispatchEvidence {
        ExecutedObservationParetoStatus::RefusedIncomparableDispatchEvidence
    } else if dispatch.status == ParetoConclusionStatus::RefusedNoDispatchDifference {
        ExecutedObservationParetoStatus::RefusedNoDispatchDifference
    } else if summaries.iter().any(|summary| {
        summary.aggregate_reported_cost_usd.is_none() || summary.mean_reported_cost_usd.is_none()
    }) {
        ExecutedObservationParetoStatus::RefusedIncompleteReportedCost
    } else if summaries.iter().any(|summary| {
        summary.accepted_quality.status != ExecutedAcceptedQualityStatus::Known
            || summary
                .accepted_quality
                .qualified_accepted_fraction
                .is_none()
    }) {
        ExecutedObservationParetoStatus::RefusedMissingReviewCoverage
    } else if summaries.len() < 2 {
        ExecutedObservationParetoStatus::RefusedNoDispatchDifference
    } else {
        let costs_differ = summaries
            .windows(2)
            .any(|pair| pair[0].mean_reported_cost_usd != pair[1].mean_reported_cost_usd);
        let quality_differs = summaries.windows(2).any(|pair| {
            pair[0].accepted_quality.qualified_accepted_fraction
                != pair[1].accepted_quality.qualified_accepted_fraction
        });
        if !costs_differ && !quality_differs {
            ExecutedObservationParetoStatus::RefusedNoDispatchDifference
        } else {
            ExecutedObservationParetoStatus::Available
        }
    };
    if status != ExecutedObservationParetoStatus::Available {
        unavailable_reason = Some(match status {
            ExecutedObservationParetoStatus::RefusedIncompleteReportedCost => {
                "reported cost-equivalent is unavailable for one or more profile repetitions"
            }
            ExecutedObservationParetoStatus::RefusedMissingReviewCoverage => {
                "qualified accepted-task fraction is unavailable because review coverage was not parent-proven"
            }
            ExecutedObservationParetoStatus::RefusedIncomparableDispatchEvidence => {
                "dispatch comparability is incomparable or refused"
            }
            ExecutedObservationParetoStatus::RefusedNoDispatchDifference => {
                "profiles do not differ on reported cost or qualified accepted-task fraction"
            }
            ExecutedObservationParetoStatus::RefusedIncompleteAcceptedQuality => {
                "qualified accepted-task fraction is incomplete for one or more profiles"
            }
            ExecutedObservationParetoStatus::Available => "",
        }
        .to_string());
    }
    let frontier = if status == ExecutedObservationParetoStatus::Available {
        summaries
            .iter()
            .filter(|summary| summary.pareto_optimal)
            .map(|summary| ExecutedParetoPoint {
                profile_id: summary.profile_id.clone(),
                mean_reported_cost_usd: summary.mean_reported_cost_usd,
                qualified_accepted_fraction: summary.accepted_quality.qualified_accepted_fraction,
            })
            .collect()
    } else {
        Vec::new()
    };
    Ok((
        ExecutedObservationParetoConclusion {
            status,
            dispatch,
            claim: DispatchComparabilityClaim::dispatch_only(),
            unavailable_reason,
        },
        frontier,
    ))
}

fn total_reported_cost(summaries: &[ExecutedProfileSummary]) -> Option<f64> {
    if summaries.is_empty() {
        return None;
    }
    let mut total = 0.0;
    for summary in summaries {
        match summary.aggregate_reported_cost_usd {
            Some(cost) if cost.is_finite() => total += cost,
            _ => return None,
        }
    }
    Some(total)
}

fn experiment_quality_proxy(summaries: &[ExecutedProfileSummary]) -> (Option<f64>, Option<String>) {
    if summaries.is_empty() {
        return (None, None);
    }
    if summaries.iter().any(|summary| {
        summary.accepted_quality.status != ExecutedAcceptedQualityStatus::Known
            || summary
                .accepted_quality
                .qualified_accepted_fraction
                .is_none()
    }) {
        return (None, None);
    }
    let total = summaries
        .iter()
        .filter_map(|summary| {
            summary
                .accepted_quality
                .qualified_accepted_fraction
                .map(|fraction| fraction * f64::from(summary.repetitions))
        })
        .sum::<f64>();
    let repetitions: u32 = summaries.iter().map(|summary| summary.repetitions).sum();
    if repetitions == 0 {
        return (None, None);
    }
    (
        Some(total / f64::from(repetitions)),
        Some(QUALIFIED_ACCEPTED_TASK_FRACTION_LABEL.to_string()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::RunArtifactFamily;
    use crate::evaluation::executed_measurements::{
        observed_run_measurements_from_captured_supervisor_final_report,
        observed_run_measurements_from_retained_supervisor_final_report,
        ParentReviewCaptureObservation,
    };
    use crate::evaluation::EvaluationProfile;
    use crate::merge::held_out::CommandObservationStatus;
    use crate::merge::CandidateValidationBinding;
    use crate::orchestrator::RunId;
    use crate::review::{
        aggregate_review_lenses_against_requests, build_review_lens_request,
        ReviewAggregationPolicy, ReviewCoverageRequirement, ReviewInformationScope,
        ReviewLensConfig, ReviewLensCoverage, ReviewLensEvidenceKind, ReviewLensRequestSources,
        ReviewLensVerdict, ReviewLensVerdictStatus,
    };
    use crate::supervise::held_out::{
        HeldOutCandidateEvidence, HeldOutCommandEvidence, HeldOutRunBinding,
    };
    use crate::supervise::{
        AgentRole, AutonomyKpiReport, OrchestratorReviewReport, ReviewStatus, RoleModelSelection,
        SupervisorFinalReport, SupervisorPlan, SupervisorRunLifecycle, SupervisorRuntime,
        UnavailableModelFallback,
    };
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn held_out_binding(
        manifest_sha256: &str,
        profile_id: &str,
        profile_sha256: &str,
        repetition: u32,
    ) -> HeldOutRunBinding {
        HeldOutRunBinding {
            manifest_sha256: manifest_sha256.to_string(),
            profile_sha256: profile_sha256.to_string(),
            profile_id: profile_id.to_string(),
            repetition,
            experiment_run_id: "experiment".to_string(),
            supervisor_run_id: format!("supervisor-{profile_id}-{repetition}"),
            assignment_id: "child-a".to_string(),
            baseline_head: "b".repeat(40),
            baseline_tree: "c".repeat(40),
        }
    }

    fn passed_held_out(binding: HeldOutRunBinding) -> HeldOutCandidateEvidence {
        HeldOutCandidateEvidence {
            version: 1,
            run: binding,
            candidate: Some(CandidateValidationBinding {
                version: 1,
                agent_id: "child-a".to_string(),
                primary_head: Some("b".repeat(40)),
                agent_head: Some("d".repeat(40)),
                merge_base: Some("b".repeat(40)),
                diff_oid: "e".repeat(40),
            }),
            candidate_revalidated: true,
            commands: vec![HeldOutCommandEvidence {
                id: "unit".to_string(),
                argv: vec!["true".to_string()],
                command_sha256: "1".repeat(64),
                observation: crate::merge::held_out::CommandObservation {
                    status: CommandObservationStatus::Passed,
                    exit_code: Some(0),
                    timed_out: false,
                    duration_ms: 1,
                    message: None,
                },
            }],
        }
    }

    fn parent_review_plan() -> SupervisorPlan {
        SupervisorPlan {
            version: 1,
            task: "fixture".to_string(),
            task_file: None,
            max_depth: 1,
            max_child_assignments: 1,
            max_child_retries: 0,
            max_gate_corrections: 0,
            child_timeout_seconds: 30,
            semantic_coordination: crate::orchestrator::SemanticCoordinationMode::Off,
            role_models: BTreeMap::from([(
                AgentRole::Worker,
                RoleModelSelection {
                    model: Some("worker".to_string()),
                    reasoning_effort: None,
                    unavailable_model_fallback: UnavailableModelFallback::FailClosed,
                },
            )]),
            model_pricing: BTreeMap::new(),
            review_lenses: vec![ReviewLensConfig {
                id: "quality-lens".to_string(),
                backend: crate::review::ReviewLensBackendConfig::Model {
                    backend_id: "openai".to_string(),
                    model: "fixture-model".to_string(),
                    reasoning_effort: None,
                },
                information_scope: ReviewInformationScope::FullChildTranscript,
            }],
            review_lens_correlation: Default::default(),
            review_aggregation_policy: ReviewAggregationPolicy::AllMustAccept,
            assignments: vec![serde_json::from_value(serde_json::json!({
                "id": "child-a",
                "phase": "execution",
                "assigned_paths": ["README.md"]
            }))
            .expect("assignment")],
        }
    }

    fn build_supervisor_report(
        cost_usd: f64,
        worker_model: &str,
        accepted: bool,
    ) -> SupervisorFinalReport {
        let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../tests/fixtures/model_mix_evaluation/supervisor-final-execution-v2.json"
        ))
        .expect("fixture");
        let mut profile = serde_json::from_value::<crate::supervise::RoleEconomicsProfile>(
            fixture["role_economics_profile"].clone(),
        )
        .expect("economics profile");
        profile
            .execution
            .as_mut()
            .expect("execution")
            .usage
            .total_cost_usd = Some(cost_usd);
        profile
            .execution
            .as_mut()
            .expect("execution")
            .role_bindings
            .get_mut(&AgentRole::Worker)
            .expect("worker")
            .resolved_model = Some(worker_model.to_string());
        let run_id = RunId::new("fixture-run-v2").expect("run id");
        let mut child = OrchestratorReviewReport {
            id: "child-a".to_string(),
            role: AgentRole::ChildOrchestrator,
            status: ReviewStatus::Succeeded,
            accepted,
            rejected: !accepted,
            remaining_risk: String::new(),
            next_safe_action: String::new(),
            assigned_paths: vec![PathBuf::from("README.md")],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            claim_token: None,
            semantic_intent_token: None,
            commands_run: Vec::new(),
            environment_failures: Vec::new(),
            files_changed: Vec::new(),
            validation_results: Vec::new(),
            findings: Vec::new(),
            field_guide_entries: Vec::new(),
            worker_reports: Vec::new(),
            audit_reports: vec![crate::supervise::AuditorReport {
                id: "child-a-review-auditor".to_string(),
                role: AgentRole::Auditor,
                reviewed_worker_ids: Vec::new(),
                reviewed_paths: Vec::new(),
                commands_run: Vec::new(),
                environment_failures: Vec::new(),
                validation_results: Vec::new(),
                findings: Vec::new(),
                rejection_kind: None,
                no_further_delegation: None,
                read_only: false,
                accepted: true,
                rejected: false,
                status: ReviewStatus::Succeeded,
                remaining_risk: String::new(),
                next_safe_action: String::new(),
            }],
            review_lens_aggregate: None,
            decomposition_completions: Vec::new(),
            licensed_breakage_review: None,
            generated_follow_up_tasks: Vec::new(),
            gate_denials: Vec::new(),
            gate_correction_outcomes: Vec::new(),
        };
        let plan = parent_review_plan();
        let output_report = serde_json::to_string(&child).expect("child json");
        let sources = ReviewLensRequestSources {
            child_transcript: "fixture transcript",
            diff: "fixture diff",
            output_report: &output_report,
        };
        let coverage = ReviewCoverageRequirement {
            worker_ids: Vec::new(),
            paths: vec![PathBuf::from("README.md")],
        };
        let requests = plan
            .review_lenses
            .iter()
            .map(|lens| build_review_lens_request(lens, sources).expect("request"))
            .collect::<Vec<_>>();
        let verdicts = plan
            .review_lenses
            .iter()
            .zip(&requests)
            .map(|(lens, request)| {
                ReviewLensVerdict::for_lens(
                    lens,
                    request.request_binding.clone(),
                    ReviewLensVerdictStatus::Accept,
                    ReviewLensCoverage {
                        worker_ids: coverage.worker_ids.clone(),
                        paths: coverage.paths.clone(),
                    },
                    vec![(
                        ReviewLensEvidenceKind::ModelReview,
                        "fixture evidence".to_string(),
                    )],
                )
                .expect("verdict")
            })
            .collect::<Vec<_>>();
        child.review_lens_aggregate = Some(
            aggregate_review_lenses_against_requests(
                &plan.review_lenses,
                &requests,
                plan.review_aggregation_policy,
                coverage,
                verdicts,
            )
            .expect("aggregate"),
        );
        let total_usage = profile
            .execution
            .as_ref()
            .and_then(|execution| execution.usage.total_usage);
        SupervisorFinalReport {
            version: 1,
            run_id,
            role: AgentRole::Supervisor,
            repo: PathBuf::from("."),
            plan_file: PathBuf::from("plan.json"),
            run_dir: RunArtifactFamily::Supervise
                .run_root()
                .join("fixture-run-v2"),
            runtime: SupervisorRuntime::Fake,
            publishable: false,
            success: accepted,
            accepted,
            rejected: !accepted,
            status: ReviewStatus::Succeeded,
            run_lifecycle: SupervisorRunLifecycle::Finalized,
            evidence_only_reaudit: None,
            assigned_paths: Vec::new(),
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            claim_tokens: Vec::new(),
            semantic_intent_tokens: Vec::new(),
            role_economics_profile: Some(profile),
            run_budget: None,
            role_usage: BTreeMap::new(),
            review_lens_usage: Vec::new(),
            review_lens_total_usage: None,
            review_lens_total_cost_usd: None,
            total_usage,
            total_cost_usd: Some(cost_usd),
            usage_complete: true,
            commands_run: Vec::new(),
            environment_failures: Vec::new(),
            sandbox_denials: Vec::new(),
            gate_denials: Vec::new(),
            pre_action_review_metrics: Vec::new(),
            gate_correction_outcomes: Vec::new(),
            autonomy_kpis: AutonomyKpiReport::default(),
            files_changed: Vec::new(),
            validation_results: Vec::new(),
            findings: Vec::new(),
            bloated_file_flags: Vec::new(),
            decomposition_candidates: Vec::new(),
            generated_follow_up_tasks: Vec::new(),
            assignment_traceability: Vec::new(),
            coverage_gaps: Vec::new(),
            breaker_trip: None,
            orchestrator_reports: vec![child],
            released_claims: Vec::new(),
            release_errors: Vec::new(),
            released_semantic_intents: Vec::new(),
            semantic_release_errors: Vec::new(),
            remaining_risk: "fixture".to_string(),
            next_safe_action: "none".to_string(),
        }
    }

    fn observation_manifest() -> ExperimentManifest {
        ExperimentManifest {
            version: crate::evaluation::experiment::EXPERIMENT_MANIFEST_SCHEMA_VERSION,
            experiment_id: "executed-summary".to_string(),
            goal: "fixture".to_string(),
            spec: "fixture".to_string(),
            limits: crate::evaluation::EvaluationLimits {
                wall_time_seconds: 60,
                max_dispatches: 4,
            },
            held_out_validation: vec![crate::evaluation::HeldOutValidation {
                id: "unit".to_string(),
                command: vec!["true".to_string()],
            }],
            repetitions: 1,
            profiles: vec![
                EvaluationProfile {
                    id: "profile-low-cost".to_string(),
                    role_models: BTreeMap::new(),
                },
                EvaluationProfile {
                    id: "profile-high-cost".to_string(),
                    role_models: BTreeMap::new(),
                },
            ],
            objective_profile: None,
        }
    }

    fn observed_run(
        profile: &EvaluationProfile,
        manifest_sha256: &str,
        cost_usd: f64,
        worker_model: &str,
    ) -> ObservedExperimentRun {
        let profile_sha256 = sha256_hex(&serde_json::to_vec(profile).expect("profile"));
        let binding = held_out_binding(manifest_sha256, &profile.id, &profile_sha256, 0);
        let held_out = passed_held_out(binding);
        let workspace = tempfile::TempDir::new().expect("workspace");
        let repo = workspace.path().join("repo");
        git2::Repository::init(&repo).expect("init");
        let live_report = build_supervisor_report(cost_usd, worker_model, true);
        let bytes = serde_json::to_vec(&live_report).expect("report bytes");
        let measurements = observed_run_measurements_from_captured_supervisor_final_report(
            &held_out,
            &live_report,
            &bytes,
            &repo,
            &BTreeSet::new(),
        )
        .expect("measurements");
        assert_eq!(measurements.manifest_sha256, manifest_sha256);
        assert_eq!(
            measurements.parent_review_capture,
            ParentReviewCaptureObservation::ProvenAtCapture
        );
        ObservedExperimentRun {
            held_out,
            admitted_dispatches: 1,
            wall_time_ms: 100,
            supervisor_succeeded: true,
            required_validation_passed: true,
            supervisor_evidence: Some(PathBuf::from("report.json")),
            failure: None,
            real_provider_execution: crate::evaluation::executed_experiment::RealProviderExecutionObservation::NotRequested,
            measurements: Some(measurements),
        }
    }

    /// Controlled in-memory parent report fixture: exercises observation Pareto
    /// arithmetic only, not `run_experiment_with_held_out` provider/capture proof.
    #[test]
    fn controlled_parent_report_fixture_observation_pareto_cost_arithmetic_only() {
        let manifest = observation_manifest();
        let manifest_sha256 = sha256_hex(&serde_json::to_vec(&manifest).expect("manifest"));
        let runs = vec![
            observed_run(&manifest.profiles[0], &manifest_sha256, 0.01, "worker-low"),
            observed_run(&manifest.profiles[1], &manifest_sha256, 0.03, "worker-high"),
        ];
        let summary = summarize_executed_observation_runs(&manifest, &manifest_sha256, &runs)
            .expect("summary");
        assert_eq!(summary.profile_summaries.len(), 2);
        assert_eq!(
            summary.profile_summaries[0].mean_reported_cost_usd,
            Some(0.01)
        );
        assert_eq!(
            summary.profile_summaries[1].mean_reported_cost_usd,
            Some(0.03)
        );
        assert_eq!(
            summary.profile_summaries[0].accepted_quality.status,
            ExecutedAcceptedQualityStatus::Known
        );
        assert_eq!(
            summary.pareto_conclusion.status,
            ExecutedObservationParetoStatus::Available
        );
        assert!(!summary.pareto_frontier.is_empty());
    }

    #[test]
    fn unavailable_measurements_without_digest_do_not_abort_summarize() {
        let mut manifest = observation_manifest();
        manifest.profiles.truncate(1);
        manifest.repetitions = 1;
        let manifest_sha256 = sha256_hex(&serde_json::to_vec(&manifest).expect("manifest"));
        let profile = &manifest.profiles[0];
        let profile_sha256 = sha256_hex(&serde_json::to_vec(profile).expect("profile"));
        let binding = held_out_binding(&manifest_sha256, &profile.id, &profile_sha256, 0);
        let held_out = passed_held_out(binding);
        let measurements =
            crate::evaluation::executed_measurements::observed_run_measurements_unavailable(
                &held_out,
                "supervisor-final.json was not retained",
            );
        let run = ObservedExperimentRun {
            held_out,
            admitted_dispatches: 1,
            wall_time_ms: 1,
            supervisor_succeeded: false,
            required_validation_passed: false,
            supervisor_evidence: None,
            failure: None,
            real_provider_execution: crate::evaluation::executed_experiment::RealProviderExecutionObservation::NotRequested,
            measurements: Some(measurements),
        };
        summarize_executed_observation_runs(&manifest, &manifest_sha256, &[run])
            .expect("summarize with unavailable measurements");
    }

    #[test]
    fn missing_review_coverage_refuses_frontier_without_dropping_cells() {
        let manifest = observation_manifest();
        let manifest_sha256 = sha256_hex(&serde_json::to_vec(&manifest).expect("manifest"));
        let profile = &manifest.profiles[0];
        let profile_sha256 = sha256_hex(&serde_json::to_vec(profile).expect("profile"));
        let binding = held_out_binding(&manifest_sha256, &profile.id, &profile_sha256, 0);
        let held_out = passed_held_out(binding);
        let workspace = tempfile::TempDir::new().expect("workspace");
        let repo = workspace.path().join("repo");
        git2::Repository::init(&repo).expect("init");
        let bytes =
            crate::evaluation::executed_measurements::supervisor_final_report_execution_fixture_bytes();
        let measurements = observed_run_measurements_from_retained_supervisor_final_report(
            &held_out,
            &bytes,
            &repo,
            &BTreeSet::new(),
        )
        .expect("measurements");
        let run = ObservedExperimentRun {
            held_out,
            admitted_dispatches: 1,
            wall_time_ms: 1,
            supervisor_succeeded: true,
            required_validation_passed: true,
            supervisor_evidence: Some(PathBuf::from("report.json")),
            failure: None,
            real_provider_execution: crate::evaluation::executed_experiment::RealProviderExecutionObservation::NotRequested,
            measurements: Some(measurements),
        };
        let mut runs = vec![
            run,
            observed_run(&manifest.profiles[1], &manifest_sha256, 0.02, "worker-high"),
        ];
        runs[0].measurements.as_mut().unwrap().total_cost_usd = Some(0.01);
        let summary = summarize_executed_observation_runs(&manifest, &manifest_sha256, &runs)
            .expect("summary");
        assert_eq!(summary.profile_summaries.len(), 2);
        assert_ne!(
            summary.pareto_conclusion.status,
            ExecutedObservationParetoStatus::Available
        );
        assert!(summary.pareto_frontier.is_empty());
        assert!(summary.labelled_quality_proxy.is_none());
    }

    #[test]
    fn forged_parent_review_capture_observation_without_proof_refuses_quality() {
        let manifest = observation_manifest();
        let manifest_sha256 = sha256_hex(&serde_json::to_vec(&manifest).expect("manifest"));
        let mut run = observed_run(&manifest.profiles[0], &manifest_sha256, 0.01, "worker-low");
        let measurements = run.measurements.as_mut().expect("measurements");
        measurements.parent_review_capture = ParentReviewCaptureObservation::ProvenAtCapture;
        measurements.parent_review_capture_proof = None;
        let summary = summarize_executed_observation_runs(
            &manifest,
            &manifest_sha256,
            &[
                run,
                observed_run(&manifest.profiles[1], &manifest_sha256, 0.02, "worker-high"),
            ],
        )
        .expect("summary");
        assert_ne!(
            summary.profile_summaries[0].accepted_quality.status,
            ExecutedAcceptedQualityStatus::Known
        );
        assert!(summary.pareto_frontier.is_empty());
    }

    #[test]
    fn mismatched_report_digest_refuses_parent_review_proof() {
        let manifest = observation_manifest();
        let manifest_sha256 = sha256_hex(&serde_json::to_vec(&manifest).expect("manifest"));
        let mut run = observed_run(&manifest.profiles[0], &manifest_sha256, 0.01, "worker-low");
        let measurements = run.measurements.as_mut().expect("measurements");
        measurements.retained_supervisor_report_sha256 = Some("0".repeat(64));
        let error = summarize_executed_observation_runs(
            &manifest,
            &manifest_sha256,
            &[
                run,
                observed_run(&manifest.profiles[1], &manifest_sha256, 0.02, "worker-high"),
            ],
        )
        .expect_err("digest mismatch");
        assert!(error
            .to_string()
            .contains("parent review capture proof does not match retained report digest"));
    }

    #[test]
    fn unknown_then_known_cost_stays_unknown_for_profile_aggregate() {
        let mut manifest = observation_manifest();
        manifest.profiles.truncate(1);
        manifest.repetitions = 2;
        let manifest_sha256 = sha256_hex(&serde_json::to_vec(&manifest).expect("manifest"));
        let profile = manifest.profiles[0].clone();
        let unknown_run = {
            let mut run = observed_run(&profile, &manifest_sha256, 0.01, "worker-low");
            run.measurements.as_mut().unwrap().total_cost_usd = None;
            run
        };
        let known_run = {
            let mut run = observed_run(&profile, &manifest_sha256, 0.02, "worker-low");
            run.held_out.run.repetition = 1;
            if let Some(measurements) = run.measurements.as_mut() {
                measurements.repetition = 1;
            }
            run
        };
        let summary = summarize_executed_observation_runs(
            &manifest,
            &manifest_sha256,
            &[unknown_run, known_run],
        )
        .expect("summary");
        assert!(summary
            .profile_summaries
            .iter()
            .find(|summary| summary.profile_id == profile.id)
            .expect("profile")
            .aggregate_reported_cost_usd
            .is_none());
    }

    #[test]
    fn mismatched_experiment_baselines_are_rejected() {
        let manifest = observation_manifest();
        let manifest_sha256 = sha256_hex(&serde_json::to_vec(&manifest).expect("manifest"));
        let run_a = observed_run(&manifest.profiles[0], &manifest_sha256, 0.01, "worker-low");
        let mut run_b = observed_run(&manifest.profiles[1], &manifest_sha256, 0.02, "worker-high");
        run_b.held_out.run.baseline_head = "f".repeat(40);
        if let Some(measurements) = run_b.measurements.as_mut() {
            measurements.baseline_head = run_b.held_out.run.baseline_head.clone();
        }
        let error =
            summarize_executed_observation_runs(&manifest, &manifest_sha256, &[run_a, run_b])
                .expect_err("baseline mismatch");
        assert!(error
            .to_string()
            .contains("baseline differs across experiment profiles"));
    }
}
