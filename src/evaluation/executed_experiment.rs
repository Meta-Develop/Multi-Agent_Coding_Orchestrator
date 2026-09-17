//! Observed local validation, deliberately separate from legacy synthetic scores.
use super::{
    executed_measurements::{
        observed_run_measurements_from_captured_supervisor_final_report,
        observed_run_measurements_unavailable, ObservedRunMeasurements,
    },
    executed_summary::{summarize_executed_observation_runs, ExecutedExperimentSummary},
    experiment::{
        self, HeldOutExplicitSourceBaseline, HeldOutRealProviderExperimentRequest,
        IsolatedSuperviseState,
    },
    EvaluationExecution, ExperimentManifest, ExperimentRunRequest,
};
use crate::{
    artifacts::{
        self, state_auth::sha256_hex, ArtifactFileDisposition, ArtifactRunReader,
        ArtifactRunWriter, RunArtifactFamily,
    },
    orchestrator::RunId,
    supervise::{
        self,
        held_out::{HeldOutCandidateEvidence, HeldOutRunBinding, ParentValidationAuthority},
        SupervisorRuntime,
    },
};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// v1/v2 experiment scores remain unchanged. This schema supplies observations,
/// not an evaluation certificate, an economic score, or a production selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutedExperimentResults {
    pub version: u32,
    pub schema: String,
    pub experiment_id: String,
    pub manifest_sha256: String,
    pub artifact_run_id: String,
    pub artifact_report: PathBuf,
    pub synthetic_baseline: bool,
    pub real_provider_executed: bool,
    /// Distinguishes Fake requests from real-provider opt-in. Parent-captured
    /// launch and native-runtime evidence only; never from child JSON or spend.
    #[serde(default)]
    pub real_provider_execution: RealProviderExecutionObservation,
    pub production_eligible: bool,
    pub eligible_for_production_economics: bool,
    pub eligible_to_justify_named_default: bool,
    pub quality: Option<f64>,
    pub total_cost_usd: Option<f64>,
    pub confidence: Option<f64>,
    pub runs: Vec<ObservedExperimentRun>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profile_summaries: Vec<super::executed_summary::ExecutedProfileSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dispatch_comparisons: Vec<super::DispatchComparison>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation_pareto_conclusion:
        Option<super::executed_summary::ExecutedObservationParetoConclusion>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observation_pareto_frontier: Vec<super::executed_summary::ExecutedParetoPoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quality_proxy_label: Option<String>,
    pub notice: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedExperimentRun {
    pub held_out: HeldOutCandidateEvidence,
    pub admitted_dispatches: u32,
    pub wall_time_ms: u64,
    pub supervisor_succeeded: bool,
    pub required_validation_passed: bool,
    pub supervisor_evidence: Option<PathBuf>,
    pub failure: Option<String>,
    #[serde(default)]
    pub real_provider_execution: RealProviderExecutionObservation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measurements: Option<ObservedRunMeasurements>,
}

/// Parent-owned observation of whether a real provider was actually launched.
/// Legacy documents without this field deserialize as `not_requested`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealProviderExecutionObservation {
    #[default]
    NotRequested,
    RequestedUnknown,
    LaunchAttempted,
    NativeRuntimeResultCaptured,
}

/// Calling this function is the operator's explicit local-command opt-in.
/// `artifact_repo` owns retained evidence only; the evaluated baseline is the
/// same fresh goal/spec fixture used by the legacy Fake experiment.
pub fn run_experiment_with_held_out(
    manifest: &ExperimentManifest,
    request: ExperimentRunRequest,
    artifact_repo: &Path,
) -> Result<ExecutedExperimentResults> {
    run_experiment_with_held_out_and_source(manifest, request, artifact_repo, None)
}

/// Held-out execution with an optional explicit evaluated source baseline.
pub fn run_experiment_with_held_out_and_source(
    manifest: &ExperimentManifest,
    request: ExperimentRunRequest,
    artifact_repo: &Path,
    explicit_source: Option<&HeldOutExplicitSourceBaseline>,
) -> Result<ExecutedExperimentResults> {
    manifest.validate()?;
    if request.execution != EvaluationExecution::DeterministicFake || request.allow_real_provider {
        bail!("held-out execution supports only deterministic-fake generation without real-provider opt-in");
    }
    if manifest.held_out_validation.is_empty() {
        bail!("--execute-held-out requires at least one declared validation");
    }
    let resolved_commit = match explicit_source {
        Some(source) => Some(
            experiment::resolve_held_out_explicit_source_baseline(source).map_err(|error| {
                anyhow!("held-out explicit source baseline is invalid: {error}")
            })?,
        ),
        None => None,
    };
    crate::git_repository::configure_libgit2_repository_extensions()?;
    let repo = artifacts::discover_repo_root(artifact_repo)?;
    let family = RunArtifactFamily::Supervise;
    let run_id = artifacts::generate_run_id(&repo, family)?;
    let mut writer =
        ArtifactRunWriter::reserve(&repo, family, run_id.clone(), "evaluation-held-out")?;
    writer.write_json(
        "held-out/manifest.json",
        manifest,
        ArtifactFileDisposition::PrivateEvidence,
    )?;
    let manifest_sha256 = sha256_hex(&serde_json::to_vec(manifest)?);
    let report_path = artifacts::final_report_path(&repo, family, &run_id);
    let writer = Arc::new(Mutex::new(writer));
    // One real timestamp fixes the synthetic commit as well as its tree across
    // profiles/repetitions. It is not a claimed source-repository revision.
    let baseline_time = if resolved_commit.is_some() {
        None
    } else {
        let seconds = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
        Some(git2::Time::new(seconds, 0))
    };
    let mut runs = Vec::new();
    let mut common_baseline: Option<(String, String)> = None;
    for (profile_index, profile) in manifest.profiles.iter().enumerate() {
        for repetition in 0..manifest.repetitions {
            let started = Instant::now();
            let deadline = started
                .checked_add(Duration::from_secs(manifest.limits.wall_time_seconds))
                .context("experiment wall-time limit cannot be represented")?;
            let mut isolated = match (explicit_source, resolved_commit) {
                (Some(source), Some(commit_oid)) => {
                    IsolatedSuperviseState::create_with_explicit_source_baseline(
                        manifest, profile, repetition, source, commit_oid,
                    )?
                }
                (None, None) => IsolatedSuperviseState::create_with_baseline_time(
                    manifest,
                    profile,
                    repetition,
                    baseline_time,
                )?,
                _ => bail!("held-out explicit source baseline resolution was inconsistent"),
            };
            isolated.run_id = RunId::new(format!(
                "{}-p{profile_index}-r{repetition}",
                run_id.as_str()
            ))?;
            let git = crate::git_repository::open(&isolated.repo)?;
            let baseline = git.head()?.peel_to_commit()?;
            let baseline_pair = (baseline.id().to_string(), baseline.tree_id().to_string());
            if common_baseline
                .as_ref()
                .is_some_and(|expected| expected != &baseline_pair)
            {
                bail!("isolated experiment baseline differs across profiles or repetitions");
            }
            common_baseline.get_or_insert(baseline_pair.clone());
            let binding = HeldOutRunBinding {
                manifest_sha256: manifest_sha256.clone(),
                profile_sha256: sha256_hex(&serde_json::to_vec(profile)?),
                profile_id: profile.id.clone(),
                repetition,
                experiment_run_id: run_id.as_str().into(),
                supervisor_run_id: isolated.run_id.as_str().into(),
                assignment_id: "child-a".into(),
                baseline_head: baseline_pair.0,
                baseline_tree: baseline_pair.1,
            };
            let authority = ParentValidationAuthority::new(
                binding,
                manifest.held_out_validation.clone(),
                deadline,
                manifest.limits.max_dispatches,
                Arc::clone(&writer),
            );
            // Retain the complete binding before even the first child dispatch.
            writer
                .lock()
                .map_err(|_| anyhow!("experiment artifact lock poisoned"))?
                .append_json_line(
                    "held-out/runs.jsonl",
                    &authority.evidence()?,
                    ArtifactFileDisposition::PrivateEvidence,
                )?;
            let mut options = isolated.options();
            options.budget_max_duration_seconds = Some(manifest.limits.wall_time_seconds);
            let report = supervise::run_held_out_fake_experiment(options, authority.clone());
            let held_out = authority.evidence()?;
            let admitted_dispatches = authority.dispatches()?;
            let prefix = PathBuf::from("held-out").join(format!("p{profile_index}-r{repetition}"));
            let (supervisor_succeeded, supervisor_evidence, failure, measurements) = match report {
                Ok(report) => {
                    let reader = ArtifactRunReader::open(&isolated.repo, family, &isolated.run_id)?;
                    let report_relative = family.final_report_relative_path();
                    let report_bytes = reader.read(&report_relative)?;
                    let measurements = observed_run_measurements_from_captured_supervisor_final_report(
                        &held_out,
                        &report,
                        &report_bytes,
                        &isolated.repo,
                        &BTreeSet::new(),
                    )
                    .map(Some)
                    .unwrap_or_else(|error| {
                        let reason = error.to_string();
                        Some(observed_run_measurements_unavailable(&held_out, &reason))
                    });
                    let mut retained = writer.lock().map_err(|_| anyhow!("experiment artifact lock poisoned"))?;
                    // Verification happens while the original repository/auth key
                    // still exists. The outer run then authenticates the copies.
                    for record in &reader.finalization().files {
                        retained.write_bytes(prefix.join(&record.path), &reader.read(&record.path)?, ArtifactFileDisposition::PrivateEvidence)?;
                    }
                    retained.write_json(prefix.join("source-finalization.json"), reader.finalization(), ArtifactFileDisposition::PrivateEvidence)?;
                    (
                        report.success,
                        Some(prefix.join(report_relative)),
                        None,
                        measurements,
                    )
                }
                Err(_) => (
                    false,
                    None,
                    Some("supervisor did not produce a verified finalized report; unfinished validation is unknown".into()),
                    Some(observed_run_measurements_unavailable(
                        &held_out,
                        "supervisor did not produce a verified finalized report",
                    )),
                ),
            };
            let run = ObservedExperimentRun {
                required_validation_passed: held_out.passed(),
                held_out,
                admitted_dispatches,
                wall_time_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                supervisor_succeeded,
                supervisor_evidence,
                failure,
                real_provider_execution: RealProviderExecutionObservation::NotRequested,
                measurements,
            };
            writer
                .lock()
                .map_err(|_| anyhow!("experiment artifact lock poisoned"))?
                .append_json_line(
                    "held-out/completed-runs.jsonl",
                    &run,
                    ArtifactFileDisposition::PrivateEvidence,
                )?;
            runs.push(run);
            // All observations and authenticated review inputs/results have been
            // retained before the temporary source/candidate repository is dropped.
        }
    }
    let results = finalize_executed_results(
        manifest,
        manifest_sha256,
        run_id.as_str(),
        report_path,
        explicit_source.is_none(),
        false,
        RealProviderExecutionObservation::NotRequested,
        runs,
        "Observed local argv validation of isolated synthetic Fake candidates. No provider execution, measured model quality, price, confidence, or production eligibility. Required unknown/failed validation cannot pass. No command replay or interrupted-run resume is supported; an unfinalized artifact run remains unknown and nonpublishable.".into(),
    )?;
    let mut writer = Arc::try_unwrap(writer)
        .map_err(|_| anyhow!("experiment validation authority still retained"))?
        .into_inner()
        .map_err(|_| anyhow!("experiment artifact lock poisoned"))?;
    writer.write_json(
        family.final_report_relative_path(),
        &results,
        ArtifactFileDisposition::PrivateEvidence,
    )?;
    writer.finalize(family.final_report_relative_path(), false)?;
    Ok(results)
}

const REAL_PROVIDER_HELD_OUT_NOTICE: &str = "Observed local argv validation of isolated real-runtime candidates over an operator-supplied source commit and caller plan. real_provider_executed is true only when parent-captured publishable native-runtime output was retained (not a launch attempt, failed login/quota/spawn, or child JSON self-report). LaunchAttempted proves target_launch_attempted only. No measured model quality, price, confidence, or production eligibility. Running a provider does not establish measured quality, cost, or named-default eligibility. Required unknown/failed validation cannot pass. No command replay or interrupted-run resume is supported; an unfinalized artifact run remains unknown and nonpublishable.";

/// Explicit opt-in wrapper for held-out real-provider execution. Refuses
/// incomplete or contradictory input before artifact reservation or provider
/// calls. Never falls back to Fake or a synthetic README plan.
pub fn run_held_out_real_provider_experiment(
    manifest: &ExperimentManifest,
    request: HeldOutRealProviderExperimentRequest,
    artifact_repo: &Path,
) -> Result<ExecutedExperimentResults> {
    manifest.validate_for_observation()?;
    refuse_incomplete_real_provider_request(&request)?;
    if manifest.held_out_validation.is_empty() {
        bail!("--execute-held-out requires at least one declared validation");
    }
    refuse_caller_plan_inside_evaluated_source(
        &request.provider_plan,
        &request.source.source_repo,
    )?;
    let frozen = supervise::freeze_held_out_production_caller_plan(&request.provider_plan)
        .map_err(|error| anyhow!("held-out production caller plan is invalid: {error}"))?;
    let resolved_commit = experiment::resolve_held_out_explicit_source_baseline(&request.source)
        .map_err(|error| anyhow!("held-out explicit source baseline is invalid: {error}"))?;
    let runtime_allowlist = freeze_runtime_bindings_before_reservation(&request)?;
    crate::git_repository::configure_libgit2_repository_extensions()?;
    let repo = artifacts::discover_repo_root(artifact_repo)?;
    let family = RunArtifactFamily::Supervise;
    let run_id = artifacts::generate_run_id(&repo, family)?;
    let mut writer =
        ArtifactRunWriter::reserve(&repo, family, run_id.clone(), "evaluation-held-out")?;
    writer.write_json(
        "held-out/manifest.json",
        manifest,
        ArtifactFileDisposition::PrivateEvidence,
    )?;
    writer.write_bytes(
        "held-out/caller-plan-original.json",
        &frozen.caller_plan_bytes,
        ArtifactFileDisposition::PrivateEvidence,
    )?;
    writer.write_json(
        "held-out/caller-plan-binding.json",
        &json!({
            "caller_plan_sha256": frozen.caller_plan_sha256,
            "assignment_id": frozen.assignment_id,
            "assigned_paths": frozen.assigned_paths,
            "observation": "requested",
        }),
        ArtifactFileDisposition::PrivateEvidence,
    )?;
    writer.write_json(
        "held-out/runtime-bindings.json",
        &runtime_allowlist.artifact_value(),
        ArtifactFileDisposition::PrivateEvidence,
    )?;
    let manifest_sha256 = sha256_hex(&serde_json::to_vec(manifest)?);
    let report_path = artifacts::final_report_path(&repo, family, &run_id);
    let writer = Arc::new(Mutex::new(writer));
    let mut runs = Vec::new();
    let mut common_baseline: Option<(String, String)> = None;
    let mut any_target_launch_attempted = false;
    let mut any_native_runtime_result = false;
    for (profile_index, profile) in manifest.profiles.iter().enumerate() {
        for repetition in 0..manifest.repetitions {
            let started = Instant::now();
            let deadline = started
                .checked_add(Duration::from_secs(manifest.limits.wall_time_seconds))
                .context("experiment wall-time limit cannot be represented")?;
            let (mut isolated, effective_plan_bytes) =
                IsolatedSuperviseState::create_with_explicit_source_and_frozen_plan(
                    manifest,
                    profile,
                    repetition,
                    &request.source,
                    resolved_commit,
                    &frozen,
                )?;
            isolated.run_id = RunId::new(format!(
                "{}-p{profile_index}-r{repetition}",
                run_id.as_str()
            ))?;
            let git = crate::git_repository::open(&isolated.repo)?;
            let baseline = git.head()?.peel_to_commit()?;
            let baseline_pair = (baseline.id().to_string(), baseline.tree_id().to_string());
            if common_baseline
                .as_ref()
                .is_some_and(|expected| expected != &baseline_pair)
            {
                bail!("isolated experiment baseline differs across profiles or repetitions");
            }
            common_baseline.get_or_insert(baseline_pair.clone());
            let effective_plan_sha256 = sha256_hex(&effective_plan_bytes);
            let prefix = PathBuf::from("held-out").join(format!("p{profile_index}-r{repetition}"));
            {
                let mut retained = writer
                    .lock()
                    .map_err(|_| anyhow!("experiment artifact lock poisoned"))?;
                retained.write_bytes(
                    prefix.join("caller-plan-original.json"),
                    &frozen.caller_plan_bytes,
                    ArtifactFileDisposition::PrivateEvidence,
                )?;
                retained.write_bytes(
                    prefix.join("requested-effective-plan.json"),
                    &effective_plan_bytes,
                    ArtifactFileDisposition::PrivateEvidence,
                )?;
                retained.write_json(
                    prefix.join("requested-profile-binding.json"),
                    &json!({
                        "profile_id": profile.id,
                        "profile_sha256": sha256_hex(&serde_json::to_vec(profile)?),
                        "requested_role_models": profile.role_models,
                        "caller_plan_sha256": frozen.caller_plan_sha256,
                        "effective_plan_sha256": effective_plan_sha256,
                        "assignment_id": frozen.assignment_id,
                        "assigned_paths": frozen.assigned_paths,
                        "observation": "requested",
                    }),
                    ArtifactFileDisposition::PrivateEvidence,
                )?;
            }
            let binding = HeldOutRunBinding {
                manifest_sha256: manifest_sha256.clone(),
                profile_sha256: sha256_hex(&serde_json::to_vec(profile)?),
                profile_id: profile.id.clone(),
                repetition,
                experiment_run_id: run_id.as_str().into(),
                supervisor_run_id: isolated.run_id.as_str().into(),
                assignment_id: frozen.assignment_id.clone(),
                baseline_head: baseline_pair.0,
                baseline_tree: baseline_pair.1,
            };
            let authority = ParentValidationAuthority::new(
                binding,
                manifest.held_out_validation.clone(),
                deadline,
                manifest.limits.max_dispatches,
                Arc::clone(&writer),
            );
            writer
                .lock()
                .map_err(|_| anyhow!("experiment artifact lock poisoned"))?
                .append_json_line(
                    "held-out/runs.jsonl",
                    &authority.evidence()?,
                    ArtifactFileDisposition::PrivateEvidence,
                )?;
            let mut options = isolated.production_options(
                request.runtime,
                request.runtime_executable.clone(),
                request.machine_global_retention.clone(),
            );
            options.budget_max_duration_seconds = Some(manifest.limits.wall_time_seconds);
            let outcome = supervise::run_held_out_production_experiment(
                options,
                authority.clone(),
                runtime_allowlist.clone(),
            );
            let (report, launch) = match outcome {
                Ok(outcome) => (outcome.report, outcome.launch),
                Err(error) => {
                    let held_out = authority.evidence()?;
                    let reason = error.to_string();
                    let measurements =
                        Some(observed_run_measurements_unavailable(&held_out, &reason));
                    let run = ObservedExperimentRun {
                        required_validation_passed: held_out.passed(),
                        admitted_dispatches: authority.dispatches()?,
                        wall_time_ms: u64::try_from(started.elapsed().as_millis())
                            .unwrap_or(u64::MAX),
                        supervisor_succeeded: false,
                        supervisor_evidence: None,
                        failure: Some(error.to_string()),
                        held_out,
                        real_provider_execution: RealProviderExecutionObservation::RequestedUnknown,
                        measurements,
                    };
                    retain_completed_run(&writer, &run)?;
                    runs.push(run);
                    continue;
                }
            };
            any_target_launch_attempted |= launch.target_launch_attempted;
            any_native_runtime_result |= launch.native_runtime_result_captured;
            let held_out = authority.evidence()?;
            let admitted_dispatches = authority.dispatches()?;
            let run_observation = real_provider_execution_from_parent_capture(
                launch.target_launch_attempted,
                launch.native_runtime_result_captured,
            );
            writer
                .lock()
                .map_err(|_| anyhow!("experiment artifact lock poisoned"))?
                .append_json_line(
                    "held-out/provider-launches.jsonl",
                    &json!({
                        "supervisor_run_id": isolated.run_id.as_str(),
                        "target_launch_attempted": launch.target_launch_attempted,
                        "native_runtime_result_captured": launch.native_runtime_result_captured,
                        "observation": run_observation,
                    }),
                    ArtifactFileDisposition::PrivateEvidence,
                )?;
            let (supervisor_succeeded, supervisor_evidence, failure, measurements) = match report {
                Ok(report) => {
                    let reader = ArtifactRunReader::open(&isolated.repo, family, &isolated.run_id)?;
                    let report_relative = family.final_report_relative_path();
                    let report_bytes = reader.read(&report_relative)?;
                    let measurements =
                        observed_run_measurements_from_captured_supervisor_final_report(
                            &held_out,
                            &report,
                            &report_bytes,
                            &isolated.repo,
                            &BTreeSet::new(),
                        )
                        .map(Some)
                        .unwrap_or_else(|error| {
                            let reason = error.to_string();
                            Some(observed_run_measurements_unavailable(&held_out, &reason))
                        });
                    let mut retained = writer
                        .lock()
                        .map_err(|_| anyhow!("experiment artifact lock poisoned"))?;
                    for record in &reader.finalization().files {
                        retained.write_bytes(
                            prefix.join(&record.path),
                            &reader.read(&record.path)?,
                            ArtifactFileDisposition::PrivateEvidence,
                        )?;
                    }
                    retained.write_json(
                        prefix.join("source-finalization.json"),
                        reader.finalization(),
                        ArtifactFileDisposition::PrivateEvidence,
                    )?;
                    (
                        report.success,
                        Some(prefix.join(report_relative)),
                        None,
                        measurements,
                    )
                }
                Err(error) => {
                    let reason =
                        format!("supervisor did not produce a verified finalized report: {error}");
                    (
                        false,
                        None,
                        Some(format!(
                            "supervisor did not produce a verified finalized report; unfinished validation is unknown: {error}"
                        )),
                        Some(observed_run_measurements_unavailable(&held_out, &reason)),
                    )
                }
            };
            let run = ObservedExperimentRun {
                required_validation_passed: held_out.passed(),
                held_out,
                admitted_dispatches,
                wall_time_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                supervisor_succeeded,
                supervisor_evidence,
                failure,
                real_provider_execution: run_observation,
                measurements,
            };
            retain_completed_run(&writer, &run)?;
            runs.push(run);
        }
    }
    let real_provider_execution = real_provider_execution_from_parent_capture(
        any_target_launch_attempted,
        any_native_runtime_result,
    );
    let results = finalize_executed_results(
        manifest,
        manifest_sha256,
        run_id.as_str(),
        report_path,
        false,
        any_native_runtime_result,
        real_provider_execution,
        runs,
        REAL_PROVIDER_HELD_OUT_NOTICE.into(),
    )?;
    let mut writer = Arc::try_unwrap(writer)
        .map_err(|_| anyhow!("experiment validation authority still retained"))?
        .into_inner()
        .map_err(|_| anyhow!("experiment artifact lock poisoned"))?;
    writer.write_json(
        family.final_report_relative_path(),
        &results,
        ArtifactFileDisposition::PrivateEvidence,
    )?;
    writer.finalize(family.final_report_relative_path(), false)?;
    Ok(results)
}

#[allow(clippy::too_many_arguments)]
fn finalize_executed_results(
    manifest: &ExperimentManifest,
    manifest_sha256: String,
    artifact_run_id: &str,
    artifact_report: PathBuf,
    synthetic_baseline: bool,
    real_provider_executed: bool,
    real_provider_execution: RealProviderExecutionObservation,
    runs: Vec<ObservedExperimentRun>,
    notice: String,
) -> Result<ExecutedExperimentResults> {
    let summary = summarize_executed_observation_runs(manifest, &manifest_sha256, &runs)?;
    Ok(apply_executed_summary(
        manifest,
        manifest_sha256,
        artifact_run_id,
        artifact_report,
        synthetic_baseline,
        real_provider_executed,
        real_provider_execution,
        runs,
        notice,
        summary,
    ))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn apply_executed_summary(
    manifest: &ExperimentManifest,
    manifest_sha256: String,
    artifact_run_id: &str,
    artifact_report: PathBuf,
    synthetic_baseline: bool,
    real_provider_executed: bool,
    real_provider_execution: RealProviderExecutionObservation,
    runs: Vec<ObservedExperimentRun>,
    notice: String,
    summary: ExecutedExperimentSummary,
) -> ExecutedExperimentResults {
    ExecutedExperimentResults {
        version: 3,
        schema: "evaluation_experiment_observations_v3".into(),
        experiment_id: manifest.experiment_id.clone(),
        manifest_sha256,
        artifact_run_id: artifact_run_id.into(),
        artifact_report,
        synthetic_baseline,
        real_provider_executed,
        real_provider_execution,
        production_eligible: false,
        eligible_for_production_economics: false,
        eligible_to_justify_named_default: false,
        quality: summary.labelled_quality_proxy,
        total_cost_usd: summary.total_reported_cost_usd,
        confidence: None,
        runs,
        profile_summaries: summary.profile_summaries,
        dispatch_comparisons: summary.dispatch_comparisons,
        observation_pareto_conclusion: Some(summary.pareto_conclusion),
        observation_pareto_frontier: summary.pareto_frontier,
        quality_proxy_label: summary.quality_proxy_label,
        notice,
    }
}

fn retain_completed_run(
    writer: &Arc<Mutex<ArtifactRunWriter>>,
    run: &ObservedExperimentRun,
) -> Result<()> {
    writer
        .lock()
        .map_err(|_| anyhow!("experiment artifact lock poisoned"))?
        .append_json_line(
            "held-out/completed-runs.jsonl",
            run,
            ArtifactFileDisposition::PrivateEvidence,
        )?;
    Ok(())
}

#[cfg(test)]
pub(super) fn native_runtime_result_captured_from_parent_run(
    run: &crate::external_agent::ExternalAgentRun,
) -> bool {
    crate::supervise::held_out_native_runtime_result_captured(run)
}

pub(super) fn real_provider_execution_from_parent_capture(
    target_launch_attempted: bool,
    native_runtime_result_captured: bool,
) -> RealProviderExecutionObservation {
    if native_runtime_result_captured {
        RealProviderExecutionObservation::NativeRuntimeResultCaptured
    } else if target_launch_attempted {
        RealProviderExecutionObservation::LaunchAttempted
    } else {
        RealProviderExecutionObservation::RequestedUnknown
    }
}

fn freeze_runtime_bindings_before_reservation(
    request: &HeldOutRealProviderExperimentRequest,
) -> Result<crate::supervise::FrozenHeldOutRuntimeAllowlist> {
    use crate::supervise::{
        freeze_held_out_runtime_allowlist, RunBudgetLimits, SupervisorAdmissionConfig,
        SupervisorRunOptions,
    };
    let additional: Vec<(SupervisorRuntime, PathBuf)> = request
        .additional_runtime_executables
        .iter()
        .map(|binding| (binding.runtime, binding.executable.clone()))
        .collect();
    let options = SupervisorRunOptions {
        repo: request.source.source_repo.clone(),
        plan_file: request.provider_plan.clone(),
        run_id: RunId::new("held-out-runtime-binding-preflight")?,
        parent_node: None,
        codex_bin: request.runtime_executable.clone(),
        runtime: request.runtime,
        allow_dirty_primary: false,
        allow_live_run_collision: false,
        admission_overrides: SupervisorAdmissionConfig::default(),
        budget_overrides: RunBudgetLimits::default(),
        budget_max_duration_seconds: None,
        machine_global_retention: Some(request.machine_global_retention.clone()),
    };
    freeze_held_out_runtime_allowlist(
        request.runtime,
        &request.runtime_executable,
        &additional,
        &options,
    )
}

fn refuse_incomplete_real_provider_request(
    request: &HeldOutRealProviderExperimentRequest,
) -> Result<()> {
    if request.execution != EvaluationExecution::RealProvider {
        bail!("held-out real-provider execution requires --execution real-provider");
    }
    if !request.allow_real_provider {
        bail!("held-out real-provider execution requires explicit allow_real_provider=true");
    }
    if request.runtime == SupervisorRuntime::Fake {
        bail!(
            "held-out real-provider execution requires a non-Fake runtime; refusing Fake fallback"
        );
    }
    if request.runtime_executable.as_os_str().is_empty() {
        bail!("held-out real-provider execution requires an explicit runtime executable; refusing to infer it from the source repository");
    }
    let additional: Vec<(SupervisorRuntime, PathBuf)> = request
        .additional_runtime_executables
        .iter()
        .map(|binding| (binding.runtime, binding.executable.clone()))
        .collect();
    crate::supervise::refuse_held_out_additional_runtime_bindings(request.runtime, &additional)?;
    if request.provider_plan.as_os_str().is_empty() {
        bail!("held-out real-provider execution requires --provider-plan");
    }
    if request.source.source_repo.as_os_str().is_empty() || request.source.base_commit.is_empty() {
        bail!(
            "held-out real-provider execution requires an explicit --source-repo and --base-commit"
        );
    }
    if request
        .machine_global_retention
        .config
        .as_os_str()
        .is_empty()
        || request.machine_global_retention.root_id.trim().is_empty()
    {
        bail!(
            "held-out real-provider execution requires a caller-supplied --machine-global-config and --machine-global-runtime-root-id; refusing to infer retention roots from the source repository"
        );
    }
    Ok(())
}

fn refuse_caller_plan_inside_evaluated_source(plan: &Path, source_repo: &Path) -> Result<()> {
    let plan = plan
        .canonicalize()
        .with_context(|| format!("failed to canonicalize --provider-plan {}", plan.display()))?;
    let source = source_repo.canonicalize().with_context(|| {
        format!(
            "failed to canonicalize --source-repo {}",
            source_repo.display()
        )
    })?;
    if plan.starts_with(&source) {
        bail!("--provider-plan must be outside the evaluated source repository");
    }
    Ok(())
}
