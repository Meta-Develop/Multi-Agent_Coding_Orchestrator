//! Observed local validation, deliberately separate from legacy synthetic scores.
use super::{
    experiment::{self, HeldOutExplicitSourceBaseline, IsolatedSuperviseState},
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
    },
};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
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
    pub production_eligible: bool,
    pub eligible_for_production_economics: bool,
    pub eligible_to_justify_named_default: bool,
    pub quality: Option<f64>,
    pub total_cost_usd: Option<f64>,
    pub confidence: Option<f64>,
    pub runs: Vec<ObservedExperimentRun>,
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
            let (supervisor_succeeded, supervisor_evidence, failure) = match report {
                Ok(report) => {
                    let reader = ArtifactRunReader::open(&isolated.repo, family, &isolated.run_id)?;
                    let mut retained = writer.lock().map_err(|_| anyhow!("experiment artifact lock poisoned"))?;
                    // Verification happens while the original repository/auth key
                    // still exists. The outer run then authenticates the copies.
                    for record in &reader.finalization().files {
                        retained.write_bytes(prefix.join(&record.path), &reader.read(&record.path)?, ArtifactFileDisposition::PrivateEvidence)?;
                    }
                    retained.write_json(prefix.join("source-finalization.json"), reader.finalization(), ArtifactFileDisposition::PrivateEvidence)?;
                    (report.success, Some(prefix.join(family.final_report_relative_path())), None)
                }
                Err(_) => (false, None, Some("supervisor did not produce a verified finalized report; unfinished validation is unknown".into())),
            };
            let run = ObservedExperimentRun {
                required_validation_passed: held_out.passed(),
                held_out,
                admitted_dispatches,
                wall_time_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                supervisor_succeeded,
                supervisor_evidence,
                failure,
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
    let results = ExecutedExperimentResults {
        version: 3, schema: "evaluation_experiment_observations_v3".into(),
        experiment_id: manifest.experiment_id.clone(), manifest_sha256,
        artifact_run_id: run_id.as_str().into(), artifact_report: report_path,
        synthetic_baseline: explicit_source.is_none(),
        real_provider_executed: false,
        production_eligible: false, eligible_for_production_economics: false,
        eligible_to_justify_named_default: false,
        quality: None, total_cost_usd: None, confidence: None, runs,
        notice: "Observed local argv validation of isolated synthetic Fake candidates. No provider execution, measured model quality, price, confidence, or production eligibility. Required unknown/failed validation cannot pass. No command replay or interrupted-run resume is supported; an unfinalized artifact run remains unknown and nonpublishable.".into(),
    };
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
