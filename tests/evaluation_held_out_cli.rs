#![cfg(target_os = "linux")]
mod support;

use anyhow::{Context, Result};
use multi_agent_coding_orchestrator::{
    artifacts::{ArtifactRunReader, RunArtifactFamily},
    evaluation::{CommandObservationStatus, ExecutedExperimentResults},
    orchestrator::RunId,
};
use serde_json::{json, Value};
use std::{fs, path::PathBuf, process::Command};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");

fn execute(commands: Value, max_dispatches: u32) -> Result<(TempDir, ExecutedExperimentResults)> {
    let workspace = TempDir::new()?;
    let repo = workspace.path().join("artifact-owner");
    git2::Repository::init(&repo)?;
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/model_mix_evaluation/experiment-manifest-v1.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(fixture)?)?;
    manifest["held_out_validation"] = commands;
    manifest["limits"]["max_dispatches"] = json!(max_dispatches);
    let manifest_path = workspace.path().join("manifest.json");
    fs::write(&manifest_path, serde_json::to_vec(&manifest)?)?;
    let output = Command::new(BIN)
        .args(["evaluation", "experiment"])
        .arg(manifest_path)
        .args(["--execute-held-out", "--json", "--repo"])
        .arg(&repo)
        .output()?;
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let results = serde_json::from_slice(&output.stdout).context("observed experiment JSON")?;
    Ok((workspace, results))
}

#[test]
fn production_cli_observes_actual_exit_mutation_and_unknown_and_retains_authenticated_review(
) -> Result<()> {
    support::require_containment!(
        "production_cli_observes_actual_exit_mutation_and_unknown_and_retains_authenticated_review"
    );
    let (workspace, results) = execute(
        json!([
            {"id":"present", "command":["/bin/sh", "-c", "test -f README.md"]},
            {"id":"actual-failure", "command":["/bin/sh", "-c", "exit 17"]},
            {"id":"mutation", "command":["/bin/sh", "-c", "printf changed >> README.md"]},
            {"id":"unavailable", "command":["/maco-missing-held-out-executable"]}
        ]),
        16,
    )?;
    assert_eq!(results.version, 3);
    assert_eq!(results.schema, "evaluation_experiment_observations_v3");
    assert!(results.synthetic_baseline);
    assert!(
        !results.real_provider_executed
            && !results.production_eligible
            && !results.eligible_for_production_economics
            && !results.eligible_to_justify_named_default
    );
    assert!(
        results.quality.is_none()
            && results.confidence.is_none()
            && results.total_cost_usd.is_none()
    );
    assert_eq!(results.runs.len(), 2);
    let baseline = &results.runs[0].held_out.run;
    for run in &results.runs {
        assert_eq!(run.held_out.run.manifest_sha256, results.manifest_sha256);
        assert_eq!(run.held_out.run.experiment_run_id, results.artifact_run_id);
        assert_eq!(run.held_out.run.baseline_head, baseline.baseline_head);
        assert_eq!(run.held_out.run.baseline_tree, baseline.baseline_tree);
        assert!(run.held_out.candidate.is_some(), "{run:?}");
        assert!(run.held_out.candidate_revalidated, "{run:?}");
        let observed = run
            .held_out
            .commands
            .iter()
            .map(|c| c.observation.status)
            .collect::<Vec<_>>();
        assert_eq!(
            observed,
            vec![
                CommandObservationStatus::Passed,
                CommandObservationStatus::Failed,
                CommandObservationStatus::Failed,
                CommandObservationStatus::Unknown
            ],
            "{run:?}"
        );
        assert_eq!(run.held_out.commands[1].observation.exit_code, Some(17));
        assert!(!run.required_validation_passed && !run.supervisor_succeeded);
        assert!(run.supervisor_evidence.is_some(), "{run:?}");
        assert!(run.admitted_dispatches <= 16);
    }
    assert_ne!(
        results.runs[0].held_out.run.profile_sha256,
        results.runs[1].held_out.run.profile_sha256
    );
    assert_ne!(
        results.runs[0].held_out.run.supervisor_run_id,
        results.runs[1].held_out.run.supervisor_run_id
    );
    let repo = workspace.path().join("artifact-owner");
    let id = RunId::new(&results.artifact_run_id)?;
    let reader = ArtifactRunReader::open(&repo, RunArtifactFamily::Supervise, &id)?;
    assert!(!reader.finalization().publishable);
    for run in &results.runs {
        let bytes = reader.read(run.supervisor_evidence.as_ref().unwrap())?;
        let retained: Value = serde_json::from_slice(&bytes)?;
        assert_eq!(retained["run_id"], run.held_out.run.supervisor_run_id);
        assert_eq!(retained["success"], false);
    }
    // Completed evidence remains authenticated after all temporary candidates
    // have been removed. A changed command/outcome is not reusable evidence.
    let observation = reader
        .finalization()
        .files
        .iter()
        .find(|r| r.path == std::path::Path::new("held-out/observations.jsonl"))
        .context("observation journal")?;
    let path = results
        .artifact_report
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join(&observation.path);
    fs::write(&path, b"{}\n")?;
    assert!(ArtifactRunReader::open(&repo, RunArtifactFamily::Supervise, &id).is_err());
    Ok(())
}

#[test]
fn production_cli_dispatch_limit_preserves_unknown_without_running_declared_commands() -> Result<()>
{
    support::require_containment!(
        "production_cli_dispatch_limit_preserves_unknown_without_running_declared_commands"
    );
    let (_workspace, results) = execute(
        json!([
            {"id":"must-not-run", "command":["/bin/sh", "-c", "exit 17"]}
        ]),
        1,
    )?;
    for run in results.runs {
        assert_eq!(run.admitted_dispatches, 1);
        assert_eq!(
            run.held_out.commands[0].observation.status,
            CommandObservationStatus::Unknown
        );
        assert_eq!(run.held_out.commands[0].observation.exit_code, None);
        assert!(!run.required_validation_passed && !run.supervisor_succeeded);
    }
    Ok(())
}
