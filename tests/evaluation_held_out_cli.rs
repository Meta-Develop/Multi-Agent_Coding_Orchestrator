#![cfg(target_os = "linux")]
mod support;

use anyhow::{Context, Result};
use multi_agent_coding_orchestrator::{
    artifacts::{ArtifactRunReader, RunArtifactFamily},
    evaluation::{
        CommandObservationStatus, ExecutedExperimentResults, RealProviderExecutionObservation,
    },
    orchestrator::RunId,
};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");

struct ExecuteOptions<'a> {
    commands: Value,
    max_dispatches: u32,
    source_repo: Option<&'a Path>,
    base_commit: Option<&'a str>,
    expect_success: bool,
}

fn execute_opts(
    options: ExecuteOptions<'_>,
) -> Result<(TempDir, Option<ExecutedExperimentResults>)> {
    let workspace = TempDir::new()?;
    let repo = workspace.path().join("artifact-owner");
    git2::Repository::init(&repo)?;
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/model_mix_evaluation/experiment-manifest-v1.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(fixture)?)?;
    manifest["held_out_validation"] = options.commands;
    manifest["limits"]["max_dispatches"] = json!(options.max_dispatches);
    let manifest_path = workspace.path().join("manifest.json");
    fs::write(&manifest_path, serde_json::to_vec(&manifest)?)?;
    let mut command = Command::new(BIN);
    command
        .args(["evaluation", "experiment"])
        .arg(&manifest_path)
        .args(["--execute-held-out", "--json", "--repo"])
        .arg(&repo);
    if let Some(source_repo) = options.source_repo {
        command.arg("--source-repo").arg(source_repo);
    }
    if let Some(base_commit) = options.base_commit {
        command.arg("--base-commit").arg(base_commit);
    }
    let output = command.output()?;
    if options.expect_success {
        assert!(
            output.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let results = serde_json::from_slice(&output.stdout).context("observed experiment JSON")?;
        Ok((workspace, Some(results)))
    } else {
        assert!(
            !output.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok((workspace, None))
    }
}

fn execute(commands: Value, max_dispatches: u32) -> Result<(TempDir, ExecutedExperimentResults)> {
    let (workspace, results) = execute_opts(ExecuteOptions {
        commands,
        max_dispatches,
        source_repo: None,
        base_commit: None,
        expect_success: true,
    })?;
    Ok((workspace, results.expect("successful execute")))
}

fn init_source_repo(workspace: &Path) -> Result<(PathBuf, String, String)> {
    let repo_path = workspace.join("evaluated-source");
    let repo = git2::Repository::init(&repo_path)?;
    fs::write(repo_path.join("README.md"), "evaluated source tree\n")?;
    let mut index = repo.index()?;
    index.add_all(["*"], git2::IndexAddOption::DEFAULT, None)?;
    index.write()?;
    let tree_id = index.write_tree()?;
    let tree = repo.find_tree(tree_id)?;
    let signature = git2::Signature::now("held-out-cli", "held-out-cli@example.invalid")?;
    let oid = repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        "evaluated source baseline",
        &tree,
        &[],
    )?;
    let head = fs::read_to_string(repo_path.join(".git/HEAD"))?;
    Ok((repo_path, oid.to_string(), head))
}

fn supervise_run_count(artifact_owner: &Path) -> Result<usize> {
    let runs = artifact_owner.join(".maco/o2/runs");
    if !runs.exists() {
        return Ok(0);
    }
    Ok(fs::read_dir(runs)?.count())
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
            && results.real_provider_execution == RealProviderExecutionObservation::NotRequested
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

#[test]
fn explicit_source_baseline_binds_commit_tree_and_preserves_fake_nonproduction() -> Result<()> {
    support::require_containment!(
        "explicit_source_baseline_binds_commit_tree_and_preserves_fake_nonproduction"
    );
    let workspace = TempDir::new()?;
    let (source_repo, base_commit, _) = init_source_repo(workspace.path())?;
    let (_run_workspace, results) = execute_opts(ExecuteOptions {
        commands: json!([{"id":"present", "command":["/bin/sh", "-c", "test -f README.md"]}]),
        max_dispatches: 8,
        source_repo: Some(&source_repo),
        base_commit: Some(&base_commit),
        expect_success: true,
    })?;
    let results = results.expect("held-out results");
    assert!(!results.synthetic_baseline);
    assert!(
        !results.real_provider_executed
            && !results.production_eligible
            && !results.eligible_for_production_economics
    );
    let baseline = &results.runs[0].held_out.run;
    assert_eq!(baseline.baseline_head, base_commit);
    for run in &results.runs {
        assert_eq!(run.held_out.run.baseline_head, baseline.baseline_head);
        assert_eq!(run.held_out.run.baseline_tree, baseline.baseline_tree);
    }
    assert_ne!(
        results.runs[0].held_out.run.supervisor_run_id,
        results.runs[1].held_out.run.supervisor_run_id
    );
    let wire = serde_json::to_string(&results)?;
    assert!(!wire.contains(source_repo.to_str().unwrap()));
    assert!(wire.contains(&base_commit));
    Ok(())
}

#[test]
fn explicit_source_flags_require_pair_and_execute_held_out() -> Result<()> {
    let workspace = TempDir::new()?;
    let (source_repo, base_commit, _) = init_source_repo(workspace.path())?;
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/model_mix_evaluation/experiment-manifest-v1.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(fixture)?)?;
    manifest["held_out_validation"] = json!([{"id":"present", "command":["true"]}]);
    let manifest_path = workspace.path().join("manifest.json");
    fs::write(&manifest_path, serde_json::to_vec(&manifest)?)?;
    let artifact_owner = workspace.path().join("artifact-owner");
    git2::Repository::init(&artifact_owner)?;
    let before = supervise_run_count(&artifact_owner)?;
    let output = Command::new(BIN)
        .args(["evaluation", "experiment"])
        .arg(&manifest_path)
        .args(["--json", "--repo"])
        .arg(&artifact_owner)
        .arg("--source-repo")
        .arg(&source_repo)
        .arg("--base-commit")
        .arg(&base_commit)
        .output()?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--execute-held-out"));
    assert_eq!(supervise_run_count(&artifact_owner)?, before);

    let output = Command::new(BIN)
        .args(["evaluation", "experiment"])
        .arg(&manifest_path)
        .args(["--execute-held-out", "--json", "--repo"])
        .arg(&artifact_owner)
        .arg("--source-repo")
        .arg(&source_repo)
        .output()?;
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("together"),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(supervise_run_count(&artifact_owner)?, before);
    Ok(())
}

#[test]
fn explicit_source_invalid_commit_is_rejected_before_artifact_reservation() -> Result<()> {
    let workspace = TempDir::new()?;
    let (source_repo, base_commit, _) = init_source_repo(workspace.path())?;
    let (run_workspace, results) = execute_opts(ExecuteOptions {
        commands: json!([{"id":"present", "command":["true"]}]),
        max_dispatches: 4,
        source_repo: Some(&source_repo),
        base_commit: Some("0000000000000000000000000000000000000000"),
        expect_success: false,
    })?;
    assert!(results.is_none());
    assert_eq!(
        supervise_run_count(&run_workspace.path().join("artifact-owner"))?,
        0
    );
    let (run_workspace, results) = execute_opts(ExecuteOptions {
        commands: json!([{"id":"present", "command":["true"]}]),
        max_dispatches: 4,
        source_repo: Some(&source_repo),
        base_commit: Some(&base_commit[..7]),
        expect_success: false,
    })?;
    assert!(results.is_none());
    assert_eq!(
        supervise_run_count(&run_workspace.path().join("artifact-owner"))?,
        0
    );
    Ok(())
}

#[test]
fn explicit_source_leaves_dirty_source_repository_unchanged() -> Result<()> {
    support::require_containment!("explicit_source_leaves_dirty_source_repository_unchanged");
    let workspace = TempDir::new()?;
    let (source_repo, base_commit, head_before) = init_source_repo(workspace.path())?;
    let dirty = source_repo.join("dirty-worktree.txt");
    fs::write(&dirty, b"dirty\n")?;
    let staged = source_repo.join("staged-only.txt");
    fs::write(&staged, b"staged\n")?;
    {
        let repo = git2::Repository::open(&source_repo)?;
        let mut index = repo.index()?;
        index.add_path(Path::new("staged-only.txt"))?;
        index.write()?;
    }
    let dirty_bytes = fs::read(&dirty)?;
    let index_bytes = fs::read(source_repo.join(".git/index"))?;
    let (_workspace, results) = execute_opts(ExecuteOptions {
        commands: json!([{"id":"present", "command":["/bin/sh", "-c", "test -f README.md"]}]),
        max_dispatches: 8,
        source_repo: Some(&source_repo),
        base_commit: Some(&base_commit),
        expect_success: true,
    })?;
    assert!(!results.expect("results").synthetic_baseline);
    assert_eq!(
        fs::read_to_string(source_repo.join(".git/HEAD"))?,
        head_before
    );
    assert_eq!(fs::read(&dirty)?, dirty_bytes);
    assert_eq!(fs::read(source_repo.join(".git/index"))?, index_bytes);
    assert!(!source_repo.join(".git/worktrees").exists());
    Ok(())
}

#[test]
fn real_provider_incomplete_tuple_is_refused_before_artifact_reservation() -> Result<()> {
    let workspace = TempDir::new()?;
    let (source_repo, base_commit, _) = init_source_repo(workspace.path())?;
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/model_mix_evaluation/experiment-manifest-v1.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(fixture)?)?;
    manifest["held_out_validation"] = json!([{"id":"present", "command":["true"]}]);
    let manifest_path = workspace.path().join("manifest.json");
    fs::write(&manifest_path, serde_json::to_vec(&manifest)?)?;
    let artifact_owner = workspace.path().join("artifact-owner");
    git2::Repository::init(&artifact_owner)?;
    let plan_path = workspace.path().join("provider-plan.json");
    fs::write(
        &plan_path,
        serde_json::to_vec(&json!({
            "version": 1,
            "task": "cli real-provider caller plan",
            "max_depth": 2,
            "max_child_assignments": 1,
            "max_child_retries": 0,
            "child_timeout_seconds": 10,
            "assignments": [{
                "id": "docs-child",
                "phase": "execution",
                "assigned_paths": ["README.md"],
                "worker_assignments": [{"id": "worker-a", "assigned_paths": ["README.md"]}]
            }]
        }))?,
    )?;
    let before = supervise_run_count(&artifact_owner)?;
    let output = Command::new(BIN)
        .args(["evaluation", "experiment"])
        .arg(&manifest_path)
        .args([
            "--execute-held-out",
            "--execution",
            "real-provider",
            "--allow-real-provider",
            "--json",
            "--repo",
        ])
        .arg(&artifact_owner)
        .arg("--source-repo")
        .arg(&source_repo)
        .arg("--base-commit")
        .arg(&base_commit)
        .arg("--provider-plan")
        .arg(&plan_path)
        .args(["--runtime", "grok"])
        .output()?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--runtime-bin") || stderr.contains("runtime executable"),
        "stderr={stderr}"
    );
    assert_eq!(supervise_run_count(&artifact_owner)?, before);

    let output = Command::new(BIN)
        .args(["evaluation", "experiment"])
        .arg(&manifest_path)
        .args([
            "--execute-held-out",
            "--execution",
            "real-provider",
            "--allow-real-provider",
            "--json",
            "--repo",
        ])
        .arg(&artifact_owner)
        .arg("--source-repo")
        .arg(&source_repo)
        .arg("--base-commit")
        .arg(&base_commit)
        .arg("--provider-plan")
        .arg(&plan_path)
        .args(["--runtime", "fake", "--runtime-bin", "/usr/bin/true"])
        .args([
            "--machine-global-config",
            "/tmp/maco-machine-global.json",
            "--machine-global-runtime-root-id",
            "runtime",
        ])
        .output()?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("non-Fake") || stderr.contains("Fake fallback"),
        "stderr={stderr}"
    );
    assert_eq!(supervise_run_count(&artifact_owner)?, before);
    Ok(())
}
