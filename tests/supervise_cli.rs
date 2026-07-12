//! Representative public CLI coverage for `supervise`.
//!
//! The former executable fake-Codex fixture cases were migrated to private injected unit tests so
//! production `--runtime fake` never becomes a shell-execution backdoor:
//! - worker/auditor omissions, delegation, path scope, validation contradictions, and schema
//!   evidence -> `supervise::tests::injected_report_validation_preserves_worker_and_auditor_failure_coverage`
//! - structural retry, corrective feedback, and parent-auditor lineage ->
//!   `supervise::tests::injected_runner_retries_structural_report_once_then_runs_parent_auditor`
//! - no retry after a path violation plus tracked, untracked, index, and HEAD integrity changes ->
//!   `supervise::tests::injected_runner_path_violation_blocks_retry_and_primary_mutations_fail_integrity_gate`
//! - mutation during the parent auditor ->
//!   `supervise::tests::injected_parent_auditor_primary_mutation_is_rejected`
//! - unverified containment stopping retries/auditors ->
//!   `supervise::tests::unverified_child_attempt_launches_neither_retry_nor_parent_auditor`
//! - setsid descendants, parent death, timeout, and delayed mutation mechanics -> the focused
//!   `process_runner::tests::required_containment_*` and guardian parent-death tests
//! - non-UTF-8 evidence serialization ->
//!   `supervise::tests::finding_serialization_escapes_non_utf8_paths_reversibly` and
//!   `supervisor_required_optional_and_vector_paths_share_reversible_serialization`

use anyhow::{Context, Result};
use git2::{Oid, Repository, Signature};
use serde_json::Value;
use std::{fs, path::Path, process::Command};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");

#[cfg(unix)]
#[test]
fn fake_runtime_never_executes_codex_bin_or_task_text_and_is_never_publishable() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = Repository::open(&repo_path).context("open repo")?;
    let head_before = repo.head()?.target().context("HEAD target")?;
    let index_path = repo.path().join("index");
    let index_before = fs::read(&index_path).context("read index")?;
    let scratch = repo_path.join("preexisting-untracked.txt");
    fs::write(&scratch, "preserve\n").context("write scratch")?;

    let script_marker = temp.path().join("malicious-script-ran");
    let network_marker = temp.path().join("malicious-network-attempted");
    let task_marker = temp.path().join("task-text-ran");
    let malicious = temp.path().join("malicious-codex");
    fs::write(
        &malicious,
        format!(
            "#!/bin/sh\ntouch '{}'\ntouch '{}'\nexit 0\n",
            script_marker.display(),
            network_marker.display()
        ),
    )?;
    let mut permissions = fs::metadata(&malicious)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&malicious, permissions)?;

    let plan_path = temp.path().join("deterministic-fake-plan.json");
    let plan = serde_json::json!({
        "version": 1,
        "task": format!("$(touch '{}'); touch '{}'", task_marker.display(), task_marker.display()),
        "assignments": [{
            "id": "deterministic-child",
            "assigned_paths": ["README.md"],
            "worker_assignments": []
        }]
    });
    fs::write(&plan_path, serde_json::to_vec_pretty(&plan)?)?;

    let report = run_success_json(&[
        "supervise",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "deterministic-fake-invariant",
        "--codex-bin",
        path_str(&malicious)?,
        "--runtime",
        "fake",
        "--allow-dirty-primary",
        "--json",
    ])?;

    assert_eq!(report["runtime"], "fake");
    assert_eq!(report["success"], true);
    assert_eq!(report["publishable"], false);
    assert_eq!(report["accepted"], false);
    assert!(!script_marker.exists());
    assert!(!network_marker.exists());
    assert!(!task_marker.exists());
    assert_eq!(
        fs::read_to_string(repo_path.join("README.md"))?,
        "# Smoke\n"
    );
    assert_eq!(fs::read_to_string(&scratch)?, "preserve\n");
    assert_eq!(fs::read(&index_path)?, index_before);
    assert_eq!(repo.head()?.target(), Some(head_before));
    assert_eq!(
        report["released_claims"]
            .as_array()
            .context("claims")?
            .len(),
        1
    );
    assert!(report["release_errors"]
        .as_array()
        .context("errors")?
        .is_empty());
    Ok(())
}

#[test]
fn deterministic_fake_cli_emits_stable_shape_artifacts_and_cleans_claims() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("two-children.json");
    fs::write(
        &plan_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "task": "deterministic shape",
            "assignments": [
                {"id": "child-a", "assigned_paths": ["README.md"], "worker_assignments": []},
                {"id": "child-b", "assigned_paths": ["src/lib.rs"], "worker_assignments": []}
            ]
        }))?,
    )?;

    let report = run_success_json(&[
        "supervise",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "deterministic-shape",
        "--runtime",
        "fake",
        "--json",
    ])?;

    assert_eq!(report["runtime"], "fake");
    assert_eq!(report["success"], true);
    assert_eq!(report["publishable"], false);
    assert_eq!(report["accepted"], false);
    assert_eq!(
        report["orchestrator_reports"]
            .as_array()
            .context("reports")?
            .len(),
        2
    );
    assert!(
        report["commands_run"]
            .as_array()
            .context("commands")?
            .iter()
            .all(|record| record["command"]
                == serde_json::json!(["maco-internal-deterministic-fake"]))
    );
    let final_report =
        repo_path.join(".maco/o2/runs/deterministic-shape/reports/supervisor-final.json");
    assert!(final_report.exists());

    let claims = run_success_json(&["sync", "status", "--repo", path_str(&repo_path)?, "--json"])?;
    assert!(claims.as_array().context("claim status")?.is_empty());
    Ok(())
}

#[cfg(unix)]
#[test]
fn codex_runtime_custom_bin_fails_closed_and_cannot_mutate_primary() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let marker = repo_path.join("must-not-be-created");
    let custom = temp.path().join("custom-codex");
    fs::write(
        &custom,
        format!(
            "#!/bin/sh\ncase \"$1\" in --version) printf 'codex-cli 0.142.3\\n';; *) touch '{}';; esac\n",
            marker.display()
        ),
    )?;
    let mut permissions = fs::metadata(&custom)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&custom, permissions)?;
    let plan_path = temp.path().join("codex-fail-closed.json");
    write_simple_plan(&plan_path, "codex-child")?;

    let output = Command::new(BIN)
        .args([
            "supervise",
            "run",
            path_str(&plan_path)?,
            "--repo",
            path_str(&repo_path)?,
            "--run-id",
            "codex-fail-closed",
            "--codex-bin",
            path_str(&custom)?,
            "--runtime",
            "codex",
            "--json",
        ])
        .output()?;
    assert!(!output.status.success());
    if !output.stdout.is_empty() {
        let report: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(report["runtime"], "codex");
        assert_eq!(report["success"], false);
        assert_eq!(report["publishable"], false);
        assert_eq!(report["accepted"], false);
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("process-tree ownership") || stderr.contains("containment guardian"),
            "unexpected fail-closed stderr: {stderr}"
        );
    }
    assert!(!marker.exists());
    assert_eq!(
        fs::read_to_string(repo_path.join("README.md"))?,
        "# Smoke\n"
    );
    Ok(())
}

#[test]
fn supervise_plan_normalizes_aliases_and_rejects_overlapping_assignments() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("aliases.json");
    fs::write(
        &plan_path,
        br#"{
          "version": 1,
          "task": "aliases",
          "max_child_processes": 2,
          "assignments": [
            {"id": "child-a", "role": "child_orchestrator", "assigned_paths": ["./README.md"]}
          ]
        }"#,
    )?;
    let plan = run_success_json(&[
        "supervise",
        "plan",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(plan["max_child_assignments"], 2);
    assert_eq!(
        plan["assignments"][0]["assigned_paths"],
        serde_json::json!(["README.md"])
    );

    let overlap = temp.path().join("overlap.json");
    fs::write(
        &overlap,
        br#"{
          "version": 1,
          "task": "overlap",
          "assignments": [
            {"id": "child-a", "assigned_paths": ["src"]},
            {"id": "child-b", "assigned_paths": ["src/lib.rs"]}
          ]
        }"#,
    )?;
    let output = Command::new(BIN)
        .args([
            "supervise",
            "run",
            path_str(&overlap)?,
            "--repo",
            path_str(&repo_path)?,
            "--run-id",
            "overlap",
            "--runtime",
            "fake",
            "--json",
        ])
        .output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("overlap"));
    Ok(())
}

#[test]
fn supervise_run_id_reuse_is_refused_and_artifacts_remain_collectable() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("artifact-plan.json");
    write_simple_plan(&plan_path, "artifact-child")?;
    let args = [
        "supervise",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "artifact-run",
        "--runtime",
        "fake",
        "--json",
    ];
    let first = run_success_json(&args)?;
    assert_eq!(first["success"], true);
    let reused = run_failure_json(&args)?;
    assert_eq!(reused["status"], "refused");

    let status = run_success_json(&[
        "supervise",
        "status",
        "artifact-run",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(status["final_report_exists"], true);
    assert_eq!(status["final_report"]["publishable"], false);
    Ok(())
}

#[test]
fn fake_prompt_keeps_role_assignment_and_consultant_contract_as_data() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("prompt-plan.json");
    fs::write(
        &plan_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "task": "parent task",
            "consultant": {"enabled": true, "runtime": "fake", "max_consultations": 1},
            "assignments": [{
                "id": "prompt-child",
                "assigned_paths": ["README.md"],
                "task": "child override $(touch must-not-run)",
                "worker_assignments": [{
                    "id": "prompt-worker",
                    "assigned_paths": ["README.md"],
                    "task": null
                }]
            }]
        }))?,
    )?;
    let report = run_success_json(&[
        "supervise",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "prompt-contract",
        "--runtime",
        "fake",
        "--json",
    ])?;
    assert_eq!(report["publishable"], false);
    let prompt = fs::read_to_string(
        repo_path.join(".maco/o2/runs/prompt-contract/assignments/prompt-child.prompt.md"),
    )?;
    assert!(prompt.starts_with("ROLE: O1_CHILD_ORCHESTRATOR\n"));
    assert!(prompt.contains("child override $(touch must-not-run)"));
    assert!(prompt.contains("maco consult ask --runtime fake"));
    assert!(!repo_path.join("must-not-run").exists());
    Ok(())
}

#[test]
fn security_document_describes_deterministic_fake_and_verified_codex_boundary() -> Result<()> {
    let security = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("SECURITY.md"))?;
    assert!(security.contains("Fake supervisor runtime is deterministic"));
    assert!(security.contains("does not execute `--codex-bin`"));
    assert!(security.contains("can never produce publishable acceptance"));
    assert!(security.contains("maco_external_codex"));
    Ok(())
}

fn write_simple_plan(path: &Path, id: &str) -> Result<()> {
    fs::write(
        path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "task": "simple deterministic plan",
            "assignments": [{
                "id": id,
                "assigned_paths": ["README.md"],
                "worker_assignments": []
            }]
        }))?,
    )?;
    Ok(())
}

fn run_success_json(args: &[&str]) -> Result<Value> {
    let output = Command::new(BIN).args(args).output().context("run maco")?;
    if !output.status.success() {
        anyhow::bail!(
            "maco command failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).context("parse success JSON")
}

fn run_failure_json(args: &[&str]) -> Result<Value> {
    let output = Command::new(BIN).args(args).output().context("run maco")?;
    if output.status.success() {
        anyhow::bail!("maco command unexpectedly succeeded");
    }
    serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "parse failure JSON: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn create_committed_repo(root: &Path) -> Result<std::path::PathBuf> {
    let repo_path = root.join("repo");
    let output = Command::new(BIN)
        .args(["init", "--repo", path_str(&repo_path)?, "--json"])
        .output()?;
    if !output.status.success() {
        anyhow::bail!("init failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    fs::create_dir_all(repo_path.join("src"))?;
    fs::write(repo_path.join(".gitignore"), ".maco/\n")?;
    fs::write(repo_path.join("README.md"), "# Smoke\n")?;
    fs::write(
        repo_path.join("src/lib.rs"),
        "pub fn ok() -> bool { true }\n",
    )?;
    let repo = Repository::open(&repo_path)?;
    commit_all(&repo, "initial")?;
    Ok(repo_path)
}

fn commit_all(repo: &Repository, message: &str) -> Result<Oid> {
    let mut index = repo.index()?;
    index.add_all(["*"], git2::IndexAddOption::DEFAULT, None)?;
    index.write()?;
    let tree_id = index.write_tree()?;
    let tree = repo.find_tree(tree_id)?;
    let signature = Signature::now("maco test", "maco-test@example.invalid")?;
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
    .context("commit")
}

fn path_str(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("path is not UTF-8: {}", path.display()))
}
