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
    let run_root = repo_path.join(".maco/o2/runs/deterministic-shape");
    assert!(run_root.join(".maco-artifact-final.json").exists());
    assert!(!run_root.join("incoming").exists());
    assert!(!run_root.join("capture").exists());
    assert!(run_root.join("evidence/incoming/child-a.json").exists());
    assert!(run_root.join("evidence/incoming/child-b.json").exists());

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
    assert_eq!(status["repo"], ".");
    assert_eq!(status["run_dir"], ".maco/o2/runs/artifact-run");
    assert_eq!(status["final_report"]["repo"], ".");
    assert_eq!(status["final_report"]["plan_file"], "<external-plan>");
    assert_eq!(
        status["final_report"]["run_dir"],
        ".maco/o2/runs/artifact-run"
    );
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
fn supervise_generates_run_ids_refuses_reuse_and_lists_artifacts() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("generated-id.json");
    write_simple_plan(&plan_path, "generated-child")?;

    let report = run_success_json(&[
        "supervise",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--runtime",
        "fake",
        "--json",
    ])?;
    let run_id = report["run_id"].as_str().context("generated run id")?;
    assert!(run_id.starts_with("o2-"));
    assert!(repo_path
        .join(".maco/o2/runs")
        .join(run_id)
        .join("reports/supervisor-final.json")
        .exists());

    let listed = run_success_json(&[
        "supervise",
        "artifacts",
        "list",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(listed["runs"][0]["run_id"], run_id);
    assert_eq!(listed["runs"][0]["final_report_status"], "succeeded");
    assert_eq!(listed["runs"][0]["final_report_success"], true);
    assert_eq!(listed["runs"][0]["finalized"], true);
    assert_eq!(listed["runs"][0]["publishable"], false);
    assert_eq!(listed["runs"][0]["provenance_valid"], true);
    assert_eq!(listed["runs"][0]["artifact_digests_verified"], true);

    let reused = run_failure_json(&[
        "supervise",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        run_id,
        "--runtime",
        "fake",
        "--json",
    ])?;
    assert_eq!(reused["status"], "refused");
    assert!(reused["message"]
        .as_str()
        .context("reuse message")?
        .contains("already exists"));
    Ok(())
}

#[test]
fn supervise_prune_deletes_only_finalized_old_runs() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("prune-plan.json");
    write_simple_plan(&plan_path, "prune-child")?;
    for run_id in ["prune-old", "prune-new"] {
        let report = run_success_json(&[
            "supervise",
            "run",
            path_str(&plan_path)?,
            "--repo",
            path_str(&repo_path)?,
            "--run-id",
            run_id,
            "--runtime",
            "fake",
            "--json",
        ])?;
        assert_eq!(report["success"], true);
        assert!(repo_path
            .join(".maco/o2/runs")
            .join(run_id)
            .join(".maco-artifact-final.json")
            .exists());
    }

    let prune = run_success_json(&[
        "supervise",
        "artifacts",
        "prune",
        "--repo",
        path_str(&repo_path)?,
        "--keep",
        "1",
        "--json",
    ])?;
    assert_eq!(prune["delete_candidate_count"], 1);
    assert_eq!(prune["deleted_count"], 1);
    assert_eq!(prune["refused_unfinalized_count"], 0);

    let listed = run_success_json(&[
        "supervise",
        "artifacts",
        "list",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    let runs = listed["runs"].as_array().context("listed supervise runs")?;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0]["finalized"], true);
    assert_eq!(runs[0]["publishable"], false);
    Ok(())
}

#[test]
fn supervise_warn_mode_reports_same_plan_semantic_conflict() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    fs::write(repo_path.join("src/lib.rs"), "pub struct Shared;\n")?;
    let repo = Repository::open(&repo_path)?;
    commit_all(&repo, "semantic symbol")?;
    let plan_path = temp.path().join("semantic-warn.json");
    fs::write(
        &plan_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "task": "coordinate semantic overlap",
            "max_depth": 2,
            "max_child_assignments": 2,
            "semantic_coordination": "warn",
            "assignments": [
                {
                    "id": "child-a",
                    "assigned_paths": ["README.md"],
                    "semantic_symbols": ["Shared"],
                    "worker_assignments": []
                },
                {
                    "id": "child-b",
                    "assigned_paths": ["src/lib.rs"],
                    "semantic_symbols": ["Shared"],
                    "worker_assignments": []
                }
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
        "semantic-warn",
        "--runtime",
        "fake",
        "--json",
    ])?;
    assert_eq!(report["success"], true);
    assert!(report["released_semantic_intents"]
        .as_array()
        .context("semantic releases")?
        .is_empty());
    assert!(report["findings"]
        .as_array()
        .context("findings")?
        .iter()
        .any(|finding| finding["severity"] == "warning"
            && finding["message"]
                .as_str()
                .is_some_and(|message| message.contains("warn-mode preview"))
            && finding["paths"]
                .as_array()
                .is_some_and(|paths| paths.iter().any(|path| path == "src/lib.rs"))));
    Ok(())
}

#[test]
fn supervise_run_reports_sync_claim_conflict_owner_and_paths() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("claim-conflict.json");
    write_simple_plan(&plan_path, "child-claim-conflict")?;
    let claim = run_success_json(&[
        "sync",
        "claim",
        "stale-agent",
        "README.md",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(claim["agent_id"], "stale-agent");

    let report = run_failure_json(&[
        "supervise",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "claim-conflict",
        "--runtime",
        "fake",
        "--json",
    ])?;
    assert_eq!(report["success"], false);
    assert!(report["findings"]
        .as_array()
        .context("findings")?
        .iter()
        .any(|finding| finding["message"]
            .as_str()
            .is_some_and(|message| message.contains("README.md currently claimed by stale-agent"))
            && finding["paths"]
                .as_array()
                .is_some_and(|paths| paths.iter().any(|path| path == "README.md"))));
    Ok(())
}

#[test]
fn supervise_run_refuses_clean_stale_reused_child_worktree_before_execution() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("stale-worktree.json");
    write_simple_plan(&plan_path, "child-clean")?;
    let first = run_success_json(&[
        "supervise",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "clean-first",
        "--runtime",
        "fake",
        "--json",
    ])?;
    assert_eq!(first["success"], true);
    fs::write(repo_path.join("README.md"), "# advanced\n")?;
    let repo = Repository::open(&repo_path)?;
    commit_all(&repo, "advance primary")?;

    let report = run_failure_json(&[
        "supervise",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "clean-stale",
        "--runtime",
        "fake",
        "--json",
    ])?;
    assert_eq!(report["success"], false);
    assert!(report["orchestrator_reports"]
        .as_array()
        .context("reports")?
        .is_empty());
    assert!(report["findings"]
        .as_array()
        .context("findings")?
        .iter()
        .any(|finding| finding["message"]
            .as_str()
            .is_some_and(|message| message.contains("refusing to reuse stale child worktree"))));
    assert!(!repo_path
        .join(".maco/o2/runs/clean-stale/evidence/incoming/child-clean.json")
        .exists());
    assert!(repo_path
        .join(".maco/o2/runs/clean-stale/.maco-artifact-final.json")
        .exists());
    Ok(())
}

#[test]
fn supervise_run_enforces_max_depth_and_process_budget() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let cases = [
        (
            "bad-depth",
            serde_json::json!({
                "version": 1,
                "task": "bad depth",
                "max_depth": 3,
                "max_child_assignments": 1,
                "assignments": [{"id": "child-a", "assigned_paths": ["README.md"]}]
            }),
            "max_depth",
        ),
        (
            "bad-budget",
            serde_json::json!({
                "version": 1,
                "task": "bad budget",
                "max_depth": 2,
                "max_child_assignments": 1,
                "assignments": [
                    {"id": "child-a", "assigned_paths": ["README.md"]},
                    {"id": "child-b", "assigned_paths": ["src/lib.rs"]}
                ]
            }),
            "max_child_assignments",
        ),
        (
            "bad-retries",
            serde_json::json!({
                "version": 1,
                "task": "bad retries",
                "max_depth": 2,
                "max_child_assignments": 1,
                "max_child_retries": 3,
                "assignments": [{"id": "child-a", "assigned_paths": ["README.md"]}]
            }),
            "max_child_retries",
        ),
    ];
    for (run_id, plan, expected) in cases {
        let plan_path = temp.path().join(format!("{run_id}.json"));
        fs::write(&plan_path, serde_json::to_vec_pretty(&plan)?)?;
        let output = Command::new(BIN)
            .args([
                "supervise",
                "run",
                path_str(&plan_path)?,
                "--repo",
                path_str(&repo_path)?,
                "--run-id",
                run_id,
                "--runtime",
                "fake",
                "--json",
            ])
            .output()?;
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "missing {expected} in {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

#[test]
fn supervise_primary_git_snapshots_ignore_ambient_repository_redirects() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let decoy_path = temp.path().join("decoy");
    Repository::init(&decoy_path)?;
    let plan_path = temp.path().join("ambient-git.json");
    write_simple_plan(&plan_path, "ambient-child")?;
    let trace = temp.path().join("git-trace.log");
    let trace2 = temp.path().join("git-trace2.json");
    let redirected = temp.path().join("git-stderr.log");
    let output = Command::new(BIN)
        .args(["supervise", "run"])
        .arg(&plan_path)
        .arg("--repo")
        .arg(&repo_path)
        .args(["--run-id", "ambient-git", "--runtime", "fake", "--json"])
        .env("GIT_DIR", decoy_path.join(".git"))
        .env("GIT_WORK_TREE", &decoy_path)
        .env("GIT_INDEX_FILE", temp.path().join("ambient-index"))
        .env("GIT_COMMON_DIR", decoy_path.join(".git"))
        .env("GIT_TRACE", &trace)
        .env("GIT_TRACE2_EVENT", &trace2)
        .env("GIT_REDIRECT_STDERR", &redirected)
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "core.fsmonitor")
        .env("GIT_CONFIG_VALUE_0", "unsafe-fsmonitor")
        .output()?;
    if !output.status.success() {
        anyhow::bail!(
            "ambient Git run failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["success"], true);
    assert!(!trace.exists());
    assert!(!trace2.exists());
    assert!(!redirected.exists());
    Ok(())
}

#[test]
fn security_document_describes_deterministic_fake_and_verified_codex_boundary() -> Result<()> {
    let security = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("SECURITY.md"))?;
    assert!(security.contains("Fake supervisor runtime is deterministic"));
    assert!(security.contains("does not execute `--codex-bin`"));
    assert!(security.contains("can never produce publishable acceptance"));
    assert!(security.contains("maco_external_codex"));
    assert!(security.contains("strict-offline `--version` diagnostic"));
    assert!(security.contains("sibling `trusted/` and `incoming/` roots"));
    assert!(security.contains("Checkpoint v1 is not authenticated state"));
    assert!(security.contains("fixed known-hosts set is a later integration boundary"));
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
