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
const SUPERVISE_RUN_UNSUPPORTED: &str =
    "supervisor assignment creation is temporarily unsupported because managed worktree creation requires a capability-bound repository cleanliness input";

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

    let stderr = run_failure_stderr(&[
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
    assert!(stderr.contains(SUPERVISE_RUN_UNSUPPORTED));
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
    assert!(!repo_path
        .join(".maco/o2/runs/deterministic-fake-invariant")
        .exists());
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

    let stderr = run_failure_stderr(&[
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
    assert!(stderr.contains(SUPERVISE_RUN_UNSUPPORTED));
    let final_report =
        repo_path.join(".maco/o2/runs/deterministic-shape/reports/supervisor-final.json");
    assert!(!final_report.exists());
    let run_root = repo_path.join(".maco/o2/runs/deterministic-shape");
    assert!(!run_root.exists());

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
            stderr.contains("process-tree ownership")
                || stderr.contains("containment guardian")
                || stderr.contains(SUPERVISE_RUN_UNSUPPORTED),
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
fn supervise_plan_normalizes_aliases_and_rejects_top_level_scope_conflicts() -> Result<()> {
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
    let overlap_error = run_failure_stderr(&[
        "supervise",
        "plan",
        path_str(&overlap)?,
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert!(
        overlap_error.contains(
            "assignments 'child-a' path 'src' and 'child-b' path 'src/lib.rs' overlap after normalization"
        ),
        "unexpected overlap error: {overlap_error}"
    );
    Ok(())
}

#[test]
fn supervise_plan_from_goal_emits_disjoint_claims_semantics_and_traceability() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let goal_path = temp.path().join("goal.md");
    fs::write(
        &goal_path,
        "Coordinate independent child orchestrators.\n\
         - Update README.\n\
         - Clarify documentation in README.\n\
         - Update the ok function in src/lib.rs.\n\
         - Explain the unmatched frobnicator.\n",
    )?;

    let plan = run_success_json(&[
        "supervise",
        "plan",
        "--from-goal",
        path_str(&goal_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;

    assert_eq!(plan["version"], 1);
    assert_eq!(plan["max_depth"], 2);
    assert_eq!(plan["max_child_assignments"], 4);
    assert!(plan.get("task_file").is_none());
    assert_eq!(
        plan["spec_fragment_ids"],
        serde_json::json!([
            "fragment-001",
            "fragment-002",
            "fragment-003",
            "fragment-004",
            "fragment-005"
        ])
    );

    let assignments = plan["assignments"].as_array().context("assignments")?;
    assert_eq!(assignments.len(), 2);
    assert_eq!(assignments[0]["id"], "assignment-001");
    assert_eq!(assignments[0]["role"], "child_orchestrator");
    assert_eq!(
        assignments[0]["assigned_paths"],
        serde_json::json!(["README.md"])
    );
    assert_eq!(
        assignments[0]["spec_fragment_ids"],
        serde_json::json!(["fragment-002", "fragment-003"])
    );
    assert_eq!(
        assignments[0]["worker_assignments"][0]["id"],
        "assignment-001-worker"
    );
    assert_eq!(
        assignments[0]["worker_assignments"][0]["assigned_paths"],
        serde_json::json!(["README.md"])
    );

    assert_eq!(assignments[1]["id"], "assignment-002");
    assert_eq!(
        assignments[1]["assigned_paths"],
        serde_json::json!(["src/lib.rs"])
    );
    assert_eq!(
        assignments[1]["semantic_symbols"],
        serde_json::json!(["crate::ok"])
    );
    assert_eq!(
        assignments[1]["spec_fragment_ids"],
        serde_json::json!(["fragment-004"])
    );
    assert_eq!(
        assignments[1]["worker_assignments"][0]["semantic_symbols"],
        serde_json::json!(["crate::ok"])
    );

    assert_eq!(
        plan["assignment_schedule"],
        serde_json::json!([
            {
                "assignment_id": "assignment-001",
                "depth": 2,
                "flattened_index": 0
            },
            {
                "assignment_id": "assignment-002",
                "depth": 2,
                "flattened_index": 1
            }
        ])
    );
    assert_eq!(
        plan["coverage_gaps"]
            .as_array()
            .context("coverage gaps")?
            .iter()
            .map(|gap| gap["spec_fragment_id"].as_str().context("gap fragment"))
            .collect::<Result<Vec<_>>>()?,
        vec!["fragment-001", "fragment-005"]
    );
    Ok(())
}

#[test]
fn supervise_plan_plain_text_without_actionable_workstreams_is_an_error() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let task_path = temp.path().join("empty-plan-task.txt");
    fs::write(&task_path, "Explain the unmatched frobnicator.\n")?;

    let error = run_failure_stderr(&[
        "supervise",
        "plan",
        path_str(&task_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert!(error.contains("goal/spec produced no actionable workstreams"));
    assert!(error.contains("repository path, Rust module, or Rust symbol"));
    assert!(!repo_path.join(".maco/o2").exists());
    Ok(())
}

#[test]
fn supervise_plan_normalizes_typed_decomposition_and_defaults_legacy_workers() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("typed-decomposition.json");
    fs::write(
        &plan_path,
        br#"{
          "version": 1,
          "task": "typed decomposition",
          "assignments": [{
            "id": "child-a",
            "assigned_paths": ["src"],
            "worker_assignments": [
              {"id": "ordinary-worker", "assigned_paths": ["src/lib.rs"]},
              {
                "id": "decomposition-worker",
                "kind": "megafile_decomposition",
                "target_path": "src/./supervise.rs",
                "assigned_paths": ["src/supervise.rs"]
              }
            ]
          }]
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
    assert_eq!(
        plan["assignments"][0]["worker_assignments"][0]["kind"],
        "ordinary"
    );
    assert!(plan["assignments"][0]["worker_assignments"][0]
        .get("target_path")
        .is_none());
    assert_eq!(
        plan["assignments"][0]["worker_assignments"][1]["kind"],
        "megafile_decomposition"
    );
    assert_eq!(
        plan["assignments"][0]["worker_assignments"][1]["target_path"],
        "src/supervise.rs"
    );
    Ok(())
}

#[test]
fn supervise_plan_fails_closed_on_invalid_typed_decomposition_values() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    for (name, worker, expected) in [
        (
            "unknown-kind",
            serde_json::json!({
                "id": "worker-a",
                "kind": "decompose_maybe",
                "assigned_paths": ["src/lib.rs"]
            }),
            "kind/target_path is invalid",
        ),
        (
            "ordinary-target",
            serde_json::json!({
                "id": "worker-a",
                "kind": "ordinary",
                "target_path": "src/lib.rs",
                "assigned_paths": ["src/lib.rs"]
            }),
            "ordinary worker assignment 'worker-a' must not declare target_path",
        ),
        (
            "missing-target",
            serde_json::json!({
                "id": "worker-a",
                "kind": "megafile_decomposition",
                "assigned_paths": ["src/lib.rs"]
            }),
            "must declare target_path",
        ),
        (
            "outside-target",
            serde_json::json!({
                "id": "worker-a",
                "kind": "megafile_decomposition",
                "target_path": "README.md",
                "assigned_paths": ["src/lib.rs"]
            }),
            "is outside assigned_paths",
        ),
    ] {
        let plan_path = temp.path().join(format!("{name}.json"));
        fs::write(
            &plan_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": 1,
                "task": "invalid typed decomposition",
                "assignments": [{
                    "id": "child-a",
                    "assigned_paths": ["README.md", "src"],
                    "worker_assignments": [worker]
                }]
            }))?,
        )?;
        let stderr = run_failure_stderr(&[
            "supervise",
            "plan",
            path_str(&plan_path)?,
            "--repo",
            path_str(&repo_path)?,
            "--json",
        ])?;
        assert!(
            stderr.contains(expected),
            "{name} did not fail with {expected:?}: {stderr}"
        );
    }
    Ok(())
}

#[test]
fn supervise_plan_still_rejects_overlapping_worker_siblings() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let overlap = temp.path().join("worker-overlap.json");
    fs::write(
        &overlap,
        br#"{
          "version": 1,
          "task": "worker overlap",
          "assignments": [{
            "id": "child-a",
            "assigned_paths": ["src"],
            "worker_assignments": [
              {"id": "worker-a", "assigned_paths": ["src/lib.rs"]},
              {"id": "worker-b", "assigned_paths": ["src"]}
            ]
          }]
        }"#,
    )?;
    let output = Command::new(BIN)
        .args([
            "supervise",
            "plan",
            path_str(&overlap)?,
            "--repo",
            path_str(&repo_path)?,
            "--json",
        ])
        .output()?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("worker 'worker-b'") && stderr.contains("overlaps worker 'worker-a'"));
    Ok(())
}

#[test]
fn supervise_run_rejects_zero_bound_before_reserving_state_and_accepts_one() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("bounded-run.json");
    write_simple_plan(&plan_path, "bounded-child")?;

    let zero_stderr = run_failure_stderr(&[
        "supervise",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "bounded-zero",
        "--runtime",
        "fake",
        "--max-concurrent-children",
        "0",
        "--json",
    ])?;
    assert!(zero_stderr.contains("--max-concurrent-children must be at least 1"));
    assert!(!repo_path.join(".maco/o2/runs/bounded-zero").exists());
    assert!(!temp
        .path()
        .join(".maco/worktrees/repo/bounded-child")
        .exists());
    let repo = Repository::open(&repo_path)?;
    assert!(repo
        .find_branch("maco/bounded-child", git2::BranchType::Local)
        .is_err());
    let claims = run_success_json(&["sync", "status", "--repo", path_str(&repo_path)?, "--json"])?;
    assert!(claims.as_array().context("claim status")?.is_empty());

    let one_stderr = run_failure_stderr(&[
        "supervise",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "bounded-one",
        "--runtime",
        "fake",
        "--max-concurrent-children",
        "1",
        "--json",
    ])?;
    assert!(one_stderr.contains(SUPERVISE_RUN_UNSUPPORTED));
    assert!(!repo_path.join(".maco/o2/runs/bounded-one").exists());
    Ok(())
}

#[test]
fn supervise_run_accepts_concurrent_bound_before_fake_runtime_safety_refusal() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("concurrent-run.json");
    write_simple_plan(&plan_path, "concurrent-child")?;
    let stderr = run_failure_stderr(&[
        "supervise",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "bounded-two",
        "--runtime",
        "fake",
        "--max-concurrent-children",
        "2",
        "--json",
    ])?;
    assert!(stderr.contains(SUPERVISE_RUN_UNSUPPORTED));
    assert!(!repo_path.join(".maco/o2/runs/bounded-two").exists());
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
    let first = run_failure_stderr(&args)?;
    assert!(first.contains(SUPERVISE_RUN_UNSUPPORTED));
    let second = run_failure_stderr(&args)?;
    assert!(second.contains(SUPERVISE_RUN_UNSUPPORTED));

    let status = run_success_json(&[
        "supervise",
        "status",
        "artifact-run",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(status["final_report_exists"], false);
    assert_eq!(status["repo"], ".");
    assert_eq!(status["run_dir"], ".maco/o2/runs/artifact-run");
    assert!(status["final_report"].is_null());
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
    let stderr = run_failure_stderr(&[
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
    assert!(stderr.contains(SUPERVISE_RUN_UNSUPPORTED));
    let prompt = fs::read_to_string(
        repo_path.join(".maco/o2/runs/prompt-contract/assignments/prompt-child.prompt.md"),
    );
    assert!(prompt.is_err());
    assert!(!repo_path.join("must-not-run").exists());
    Ok(())
}

#[test]
fn supervise_generates_run_ids_refuses_reuse_and_lists_artifacts() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("generated-id.json");
    write_simple_plan(&plan_path, "generated-child")?;

    let stderr = run_failure_stderr(&[
        "supervise",
        "run",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--runtime",
        "fake",
        "--json",
    ])?;
    assert!(stderr.contains(SUPERVISE_RUN_UNSUPPORTED));

    let listed = run_success_json(&[
        "supervise",
        "artifacts",
        "list",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert!(listed["runs"].as_array().context("runs")?.is_empty());
    Ok(())
}

#[test]
fn supervise_prune_deletes_only_finalized_old_runs() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;

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
    assert_eq!(prune["delete_candidate_count"], 0);
    assert_eq!(prune["deleted_count"], 0);
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
    assert!(runs.is_empty());
    Ok(())
}

#[test]
fn supervise_plan_rejects_cross_assignment_semantic_conflicts_even_in_warn_mode() -> Result<()> {
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

    let error = run_failure_stderr(&[
        "supervise",
        "plan",
        path_str(&plan_path)?,
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert!(
        error.contains(
            "assignment 'child-a' and assignment 'child-b' overlap semantic symbol 'Shared' after normalization"
        ),
        "unexpected semantic conflict error: {error}"
    );
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

    let stderr = run_failure_stderr(&[
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
    assert!(stderr.contains(SUPERVISE_RUN_UNSUPPORTED));
    let claims = run_success_json(&["sync", "status", "--repo", path_str(&repo_path)?, "--json"])?;
    assert!(claims
        .as_array()
        .context("claims")?
        .iter()
        .any(|claim| claim["agent_id"] == "stale-agent"));
    Ok(())
}

#[test]
fn supervise_run_refuses_clean_stale_reused_child_worktree_before_execution() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("stale-worktree.json");
    write_simple_plan(&plan_path, "child-clean")?;
    let first = run_failure_stderr(&[
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
    assert!(first.contains(SUPERVISE_RUN_UNSUPPORTED));
    fs::write(repo_path.join("README.md"), "# advanced\n")?;
    let repo = Repository::open(&repo_path)?;
    commit_all(&repo, "advance primary")?;

    let stderr = run_failure_stderr(&[
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
    assert!(stderr.contains(SUPERVISE_RUN_UNSUPPORTED));
    assert!(!repo_path
        .join(".maco/o2/runs/clean-stale/evidence/incoming/child-clean.json")
        .exists());
    assert!(!repo_path.join(".maco/o2/runs/clean-stale").exists());
    Ok(())
}

#[test]
fn supervise_plan_enforces_depth_assignment_and_retry_bounds() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let cases = [
        (
            "bad-depth",
            serde_json::json!({
                "version": 1,
                "task": "bad depth",
                "max_depth": 33,
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
                "plan",
                path_str(&plan_path)?,
                "--repo",
                path_str(&repo_path)?,
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
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains(SUPERVISE_RUN_UNSUPPORTED));
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
    assert!(security.contains("Version 1 and version 2 checkpoints are unauthenticated"));
    assert!(security.contains("legacy formats and are refused for resume"));
    assert!(security.contains("fixed known-hosts set is a later integration boundary")
        || security.contains("Destination allowlisting against a fixed known-hosts set is a later integration boundary"));
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

fn run_failure_stderr(args: &[&str]) -> Result<String> {
    let output = Command::new(BIN).args(args).output().context("run maco")?;
    if output.status.success() {
        anyhow::bail!("maco command unexpectedly succeeded");
    }
    Ok(String::from_utf8_lossy(&output.stderr).into_owned())
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
