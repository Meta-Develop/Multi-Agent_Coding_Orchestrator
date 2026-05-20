use anyhow::{Context, Result};
use git2::{Oid, Repository, Signature};
use serde_json::Value;
use std::{fs, path::Path, process::Command};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");

#[test]
fn supervise_run_launches_two_fake_child_orchestrators_and_collects_reports() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let fake_codex = write_fake_codex(temp.path())?;
    let plan_path = temp.path().join("supervisor-plan.json");
    write_plan(
        &plan_path,
        r#"{
          "version": 1,
          "task": "coordinate two child orchestrators",
          "max_depth": 2,
          "max_child_processes": 2,
          "child_timeout_seconds": 10,
          "assignments": [
            {
              "id": "child-a",
              "assigned_paths": ["README.md"],
              "worker_assignments": [
                {"id": "worker-a", "assigned_paths": ["README.md"]}
              ]
            },
            {
              "id": "child-b",
              "assigned_paths": ["src/lib.rs"],
              "worker_assignments": [
                {"id": "worker-b", "assigned_paths": ["src/lib.rs"]}
              ]
            }
          ]
        }"#,
    )?;

    let report = run_success_json_args(&[
        "supervise",
        "run",
        plan_path.to_str().context("plan path utf8")?,
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--run-id",
        "supervise-two",
        "--codex-bin",
        fake_codex.to_str().context("fake codex path utf8")?,
        "--json",
    ])?;

    assert_eq!(report["success"], true);
    assert_eq!(report["status"], "succeeded");
    assert_eq!(
        report["orchestrator_reports"]
            .as_array()
            .context("reports")?
            .len(),
        2
    );
    assert_eq!(
        report["commands_run"].as_array().context("commands")?.len(),
        2
    );
    assert_eq!(
        report["released_claims"]
            .as_array()
            .context("claims")?
            .len(),
        2
    );
    assert!(repo_path
        .join(".maco/o2/runs/supervise-two/logs/child-a.jsonl")
        .exists());
    assert!(repo_path
        .join(".maco/o2/runs/supervise-two/reports/child-b.json")
        .exists());
    let first_command = report["commands_run"][0]["command"]
        .as_array()
        .context("first command")?;
    assert!(first_command.iter().any(|arg| arg == "--json"));
    assert!(!first_command
        .iter()
        .any(|arg| arg.as_str().is_some_and(|value| value.ends_with(".jsonl"))));
    assert_eq!(
        first_command
            .last()
            .and_then(|value| value.as_str())
            .context("prompt arg")?,
        "-"
    );
    let child_a_log =
        fs::read_to_string(repo_path.join(".maco/o2/runs/supervise-two/logs/child-a.jsonl"))
            .context("read child-a json log")?;
    assert!(child_a_log.contains(r#""event":"fake-start""#));
    assert!(child_a_log.contains(r#""prompt_from_stdin":true"#));

    let status = run_success_json_args(&[
        "supervise",
        "status",
        "supervise-two",
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--json",
    ])?;
    assert_eq!(status["final_report_exists"], true);
    assert_eq!(status["final_report"]["success"], true);

    let collected = run_success_json_args(&[
        "supervise",
        "collect",
        "supervise-two",
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--json",
    ])?;
    assert_eq!(collected["success"], true);
    assert_eq!(collected["run_id"], "supervise-two");

    Ok(())
}

#[test]
fn supervise_warn_mode_reports_same_plan_semantic_conflict() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    fs::write(repo_path.join("src/lib.rs"), "pub struct Shared;\n")
        .context("write semantic lib")?;
    let repo = Repository::open(&repo_path).context("open repo")?;
    commit_all(&repo, "semantic lib")?;
    let fake_codex = write_fake_codex(temp.path())?;
    let plan_path = temp.path().join("supervisor-plan.json");
    write_plan(
        &plan_path,
        r#"{
          "version": 1,
          "task": "coordinate semantic overlap in warn mode",
          "max_depth": 2,
          "max_child_processes": 2,
          "child_timeout_seconds": 10,
          "semantic_coordination": "warn",
          "assignments": [
            {
              "id": "child-a",
              "assigned_paths": ["README.md"],
              "semantic_symbols": ["Shared"],
              "worker_assignments": [
                {"id": "worker-a", "assigned_paths": ["README.md"]}
              ]
            },
            {
              "id": "child-b",
              "assigned_paths": ["src/lib.rs"],
              "semantic_symbols": ["Shared"],
              "worker_assignments": [
                {"id": "worker-b", "assigned_paths": ["src/lib.rs"]}
              ]
            }
          ]
        }"#,
    )?;

    let report = run_success_json_args(&[
        "supervise",
        "run",
        plan_path.to_str().context("plan path utf8")?,
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--run-id",
        "supervise-warn-semantic",
        "--codex-bin",
        fake_codex.to_str().context("fake codex path utf8")?,
        "--json",
    ])?;

    assert_eq!(report["success"], true);
    assert_eq!(
        report["released_semantic_intents"]
            .as_array()
            .context("semantic releases")?
            .len(),
        0
    );
    assert_finding(
        &report["findings"],
        "warning",
        "semantic coordination warn-mode preview",
        "src/lib.rs",
    )?;

    Ok(())
}

#[test]
fn supervise_run_failed_worker_report_marks_final_failure() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let fake_codex = write_fake_codex(temp.path())?;
    let plan_path = temp.path().join("supervisor-plan.json");
    write_plan(
        &plan_path,
        r#"{
          "version": 1,
          "task": "surface failed worker",
          "max_depth": 2,
          "max_child_processes": 1,
          "child_timeout_seconds": 10,
          "assignments": [
            {
              "id": "child-fail",
              "assigned_paths": ["README.md"],
              "worker_assignments": [
                {"id": "worker-fail", "assigned_paths": ["README.md"]}
              ]
            }
          ]
        }"#,
    )?;

    let report = run_failure_json_args(&[
        "supervise",
        "run",
        plan_path.to_str().context("plan path utf8")?,
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--run-id",
        "supervise-fail",
        "--codex-bin",
        fake_codex.to_str().context("fake codex path utf8")?,
        "--json",
    ])?;

    assert_eq!(report["success"], false);
    assert_eq!(report["status"], "failed");
    assert_eq!(report["orchestrator_reports"][0]["status"], "failed");
    assert_eq!(
        report["orchestrator_reports"][0]["worker_reports"][0]["status"],
        "failed"
    );
    assert!(report["remaining_risk"]
        .as_str()
        .context("risk")?
        .contains("failed"));

    Ok(())
}

#[test]
fn supervise_run_refuses_overlapping_path_claims_in_plan() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let fake_codex = write_fake_codex(temp.path())?;
    let plan_path = temp.path().join("supervisor-plan.json");
    write_plan(
        &plan_path,
        r#"{
          "version": 1,
          "task": "bad overlap",
          "max_depth": 2,
          "max_child_processes": 2,
          "assignments": [
            {"id": "child-a", "assigned_paths": ["README.md"]},
            {"id": "child-b", "assigned_paths": ["README.md"]}
          ]
        }"#,
    )?;

    let output = Command::new(BIN)
        .args([
            "supervise",
            "run",
            plan_path.to_str().context("plan path utf8")?,
            "--repo",
            repo_path.to_str().context("repo path utf8")?,
            "--run-id",
            "supervise-overlap",
            "--codex-bin",
            fake_codex.to_str().context("fake codex path utf8")?,
            "--json",
        ])
        .output()
        .context("run maco")?;

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("overlaps"));

    Ok(())
}

#[test]
fn supervise_run_missing_child_report_is_final_failure() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let fake_codex = write_fake_codex(temp.path())?;
    let plan_path = temp.path().join("supervisor-plan.json");
    write_plan(
        &plan_path,
        r#"{
          "version": 1,
          "task": "missing report",
          "max_depth": 2,
          "max_child_processes": 1,
          "assignments": [
            {"id": "child-missing", "assigned_paths": ["README.md"]}
          ]
        }"#,
    )?;

    let report = run_failure_json_args(&[
        "supervise",
        "run",
        plan_path.to_str().context("plan path utf8")?,
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--run-id",
        "supervise-missing",
        "--codex-bin",
        fake_codex.to_str().context("fake codex path utf8")?,
        "--json",
    ])?;

    assert_eq!(report["success"], false);
    assert_eq!(report["orchestrator_reports"][0]["status"], "missing");
    assert!(report["orchestrator_reports"][0]["findings"][0]["message"]
        .as_str()
        .context("finding")?
        .contains("missing"));

    Ok(())
}

#[test]
fn supervise_run_rejects_successful_child_that_edits_unassigned_path() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let fake_codex = write_fake_codex(temp.path())?;
    let plan_path = temp.path().join("supervisor-plan.json");
    write_plan(
        &plan_path,
        r#"{
          "version": 1,
          "task": "catch unauthorized edit",
          "max_depth": 2,
          "max_child_processes": 1,
          "child_timeout_seconds": 10,
          "assignments": [
            {"id": "child-unauthorized", "assigned_paths": ["README.md"]}
          ]
        }"#,
    )?;

    let report = run_failure_json_args(&[
        "supervise",
        "run",
        plan_path.to_str().context("plan path utf8")?,
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--run-id",
        "supervise-unauthorized",
        "--codex-bin",
        fake_codex.to_str().context("fake codex path utf8")?,
        "--json",
    ])?;

    assert_eq!(report["success"], false);
    assert_eq!(report["orchestrator_reports"][0]["status"], "failed");
    assert_eq!(report["orchestrator_reports"][0]["rejected"], true);
    assert_json_array_contains(
        &report["orchestrator_reports"][0]["files_changed"],
        "src/lib.rs",
    )?;
    assert_json_array_contains(&report["files_changed"], "src/lib.rs")?;
    assert_finding(
        &report["orchestrator_reports"][0]["findings"],
        "error",
        "outside its assigned paths",
        "src/lib.rs",
    )?;

    Ok(())
}

#[test]
fn supervise_run_includes_actual_assigned_path_when_child_omits_it() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let fake_codex = write_fake_codex(temp.path())?;
    let plan_path = temp.path().join("supervisor-plan.json");
    write_plan(
        &plan_path,
        r#"{
          "version": 1,
          "task": "detect omitted assigned path",
          "max_depth": 2,
          "max_child_processes": 1,
          "child_timeout_seconds": 10,
          "assignments": [
            {"id": "child-omits-assigned", "assigned_paths": ["README.md"]}
          ]
        }"#,
    )?;

    let report = run_success_json_args(&[
        "supervise",
        "run",
        plan_path.to_str().context("plan path utf8")?,
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--run-id",
        "supervise-omitted",
        "--codex-bin",
        fake_codex.to_str().context("fake codex path utf8")?,
        "--json",
    ])?;

    assert_eq!(report["success"], true);
    assert_json_array_contains(
        &report["orchestrator_reports"][0]["files_changed"],
        "README.md",
    )?;
    assert_json_array_contains(&report["files_changed"], "README.md")?;
    assert_finding(
        &report["orchestrator_reports"][0]["findings"],
        "warning",
        "files_changed does not match",
        "README.md",
    )?;

    Ok(())
}

#[test]
fn supervise_run_passes_when_child_only_edits_assigned_paths() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let fake_codex = write_fake_codex(temp.path())?;
    let plan_path = temp.path().join("supervisor-plan.json");
    write_plan(
        &plan_path,
        r#"{
          "version": 1,
          "task": "assigned-only edit",
          "max_depth": 2,
          "max_child_processes": 1,
          "child_timeout_seconds": 10,
          "assignments": [
            {"id": "child-assigned-only", "assigned_paths": ["README.md"]}
          ]
        }"#,
    )?;

    let report = run_success_json_args(&[
        "supervise",
        "run",
        plan_path.to_str().context("plan path utf8")?,
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--run-id",
        "supervise-assigned",
        "--codex-bin",
        fake_codex.to_str().context("fake codex path utf8")?,
        "--json",
    ])?;

    assert_eq!(report["success"], true);
    assert_eq!(report["orchestrator_reports"][0]["status"], "succeeded");
    assert_json_array_contains(
        &report["orchestrator_reports"][0]["files_changed"],
        "README.md",
    )?;
    assert_eq!(
        report["orchestrator_reports"][0]["findings"]
            .as_array()
            .context("findings")?
            .len(),
        0
    );

    Ok(())
}

#[test]
fn supervise_run_refuses_clean_stale_reused_child_worktree_before_execution() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let fake_codex = write_fake_codex(temp.path())?;
    let plan_path = temp.path().join("supervisor-plan.json");
    write_plan(
        &plan_path,
        r#"{
          "version": 1,
          "task": "reuse clean child",
          "max_depth": 2,
          "max_child_processes": 1,
          "child_timeout_seconds": 10,
          "assignments": [
            {"id": "child-clean", "assigned_paths": ["README.md"]}
          ]
        }"#,
    )?;

    let first_report = run_success_json_args(&[
        "supervise",
        "run",
        plan_path.to_str().context("plan path utf8")?,
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--run-id",
        "supervise-clean-first",
        "--codex-bin",
        fake_codex.to_str().context("fake codex path utf8")?,
        "--json",
    ])?;
    assert_eq!(first_report["success"], true);

    fs::write(repo_path.join("README.md"), "# Smoke\n\nprimary advanced\n")
        .context("advance readme")?;
    let repo = Repository::open(&repo_path).context("open repo")?;
    commit_all(&repo, "advance primary")?;

    let report = run_failure_json_args(&[
        "supervise",
        "run",
        plan_path.to_str().context("plan path utf8")?,
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--run-id",
        "supervise-clean-stale",
        "--codex-bin",
        fake_codex.to_str().context("fake codex path utf8")?,
        "--json",
    ])?;

    assert_eq!(report["success"], false);
    assert!(report["orchestrator_reports"]
        .as_array()
        .context("orchestrator reports")?
        .is_empty());
    assert!(report["findings"][0]["message"]
        .as_str()
        .context("finding message")?
        .contains("refusing to reuse stale child worktree"));
    assert!(!repo_path
        .join(".maco/o2/runs/supervise-clean-stale/logs/child-clean.jsonl")
        .exists());

    let sync_status = run_success_json_args(&[
        "sync",
        "status",
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--json",
    ])?;
    assert!(sync_status.as_array().context("sync status")?.is_empty());
    let coord_status = run_success_json_args(&[
        "coord",
        "status",
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--json",
    ])?;
    assert!(coord_status.as_array().context("coord status")?.is_empty());

    Ok(())
}

#[test]
fn supervise_run_enforces_max_depth_and_process_budget() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let fake_codex = write_fake_codex(temp.path())?;
    let bad_depth = temp.path().join("bad-depth.json");
    write_plan(
        &bad_depth,
        r#"{
          "version": 1,
          "task": "bad depth",
          "max_depth": 3,
          "max_child_processes": 1,
          "assignments": [
            {"id": "child-a", "assigned_paths": ["README.md"]}
          ]
        }"#,
    )?;
    let bad_budget = temp.path().join("bad-budget.json");
    write_plan(
        &bad_budget,
        r#"{
          "version": 1,
          "task": "bad budget",
          "max_depth": 2,
          "max_child_processes": 1,
          "assignments": [
            {"id": "child-a", "assigned_paths": ["README.md"]},
            {"id": "child-b", "assigned_paths": ["src/lib.rs"]}
          ]
        }"#,
    )?;

    let depth_output = run_failure_output(&[
        "supervise",
        "run",
        bad_depth.to_str().context("bad depth path utf8")?,
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--run-id",
        "supervise-bad-depth",
        "--codex-bin",
        fake_codex.to_str().context("fake codex path utf8")?,
        "--json",
    ])?;
    assert!(String::from_utf8_lossy(&depth_output.stderr).contains("max_depth"));

    let budget_output = run_failure_output(&[
        "supervise",
        "run",
        bad_budget.to_str().context("bad budget path utf8")?,
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--run-id",
        "supervise-bad-budget",
        "--codex-bin",
        fake_codex.to_str().context("fake codex path utf8")?,
        "--json",
    ])?;
    assert!(String::from_utf8_lossy(&budget_output.stderr).contains("max_child_processes"));

    Ok(())
}

#[test]
fn supervise_plan_json_output_is_stable() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("supervisor-plan.json");
    write_plan(
        &plan_path,
        r#"{
          "version": 1,
          "task": "normalize JSON plan",
          "max_depth": 2,
          "max_child_processes": 1,
          "assignments": [
            {
              "id": "child-a",
              "assigned_paths": ["README.md"],
              "semantic_symbols": ["Readme", "Readme"],
              "worker_assignments": [
                {"id": "worker-a", "assigned_paths": ["README.md"]}
              ]
            }
          ]
        }"#,
    )?;

    let plan = run_success_json_args(&[
        "supervise",
        "plan",
        plan_path.to_str().context("plan path utf8")?,
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--json",
    ])?;

    assert_eq!(plan["version"], 1);
    assert_eq!(plan["max_depth"], 2);
    assert_eq!(plan["semantic_coordination"], "off");
    assert_eq!(plan["assignments"][0]["role"], "child_orchestrator");
    assert_eq!(plan["assignments"][0]["semantic_symbols"][0], "Readme");
    assert_eq!(
        plan["assignments"][0]["semantic_symbols"]
            .as_array()
            .context("symbols")?
            .len(),
        1
    );

    Ok(())
}

fn assert_json_array_contains(value: &Value, expected: &str) -> Result<()> {
    let values = value.as_array().context("json array")?;
    if !values.iter().any(|value| value == expected) {
        anyhow::bail!("expected JSON array to contain {expected}: {values:?}");
    }
    Ok(())
}

fn assert_finding(
    findings: &Value,
    severity: &str,
    message_substring: &str,
    path: &str,
) -> Result<()> {
    let findings = findings.as_array().context("findings array")?;
    let found = findings.iter().any(|finding| {
        finding["severity"] == severity
            && finding["message"]
                .as_str()
                .is_some_and(|message| message.contains(message_substring))
            && finding["paths"]
                .as_array()
                .is_some_and(|paths| paths.iter().any(|value| value == path))
    });
    if !found {
        anyhow::bail!(
            "expected {severity} finding containing '{message_substring}' and path {path}: {findings:?}"
        );
    }
    Ok(())
}

fn write_fake_codex(root: &Path) -> Result<std::path::PathBuf> {
    let path = root.join("fake-codex");
    fs::write(
        &path,
        r#"#!/bin/sh
set -eu
report=
worktree=
json_seen=false
prompt_arg=
while [ "$#" -gt 0 ]; do
  case "$1" in
    exec)
      shift
      ;;
    --json)
      json_seen=true
      shift
      ;;
    --output-last-message)
      report="$2"
      shift 2
      ;;
    --output-schema|--sandbox|-c)
      shift 2
      ;;
    --cd)
      worktree="$2"
      shift 2
      ;;
    -*)
      prompt_arg="$1"
      shift
      ;;
    *)
      prompt_arg="$1"
      shift
      ;;
  esac
done
if [ "$json_seen" != "true" ]; then
  echo "missing --json flag" >&2
  exit 64
fi
if [ "$prompt_arg" != "-" ]; then
  echo "expected prompt from stdin marker '-'" >&2
  exit 64
fi
prompt_body="$(cat)"
case "$prompt_body" in
  *"Supervisor task:"*)
    prompt_from_stdin=true
    ;;
  *)
    prompt_from_stdin=false
    ;;
esac
mkdir -p "$(dirname "$report")"
printf '{"event":"fake-start","worktree":"%s","prompt_from_stdin":%s}\n' "$worktree" "$prompt_from_stdin"
name="$(basename "$report" .json)"
edit=true
files_changed_json=
case "$name" in
  child-b)
    path="src/lib.rs"
    edit_path="src/lib.rs"
    worker="worker-b"
    ;;
  child-fail)
    path="README.md"
    edit_path="README.md"
    worker="worker-fail"
    ;;
  child-unauthorized)
    path="README.md"
    edit_path="src/lib.rs"
    worker="worker-unauthorized"
    ;;
  child-omits-assigned)
    path="README.md"
    edit_path="README.md"
    worker="worker-omits-assigned"
    files_changed_json='[]'
    ;;
  child-assigned-only)
    path="README.md"
    edit_path="README.md"
    worker="worker-assigned-only"
    ;;
  child-clean)
    path="README.md"
    edit_path="README.md"
    worker="worker-clean"
    edit=false
    files_changed_json='[]'
    ;;
  *)
    path="README.md"
    edit_path="README.md"
    worker="worker-a"
    ;;
esac
if [ "$name" = "child-missing" ]; then
  exit 0
fi
if [ -z "$files_changed_json" ]; then
  files_changed_json='["'"$path"'"]'
fi
if [ "$edit" = "true" ]; then
  mkdir -p "$(dirname "$worktree/$edit_path")"
  printf '\nfake change from %s\n' "$name" >> "$worktree/$edit_path"
fi
if [ "$name" = "child-fail" ]; then
  status="failed"
  accepted="false"
  rejected="true"
  risk="worker failed validation"
  next="fix worker output"
else
  status="succeeded"
  accepted="true"
  rejected="false"
  risk="none"
  next="review diff"
fi
cat > "$report" <<JSON
{
  "id": "$name",
  "role": "child_orchestrator",
  "assigned_paths": ["$path"],
  "semantic_symbols": [],
  "semantic_modules": [],
  "commands_run": [],
  "files_changed": $files_changed_json,
  "validation_results": [
    {"name": "fake validation", "status": "$status", "command": [], "message": null}
  ],
  "findings": [],
  "worker_reports": [
    {
      "id": "$worker",
      "role": "worker",
      "assigned_paths": ["$path"],
      "semantic_symbols": [],
      "semantic_modules": [],
      "commands_run": [],
      "files_changed": $files_changed_json,
      "validation_results": [
        {"name": "fake worker validation", "status": "$status", "command": [], "message": null}
      ],
      "findings": [],
      "accepted": $accepted,
      "rejected": $rejected,
      "status": "$status",
      "remaining_risk": "$risk",
      "next_safe_action": "$next"
    }
  ],
  "accepted": $accepted,
  "rejected": $rejected,
  "status": "$status",
  "remaining_risk": "$risk",
  "next_safe_action": "$next"
}
JSON
"#,
    )
    .context("write fake codex")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .context("chmod fake codex")?;
    }
    Ok(path)
}

fn write_plan(path: &Path, contents: &str) -> Result<()> {
    fs::write(path, contents).with_context(|| format!("write plan {}", path.display()))
}

fn run_success_json_args(args: &[&str]) -> Result<Value> {
    let output = Command::new(BIN).args(args).output().context("run maco")?;
    if !output.status.success() {
        anyhow::bail!(
            "maco command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).context("parse json")
}

fn run_failure_json_args(args: &[&str]) -> Result<Value> {
    let output = run_failure_output(args)?;
    serde_json::from_slice(&output.stdout).context("parse failure json")
}

fn run_failure_output(args: &[&str]) -> Result<std::process::Output> {
    let output = Command::new(BIN).args(args).output().context("run maco")?;
    if output.status.success() {
        anyhow::bail!("maco command unexpectedly succeeded");
    }
    Ok(output)
}

fn create_committed_repo(root: &Path) -> Result<std::path::PathBuf> {
    let repo_path = root.join("repo");
    let output = Command::new(BIN)
        .args([
            "init",
            "--repo",
            repo_path.to_str().context("repo path utf8")?,
            "--json",
        ])
        .output()
        .context("init repo")?;
    if !output.status.success() {
        anyhow::bail!("init failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    fs::create_dir_all(repo_path.join("src")).context("create src")?;
    fs::write(repo_path.join(".gitignore"), ".maco/\n").context("write gitignore")?;
    fs::write(repo_path.join("README.md"), "# Smoke\n").context("write readme")?;
    fs::write(
        repo_path.join("src/lib.rs"),
        "pub fn ok() -> bool { true }\n",
    )
    .context("write lib")?;
    let repo = Repository::open(&repo_path).context("open repo")?;
    commit_all(&repo, "initial commit")?;

    Ok(repo_path)
}

fn commit_all(repo: &Repository, message: &str) -> Result<Oid> {
    let mut index = repo.index().context("open index")?;
    index
        .add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)
        .context("add all")?;
    index.write().context("write index")?;
    let tree_id = index.write_tree().context("write tree")?;
    let tree = repo.find_tree(tree_id).context("find tree")?;
    let signature =
        Signature::now("maco test", "maco-test@example.invalid").context("signature")?;
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
