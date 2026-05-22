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
    assert!(command_contains_sequence(
        first_command,
        &["--enable", "multi_agent"]
    ));
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
    assert!(child_a_log.contains(r#""multi_agent":true"#));

    let child_a_prompt = fs::read_to_string(
        repo_path.join(".maco/o2/runs/supervise-two/assignments/child-a.prompt.md"),
    )
    .context("read child-a prompt")?;
    assert!(child_a_prompt.starts_with("ROLE: O1_CHILD_ORCHESTRATOR\n"));
    assert!(child_a_prompt.contains("ROLE: TERMINAL_WORKER\n"));
    assert!(child_a_prompt.contains("First, read and follow AGENTS.md"));
    assert!(child_a_prompt.contains(".agents/skills/agent-orchestration/SKILL.md"));
    assert!(child_a_prompt.contains(".agents/docs/AGENT_ORCHESTRATION.md"));
    assert!(child_a_prompt.contains("Use Codex native SubAgent/delegated-worker mechanisms"));
    assert!(child_a_prompt.contains("If no delegated-worker mechanism is available"));
    assert!(child_a_prompt.contains("exact blocked worker task"));
    assert!(child_a_prompt
        .contains("O2 supervisor -> O1 child orchestrator -> terminal worker/researcher"));
    assert!(child_a_prompt.contains("You must not spawn, impersonate, or take over a peer O2"));
    assert!(child_a_prompt.contains("top O2/supervisor may launch peer O2 supervisors"));
    assert!(child_a_prompt.contains("Report such escalation candidates"));
    assert!(child_a_prompt.contains("must not launch further workers"));
    assert!(child_a_prompt.contains("worker-report.schema.json"));
    assert!(
        child_a_prompt.contains("Return your OrchestratorReviewReport JSON as your final response")
    );
    assert!(child_a_prompt.contains("Codex CLI --output-last-message records your final response"));
    assert!(child_a_prompt.contains("MACO collection target"));
    assert!(!child_a_prompt.contains("Write your final OrchestratorReviewReport as JSON to:"));
    assert!(child_a_prompt.contains("Return WorkerReport JSON in your final response"));
    assert!(child_a_prompt.contains("\"no_further_delegation\": true"));
    assert!(child_a_prompt
        .contains("Only write a report file when an explicit report_path is assigned"));
    assert!(child_a_prompt.contains("If the explicit report path is <none>"));
    assert!(child_a_prompt.contains("only return WorkerReport JSON in your final response"));
    assert!(!child_a_prompt.contains("The only allowed depth"));
    let worker_schema_line = child_a_prompt
        .lines()
        .find(|line| line.contains("Use the worker report schema path:"))
        .context("worker schema line")?;
    assert!(worker_schema_line.contains("worker-report.schema.json"));
    assert!(!worker_schema_line.contains("orchestrator-review-report.schema.json"));
    let worker_schema: Value = serde_json::from_str(
        &fs::read_to_string(
            repo_path.join(".maco/o2/runs/supervise-two/schemas/worker-report.schema.json"),
        )
        .context("read worker schema")?,
    )
    .context("parse worker schema")?;
    assert_object_schema_sealed(&worker_schema, "worker schema")?;
    assert_all_array_schemas_define_items(&worker_schema, "worker schema")?;
    assert_string_const_schema_property(&worker_schema, "worker schema", "role", "worker")?;
    assert_boolean_const_schema_property(
        &worker_schema,
        "worker schema",
        "no_further_delegation",
        true,
    )?;
    assert_string_enum_schema_property(
        &worker_schema,
        "worker schema",
        "status",
        &["pending", "succeeded", "failed", "rejected", "missing"],
    )?;
    assert_report_array_item_schemas(&worker_schema, "worker schema")?;
    let orchestrator_schema: Value = serde_json::from_str(
        &fs::read_to_string(
            repo_path
                .join(".maco/o2/runs/supervise-two/schemas/orchestrator-review-report.schema.json"),
        )
        .context("read orchestrator schema")?,
    )
    .context("parse orchestrator schema")?;
    assert_object_schema_sealed(&orchestrator_schema, "orchestrator schema")?;
    assert_all_array_schemas_define_items(&orchestrator_schema, "orchestrator schema")?;
    assert_string_const_schema_property(
        &orchestrator_schema,
        "orchestrator schema",
        "role",
        "child_orchestrator",
    )?;
    assert_string_enum_schema_property(
        &orchestrator_schema,
        "orchestrator schema",
        "status",
        &["pending", "succeeded", "failed", "rejected", "missing"],
    )?;
    assert_report_array_item_schemas(&orchestrator_schema, "orchestrator schema")?;
    let nested_worker_schema = &orchestrator_schema["properties"]["worker_reports"]["items"];
    assert_object_schema_sealed(nested_worker_schema, "nested worker schema")?;
    assert_string_const_schema_property(
        nested_worker_schema,
        "nested worker schema",
        "role",
        "worker",
    )?;
    assert_boolean_const_schema_property(
        nested_worker_schema,
        "nested worker schema",
        "no_further_delegation",
        true,
    )?;
    assert_string_enum_schema_property(
        nested_worker_schema,
        "nested worker schema",
        "status",
        &["pending", "succeeded", "failed", "rejected", "missing"],
    )?;
    assert_report_array_item_schemas(nested_worker_schema, "nested worker schema")?;
    assert!(orchestrator_schema["properties"]
        .as_object()
        .context("orchestrator properties")?
        .contains_key("worker_reports"));

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
fn supervise_generates_run_ids_refuses_reuse_and_lists_artifacts() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let fake_codex = write_fake_codex(temp.path())?;
    let plan_path = temp.path().join("supervisor-plan.json");
    write_plan(
        &plan_path,
        r#"{
          "version": 1,
          "task": "generated supervise id",
          "max_depth": 2,
          "max_child_assignments": 1,
          "child_timeout_seconds": 10,
          "assignments": [
            {"id": "child-generated", "assigned_paths": ["README.md"]}
          ]
        }"#,
    )?;

    let report = run_success_json_args(&[
        "supervise",
        "run",
        plan_path.to_str().context("plan path utf8")?,
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--codex-bin",
        fake_codex.to_str().context("fake codex path utf8")?,
        "--json",
    ])?;
    let run_id = report["run_id"].as_str().context("generated run id")?;
    assert!(run_id.starts_with("o2-"));
    assert!(repo_path
        .join(".maco/o2/runs")
        .join(run_id)
        .join("reports/supervisor-final.json")
        .exists());

    let listed = run_success_json_args(&[
        "supervise",
        "artifacts",
        "list",
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--json",
    ])?;
    assert_eq!(listed["runs"][0]["run_id"], run_id);
    assert_eq!(listed["runs"][0]["final_report_status"], "succeeded");
    assert_eq!(listed["runs"][0]["final_report_success"], true);

    let refused = run_failure_json_args(&[
        "supervise",
        "run",
        plan_path.to_str().context("plan path utf8")?,
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--run-id",
        run_id,
        "--codex-bin",
        fake_codex.to_str().context("fake codex path utf8")?,
        "--json",
    ])?;
    assert_eq!(refused["status"], "refused");
    assert!(refused["message"]
        .as_str()
        .context("reuse message")?
        .contains("already exists"));

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
fn supervise_run_rejects_worker_report_that_delegated_further() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let fake_codex = write_fake_codex(temp.path())?;
    let plan_path = temp.path().join("supervisor-plan.json");
    write_plan(
        &plan_path,
        r#"{
          "version": 1,
          "task": "reject non-terminal worker",
          "max_depth": 2,
          "max_child_processes": 1,
          "child_timeout_seconds": 10,
          "assignments": [
            {
              "id": "child-delegated",
              "assigned_paths": ["README.md"],
              "worker_assignments": [
                {"id": "worker-delegated", "assigned_paths": ["README.md"]}
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
        "supervise-delegated-worker",
        "--codex-bin",
        fake_codex.to_str().context("fake codex path utf8")?,
        "--json",
    ])?;

    assert_eq!(report["success"], false);
    let child_report = &report["orchestrator_reports"][0];
    assert_eq!(child_report["status"], "failed");
    assert_eq!(child_report["accepted"], false);
    assert_eq!(child_report["rejected"], true);
    let worker_report = &child_report["worker_reports"][0];
    assert_eq!(worker_report["status"], "failed");
    assert_eq!(worker_report["accepted"], false);
    assert_eq!(worker_report["rejected"], true);
    assert_eq!(worker_report["no_further_delegation"], false);
    assert_json_findings_contain_message(
        &child_report["findings"],
        "without terminal no-delegation attestation",
    )?;
    assert_json_findings_contain_message(
        &worker_report["findings"],
        "worker report indicates further delegation",
    )?;
    assert!(report["remaining_risk"]
        .as_str()
        .context("risk")?
        .contains("failed"));

    Ok(())
}

#[test]
fn supervise_run_rejects_missing_worker_reports_for_assigned_workers() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let fake_codex = write_fake_codex(temp.path())?;
    let plan_path = temp.path().join("supervisor-plan.json");
    write_plan(
        &plan_path,
        r#"{
          "version": 1,
          "task": "reject missing worker reports",
          "max_depth": 2,
          "max_child_processes": 1,
          "child_timeout_seconds": 10,
          "assignments": [
            {
              "id": "child-omits-workers",
              "assigned_paths": ["README.md"],
              "worker_assignments": [
                {"id": "worker-omitted", "assigned_paths": ["README.md"]}
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
        "supervise-missing-worker-reports",
        "--codex-bin",
        fake_codex.to_str().context("fake codex path utf8")?,
        "--json",
    ])?;

    assert_eq!(report["success"], false);
    assert_eq!(report["status"], "failed");
    let child_report = &report["orchestrator_reports"][0];
    assert_eq!(child_report["status"], "failed");
    assert_eq!(child_report["accepted"], false);
    assert_eq!(child_report["rejected"], true);
    assert_eq!(
        child_report["worker_reports"]
            .as_array()
            .context("worker reports")?
            .len(),
        0
    );
    assert_json_findings_contain_message(
        &child_report["findings"],
        "omitted required worker reports for assignment worker IDs: worker-omitted",
    )?;
    assert!(child_report["remaining_risk"]
        .as_str()
        .context("child risk")?
        .contains("missing terminal no-delegation attestations"));

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
    assert!(String::from_utf8_lossy(&budget_output.stderr).contains("max_child_assignments"));

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
    assert_eq!(plan["max_child_assignments"], 1);
    assert_eq!(plan.get("max_child_processes"), None);
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

#[test]
fn supervise_plan_accepts_new_child_assignment_name_and_legacy_alias() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let new_name = temp.path().join("new-name.json");
    write_plan(
        &new_name,
        r#"{
          "version": 1,
          "task": "new child assignment name",
          "max_depth": 2,
          "max_child_assignments": 1,
          "assignments": [
            {"id": "child-a", "assigned_paths": ["README.md"]}
          ]
        }"#,
    )?;
    let legacy_alias = temp.path().join("legacy-alias.json");
    write_plan(
        &legacy_alias,
        r#"{
          "version": 1,
          "task": "legacy child process alias",
          "max_depth": 2,
          "max_child_processes": 1,
          "assignments": [
            {"id": "child-a", "assigned_paths": ["README.md"]}
          ]
        }"#,
    )?;

    let new_plan = run_success_json_args(&[
        "supervise",
        "plan",
        new_name.to_str().context("new name path utf8")?,
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--json",
    ])?;
    let legacy_plan = run_success_json_args(&[
        "supervise",
        "plan",
        legacy_alias.to_str().context("legacy path utf8")?,
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--json",
    ])?;

    assert_eq!(new_plan["max_child_assignments"], 1);
    assert_eq!(legacy_plan["max_child_assignments"], 1);
    assert_eq!(new_plan.get("max_child_processes"), None);
    assert_eq!(legacy_plan.get("max_child_processes"), None);

    Ok(())
}

#[test]
fn supervise_readme_documents_o2_o1_contract_without_worker_fallback() -> Result<()> {
    let readme = fs::read_to_string("README.md").context("read README")?;

    assert!(readme.contains("O2 supervisor -> O1 child orchestrator -> terminal worker/researcher"));
    assert!(readme.contains("peer O2 supervisors"));
    assert!(readme.contains("report peer-O2 escalation"));
    assert!(readme.contains("report escalation"));
    assert!(!readme.contains("command-backed worker execution is fallback behavior"));

    Ok(())
}

fn assert_json_array_contains(value: &Value, expected: &str) -> Result<()> {
    let values = value.as_array().context("json array")?;
    if !values.iter().any(|value| value == expected) {
        anyhow::bail!("expected JSON array to contain {expected}: {values:?}");
    }
    Ok(())
}

fn assert_json_findings_contain_message(value: &Value, expected: &str) -> Result<()> {
    let findings = value.as_array().context("findings array")?;
    if findings.iter().any(|finding| {
        finding["message"]
            .as_str()
            .is_some_and(|message| message.contains(expected))
    }) {
        return Ok(());
    }
    anyhow::bail!("expected finding containing '{expected}': {findings:?}");
}

fn command_contains_sequence(command: &[Value], expected: &[&str]) -> bool {
    command.windows(expected.len()).any(|window| {
        window
            .iter()
            .zip(expected)
            .all(|(value, expected)| value.as_str() == Some(*expected))
    })
}

fn assert_report_array_item_schemas(schema: &Value, label: &str) -> Result<()> {
    let command_items = assert_array_property_has_items(schema, label, "commands_run")?;
    assert_object_schema_sealed(command_items, &format!("{label}.commands_run items"))?;
    assert_schema_required_contains(
        command_items,
        &format!("{label}.commands_run items"),
        &[
            "command",
            "cwd",
            "exit_code",
            "status",
            "timeout_seconds",
            "duration_ms",
            "timed_out",
            "stdout",
            "stderr",
            "error",
        ],
    )?;
    let command = schema_property(
        command_items,
        &format!("{label}.commands_run items"),
        "command",
    )?;
    assert_schema_array_has_items(command, &format!("{label}.commands_run items.command"))?;

    let validation_items = assert_array_property_has_items(schema, label, "validation_results")?;
    assert_object_schema_sealed(
        validation_items,
        &format!("{label}.validation_results items"),
    )?;
    assert_schema_required_contains(
        validation_items,
        &format!("{label}.validation_results items"),
        &["name", "status", "command", "message"],
    )?;
    let validation_command = schema_property(
        validation_items,
        &format!("{label}.validation_results items"),
        "command",
    )?;
    assert_schema_array_has_items(
        validation_command,
        &format!("{label}.validation_results items.command"),
    )?;

    let finding_items = assert_array_property_has_items(schema, label, "findings")?;
    assert_object_schema_sealed(finding_items, &format!("{label}.findings items"))?;
    assert_schema_required_contains(
        finding_items,
        &format!("{label}.findings items"),
        &["severity", "message", "paths"],
    )?;
    let paths = schema_property(finding_items, &format!("{label}.findings items"), "paths")?;
    assert_schema_array_has_items(paths, &format!("{label}.findings items.paths"))?;

    Ok(())
}

fn assert_all_array_schemas_define_items(schema: &Value, label: &str) -> Result<()> {
    match schema {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("array") {
                assert_schema_array_has_items(schema, label)?;
            }
            for (key, value) in object {
                assert_all_array_schemas_define_items(value, &format!("{label}.{key}"))?;
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                assert_all_array_schemas_define_items(value, &format!("{label}[{index}]"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn assert_array_property_has_items<'a>(
    schema: &'a Value,
    label: &str,
    property: &str,
) -> Result<&'a Value> {
    let property_schema = schema_property(schema, label, property)?;
    assert_schema_array_has_items(property_schema, &format!("{label}.{property}"))
}

fn assert_schema_array_has_items<'a>(schema: &'a Value, label: &str) -> Result<&'a Value> {
    assert_schema_type(schema, label, "array")?;
    schema
        .get("items")
        .with_context(|| format!("{label} array schema must define items: {schema:?}"))
}

fn assert_object_schema_sealed(schema: &Value, label: &str) -> Result<()> {
    assert_schema_type(schema, label, "object")?;
    if schema.get("additionalProperties").and_then(Value::as_bool) != Some(false) {
        anyhow::bail!("{label} must set additionalProperties to false: {schema:?}");
    }
    Ok(())
}

fn assert_schema_required_contains(
    schema: &Value,
    label: &str,
    expected_required: &[&str],
) -> Result<()> {
    let required = schema
        .get("required")
        .and_then(Value::as_array)
        .with_context(|| format!("{label} must define required fields: {schema:?}"))?;
    for expected in expected_required {
        if !required
            .iter()
            .any(|value| value.as_str() == Some(*expected))
        {
            anyhow::bail!("{label} required fields must include {expected:?}: {required:?}");
        }
    }
    Ok(())
}

fn assert_string_const_schema_property(
    schema: &Value,
    label: &str,
    property: &str,
    expected_const: &str,
) -> Result<()> {
    let property_schema = schema_property(schema, label, property)?;
    assert_schema_property_type(property_schema, label, property, "string")?;
    if property_schema.get("const").and_then(Value::as_str) != Some(expected_const) {
        anyhow::bail!(
            "{label}.{property} must set const to {expected_const:?}: {property_schema:?}"
        );
    }
    Ok(())
}

fn assert_boolean_const_schema_property(
    schema: &Value,
    label: &str,
    property: &str,
    expected_const: bool,
) -> Result<()> {
    let property_schema = schema_property(schema, label, property)?;
    assert_schema_property_type(property_schema, label, property, "boolean")?;
    if property_schema.get("const").and_then(Value::as_bool) != Some(expected_const) {
        anyhow::bail!(
            "{label}.{property} must set const to {expected_const:?}: {property_schema:?}"
        );
    }
    Ok(())
}

fn assert_string_enum_schema_property(
    schema: &Value,
    label: &str,
    property: &str,
    expected_enum: &[&str],
) -> Result<()> {
    let property_schema = schema_property(schema, label, property)?;
    assert_schema_property_type(property_schema, label, property, "string")?;
    let actual_enum = property_schema
        .get("enum")
        .and_then(Value::as_array)
        .with_context(|| format!("{label}.{property} must define enum: {property_schema:?}"))?;
    let actual_enum = actual_enum
        .iter()
        .map(|value| {
            value
                .as_str()
                .with_context(|| format!("{label}.{property} enum values must be strings"))
        })
        .collect::<Result<Vec<_>>>()?;
    if actual_enum != expected_enum {
        anyhow::bail!(
            "{label}.{property} enum mismatch; expected {expected_enum:?}, got {actual_enum:?}"
        );
    }
    Ok(())
}

fn assert_schema_property_type(
    property_schema: &Value,
    label: &str,
    property: &str,
    expected_type: &str,
) -> Result<()> {
    assert_schema_type(
        property_schema,
        &format!("{label}.{property}"),
        expected_type,
    )
}

fn assert_schema_type(schema: &Value, label: &str, expected_type: &str) -> Result<()> {
    if schema.get("type").and_then(Value::as_str) != Some(expected_type) {
        anyhow::bail!("{label} must set type to {expected_type:?}: {schema:?}");
    }
    Ok(())
}

fn schema_property<'a>(schema: &'a Value, label: &str, property: &str) -> Result<&'a Value> {
    schema
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get(property))
        .with_context(|| format!("{label} missing {property} property schema: {schema:?}"))
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
multi_agent_seen=false
prompt_arg=
no_further_delegation=true
worker_reports_json=
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
    --enable)
      if [ "$2" = "multi_agent" ]; then
        multi_agent_seen=true
      fi
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
if [ "$multi_agent_seen" != "true" ]; then
  echo "missing --enable multi_agent flag" >&2
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
printf '{"event":"fake-start","worktree":"%s","prompt_from_stdin":%s,"multi_agent":%s}\n' "$worktree" "$prompt_from_stdin" "$multi_agent_seen"
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
  child-delegated)
    path="README.md"
    edit_path="README.md"
    worker="worker-delegated"
    no_further_delegation=false
    ;;
  child-omits-workers)
    path="README.md"
    edit_path="README.md"
    worker="worker-omitted"
    worker_reports_json='[]'
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
if [ -z "$worker_reports_json" ]; then
  worker_reports_json=$(cat <<JSON
[
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
      "no_further_delegation": $no_further_delegation,
      "accepted": $accepted,
      "rejected": $rejected,
      "status": "$status",
      "remaining_risk": "$risk",
      "next_safe_action": "$next"
    }
  ]
JSON
)
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
  "worker_reports": $worker_reports_json,
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
