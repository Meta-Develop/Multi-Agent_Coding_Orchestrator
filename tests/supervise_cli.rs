use anyhow::{Context, Result};
use git2::{Oid, Repository, Signature};
use serde_json::Value;
use std::{fs, path::Path, process::Command};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");
const CHILD_A_O1_PREFIX: &str = "\
ROLE: O1_CHILD_ORCHESTRATOR
AGENT_KIND: child_orchestrator
AGENT_LABEL: child-a
PARENT_THREAD_ID: none
THREAD_DEPTH: 1
NO_FURTHER_DELEGATION: false
";
const WORKER_A_PREFIX: &str = "\
ROLE: TERMINAL_WORKER
AGENT_KIND: worker
AGENT_LABEL: worker-a
PARENT_THREAD_ID: none
THREAD_DEPTH: 2
NO_FURTHER_DELEGATION: true
";
const CHILD_A_AUDITOR_PREFIX: &str = "\
ROLE: REVIEW_AUDITOR
AGENT_KIND: auditor
AGENT_LABEL: child-a-review-auditor
PARENT_THREAD_ID: none
THREAD_DEPTH: 2
NO_FURTHER_DELEGATION: true
";

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
        4
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
        .join(".maco/o2/runs/supervise-two/logs/child-a-review-auditor.jsonl")
        .exists());
    assert!(repo_path
        .join(".maco/o2/runs/supervise-two/reports/child-b.json")
        .exists());
    assert!(repo_path
        .join(".maco/o2/runs/supervise-two/reports/child-a-review-auditor.json")
        .exists());
    let first_command = report["commands_run"][0]["command"]
        .as_array()
        .context("first command")?;
    assert!(first_command.iter().any(|arg| arg == "--json"));
    assert!(command_contains_sequence(
        first_command,
        &["--sandbox", "danger-full-access"]
    ));
    assert!(command_contains_sequence(
        first_command,
        &["--enable", "goals"]
    ));
    assert!(command_contains_sequence(
        first_command,
        &["--enable", "multi_agent"]
    ));
    let child_a_report_arg = repo_path
        .join(".maco/o2/runs/supervise-two/reports/child-a.json")
        .display()
        .to_string();
    assert!(command_contains_sequence(
        first_command,
        &["--output-last-message", child_a_report_arg.as_str()]
    ));
    let orchestrator_schema_arg = repo_path
        .join(".maco/o2/runs/supervise-two/schemas/orchestrator-review-report.schema.json")
        .display()
        .to_string();
    assert!(command_contains_sequence(
        first_command,
        &["--output-schema", orchestrator_schema_arg.as_str()]
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
    let auditor_command = report["commands_run"][1]["command"]
        .as_array()
        .context("auditor command")?;
    let child_a_auditor_report_arg = repo_path
        .join(".maco/o2/runs/supervise-two/reports/child-a-review-auditor.json")
        .display()
        .to_string();
    let auditor_schema_arg = repo_path
        .join(".maco/o2/runs/supervise-two/schemas/auditor-report.schema.json")
        .display()
        .to_string();
    assert!(command_contains_sequence(
        auditor_command,
        &["--sandbox", "read-only"]
    ));
    assert!(command_contains_sequence(
        auditor_command,
        &["--enable", "goals"]
    ));
    assert!(command_contains_sequence(
        auditor_command,
        &["--enable", "multi_agent"]
    ));
    assert!(command_contains_sequence(
        auditor_command,
        &["--output-last-message", child_a_auditor_report_arg.as_str()]
    ));
    assert!(command_contains_sequence(
        auditor_command,
        &["--output-schema", auditor_schema_arg.as_str()]
    ));
    let child_a_log =
        fs::read_to_string(repo_path.join(".maco/o2/runs/supervise-two/logs/child-a.jsonl"))
            .context("read child-a json log")?;
    assert!(child_a_log.contains(r#""event":"fake-start""#));
    assert!(child_a_log.contains(r#""prompt_from_stdin":true"#));
    assert!(child_a_log.contains(r#""goals":true"#));
    assert!(child_a_log.contains(r#""multi_agent":true"#));
    assert!(child_a_log.contains(r#""o1_role_prefix":true"#));
    assert!(child_a_log.contains(r#""sandbox":"danger-full-access""#));
    let child_a_auditor_log = fs::read_to_string(
        repo_path.join(".maco/o2/runs/supervise-two/logs/child-a-review-auditor.jsonl"),
    )
    .context("read child-a auditor json log")?;
    assert!(child_a_auditor_log.contains(r#""auditor_role_prefix":true"#));
    assert!(child_a_auditor_log.contains(r#""goals":true"#));
    assert!(child_a_auditor_log.contains(r#""multi_agent":true"#));
    assert!(child_a_auditor_log.contains(r#""sandbox":"read-only""#));

    let child_a_prompt = fs::read_to_string(
        repo_path.join(".maco/o2/runs/supervise-two/assignments/child-a.prompt.md"),
    )
    .context("read child-a prompt")?;
    assert_prompt_starts_with_prefix(&child_a_prompt, CHILD_A_O1_PREFIX)?;
    assert!(child_a_prompt.contains(WORKER_A_PREFIX));
    assert!(child_a_prompt.contains(CHILD_A_AUDITOR_PREFIX));
    let embedded_worker_prompt = child_a_prompt
        .split_once("Worker prompt templates:\n")
        .map(|(_, prompt)| prompt)
        .context("embedded worker prompt templates block")?;
    assert_prompt_starts_with_prefix(embedded_worker_prompt, WORKER_A_PREFIX)?;
    let embedded_auditor_prompt = child_a_prompt
        .split_once("Review auditor prompt template:\n")
        .map(|(_, prompt)| prompt)
        .context("embedded auditor prompt template block")?;
    assert_prompt_starts_with_prefix(embedded_auditor_prompt, CHILD_A_AUDITOR_PREFIX)?;
    assert!(child_a_prompt.contains("First, read and follow AGENTS.md"));
    assert!(child_a_prompt.contains(".agents/skills/agent-orchestration/SKILL.md"));
    assert!(child_a_prompt.contains(".agents/docs/AGENT_ORCHESTRATION.md"));
    assert!(child_a_prompt.contains(
        "Use Codex native SubAgent/delegated-worker mechanisms only for lightweight terminal worker or researcher assignments"
    ));
    assert!(!child_a_prompt
        .contains("Use Codex native SubAgent/delegated-worker mechanisms for worker assignments"));
    assert!(child_a_prompt.contains(
        "You must not use native SubAgent/delegated-worker mechanisms to bind, spawn, impersonate, or take over O1 or O2 roles"
    ));
    assert!(child_a_prompt.contains("use the generated worker prompt template verbatim"));
    assert!(child_a_prompt
        .contains("preserve its six-line TERMINAL_WORKER role-prefix block with no preamble"));
    assert!(child_a_prompt.contains("If no delegated-worker mechanism is available"));
    assert!(child_a_prompt.contains("exact blocked worker task"));
    assert!(child_a_prompt.contains(
        "user-directed root O2 or autonomous O2 supervisor -> O1 child orchestrator -> terminal worker/researcher/review-auditor"
    ));
    assert!(child_a_prompt.contains("Durable role names are canonical"));
    assert!(child_a_prompt.contains(
        "Runtime labels belong in runtime bridge metadata such as AGENT_LABEL, never in ROLE"
    ));
    assert!(!child_a_prompt.contains("ROLE: expert-coder"));
    assert!(child_a_prompt.contains("You may collect advisory child-side review-auditor evidence"));
    assert!(child_a_prompt.contains("six-line REVIEW_AUDITOR role-prefix block"));
    assert!(child_a_prompt.contains(
        "Acceptance-gate review auditors are parent-launched MACO/Codex CLI subprocess roles"
    ));
    assert!(child_a_prompt.contains(
        "a child-launched review auditor is advisory child-side evidence unless MACO/O2 collects it through the parent-enforced acceptance gate"
    ));
    assert!(child_a_prompt.contains("audit_reports"));
    assert!(child_a_prompt.contains("AuditorReport JSON"));
    assert!(child_a_prompt.contains("auditor-report.schema.json"));
    assert!(child_a_prompt.contains("You must not spawn, impersonate, or take over a peer O2"));
    assert!(child_a_prompt.contains("O1 reports peer-O2 escalation candidates upward"));
    assert!(child_a_prompt.contains(
        "user-root O2 or an autonomous O2 durable queue may launch bounded peer O2 supervisors through MACO/Codex CLI subprocess orchestration"
    ));
    assert!(child_a_prompt.contains(
        "Autonomous O2-to-O2 follow-up must go through durable queue state such as NEXT_O2_TASKS.tsv, not native SubAgent"
    ));
    assert!(child_a_prompt.contains(
        "You were launched as a Codex CLI subprocess with this O1/O2 orchestration boundary:"
    ));
    assert!(child_a_prompt.contains("- --sandbox danger-full-access"));
    assert!(child_a_prompt.contains("- --enable goals"));
    assert!(child_a_prompt.contains("- --enable multi_agent"));
    assert!(child_a_prompt.contains(
        "Nested O2/O1 subprocess chains must preserve this boundary for orchestrator roles"
    ));
    assert!(child_a_prompt.contains("Do not use workspace-write for O2/O1 subprocess chains"));
    assert!(child_a_prompt.contains(
        "nested Codex state DB access can collide, corrupt, or fail under workspace-write style restrictions"
    ));
    assert!(!child_a_prompt
        .contains("The top O2/supervisor may launch peer O2 supervisors as parallel scopes"));
    assert!(child_a_prompt.contains("O1 reports peer-O2 escalation candidates upward"));
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
    assert_report_token_schemas(&worker_schema, "worker schema")?;
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
    assert_report_token_schemas(&orchestrator_schema, "orchestrator schema")?;
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
    assert_report_token_schemas(nested_worker_schema, "nested worker schema")?;
    assert_report_array_item_schemas(nested_worker_schema, "nested worker schema")?;
    assert!(orchestrator_schema["properties"]
        .as_object()
        .context("orchestrator properties")?
        .contains_key("worker_reports"));
    assert!(orchestrator_schema["properties"]
        .as_object()
        .context("orchestrator properties")?
        .contains_key("audit_reports"));
    let nested_auditor_schema = &orchestrator_schema["properties"]["audit_reports"]["items"];
    assert_object_schema_sealed(nested_auditor_schema, "nested auditor schema")?;
    assert_string_const_schema_property(
        nested_auditor_schema,
        "nested auditor schema",
        "role",
        "auditor",
    )?;
    assert_boolean_const_schema_property(
        nested_auditor_schema,
        "nested auditor schema",
        "no_further_delegation",
        true,
    )?;
    assert_boolean_const_schema_property(
        nested_auditor_schema,
        "nested auditor schema",
        "read_only",
        true,
    )?;
    assert_string_enum_schema_property(
        nested_auditor_schema,
        "nested auditor schema",
        "status",
        &["pending", "succeeded", "failed", "rejected", "missing"],
    )?;
    assert_report_array_item_schemas(nested_auditor_schema, "nested auditor schema")?;
    let auditor_schema: Value = serde_json::from_str(
        &fs::read_to_string(
            repo_path.join(".maco/o2/runs/supervise-two/schemas/auditor-report.schema.json"),
        )
        .context("read auditor schema")?,
    )
    .context("parse auditor schema")?;
    assert_object_schema_sealed(&auditor_schema, "auditor schema")?;
    assert_all_array_schemas_define_items(&auditor_schema, "auditor schema")?;
    assert_string_const_schema_property(&auditor_schema, "auditor schema", "role", "auditor")?;
    assert_boolean_const_schema_property(
        &auditor_schema,
        "auditor schema",
        "no_further_delegation",
        true,
    )?;
    assert_boolean_const_schema_property(&auditor_schema, "auditor schema", "read_only", true)?;
    assert_report_array_item_schemas(&auditor_schema, "auditor schema")?;
    let child_a_report: Value = serde_json::from_str(
        &fs::read_to_string(repo_path.join(".maco/o2/runs/supervise-two/reports/child-a.json"))
            .context("read gated child-a report")?,
    )
    .context("parse gated child-a report")?;
    assert_eq!(
        child_a_report["audit_reports"]
            .as_array()
            .context("gated audit reports")?
            .len(),
        1
    );
    assert_eq!(
        child_a_report["audit_reports"][0]["id"],
        "child-a-review-auditor"
    );
    assert_eq!(
        child_a_report["audit_reports"][0]["reviewed_worker_ids"][0],
        "worker-a"
    );

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
    assert_eq!(
        child_report["audit_reports"]
            .as_array()
            .context("audit reports")?
            .len(),
        0
    );
    assert_eq!(
        report["commands_run"].as_array().context("commands")?.len(),
        1
    );
    assert_json_findings_contain_message(
        &child_report["findings"],
        "contained zero worker_reports despite assigned worker IDs: worker-omitted",
    )?;
    assert_json_findings_contain_message(
        &child_report["findings"],
        "omitted required worker reports for assignment worker IDs: worker-omitted",
    )?;
    assert!(child_report["remaining_risk"]
        .as_str()
        .context("child risk")?
        .contains("terminal review-auditor evidence"));

    Ok(())
}

#[test]
fn supervise_run_skips_parent_auditor_when_child_report_is_unusable() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let fake_codex = write_fake_codex(temp.path())?;
    let plan_path = temp.path().join("supervisor-plan.json");
    write_plan(
        &plan_path,
        r#"{
          "version": 1,
          "task": "skip parent auditor when child report is unusable",
          "max_depth": 2,
          "max_child_processes": 1,
          "child_timeout_seconds": 10,
          "assignments": [
            {
              "id": "child-missing",
              "assigned_paths": ["README.md"],
              "worker_assignments": [
                {"id": "worker-missing-child", "assigned_paths": ["README.md"]}
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
        "supervise-unusable-child-skips-parent-auditor",
        "--codex-bin",
        fake_codex.to_str().context("fake codex path utf8")?,
        "--json",
    ])?;

    assert_eq!(report["success"], false);
    assert_eq!(report["status"], "failed");
    assert_eq!(
        report["commands_run"].as_array().context("commands")?.len(),
        1
    );
    let child_report = &report["orchestrator_reports"][0];
    assert_eq!(child_report["status"], "failed");
    assert_eq!(
        child_report["worker_reports"]
            .as_array()
            .context("worker reports")?
            .len(),
        0
    );
    assert_eq!(
        child_report["audit_reports"]
            .as_array()
            .context("audit reports")?
            .len(),
        0
    );
    assert_json_findings_contain_message(
        &child_report["findings"],
        "required child report is missing or invalid",
    )?;
    assert_json_findings_contain_message(
        &child_report["findings"],
        "omitted required worker reports for assignment worker IDs: worker-missing-child",
    )?;
    assert!(!repo_path
        .join(
            ".maco/o2/runs/supervise-unusable-child-skips-parent-auditor/logs/child-missing-review-auditor.jsonl"
        )
        .exists());

    Ok(())
}

#[test]
fn supervise_run_rejects_missing_parent_auditor_report_for_assigned_workers() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let fake_codex = write_fake_codex(temp.path())?;
    let plan_path = temp.path().join("supervisor-plan.json");
    write_plan(
        &plan_path,
        r#"{
          "version": 1,
          "task": "reject missing parent auditor report",
          "max_depth": 2,
          "max_child_processes": 1,
          "child_timeout_seconds": 10,
          "assignments": [
            {
              "id": "child-auditor-missing",
              "assigned_paths": ["README.md"],
              "worker_assignments": [
                {"id": "worker-auditor-missing", "assigned_paths": ["README.md"]}
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
        "supervise-missing-parent-auditor-report",
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
        child_report["audit_reports"]
            .as_array()
            .context("audit reports")?
            .len(),
        1
    );
    assert_eq!(child_report["audit_reports"][0]["status"], "failed");
    assert_json_findings_contain_message(
        &child_report["audit_reports"][0]["findings"],
        "required parent-launched auditor report is missing or invalid",
    )?;
    assert_json_findings_contain_message(
        &child_report["findings"],
        "lacks accepted parent-launched review auditor report",
    )?;
    assert!(child_report["remaining_risk"]
        .as_str()
        .context("child risk")?
        .contains("terminal review-auditor evidence"));

    Ok(())
}

#[test]
fn supervise_run_rejects_invalid_auditor_report_for_assigned_workers() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let fake_codex = write_fake_codex(temp.path())?;
    let plan_path = temp.path().join("supervisor-plan.json");
    write_plan(
        &plan_path,
        r#"{
          "version": 1,
          "task": "reject invalid auditor reports",
          "max_depth": 2,
          "max_child_processes": 1,
          "child_timeout_seconds": 10,
          "assignments": [
            {
              "id": "child-invalid-auditor",
              "assigned_paths": ["README.md"],
              "worker_assignments": [
                {"id": "worker-invalid-auditor", "assigned_paths": ["README.md"]}
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
        "supervise-invalid-parent-auditor-report",
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
    let auditor_report = &child_report["audit_reports"][0];
    assert_eq!(auditor_report["status"], "failed");
    assert_eq!(auditor_report["accepted"], false);
    assert_eq!(auditor_report["rejected"], true);
    assert_eq!(
        auditor_report["reviewed_worker_ids"][0],
        "worker-invalid-auditor"
    );
    assert_json_findings_contain_message(
        &auditor_report["findings"],
        "auditor report omitted reviewed_paths evidence",
    )?;
    assert_json_findings_contain_message(
        &auditor_report["findings"],
        "auditor report omitted remaining_risk evidence",
    )?;
    assert_json_findings_contain_message(
        &auditor_report["findings"],
        "auditor report omitted next_safe_action evidence",
    )?;
    assert_json_findings_contain_message(
        &child_report["findings"],
        "included invalid review auditor reports: child-invalid-auditor-review-auditor",
    )?;
    assert!(child_report["remaining_risk"]
        .as_str()
        .context("child risk")?
        .contains("terminal review-auditor evidence"));

    Ok(())
}

#[test]
fn supervise_run_rejects_parent_auditor_path_coverage_mismatch() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let fake_codex = write_fake_codex(temp.path())?;
    let plan_path = temp.path().join("supervisor-plan.json");
    write_plan(
        &plan_path,
        r#"{
          "version": 1,
          "task": "reject auditor path coverage mismatch",
          "max_depth": 2,
          "max_child_processes": 1,
          "child_timeout_seconds": 10,
          "assignments": [
            {
              "id": "child-auditor-path-mismatch",
              "assigned_paths": ["src/lib.rs"],
              "worker_assignments": [
                {"id": "worker-auditor-path-mismatch", "assigned_paths": ["src/lib.rs"]}
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
        "supervise-auditor-path-mismatch",
        "--codex-bin",
        fake_codex.to_str().context("fake codex path utf8")?,
        "--json",
    ])?;

    assert_eq!(report["success"], false);
    assert_eq!(report["status"], "failed");
    let child_report = &report["orchestrator_reports"][0];
    let auditor_report = &child_report["audit_reports"][0];
    assert_eq!(auditor_report["status"], "failed");
    assert_eq!(auditor_report["accepted"], false);
    assert_json_findings_contain_message(
        &auditor_report["findings"],
        "parent auditor reviewed_paths omitted required assignment/change path coverage for: src/lib.rs",
    )?;
    assert_json_findings_contain_message(
        &child_report["findings"],
        "lacks accepted parent-launched review auditor report",
    )?;

    Ok(())
}

#[test]
fn supervise_run_rejects_parent_auditor_missing_schema_required_evidence() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let fake_codex = write_fake_codex(temp.path())?;
    let plan_path = temp.path().join("supervisor-plan.json");
    write_plan(
        &plan_path,
        r#"{
          "version": 1,
          "task": "reject auditor missing schema evidence",
          "max_depth": 2,
          "max_child_processes": 1,
          "child_timeout_seconds": 10,
          "assignments": [
            {
              "id": "child-auditor-evidence-missing",
              "assigned_paths": ["README.md"],
              "worker_assignments": [
                {"id": "worker-auditor-evidence-missing", "assigned_paths": ["README.md"]}
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
        "supervise-auditor-missing-schema-evidence",
        "--codex-bin",
        fake_codex.to_str().context("fake codex path utf8")?,
        "--json",
    ])?;

    assert_eq!(report["success"], false);
    assert_eq!(report["status"], "failed");
    let child_report = &report["orchestrator_reports"][0];
    let auditor_report = &child_report["audit_reports"][0];
    assert_eq!(auditor_report["status"], "failed");
    assert_eq!(auditor_report["accepted"], false);
    assert_eq!(
        auditor_report["commands_run"]
            .as_array()
            .context("parent auditor command evidence")?
            .len(),
        1
    );
    assert_json_findings_contain_message(
        &auditor_report["findings"],
        "auditor report omitted validation_results evidence",
    )?;
    assert_json_findings_contain_message(
        &child_report["findings"],
        "included invalid review auditor reports: child-auditor-evidence-missing-review-auditor",
    )?;

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
    assert_eq!(
        report["commands_run"].as_array().context("commands")?.len(),
        2
    );
    assert_json_array_contains(
        &report["orchestrator_reports"][0]["files_changed"],
        "README.md",
    )?;
    assert_eq!(
        report["orchestrator_reports"][0]["audit_reports"][0]["reviewed_worker_ids"][0],
        "child-assigned-only"
    );
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
fn supervise_run_fails_when_child_mutates_primary_worktree() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let fake_codex = write_fake_codex(temp.path())?;
    let plan_path = temp.path().join("supervisor-plan.json");
    write_plan(
        &plan_path,
        r#"{
          "version": 1,
          "task": "catch primary mutation",
          "max_depth": 2,
          "max_child_processes": 1,
          "child_timeout_seconds": 10,
          "assignments": [
            {"id": "child-primary-mutation", "assigned_paths": ["README.md"]}
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
        "supervise-primary-mutation",
        "--codex-bin",
        fake_codex.to_str().context("fake codex path utf8")?,
        "--json",
    ])?;

    assert_eq!(report["success"], false);
    assert_finding(
        &report["orchestrator_reports"][0]["findings"],
        "error",
        "primary worktree became dirty during child orchestrator 'child-primary-mutation' run",
        "README.md",
    )?;

    Ok(())
}

#[test]
fn supervise_run_retries_report_shape_failure_once_with_corrective_feedback() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let fake_codex = write_fake_codex(temp.path())?;
    let plan_path = temp.path().join("supervisor-plan.json");
    write_plan(
        &plan_path,
        r#"{
          "version": 1,
          "task": "retry malformed report",
          "max_depth": 2,
          "max_child_processes": 1,
          "max_child_retries": 1,
          "child_timeout_seconds": 10,
          "assignments": [
            {"id": "child-retry-shape", "assigned_paths": ["README.md"]}
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
        "supervise-retry-shape",
        "--codex-bin",
        fake_codex.to_str().context("fake codex path utf8")?,
        "--json",
    ])?;

    assert_eq!(report["success"], true);
    assert_eq!(
        report["commands_run"].as_array().context("commands")?.len(),
        3
    );
    assert!(repo_path
        .join(".maco/o2/runs/supervise-retry-shape/logs/child-retry-shape.attempt-1.jsonl")
        .exists());
    assert!(repo_path
        .join(".maco/o2/runs/supervise-retry-shape/logs/child-retry-shape.attempt-2.jsonl")
        .exists());
    assert!(repo_path
        .join(".maco/o2/runs/supervise-retry-shape/reports/child-retry-shape.attempt-1.json")
        .exists());
    assert!(repo_path
        .join(".maco/o2/runs/supervise-retry-shape/reports/child-retry-shape.attempt-2.json")
        .exists());
    let retry_prompt = fs::read_to_string(repo_path.join(
        ".maco/o2/runs/supervise-retry-shape/assignments/child-retry-shape.attempt-2.prompt.md",
    ))
    .context("read retry prompt")?;
    assert!(retry_prompt.contains("CORRECTIVE FEEDBACK"));
    assert!(retry_prompt.contains("required child report is missing or invalid"));
    assert_json_findings_contain_message(
        &report["orchestrator_reports"][0]["findings"],
        "corrective retry attempt 2",
    )?;
    let canonical_report_path =
        repo_path.join(".maco/o2/runs/supervise-retry-shape/reports/child-retry-shape.json");
    assert!(canonical_report_path.exists());
    let canonical_report: Value = serde_json::from_str(
        &fs::read_to_string(&canonical_report_path).context("read canonical child report")?,
    )
    .context("parse canonical child report")?;
    assert_json_findings_contain_message(
        &canonical_report["findings"],
        "child attempt 1 history: structural_problems=",
    )?;
    assert_json_findings_contain_message(
        &canonical_report["findings"],
        "corrective_retry_used=false",
    )?;
    assert_json_findings_contain_message(
        &canonical_report["findings"],
        "child attempt 2 history: structural_problems=<none>; corrective_retry_used=true",
    )?;

    Ok(())
}

#[test]
fn supervise_run_retries_malformed_first_attempt_that_left_assigned_diff() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let fake_codex = write_fake_codex(temp.path())?;
    let plan_path = temp.path().join("supervisor-plan.json");
    write_plan(
        &plan_path,
        r#"{
          "version": 1,
          "task": "retry malformed report with assigned diff",
          "max_depth": 2,
          "max_child_processes": 1,
          "max_child_retries": 1,
          "child_timeout_seconds": 10,
          "assignments": [
            {"id": "child-retry-shape-diff", "assigned_paths": ["README.md"]}
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
        "supervise-retry-shape-diff",
        "--codex-bin",
        fake_codex.to_str().context("fake codex path utf8")?,
        "--json",
    ])?;

    assert_eq!(report["success"], true);
    assert_json_array_contains(
        &report["orchestrator_reports"][0]["files_changed"],
        "README.md",
    )?;
    assert!(repo_path
        .join(
            ".maco/o2/runs/supervise-retry-shape-diff/logs/child-retry-shape-diff.attempt-1.jsonl"
        )
        .exists());
    assert!(repo_path
        .join(
            ".maco/o2/runs/supervise-retry-shape-diff/logs/child-retry-shape-diff.attempt-2.jsonl"
        )
        .exists());
    assert_json_findings_contain_message(
        &report["orchestrator_reports"][0]["findings"],
        "corrective retry attempt 2",
    )?;

    Ok(())
}

#[test]
fn supervise_run_does_not_retry_malformed_first_attempt_with_path_violation() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let fake_codex = write_fake_codex(temp.path())?;
    let plan_path = temp.path().join("supervisor-plan.json");
    write_plan(
        &plan_path,
        r#"{
          "version": 1,
          "task": "do not retry malformed report with path violation",
          "max_depth": 2,
          "max_child_processes": 1,
          "max_child_retries": 1,
          "child_timeout_seconds": 10,
          "assignments": [
            {"id": "child-retry-shape-unauthorized", "assigned_paths": ["README.md"]}
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
        "supervise-retry-shape-unauthorized",
        "--codex-bin",
        fake_codex.to_str().context("fake codex path utf8")?,
        "--json",
    ])?;

    assert_eq!(report["success"], false);
    assert!(repo_path
        .join(".maco/o2/runs/supervise-retry-shape-unauthorized/logs/child-retry-shape-unauthorized.attempt-1.jsonl")
        .exists());
    assert!(!repo_path
        .join(".maco/o2/runs/supervise-retry-shape-unauthorized/logs/child-retry-shape-unauthorized.attempt-2.jsonl")
        .exists());
    assert_finding(
        &report["orchestrator_reports"][0]["findings"],
        "error",
        "outside its assigned paths",
        "src/lib.rs",
    )?;

    Ok(())
}

#[test]
fn supervise_run_rejects_worker_report_files_changed_outside_worker_assignment() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let fake_codex = write_fake_codex(temp.path())?;
    let plan_path = temp.path().join("supervisor-plan.json");
    write_plan(
        &plan_path,
        r#"{
          "version": 1,
          "task": "catch worker report path violation",
          "max_depth": 2,
          "max_child_processes": 1,
          "child_timeout_seconds": 10,
          "assignments": [
            {
              "id": "child-worker-outside",
              "assigned_paths": ["README.md", "src/lib.rs"],
              "worker_assignments": [
                {"id": "worker-worker-outside", "assigned_paths": ["README.md"]}
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
        "supervise-worker-outside",
        "--codex-bin",
        fake_codex.to_str().context("fake codex path utf8")?,
        "--json",
    ])?;

    assert_eq!(report["success"], false);
    assert_finding(
        &report["orchestrator_reports"][0]["findings"],
        "error",
        "worker 'worker-worker-outside' reported files_changed outside its assigned_paths",
        "src/lib.rs",
    )?;

    Ok(())
}

#[test]
fn supervise_run_rejects_unassigned_worker_report_that_self_authorizes_diff() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let fake_codex = write_fake_codex(temp.path())?;
    let plan_path = temp.path().join("supervisor-plan.json");
    write_plan(
        &plan_path,
        r#"{
          "version": 1,
          "task": "catch extra unassigned worker self authorization",
          "max_depth": 2,
          "max_child_processes": 1,
          "child_timeout_seconds": 10,
          "assignments": [
            {
              "id": "child-worker-extra-self-authorized",
              "assigned_paths": ["README.md"],
              "worker_assignments": [
                {"id": "worker-extra-assigned", "assigned_paths": ["README.md"]}
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
        "supervise-worker-extra-self-authorized",
        "--codex-bin",
        fake_codex.to_str().context("fake codex path utf8")?,
        "--json",
    ])?;

    assert_eq!(report["success"], false);
    assert_finding(
        &report["orchestrator_reports"][0]["findings"],
        "error",
        "worker 'worker-extra-self-authorized' is not declared in assignment 'child-worker-extra-self-authorized' worker_assignments",
        "README.md",
    )?;

    Ok(())
}

#[test]
fn supervise_run_warns_when_worker_report_union_differs_from_git_diff() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let fake_codex = write_fake_codex(temp.path())?;
    let plan_path = temp.path().join("supervisor-plan.json");
    write_plan(
        &plan_path,
        r#"{
          "version": 1,
          "task": "warn about worker evidence mismatch",
          "max_depth": 2,
          "max_child_processes": 1,
          "child_timeout_seconds": 10,
          "assignments": [
            {
              "id": "child-worker-union-mismatch",
              "assigned_paths": ["README.md"],
              "worker_assignments": [
                {"id": "worker-worker-union-mismatch", "assigned_paths": ["README.md"]}
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
        "supervise-worker-union-mismatch",
        "--codex-bin",
        fake_codex.to_str().context("fake codex path utf8")?,
        "--json",
    ])?;

    assert_eq!(report["success"], true);
    assert_finding(
        &report["orchestrator_reports"][0]["findings"],
        "warning",
        "worker files_changed union differs from actual child worktree Git changes",
        "README.md",
    )?;
    assert_json_findings_contain_message(
        &report["orchestrator_reports"][0]["findings"],
        "reported-but-not-observed: <none>; observed-but-not-reported: README.md",
    )?;

    Ok(())
}

#[test]
fn supervise_run_rejects_worker_with_failed_validation_but_accepted_success() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let fake_codex = write_fake_codex(temp.path())?;
    let plan_path = temp.path().join("supervisor-plan.json");
    write_plan(
        &plan_path,
        r#"{
          "version": 1,
          "task": "catch inconsistent worker validation",
          "max_depth": 2,
          "max_child_processes": 1,
          "child_timeout_seconds": 10,
          "assignments": [
            {
              "id": "child-worker-failed-accepted",
              "assigned_paths": ["README.md"],
              "worker_assignments": [
                {"id": "worker-worker-failed-accepted", "assigned_paths": ["README.md"]}
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
        "supervise-worker-failed-accepted",
        "--codex-bin",
        fake_codex.to_str().context("fake codex path utf8")?,
        "--json",
    ])?;

    assert_eq!(report["success"], false);
    assert_finding(
        &report["orchestrator_reports"][0]["findings"],
        "error",
        "worker 'worker-worker-failed-accepted' reports failed validation while accepted=true and status=succeeded",
        "README.md",
    )?;

    Ok(())
}

#[test]
fn supervise_run_uses_recorded_child_base_when_primary_advances_mid_run() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let fake_codex = write_fake_codex(temp.path())?;
    let plan_path = temp.path().join("supervisor-plan.json");
    write_plan(
        &plan_path,
        r#"{
          "version": 1,
          "task": "primary may advance while child runs",
          "max_depth": 2,
          "max_child_processes": 2,
          "child_timeout_seconds": 10,
          "assignments": [
            {"id": "child-primary-mid-commit", "assigned_paths": ["README.md"]},
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
        "supervise-primary-mid-commit",
        "--codex-bin",
        fake_codex.to_str().context("fake codex path utf8")?,
        "--json",
    ])?;

    assert_eq!(report["success"], true);
    assert_json_array_contains(
        &report["orchestrator_reports"][0]["files_changed"],
        "README.md",
    )?;
    assert_json_array_not_contains(
        &report["orchestrator_reports"][0]["files_changed"],
        "src/inbox.rs",
    )?;
    assert_no_finding_message_contains(
        &report["orchestrator_reports"][0]["findings"],
        "outside its assigned paths",
    )?;
    assert_json_array_contains(
        &report["orchestrator_reports"][1]["files_changed"],
        "src/lib.rs",
    )?;
    assert_json_array_not_contains(
        &report["orchestrator_reports"][1]["files_changed"],
        "src/inbox.rs",
    )?;
    assert_no_finding_message_contains(
        &report["orchestrator_reports"][1]["findings"],
        "outside its assigned paths",
    )?;

    Ok(())
}

#[test]
fn supervise_run_reports_sync_claim_conflict_owner_and_paths() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let fake_codex = write_fake_codex(temp.path())?;
    let plan_path = temp.path().join("supervisor-plan.json");
    write_plan(
        &plan_path,
        r#"{
          "version": 1,
          "task": "claim conflict diagnostics",
          "max_depth": 2,
          "max_child_processes": 1,
          "child_timeout_seconds": 10,
          "assignments": [
            {"id": "child-claim-conflict", "assigned_paths": ["README.md"]}
          ]
        }"#,
    )?;

    let preclaim = run_success_json_args(&[
        "sync",
        "claim",
        "stale-agent",
        "README.md",
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--json",
    ])?;
    assert_eq!(preclaim["agent_id"], "stale-agent");

    let report = run_failure_json_args(&[
        "supervise",
        "run",
        plan_path.to_str().context("plan path utf8")?,
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--run-id",
        "supervise-claim-conflict",
        "--codex-bin",
        fake_codex.to_str().context("fake codex path utf8")?,
        "--json",
    ])?;

    assert_eq!(report["success"], false);
    assert_finding(
        &report["findings"],
        "error",
        "README.md currently claimed by stale-agent (token",
        "README.md",
    )?;

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
    let bad_retries = temp.path().join("bad-retries.json");
    write_plan(
        &bad_retries,
        r#"{
          "version": 1,
          "task": "bad retries",
          "max_depth": 2,
          "max_child_processes": 1,
          "max_child_retries": 3,
          "assignments": [
            {"id": "child-a", "assigned_paths": ["README.md"]}
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

    let retries_output = run_failure_output(&[
        "supervise",
        "run",
        bad_retries.to_str().context("bad retries path utf8")?,
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--run-id",
        "supervise-bad-retries",
        "--codex-bin",
        fake_codex.to_str().context("fake codex path utf8")?,
        "--json",
    ])?;
    assert!(String::from_utf8_lossy(&retries_output.stderr).contains("max_child_retries"));

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
    assert_eq!(plan["max_child_retries"], 0);
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
fn supervise_run_assignment_task_overrides_child_prompt_and_worker_fallback() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let fake_codex = write_fake_codex(temp.path())?;
    let plan_path = temp.path().join("supervisor-plan-task-override.json");
    write_plan(
        &plan_path,
        r#"{
          "version": 1,
          "task": "plan fallback task",
          "max_depth": 2,
          "max_child_processes": 1,
          "child_timeout_seconds": 10,
          "assignments": [
            {
              "id": "child-a",
              "assigned_paths": ["README.md", "src/lib.rs"],
              "task": "assignment scoped task",
              "worker_assignments": [
                {"id": "worker-a", "assigned_paths": ["README.md"]},
                {"id": "worker-b", "assigned_paths": ["src/lib.rs"], "task": "worker specific task"}
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
        "supervise-task-override",
        "--codex-bin",
        fake_codex.to_str().context("fake codex path utf8")?,
        "--json",
    ])?;
    assert_eq!(report["success"], false);

    let child_prompt = fs::read_to_string(
        repo_path.join(".maco/o2/runs/supervise-task-override/assignments/child-a.prompt.md"),
    )
    .context("read child prompt")?;
    assert!(child_prompt.contains("Supervisor task:\nassignment scoped task"));
    assert!(!child_prompt.contains("Supervisor task:\nplan fallback task"));
    let worker_a_section = prompt_section_after(&child_prompt, "- Worker id: worker-a")?;
    assert!(worker_a_section.contains("Supervisor task:\nassignment scoped task"));
    let worker_b_section = prompt_section_after(&child_prompt, "- Worker id: worker-b")?;
    assert!(worker_b_section.contains("Supervisor task:\nworker specific task"));

    Ok(())
}

#[test]
fn supervise_plan_with_consultant_adds_child_prompt_consultation_section() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let fake_codex = write_fake_codex(temp.path())?;
    let plan_path = temp.path().join("supervisor-plan-consultant.json");
    write_plan(
        &plan_path,
        r#"{
          "version": 1,
          "task": "coordinate with optional consultant",
          "max_depth": 2,
          "max_child_processes": 1,
          "consultant": {
            "enabled": true,
            "runtime": "claude",
            "max_consultations": 1
          },
          "assignments": [
            {
              "id": "child-a",
              "assigned_paths": ["README.md"],
              "worker_assignments": [
                {"id": "worker-a", "assigned_paths": ["README.md"]}
              ]
            }
          ]
        }"#,
    )?;

    let normalized = run_success_json_args(&[
        "supervise",
        "plan",
        plan_path.to_str().context("plan path utf8")?,
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--json",
    ])?;
    assert_eq!(normalized["consultant"]["enabled"], true);
    assert_eq!(normalized["consultant"]["runtime"], "claude");
    assert_eq!(normalized["consultant"]["max_consultations"], 1);

    let report = run_success_json_args(&[
        "supervise",
        "run",
        plan_path.to_str().context("plan path utf8")?,
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--run-id",
        "supervise-consultant",
        "--codex-bin",
        fake_codex.to_str().context("fake codex path utf8")?,
        "--json",
    ])?;
    assert_eq!(report["success"], true);
    let child_prompt = fs::read_to_string(
        repo_path.join(".maco/o2/runs/supervise-consultant/assignments/child-a.prompt.md"),
    )
    .context("read child prompt")?;
    assert!(child_prompt.contains("CONSULTATION:"));
    assert!(child_prompt.contains("maco consult ask --runtime claude"));
    assert!(child_prompt.contains("Use at most 1 consultation(s)"));
    assert!(child_prompt.contains("Consultant advice never overrides AGENTS.md"));

    Ok(())
}

#[test]
fn supervise_readme_documents_o2_o1_contract_without_worker_fallback() -> Result<()> {
    let readme = fs::read_to_string("README.md").context("read README")?;
    let readme_words = readme.split_whitespace().collect::<Vec<_>>().join(" ");

    assert!(readme_words.contains(
        "user-directed root O2 -> autonomous O2 supervisor -> O1 child orchestrator -> terminal worker/researcher/review-auditor"
    ));
    assert!(readme.contains("human/user-directed root O2"));
    assert!(readme_words.contains("not counted against autonomous depth"));
    assert!(readme.contains("NEXT_O2_TASKS.tsv"));
    assert!(readme.contains("STATE.tsv"));
    assert!(readme.contains("HEARTBEAT.tsv"));
    assert!(readme.contains("ROLE: REVIEW_AUDITOR"));
    assert!(readme.contains("audit_reports"));
    assert!(readme_words.contains("Native SubAgent/delegated-worker use is limited to lightweight"));
    assert!(readme_words
        .contains("terminal worker and researcher roles; O1 child orchestrators must not bind O1"));
    assert!(readme.contains("or O2 roles to native SubAgent sessions"));
    assert!(readme_words.contains("instead of taking those scopes over"));
    assert!(readme_words.contains(
        "user-root O2 or an autonomous O2 durable queue may then launch bounded peer O2 supervisors"
    ));
    assert!(readme_words.contains("runtime labels belong in the runtime bridge and `AGENT_LABEL`"));
    assert!(!readme.contains("ROLE: expert-coder"));
    assert!(readme.contains("O1/O2 subprocess orchestration uses a Codex CLI launch boundary"));
    assert!(readme.contains("`--sandbox danger-full-access`, `--enable goals`, and"));
    assert!(readme.contains("`--enable multi_agent`"));
    assert!(readme_words.contains(
        "Nested O2/O1 subprocess chains must preserve that boundary for orchestrator roles"
    ));
    assert!(readme.contains("Do not use `workspace-write` for O2/O1 subprocess chains"));
    assert!(readme_words.contains(
        "nested Codex state DB access can collide, corrupt, or fail under workspace-write style restrictions"
    ));
    assert!(readme.contains("leave O1/O2 hierarchy and"));
    assert!(readme_words.contains("enforced audit gates to MACO/Codex CLI subprocess workflows"));
    assert!(readme_words.contains(
        "A child-side review auditor is advisory unless the parent MACO/O2 acceptance gate collects and accepts it"
    ));
    assert!(readme.contains("peer O2 supervisors"));
    assert!(readme.contains("report peer-O2 escalation"));
    assert!(!readme.contains("command-backed worker execution is fallback behavior"));
    assert!(!readme.contains("SubAgent/delegated-worker mechanisms when available so the project"));

    Ok(())
}

fn assert_json_array_contains(value: &Value, expected: &str) -> Result<()> {
    let values = value.as_array().context("json array")?;
    if !values.iter().any(|value| value == expected) {
        anyhow::bail!("expected JSON array to contain {expected}: {values:?}");
    }
    Ok(())
}

fn assert_json_array_not_contains(value: &Value, unexpected: &str) -> Result<()> {
    let values = value.as_array().context("json array")?;
    if values.iter().any(|value| value == unexpected) {
        anyhow::bail!("expected JSON array not to contain {unexpected}: {values:?}");
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

fn assert_no_finding_message_contains(value: &Value, unexpected: &str) -> Result<()> {
    let findings = value.as_array().context("findings array")?;
    if findings.iter().any(|finding| {
        finding["message"]
            .as_str()
            .is_some_and(|message| message.contains(unexpected))
    }) {
        anyhow::bail!("unexpected finding containing '{unexpected}': {findings:?}");
    }
    Ok(())
}

fn command_contains_sequence(command: &[Value], expected: &[&str]) -> bool {
    command.windows(expected.len()).any(|window| {
        window
            .iter()
            .zip(expected)
            .all(|(value, expected)| value.as_str() == Some(*expected))
    })
}

fn assert_prompt_starts_with_prefix(prompt: &str, expected_prefix: &str) -> Result<()> {
    if prompt.starts_with(expected_prefix) {
        return Ok(());
    }
    let actual = prompt.lines().take(6).collect::<Vec<_>>();
    anyhow::bail!("prompt did not start with expected role prefix; first six lines: {actual:?}");
}

fn prompt_section_after<'a>(prompt: &'a str, marker: &str) -> Result<&'a str> {
    prompt
        .split(marker)
        .nth(1)
        .with_context(|| format!("prompt missing marker {marker:?}"))
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
    assert_integer_nullable_schema_property(
        command_items,
        &format!("{label}.commands_run items"),
        "exit_code",
    )?;
    assert_string_nullable_schema_property(
        command_items,
        &format!("{label}.commands_run items"),
        "error",
    )?;

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
    assert_string_nullable_schema_property(
        validation_items,
        &format!("{label}.validation_results items"),
        "message",
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

fn assert_report_token_schemas(schema: &Value, label: &str) -> Result<()> {
    assert_schema_required_contains(schema, label, &["claim_token", "semantic_intent_token"])?;
    assert_integer_nullable_schema_property(schema, label, "claim_token")?;
    assert_integer_nullable_schema_property(schema, label, "semantic_intent_token")?;
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
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .with_context(|| format!("{label} must define properties: {schema:?}"))?;
    let required = schema
        .get("required")
        .and_then(Value::as_array)
        .with_context(|| format!("{label} must define required fields: {schema:?}"))?;
    for property in properties.keys() {
        if !required
            .iter()
            .any(|value| value.as_str() == Some(property.as_str()))
        {
            anyhow::bail!(
                "{label} required fields must include property {property:?}: {required:?}"
            );
        }
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

fn assert_integer_nullable_schema_property(
    schema: &Value,
    label: &str,
    property: &str,
) -> Result<()> {
    assert_schema_property_types(
        schema_property(schema, label, property)?,
        label,
        property,
        &["integer", "null"],
    )
}

fn assert_string_nullable_schema_property(
    schema: &Value,
    label: &str,
    property: &str,
) -> Result<()> {
    assert_schema_property_types(
        schema_property(schema, label, property)?,
        label,
        property,
        &["string", "null"],
    )
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

fn assert_schema_property_types(
    property_schema: &Value,
    label: &str,
    property: &str,
    expected_types: &[&str],
) -> Result<()> {
    let actual_types = property_schema
        .get("type")
        .and_then(Value::as_array)
        .with_context(|| format!("{label}.{property} must set type array: {property_schema:?}"))?;
    let actual_types = actual_types
        .iter()
        .map(|value| {
            value
                .as_str()
                .with_context(|| format!("{label}.{property} type values must be strings"))
        })
        .collect::<Result<Vec<_>>>()?;
    if actual_types != expected_types {
        anyhow::bail!(
            "{label}.{property} type mismatch; expected {expected_types:?}, got {actual_types:?}"
        );
    }
    Ok(())
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
sandbox_mode=
json_seen=false
goals_seen=false
multi_agent_seen=false
prompt_arg=
no_further_delegation=true
worker_reports_json=
audit_reports_json=
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
    --sandbox)
      sandbox_mode="$2"
      shift 2
      ;;
    --output-schema|-c)
      shift 2
      ;;
    --enable)
      case "$2" in
        goals)
          goals_seen=true
          ;;
        multi_agent)
          multi_agent_seen=true
          ;;
      esac
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
if [ "$goals_seen" != "true" ]; then
  echo "missing --enable goals flag" >&2
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
name="$(basename "$report" .json)"
logical_name="$name"
case "$logical_name" in
  *.attempt-*)
    logical_name="${logical_name%%.attempt-*}"
    ;;
esac
expected_o1_prefix="ROLE: O1_CHILD_ORCHESTRATOR
AGENT_KIND: child_orchestrator
AGENT_LABEL: $logical_name
PARENT_THREAD_ID: none
THREAD_DEPTH: 1
NO_FURTHER_DELEGATION: false"
case "$prompt_body" in
  "$expected_o1_prefix"*)
    o1_role_prefix=true
    ;;
  *)
    o1_role_prefix=false
    ;;
esac
expected_auditor_prefix="ROLE: REVIEW_AUDITOR
AGENT_KIND: auditor
AGENT_LABEL: $name
PARENT_THREAD_ID: none
THREAD_DEPTH: 2
NO_FURTHER_DELEGATION: true"
case "$prompt_body" in
  "$expected_auditor_prefix"*)
    auditor_role_prefix=true
    ;;
  *)
    auditor_role_prefix=false
    ;;
esac
mkdir -p "$(dirname "$report")"
printf '{"event":"fake-start","worktree":"%s","prompt_from_stdin":%s,"goals":%s,"multi_agent":%s,"o1_role_prefix":%s,"auditor_role_prefix":%s,"sandbox":"%s"}\n' "$worktree" "$prompt_from_stdin" "$goals_seen" "$multi_agent_seen" "$o1_role_prefix" "$auditor_role_prefix" "$sandbox_mode"
edit=true
files_changed_json=
worker_files_changed_json=
worker_validation_status=
worker_status=
worker_accepted=
worker_rejected=
worker_risk=
worker_next=
if [ "$auditor_role_prefix" = "true" ]; then
  child_report_path="$(printf '%s\n' "$prompt_body" | sed -n 's/^- Child report path: //p' | head -n 1)"
  if [ -n "$child_report_path" ] && [ ! -f "$child_report_path" ]; then
    cat > "$report" <<JSON
{
  "id": "$name",
  "role": "auditor",
  "reviewed_worker_ids": [],
  "reviewed_paths": [],
  "commands_run": [],
  "validation_results": [],
  "findings": [
    {"severity": "error", "message": "canonical child report was missing before parent audit", "paths": ["$child_report_path"]}
  ],
  "no_further_delegation": true,
  "read_only": true,
  "accepted": false,
  "rejected": true,
  "status": "failed",
  "remaining_risk": "canonical child report missing",
  "next_safe_action": "write canonical report before launching parent auditor"
}
JSON
    exit 0
  fi
  child_name="$name"
  case "$child_name" in
    *-review-auditor)
      child_name="${child_name%-review-auditor}"
      ;;
  esac
  case "$child_name" in
    child-b)
      path="src/lib.rs"
      worker="worker-b"
      ;;
    child-auditor-missing)
      path="README.md"
      worker="worker-auditor-missing"
      ;;
    child-invalid-auditor)
      path="README.md"
      worker="worker-invalid-auditor"
      ;;
    child-auditor-path-mismatch)
      path="README.md"
      worker="worker-auditor-path-mismatch"
      ;;
    child-auditor-evidence-missing)
      path="README.md"
      worker="worker-auditor-evidence-missing"
      ;;
    child-fail)
      path="README.md"
      worker="worker-fail"
      ;;
    child-delegated)
      path="README.md"
      worker="worker-delegated"
      ;;
    child-omits-workers)
      path="README.md"
      worker="worker-omitted"
      ;;
    child-unauthorized)
      path="README.md"
      worker="child-unauthorized"
      ;;
    child-omits-assigned)
      path="README.md"
      worker="child-omits-assigned"
      ;;
    child-assigned-only)
      path="README.md"
      worker="child-assigned-only"
      ;;
    child-generated)
      path="README.md"
      worker="child-generated"
      ;;
    child-primary-mutation)
      path="README.md"
      worker="child-primary-mutation"
      ;;
    child-retry-shape)
      path="README.md"
      worker="child-retry-shape"
      ;;
    child-retry-shape-diff)
      path="README.md"
      worker="child-retry-shape-diff"
      ;;
    child-retry-shape-unauthorized)
      path="README.md"
      worker="child-retry-shape-unauthorized"
      ;;
    child-worker-outside)
      path="README.md"
      worker="worker-worker-outside"
      reviewed_paths_json='["README.md", "src/lib.rs"]'
      ;;
    child-worker-extra-self-authorized)
      path="README.md"
      worker="worker-extra-assigned"
      ;;
    child-worker-union-mismatch)
      path="README.md"
      worker="worker-worker-union-mismatch"
      ;;
    child-worker-failed-accepted)
      path="README.md"
      worker="worker-worker-failed-accepted"
      ;;
    child-primary-mid-commit)
      path="README.md"
      worker="child-primary-mid-commit"
      ;;
    *)
      path="README.md"
      worker="worker-a"
      ;;
  esac
  if [ -z "${reviewed_paths_json:-}" ]; then
    reviewed_paths_json='["'"$path"'"]'
  fi
  if [ "$name" = "child-auditor-missing-review-auditor" ]; then
    exit 0
  fi
  if [ "$name" = "child-invalid-auditor-review-auditor" ]; then
    cat > "$report" <<JSON
{
  "id": "$name",
  "role": "auditor",
  "reviewed_worker_ids": ["$worker"],
  "commands_run": [],
  "validation_results": [],
  "findings": [],
  "no_further_delegation": true,
  "read_only": true,
  "accepted": true,
  "rejected": false,
  "status": "succeeded"
}
JSON
    exit 0
  fi
  if [ "$name" = "child-auditor-evidence-missing-review-auditor" ]; then
    cat > "$report" <<JSON
{
  "id": "$name",
  "role": "auditor",
  "reviewed_worker_ids": ["$worker"],
  "reviewed_paths": $reviewed_paths_json,
  "findings": [],
  "no_further_delegation": true,
  "read_only": true,
  "accepted": true,
  "rejected": false,
  "status": "succeeded",
  "remaining_risk": "none",
  "next_safe_action": "review audited diff"
}
JSON
    exit 0
  fi
  cat > "$report" <<JSON
{
  "id": "$name",
  "role": "auditor",
  "reviewed_worker_ids": ["$worker"],
  "reviewed_paths": $reviewed_paths_json,
  "commands_run": [],
  "validation_results": [
    {"name": "fake parent auditor validation", "status": "succeeded", "command": [], "message": null}
  ],
  "findings": [],
  "no_further_delegation": true,
  "read_only": true,
  "accepted": true,
  "rejected": false,
  "status": "succeeded",
  "remaining_risk": "none",
  "next_safe_action": "review audited diff"
}
JSON
  exit 0
fi
case "$logical_name" in
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
    worker_reports_json='[]'
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
  child-auditor-missing)
    path="README.md"
    edit_path="README.md"
    worker="worker-auditor-missing"
    ;;
  child-invalid-auditor)
    path="README.md"
    edit_path="README.md"
    worker="worker-invalid-auditor"
    ;;
  child-auditor-path-mismatch)
    path="src/lib.rs"
    edit_path="src/lib.rs"
    worker="worker-auditor-path-mismatch"
    ;;
  child-auditor-evidence-missing)
    path="README.md"
    edit_path="README.md"
    worker="worker-auditor-evidence-missing"
    ;;
  child-generated)
    path="README.md"
    edit_path="README.md"
    worker="worker-generated"
    worker_reports_json='[]'
    ;;
  child-omits-assigned)
    path="README.md"
    edit_path="README.md"
    worker="worker-omits-assigned"
    files_changed_json='[]'
    worker_reports_json='[]'
    ;;
  child-assigned-only)
    path="README.md"
    edit_path="README.md"
    worker="worker-assigned-only"
    worker_reports_json='[]'
    ;;
  child-primary-mutation)
    path="README.md"
    edit_path="README.md"
    worker="worker-primary-mutation"
    worker_reports_json='[]'
    ;;
  child-retry-shape)
    path="README.md"
    edit_path="README.md"
    worker="worker-retry-shape"
    worker_reports_json='[]'
    ;;
  child-retry-shape-diff)
    path="README.md"
    edit_path="README.md"
    worker="worker-retry-shape-diff"
    worker_reports_json='[]'
    ;;
  child-retry-shape-unauthorized)
    path="README.md"
    edit_path="src/lib.rs"
    worker="worker-retry-shape-unauthorized"
    worker_reports_json='[]'
    ;;
  child-worker-outside)
    path="README.md"
    edit_path="src/lib.rs"
    worker="worker-worker-outside"
    files_changed_json='["src/lib.rs"]'
    worker_files_changed_json='["src/lib.rs"]'
    ;;
  child-worker-extra-self-authorized)
    path="README.md"
    edit_path="README.md"
    worker="worker-extra-assigned"
    files_changed_json='["README.md"]'
    ;;
  child-worker-union-mismatch)
    path="README.md"
    edit_path="README.md"
    worker="worker-worker-union-mismatch"
    files_changed_json='["README.md"]'
    worker_files_changed_json='[]'
    ;;
  child-worker-failed-accepted)
    path="README.md"
    edit_path="README.md"
    worker="worker-worker-failed-accepted"
    worker_validation_status="failed"
    worker_status="succeeded"
    worker_accepted="true"
    worker_rejected="false"
    worker_risk="worker validation failed despite accepted success"
    worker_next="fix worker validation evidence"
    ;;
  child-primary-mid-commit)
    path="README.md"
    edit_path="README.md"
    worker="worker-primary-mid-commit"
    worker_reports_json='[]'
    ;;
  child-clean)
    path="README.md"
    edit_path="README.md"
    worker="worker-clean"
    edit=false
    files_changed_json='[]'
    worker_reports_json='[]'
    ;;
  *)
    path="README.md"
    edit_path="README.md"
    worker="worker-a"
    ;;
esac
if [ "$logical_name" = "child-missing" ]; then
  exit 0
fi
case "$logical_name" in
  child-retry-shape|child-retry-shape-diff|child-retry-shape-unauthorized)
  case "$name" in
    *.attempt-1)
      if [ "$logical_name" != "child-retry-shape" ]; then
        mkdir -p "$(dirname "$worktree/$edit_path")"
        printf '\nfirst malformed attempt change from %s\n' "$name" >> "$worktree/$edit_path"
      fi
      printf 'not a usable report from first attempt\n{broken\n' > "$report"
      exit 0
      ;;
  esac
  ;;
esac
if [ -z "$files_changed_json" ]; then
  files_changed_json='["'"$path"'"]'
fi
if [ "$edit" = "true" ]; then
  mkdir -p "$(dirname "$worktree/$edit_path")"
  printf '\nfake change from %s\n' "$name" >> "$worktree/$edit_path"
fi
if [ "$logical_name" = "child-primary-mutation" ]; then
  primary="${report%%/.maco/o2/runs/*}"
  printf '\nprimary mutation from %s\n' "$name" >> "$primary/README.md"
fi
if [ "$logical_name" = "child-primary-mid-commit" ]; then
  primary="${report%%/.maco/o2/runs/*}"
  printf 'pub fn inbox_mid_run() -> bool { true }\n' > "$primary/src/inbox.rs"
  git -C "$primary" add src/inbox.rs
  git -C "$primary" -c user.name="maco test" -c user.email="maco-test@example.invalid" commit -m "primary mid-run unrelated commit"
fi
if [ "$logical_name" = "child-fail" ]; then
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
if [ -z "$worker_files_changed_json" ]; then
  worker_files_changed_json="$files_changed_json"
fi
if [ -z "$worker_status" ]; then
  worker_status="$status"
fi
if [ -z "$worker_validation_status" ]; then
  worker_validation_status="$worker_status"
fi
if [ -z "$worker_accepted" ]; then
  worker_accepted="$accepted"
fi
if [ -z "$worker_rejected" ]; then
  worker_rejected="$rejected"
fi
if [ -z "$worker_risk" ]; then
  worker_risk="$risk"
fi
if [ -z "$worker_next" ]; then
  worker_next="$next"
fi
if [ "$logical_name" = "child-worker-extra-self-authorized" ]; then
  worker_reports_json=$(cat <<JSON
[
    {
      "id": "worker-extra-assigned",
      "role": "worker",
      "assigned_paths": ["README.md"],
      "semantic_symbols": [],
      "semantic_modules": [],
      "commands_run": [],
      "files_changed": [],
      "validation_results": [
        {"name": "fake worker validation", "status": "succeeded", "command": [], "message": null}
      ],
      "findings": [],
      "no_further_delegation": true,
      "accepted": true,
      "rejected": false,
      "status": "succeeded",
      "remaining_risk": "none",
      "next_safe_action": "review diff"
    },
    {
      "id": "worker-extra-self-authorized",
      "role": "worker",
      "assigned_paths": ["README.md"],
      "semantic_symbols": [],
      "semantic_modules": [],
      "commands_run": [],
      "files_changed": ["README.md"],
      "validation_results": [
        {"name": "fake worker validation", "status": "succeeded", "command": [], "message": null}
      ],
      "findings": [],
      "no_further_delegation": true,
      "accepted": true,
      "rejected": false,
      "status": "succeeded",
      "remaining_risk": "none",
      "next_safe_action": "review diff"
    }
  ]
JSON
)
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
      "files_changed": $worker_files_changed_json,
      "validation_results": [
        {"name": "fake worker validation", "status": "$worker_validation_status", "command": [], "message": null}
      ],
      "findings": [],
      "no_further_delegation": $no_further_delegation,
      "accepted": $worker_accepted,
      "rejected": $worker_rejected,
      "status": "$worker_status",
      "remaining_risk": "$worker_risk",
      "next_safe_action": "$worker_next"
    }
  ]
JSON
)
fi
if [ -z "$audit_reports_json" ]; then
  audit_reports_json='[]'
fi
cat > "$report" <<JSON
{
  "id": "$logical_name",
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
  "audit_reports": $audit_reports_json,
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
