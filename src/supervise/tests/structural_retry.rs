use super::*;

fn sample_worker_report_json_missing_finding_severity() -> String {
    r#"{
  "id": "unit-worker",
  "role": "worker",
  "assigned_paths": ["README.md"],
  "semantic_symbols": [],
  "semantic_modules": [],
  "commands_run": [],
  "environment_failures": [],
  "files_changed": [],
  "validation_results": [],
  "findings": [
    {
      "message": "summary of completed work",
      "paths": []
    }
  ],
  "field_guide_entries": [],
  "bloated_file_flags": [],
  "accepted": true,
  "rejected": false,
  "status": "succeeded",
  "remaining_risk": "none",
  "next_safe_action": "review"
}"#
    .to_string()
}

fn prose_wrapped_worker_report() -> String {
    format!(
        "Summary first.\n{}",
        sample_worker_report_json_missing_finding_severity()
    )
}

fn fixture_head(repo_path: &Path) -> Oid {
    git2::Repository::open(repo_path)
        .expect("open fixture repository")
        .head()
        .expect("read fixture head")
        .target()
        .expect("fixture head oid")
}

fn direct_worker_assignment() -> OrchestratorAssignment {
    let mut assignment = injected_assignment(false);
    assignment.id = "unit-worker".to_string();
    assignment.role = AgentRole::Worker;
    assignment.role_category = Some(RoleCategory::NonDelegatingTerminalWorker);
    assignment
}

fn collect_direct_worker_report(
    assignment: &OrchestratorAssignment,
    command: &ExternalAgentCommand,
    external_run: &ExternalAgentRun,
    child_base_head: &Oid,
) -> (OrchestratorReviewReport, Vec<String>) {
    collect_child_report(ChildReportCollectionContext {
        assignment,
        assignment_metadata: &AssignmentMetadata::new(),
        report_path: Path::new("unit-worker.raw.json"),
        external_run,
        external_command: command,
        worktree_path: Path::new("."),
        child_base_head,
        observed_changed_paths: Some(&[]),
        worker_journals: &WorkerExecutionJournalEvidenceSet::default(),
        evidence_only_source: None,
    })
}

#[test]
fn parse_report_json_reports_last_candidate_serde_error() {
    let error = parse_report_json::<WorkerReport>(&prose_wrapped_worker_report())
        .expect_err("worker report without finding severity must not parse");
    let message = error.to_string();
    assert!(
        message.contains("missing field `severity`"),
        "unexpected error: {message}"
    );
    assert!(
        message.contains("report JSON/contract parse failed"),
        "unexpected error: {message}"
    );
    assert!(
        message.contains("lenient JSON extraction did not produce"),
        "unexpected error: {message}"
    );
}

#[test]
fn direct_worker_invalid_captured_report_gets_structural_retry() {
    let (temp, repo_path) = injected_repository();
    let assignment = direct_worker_assignment();
    let command = ExternalAgentCommand::codex(
        "codex",
        &repo_path,
        temp.path().join("structural-retry-prompt.md"),
        temp.path().join("structural-retry-events.jsonl"),
        temp.path().join("structural-retry-report.json"),
        Duration::from_secs(1),
    );
    fs::write(&command.output_last_message, prose_wrapped_worker_report())
        .expect("write invalid direct worker report");
    let external_run = injected_verified_run(&command);
    let (report, problems) = collect_direct_worker_report(
        &assignment,
        &command,
        &external_run,
        &fixture_head(&repo_path),
    );
    assert!(!problems.is_empty(), "shape problems must be recorded");
    assert!(
        problems.iter().any(|problem| problem.contains("severity")),
        "shape problems must retain the contract error: {problems:?}"
    );
    assert!(should_retry_child_report(&report, &problems, 1, 1));
    assert!(!should_retry_child_report(&report, &problems, 2, 1));
}

#[test]
fn direct_worker_without_captured_report_gets_no_structural_retry() {
    let (temp, repo_path) = injected_repository();
    let assignment = direct_worker_assignment();
    let command = ExternalAgentCommand::codex(
        "codex",
        &repo_path,
        temp.path().join("no-capture-prompt.md"),
        temp.path().join("no-capture-events.jsonl"),
        temp.path().join("no-capture-report.json"),
        Duration::from_secs(1),
    );
    let external_run = injected_verified_run(&command);
    let (report, problems) = collect_direct_worker_report(
        &assignment,
        &command,
        &external_run,
        &fixture_head(&repo_path),
    );
    assert!(
        problems.iter().any(|problem| problem
            .contains("external run did not capture a descriptor-held direct worker report")),
        "missing capture must be recorded: {problems:?}"
    );
    assert!(!should_retry_child_report(&report, &problems, 1, 1));
}

#[test]
fn direct_worker_structural_retry_blocked_by_unrelated_error_finding() {
    let (temp, repo_path) = injected_repository();
    let assignment = direct_worker_assignment();
    let command = ExternalAgentCommand::codex(
        "codex",
        &repo_path,
        temp.path().join("unrelated-error-prompt.md"),
        temp.path().join("unrelated-error-events.jsonl"),
        temp.path().join("unrelated-error-report.json"),
        Duration::from_secs(1),
    );
    fs::write(&command.output_last_message, prose_wrapped_worker_report())
        .expect("write invalid direct worker report");
    let external_run = injected_verified_run(&command);
    let (mut report, problems) = collect_direct_worker_report(
        &assignment,
        &command,
        &external_run,
        &fixture_head(&repo_path),
    );
    report.findings.push(Finding {
        severity: FindingSeverity::Error,
        message: "validation failed: cargo test".to_string(),
        paths: Vec::new(),
    });
    assert!(!should_retry_child_report(&report, &problems, 1, 1));
}

#[test]
fn prompt_with_structural_retry_names_report_type_and_problems() {
    let prompt = prompt_with_structural_retry(
        "BASE",
        "WorkerReport",
        &[
            "missing field `severity` at line 1 column 523".to_string(),
            "invalid value: string \"project-local\" for remediation scope".to_string(),
        ],
    );
    assert!(prompt.contains("STRUCTURAL REPORT RETRY:"));
    assert!(prompt.contains("missing field `severity` at line 1 column 523"));
    assert!(prompt.contains("invalid value: string \"project-local\" for remediation scope"));
    assert!(prompt.contains("compliant WorkerReport JSON"));
    assert!(!prompt.contains("OrchestratorReviewReport"));
}

#[test]
fn prompt_with_structural_retry_preserves_orchestrator_prompt() {
    let problems = [
        "missing field `severity` at line 1 column 523".to_string(),
        "report does not match assignment".to_string(),
    ];
    let prompt = prompt_with_structural_retry("BASE", "OrchestratorReviewReport", &problems);
    assert_eq!(
        prompt,
        concat!(
            "BASE\n\nSTRUCTURAL REPORT RETRY:\n",
            "The previous response did not satisfy the trusted report schema.\n\n",
            "Return only a compliant OrchestratorReviewReport JSON final response matching the schema. Do not include Markdown fences, prose, or any non-JSON wrapper.\n"
        )
    );
    for problem in problems {
        assert!(!prompt.contains(&problem));
    }
}

#[test]
fn prompt_with_structural_retry_lists_at_most_eight_truncated_problems() {
    let problems: Vec<String> = (0..20)
        .map(|index| format!("problem-{index:02}-{}", "x".repeat(5000)))
        .collect();
    let prompt = prompt_with_structural_retry("BASE", "WorkerReport", &problems);
    let listed = prompt
        .split("Problems found by the supervisor:\n")
        .nth(1)
        .expect("problems heading")
        .split("If your earlier changes are present in the worktree")
        .next()
        .expect("keep-changes sentence");
    let entries: Vec<&str> = listed
        .lines()
        .filter(|line| line.starts_with("- "))
        .collect();
    assert_eq!(entries.len(), 8, "exactly eight problems must be listed");
    for entry in entries {
        let problem = entry.strip_prefix("- ").expect("problem entry");
        assert!(
            problem.len() <= 1000,
            "listed problem must be truncated to at most 1000 bytes"
        );
        assert!(problem.starts_with("problem-"));
    }
}
