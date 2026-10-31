use super::*;
use crate::external_agent::{
    CapturedOutput, CodexParentEvidence, CodexParentResolvedField, CodexParentTurnUsage,
};

pub(super) const CHECKPOINT_FAILURE_CASE: &str = "managed-cycle-isolated-interrupted-checkpoint";
pub(super) const JOURNAL_FAILURE_CASE: &str = "managed-cycle-isolated-interrupted-journal-failure";

pub(super) fn interrupt_returned_worker(
    case: &str,
    command: &ExternalAgentCommand,
    cancellation: &ProcessCancellation,
    subject: &OrchestratorAssignment,
    run: &mut ExternalAgentRun,
) {
    if subject.id == "parent" {
        run.stdout = CapturedOutput::from_captured_bytes_for_test(
            &crate::process_runner::CapturedBytes::from_bytes_for_test(
                b"{\"type\":\"turn.completed\",\"usage\":{\"input_tokens\":43043,\"output_tokens\":190}}\n".to_vec(),
            ),
        );
        run.stdout.target_launch_attempted = true;
        return;
    }
    assert_eq!(
        subject.id, "worker",
        "Worker 2 must be refused before invocation"
    );
    let grant = command.live_token_grant_for_test().unwrap();
    assert_eq!(grant.tokens(), 21_767);
    grant.exhaust();
    cancellation.cancel();
    if case.ends_with("empty") {
        fs::write(command.cwd.join("src/lib.rs"), "pub fn selected() {}\n").unwrap();
    } else {
        fs::write(command.cwd.join("src/lib.rs"), "// partial worker repair\n").unwrap();
    }
    let mut captures = run.worker_journal_artifacts().to_vec();
    let journal = json!({
        "command":["fixture-inspect"], "cwd":command.cwd,
        "start_timestamp":"fixture-start", "end_timestamp":"fixture-end",
        "changed_paths":if case.ends_with("empty") { Vec::<String>::new() } else { vec!["src/lib.rs".into()] }
    });
    captures[0].status = crate::external_agent::WorkerJournalArtifactCaptureStatus::Loaded(
        serde_json::to_vec(&journal).unwrap(),
    );
    if case == CHECKPOINT_FAILURE_CASE || case == JOURNAL_FAILURE_CASE {
        // Preserve real source bytes as well as the returned descriptor capture.
        fs::write(&captures[0].path, serde_json::to_vec(&journal).unwrap()).unwrap();
    }
    let mut raw = Vec::new();
    for (input, output) in [(18_965, 360), (38_557, 564)] {
        raw.extend(
            serde_json::to_vec(&json!({
                "method":"thread/tokenUsage/updated", "params":{
                    "threadId":"worker-thread", "turnId":"worker-turn", "tokenUsage":{"total":{
                        "inputTokens":input, "outputTokens":output, "cachedInputTokens":0,
                        "reasoningOutputTokens":0, "totalTokens":input + output}}}
            }))
            .unwrap(),
        );
        raw.push(b'\n');
    }
    raw.extend_from_slice(b"{\"id\":4,\"result\":{}}\n{\"method\":\"turn/completed\",\"params\":{\"threadId\":\"worker-thread\",\"turn\":{\"id\":\"worker-turn\",\"status\":\"interrupted\",\"error\":null}}}\n");
    run.stdout = CapturedOutput::from_captured_bytes_for_test(
        &crate::process_runner::CapturedBytes::from_bytes_for_test(raw),
    );
    run.stdout.target_launch_attempted = true;
    run.replace_worker_journal_artifacts(captures);
    run.codex_parent_evidence = Some(CodexParentEvidence {
        codex_version: Some("0.162.0".into()),
        thread_id: Some("worker-thread".into()),
        requested_model: command.model.clone(),
        requested_effort: command.reasoning_effort.clone(),
        rollout_model: CodexParentResolvedField::Unknown,
        rollout_effort: CodexParentResolvedField::Unknown,
        observed_model: CodexParentResolvedField::Known(command.model.clone().unwrap()),
        observed_effort: CodexParentResolvedField::Known(command.reasoning_effort.clone().unwrap()),
        server_rerouted_model: None,
        model_mismatch: false,
        turn_usage: CodexParentTurnUsage::Known {
            input_tokens: 38_557,
            output_tokens: 564,
            cached_input_tokens: 19_200,
            reasoning_output_tokens: 125,
        },
        resolution_status: "turn_failed".into(),
    });
    run.exit_code = Some(255);
    run.error = Some("Codex app-server token grant exhausted: 39121 >= 21767".into());
    run.publishable = false;
    run.output_last_message = Some(
        if case.ends_with("malformed") || case == JOURNAL_FAILURE_CASE {
            b"{partial".to_vec()
        } else {
            Vec::new()
        },
    );
    run.retain_app_server_parent_evidence_for_test();
    run.retain_live_budget_invocation_for_test(command);
    assert!(!run.authenticated_app_server_usage_complete());
    if case == CHECKPOINT_FAILURE_CASE {
        super::super::checkpoint::install_checkpoint_failure(
            &command.agent_lifecycle.as_ref().unwrap().run_id,
            "child_dispatch_completed",
        );
    }
}

pub(super) fn check_interrupted_result(
    case: &str,
    context: &AssignmentExecutionContext<'_, '_>,
    preflight: &AssignmentExecutionPreflight<'_>,
    outcome: &AssignmentExecutionOutcome,
    result: Result<CollectedChildAttempt<'_>>,
    observed: &[String],
) -> Result<()> {
    assert!(result.is_err(), "interrupted candidate was accepted");
    assert!(outcome.assignment_failed);
    assert!(outcome.usage_incomplete);
    assert_eq!(observed, ["parent", "worker"]);
    let budget = context.budget_ledger.report()?;
    assert_eq!(budget.consumed.tokens, 82_354);
    assert_eq!(budget.charges.len(), 2);
    assert_eq!(budget.charges[0].tokens, 43_233);
    assert!(budget.charges[0].usage_complete);
    assert_eq!(budget.charges[1].tokens, 39_121);
    assert!(!budget.charges[1].usage_complete);
    assert!(!budget.usage_complete);
    assert!(!budget.new_dispatch_allowed);
    assert_eq!(budget.active_reservations, 0);
    assert_eq!(budget.reserved.tokens, 0);
    assert!(outcome.gate_denials.iter().any(|denial| {
        denial.context.owner == "worker-two"
            && matches!(denial.reason, GateDenialReason::BudgetAdmission { .. })
    }));
    assert_eq!(
        context.sync_store.snapshot()?,
        vec![preflight.claim.clone()]
    );
    assert_eq!(
        fs::read_to_string(context.repo.join("src/lib.rs"))?,
        "pub fn selected() {}\n"
    );
    assert_eq!(
        fs::read_to_string(preflight.worktree.path.join("src/lib.rs"))?,
        "pub fn selected() {}\n"
    );

    let (incoming_name, capture_name) = invocation_scratch_names(1, 1, false, true);
    let source_journal = context
        .run_dir
        .join(&incoming_name)
        .join("worker-journals/worker.jsonl");
    if case == CHECKPOINT_FAILURE_CASE || case == JOURNAL_FAILURE_CASE {
        let error = format!("{:#}", result.as_ref().err().unwrap());
        if case == CHECKPOINT_FAILURE_CASE {
            assert!(
                error.contains("injected supervise checkpoint failure"),
                "{error}"
            );
            assert!(
                context
                    .run_dir
                    .join("logs/workers/worker/worker.jsonl")
                    .is_file(),
                "checkpoint failure bypassed Worker journal retention"
            );
        } else {
            assert!(
                error.contains("isolated Worker evidence retention failed: journals:"),
                "{error}"
            );
            assert!(!context
                .run_dir
                .join("logs/workers/worker/worker.jsonl")
                .is_file());
        }
        assert!(
            source_journal.is_file(),
            "failed retention deleted the source journal"
        );
        assert!(
            context.run_dir.join(&capture_name).is_dir(),
            "failed retention deleted capture scratch"
        );
        assert!(context.run_dir.join("logs/worker.jsonl").is_file());
    }
    let raw_report = Path::new("evidence/incoming/worker.json");
    let manifest_path = raw_report.with_extension("candidate.json");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(context.run_dir.join(&manifest_path))?)?;
    assert_eq!(manifest["assignment_id"], "worker");
    assert_eq!(manifest["reservation_id"], budget.charges[1].reservation_id);
    assert_eq!(
        manifest["base_commit"],
        preflight.child_base_head.to_string()
    );
    assert_eq!(manifest["review_status"], "pending");
    assert_eq!(manifest["acceptance_authority"], false);
    let journal_path = manifest["worker_journal"].as_str().unwrap();
    let retained_journal = if case == JOURNAL_FAILURE_CASE {
        source_journal
    } else {
        context.run_dir.join(journal_path)
    };
    let entries = parse_worker_execution_journal(&fs::read(&retained_journal)?, &retained_journal)?;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].command, ["fixture-inspect"]);
    let patch_path = manifest["patch"]["path"].as_str().unwrap();
    let patch = fs::read(context.run_dir.join(patch_path))?;
    assert_eq!(
        manifest["patch"]["sha256"],
        crate::artifacts::state_auth::sha256_hex(&patch)
    );
    let review_dir = tempfile::tempdir()?;
    let review = git2::Repository::clone(context.repo.to_str().unwrap(), review_dir.path())?;
    if !patch.is_empty() {
        review.apply(
            &git2::Diff::from_buffer(&patch)?,
            git2::ApplyLocation::WorkDir,
            None,
        )?;
    }
    let expected = if case.ends_with("empty") {
        "pub fn selected() {}\n"
    } else {
        "// partial worker repair\n"
    };
    assert_eq!(
        fs::read_to_string(review_dir.path().join("src/lib.rs"))?,
        expected
    );
    let mut index = review.index()?;
    index.add_all(["*"], git2::IndexAddOption::DEFAULT, None)?;
    assert_eq!(manifest["candidate_tree"], index.write_tree()?.to_string());
    // Independent check on the reconstructed candidate, including the unchanged
    // seed case. A stopped Worker supplies neither this test nor its outcome.
    let review_result = std::process::Command::new("python3").args(["-B", "-c", "import pathlib, unittest\nclass Review(unittest.TestCase):\n def test_repair_complete(self):\n  self.assertIn('// completed worker repair', pathlib.Path('src/lib.rs').read_text())\nunittest.main()\n"])
        .current_dir(review_dir.path()).output()?;
    assert!(!review_result.status.success());
    assert!(String::from_utf8_lossy(&review_result.stderr).contains("FAILED (failures=1)"));
    let expected_report: &[u8] = if case.ends_with("malformed") || case == JOURNAL_FAILURE_CASE {
        b"{partial"
    } else {
        b""
    };
    assert_eq!(fs::read(context.run_dir.join(raw_report))?, expected_report);
    Ok(())
}

#[test]
fn interrupted_worker_without_report_retains_unchanged_candidate_and_journals() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-isolated-interrupted-empty")
}

#[test]
fn interrupted_worker_partial_candidate_can_be_independently_reviewed_and_rejected() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-isolated-interrupted-partial")
}

#[test]
fn interrupted_worker_malformed_report_cannot_hide_candidate_or_journals() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-isolated-interrupted-malformed")
}

#[test]
fn interrupted_worker_checkpoint_failure_retains_candidate_journal_report_and_source() -> Result<()>
{
    super::nested_driver_tests::driver_fixture(CHECKPOINT_FAILURE_CASE)
}

#[test]
fn interrupted_worker_journal_retention_failure_preserves_source_and_other_evidence() -> Result<()>
{
    super::nested_driver_tests::driver_fixture(JOURNAL_FAILURE_CASE)
}
