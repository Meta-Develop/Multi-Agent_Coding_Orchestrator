use super::*;
use crate::messaging::transport::{
    AssignmentMessagingLaunch, ENV_MESSAGE_ENDPOINT, ENV_MESSAGE_TOKEN,
};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;

pub(super) fn submit_worker_request(
    launch: &AssignmentMessagingLaunch,
    run: &str,
    request: &str,
    worker: &str,
    read_response: bool,
) -> Result<()> {
    let env: BTreeMap<_, _> = launch.environment_for(run, "parent")?.into_iter().collect();
    let mut stream = TcpStream::connect(&env[ENV_MESSAGE_ENDPOINT])?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    if read_response {
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    }
    writeln!(
        stream,
        "{}",
        json!({"bearer":env[ENV_MESSAGE_TOKEN], "request":{
            "operation":"submit_worker_request", "request_id":request, "worker_id":worker
        }})
    )?;
    stream.flush()?;
    if read_response {
        let mut response = String::new();
        BufReader::new(stream).read_line(&mut response)?;
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&response)?["ok"],
            true
        );
    }
    Ok(())
}

fn held_resources(
    context: &AssignmentExecutionContext<'_, '_>,
    preflight: &AssignmentExecutionPreflight<'_>,
) -> Result<()> {
    assert!(preflight.worktree_write_lease.is_some());
    assert_eq!(
        context.sync_store.snapshot()?,
        vec![preflight.claim.clone()]
    );
    Ok(())
}

pub(super) fn exercise(
    case: &str,
    context: &AssignmentExecutionContext<'_, '_>,
    preflight: &AssignmentExecutionPreflight<'_>,
    outcome: &mut AssignmentExecutionOutcome,
    prepared: PreparedChildAttempt<'_>,
    calls: &Mutex<Vec<String>>,
) -> Result<()> {
    if case.starts_with("managed-cycle-retained-") {
        return exercise_retained_failure(case, context, preflight, outcome, prepared, calls);
    }
    let schemas = &context.dirs.schemas;
    if case == "managed-cycle-initial-import-error" {
        let report = context
            .run_dir
            .join(&prepared.attempt_artifacts.raw_report_relative);
        if report.exists() {
            bail!(
                "initial evidence report path already exists; refusing to replace it: {}",
                report.display()
            );
        }
        if let Some(parent) = report.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::create_dir(&report)
            .context("plant a directory where the initial evidence file must be imported")?;
    }
    let result = super::managed_parent_controller::dispatch_and_collect_managed_parent_attempt(
        context,
        outcome,
        preflight,
        context.options.run_id.as_str(),
        1,
        prepared,
        &context.budget_policy,
        1,
        &schemas.join("orchestrator-review-report.schema.json"),
        &schemas.join("worker-report.schema.json"),
        &schemas.join("auditor-report.schema.json"),
    );
    let observed = calls.lock().unwrap().clone();
    match case {
        "managed-cycle-happy" | "managed-cycle-lost-reply" => {
            let collected = result?;
            assert!(
                !report_failed(&collected.attempt_report),
                "managed parent collection failed: {:?}",
                collected.attempt_report
            );
            assert!(
                collected.report_shape_problems.is_empty(),
                "managed parent report shape problems: {:?}",
                collected.report_shape_problems
            );
            assert!(collected.attempt_containment_verified);
            assert_eq!(collected._worker_journal_evidence.len(), 2);
            assert!(collected._worker_journal_evidence.contains_key("worker"));
            assert!(collected
                ._worker_journal_evidence
                .contains_key("worker-two"));
            assert_eq!(observed, ["parent", "worker", "worker-two", "parent"]);
            assert!(!outcome.usage_incomplete);
            assert!(outcome
                .usage_samples
                .iter()
                .any(|sample| sample.role == AgentRole::ChildOrchestrator));
            assert!(outcome
                .usage_samples
                .iter()
                .any(|sample| sample.role == AgentRole::Worker));
            let edited = fs::read_to_string(preflight.worktree.path.join("src/lib.rs"))?;
            assert!(
                edited.contains("written by worker-two"),
                "final worktree candidate lost the worker edit: {edited}"
            );
        }
        "managed-cycle-foreign-yield" => {
            assert!(result.is_err(), "foreign yield was accepted");
            assert_eq!(observed, ["parent"]);
        }
        "managed-cycle-cancel-after-first" => {
            assert!(result.is_err(), "cancelled cycle was accepted");
            assert_eq!(observed, ["parent", "worker"]);
        }
        "managed-cycle-initial-import-error" => {
            let error = match result {
                Err(error) => error,
                Ok(_) => bail!("initial evidence import failure was accepted"),
            };
            let text = format!("{error:#}");
            assert!(
                text.to_ascii_lowercase().contains("import"),
                "missing import failure diagnostic: {text}"
            );
            assert_eq!(observed, ["parent", "worker", "worker-two", "parent"]);
            let edited = fs::read_to_string(preflight.worktree.path.join("src/lib.rs"))?;
            assert!(edited.contains("written by worker-two"));
            assert_eq!(
                current_head_oid(&preflight.worktree.path)?,
                preflight.child_base_head
            );
            assert_eq!(
                fs::read_to_string(context.repo.join("src/lib.rs"))?,
                "pub fn selected() {}\n"
            );
        }
        "managed-cycle-final-forgery" => {
            assert!(result.is_err(), "forged final report was accepted");
            assert_eq!(observed, ["parent", "worker", "worker-two", "parent"]);
            let edited = fs::read_to_string(preflight.worktree.path.join("src/lib.rs"))?;
            assert!(edited.contains("written by worker-two"));
            assert_eq!(
                fs::read_to_string(context.repo.join("src/lib.rs"))?,
                "pub fn selected() {}\n"
            );
        }
        other => bail!("unknown managed cycle case {other}"),
    }
    held_resources(context, preflight)?;
    Ok(())
}

#[test]
fn managed_cycle_happy_runs_both_workers_and_final_parent() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-happy")
}

#[test]
fn managed_cycle_lost_reply_retries_the_same_request_once() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-lost-reply")
}

#[test]
fn managed_cycle_foreign_yield_dispatches_no_worker() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-foreign-yield")
}

#[test]
fn managed_cycle_final_forgery_keeps_edits_unmaterialized() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-final-forgery")
}

#[test]
fn managed_cycle_cancel_after_first_skips_worker_two() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-cancel-after-first")
}

#[test]
fn managed_cycle_initial_import_error_keeps_worker_edits_unmaterialized() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-initial-import-error")
}

// Reuse the managed-cycle runner and ownership fixture; only its returned bytes
// and terminal result are injected. Never recover evidence from the writable path.
fn exercise_retained_failure(
    case: &str,
    context: &AssignmentExecutionContext<'_, '_>,
    preflight: &AssignmentExecutionPreflight<'_>,
    outcome: &mut AssignmentExecutionOutcome,
    prepared: PreparedChildAttempt<'_>,
    calls: &Mutex<Vec<String>>,
) -> Result<()> {
    use crate::external_agent::{
        CapturedOutput, CodexParentEvidence, CodexParentResolvedField, CodexParentTurnUsage,
    };
    let checkpoint_failure = case == "managed-cycle-retained-checkpoint-error";
    let continuation_failure = case == "managed-cycle-retained-continuation" || checkpoint_failure;
    let import_failure = case == "managed-cycle-retained-import-error";
    let initial_scratch = prepared.capture_scratch.path().to_path_buf();
    let blocked_raw = context
        .run_dir
        .join(&prepared.attempt_artifacts.raw_stdout_relative);
    if import_failure {
        fs::create_dir_all(blocked_raw.parent().unwrap())?;
        fs::create_dir(&blocked_raw)?;
    }
    let retained = Mutex::new(Vec::<(PathBuf, Vec<u8>)>::new());
    let runner = |command: &ExternalAgentCommand,
                  cancellation: &ProcessCancellation,
                  review: Option<ExternalPreActionReviewRuntime<'_>>| {
        let mut run = (context.external_runner)(command, cancellation, review);
        assert!(run.scratch_quiescence_verified());
        if command.agent_lifecycle.as_ref().unwrap().task_id != "parent" {
            return run;
        }
        let final_turn = command.codex_managed_readonly_continuation_enabled();
        let failed = !continuation_failure && !import_failure;
        let mut raw = serde_json::to_vec(&json!({
            "method":"item/agentMessage/delta", "params":{"delta":"x".repeat(40 * 1024)}
        }))
        .unwrap();
        raw.push(b'\n');
        for (method, status, exit_code) in [
            ("item/started", "inProgress", serde_json::Value::Null),
            ("item/completed", "completed", json!(0)),
        ] {
            raw.extend(
                serde_json::to_vec(&json!({
                    "method":method, "params":{"threadId":"held-parent", "turnId":"held-turn",
                        "item":{"id":"late-command", "type":"commandExecution",
                            "command":"git status --short", "cwd":command.cwd,
                            "status":status,"exitCode":exit_code}}
                }))
                .unwrap(),
            );
            raw.push(b'\n');
        }
        raw.extend(
            serde_json::to_vec(&json!({
                "method":"thread/tokenUsage/updated", "params":{
                    "threadId":"held-parent", "turnId":"held-turn", "tokenUsage":{"total":{
                        "inputTokens":35000,"outputTokens":2000,"cachedInputTokens":0,
                        "reasoningOutputTokens":0,"totalTokens":37000}}}
            }))
            .unwrap(),
        );
        raw.push(b'\n');
        let journals = run.worker_journal_artifacts().to_vec();
        run.stdout = CapturedOutput::from_captured_bytes_for_test(
            &crate::process_runner::CapturedBytes::from_bytes_for_test(raw.clone()),
        );
        run.stdout.target_launch_attempted = true;
        run.replace_worker_journal_artifacts(journals);
        run.codex_parent_evidence = Some(CodexParentEvidence {
            codex_version: Some("0.144.4".into()),
            thread_id: Some("held-parent".into()),
            requested_model: command.model.clone(),
            requested_effort: command.reasoning_effort.clone(),
            rollout_model: CodexParentResolvedField::Unknown,
            rollout_effort: CodexParentResolvedField::Unknown,
            observed_model: CodexParentResolvedField::Known("gpt-5.6-sol".into()),
            observed_effort: CodexParentResolvedField::Known("high".into()),
            server_rerouted_model: None,
            model_mismatch: false,
            turn_usage: CodexParentTurnUsage::Known {
                input_tokens: 35_000,
                output_tokens: 2_000,
                cached_input_tokens: 0,
                reasoning_output_tokens: 0,
            },
            resolution_status: if failed { "turn_failed" } else { "complete" }.into(),
        });
        run.retain_app_server_parent_evidence_for_test();
        assert!(!run.stdout.text.contains("late-command"));
        let relative = PathBuf::from("logs").join(command.json_log.file_name().unwrap());
        retained.lock().unwrap().push((relative, raw));
        if failed {
            run.publishable = false;
            run.output_last_message = None;
            match case {
                "managed-cycle-retained-timeout" => run.timed_out = true,
                "managed-cycle-retained-cancel" => {
                    cancellation.cancel();
                    run.error = Some("injected cancelled app-server turn".into());
                }
                "managed-cycle-retained-protocol" => {
                    run.error = Some("injected app-server protocol loss".into());
                }
                _ => panic!("unknown retained failure case"),
            }
            assert!(!external_process_completed(&run, SupervisorRuntime::Codex));
            assert!(!run.publishable);
        } else if final_turn && checkpoint_failure {
            let budget = context
                .budget_ledger
                .report()
                .expect("healthy ledger before return");
            assert_eq!(budget.consumed.tokens, 37_028);
            assert_eq!(budget.reserved.tokens, 2);
            assert_eq!(budget.active_reservations, 1);
            super::super::checkpoint::install_checkpoint_failure(
                context.options.run_id.as_str(),
                "child_dispatch_completed",
            );
        } else if final_turn {
            // A valid envelope at the writable path must not rescue malformed
            // descriptor-held bytes or confer acceptance during evidence retention.
            fs::write(
                &command.output_last_message,
                run.output_last_message().unwrap(),
            )
            .expect("write conflicting valid continuation envelope");
            run.output_last_message = Some(b"{malformed continuation".to_vec());
        }
        run
    };
    let wrapped = AssignmentExecutionContext {
        external_runner: &runner,
        budget_policy: context.budget_policy.clone(),
        admission_commit: context.admission_commit.clone(),
        cancellation: context.cancellation.clone(),
        ..*context
    };
    let schemas = &context.dirs.schemas;
    let result = super::managed_parent_controller::dispatch_and_collect_managed_parent_attempt(
        &wrapped,
        outcome,
        preflight,
        context.options.run_id.as_str(),
        1,
        prepared,
        &context.budget_policy,
        1,
        &schemas.join("orchestrator-review-report.schema.json"),
        &schemas.join("worker-report.schema.json"),
        &schemas.join("auditor-report.schema.json"),
    );
    let error = match result {
        Err(error) => error,
        Ok(_) => bail!("failed parent capture was accepted or materialized"),
    };
    if import_failure {
        assert!(format!("{error:#}").contains("evidence import"));
    }
    if checkpoint_failure {
        assert!(
            format!("{error:#}").contains(
                "injected supervise checkpoint failure before phase 'child_dispatch_completed'"
            ),
            "continuation failed before the injected checkpoint boundary: {error:#}"
        );
    }
    assert!(
        outcome.report.is_none(),
        "no accepted report may be published"
    );
    assert!(
        outcome.candidate_inspection.is_none(),
        "no publishable candidate"
    );
    let observed = calls.lock().unwrap().clone();
    if continuation_failure {
        assert_eq!(observed, ["parent", "worker", "worker-two", "parent"]);
    } else {
        assert_eq!(observed, ["parent"], "dispatch continued after refusal");
    }
    assert_eq!(
        current_head_oid(&preflight.worktree.path)?,
        preflight.child_base_head
    );
    assert_eq!(
        fs::read_to_string(context.repo.join("src/lib.rs"))?,
        "pub fn selected() {}\n"
    );
    let budget = context.budget_ledger.report()?;
    assert_eq!(
        budget.consumed.tokens,
        if continuation_failure { 74_028 } else { 37_000 }
    );
    assert_eq!(budget.reserved.tokens, 0);
    assert_eq!(budget.active_reservations, 0);
    if !continuation_failure && !import_failure {
        assert!(outcome.usage_incomplete);
    }
    // Exercise the same identity-bound terminal cleanup used by the scheduler,
    // only after every injected returned process proved quiescent above.
    with_supervisor_artifacts(context.artifacts, |writer, _| {
        writer.discard_supervisor_invocation_scratches_after_quiescence(
            crate::artifacts::ArtifactScratchQuiescence::Verified,
        )?;
        Ok(())
    })?;
    assert!(!initial_scratch.exists());
    if !import_failure {
        for (relative, raw) in retained.lock().unwrap().iter() {
            let imported = fs::read(context.run_dir.join(relative))?;
            assert_eq!(&imported, raw);
            let late = imported
                .windows(b"late-command".len())
                .position(|window| window == b"late-command")
                .unwrap();
            assert!(late > 32 * 1024);
        }
    }
    held_resources(context, preflight)?;
    Ok(())
}

#[test]
fn managed_cycle_timeout_retains_private_tail_after_terminal_cleanup() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-retained-timeout")
}

#[test]
fn managed_cycle_cancellation_retains_private_tail_after_terminal_cleanup() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-retained-cancel")
}

#[test]
fn managed_cycle_protocol_failure_retains_private_tail_after_terminal_cleanup() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-retained-protocol")
}

#[test]
fn managed_cycle_malformed_continuation_retains_private_tail_after_terminal_cleanup() -> Result<()>
{
    super::nested_driver_tests::driver_fixture("managed-cycle-retained-continuation")
}

#[test]
fn managed_cycle_continuation_checkpoint_failure_settles_once_and_retains_private_tail(
) -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-retained-checkpoint-error")
}

#[test]
fn managed_cycle_returned_import_error_settles_once_and_stops_dispatch() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-retained-import-error")
}
