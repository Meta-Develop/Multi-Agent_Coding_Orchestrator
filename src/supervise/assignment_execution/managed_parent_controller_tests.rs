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
