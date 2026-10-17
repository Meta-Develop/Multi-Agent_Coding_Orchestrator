use super::*;
use crate::artifacts::repository_authenticator_key_only;
use crate::supervise::messaging_bridge::{
    with_supervisor_messaging_session,
    worker_requests::{
        frozen::{WorkerInboxEndpoint, WorkerInboxResources, WorkerInboxShutdown, WorkerInboxTurn},
        WorkerRequestBinding, WorkerRequestInbox,
    },
};

fn recover_while_held(repo: &Path, binding: &WorkerRequestBinding) -> Result<()> {
    match WorkerRequestInbox::recover(repository_authenticator_key_only(repo)?, binding.clone()) {
        Err(_) => Ok(()),
        Ok(_) => bail!("inbox recovery acquired the journal while attached capture still owned it"),
    }
}

pub(super) fn exercise<'budget>(
    case: &str,
    context: &AssignmentExecutionContext<'budget, '_>,
    preflight: &AssignmentExecutionPreflight<'_>,
    outcome: &mut AssignmentExecutionOutcome,
    mut prepared: Box<PreparedChildAttempt<'budget>>,
) -> Result<()> {
    // The typed lock refusal carries the exact journal derived from this binding.
    // Missing/corrupt state is never evidence that an owner retained the lock.
    fn held_inbox_journal(repo: &Path, binding: &WorkerRequestBinding) -> Result<PathBuf> {
        let error =
            WorkerRequestInbox::recover(repository_authenticator_key_only(repo)?, binding.clone())
                .err()
                .context(
                    "inbox recovery acquired the journal while attached capture still owned it",
                )?;
        match error.downcast_ref::<crate::messaging::store::StoreError>() {
            Some(crate::messaging::store::StoreError::WriterAlreadyActive { path }) => {
                Ok(path.clone())
            }
            _ => Err(error).context("expected the exact parent inbox journal lock refusal"),
        }
    }

    let incoming_scratch = prepared.incoming_scratch.path().to_path_buf();
    let capture_scratch = prepared.capture_scratch.path().to_path_buf();
    let binding = with_supervisor_messaging_session(context.run_dir, |factory| {
        factory.worker_request_binding(
            &context.options.run_id,
            &preflight.assignment,
            1,
            "attached-test",
        )
    })?;
    let turn = WorkerInboxTurn::new(
        binding.clone(),
        1,
        WorkerInboxResources {
            repo: context.repo,
            parent: &preflight.assignment,
            lease: preflight.worktree_write_lease.as_ref().unwrap(),
            claim: &preflight.claim,
            claims: context.sync_store,
        },
    )?;
    let inbox = WorkerRequestInbox::create(
        repository_authenticator_key_only(context.repo)?,
        binding.clone(),
    )?;
    let journal = held_inbox_journal(context.repo, &binding)?;
    assert!(
        journal.is_file(),
        "managed parent inbox journal exists before attachment"
    );
    let journal_identity = crate::safe_state::BoundedRegularReader::identity(&journal)?;
    let endpoint =
        WorkerInboxEndpoint::start(context.run_dir, &turn, inbox, ProcessCancellation::new())?;
    let launch = endpoint.launch();
    prepared.command = prepared
        .command
        .clone()
        .with_assignment_messaging(launch.clone());
    prepared
        .command
        .verify_assignment_messaging_protocol_instructions()?;
    assert_eq!(
        prepared.command.assignment_messaging_launch(),
        Some(&launch)
    );
    prepared.command_admission = Some(
        super::managed_parent_controller::admit_attached_parent_initial_for_test(
            context, preflight, &prepared,
        )?,
    );
    let capture = dispatch_and_capture_attached_parent_attempt(
        context,
        outcome,
        preflight,
        context.options.run_id.as_str(),
        1,
        prepared,
        endpoint,
    )?;
    let owners_remain = incoming_scratch.is_dir()
        && capture_scratch.is_dir()
        && journal.is_file()
        && capture.prepared.incoming_scratch.path() == incoming_scratch
        && capture.prepared.capture_scratch.path() == capture_scratch;
    assert!(
        owners_remain,
        "prepared scratch and managed parent inbox journal stayed owned"
    );
    match case {
        "attached-capture-success" => {
            assert!(capture.external_run.is_some());
            assert!(matches!(capture.endpoint, WorkerInboxShutdown::Frozen(_)));
            assert!(
                capture.diagnostics.is_empty(),
                "fixture accounting diagnostics: {:?}",
                capture.diagnostics
            );
            assert!(!outcome.usage_incomplete);
            assert!(!outcome.external_containment_failed);
            assert_eq!(
                capture.prepared.command.assignment_messaging_launch(),
                Some(&launch)
            );
        }
        "attached-capture-panic" => {
            assert!(capture.external_run.is_none());
            assert!(capture
                .diagnostics
                .iter()
                .any(|line| line.contains("attached parent runner panicked")));
            assert!(outcome.usage_incomplete);
            assert!(outcome.external_containment_failed);
            assert_eq!(
                capture.prepared.budget_reservation.state,
                DispatchBudgetReservationState::Invoked(SupervisorRuntime::Codex)
            );
        }
        "attached-capture-unquiescent" => {
            let run = capture
                .external_run
                .as_ref()
                .expect("unquiescent parent returned a run");
            assert!(run.process_tree.is_none());
            assert_eq!(
                fs::read(
                    context
                        .run_dir
                        .join(&capture.prepared.attempt_artifacts.raw_stdout_relative)
                )?,
                run.stdout_bytes(),
                "held raw evidence can be preserved without authorizing scratch cleanup"
            );
            assert!(incoming_scratch.is_dir() && capture_scratch.is_dir());
            assert!(capture
                .diagnostics
                .iter()
                .any(|line| line.contains("attached parent quiescence refused")));
        }
        "attached-capture-errors" => {
            match &capture.endpoint {
                WorkerInboxShutdown::Rejected(rejected) => {
                    assert!(!rejected.reason().is_empty());
                }
                WorkerInboxShutdown::Frozen(_) => bail!("revoked claim still froze the inbox"),
            }
            let text = capture.diagnostics.join("\n");
            assert!(
                text.contains("attached parent inbox shutdown rejected"),
                "{text}"
            );
            assert!(
                text.contains("attached parent post-return dispatch checkpoint failed"),
                "{text}"
            );
            assert!(
                text.contains("attached parent live invocation persistence failed"),
                "{text}"
            );
            assert!(outcome.usage_incomplete);
            assert_eq!(capture.prepared.incoming_scratch.path(), incoming_scratch);
        }
        other => bail!("unknown attached capture case {other}"),
    }
    recover_while_held(context.repo, &binding)?;
    assert_eq!(held_inbox_journal(context.repo, &binding)?, journal);
    assert_eq!(
        crate::safe_state::BoundedRegularReader::identity(&journal)?,
        journal_identity,
        "attached capture retained the exact managed parent inbox journal"
    );
    drop(capture);
    let recovered =
        WorkerRequestInbox::recover(repository_authenticator_key_only(context.repo)?, binding)?;
    assert!(recovered.requires_reconciliation());
    assert!(
        journal.is_file(),
        "managed parent inbox journal survives recovery"
    );
    assert_eq!(
        crate::safe_state::BoundedRegularReader::identity(&journal)?,
        journal_identity,
        "recovery reopened the same managed parent inbox journal"
    );
    Ok(())
}

#[test]
fn attached_capture_success_retains_real_owners() -> Result<()> {
    super::nested_driver_tests::driver_fixture("attached-capture-success")
}

#[test]
fn attached_capture_panic_retains_unsettled_owners() -> Result<()> {
    super::nested_driver_tests::driver_fixture("attached-capture-panic")
}

#[test]
fn attached_capture_unquiescent_retains_owners() -> Result<()> {
    super::nested_driver_tests::driver_fixture("attached-capture-unquiescent")
}

#[test]
fn attached_capture_bookkeeping_and_shutdown_errors_retain_owners() -> Result<()> {
    super::nested_driver_tests::driver_fixture("attached-capture-errors")
}
