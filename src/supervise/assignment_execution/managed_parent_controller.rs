//! Serial managed-parent cycle: one fresh inbox turn, one Worker pass, one final parent.
//! Refusal without verified scratch quiescence aborts while the capture is still owned.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;

use anyhow::{bail, Context, Result};

use super::bound_parent_turn::BoundParentTurnYield;
use super::{
    collect_prepared_managed_parent_final, dispatch_and_capture_attached_parent_attempt,
    dispatch_and_capture_child_attempt, import_external_attempt_evidence,
    inspect_attached_parent_capture, prepare_child_attempt, prepare_managed_parent_final_attempt,
    with_supervisor_artifacts, AgentRole, AssignmentAttemptAuthority, AssignmentBudgetPolicy,
    AssignmentExecutionContext, AssignmentExecutionDisposition, AssignmentExecutionOutcome,
    AssignmentExecutionPreflight, AssignmentPhase, AttachedParentCapture, AttachedParentInspection,
    CollectedChildAttempt, ExternalAttemptEvidenceContext, InspectedAttachedParent,
    ParentContinuationLaunch, PreparedChildAttempt, RoleCategory, SupervisorExecutionRuntime,
    SupervisorRuntime, WorkspaceAccess,
};
use crate::artifacts::repository_authenticator_key_only;
use crate::process_runner::ProcessCancellation;
use crate::supervise::messaging_bridge::with_supervisor_messaging_session;
use crate::supervise::messaging_bridge::worker_requests::frozen::{
    WorkerInboxEndpoint, WorkerInboxResources, WorkerInboxTurn,
};
use crate::supervise::messaging_bridge::worker_requests::WorkerRequestInbox;

#[allow(clippy::too_many_arguments)]
pub(super) fn dispatch_and_collect_managed_parent_attempt<'budget>(
    context: &AssignmentExecutionContext<'budget, '_>,
    outcome: &mut AssignmentExecutionOutcome,
    preflight: &AssignmentExecutionPreflight<'_>,
    journal_parent_id: &str,
    source_attempt: usize,
    mut prepared: PreparedChildAttempt<'budget>,
    budget_policy: &AssignmentBudgetPolicy,
    max_attempts: usize,
    schema_path: &Path,
    worker_schema_path: &Path,
    auditor_schema_path: &Path,
) -> Result<CollectedChildAttempt<'budget>> {
    require_managed_parent_input(context, preflight, source_attempt, &prepared)?;
    let turn_number = u64::try_from(source_attempt)
        .context("managed parent source attempt does not fit a supervisor turn")?;
    if turn_number == 0 {
        bail!("managed parent inbox turn must be nonzero");
    }
    let binding = with_supervisor_messaging_session(context.run_dir, |factory| {
        factory.claim_fresh_worker_request_binding(
            &context.options.run_id,
            &preflight.assignment,
            source_attempt,
            SupervisorRuntime::Codex,
        )
    })?;
    let lease = preflight
        .worktree_write_lease
        .as_ref()
        .context("managed parent cycle requires the held write lease")?;
    let turn = WorkerInboxTurn::new(
        binding.clone(),
        turn_number,
        WorkerInboxResources {
            repo: context.repo,
            parent: &preflight.assignment,
            lease,
            claim: &preflight.claim,
            claims: context.sync_store,
        },
    )?;
    let inbox = WorkerRequestInbox::create(
        repository_authenticator_key_only(context.repo)?,
        binding.clone(),
    )?;
    let endpoint = WorkerInboxEndpoint::start(
        context.run_dir,
        &turn,
        inbox,
        managed_cancellation(preflight).clone(),
    )?;
    let launch = endpoint.launch();
    prepared.command = prepared
        .command
        .clone()
        .with_assignment_messaging(launch.clone());
    prepared
        .command
        .verify_assignment_messaging_protocol_instructions()?;
    if prepared.command.assignment_messaging_launch() != Some(&launch) {
        bail!("managed parent command did not keep the fresh inbox launch");
    }
    prepared.command_admission = Some(admit_read_only(
        context,
        preflight,
        source_attempt,
        &prepared.command,
    )?);
    let capture = dispatch_and_capture_attached_parent_attempt(
        context,
        outcome,
        preflight,
        journal_parent_id,
        source_attempt,
        prepared,
        endpoint,
    )?;
    let (parent, frozen) = match inspect_attached_parent_capture(context, preflight, capture) {
        AttachedParentInspection::Ready { parent, frozen } => (*parent, *frozen),
        AttachedParentInspection::Refused(capture) => {
            return refuse_attached_parent(preflight, *capture);
        }
    };
    let bound = BoundParentTurnYield::bind_inspected(
        context,
        preflight,
        source_attempt,
        &parent,
        &turn,
        frozen,
    )?;
    let requested = bound
        .requests()
        .map(|(_, worker_id)| worker_id.to_string())
        .collect::<Vec<_>>();
    require_exact_authored_workers(preflight, &requested)?;
    let completed = bound.execute_serial(
        context,
        preflight,
        source_attempt,
        &turn,
        outcome,
        budget_policy,
    )?;
    let continuation = ParentContinuationLaunch::from_bound_completed_workers(
        context,
        preflight,
        source_attempt,
        &turn,
        &completed,
    )?;
    let (_, _, bound_source_attempt, next_attempt) = continuation.binding();
    if bound_source_attempt != source_attempt {
        bail!("managed parent continuation left the source attempt");
    }
    let mut final_prepared = match prepare_child_attempt(
        context,
        outcome,
        budget_policy,
        preflight,
        journal_parent_id,
        next_attempt,
        max_attempts,
        &None,
        schema_path,
        worker_schema_path,
        auditor_schema_path,
        Some(&continuation),
    )? {
        AssignmentExecutionDisposition::Continue(prepared) => prepared,
        AssignmentExecutionDisposition::Complete => {
            bail!("managed parent continuation stopped before final parent dispatch")
        }
    };
    require_read_only_native_off(&final_prepared, "managed parent continuation")?;
    final_prepared.command_admission = Some(admit_read_only(
        context,
        preflight,
        next_attempt,
        &final_prepared.command,
    )?);
    continuation.revalidate(context, preflight, next_attempt)?;
    let captured = dispatch_and_capture_child_attempt(
        context,
        outcome,
        preflight,
        journal_parent_id,
        next_attempt,
        final_prepared,
    )?;
    let prepared_final = prepare_managed_parent_final_attempt(
        context,
        preflight,
        captured,
        &continuation,
        &completed,
        source_attempt,
        &turn,
    );
    drop(continuation);
    drop(completed);
    let imported = import_initial_parent_evidence(context, parent);
    match (prepared_final, imported) {
        (Ok(prepared_final), Ok(())) => {
            collect_prepared_managed_parent_final(context, outcome, preflight, prepared_final)
        }
        (Ok(_prepared_final), Err(import_error)) => {
            Err(import_error).context("managed parent initial evidence import failed")
        }
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(import_error)) => Err(error).context(format!(
            "managed parent initial evidence import also failed: {import_error:#}"
        )),
    }
}

fn require_managed_parent_input(
    context: &AssignmentExecutionContext<'_, '_>,
    preflight: &AssignmentExecutionPreflight<'_>,
    source_attempt: usize,
    prepared: &PreparedChildAttempt<'_>,
) -> Result<()> {
    if source_attempt != 1
        || context.execution_runtime != SupervisorExecutionRuntime::Verified
        || context.execution_target.is_some()
        || context.evidence_only_reaudit.is_some()
        || preflight.assignment.role != AgentRole::ChildOrchestrator
        || preflight.assignment.phase != AssignmentPhase::Execution
        || preflight.assignment.effective_role_category() != RoleCategory::DelegatingCoordinator
        || preflight.assignment.worker_assignments.is_empty()
        || prepared.launch_runtime != SupervisorRuntime::Codex
        || prepared.model_provenance.launch_runtime != SupervisorRuntime::Codex
    {
        bail!(
            "managed parent cycle requires source attempt 1 on a verified Codex child orchestrator with authored workers and no primary, evidence-only, or simulated runtime"
        );
    }
    require_read_only_native_off(prepared, "managed parent initial attempt")?;
    Ok(())
}

fn require_read_only_native_off(prepared: &PreparedChildAttempt<'_>, label: &str) -> Result<()> {
    if prepared.command.workspace_access != WorkspaceAccess::ReadOnly
        || !prepared.command.codex_native_delegation_is_disabled()
    {
        bail!("{label} requires a read-only workspace and Codex native delegation disabled");
    }
    Ok(())
}

fn require_exact_authored_workers(
    preflight: &AssignmentExecutionPreflight<'_>,
    requested: &[String],
) -> Result<()> {
    let authored = preflight
        .assignment
        .worker_assignments
        .iter()
        .map(|worker| worker.id.as_str())
        .collect::<Vec<_>>();
    let mut seen = BTreeSet::new();
    if requested.len() != authored.len()
        || requested.iter().any(|worker_id| {
            !authored.contains(&worker_id.as_str()) || !seen.insert(worker_id.as_str())
        })
        || seen.len() != authored.len()
    {
        bail!("frozen parent requests do not cover each authored worker once");
    }
    Ok(())
}

fn admit_read_only(
    context: &AssignmentExecutionContext<'_, '_>,
    preflight: &AssignmentExecutionPreflight<'_>,
    attempt: usize,
    command: &crate::external_agent::ExternalAgentCommand,
) -> Result<super::AssignmentCommandAdmission> {
    AssignmentAttemptAuthority::from_preflight(context, preflight, attempt)?
        .admit_managed_parent_read_only(&preflight.assignment.id, command, SupervisorRuntime::Codex)
}

fn managed_cancellation<'a>(
    preflight: &'a AssignmentExecutionPreflight<'_>,
) -> &'a ProcessCancellation {
    preflight.managed_process_cancellation.cancellation()
}

fn refuse_attached_parent<'budget>(
    preflight: &AssignmentExecutionPreflight<'_>,
    capture: AttachedParentCapture<'budget, '_>,
) -> Result<CollectedChildAttempt<'budget>> {
    managed_cancellation(preflight).cancel();
    let quiescence_verified = capture
        .external_run
        .as_ref()
        .is_some_and(|run| run.scratch_quiescence_verified());
    if quiescence_verified {
        let detail = if capture.diagnostics.is_empty() {
            "attached parent inspection refused the capture".to_string()
        } else {
            capture.diagnostics.join("; ")
        };
        bail!("managed parent inspection refused a quiescent capture: {detail}");
    }
    // Owners stay in this frame. Abort skips destructors, so the live capture is not detached.
    let _owner = &capture;
    let _ = writeln!(
        std::io::stderr().lock(),
        "fatal: attached parent owner remained live without verified scratch quiescence; aborting rather than detaching owned execution"
    );
    std::process::abort()
}

fn import_initial_parent_evidence(
    context: &AssignmentExecutionContext<'_, '_>,
    parent: InspectedAttachedParent<'_>,
) -> Result<()> {
    let InspectedAttachedParent {
        prepared,
        external_run,
        ..
    } = parent;
    let PreparedChildAttempt {
        attempt_artifacts,
        command,
        incoming_scratch,
        capture_scratch,
        incoming_output_root,
        capture_output_root,
        launch_runtime,
        budget_reservation,
        ..
    } = prepared;
    drop(incoming_output_root);
    drop(capture_output_root);
    let imported = with_supervisor_artifacts(context.artifacts, |writer, _| {
        import_external_attempt_evidence(
            writer,
            ExternalAttemptEvidenceContext {
                incoming_scratch: &incoming_scratch,
                capture_scratch: &capture_scratch,
                artifacts: &attempt_artifacts,
                external_run: &external_run,
                external_command: &command,
                raw_report_validated: true,
                runtime: launch_runtime,
            },
        )
    });
    drop(budget_reservation);
    imported
}
