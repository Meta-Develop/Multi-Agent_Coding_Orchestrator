//! Authenticated yield evidence only. No Worker reservation, dispatch or continuation.
//! The frozen journal lock and exact live turn owner remain held for the binding's
//! lifetime. This is deliberately neither serializable nor reconstructible on recovery.

use super::*;
use crate::supervise::messaging_bridge::worker_requests::{
    frozen::{FrozenWorkerInbox, FrozenWorkerInboxView, WorkerInboxResources, WorkerInboxTurn},
    WorkerRequestStatus,
};

/// The candidate here is the quiescent parent's current candidate, before any
/// subsequent Worker execution. Completion must establish a separate bound result;
/// it must not relabel this snapshot as a post-Worker candidate.
pub(super) struct BoundParentTurnYield<'inbox, 'parent, 'context> {
    frozen: FrozenWorkerInbox<'inbox>,
    parent: &'parent CollectedChildAttempt<'context>,
    admission: AssignmentCommandAdmission,
    yielded: parent_turn_yield::ValidatedParentTurnYield,
    candidate: PrimaryWorktreeSnapshot,
}

impl<'inbox, 'parent, 'context> BoundParentTurnYield<'inbox, 'parent, 'context> {
    pub(super) fn bind(
        context: &AssignmentExecutionContext<'_, '_>,
        preflight: &AssignmentExecutionPreflight<'_>,
        parent_attempt: usize,
        parent: &'parent CollectedChildAttempt<'context>,
        current: &WorkerInboxTurn<'_>,
        frozen: FrozenWorkerInbox<'inbox>,
    ) -> Result<Self> {
        verify_parent(context, preflight, parent)?;
        let admission =
            AssignmentAttemptAuthority::from_preflight(context, preflight, parent_attempt)?.admit(
                &preflight.assignment.id,
                &parent._command,
                SupervisorRuntime::Codex,
            )?;
        let view = verify_inbox(context, preflight, parent_attempt, parent, current, &frozen)?;
        if view
            .requests
            .iter()
            .any(|r| r.status != WorkerRequestStatus::Queued)
            || view.watermark.last_sequence != view.requests.len()
        {
            bail!("parent yield requires the exact queued journal watermark");
        }
        let expected = view
            .requests
            .iter()
            .map(|r| parent_turn_yield::ExpectedWorkerRequest::new(&r.request_id, &r.worker_id))
            .collect::<Result<Vec<_>>>()?;
        let yielded = parent_turn_yield::validate_frozen_yield_bytes(
            parent
                .external_run
                .output_last_message()
                .context("parent yield lost its held capture")?,
            context.options.run_id.as_str(),
            &preflight.assignment,
            parent_attempt,
            &expected,
        )?;
        let candidate =
            primary_worktree_snapshot(&preflight.worktree.path, context.execution_runtime)?;
        let bound = Self {
            frozen,
            parent,
            admission,
            yielded,
            candidate,
        };
        // A second read refuses drift while establishing this observation. Future
        // consumers must call revalidate again before consuming the held evidence.
        bound.revalidate(context, preflight, parent_attempt, current)?;
        Ok(bound)
    }

    pub(super) fn revalidate(
        &self,
        context: &AssignmentExecutionContext<'_, '_>,
        preflight: &AssignmentExecutionPreflight<'_>,
        current_attempt: usize,
        current: &WorkerInboxTurn<'_>,
    ) -> Result<FrozenWorkerInboxView<'_>> {
        verify_parent(context, preflight, self.parent)?;
        let (run, parent, attempt) = self.yielded.parent_binding();
        if run != context.options.run_id.as_str()
            || parent != preflight.assignment.id
            || attempt != current_attempt
        {
            bail!("bound parent yield differs from current run, assignment or attempt");
        }
        self.admission.revalidate(
            &AssignmentAttemptAuthority::from_preflight(context, preflight, attempt)?,
            &preflight.assignment.id,
            &self.parent._command,
        )?;
        let view = verify_inbox(
            context,
            preflight,
            attempt,
            self.parent,
            current,
            &self.frozen,
        )?;
        let observed =
            primary_worktree_snapshot(&preflight.worktree.path, context.execution_runtime)
                .context("failed to inspect bound parent candidate snapshot")?;
        if self.candidate.inspection_problem().is_some() || observed.inspection_problem().is_some()
        {
            bail!("bound parent candidate snapshot is incomplete");
        }
        if self.candidate != observed {
            bail!("bound parent candidate snapshot changed");
        }
        Ok(view)
    }

    pub(super) fn requests(&self) -> impl Iterator<Item = (&str, &str)> {
        self.yielded.requests()
    }
}

fn verify_parent(
    context: &AssignmentExecutionContext<'_, '_>,
    preflight: &AssignmentExecutionPreflight<'_>,
    parent: &CollectedChildAttempt<'_>,
) -> Result<()> {
    if context.execution_runtime != SupervisorExecutionRuntime::Verified
        || context.execution_target.is_some()
        || context.evidence_only_reaudit.is_some()
        || context.assignment != &preflight.assignment
        || preflight.assignment.role != AgentRole::ChildOrchestrator
        || parent.model_provenance.launch_runtime != SupervisorRuntime::Codex
        || parent.environment_blocked
        || parent.external_side_effect_state.is_some()
    {
        bail!("bound parent yield requires an unblocked verified managed Codex parent");
    }
    NestedWorkerSerialDriver::verify_parent_quiescence(parent, preflight)?;
    preflight.mandatory_worktree_controls.revalidate()
}

fn verify_inbox<'frozen>(
    context: &AssignmentExecutionContext<'_, '_>,
    preflight: &AssignmentExecutionPreflight<'_>,
    attempt: usize,
    parent: &CollectedChildAttempt<'_>,
    current: &WorkerInboxTurn<'_>,
    frozen: &'frozen FrozenWorkerInbox<'_>,
) -> Result<FrozenWorkerInboxView<'frozen>> {
    current.verify_parent_resources(
        &context.options.run_id,
        attempt,
        WorkerInboxResources {
            repo: context.repo,
            parent: &preflight.assignment,
            lease: preflight
                .worktree_write_lease
                .as_ref()
                .context("parent yield lost its held worktree lease")?,
            claim: &preflight.claim,
            claims: context.sync_store,
        },
    )?;
    frozen.verify_parent_launch(
        context.run_dir,
        parent
            ._command
            .assignment_messaging_launch()
            .context("parent yield command has no bound inbox endpoint")?,
    )?;
    frozen.view(current)
}
