//! Staged authenticated yield-to-Worker evidence binding. No production caller or continuation.
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
        let view = self.revalidate_identity(context, preflight, current_attempt, current)?;
        verify_candidate(&self.candidate, context, preflight)?;
        Ok(view)
    }

    fn revalidate_identity(
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
        verify_inbox(
            context,
            preflight,
            attempt,
            self.parent,
            current,
            &self.frozen,
        )
    }

    pub(super) fn requests(&self) -> impl Iterator<Item = (&str, &str)> {
        self.yielded.requests()
    }

    /// Consumes the live inbox authority, never an arbitrary completed-report list.
    /// The driver burns the preflight's one-shot permit even if execution fails;
    /// durable nested reservations and recovery quarantine remain authoritative.
    /// No partial success token is returned on error. Artifacts/accounting stay in
    /// the enclosing outcome and journal for explicit supervisor reconciliation.
    /// The inbox stays frozen: execution uses the driver's existing durable Worker
    /// reservations, not a new recoverable inbox transition/activation protocol.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn execute_serial(
        self,
        context: &AssignmentExecutionContext<'context, '_>,
        preflight: &AssignmentExecutionPreflight<'_>,
        current_attempt: usize,
        current: &WorkerInboxTurn<'_>,
        outcome: &mut AssignmentExecutionOutcome,
        policy: &AssignmentBudgetPolicy,
    ) -> Result<BoundNestedWorkerEvidence<'inbox, 'parent, 'context>> {
        self.revalidate(context, preflight, current_attempt, current)?;
        let requests = self
            .requests()
            .map(|(r, w)| (r.to_owned(), w.to_owned()))
            .collect::<Vec<_>>();
        let mut driver = NestedWorkerSerialDriver::from_collected_parent(
            context,
            preflight,
            outcome,
            current_attempt,
            self.parent,
        )?;
        let mut candidate = self.candidate.clone();
        let mut workers = Vec::new();
        for (index, (request_id, worker_id)) in requests.into_iter().enumerate() {
            self.revalidate_identity(context, preflight, current_attempt, current)?;
            verify_candidate(&candidate, context, preflight)?;
            let usage_start = driver.outcome.usage_samples.len();
            #[cfg(test)]
            mutate_candidate_at_handoff(true, &preflight.worktree.path)?;
            let evidence = driver.execute_worker(&worker_id, policy)?;
            let handoff = (|| -> Result<()> {
                #[cfg(test)]
                mutate_candidate_at_handoff(false, &preflight.worktree.path)?;
                let (before, after) = evidence.candidate_snapshots();
                if before != &candidate {
                    bail!("validated Worker candidate does not follow bound predecessor");
                }
                verify_candidate(after, context, preflight)
            })();
            if let Err(error) = handoff {
                context.cancellation.cancel();
                driver.outcome.assignment_failed = true;
                driver.outcome.external_containment_failed = true;
                return Err(error);
            }
            candidate = evidence.candidate_snapshots().1.clone();
            workers.push(BoundWorkerResult {
                // bind() required only Queued events and sequence == request count.
                sequence: index + 1,
                request_id,
                worker_id,
                evidence,
                usage: driver.outcome.usage_samples[usage_start..].to_vec(),
            });
        }
        drop(driver);
        let completed = BoundNestedWorkerEvidence {
            source: self,
            workers,
        };
        completed.revalidate(context, preflight, current_attempt, current)?;
        Ok(completed)
    }
}

/// Non-Clone/non-Deserialize authority. Retains the original frozen journal lock,
/// turn/lease borrow, captured parent, and exact before/after Worker evidence.
/// Recovery cannot reconstruct it; continuation and scheduler activation stay closed.
pub(super) struct BoundNestedWorkerEvidence<'inbox, 'parent, 'context> {
    source: BoundParentTurnYield<'inbox, 'parent, 'context>,
    workers: Vec<BoundWorkerResult>,
}

pub(super) struct BoundWorkerResult {
    sequence: usize,
    request_id: String,
    worker_id: String,
    evidence: nested_worker_executor::NestedWorkerAttemptEvidence,
    // Per-request settled samples; an empty slice is not proof of zero usage.
    // The full runner's usage reliability evidence is retained in `evidence`.
    usage: Vec<RoleUsageSample>,
}

impl BoundWorkerResult {
    pub(super) fn identity(&self) -> (usize, &str, &str) {
        (self.sequence, &self.request_id, &self.worker_id)
    }

    pub(super) fn evidence(&self) -> &nested_worker_executor::NestedWorkerAttemptEvidence {
        &self.evidence
    }

    pub(super) fn usage(&self) -> &[RoleUsageSample] {
        &self.usage
    }

    pub(super) fn candidate_snapshots(
        &self,
    ) -> (&PrimaryWorktreeSnapshot, &PrimaryWorktreeSnapshot) {
        self.evidence.candidate_snapshots()
    }
}

impl BoundNestedWorkerEvidence<'_, '_, '_> {
    /// The frozen view supplies the original state-instance/generation/turn and
    /// watermark, not labels copied from Worker reports or reconstructed JSON.
    pub(super) fn revalidate(
        &self,
        context: &AssignmentExecutionContext<'_, '_>,
        preflight: &AssignmentExecutionPreflight<'_>,
        attempt: usize,
        current: &WorkerInboxTurn<'_>,
    ) -> Result<(FrozenWorkerInboxView<'_>, &[BoundWorkerResult])> {
        let view = self
            .source
            .revalidate_identity(context, preflight, attempt, current)?;
        if self.workers.len() != view.requests.len() || self.workers.is_empty() {
            bail!("bound Worker evidence differs from the frozen request count");
        }
        let mut candidate = &self.source.candidate;
        for (index, (request, worker)) in view.requests.iter().zip(&self.workers).enumerate() {
            if worker.identity()
                != (
                    index + 1,
                    request.request_id.as_str(),
                    request.worker_id.as_str(),
                )
                || worker.evidence.report().id != request.worker_id
                || worker.candidate_snapshots().0 != candidate
                || worker
                    .candidate_snapshots()
                    .1
                    .inspection_problem()
                    .is_some()
                || worker.evidence.journals().len() != 1
                || !worker.evidence.journals().contains_key(&request.worker_id)
                || read_worker_report(
                    worker.evidence.run().output_last_message(),
                    &worker.evidence.artifacts().raw_report_relative,
                )?
                .report
                    != *worker.evidence.report()
            {
                bail!("bound Worker evidence differs from its exact request or held capture");
            }
            candidate = worker.candidate_snapshots().1;
        }
        verify_candidate(candidate, context, preflight)?;
        Ok((view, &self.workers))
    }
}

fn verify_candidate(
    expected: &PrimaryWorktreeSnapshot,
    context: &AssignmentExecutionContext<'_, '_>,
    preflight: &AssignmentExecutionPreflight<'_>,
) -> Result<()> {
    let observed = primary_worktree_snapshot(&preflight.worktree.path, context.execution_runtime)
        .context("failed to inspect bound parent candidate snapshot")?;
    if expected.inspection_problem().is_some() || observed.inspection_problem().is_some() {
        bail!("bound parent candidate snapshot is incomplete");
    }
    if *expected != observed {
        bail!("bound parent candidate snapshot changed");
    }
    Ok(())
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

// One-shot, thread-local injection at the wrapper/executor handoff only.
#[cfg(test)]
thread_local! {
    static CANDIDATE_HANDOFF_MUTATION: std::cell::RefCell<Option<(bool, PathBuf)>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(super) fn set_candidate_handoff_mutation(before: bool, path: PathBuf) {
    CANDIDATE_HANDOFF_MUTATION.with(|hook| *hook.borrow_mut() = Some((before, path)));
}

#[cfg(test)]
fn mutate_candidate_at_handoff(before: bool, worktree: &Path) -> Result<()> {
    CANDIDATE_HANDOFF_MUTATION.with(|hook| {
        let mut hook = hook.borrow_mut();
        if hook
            .as_ref()
            .is_some_and(|(at_before, _)| *at_before == before)
        {
            let (_, path) = hook.take().unwrap();
            fs::write(worktree.join(path), "unreported handoff mutation\n")?;
        }
        Ok(())
    })
}
