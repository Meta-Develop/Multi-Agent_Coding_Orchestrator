//! Authenticated yield-to-Worker evidence for serial and isolated managed turns.
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
pub(super) struct BoundParentTurnYield<'inbox, 'parent> {
    frozen: FrozenWorkerInbox<'inbox>,
    parent: ParentTurnObservation<'parent>,
    admission: AssignmentCommandAdmission,
    yielded: parent_turn_yield::ValidatedParentTurnYield,
    candidate: PrimaryWorktreeSnapshot,
}

impl<'inbox, 'parent> BoundParentTurnYield<'inbox, 'parent> {
    pub(super) fn bind<'context>(
        context: &AssignmentExecutionContext<'_, '_>,
        preflight: &AssignmentExecutionPreflight<'_>,
        parent_attempt: usize,
        parent: &'parent CollectedChildAttempt<'context>,
        current: &WorkerInboxTurn<'_>,
        frozen: FrozenWorkerInbox<'inbox>,
    ) -> Result<Self> {
        Self::bind_observed(
            context,
            preflight,
            parent_attempt,
            ParentTurnObservation::from_collected(parent),
            current,
            frozen,
        )
    }

    #[allow(dead_code)]
    pub(super) fn bind_inspected(
        context: &AssignmentExecutionContext<'_, '_>,
        preflight: &AssignmentExecutionPreflight<'_>,
        parent_attempt: usize,
        parent: &'parent InspectedAttachedParent<'_>,
        current: &WorkerInboxTurn<'_>,
        frozen: FrozenWorkerInbox<'inbox>,
    ) -> Result<Self> {
        Self::bind_observed(
            context,
            preflight,
            parent_attempt,
            ParentTurnObservation::from_inspected(parent),
            current,
            frozen,
        )
    }

    fn bind_observed(
        context: &AssignmentExecutionContext<'_, '_>,
        preflight: &AssignmentExecutionPreflight<'_>,
        parent_attempt: usize,
        parent: ParentTurnObservation<'parent>,
        current: &WorkerInboxTurn<'_>,
        frozen: FrozenWorkerInbox<'inbox>,
    ) -> Result<Self> {
        verify_parent(context, preflight, &parent)?;
        let admission = super::admit_parent_turn_command(
            AssignmentAttemptAuthority::from_preflight(context, preflight, parent_attempt)?,
            &preflight.assignment.id,
            parent.command,
            parent.model_provenance.launch_runtime,
        )?;
        let view = verify_inbox(
            context,
            preflight,
            parent_attempt,
            &parent,
            current,
            &frozen,
        )?;
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
        verify_parent(context, preflight, &self.parent)?;
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
            self.parent.command,
        )?;
        verify_inbox(
            context,
            preflight,
            attempt,
            &self.parent,
            current,
            &self.frozen,
        )
    }

    pub(super) fn requests(&self) -> impl Iterator<Item = (&str, &str)> {
        self.yielded.requests()
    }

    pub(super) fn selects_isolated_route(
        &self,
        context: &AssignmentExecutionContext<'_, '_>,
        preflight: &AssignmentExecutionPreflight<'_>,
        parent_attempt: usize,
        current: &WorkerInboxTurn<'_>,
    ) -> Result<bool> {
        use crate::selection::routing_policy::{
            current_routing_policy, evaluate_task_grain, TaskGrain, TaskRoutingFeatures,
        };
        let Some(frozen) = current_routing_policy() else {
            return Ok(false);
        };
        let view = self.revalidate(context, preflight, parent_attempt, current)?;
        if validate_isolated_request_set(&preflight.assignment, view.requests).is_err() {
            return Ok(false);
        }
        let depth = context
            .assignment_schedule
            .get(context.index)
            .context("isolated parent is outside its validated schedule")?
            .depth;
        if view.requests.len() > frozen.policy.tree.max_workers
            || usize::from(depth) + 1 > frozen.policy.tree.max_depth
        {
            bail!("isolated authored Worker tree exceeds its frozen policy bounds");
        }
        let parent = &preflight.assignment;
        let paths = parent
            .worker_assignments
            .iter()
            .flat_map(|worker| &worker.assigned_paths)
            .collect::<BTreeSet<_>>();
        let modules = parent
            .worker_assignments
            .iter()
            .flat_map(|worker| &worker.semantic_modules)
            .collect::<BTreeSet<_>>();
        let features = TaskRoutingFeatures {
            scope_paths: paths.len(), scope_modules: modules.len(), complexity:0, risk:0, horizon:0,
            context_tokens:0, dependency_edges:parent.decision_refs.len(),
            independent_groups: if parent.decision_refs.is_empty() { view.requests.len() } else { 1 },
            evidence: vec![
                "Exact authenticated authored Worker scopes and frozen receipt order revalidated".into(),
                "Disjoint scope groups are structural grain; shared parent decisions conservatively join groups".into(),
                "Complexity risk horizon and context are unassessed lower bounds".into(),
            ],
        };
        Ok(evaluate_task_grain(&features, &frozen.policy.tree)? == TaskGrain::CoordinatedWorkers)
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
        context: &AssignmentExecutionContext<'_, '_>,
        preflight: &AssignmentExecutionPreflight<'_>,
        current_attempt: usize,
        current: &WorkerInboxTurn<'_>,
        outcome: &mut AssignmentExecutionOutcome,
        policy: &AssignmentBudgetPolicy,
    ) -> Result<BoundNestedWorkerEvidence<'inbox, 'parent>> {
        self.revalidate(context, preflight, current_attempt, current)?;
        let requests = self
            .requests()
            .map(|(r, w)| (r.to_owned(), w.to_owned()))
            .collect::<Vec<_>>();
        let mut driver = NestedWorkerSerialDriver::from_observation(
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

    /// The frozen source stays held while independently leased Workers run.
    /// This consumes the same one-shot preflight permit as the serial route.
    pub(super) fn execute_isolated(
        self,
        context: &AssignmentExecutionContext<'_, '_>,
        preflight: &AssignmentExecutionPreflight<'_>,
        parent_attempt: usize,
        current: &WorkerInboxTurn<'_>,
        outcome: &mut AssignmentExecutionOutcome,
        policy: &AssignmentBudgetPolicy,
    ) -> Result<BoundIsolatedWorkers<'inbox, 'parent>> {
        let view = self.revalidate(context, preflight, parent_attempt, current)?;
        validate_isolated_request_set(&preflight.assignment, view.requests)?;
        let source_digest =
            crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(&json!({
                "binding":view.binding, "turn":view.turn,
                "journal_instance":view.watermark.journal_instance,
                "last_sequence":view.watermark.last_sequence,
                "journal_digest":view.watermark.journal_digest,
                "requests":view.requests
            }))?);
        let workers = {
            let _permit = preflight.issue_nested_turn(parent_attempt)?;
            let mut grants: Vec<IsolatedWorkerDispatchAuthority> = Vec::new();
            for (index, request) in view.requests.iter().enumerate() {
                if context.cancellation.is_cancelled() {
                    break;
                }
                let worker = preflight
                    .assignment
                    .worker_assignments
                    .iter()
                    .find(|worker| worker.id == request.worker_id)
                    .context("isolated Worker is outside the frozen authored set")?;
                let claim = context.sync_store.claim_subordinate_paths_for_run(
                    &context.options.run_id,
                    &preflight.claim,
                    &worker.id,
                    &worker.assigned_paths,
                    &source_digest,
                );
                match claim {
                    Ok(claim) => grants.push(IsolatedWorkerDispatchAuthority {
                        sequence: index + 1,
                        request_id: request.request_id.clone(),
                        worker: worker.clone(),
                        run_id: context.options.run_id.clone(),
                        parent_attempt,
                        parent_claim: preflight.claim.clone(),
                        source_digest: source_digest.clone(),
                        claim,
                    }),
                    Err(error) => {
                        release_unstarted_grants(context, outcome, &grants);
                        return Err(error)
                            .context("isolated subordinate admission failed before launch");
                    }
                }
            }
            if grants.len() != view.requests.len() {
                release_unstarted_grants(context, outcome, &grants);
                bail!("isolated dispatch cancelled before complete subordinate admission");
            }
            super::dispatch_isolated_parent_workers(
                context,
                preflight,
                parent_attempt,
                grants,
                outcome,
                policy,
            )?
        };
        let completed = BoundIsolatedWorkers {
            source: self,
            workers,
        };
        completed.revalidate(context, preflight, parent_attempt, current)?;
        Ok(completed)
    }
}

fn validate_isolated_request_set(
    parent: &OrchestratorAssignment,
    requests: &[crate::supervise::messaging_bridge::worker_requests::WorkerRequestRecord],
) -> Result<()> {
    let mut seen = BTreeSet::new();
    let mut scopes: Vec<PathBuf> = Vec::new();
    if requests.len() != parent.worker_assignments.len() || requests.len() < 2 {
        bail!("isolated dispatch requires every exact authored Worker and useful parallel grain");
    }
    for (index, request) in requests.iter().enumerate() {
        let worker = parent
            .worker_assignments
            .iter()
            .find(|worker| worker.id == request.worker_id)
            .context("isolated request references an unauthored Worker")?;
        if parent.worker_assignments[index].id != request.worker_id
            || request.status != WorkerRequestStatus::Queued
            || !seen.insert(&worker.id)
            || worker.role != AgentRole::Worker
            || worker.assigned_paths.is_empty()
            || worker.effective_role_category() != RoleCategory::NonDelegatingTerminalWorker
        {
            bail!("isolated request set is duplicated, incomplete or nonterminal");
        }
        for path in &worker.assigned_paths {
            if crate::sync::normalize_repo_relative_path(path)? != *path
                || !parent
                    .assigned_paths
                    .iter()
                    .any(|scope| path.starts_with(scope))
                || scopes
                    .iter()
                    .any(|scope| crate::sync::paths_overlap(scope, path))
            {
                bail!("isolated Worker scopes must be canonical disjoint authored parent subsets");
            }
            scopes.push(path.clone());
        }
    }
    Ok(())
}

fn release_unstarted_grants(
    context: &AssignmentExecutionContext<'_, '_>,
    outcome: &mut AssignmentExecutionOutcome,
    grants: &[IsolatedWorkerDispatchAuthority],
) {
    for grant in grants {
        if let Err(error) = context.sync_store.release(grant.claim.token) {
            outcome
                .release_errors
                .push(format!("isolated unstarted Worker claim: {error:#}"));
        }
    }
}

/// No wire constructor and no Clone: only the held frozen-yield consumer issues it.
pub(super) struct IsolatedWorkerDispatchAuthority {
    sequence: usize,
    request_id: String,
    worker: WorkerAssignment,
    run_id: RunId,
    parent_attempt: usize,
    parent_claim: PathClaim,
    source_digest: String,
    claim: PathClaim,
}

impl IsolatedWorkerDispatchAuthority {
    pub(super) fn identity(&self) -> (usize, &str, &str) {
        (self.sequence, &self.request_id, &self.worker.id)
    }
    pub(super) fn worker(&self) -> &WorkerAssignment {
        &self.worker
    }
    pub(super) fn claim(&self) -> &PathClaim {
        &self.claim
    }
    pub(super) fn revalidate(
        &self,
        context: &AssignmentExecutionContext<'_, '_>,
        preflight: &AssignmentExecutionPreflight<'_>,
    ) -> Result<()> {
        if self.run_id != context.options.run_id
            || self.parent_attempt == 0
            || self.parent_claim != preflight.claim
            || !preflight
                .assignment
                .worker_assignments
                .iter()
                .any(|worker| worker == &self.worker)
        {
            bail!("isolated dispatch capability differs from its current authored parent");
        }
        context.sync_store.verify_subordinate_claim(
            &self.run_id,
            &self.parent_claim,
            &self.claim,
            &self.source_digest,
        )
    }
}

/// Owns the independent write lease, exact settled capture and original grant.
pub(super) struct IsolatedWorkerAttemptEvidence {
    authority: IsolatedWorkerDispatchAuthority,
    lease: crate::worktree::ManagedWorktreeWriteLease,
    worker_attempt: usize,
    semantic_token: Option<u64>,
    command: ExternalAgentCommand,
    settlement: DispatchUsageSettlement,
    evidence: nested_worker_executor::NestedWorkerAttemptEvidence,
}

impl IsolatedWorkerAttemptEvidence {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn seal(
        context: &AssignmentExecutionContext<'_, '_>,
        parent_preflight: &AssignmentExecutionPreflight<'_>,
        authority: IsolatedWorkerDispatchAuthority,
        lease: crate::worktree::ManagedWorktreeWriteLease,
        worker_attempt: usize,
        semantic_token: Option<u64>,
        report: WorkerReport,
        journals: WorkerExecutionJournalEvidenceSet,
        artifacts: ChildAttemptArtifacts,
        run: ExternalAgentRun,
        command: ExternalAgentCommand,
        model_provenance: CompletedLaunchModelProvenance,
        observed_changed_paths: Vec<PathBuf>,
        candidate_before: PrimaryWorktreeSnapshot,
        candidate_after: PrimaryWorktreeSnapshot,
        settled_reservation: &DispatchBudgetReservation<'_>,
        settlement: DispatchUsageSettlement,
    ) -> Result<Self> {
        if settled_reservation.state != DispatchBudgetReservationState::Settled
            || settled_reservation.reservation.role != AgentRole::Worker
            || !std::ptr::eq(settled_reservation.ledger, context.budget_ledger)
        {
            bail!("isolated Worker capture requires its actual once-settled run reservation");
        }
        let sealed = Self {
            authority,
            lease,
            worker_attempt,
            semantic_token,
            command,
            settlement,
            evidence: nested_worker_executor::NestedWorkerAttemptEvidence::from_isolated_parts(
                report,
                journals,
                artifacts,
                run,
                observed_changed_paths,
                model_provenance,
                candidate_before,
                candidate_after,
            ),
        };
        sealed.revalidate(context, parent_preflight)?;
        Ok(sealed)
    }

    pub(super) fn identity(&self) -> (usize, &str, &str) {
        self.authority.identity()
    }
    pub(super) fn evidence(&self) -> &nested_worker_executor::NestedWorkerAttemptEvidence {
        &self.evidence
    }
    pub(super) fn report(&self) -> &WorkerReport {
        self.evidence.report()
    }
    pub(super) fn journals(&self) -> &WorkerExecutionJournalEvidenceSet {
        self.evidence.journals()
    }
    pub(super) fn artifacts(&self) -> &ChildAttemptArtifacts {
        self.evidence.artifacts()
    }
    pub(super) fn run(&self) -> &ExternalAgentRun {
        self.evidence.run()
    }
    pub(super) fn command(&self) -> &ExternalAgentCommand {
        &self.command
    }
    pub(super) fn model_provenance(&self) -> &CompletedLaunchModelProvenance {
        self.evidence.model_provenance()
    }
    pub(super) fn usage_settlement(&self) -> &DispatchUsageSettlement {
        &self.settlement
    }
    pub(super) fn claim(&self) -> &PathClaim {
        self.authority.claim()
    }
    pub(super) fn lease(&self) -> &crate::worktree::ManagedWorktreeWriteLease {
        &self.lease
    }
    pub(super) fn worker_attempt(&self) -> usize {
        self.worker_attempt
    }
    pub(super) fn candidate_snapshots(
        &self,
    ) -> (&PrimaryWorktreeSnapshot, &PrimaryWorktreeSnapshot) {
        self.evidence.candidate_snapshots()
    }

    fn revalidate(
        &self,
        context: &AssignmentExecutionContext<'_, '_>,
        preflight: &AssignmentExecutionPreflight<'_>,
    ) -> Result<()> {
        self.authority.revalidate(context, preflight)?;
        let worker = self.authority.worker();
        let report = self.report();
        let (before, after) = self.candidate_snapshots();
        let artifacts = self.artifacts();
        let stems = if self.worker_attempt == 1 {
            vec![worker.id.clone(), format!("{}.attempt-1", worker.id)]
        } else {
            vec![format!("{}.attempt-{}", worker.id, self.worker_attempt)]
        };
        let artifact_matches = stems.iter().any(|stem| {
            artifacts.raw_report_relative
                == PathBuf::from("evidence/incoming").join(format!("{stem}.json"))
                && artifacts.prompt_path
                    == context.dirs.assignments.join(format!("{stem}.prompt.md"))
        });
        super::parent_continuation_binding::verified_worker_completion_runtime(
            self.model_provenance(),
            self.run(),
        )?;
        context
            .manager
            .verify_write_execution_lease(&worker.id, &self.lease)?;
        let changes = primary_integrity_changes(before, after);
        if self.worker_attempt == 0
            || self.lease.record().name != worker.id
            || self.lease.path() == preflight.worktree.path
            || self.run().cwd != self.lease.path()
            || self.command.cwd != self.lease.path()
            || !artifact_matches
            || self.command.workspace_access != WorkspaceAccess::ReadWrite
            || self.model_provenance().launched_model != self.command.model
            || before.inspection_problem().is_some()
            || after.inspection_problem().is_some()
            || primary_worktree_snapshot(self.lease.path(), context.execution_runtime)? != *after
            || !primary_integrity_changes_outside_scope(&changes, &worker.assigned_paths).is_empty()
            || changes.paths != *self.evidence.observed_changed_paths()
            || report.id != worker.id
            || report.role != AgentRole::Worker
            || report.assignment_kind != AssignmentKind::Ordinary
            || report.target_path.is_some()
            || report.assigned_paths != worker.assigned_paths
            || report.semantic_symbols != worker.semantic_symbols
            || report.semantic_modules != worker.semantic_modules
            || report.claim_token != Some(self.claim().token.get())
            || report.semantic_intent_token != self.semantic_token
            || report.no_further_delegation != Some(true)
            || report.files_changed != changes.paths
            || worker_technical_failure(report, &[])
            || self.run().environment_blocked()
            || self.run().external_side_effect_state().is_some()
            || !self.run().sandbox_denials().is_empty()
            || !self.run().gate_denials().is_empty()
            || self.journals().len() != 1
            || !self.journals().get(&worker.id).is_some_and(|journal| {
                matches!(journal.status, WorkerExecutionJournalStatus::Loaded(_))
            })
            || read_worker_report(
                self.run().output_last_message(),
                &artifacts.raw_report_relative,
            )?
            .report
                != *report
        {
            bail!("isolated Worker evidence differs from its held capture, scope, lease or settled request");
        }
        Ok(())
    }
}

pub(super) struct BoundIsolatedWorkers<'inbox, 'parent> {
    source: BoundParentTurnYield<'inbox, 'parent>,
    workers: Vec<IsolatedWorkerAttemptEvidence>,
}

impl BoundIsolatedWorkers<'_, '_> {
    pub(super) fn parent_candidate(&self) -> &PrimaryWorktreeSnapshot {
        &self.source.candidate
    }
    pub(super) fn revalidate(
        &self,
        context: &AssignmentExecutionContext<'_, '_>,
        preflight: &AssignmentExecutionPreflight<'_>,
        parent_attempt: usize,
        current: &WorkerInboxTurn<'_>,
    ) -> Result<(FrozenWorkerInboxView<'_>, &[IsolatedWorkerAttemptEvidence])> {
        let view = self
            .source
            .revalidate(context, preflight, parent_attempt, current)?;
        let mut worktrees = BTreeSet::new();
        if self.workers.len() != view.requests.len() || self.workers.len() < 2 {
            bail!("isolated completion differs from the exact frozen Worker set");
        }
        for (index, (request, worker)) in view.requests.iter().zip(&self.workers).enumerate() {
            if worker.identity()
                != (
                    index + 1,
                    request.request_id.as_str(),
                    request.worker_id.as_str(),
                )
                || !worktrees.insert(worker.lease().path())
                || worker.candidate_snapshots().0.head.target != self.source.candidate.head.target
            {
                bail!("isolated completion duplicates or substitutes its ordered source/Worker/worktree");
            }
            worker.revalidate(context, preflight)?;
        }
        Ok((view, &self.workers))
    }

    /// After final collection, release only actually settled, quiescent children.
    /// Captures, sibling leases and the frozen source owner remain in this value.
    /// The spent reservations persist and no longer authorize continuation/replay.
    pub(super) fn release_completed_claims(
        &self,
        context: &AssignmentExecutionContext<'_, '_>,
        preflight: &AssignmentExecutionPreflight<'_>,
        parent_attempt: usize,
        current: &WorkerInboxTurn<'_>,
    ) -> Result<()> {
        self.revalidate(context, preflight, parent_attempt, current)?;
        for worker in &self.workers {
            context.sync_store.release(worker.claim().token)?;
        }
        self.source
            .revalidate(context, preflight, parent_attempt, current)?;
        Ok(())
    }
}

/// Non-Clone/non-Deserialize authority. Retains the original frozen journal lock,
/// turn/lease borrow, captured parent, and exact before/after Worker evidence.
/// Recovery cannot reconstruct it; continuation and scheduler activation stay closed.
pub(super) struct BoundNestedWorkerEvidence<'inbox, 'parent> {
    source: BoundParentTurnYield<'inbox, 'parent>,
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

impl BoundNestedWorkerEvidence<'_, '_> {
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
    parent: &ParentTurnObservation<'_>,
) -> Result<()> {
    if context.execution_runtime != SupervisorExecutionRuntime::Verified
        || context.execution_target.is_some()
        || context.evidence_only_reaudit.is_some()
        || context.assignment != &preflight.assignment
        || preflight.assignment.role != AgentRole::ChildOrchestrator
        || parent.environment_blocked
        || parent.external_side_effect_state.is_some()
    {
        bail!("bound parent yield requires an unblocked verified managed parent");
    }
    parent
        .command
        .managed_parent_control_transport(parent.model_provenance.launch_runtime)?;
    NestedWorkerSerialDriver::verify_parent_quiescence(parent, preflight)?;
    preflight.mandatory_worktree_controls.revalidate()
}

fn verify_inbox<'frozen>(
    context: &AssignmentExecutionContext<'_, '_>,
    preflight: &AssignmentExecutionPreflight<'_>,
    attempt: usize,
    parent: &ParentTurnObservation<'_>,
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
            .command
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

#[cfg(test)]
mod isolated_request_tests {
    use super::*;
    use crate::supervise::messaging_bridge::worker_requests::WorkerRequestRecord;

    fn fixture() -> (OrchestratorAssignment, Vec<WorkerRequestRecord>) {
        let parent = serde_json::from_value(json!({
            "id":"parent", "phase":"execution", "role":"child_orchestrator",
            "assigned_paths":["src"], "worker_assignments":[
                {"id":"first", "assigned_paths":["src/a.rs"]},
                {"id":"second", "assigned_paths":["src/b.rs"]}
            ]
        }))
        .unwrap();
        let requests = ["first", "second"]
            .into_iter()
            .enumerate()
            .map(|(index, worker)| WorkerRequestRecord {
                request_id: format!("request-{}", index + 1),
                worker_id: worker.into(),
                status: WorkerRequestStatus::Queued,
            })
            .collect();
        (parent, requests)
    }

    #[test]
    fn isolated_request_scope_accepts_exact_ordered_disjoint_workers() {
        let (parent, requests) = fixture();
        validate_isolated_request_set(&parent, &requests).unwrap();
    }

    #[test]
    fn isolated_request_scope_refuses_missing_duplicate_foreign_reordered_or_spent_requests() {
        let (parent, requests) = fixture();
        assert!(validate_isolated_request_set(&parent, &requests[..1]).is_err());
        let mut duplicate = requests.clone();
        duplicate[1] = duplicate[0].clone();
        assert!(validate_isolated_request_set(&parent, &duplicate).is_err());
        let mut foreign = requests.clone();
        foreign[0].worker_id = "foreign".into();
        assert!(validate_isolated_request_set(&parent, &foreign).is_err());
        let mut reordered = requests.clone();
        reordered.reverse();
        assert!(validate_isolated_request_set(&parent, &reordered).is_err());
        let mut spent = requests;
        spent[0].status = WorkerRequestStatus::Completed;
        assert!(validate_isolated_request_set(&parent, &spent).is_err());
    }

    #[test]
    fn isolated_request_scope_refuses_overlap_escape_noncanonical_or_delegating_workers() {
        let (parent, requests) = fixture();
        let mut overlap = parent.clone();
        overlap.worker_assignments[1].assigned_paths = vec!["src/a.rs".into()];
        assert!(validate_isolated_request_set(&overlap, &requests).is_err());
        let mut escape = parent.clone();
        escape.worker_assignments[1].assigned_paths = vec!["other/b.rs".into()];
        assert!(validate_isolated_request_set(&escape, &requests).is_err());
        let mut noncanonical = parent.clone();
        noncanonical.worker_assignments[1].assigned_paths = vec!["src/../other/b.rs".into()];
        assert!(validate_isolated_request_set(&noncanonical, &requests).is_err());
        let mut delegating = parent;
        delegating.worker_assignments[1].role = AgentRole::ChildOrchestrator;
        assert!(validate_isolated_request_set(&delegating, &requests).is_err());
    }
}
