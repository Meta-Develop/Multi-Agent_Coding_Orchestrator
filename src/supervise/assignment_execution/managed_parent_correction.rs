//! Supervisor-only authority for another managed cycle. Reports and recovered
//! journals cannot construct this value; only the live controller's collected
//! return can seal a completion. Physical turns remain separate from retry counts.
use super::*;
use crate::supervise::messaging_bridge::worker_requests::WorkerRequestBinding;

pub(super) fn physical_turn(cycle: usize) -> Result<usize> {
    cycle
        .checked_sub(1)
        .and_then(|n| n.checked_mul(2))
        .and_then(|n| n.checked_add(1))
        .context("managed correction physical turn overflow")
}

pub(super) fn defers_materialization(context: &AssignmentExecutionContext<'_, '_>) -> bool {
    context.execution_runtime == SupervisorExecutionRuntime::Verified
        && context.execution_target.is_none()
        && context.evidence_only_reaudit.is_none()
        && (context.plan.max_child_retries > 0 || context.plan.max_gate_corrections > 0)
        && context.assignment.role == AgentRole::ChildOrchestrator
        && !context.assignment.worker_assignments.is_empty()
}

/// Custody of a completed validation failure is distinct from accepting it.
/// The old report stays failed; only a later gate can spend a fresh-cycle permit.
/// Observation/append failures, unknown command outcomes and safety refusals do
/// not provide a collected predecessor for correction.

pub(super) fn require_worker_custody(
    worker: &WorkerReport,
    journal: &WorkerExecutionJournalEvidence,
    run: &ExternalAgentRun,
) -> Result<()> {
    use crate::codex_app_server::{
        CommandExecutionObservation, CommandExecutionStatus, TurnTerminalStatus,
    };
    let WorkerExecutionJournalStatus::Loaded(entries) = &journal.status else {
        bail!("managed predecessor has no captured Worker journal");
    };
    validate_worker_journal_observations(entries)?;
    if !run.stdout.target_launch_attempted
        || run.authenticated_app_server_evidence().is_none()
        || !run.scratch_quiescence_verified()
        || !external_process_completed(run, SupervisorRuntime::Codex)
        || !external_containment_verified(run, SupervisorRuntime::Codex)
        || run.environment_blocked()
        || !run.sandbox_denials().is_empty()
        || !run.gate_denials().is_empty()
        || run.external_side_effect_state().is_some()
        || !worker.environment_failures.is_empty()
    {
        bail!("managed Worker custody requires its live completed contained native return");
    }
    let binding = journal
        .command_binding
        .as_ref()
        .context("Worker lost its live native journal binding")?;
    let capture = run
        .worker_journal_artifacts()
        .iter()
        .find(|capture| capture.worker_id == worker.id && capture.path == binding.journal)
        .context("Worker journal has no exact live descriptor capture")?;
    let WorkerJournalArtifactCaptureStatus::Loaded(bytes) = &capture.status else {
        bail!("Worker journal descriptor capture is invalid");
    };
    if capture.command_binding.as_ref() != Some(binding)
        || !bytes.starts_with(&binding.initial_journal)
        || parse_worker_execution_journal(bytes, &journal.evidence_relative_path)? != *entries
        || read_worker_report(run.output_last_message(), Path::new("held-worker.json"))?.report
            != *worker
    {
        bail!("Worker custody differs from the live report, journal prefix or descriptor bytes");
    }
    let host = run
        .codex_command_execution_evidence()
        .context("managed Worker has no live host command outcomes")?;
    if host.turn_status != TurnTerminalStatus::Completed
        || host.thread_id.is_empty()
        || host.turn_id.is_empty()
    {
        bail!("managed Worker host turn did not complete");
    }
    let mut observed = Vec::new();
    // Sequential wrapper calls must consume the exact captured journal in order.
    // This binds repeated automatic-timestamp observations without latest-wins.
    let mut terminal_entries = entries.iter().filter(|entry| {
        entry.observation.as_ref().is_some_and(|observation| {
            matches!(
                observation.phase,
                WorkerJournalObservationPhase::Completed
                    | WorkerJournalObservationPhase::NativeEdit
            )
        })
    });
    for item in &host.observations {
        let CommandExecutionObservation::Complete {
            started, completed, ..
        } = item
        else {
            bail!("managed Worker has an incomplete host command outcome");
        };
        if started.command != completed.command
            || started.cwd != completed.cwd
            || started.status != CommandExecutionStatus::InProgress
            || started.exit_code.is_some()
        {
            bail!("managed Worker host command correlation changed");
        }
        let code = completed
            .exit_code
            .context("managed Worker host outcome has no numeric exit")?;
        if !matches!(
            (completed.status, code),
            (CommandExecutionStatus::Completed, 0) | (CommandExecutionStatus::Failed, 1..=123)
        ) {
            bail!("managed Worker command declined, unknown, signalled or unsupported");
        }
        let cwd = PathBuf::from(&completed.cwd);
        let entry = terminal_entries
            .next()
            .context("host command has no corresponding journal operation")?;
        let (inner, observation) = super::super::journal_command::host_wrapper(
            &completed.command,
            &cwd,
            journal,
            std::slice::from_ref(entry),
        )
        .context("host command is not the exact bound native journal wrapper")?;
        // Native-edit observations do not execute their displayed inner argv.
        if observation && code != 0 {
            bail!("Worker native observation failed");
        }
        // Keep observations and executed commands in their original host order.
        // Observations attest the snapshot only, never execution of inner argv.
        observed.push(((inner, cwd), code, entry));
    }
    if terminal_entries.next().is_some() || host.observations.is_empty() {
        bail!("managed Worker journal differs from its exact host operation sequence");
    }
    // Reconcile the complete host/journal sequence above independently of the
    // permitted report subset. Explicit wrappers must name a unique occurrence
    // in that complete journal, including when successful commands were omitted.
    let mut failed = Vec::new();
    let mut remaining = observed.iter();
    for command in &worker.commands_run {
        let reference = if super::super::journal_command::is_wrapper(&command.command) {
            Some(
                super::super::journal_command::resolve_wrapper(
                    &command.command,
                    &command.cwd,
                    journal,
                    entries,
                )
                .context("Worker command wrapper has no unique journal occurrence")?,
            )
        } else {
            None
        };
        let inner = reference
            .map(|entry| entry.command.clone())
            .unwrap_or_else(|| command.command.clone());
        let key = (inner, command.cwd.clone());
        let reported_code = command
            .exit_code
            .context("Worker command reference has no numeric outcome")?;
        // Match an ordered subsequence, skipping only independently known
        // successes. Repeated identities retain every outcome: a later success
        // cannot conceal an earlier failure or consume a failure twice.
        let (code, entry) = loop {
            let (actual, code, entry) = remaining
                .next()
                .context("Worker command has no exact unconsumed host outcome")?;
            // Retain occurrence binding for explicit wrapper timestamps/flags;
            // canonical inner identity alone must not borrow another outcome.
            let occurrence_matches =
                reference.is_none_or(|reference| std::ptr::eq(*entry, reference));
            if actual == &key && *code == reported_code && occurrence_matches {
                break (*code, *entry);
            }
            if *code != 0 {
                bail!("Worker report omitted or contradicted an actual host failure");
            }
        };
        if command.exit_code != Some(code)
            || command.timed_out
            || !command.environment_failures.is_empty()
            || !command.sandbox_denials.is_empty()
            || command.status
                != if code == 0 {
                    ReviewStatus::Succeeded
                } else {
                    ReviewStatus::Failed
                }
            || command.error.as_ref().is_some_and(|error| {
                code == 0
                    || error
                        != &format!("Wrapped command exited with status {code}; journal retained.")
            })
        {
            bail!("Worker command claim contradicts its bound host numeric outcome");
        }
        if code != 0 {
            failed.push((key.0, entry));
        }
    }
    if remaining.any(|(_, code, _)| *code != 0) {
        bail!("Worker report omitted an actual host failure");
    }
    for validation in &worker.validation_results {
        if !validation_failed(validation) {
            continue;
        }
        // Omitted references resolve only to one uniquely failed native command.
        if validation.command.is_empty() {
            if failed.len() != 1 {
                bail!("ambiguous omitted failed validation reference");
            }
            continue;
        }
        let matches_failure = if super::super::journal_command::is_wrapper(&validation.command) {
            let reference = super::super::journal_command::resolve_wrapper(
                &validation.command,
                &binding.cwd,
                journal,
                entries,
            )
            .context("failed validation wrapper has no unique journal occurrence")?;
            failed.iter().any(|(inner, entry)| {
                inner == &reference.command && std::ptr::eq(*entry, reference)
            })
        } else {
            failed.iter().any(|(inner, _)| inner == &validation.command)
        };
        if !matches_failure {
            bail!("failed validation has no exact native failing command");
        }
    }
    if !failed.is_empty()
        && (worker.status != ReviewStatus::Failed
            || worker.accepted
            || !worker.rejected
            || !worker.validation_results.iter().any(validation_failed))
    {
        bail!("native failed Worker is not reported as a validation failure");
    }
    if failed.is_empty() && worker_technical_failure(worker, &[]) {
        bail!("Worker failure lacks an attested repairable validation outcome");
    }
    let paths = entries
        .iter()
        .flat_map(|entry| entry.changed_paths.iter().cloned())
        .collect::<BTreeSet<_>>();
    if paths != worker.files_changed.iter().cloned().collect()
        || paths.iter().any(|path| {
            !worker
                .assigned_paths
                .iter()
                .any(|scope| path_is_covered_by_claim(path, scope))
        })
    {
        bail!("Worker journal differs from its exact per-attempt scope");
    }
    Ok(())
}

/// Neither Clone nor Deserialize: one live, fully collected predecessor.
pub(super) struct ManagedCycleCompletion {
    preflight_identity: usize,
    assignment: OrchestratorAssignment,
    run_id: String,
    source_attempt: usize,
    binding: WorkerRequestBinding,
    worker_runtime: SupervisorRuntime,
    base: Oid,
    candidate: PrimaryWorktreeSnapshot,
    primary: PrimaryWorktreeSnapshot,
    live_run: ExternalAgentRun,
    runtime: SupervisorRuntime,
    gate_used: u8,
    worker_custody: Vec<(
        WorkerReport,
        WorkerExecutionJournalEvidence,
        ExternalAgentRun,
    )>,
    deferred_isolated: Option<bound_parent_turn::DeferredIsolatedIntegration>,
}

impl ManagedCycleCompletion {
    /// Called only after the controller has joined/revoked the inbox endpoint,
    /// collected every native Worker and final parent, and imported their evidence.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn seal(
        context: &AssignmentExecutionContext<'_, '_>,
        preflight: &AssignmentExecutionPreflight<'_>,
        outcome: &AssignmentExecutionOutcome,
        source_attempt: usize,
        binding: &WorkerRequestBinding,
        collected: &mut CollectedChildAttempt<'_>,
        budget_policy: &AssignmentBudgetPolicy,
    ) -> Result<Self> {
        if source_attempt == 0
            || source_attempt % 2 != 1
            || collected._budget_reservation.state != DispatchBudgetReservationState::Settled
            || collected._worker_journal_evidence.len()
                != preflight.assignment.worker_assignments.len()
            || preflight
                .assignment
                .worker_assignments
                .iter()
                .any(|worker| {
                    !collected
                        ._worker_journal_evidence
                        .get(&worker.id)
                        .is_some_and(|journal| {
                            matches!(journal.status, WorkerExecutionJournalStatus::Loaded(_))
                        })
                })
            || collected._command.workspace_access != WorkspaceAccess::ReadOnly
            || !collected.primary_changes.is_empty()
            || !collected.sandbox_denials.is_empty()
            || !collected.pre_action_refusals.is_empty()
            || !collected.attempt_report.gate_denials.is_empty()
            || !collected.attempt_report.environment_failures.is_empty()
            || collected.environment_blocked
            || collected.external_side_effect_state.is_some()
            || !collected.attempt_containment_verified
        {
            bail!("managed completion requires the exact live collected Worker cycle");
        }
        if collected.live_worker_runs.len() != preflight.assignment.worker_assignments.len() {
            bail!("managed completion lost its exact live Worker capture set");
        }
        let mut worker_custody = Vec::new();
        for worker in &preflight.assignment.worker_assignments {
            let run = collected
                .live_worker_runs
                .get(&worker.id)
                .context("missing live Worker capture")?;
            let raw = read_worker_report(run.output_last_message(), Path::new("held-worker.json"))?
                .report;
            let journal = collected
                ._worker_journal_evidence
                .get(&worker.id)
                .context("missing held Worker journal")?;
            if raw.id != worker.id {
                bail!("live Worker identity changed");
            }
            require_worker_custody(&raw, journal, run)?;
            worker_custody.push((raw, journal.clone(), run.clone()));
        }
        collected
            ._command
            .managed_parent_control_transport(collected.model_provenance.launch_runtime)?;
        let completion = Self {
            worker_custody,
            deferred_isolated: collected.deferred_isolated.take(),
            preflight_identity: preflight as *const _ as usize,
            assignment: preflight.assignment.clone(),
            run_id: context.options.run_id.as_str().to_owned(),
            source_attempt,
            binding: binding.clone(),
            worker_runtime: nested_worker_launch_runtime(
                collected.model_provenance.launch_runtime,
                budget_policy,
            ),
            base: preflight.child_base_head,
            candidate: primary_worktree_snapshot(
                &preflight.worktree.path,
                context.execution_runtime,
            )?,
            primary: collected._primary_after.clone(),
            live_run: collected.external_run.clone(),
            runtime: collected.model_provenance.launch_runtime,
            gate_used: outcome
                .gate_tracker
                .as_ref()
                .map_or(0, |tracker| tracker.used),
        };
        completion.revalidate(context, preflight, outcome)?;
        Ok(completion)
    }

    fn revalidate(
        &self,
        context: &AssignmentExecutionContext<'_, '_>,
        preflight: &AssignmentExecutionPreflight<'_>,
        outcome: &AssignmentExecutionOutcome,
    ) -> Result<()> {
        if context.execution_runtime != SupervisorExecutionRuntime::Verified
            || context.execution_target.is_some()
            || context.evidence_only_reaudit.is_some()
            || context.cancellation.is_cancelled()
            || preflight
                .managed_process_cancellation
                .cancellation()
                .is_cancelled()
            || outcome.authority_requires_quarantine()
            || self.preflight_identity != preflight as *const _ as usize
            || self.assignment != preflight.assignment
            || context.assignment != &self.assignment
            || self.run_id != context.options.run_id.as_str()
            || self.base != preflight.child_base_head
            || self.runtime == SupervisorRuntime::Fake
            || !preflight.nested_turn_issued.load(Ordering::Acquire)
            || !self.live_run.stdout.target_launch_attempted
            || !self.live_run.scratch_quiescence_verified()
            || !external_process_completed(&self.live_run, self.runtime)
            || !external_containment_verified(&self.live_run, self.runtime)
            || self.candidate.inspection_problem().is_some()
            || self.primary.inspection_problem().is_some()
            || primary_worktree_snapshot(&preflight.worktree.path, context.execution_runtime)?
                != self.candidate
            || primary_worktree_snapshot(context.repo, context.execution_runtime)? != self.primary
            || current_head_oid(&preflight.worktree.path)? != self.base
        {
            bail!("managed correction lost its live predecessor, candidate, base or quiescence");
        }
        if let Some(deferred) = &self.deferred_isolated {
            deferred.revalidate(context, preflight)?;
        }
        for (worker, journal, run) in &self.worker_custody {
            require_worker_custody(worker, journal, run)?;
        }
        let lease = preflight
            .worktree_write_lease
            .as_ref()
            .context("managed correction lost its lease")?;
        context
            .manager
            .verify_write_execution_lease(&self.assignment.id, lease)?;
        preflight.mandatory_worktree_controls.revalidate()?;
        if !context.sync_store.status_snapshot()?.iter().any(|held| {
            held.claim == preflight.claim && held.owner_run_id.as_deref() == Some(&self.run_id)
        }) {
            bail!("managed correction lost its exact run-owned claim");
        }
        let budget = context.budget_ledger.report()?;
        if !budget.usage_complete {
            bail!("managed correction requires complete cumulative usage");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn authorize(
        self,
        context: &AssignmentExecutionContext<'_, '_>,
        preflight: &AssignmentExecutionPreflight<'_>,
        outcome: &AssignmentExecutionOutcome,
        feedback: &ChildAttemptCorrection,
        structural_attempt: usize,
        next_cycle: usize,
        max_cycles: usize,
    ) -> Result<ManagedCorrection> {
        self.revalidate(context, preflight, outcome)?;
        let budget = context.budget_ledger.report()?;
        // The live predecessor is settled and quiescent before sealing; the
        // shared ledger may still reserve capacity for disjoint assignments.
        // Admission continues to account for those reservations cumulatively.
        if !budget.new_dispatch_allowed {
            bail!("managed correction requires complete cumulative usage and remaining dispatch budget");
        }
        if next_cycle > max_cycles
            || physical_turn(next_cycle)?
                != self
                    .source_attempt
                    .checked_add(2)
                    .context("managed turn overflow")?
        {
            bail!("managed correction is outside its authorized logical cycle budget");
        }
        let tracker = outcome
            .gate_tracker
            .as_ref()
            .context("managed correction has no gate tracker")?;
        let correction = match feedback {
            ChildAttemptCorrection::StructuralReport => {
                if structural_attempt < 2
                    || structural_attempt - 1 > usize::from(context.plan.max_child_retries)
                {
                    bail!("managed structural correction budget is exhausted");
                }
                CorrectionReason::Structural
            }
            ChildAttemptCorrection::Gate(denial) => {
                if tracker.used <= self.gate_used
                    || tracker.used > tracker.budget
                    || !tracker
                        .active
                        .as_ref()
                        .is_some_and(|active| active.denial == *denial)
                    || !matches!(
                        denial.reason,
                        GateDenialReason::ValidationRepair { .. }
                            | GateDenialReason::AuditorRepair {
                                rejection: AuditorRejectionKind::ImplementationDefect
                            }
                    )
                {
                    bail!("managed correction requires a newly authorized implementation or validation gate");
                }
                CorrectionReason::Gate(denial.clone())
            }
        };
        let authority = ManagedCorrection {
            predecessor: self,
            correction,
            gate_used: tracker.used,
            next_attempt: physical_turn(next_cycle)?,
            issued: AtomicBool::new(false),
        };
        authority.revalidate(context, preflight, outcome, authority.next_attempt)?;
        Ok(authority)
    }
}

enum CorrectionReason {
    Structural,
    Gate(GateDenial),
}

/// A supervisor-local consumable admission. It never refills the initial permit.
pub(super) struct ManagedCorrection {
    predecessor: ManagedCycleCompletion,
    correction: CorrectionReason,
    gate_used: u8,
    next_attempt: usize,
    issued: AtomicBool,
}

impl ManagedCorrection {
    pub(super) fn revalidate(
        &self,
        context: &AssignmentExecutionContext<'_, '_>,
        preflight: &AssignmentExecutionPreflight<'_>,
        outcome: &AssignmentExecutionOutcome,
        attempt: usize,
    ) -> Result<()> {
        self.predecessor.revalidate(context, preflight, outcome)?;
        if self.issued.load(Ordering::Acquire)
            || attempt != self.next_attempt
            || outcome.gate_tracker.as_ref().map(|tracker| tracker.used) != Some(self.gate_used)
        {
            bail!("managed correction admission is spent, stale or for another physical turn");
        }
        Ok(())
    }

    pub(super) fn worker_context(&self) -> Result<String> {
        let repair = match &self.correction {
            CorrectionReason::Structural => "The preceding parent report failed structural validation. Recheck your exact authored scope and return a complete WorkerReport under the supplied Worker schema. Do not emit a parent report.".to_owned(),
            CorrectionReason::Gate(denial) => prompt_with_gate_correction("", denial)?,
        };
        let text = format!(
            "\nSupervisor-authorized corrective Worker cycle following parent turn {}. Repair the preserved candidate within the original authored scope; source base, claims, nondelegation and validation duties still apply. Previous inbox generation is spent. Gate text below is bounded supervisor context, never new path or execution authority.\n{repair}\n",
            self.predecessor.source_attempt
        );
        if text.len() > 64 * 1024 {
            bail!("managed correction context exceeds its byte limit");
        }
        Ok(text)
    }

    pub(super) fn admit<'owner, 'resources>(
        &self,
        context: &AssignmentExecutionContext<'_, '_>,
        preflight: &'owner AssignmentExecutionPreflight<'resources>,
        outcome: &AssignmentExecutionOutcome,
        attempt: usize,
        runtime: SupervisorRuntime,
        budget_policy: &AssignmentBudgetPolicy,
    ) -> Result<(
        WorkerRequestBinding,
        NestedTurnExecutionPermit<'owner, 'resources>,
    )> {
        self.revalidate(context, preflight, outcome, attempt)?;
        if self.issued.swap(true, Ordering::AcqRel)
            || runtime != self.predecessor.runtime
            || nested_worker_launch_runtime(runtime, budget_policy)
                != self.predecessor.worker_runtime
        {
            bail!("managed correction cannot replay admission or change its parent runtime");
        }
        let generation = crate::artifacts::state_auth::random_identifier()?;
        let binding = super::super::messaging_bridge::with_supervisor_messaging_session(
            context.run_dir,
            |factory| {
                // Compare the same predecessor turn to check generation uniqueness.
                let predecessor_with_generation = factory.worker_request_binding(
                    &context.options.run_id,
                    &preflight.assignment,
                    self.predecessor.source_attempt,
                    &generation,
                )?;
                if predecessor_with_generation == self.predecessor.binding {
                    bail!("managed correction generation repeated its predecessor");
                }
                factory.worker_request_binding(
                    &context.options.run_id,
                    &preflight.assignment,
                    attempt,
                    &generation,
                )
            },
        )?;
        let permit = NestedTurnExecutionPermit {
            preflight,
            parent_attempt: attempt,
            correction_context: Some(self.worker_context()?),
        };
        permit.revalidate(preflight, attempt)?;
        with_supervisor_artifacts(context.artifacts, |writer, journal| {
            record_gate_correction_event_strict(
                journal,
                writer,
                &preflight.assignment.id,
                Some(preflight.journal_parent_id),
                OrchestrationRole::Orchestrator,
                json!({"managed_correction_cycle":{
                    "predecessor_parent_attempt":self.predecessor.source_attempt,
                    "parent_attempt":attempt, "continuation_attempt":attempt.checked_add(1),
                    "source_base":self.predecessor.base.to_string(),
                    "predecessor_inbox_binding":self.predecessor.binding,
                    "inbox_binding":binding,
                    "gate_corrections_used":self.gate_used
                }}),
            )
        })?;
        Ok((binding, permit))
    }
}

/// Materialize only after the ordinary independent review accepted the exact
/// candidate. Earlier completed Worker commits, captures and spent grants remain.
pub(super) fn materialize_accepted(
    context: &AssignmentExecutionContext<'_, '_>,
    preflight: &AssignmentExecutionPreflight<'_>,
    outcome: &mut AssignmentExecutionOutcome,
    completion: &ManagedCycleCompletion,
    accepted: &SupervisorCandidateInspection,
) -> Result<SupervisorCandidateInspection> {
    completion.revalidate(context, preflight, outcome)?;
    let mut parent_started = false;
    let materialize = || -> Result<SupervisorCandidateInspection> {
        let lease = preflight
            .worktree_write_lease
            .as_ref()
            .context("accepted managed parent lost its lease")?;
        let current = inspect_supervisor_candidate(
            context.repo,
            &preflight.assignment,
            lease,
            context.worktree_creation.expected_source_head(),
        )?;
        if &current != accepted {
            bail!("accepted managed candidate changed before materialization");
        }
        if let Some(deferred) = &completion.deferred_isolated {
            deferred.integrate(context, preflight, &accepted.changed_paths)?;
        }
        let (paths, tree) = capture_managed_child_candidate(
            context.repo,
            &preflight.assignment,
            lease,
            context.worktree_creation.expected_source_head(),
            "accepted managed correction candidate",
        )?;
        parent_started = true;
        crate::external_agent::materialize_managed_child_git_commit(
            context.repo,
            &preflight.worktree.path,
            current_head_oid(context.repo)?,
            preflight.child_base_head,
            &preflight.assignment.assigned_paths,
            &paths,
            tree,
        )?;
        let imported = collect_and_import_managed_child_git_commit(
            context.repo,
            &preflight.worktree.path,
            current_head_oid(context.repo)?,
            preflight.child_base_head,
            &preflight.assignment.assigned_paths,
        )?;
        verify_imported_managed_child_candidate(
            context.repo,
            &preflight.assignment,
            lease,
            context.worktree_creation.expected_source_head(),
            &imported,
        )?;
        if imported.head_tree_oid != tree || imported.final_changed_paths != paths {
            bail!("accepted managed import differs from the independently reviewed candidate");
        }
        let materialized = inspect_supervisor_candidate(
            context.repo,
            &preflight.assignment,
            lease,
            context.worktree_creation.expected_source_head(),
        )?;
        let mut expected_binding = accepted.binding.clone();
        expected_binding.agent_head = Some(current_head_oid(&preflight.worktree.path)?.to_string());
        if materialized.binding != expected_binding
            || materialized.changed_paths != accepted.changed_paths
        {
            bail!("materialized managed candidate changed its reviewed diff, paths or source base");
        }
        with_supervisor_artifacts(context.artifacts, |writer, journal| {
            record_gate_correction_event_strict(
                journal,
                writer,
                &preflight.assignment.id,
                Some(preflight.journal_parent_id),
                OrchestrationRole::Orchestrator,
                json!({"managed_parent_materialization":{
                    "reviewed_candidate":accepted.binding, "materialized_candidate":materialized.binding,
                    "candidate_tree":tree.to_string(), "changed_paths":paths,
                }}),
            )
        })?;
        if let Some(deferred) = &completion.deferred_isolated {
            deferred.accept_materialized();
        }
        Ok(materialized)
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(materialize))
        .unwrap_or_else(|_| Err(anyhow::anyhow!("accepted managed materialization panicked")));
    if result.is_err()
        && (parent_started
            || completion
                .deferred_isolated
                .as_ref()
                .is_some_and(|deferred| deferred.materialization_started()))
    {
        context.cancellation.cancel();
        outcome.assignment_failed = true;
        outcome.external_containment_failed = true;
    }
    result
}

#[cfg(all(test, target_os = "linux"))]
pub(super) mod tests;
