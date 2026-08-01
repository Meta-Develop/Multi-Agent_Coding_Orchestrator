use super::*;

/// Admission policy for concurrently runnable supervisor children.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SupervisorConcurrencyPolicy {
    /// Use the same measured, cgroup-aware process capacity as strict systemd containment.
    ///
    /// The issue #24 swarm-health circuit breaker remains the admission safety backstop: higher
    /// default fan-out never bypasses its pre-dispatch check or active-child drain behavior.
    #[default]
    Auto,
    /// Run at most this explicit positive number of children.
    Fixed(NonZeroUsize),
}

impl SupervisorConcurrencyPolicy {
    pub(crate) const fn resolve(self, capacity: HostProcessCapacity) -> usize {
        match self {
            Self::Auto => capacity.supervisor_children(),
            Self::Fixed(limit) => limit.get(),
        }
    }
}

impl fmt::Display for SupervisorConcurrencyPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auto => formatter.write_str("auto"),
            Self::Fixed(limit) => write!(formatter, "{limit}"),
        }
    }
}

impl FromStr for SupervisorConcurrencyPolicy {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        if value == "auto" {
            return Ok(Self::Auto);
        }
        let parsed = value
            .parse::<usize>()
            .map_err(|_| "--max-concurrent-children must be at least 1 or 'auto'".to_string())?;
        NonZeroUsize::new(parsed)
            .map(Self::Fixed)
            .ok_or_else(|| "--max-concurrent-children must be at least 1 or 'auto'".to_string())
    }
}

fn assignments_overlap(left: &OrchestratorAssignment, right: &OrchestratorAssignment) -> bool {
    left.assigned_paths.iter().any(|left_path| {
        right
            .assigned_paths
            .iter()
            .any(|right_path| paths_overlap(left_path, right_path))
    })
}

fn plan_has_overlapping_assignments(plan: &SupervisorPlan) -> bool {
    plan.assignments
        .iter()
        .enumerate()
        .any(|(left_index, left)| {
            plan.assignments
                .iter()
                .skip(left_index.saturating_add(1))
                .any(|right| assignments_overlap(left, right))
        })
}

fn validated_scheduler_assignment_schedule(
    plan: &SupervisorPlan,
    metadata: &SupervisorPlanMetadata,
) -> Result<Vec<AssignmentScheduleEntry>> {
    let flattened_assignments = plan
        .assignments
        .iter()
        .enumerate()
        .map(|(flattened_index, assignment)| AssignmentScheduleEntry {
            assignment_id: assignment.id.clone(),
            parent_assignment_id: None,
            depth: MIN_SUPERVISOR_DEPTH,
            flattened_index,
        })
        .collect::<Vec<_>>();
    let supplied = if metadata.assignment_schedule.is_empty() {
        flattened_assignments.clone()
    } else {
        metadata.assignment_schedule.clone()
    };
    validate_assignment_schedule(supplied, &flattened_assignments, plan.max_depth)
        .context("supervisor scheduler rejected the validated assignment schedule")
}

pub(super) fn release_assignment_resources_after_completion(
    plan: &SupervisorPlan,
    schedule: &[AssignmentScheduleEntry],
    max_concurrent_children: usize,
) -> bool {
    max_concurrent_children > 1
        || plan_has_overlapping_assignments(plan)
        || schedule
            .iter()
            .any(|entry| entry.parent_assignment_id.is_some())
}

pub(super) fn semantic_preview_intents_for_assignment(
    assignment_index: usize,
    schedule: &[AssignmentScheduleEntry],
    planned: &[(usize, SemanticIntent)],
) -> Vec<SemanticIntent> {
    planned
        .iter()
        .filter(|(planned_index, _)| {
            !schedule_entries_share_strict_lineage(schedule, *planned_index, assignment_index)
        })
        .map(|(_, intent)| intent.clone())
        .collect()
}

fn prepare_semantic_warn_assignments(
    store: &SemanticIntentStore,
    plan: &SupervisorPlan,
    schedule: &[AssignmentScheduleEntry],
) -> Result<Vec<PreparedSemanticAssignment>> {
    let mut prepared = plan
        .assignments
        .iter()
        .map(|_| PreparedSemanticAssignment::default())
        .collect::<Vec<_>>();
    if plan.semantic_coordination != SemanticCoordinationMode::Warn {
        return Ok(prepared);
    }

    let mut planned_preview_intents = Vec::<(usize, SemanticIntent)>::new();
    for (index, assignment) in plan.assignments.iter().enumerate() {
        let additional_active =
            semantic_preview_intents_for_assignment(index, schedule, &planned_preview_intents);
        let report = match store.preview_with_additional_active(
            semantic_assignment_request(assignment),
            &additional_active,
        ) {
            Ok(report) => report,
            Err(error) if semantic_resolution_error(&error) => {
                prepared[index]
                    .findings
                    .push(semantic_resolution_finding(assignment, &error));
                prepared[index].assignment_failed = true;
                continue;
            }
            Err(error) => return Err(error),
        };
        if report.has_blocking_conflicts || report.has_advisory_conflicts {
            let conflict_count = report
                .blocking_conflict_count
                .saturating_add(report.advisory_conflict_count);
            prepared[index].findings.push(Finding {
                severity: FindingSeverity::Warning,
                message: format!(
                    "semantic coordination warn-mode preview for assignment '{}' found {} conflict(s)",
                    assignment.id,
                    conflict_count
                ),
                paths: assignment.assigned_paths.clone(),
            });
            prepared[index]
                .health_signals
                .push(SwarmHealthSignal::SemanticConflictWarned {
                    conflicts: conflict_count,
                });
        }
        prepared[index].token = Some(report.intent.token.get());
        planned_preview_intents.push((index, report.intent));
    }
    Ok(prepared)
}

struct AssignmentSchedulerContext<'context, 'writer> {
    plan: &'context SupervisorPlan,
    budget_config: &'context SupervisorBudgetConfig,
    consultant: &'context SupervisorConsultantPlan,
    assignment_metadata: &'context AssignmentMetadata,
    options: &'context SupervisorRunOptions,
    repo: &'context Path,
    run_dir: &'context Path,
    dirs: &'context RunDirs,
    execution_runtime: SupervisorExecutionRuntime,
    worktree_creation: SupervisorWorktreeCreation<'context>,
    manager: &'context WorktreeManager,
    existing_ids: &'context BTreeSet<String>,
    sync_store: &'context SyncStore,
    semantic_store: &'context SemanticIntentStore,
    prepared_semantic_assignments: &'context [PreparedSemanticAssignment],
    assignment_schedule: &'context [AssignmentScheduleEntry],
    field_guide: &'context SupervisorFieldGuidePrompt,
    artifacts: &'context Mutex<SharedSupervisorArtifacts<'writer>>,
    budget_ledger: &'context RunBudgetLedger,
    runtime_model_catalog: &'context RuntimeModelCatalog,
    external_runner: &'context CancellableExternalRunner<'context>,
    release_per_assignment: bool,
    max_concurrent_children: usize,
}

struct SchedulerProgress {
    indexed_outcomes: Vec<Option<AssignmentExecutionOutcome>>,
    health_breaker: SwarmHealthCircuitBreaker,
    budget_prevented_dispatch: bool,
    budget_denied_assignment_indices: BTreeSet<usize>,
    circuit_breaker_trip: Option<CircuitBreakerTrip>,
}

impl SchedulerProgress {
    fn new(assignment_count: usize) -> Self {
        Self {
            indexed_outcomes: (0..assignment_count).map(|_| None).collect(),
            health_breaker: SwarmHealthCircuitBreaker::default(),
            budget_prevented_dispatch: false,
            budget_denied_assignment_indices: BTreeSet::new(),
            circuit_breaker_trip: None,
        }
    }
}

#[derive(Default)]
struct CollectedAssignmentOutcomes {
    acquired_claim_tokens: Vec<ClaimToken>,
    acquired_semantic_tokens: Vec<crate::semantic_coord::SemanticIntentToken>,
    concurrently_released_claims: Vec<PathClaim>,
    concurrent_release_errors: Vec<String>,
    concurrently_released_semantic_intents: Vec<SemanticIntent>,
    concurrent_semantic_release_errors: Vec<String>,
    command_records: Vec<CommandRunRecord>,
    usage_samples: Vec<RoleUsageSample>,
    usage_incomplete: bool,
    orchestrator_reports: Vec<OrchestratorReviewReport>,
    gate_denials: Vec<GateDenial>,
    pre_action_review_metrics: Vec<ReviewMetricSnapshot>,
    gate_correction_outcomes: Vec<GateCorrectionOutcomeRecord>,
    candidate_inspections: BTreeMap<String, SupervisorCandidateInspection>,
    findings: Vec<Finding>,
    assignment_execution_failed: bool,
    external_containment_failed: bool,
}

fn collect_indexed_assignment_outcomes(
    indexed_outcomes: Vec<Option<AssignmentExecutionOutcome>>,
    release_per_assignment: bool,
    collected: &mut CollectedAssignmentOutcomes,
) -> Vec<String> {
    let mut fatal_errors = Vec::new();
    for outcome in indexed_outcomes.into_iter().flatten() {
        collected.command_records.extend(outcome.command_records);
        collected.usage_samples.extend(outcome.usage_samples);
        collected.usage_incomplete |= outcome.usage_incomplete;
        collected.findings.extend(outcome.findings);
        collected.gate_denials.extend(outcome.gate_denials);
        collected
            .pre_action_review_metrics
            .extend(outcome.pre_action_review_metrics);
        collected
            .gate_correction_outcomes
            .extend(outcome.gate_correction_outcomes);
        collected.assignment_execution_failed |= outcome.assignment_failed;
        collected.external_containment_failed |= outcome.external_containment_failed;
        if !release_per_assignment {
            collected.acquired_claim_tokens.extend(outcome.claim_tokens);
            collected
                .acquired_semantic_tokens
                .extend(outcome.semantic_tokens);
        } else {
            collected
                .concurrently_released_claims
                .extend(outcome.released_claims);
            collected
                .concurrent_release_errors
                .extend(outcome.release_errors);
            collected
                .concurrently_released_semantic_intents
                .extend(outcome.released_semantic_intents);
            collected
                .concurrent_semantic_release_errors
                .extend(outcome.semantic_release_errors);
        }
        if let (Some(report), Some(inspection)) =
            (outcome.report.as_ref(), outcome.candidate_inspection)
        {
            collected
                .candidate_inspections
                .insert(report.id.clone(), inspection);
        }
        if let Some(report) = outcome.report {
            collected.orchestrator_reports.push(report);
        }
        if let Some(error) = outcome.fatal_error {
            fatal_errors.push(error);
        }
    }
    fatal_errors
}

fn select_ready_nonoverlapping_assignment<I>(
    pending: &BTreeSet<usize>,
    assignment_schedule: &[AssignmentScheduleEntry],
    indexed_outcomes: &[Option<AssignmentExecutionOutcome>],
    plan: &SupervisorPlan,
    active_indices: I,
) -> Result<Option<usize>>
where
    I: Iterator<Item = usize> + Clone,
{
    for candidate in pending.iter().copied() {
        if assignment_admission_state(candidate, assignment_schedule, indexed_outcomes)?
            != AssignmentAdmissionState::Ready
        {
            continue;
        }
        if active_indices.clone().all(|active_index| {
            !assignments_overlap(
                &plan.assignments[candidate],
                &plan.assignments[active_index],
            )
        }) {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

fn run_serial_assignment_schedule(
    context: &AssignmentSchedulerContext<'_, '_>,
    progress: &mut SchedulerProgress,
    cancellation: &ProcessCancellation,
    serial_semantic_warn_intents: &Mutex<Vec<(usize, SemanticIntent)>>,
) -> Result<()> {
    let mut pending = (0..context.plan.assignments.len()).collect::<BTreeSet<_>>();
    while !pending.is_empty() {
        suppress_failed_descendants(
            &mut pending,
            &mut progress.indexed_outcomes,
            context.plan,
            context.assignment_schedule,
            context.artifacts,
        )?;
        if pending.is_empty() {
            break;
        }
        if !progress.health_breaker.permits_admission() {
            break;
        }
        if !context
            .budget_ledger
            .report()
            .context("failed to inspect run budget before serial admission")?
            .new_dispatch_allowed
        {
            progress.budget_prevented_dispatch = true;
            progress
                .budget_denied_assignment_indices
                .extend(pending.iter().copied());
            break;
        }
        let mut next = None;
        for candidate in pending.iter().copied() {
            if assignment_admission_state(
                candidate,
                context.assignment_schedule,
                &progress.indexed_outcomes,
            )? == AssignmentAdmissionState::Ready
            {
                next = Some(candidate);
                break;
            }
        }
        let Some(index) = next else {
            bail!("supervisor scheduler could not select a hierarchy-ready pending assignment");
        };
        pending.remove(&index);
        let assignment = &context.plan.assignments[index];
        let outcome = execute_supervisor_assignment(AssignmentExecutionContext {
            index,
            concurrent_mode: false,
            plan: context.plan,
            budget_config: context.budget_config,
            consultant: context.consultant,
            assignment_metadata: context.assignment_metadata,
            assignment,
            options: context.options,
            repo: context.repo,
            run_dir: context.run_dir,
            dirs: context.dirs,
            execution_runtime: context.execution_runtime,
            worktree_creation: context.worktree_creation,
            manager: context.manager,
            reused: context.existing_ids.contains(&assignment.id),
            sync_store: context.sync_store,
            semantic_store: context.semantic_store,
            prepared_semantic_token: context.prepared_semantic_assignments[index].token,
            prepared_semantic_findings: &context.prepared_semantic_assignments[index].findings,
            prepared_semantic_signals: &context.prepared_semantic_assignments[index].health_signals,
            prepared_semantic_failed: context.prepared_semantic_assignments[index]
                .assignment_failed,
            assignment_schedule: context.assignment_schedule,
            field_guide: context.field_guide,
            serial_semantic_warn_intents: Some(serial_semantic_warn_intents),
            semantic_block_order: None,
            semantic_block_gate: None,
            artifacts: context.artifacts,
            budget_ledger: context.budget_ledger,
            runtime_model_catalog: context.runtime_model_catalog,
            cancellation: cancellation.clone(),
            external_runner: context.external_runner,
        });
        let mut outcome = outcome;
        if context.release_per_assignment {
            release_concurrent_assignment(&mut outcome, context.sync_store, context.semantic_store);
        }
        if progress.circuit_breaker_trip.is_none() {
            if let Some(trip) = observe_assignment_health(&mut progress.health_breaker, &outcome) {
                record_breaker_trip(context.artifacts, &context.options.run_id, &trip)?;
                progress.circuit_breaker_trip = Some(trip);
            }
        }
        let abort = outcome.requires_scheduler_abort();
        let budget_stopped = outcome.budget_dispatch_stopped;
        progress.indexed_outcomes[index] = Some(outcome);
        if abort || budget_stopped {
            progress.budget_prevented_dispatch |= budget_stopped;
            if !pending.is_empty()
                && !context
                    .budget_ledger
                    .report()
                    .context("failed to inspect run budget after aborted serial dispatch")?
                    .new_dispatch_allowed
            {
                progress.budget_prevented_dispatch = true;
                progress
                    .budget_denied_assignment_indices
                    .extend(pending.iter().copied());
            }
            if budget_stopped {
                progress
                    .budget_denied_assignment_indices
                    .extend(pending.iter().copied());
            }
            break;
        }
        if !pending.is_empty()
            && !context
                .budget_ledger
                .report()
                .context("failed to inspect run budget after serial dispatch")?
                .new_dispatch_allowed
        {
            progress.budget_prevented_dispatch = true;
            progress
                .budget_denied_assignment_indices
                .extend(pending.iter().copied());
            break;
        }
    }
    Ok(())
}

fn run_concurrent_assignment_schedule(
    context: &AssignmentSchedulerContext<'_, '_>,
    progress: &mut SchedulerProgress,
    cancellation: &ProcessCancellation,
    semantic_block_gate: &SemanticBlockGate,
) -> Result<()> {
    thread::scope(|scope| -> Result<()> {
        let (completion_sender, completion_receiver) = mpsc::channel::<usize>();
        let mut pending = (0..context.plan.assignments.len()).collect::<BTreeSet<_>>();
        let mut active = BTreeMap::new();
        let mut stop_scheduling = false;
        let mut next_semantic_block_order = 0usize;

        while !pending.is_empty() || !active.is_empty() {
            if !stop_scheduling {
                suppress_failed_descendants(
                    &mut pending,
                    &mut progress.indexed_outcomes,
                    context.plan,
                    context.assignment_schedule,
                    context.artifacts,
                )?;
                while active.len() < context.max_concurrent_children {
                    if !progress.health_breaker.permits_admission() {
                        stop_scheduling = true;
                        break;
                    }
                    if !context
                        .budget_ledger
                        .report()
                        .context("failed to inspect run budget before concurrent admission")?
                        .new_dispatch_allowed
                    {
                        progress.budget_prevented_dispatch |= !pending.is_empty();
                        progress
                            .budget_denied_assignment_indices
                            .extend(pending.iter().copied());
                        stop_scheduling = true;
                        break;
                    }
                    let next = select_ready_nonoverlapping_assignment(
                        &pending,
                        context.assignment_schedule,
                        &progress.indexed_outcomes,
                        context.plan,
                        active.keys().copied(),
                    )?;
                    let Some(index) = next else {
                        break;
                    };
                    pending.remove(&index);
                    let assignment = &context.plan.assignments[index];
                    let semantic_block_order = (context.plan.semantic_coordination
                        == SemanticCoordinationMode::Block)
                        .then(|| {
                            let order = next_semantic_block_order;
                            next_semantic_block_order = next_semantic_block_order.saturating_add(1);
                            order
                        });
                    let completion_sender = completion_sender.clone();
                    let assignment_cancellation = cancellation.clone();
                    let spawn_result = thread::Builder::new().spawn_scoped(scope, move || {
                        let _completion = CompletionSignal {
                            index,
                            sender: completion_sender,
                        };
                        execute_supervisor_assignment(AssignmentExecutionContext {
                            index,
                            concurrent_mode: true,
                            plan: context.plan,
                            budget_config: context.budget_config,
                            consultant: context.consultant,
                            assignment_metadata: context.assignment_metadata,
                            assignment,
                            options: context.options,
                            repo: context.repo,
                            run_dir: context.run_dir,
                            dirs: context.dirs,
                            execution_runtime: context.execution_runtime,
                            worktree_creation: context.worktree_creation,
                            manager: context.manager,
                            reused: context.existing_ids.contains(&assignment.id),
                            sync_store: context.sync_store,
                            semantic_store: context.semantic_store,
                            prepared_semantic_token: context.prepared_semantic_assignments[index]
                                .token,
                            prepared_semantic_findings: &context.prepared_semantic_assignments
                                [index]
                                .findings,
                            prepared_semantic_signals: &context.prepared_semantic_assignments
                                [index]
                                .health_signals,
                            prepared_semantic_failed: context.prepared_semantic_assignments[index]
                                .assignment_failed,
                            assignment_schedule: context.assignment_schedule,
                            field_guide: context.field_guide,
                            serial_semantic_warn_intents: None,
                            semantic_block_order,
                            semantic_block_gate: semantic_block_order.map(|_| semantic_block_gate),
                            artifacts: context.artifacts,
                            budget_ledger: context.budget_ledger,
                            runtime_model_catalog: context.runtime_model_catalog,
                            cancellation: assignment_cancellation,
                            external_runner: context.external_runner,
                        })
                    });
                    match spawn_result {
                        Ok(handle) => {
                            active.insert(index, handle);
                        }
                        Err(error) => {
                            cancellation.cancel();
                            record_assignment_spawn_failure(
                                &mut progress.indexed_outcomes,
                                &mut stop_scheduling,
                                index,
                                &assignment.id,
                                &error,
                            )?;
                            break;
                        }
                    }
                }
            }

            if active.is_empty() {
                if pending.is_empty() || stop_scheduling {
                    break;
                }
                cancellation.cancel();
                bail!("supervisor scheduler could not select a hierarchy-ready pending assignment");
            }

            let completed_index = match completion_receiver.recv() {
                Ok(index) => index,
                Err(error) => {
                    cancellation.cancel();
                    return Err(error).context("supervisor assignment completion channel closed");
                }
            };
            let handle = match active.remove(&completed_index) {
                Some(handle) => handle,
                None => {
                    cancellation.cancel();
                    bail!("supervisor completion referenced an inactive assignment");
                }
            };
            let mut outcome = match handle.join() {
                Ok(outcome) => outcome,
                Err(_) => AssignmentExecutionOutcome::fatal(format!(
                    "supervisor assignment '{}' thread panicked",
                    context.plan.assignments[completed_index].id
                )),
            };
            release_concurrent_assignment(&mut outcome, context.sync_store, context.semantic_store);
            if outcome.requires_scheduler_abort() {
                cancellation.cancel();
                stop_scheduling = true;
            } else {
                if progress.circuit_breaker_trip.is_none() {
                    if let Some(trip) =
                        observe_assignment_health(&mut progress.health_breaker, &outcome)
                    {
                        record_breaker_trip(context.artifacts, &context.options.run_id, &trip)?;
                        progress.circuit_breaker_trip = Some(trip);
                        // A breaker trip is a graceful scheduler stop: pending assignments are not
                        // admitted, while already-active children retain their cancellation tokens
                        // and are drained.
                        stop_scheduling = true;
                    }
                }
                if outcome.budget_dispatch_stopped
                    || (!pending.is_empty()
                        && !context
                            .budget_ledger
                            .report()
                            .context("failed to inspect run budget after concurrent dispatch")?
                            .new_dispatch_allowed)
                {
                    progress.budget_prevented_dispatch = true;
                    progress
                        .budget_denied_assignment_indices
                        .extend(pending.iter().copied());
                    stop_scheduling = true;
                }
            }
            progress.indexed_outcomes[completed_index] = Some(outcome);
        }

        for (index, handle) in active {
            let mut outcome = match handle.join() {
                Ok(outcome) => outcome,
                Err(_) => AssignmentExecutionOutcome::fatal(format!(
                    "supervisor assignment '{}' thread panicked",
                    context.plan.assignments[index].id
                )),
            };
            release_concurrent_assignment(&mut outcome, context.sync_store, context.semantic_store);
            progress.indexed_outcomes[index] = Some(outcome);
        }
        Ok(())
    })
}

struct SupervisorFinalReportConstruction<'context> {
    plan: &'context SupervisorPlan,
    runtime_model_catalog: &'context RuntimeModelCatalog,
    run_id: RunId,
    report_plan_file: PathBuf,
    report_run_dir: PathBuf,
    runtime: SupervisorRuntime,
    publishable: bool,
    success: bool,
    run_budget_report: Option<RunBudgetReport>,
    role_usage: BTreeMap<AgentRole, RoleUsageReport>,
    review_lens_usage: Vec<ReviewLensUsageReport>,
    review_lens_total_usage: Option<Usage>,
    review_lens_total_cost_usd: Option<f64>,
    total_usage: Option<Usage>,
    total_cost_usd: Option<f64>,
    usage_complete: bool,
    environment_failures: Vec<EnvironmentFailure>,
    sandbox_denials: Vec<SandboxDenialEvidence>,
    collected: CollectedAssignmentOutcomes,
    bloated_file_flags: Vec<BloatedFileFlag>,
    decomposition_candidates: Vec<DecompositionCompletion>,
    assignment_traceability: Vec<AssignmentTraceability>,
    coverage_gaps: Vec<SupervisorCoverageGap>,
    supervisor_breaker_trip: Option<SupervisorBreakerTrip>,
    released_claims: Vec<PathClaim>,
    release_errors: Vec<String>,
    released_semantic_intents: Vec<SemanticIntent>,
    semantic_release_errors: Vec<String>,
    external_containment_failed: bool,
    final_primary_integrity_failed: bool,
    budget_prevented_dispatch: bool,
    budget_accounting_failed: bool,
    breaker_tripped: bool,
    field_guide_mutation_failed: bool,
}

fn build_supervisor_final_report(
    construction: SupervisorFinalReportConstruction<'_>,
) -> SupervisorFinalReport {
    let SupervisorFinalReportConstruction {
        plan,
        runtime_model_catalog,
        run_id,
        report_plan_file,
        report_run_dir,
        runtime,
        publishable,
        success,
        run_budget_report,
        role_usage,
        review_lens_usage,
        review_lens_total_usage,
        review_lens_total_cost_usd,
        total_usage,
        total_cost_usd,
        usage_complete,
        environment_failures,
        sandbox_denials,
        collected,
        bloated_file_flags,
        decomposition_candidates,
        assignment_traceability,
        coverage_gaps,
        supervisor_breaker_trip,
        released_claims,
        release_errors,
        released_semantic_intents,
        semantic_release_errors,
        external_containment_failed,
        final_primary_integrity_failed,
        budget_prevented_dispatch,
        budget_accounting_failed,
        breaker_tripped,
        field_guide_mutation_failed,
    } = construction;
    SupervisorFinalReport {
        version: SUPERVISOR_SCHEMA_VERSION,
        run_id,
        role: AgentRole::Supervisor,
        repo: PathBuf::from("."),
        plan_file: report_plan_file,
        run_dir: report_run_dir,
        runtime,
        publishable,
        success,
        accepted: publishable,
        rejected: !success,
        status: if success {
            ReviewStatus::Succeeded
        } else {
            ReviewStatus::Failed
        },
        assigned_paths: plan
            .assignments
            .iter()
            .flat_map(|assignment| assignment.assigned_paths.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        semantic_symbols: plan
            .assignments
            .iter()
            .flat_map(|assignment| assignment.semantic_symbols.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        semantic_modules: plan
            .assignments
            .iter()
            .flat_map(|assignment| assignment.semantic_modules.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        claim_tokens: released_claims
            .iter()
            .map(|claim| claim.token.get())
            .collect(),
        semantic_intent_tokens: released_semantic_intents
            .iter()
            .map(|intent| intent.token.get())
            .collect(),
        role_economics_profile: Some(
            plan.effective_role_economics_profile_for_runtime(runtime_model_catalog),
        ),
        run_budget: run_budget_report,
        role_usage,
        review_lens_usage,
        review_lens_total_usage,
        review_lens_total_cost_usd,
        total_usage,
        total_cost_usd,
        usage_complete,
        commands_run: collected.command_records,
        environment_failures: environment_failures.clone(),
        sandbox_denials,
        gate_denials: collected.gate_denials,
        pre_action_review_metrics: collected.pre_action_review_metrics,
        gate_correction_outcomes: collected.gate_correction_outcomes,
        files_changed: collected
            .orchestrator_reports
            .iter()
            .flat_map(|report| report.files_changed.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        validation_results: collected
            .orchestrator_reports
            .iter()
            .flat_map(|report| report.validation_results.iter().cloned())
            .collect(),
        findings: collected.findings,
        bloated_file_flags,
        decomposition_candidates,
        assignment_traceability,
        coverage_gaps: coverage_gaps.clone(),
        breaker_trip: supervisor_breaker_trip,
        orchestrator_reports: collected.orchestrator_reports,
        released_claims,
        release_errors,
        released_semantic_intents,
        semantic_release_errors,
        remaining_risk: if success && !publishable {
            "fake supervisor simulation succeeded but is not publishable or acceptable as real model evidence"
                .to_string()
        } else if success && !coverage_gaps.is_empty() {
            format!(
                "all child reports passed, but {} spec-to-diff traceability coverage gap(s) remain; worker changes remain isolated in child worktrees",
                coverage_gaps.len()
            )
        } else if success {
            "no failed child orchestrator reports; worker changes remain isolated in child worktrees"
                .to_string()
        } else if !environment_failures.is_empty() {
            "one or more assignments were blocked by unsatisfied structured environment requirements"
                .to_string()
        } else if external_containment_failed {
            "one or more external agent process trees lacked verified-empty containment; delayed child activity cannot be ruled out"
                .to_string()
        } else if final_primary_integrity_failed {
            "primary worktree final integrity could not be established".to_string()
        } else if budget_prevented_dispatch || budget_accounting_failed {
            "run budget enforcement stopped new dispatch or could not prove reliable accounting; already-started work was drained and assignment resources were released"
                .to_string()
        } else if breaker_tripped {
            "the swarm-health circuit breaker stopped pending assignment admission after a repeated coordination failure"
                .to_string()
        } else if field_guide_mutation_failed {
            "field-guide mutation or strict journal provenance did not complete; planned evidence may require manual reconciliation"
                .to_string()
        } else {
            "one or more child or worker reports failed, were rejected, or were missing".to_string()
        },
        next_safe_action: if success && !publishable {
            "rerun with the trusted system Codex runtime before any real acceptance, merge, or publication"
                .to_string()
        } else if success && !coverage_gaps.is_empty() {
            "inspect traceability coverage_gaps and child worktree diffs before any separate merge preview or apply step"
                .to_string()
        } else if success {
            "review child worktree diffs before any separate merge preview or apply step"
                .to_string()
        } else if !environment_failures.is_empty() {
            "apply the structured environment remediation without auto-installing software, injecting secrets, enabling networking, or broadening confinement, then rerun the blocked assignment"
                .to_string()
        } else if external_containment_failed {
            "do not trust or merge child outputs; restore the primary worktree if needed, fix host containment support, and rerun supervise"
                .to_string()
        } else if final_primary_integrity_failed {
            "inspect and restore the primary worktree before rerunning supervise".to_string()
        } else if budget_prevented_dispatch || budget_accounting_failed {
            "inspect run_budget reasons and per-role attribution, then raise the configured ceiling, repair pricing/usage accounting, or explicitly narrow the next run"
                .to_string()
        } else if breaker_tripped {
            BREAKER_RECOVERY_GUIDANCE.to_string()
        } else if field_guide_mutation_failed {
            "inspect strict field-guide planned/committed journal evidence and authenticated state before any manual retry"
                .to_string()
        } else {
            "inspect run reports and rerun failed child scopes after correcting the issue"
                .to_string()
        },
    }
}

struct ReleasedSchedulerResources {
    released_claims: Vec<PathClaim>,
    release_errors: Vec<String>,
    released_semantic_intents: Vec<SemanticIntent>,
    semantic_release_errors: Vec<String>,
}

fn release_collected_scheduler_resources(
    sync_store: Option<&SyncStore>,
    semantic_store: Option<&SemanticIntentStore>,
    collected: &mut CollectedAssignmentOutcomes,
) -> ReleasedSchedulerResources {
    let (mut released_claims, mut release_errors) = match sync_store {
        Some(store) => release_claims(store, std::mem::take(&mut collected.acquired_claim_tokens)),
        None => (Vec::new(), Vec::new()),
    };
    released_claims.extend(std::mem::take(&mut collected.concurrently_released_claims));
    release_errors.extend(std::mem::take(&mut collected.concurrent_release_errors));
    let (mut released_semantic_intents, mut semantic_release_errors) = match semantic_store {
        Some(store) => release_semantic_intents(
            store,
            std::mem::take(&mut collected.acquired_semantic_tokens),
        ),
        None => (Vec::new(), Vec::new()),
    };
    released_semantic_intents.extend(std::mem::take(
        &mut collected.concurrently_released_semantic_intents,
    ));
    semantic_release_errors.extend(std::mem::take(
        &mut collected.concurrent_semantic_release_errors,
    ));
    ReleasedSchedulerResources {
        released_claims,
        release_errors,
        released_semantic_intents,
        semantic_release_errors,
    }
}

fn supervisor_report_paths(
    repo: &Path,
    plan_file: &Path,
    run_dir: &Path,
    run_id: &RunId,
) -> (PathBuf, PathBuf) {
    let report_plan_file = plan_file
        .strip_prefix(repo)
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| PathBuf::from("<external-plan>"));
    let report_run_dir = run_dir
        .strip_prefix(repo)
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| {
            RunArtifactFamily::Supervise
                .run_root()
                .join(run_id.as_str())
        });
    (report_plan_file, report_run_dir)
}

fn persist_supervisor_final_report(
    mut final_report: SupervisorFinalReport,
    orchestration_journal: &mut Option<OrchestrationEventJournal>,
    mut artifact_writer: ArtifactRunWriter,
) -> Result<SupervisorFinalReport> {
    enforce_supervisor_final_environment_failure_outcome(&mut final_report);
    record_orchestration_event(
        orchestration_journal,
        &mut artifact_writer,
        final_report.run_id.as_str(),
        None,
        OrchestrationRole::Supervisor,
        OrchestrationEventKind::Gate,
        json!({
            "success": final_report.success,
            "publishable": final_report.publishable,
            "accepted": final_report.accepted,
            "rejected": final_report.rejected,
            "breaker_trip": final_report.breaker_trip,
            "run_budget": final_report.run_budget,
        }),
    );
    record_orchestration_event(
        orchestration_journal,
        &mut artifact_writer,
        final_report.run_id.as_str(),
        None,
        OrchestrationRole::Supervisor,
        OrchestrationEventKind::Status,
        json!({
            "status": "final",
            "result": final_report.status,
            "success": final_report.success,
            "run_budget": final_report.run_budget,
        }),
    );
    write_final_report(&mut artifact_writer, &final_report)?;
    artifact_writer.finalize(
        RunArtifactFamily::Supervise.final_report_relative_path(),
        final_report.publishable,
    )?;
    Ok(final_report)
}

struct SchedulerEvidenceInitialization<'context> {
    plan: &'context SupervisorPlan,
    consultant: &'context SupervisorConsultantPlan,
    assignment_metadata: &'context AssignmentMetadata,
    plan_metadata: &'context SupervisorPlanMetadata,
    options: &'context SupervisorRunOptions,
    repo: &'context Path,
    execution_runtime: SupervisorExecutionRuntime,
    artifact_writer: &'context mut ArtifactRunWriter,
    field_guide_store_slot: &'context mut Option<FieldGuideStore>,
    field_guide_prompt_slot: &'context mut Option<SupervisorFieldGuidePrompt>,
    sync_store_slot: &'context mut Option<SyncStore>,
    semantic_store_slot: &'context mut Option<SemanticIntentStore>,
    orchestration_journal: &'context mut Option<OrchestrationEventJournal>,
    primary_run_baseline: &'context mut Option<PrimaryWorktreeSnapshot>,
}

fn initialize_scheduler_evidence(
    initialization: &mut SchedulerEvidenceInitialization<'_>,
) -> Result<()> {
    if !initialization.options.allow_dirty_primary {
        ensure_clean_primary(initialization.repo, initialization.execution_runtime)?;
    }
    write_plan_snapshot(
        initialization.artifact_writer,
        Path::new("assignments/supervisor-plan.json"),
        initialization.plan,
        initialization.consultant,
        initialization.assignment_metadata,
        initialization.plan_metadata,
    )?;
    write_orchestrator_schema(
        initialization.artifact_writer,
        Path::new("schemas/orchestrator-review-report.schema.json"),
    )?;
    write_worker_schema(
        initialization.artifact_writer,
        Path::new("schemas/worker-report.schema.json"),
    )?;
    write_auditor_schema(
        initialization.artifact_writer,
        Path::new("schemas/auditor-report.schema.json"),
    )?;
    write_supervisor_final_schema(
        initialization.artifact_writer,
        Path::new("schemas/supervisor-final-report.schema.json"),
    )?;
    let field_guide_store = FieldGuideStore::open(initialization.repo, FieldGuideLimits::default())
        .context("failed to open authenticated field guide for supervise run")?;
    let field_guide_prompt = SupervisorFieldGuidePrompt::from_store(&field_guide_store)?;
    *initialization.field_guide_store_slot = Some(field_guide_store);
    *initialization.field_guide_prompt_slot = Some(field_guide_prompt);
    *initialization.sync_store_slot = Some(SyncStore::open(initialization.repo)?);
    *initialization.semantic_store_slot = Some(SemanticIntentStore::open(initialization.repo)?);
    *initialization.orchestration_journal =
        initialize_orchestration_event_journal(initialization.repo, &initialization.options.run_id);
    record_orchestration_event(
        initialization.orchestration_journal,
        initialization.artifact_writer,
        initialization.options.run_id.as_str(),
        None,
        OrchestrationRole::Supervisor,
        OrchestrationEventKind::Status,
        lifecycle_event_payload("running", None, None),
    );

    let baseline =
        primary_worktree_snapshot(initialization.repo, initialization.execution_runtime)?;
    if let Some(error) = baseline.inspection_problem() {
        bail!(
            "refusing to launch supervised work without a complete primary integrity snapshot: {error}"
        );
    }
    *initialization.primary_run_baseline = Some(baseline);
    Ok(())
}

struct PreparedSupervisorRun {
    plan: SupervisorPlan,
    consultant: SupervisorConsultantPlan,
    assignment_metadata: AssignmentMetadata,
    plan_metadata: SupervisorPlanMetadata,
    runtime_model_catalog: RuntimeModelCatalog,
    budget_ledger: RunBudgetLedger,
    runtime: SupervisorRuntime,
    repo: PathBuf,
    assignment_schedule: Vec<AssignmentScheduleEntry>,
    artifact_writer: ArtifactRunWriter,
    run_dir: PathBuf,
    dirs: RunDirs,
    manager: WorktreeManager,
}

fn prepare_supervisor_run(
    loaded: LoadedSupervisorPlan,
    options: &SupervisorRunOptions,
    max_concurrent_children: usize,
    execution_runtime: SupervisorExecutionRuntime,
    worktree_creation: SupervisorWorktreeCreation<'_>,
    runtime_model_catalog: Result<RuntimeModelCatalog>,
) -> Result<PreparedSupervisorRun> {
    let LoadedSupervisorPlan {
        plan,
        consultant,
        assignment_metadata,
        plan_metadata,
    } = loaded;
    let runtime_model_catalog = runtime_model_catalog.context(
        "runtime model availability could not be established; refusing supervisor dispatch",
    )?;
    validate_max_concurrent_children(max_concurrent_children)?;
    let budget_ledger = RunBudgetLedger::new(plan_metadata.run_budget.limits)
        .context("failed to initialize the supervise run budget ledger")?;
    match worktree_creation {
        SupervisorWorktreeCreation::Bound(_)
            if execution_runtime != SupervisorExecutionRuntime::Verified =>
        {
            bail!("verified worktree creation capability requires the verified supervisor runtime")
        }
        #[cfg(test)]
        SupervisorWorktreeCreation::TestOnly
            if execution_runtime != SupervisorExecutionRuntime::NonpublishableSimulation =>
        {
            bail!("test-only worktree creation requires the simulation supervisor runtime")
        }
        _ => {}
    }
    let runtime = options.runtime;
    let repo = discover_repo_root(&options.repo)?;
    let assignment_schedule = validated_scheduler_assignment_schedule(&plan, &plan_metadata)?;
    let artifact_writer = ArtifactRunWriter::reserve(
        &repo,
        RunArtifactFamily::Supervise,
        options.run_id.clone(),
        "maco-supervise",
    )?;
    let run_dir = artifact_writer.run_dir().to_path_buf();
    let dirs = RunDirs::for_writer(&artifact_writer);
    let manager = WorktreeManager::new(&repo);
    Ok(PreparedSupervisorRun {
        plan,
        consultant,
        assignment_metadata,
        plan_metadata,
        runtime_model_catalog,
        budget_ledger,
        runtime,
        repo,
        assignment_schedule,
        artifact_writer,
        run_dir,
        dirs,
        manager,
    })
}

pub(super) fn run_supervisor_plan_with_runner_and_creation(
    loaded: LoadedSupervisorPlan,
    options: SupervisorRunOptions,
    max_concurrent_children: usize,
    execution_runtime: SupervisorExecutionRuntime,
    worktree_creation: SupervisorWorktreeCreation<'_>,
    runtime_model_catalog: Result<RuntimeModelCatalog>,
    external_runner: &CancellableExternalRunner<'_>,
) -> Result<SupervisorFinalReport> {
    let PreparedSupervisorRun {
        plan,
        consultant,
        assignment_metadata,
        plan_metadata,
        runtime_model_catalog,
        budget_ledger,
        runtime,
        repo,
        assignment_schedule,
        mut artifact_writer,
        run_dir,
        dirs,
        manager,
    } = prepare_supervisor_run(
        loaded,
        &options,
        max_concurrent_children,
        execution_runtime,
        worktree_creation,
        runtime_model_catalog,
    )?;
    let budget_config = &plan_metadata.run_budget;
    let mut sync_store_slot = None;
    let mut semantic_store_slot = None;
    let mut field_guide_store_slot = None;
    let mut field_guide_prompt_slot = None;
    let mut orchestration_journal = None;
    let mut collected = CollectedAssignmentOutcomes::default();
    if runtime == SupervisorRuntime::Fake {
        collected.findings.push(Finding {
            severity: FindingSeverity::Warning,
            message:
                "explicit fake supervisor runtime is simulation-only and cannot publish acceptance"
                    .to_string(),
            paths: Vec::new(),
        });
    }
    let mut primary_run_baseline = None;
    let mut budget_prevented_dispatch = false;
    let mut budget_denied_assignment_indices = BTreeSet::new();
    let mut circuit_breaker_trip = None;
    let run_result = (|| -> Result<()> {
        initialize_scheduler_evidence(&mut SchedulerEvidenceInitialization {
            plan: &plan,
            consultant: &consultant,
            assignment_metadata: &assignment_metadata,
            plan_metadata: &plan_metadata,
            options: &options,
            repo: &repo,
            execution_runtime,
            artifact_writer: &mut artifact_writer,
            field_guide_store_slot: &mut field_guide_store_slot,
            field_guide_prompt_slot: &mut field_guide_prompt_slot,
            sync_store_slot: &mut sync_store_slot,
            semantic_store_slot: &mut semantic_store_slot,
            orchestration_journal: &mut orchestration_journal,
            primary_run_baseline: &mut primary_run_baseline,
        })?;
        let sync_store = sync_store_slot
            .as_ref()
            .context("supervisor sync store was not initialized")?;
        let semantic_store = semantic_store_slot
            .as_ref()
            .context("supervisor semantic store was not initialized")?;
        let field_guide = field_guide_prompt_slot
            .as_ref()
            .context("supervisor field-guide prompt was not initialized")?;

        let existing_ids = manager
            .list()?
            .into_iter()
            .map(|record| record.name)
            .collect::<BTreeSet<_>>();
        let release_per_assignment = release_assignment_resources_after_completion(
            &plan,
            &assignment_schedule,
            max_concurrent_children,
        );
        let prepared_semantic_assignments = if max_concurrent_children > 1 {
            prepare_semantic_warn_assignments(semantic_store, &plan, &assignment_schedule)?
        } else {
            plan.assignments
                .iter()
                .map(|_| PreparedSemanticAssignment::default())
                .collect()
        };
        let (scheduler_result, progress) = {
            let cancellation = ProcessCancellation::new();
            let shared_artifacts = Mutex::new(SharedSupervisorArtifacts {
                writer: &mut artifact_writer,
                journal: &mut orchestration_journal,
            });
            let semantic_block_gate = SemanticBlockGate::default();
            let serial_semantic_warn_intents = Mutex::new(Vec::<(usize, SemanticIntent)>::new());
            let mut progress = SchedulerProgress::new(plan.assignments.len());
            let scheduler_context = AssignmentSchedulerContext {
                plan: &plan,
                budget_config,
                consultant: &consultant,
                assignment_metadata: &assignment_metadata,
                options: &options,
                repo: &repo,
                run_dir: &run_dir,
                dirs: &dirs,
                execution_runtime,
                worktree_creation,
                manager: &manager,
                existing_ids: &existing_ids,
                sync_store,
                semantic_store,
                prepared_semantic_assignments: &prepared_semantic_assignments,
                assignment_schedule: &assignment_schedule,
                field_guide,
                artifacts: &shared_artifacts,
                budget_ledger: &budget_ledger,
                runtime_model_catalog: &runtime_model_catalog,
                external_runner,
                release_per_assignment,
                max_concurrent_children,
            };
            let scheduler_result = if max_concurrent_children == 1 {
                if let Err(error) = run_serial_assignment_schedule(
                    &scheduler_context,
                    &mut progress,
                    &cancellation,
                    &serial_semantic_warn_intents,
                ) {
                    budget_prevented_dispatch |= progress.budget_prevented_dispatch;
                    budget_denied_assignment_indices
                        .extend(progress.budget_denied_assignment_indices);
                    circuit_breaker_trip = progress.circuit_breaker_trip;
                    return Err(error);
                }
                Ok(())
            } else {
                run_concurrent_assignment_schedule(
                    &scheduler_context,
                    &mut progress,
                    &cancellation,
                    &semantic_block_gate,
                )
            };
            (scheduler_result, progress)
        };
        budget_prevented_dispatch |= progress.budget_prevented_dispatch;
        budget_denied_assignment_indices.extend(progress.budget_denied_assignment_indices);
        circuit_breaker_trip = progress.circuit_breaker_trip;

        let fatal_errors = collect_indexed_assignment_outcomes(
            progress.indexed_outcomes,
            release_per_assignment,
            &mut collected,
        );
        scheduler_result?;
        if let Some(error) = fatal_errors.into_iter().next() {
            bail!("{error}");
        }
        Ok(())
    })();

    if let Err(error) = &run_result {
        collected.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: format!("{error:#}"),
            paths: Vec::new(),
        });
    }
    let breaker_tripped = circuit_breaker_trip.is_some();
    let supervisor_breaker_trip = circuit_breaker_trip.map(|trip| SupervisorBreakerTrip {
        reason: trip.reason,
        window: trip.window,
        recovery_guidance: BREAKER_RECOVERY_GUIDANCE.to_string(),
    });
    if let Some(trip) = &supervisor_breaker_trip {
        collected.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: format!(
                "swarm-health circuit breaker opened and drained active assignments: {:?}",
                trip.reason
            ),
            paths: Vec::new(),
        });
    }

    let ReleasedSchedulerResources {
        released_claims,
        release_errors,
        released_semantic_intents,
        semantic_release_errors,
    } = release_collected_scheduler_resources(
        sync_store_slot.as_ref(),
        semantic_store_slot.as_ref(),
        &mut collected,
    );
    let final_primary_integrity_failed = match primary_run_baseline.as_ref() {
        Some(baseline) => match primary_worktree_snapshot(&repo, execution_runtime) {
            Ok(final_snapshot) => {
                if let Some(error) = final_snapshot.inspection_problem() {
                    collected.findings.push(Finding {
                        severity: FindingSeverity::Error,
                        message: format!(
                            "primary worktree final integrity snapshot was incomplete: {error}"
                        ),
                        paths: Vec::new(),
                    });
                    true
                } else {
                    let changes = primary_integrity_changes(baseline, &final_snapshot);
                    let integrity_failed = !changes.is_empty();
                    if integrity_failed {
                        collected.findings.push(Finding {
                            severity: FindingSeverity::Error,
                            message: format!(
                                "primary worktree integrity differed from the supervise-run baseline during final acceptance: {}",
                                changes.details.join("; ")
                            ),
                            paths: changes.paths,
                        });
                    }
                    integrity_failed
                }
            }
            Err(error) => {
                collected.findings.push(Finding {
                    severity: FindingSeverity::Error,
                    message: format!("primary worktree final integrity check failed: {error}"),
                    paths: Vec::new(),
                });
                true
            }
        },
        None => true,
    };
    let nested_workers_present = plan
        .assignments
        .iter()
        .any(|assignment| !assignment.worker_assignments.is_empty());
    if nested_workers_present {
        collected.findings.push(Finding {
            severity: FindingSeverity::Warning,
            message: "worker usage is not process-observable because nested workers execute inside child Codex sessions; child-orchestrator and auditor process usage remains reportable, while runtime-side role-tagged usage reporting is required before worker usage or cost can be reported"
                .to_string(),
            paths: Vec::new(),
        });
    }
    let (run_budget_report, budget_accounting_failed) = match budget_ledger.report() {
        Ok(report) => (Some(report), false),
        Err(error) => {
            collected.findings.push(Finding {
                severity: FindingSeverity::Error,
                message: format!("run budget accounting could not be finalized: {error}"),
                paths: Vec::new(),
            });
            (None, true)
        }
    };
    collected.usage_incomplete |= budget_accounting_failed
        || run_budget_report
            .as_ref()
            .is_some_and(|report| !report.usage_complete);
    if collected.usage_incomplete {
        collected.findings.push(Finding {
            severity: FindingSeverity::Warning,
            message: "process usage is incomplete because at least one external Codex JSONL capture was missing, truncated, or malformed, or conservatively reconciled because usage was observed but unreliable after its run failed, timed out, or lacked verified completion or containment"
                .to_string(),
            paths: Vec::new(),
        });
    }
    if budget_prevented_dispatch {
        for index in &budget_denied_assignment_indices {
            let assignment = plan
                .assignments
                .get(*index)
                .context("budget denial referenced an assignment outside the plan")?;
            collected.gate_denials.push(
                GateDenial::new(
                    gate_correlation_id(&assignment.id, 1),
                    GateDenialReason::BudgetAdmission {
                        denial: BudgetAdmissionDenial::NewDispatchStopped,
                    },
                    VerifiedGateContext::new(
                        &assignment.id,
                        GateCheckSource::BudgetAdmission,
                        &assignment.assigned_paths,
                    )?,
                )
                .context("failed to construct scheduler budget-admission gate denial")?,
            );
        }
        collected.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: "run budget stopped one or more new dispatches and drained already-started work; inspect typed gate_denials and the structured run_budget report"
                .to_string(),
            paths: Vec::new(),
        });
    }
    let field_guide_mutation_failed = match append_accepted_field_guide_drafts(
        &plan,
        &collected.orchestrator_reports,
        &options.run_id,
        field_guide_store_slot.as_ref(),
        &mut orchestration_journal,
        &mut artifact_writer,
    ) {
        Ok(_) => false,
        Err(error) => {
            collected.findings.push(Finding {
                severity: FindingSeverity::Error,
                message: format!(
                    "accepted field-guide suggestions were not fully persisted: {error:#}; do not retry blindly when planned mutation evidence exists"
                ),
                paths: Vec::new(),
            });
            true
        }
    };
    let environment_failures =
        aggregate_environment_failures(&collected.command_records, &collected.orchestrator_reports);
    let failed = run_result.is_err()
        || !release_errors.is_empty()
        || !semantic_release_errors.is_empty()
        || collected.assignment_execution_failed
        || budget_prevented_dispatch
        || budget_accounting_failed
        || collected.external_containment_failed
        || final_primary_integrity_failed
        || breaker_tripped
        || field_guide_mutation_failed
        || !environment_failures.is_empty()
        || collected.orchestrator_reports.iter().any(report_failed);
    let success = !failed;
    let publishable = success && runtime == SupervisorRuntime::Codex;
    let (report_plan_file, report_run_dir) =
        supervisor_report_paths(&repo, &options.plan_file, &run_dir, &options.run_id);
    let usage_complete = !collected.usage_incomplete;
    let RoleUsageAggregation {
        reports: mut role_usage,
        lens_reports: review_lens_usage,
        total_usage,
        total_cost_usd: observed_total_cost_usd,
        lens_total_usage: review_lens_total_usage,
        lens_total_cost_usd: observed_review_lens_total_cost_usd,
    } = role_usage_report(&plan, std::mem::take(&mut collected.usage_samples))?;
    let total_cost_usd =
        finalize_supervisor_cost(usage_complete, &mut role_usage, observed_total_cost_usd);
    let review_lens_total_cost_usd = usage_complete
        .then_some(observed_review_lens_total_cost_usd)
        .flatten();
    let bloated_file_flags = accepted_bloated_file_flags(&collected.orchestrator_reports);
    let decomposition_candidates =
        accepted_decomposition_candidates(&collected.orchestrator_reports);
    let (assignment_traceability, runtime_coverage_gaps) = supervisor_assignment_traceability(
        &plan,
        &plan_metadata,
        &collected.orchestrator_reports,
        &collected.candidate_inspections,
    );
    let mut coverage_gaps = plan_metadata.coverage_gaps.clone();
    coverage_gaps.extend(runtime_coverage_gaps);
    let sandbox_denials = aggregate_sandbox_denials(&collected.command_records);
    let external_containment_failed = collected.external_containment_failed;
    let final_report = build_supervisor_final_report(SupervisorFinalReportConstruction {
        plan: &plan,
        runtime_model_catalog: &runtime_model_catalog,
        run_id: options.run_id,
        report_plan_file,
        report_run_dir,
        runtime,
        publishable,
        success,
        run_budget_report,
        role_usage,
        review_lens_usage,
        review_lens_total_usage,
        review_lens_total_cost_usd,
        total_usage,
        total_cost_usd,
        usage_complete,
        environment_failures,
        sandbox_denials,
        collected,
        bloated_file_flags,
        decomposition_candidates,
        assignment_traceability,
        coverage_gaps,
        supervisor_breaker_trip,
        released_claims,
        release_errors,
        released_semantic_intents,
        semantic_release_errors,
        external_containment_failed,
        final_primary_integrity_failed,
        budget_prevented_dispatch,
        budget_accounting_failed,
        breaker_tripped,
        field_guide_mutation_failed,
    });
    persist_supervisor_final_report(final_report, &mut orchestration_journal, artifact_writer)
}

#[cfg(test)]
mod decomposition_tests {
    use super::*;
    use crate::orchestration_event::{OrchestrationEvent, ORCHESTRATION_EVENT_PATH};
    use git2::Signature;

    static TEST_RUNTIME_MODEL_CATALOG: RuntimeModelCatalog =
        RuntimeModelCatalog::LocalDeterministicFake;

    fn test_assignment(id: &str, path: &str) -> OrchestratorAssignment {
        OrchestratorAssignment {
            id: id.to_string(),
            role: AgentRole::ChildOrchestrator,
            assigned_paths: vec![PathBuf::from(path)],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            task: None,
            worker_assignments: Vec::new(),
            environment_requirements: Vec::new(),
            notes: None,
        }
    }

    fn test_plan(assignments: Vec<OrchestratorAssignment>) -> SupervisorPlan {
        SupervisorPlan {
            version: SUPERVISOR_SCHEMA_VERSION,
            task: "scheduler decomposition fixture".to_string(),
            task_file: None,
            max_depth: MIN_SUPERVISOR_DEPTH,
            max_child_assignments: assignments.len(),
            max_child_retries: 0,
            max_gate_corrections: 0,
            child_timeout_seconds: 10,
            semantic_coordination: SemanticCoordinationMode::Off,
            role_models: BTreeMap::new(),
            model_pricing: BTreeMap::new(),
            review_lenses: default_supervisor_review_lenses(),
            review_aggregation_policy: ReviewAggregationPolicy::AllMustAccept,
            assignments,
        }
    }

    fn root_schedule(plan: &SupervisorPlan) -> Vec<AssignmentScheduleEntry> {
        plan.assignments
            .iter()
            .enumerate()
            .map(|(flattened_index, assignment)| AssignmentScheduleEntry {
                assignment_id: assignment.id.clone(),
                parent_assignment_id: None,
                depth: MIN_SUPERVISOR_DEPTH,
                flattened_index,
            })
            .collect()
    }

    fn test_options(repo: &Path, run_id: &str) -> SupervisorRunOptions {
        SupervisorRunOptions {
            repo: repo.to_path_buf(),
            plan_file: repo.join("plan.json"),
            run_id: RunId::new(run_id).expect("valid scheduler test run id"),
            codex_bin: PathBuf::from("unused-test-codex"),
            runtime: SupervisorRuntime::Fake,
            allow_dirty_primary: true,
            machine_global_retention: None,
        }
    }

    fn test_repository() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().expect("temporary scheduler repository");
        let repo = temp.path().join("repo");
        let repository = Repository::init(&repo).expect("initialize scheduler repository");
        fs::write(repo.join("README.md"), "scheduler fixture\n")
            .expect("write scheduler repository fixture");
        fs::write(
            repo.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
        )
        .expect("write second scheduler repository fixture");
        let mut index = repository.index().expect("open scheduler fixture index");
        index
            .add_all(["*"], git2::IndexAddOption::DEFAULT, None)
            .expect("stage scheduler fixture");
        index.write().expect("write scheduler fixture index");
        let tree_id = index.write_tree().expect("write scheduler fixture tree");
        let tree = repository
            .find_tree(tree_id)
            .expect("find scheduler fixture tree");
        let signature =
            Signature::now("maco test", "maco-test@example.invalid").expect("fixture signature");
        repository
            .commit(Some("HEAD"), &signature, &signature, "baseline", &tree, &[])
            .expect("commit scheduler fixture");
        (temp, repo)
    }

    macro_rules! with_invalid_schedule_context {
        ($context:ident, $body:block) => {{
            let (_temp, repo) = test_repository();
            let options = test_options(&repo, "direct-scheduler");
            let plan = test_plan(vec![test_assignment("child-a", "README.md")]);
            let schedule = Vec::new();
            let consultant = SupervisorConsultantPlan::default();
            let assignment_metadata = AssignmentMetadata::new();
            let budget_config = SupervisorBudgetConfig::default();
            let budget_ledger =
                RunBudgetLedger::new(budget_config.limits).expect("test budget ledger");
            let mut artifact_writer = ArtifactRunWriter::reserve(
                &repo,
                RunArtifactFamily::Supervise,
                options.run_id.clone(),
                "scheduler-decomposition-test",
            )
            .expect("reserve scheduler artifacts");
            let run_dir = artifact_writer.run_dir().to_path_buf();
            let dirs = RunDirs::for_writer(&artifact_writer);
            let manager = WorktreeManager::new(&repo);
            let existing_ids = BTreeSet::new();
            let sync_store = SyncStore::open(&repo).expect("open scheduler sync store");
            let semantic_store =
                SemanticIntentStore::open(&repo).expect("open scheduler semantic store");
            let prepared = vec![PreparedSemanticAssignment::default()];
            let field_guide =
                SupervisorFieldGuidePrompt::empty().expect("empty scheduler field guide");
            let mut journal = initialize_orchestration_event_journal(&repo, &options.run_id);
            let shared_artifacts = Mutex::new(SharedSupervisorArtifacts {
                writer: &mut artifact_writer,
                journal: &mut journal,
            });
            let runtime_model_catalog = RuntimeModelCatalog::LocalDeterministicFake;
            let runner = |_: &ExternalAgentCommand,
                          _: &ProcessCancellation,
                          _: Option<ExternalPreActionReviewRuntime<'_>>|
             -> ExternalAgentRun {
                panic!("invalid schedule must fail before external dispatch")
            };
            let $context = AssignmentSchedulerContext {
                plan: &plan,
                budget_config: &budget_config,
                consultant: &consultant,
                assignment_metadata: &assignment_metadata,
                options: &options,
                repo: &repo,
                run_dir: &run_dir,
                dirs: &dirs,
                execution_runtime: SupervisorExecutionRuntime::NonpublishableSimulation,
                worktree_creation: SupervisorWorktreeCreation::TestOnly,
                manager: &manager,
                existing_ids: &existing_ids,
                sync_store: &sync_store,
                semantic_store: &semantic_store,
                prepared_semantic_assignments: &prepared,
                assignment_schedule: &schedule,
                field_guide: &field_guide,
                artifacts: &shared_artifacts,
                budget_ledger: &budget_ledger,
                runtime_model_catalog: &runtime_model_catalog,
                external_runner: &runner,
                release_per_assignment: false,
                max_concurrent_children: 2,
            };
            $body
        }};
    }

    macro_rules! with_valid_schedule_context {
        ($context:ident, $assignments:expr, $max_children:expr, $body:block) => {{
            let (_temp, repo) = test_repository();
            let options = test_options(&repo, "direct-valid-scheduler");
            let plan = test_plan($assignments);
            let schedule = root_schedule(&plan);
            let consultant = SupervisorConsultantPlan::default();
            let assignment_metadata = AssignmentMetadata::new();
            let budget_config = SupervisorBudgetConfig::default();
            let budget_ledger =
                RunBudgetLedger::new(budget_config.limits).expect("test budget ledger");
            let mut artifact_writer = ArtifactRunWriter::reserve(
                &repo,
                RunArtifactFamily::Supervise,
                options.run_id.clone(),
                "scheduler-success-test",
            )
            .expect("reserve scheduler artifacts");
            let run_dir = artifact_writer.run_dir().to_path_buf();
            let dirs = RunDirs::for_writer(&artifact_writer);
            let manager = WorktreeManager::new(&repo);
            let existing_ids = BTreeSet::new();
            let sync_store = SyncStore::open(&repo).expect("open scheduler sync store");
            let semantic_store =
                SemanticIntentStore::open(&repo).expect("open scheduler semantic store");
            let prepared = plan
                .assignments
                .iter()
                .map(|_| PreparedSemanticAssignment::default())
                .collect::<Vec<_>>();
            let field_guide =
                SupervisorFieldGuidePrompt::empty().expect("empty scheduler field guide");
            let mut journal = initialize_orchestration_event_journal(&repo, &options.run_id);
            let shared_artifacts = Mutex::new(SharedSupervisorArtifacts {
                writer: &mut artifact_writer,
                journal: &mut journal,
            });
            let runtime_model_catalog = RuntimeModelCatalog::LocalDeterministicFake;
            let runner = |_: &ExternalAgentCommand,
                          _: &ProcessCancellation,
                          _: Option<ExternalPreActionReviewRuntime<'_>>|
             -> ExternalAgentRun {
                panic!("fake scheduler success fixture must not invoke the external runner")
            };
            let $context = AssignmentSchedulerContext {
                plan: &plan,
                budget_config: &budget_config,
                consultant: &consultant,
                assignment_metadata: &assignment_metadata,
                options: &options,
                repo: &repo,
                run_dir: &run_dir,
                dirs: &dirs,
                execution_runtime: SupervisorExecutionRuntime::NonpublishableSimulation,
                worktree_creation: SupervisorWorktreeCreation::TestOnly,
                manager: &manager,
                existing_ids: &existing_ids,
                sync_store: &sync_store,
                semantic_store: &semantic_store,
                prepared_semantic_assignments: &prepared,
                assignment_schedule: &schedule,
                field_guide: &field_guide,
                artifacts: &shared_artifacts,
                budget_ledger: &budget_ledger,
                runtime_model_catalog: &runtime_model_catalog,
                external_runner: &runner,
                release_per_assignment: true,
                max_concurrent_children: $max_children,
            };
            $body
        }};
    }

    fn test_report_construction(
        plan: &SupervisorPlan,
        run_id: RunId,
    ) -> SupervisorFinalReportConstruction<'_> {
        SupervisorFinalReportConstruction {
            plan,
            runtime_model_catalog: &TEST_RUNTIME_MODEL_CATALOG,
            run_id,
            report_plan_file: PathBuf::from("plan.json"),
            report_run_dir: PathBuf::from(".maco/o2/runs/test"),
            runtime: SupervisorRuntime::Fake,
            publishable: false,
            success: true,
            run_budget_report: None,
            role_usage: BTreeMap::new(),
            review_lens_usage: Vec::new(),
            review_lens_total_usage: None,
            review_lens_total_cost_usd: None,
            total_usage: None,
            total_cost_usd: None,
            usage_complete: true,
            environment_failures: Vec::new(),
            sandbox_denials: Vec::new(),
            collected: CollectedAssignmentOutcomes::default(),
            bloated_file_flags: Vec::new(),
            decomposition_candidates: Vec::new(),
            assignment_traceability: Vec::new(),
            coverage_gaps: Vec::new(),
            supervisor_breaker_trip: None,
            released_claims: Vec::new(),
            release_errors: Vec::new(),
            released_semantic_intents: Vec::new(),
            semantic_release_errors: Vec::new(),
            external_containment_failed: false,
            final_primary_integrity_failed: false,
            budget_prevented_dispatch: false,
            budget_accounting_failed: false,
            breaker_tripped: false,
            field_guide_mutation_failed: false,
        }
    }

    #[test]
    fn ready_nonoverlap_selector_skips_active_path_conflict() {
        let plan = test_plan(vec![
            test_assignment("active", "src"),
            test_assignment("overlap", "src/lib.rs"),
            test_assignment("ready", "README.md"),
        ]);
        let schedule = root_schedule(&plan);
        let pending = BTreeSet::from([1, 2]);
        let outcomes = (0..plan.assignments.len())
            .map(|_| None)
            .collect::<Vec<_>>();

        let selected = select_ready_nonoverlapping_assignment(
            &pending,
            &schedule,
            &outcomes,
            &plan,
            std::iter::once(0),
        )
        .expect("select a ready non-overlapping assignment");

        assert_eq!(selected, Some(2));
    }

    #[test]
    fn serial_scheduler_preserves_schedule_error_context() {
        with_invalid_schedule_context!(context, {
            let mut progress = SchedulerProgress::new(1);
            let cancellation = ProcessCancellation::new();
            let serial_intents = Mutex::new(Vec::new());
            let error = run_serial_assignment_schedule(
                &context,
                &mut progress,
                &cancellation,
                &serial_intents,
            )
            .expect_err("invalid serial schedule must fail");
            assert_eq!(
                error.to_string(),
                "assignment admission referenced an index outside the validated schedule"
            );
            assert!(progress.indexed_outcomes[0].is_none());
        });
    }

    #[test]
    fn concurrent_scheduler_preserves_schedule_error_context_before_spawning() {
        with_invalid_schedule_context!(context, {
            let mut progress = SchedulerProgress::new(1);
            let cancellation = ProcessCancellation::new();
            let semantic_block_gate = SemanticBlockGate::default();
            let error = run_concurrent_assignment_schedule(
                &context,
                &mut progress,
                &cancellation,
                &semantic_block_gate,
            )
            .expect_err("invalid concurrent schedule must fail");
            assert_eq!(
                error.to_string(),
                "assignment admission referenced an index outside the validated schedule"
            );
            assert!(progress.indexed_outcomes[0].is_none());
        });
    }

    #[test]
    fn serial_scheduler_directly_dispatches_and_completes_fake_assignment() {
        with_valid_schedule_context!(
            context,
            vec![test_assignment("serial-child", "README.md")],
            1,
            {
                let mut progress = SchedulerProgress::new(1);
                let cancellation = ProcessCancellation::new();
                let serial_intents = Mutex::new(Vec::new());

                run_serial_assignment_schedule(
                    &context,
                    &mut progress,
                    &cancellation,
                    &serial_intents,
                )
                .expect("serial scheduler dispatch succeeds");

                let outcome = progress.indexed_outcomes[0]
                    .as_ref()
                    .expect("serial scheduler stores completed outcome");
                assert_eq!(
                    outcome.report.as_ref().map(|report| report.id.as_str()),
                    Some("serial-child")
                );
                assert!(outcome.fatal_error.is_none());
                assert!(!outcome.assignment_failed);
                assert_eq!(outcome.released_claims.len(), 1);
                assert!(outcome.release_errors.is_empty());
                assert!(outcome.semantic_release_errors.is_empty());
            }
        );
    }

    #[test]
    fn concurrent_scheduler_directly_dispatches_completes_and_orders_fake_assignments() {
        with_valid_schedule_context!(
            context,
            vec![
                test_assignment("concurrent-a", "README.md"),
                test_assignment("concurrent-b", "Cargo.toml"),
            ],
            2,
            {
                let mut progress = SchedulerProgress::new(2);
                let cancellation = ProcessCancellation::new();
                let semantic_block_gate = SemanticBlockGate::default();

                run_concurrent_assignment_schedule(
                    &context,
                    &mut progress,
                    &cancellation,
                    &semantic_block_gate,
                )
                .expect("concurrent scheduler dispatch succeeds");

                assert_eq!(
                    progress
                        .indexed_outcomes
                        .iter()
                        .map(|outcome| {
                            outcome
                                .as_ref()
                                .and_then(|outcome| outcome.report.as_ref())
                                .map(|report| report.id.as_str())
                        })
                        .collect::<Vec<_>>(),
                    vec![Some("concurrent-a"), Some("concurrent-b")]
                );
                assert!(progress.indexed_outcomes.iter().all(|outcome| {
                    outcome.as_ref().is_some_and(|outcome| {
                        outcome.fatal_error.is_none()
                            && !outcome.assignment_failed
                            && outcome.released_claims.len() == 1
                            && outcome.release_errors.is_empty()
                            && outcome.semantic_release_errors.is_empty()
                    })
                }));
            }
        );
    }

    #[test]
    fn indexed_outcome_collection_keeps_plan_order_and_first_fatal() {
        let first = AssignmentExecutionOutcome {
            findings: vec![Finding {
                severity: FindingSeverity::Warning,
                message: "first".to_string(),
                paths: Vec::new(),
            }],
            assignment_failed: true,
            fatal_error: Some("first fatal".to_string()),
            ..AssignmentExecutionOutcome::default()
        };
        let second = AssignmentExecutionOutcome {
            findings: vec![Finding {
                severity: FindingSeverity::Error,
                message: "second".to_string(),
                paths: Vec::new(),
            }],
            external_containment_failed: true,
            fatal_error: Some("second fatal".to_string()),
            ..AssignmentExecutionOutcome::default()
        };
        let mut collected = CollectedAssignmentOutcomes::default();

        let fatal_errors = collect_indexed_assignment_outcomes(
            vec![Some(first), None, Some(second)],
            false,
            &mut collected,
        );

        assert_eq!(fatal_errors, vec!["first fatal", "second fatal"]);
        assert_eq!(
            collected
                .findings
                .iter()
                .map(|finding| finding.message.as_str())
                .collect::<Vec<_>>(),
            vec!["first", "second"]
        );
        assert!(collected.assignment_execution_failed);
        assert!(collected.external_containment_failed);
    }

    #[test]
    fn resource_release_collection_preserves_concurrent_release_evidence_without_stores() {
        let released_claim = PathClaim {
            token: ClaimToken::from_u64(7),
            agent_id: "child-a".to_string(),
            paths: vec![PathBuf::from("README.md")],
        };
        let mut collected = CollectedAssignmentOutcomes {
            concurrently_released_claims: vec![released_claim.clone()],
            concurrent_release_errors: vec!["claim release failed".to_string()],
            concurrent_semantic_release_errors: vec!["semantic release failed".to_string()],
            ..CollectedAssignmentOutcomes::default()
        };

        let released = release_collected_scheduler_resources(None, None, &mut collected);

        assert_eq!(released.released_claims, vec![released_claim]);
        assert_eq!(released.release_errors, vec!["claim release failed"]);
        assert!(released.released_semantic_intents.is_empty());
        assert_eq!(
            released.semantic_release_errors,
            vec!["semantic release failed"]
        );
        assert!(collected.concurrently_released_claims.is_empty());
        assert!(collected.concurrent_release_errors.is_empty());
        assert!(collected.concurrent_semantic_release_errors.is_empty());
    }

    #[test]
    fn report_paths_keep_repo_relative_plan_and_fallback_for_external_run_dir() {
        let repo = Path::new("/repo");
        let run_id = RunId::new("direct-report-paths").expect("valid report path run id");

        let (plan_file, run_dir) = supervisor_report_paths(
            repo,
            Path::new("/repo/plans/supervise.json"),
            Path::new("/external/run"),
            &run_id,
        );

        assert_eq!(plan_file, PathBuf::from("plans/supervise.json"));
        assert_eq!(
            run_dir,
            RunArtifactFamily::Supervise
                .run_root()
                .join("direct-report-paths")
        );
    }

    #[test]
    fn report_builder_keeps_fake_success_nonpublishable() {
        let plan = test_plan(vec![
            test_assignment("child-a", "README.md"),
            test_assignment("child-b", "README.md"),
        ]);
        let report = build_supervisor_final_report(test_report_construction(
            &plan,
            RunId::new("direct-report-builder").expect("valid report run id"),
        ));

        assert!(report.success);
        assert!(!report.publishable);
        assert!(!report.accepted);
        assert_eq!(report.assigned_paths, vec![PathBuf::from("README.md")]);
        assert_eq!(
            report.remaining_risk,
            "fake supervisor simulation succeeded but is not publishable or acceptable as real model evidence"
        );
    }

    #[test]
    fn preflight_retains_runtime_catalog_error_context() {
        let loaded = LoadedSupervisorPlan {
            plan: test_plan(Vec::new()),
            consultant: SupervisorConsultantPlan::default(),
            assignment_metadata: AssignmentMetadata::new(),
            plan_metadata: SupervisorPlanMetadata::default(),
        };
        let options = test_options(Path::new("/does/not/need/to/exist"), "direct-preflight");

        let result = prepare_supervisor_run(
            loaded,
            &options,
            1,
            SupervisorExecutionRuntime::NonpublishableSimulation,
            SupervisorWorktreeCreation::TestOnly,
            Err(anyhow!("catalog probe failed")),
        );
        let error = match result {
            Ok(_) => panic!("catalog failure must stop before repository discovery"),
            Err(error) => error,
        };

        assert_eq!(
            format!("{error:#}"),
            "runtime model availability could not be established; refusing supervisor dispatch: catalog probe failed"
        );
    }

    #[test]
    fn preflight_directly_validates_schedule_and_reserves_artifacts() {
        let (_temp, repo) = test_repository();
        let plan = test_plan(vec![test_assignment("prepared-child", "README.md")]);
        let loaded = LoadedSupervisorPlan {
            plan,
            consultant: SupervisorConsultantPlan::default(),
            assignment_metadata: AssignmentMetadata::new(),
            plan_metadata: SupervisorPlanMetadata::default(),
        };
        let options = test_options(&repo, "direct-preflight-success");

        let prepared = prepare_supervisor_run(
            loaded,
            &options,
            1,
            SupervisorExecutionRuntime::NonpublishableSimulation,
            SupervisorWorktreeCreation::TestOnly,
            Ok(RuntimeModelCatalog::LocalDeterministicFake),
        )
        .expect("prepare scheduler run directly");

        assert_eq!(prepared.repo, repo);
        assert_eq!(prepared.runtime, SupervisorRuntime::Fake);
        assert_eq!(prepared.assignment_schedule.len(), 1);
        assert_eq!(
            prepared.assignment_schedule[0].assignment_id,
            "prepared-child"
        );
        assert!(prepared.run_dir.is_dir());
        assert_eq!(prepared.dirs.run_dir, prepared.run_dir);
        assert!(
            prepared
                .budget_ledger
                .report()
                .expect("prepared budget report")
                .new_dispatch_allowed
        );
    }

    #[test]
    fn evidence_initialization_populates_stores_journal_and_baseline() {
        let (_temp, repo) = test_repository();
        let options = test_options(&repo, "direct-evidence-initialization");
        let plan = test_plan(Vec::new());
        let consultant = SupervisorConsultantPlan::default();
        let assignment_metadata = AssignmentMetadata::new();
        let plan_metadata = SupervisorPlanMetadata::default();
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            options.run_id.clone(),
            "scheduler-initialization-test",
        )
        .expect("reserve initialization artifacts");
        let mut field_guide_store = None;
        let mut field_guide_prompt = None;
        let mut sync_store = None;
        let mut semantic_store = None;
        let mut journal = None;
        let mut baseline = None;

        initialize_scheduler_evidence(&mut SchedulerEvidenceInitialization {
            plan: &plan,
            consultant: &consultant,
            assignment_metadata: &assignment_metadata,
            plan_metadata: &plan_metadata,
            options: &options,
            repo: &repo,
            execution_runtime: SupervisorExecutionRuntime::NonpublishableSimulation,
            artifact_writer: &mut writer,
            field_guide_store_slot: &mut field_guide_store,
            field_guide_prompt_slot: &mut field_guide_prompt,
            sync_store_slot: &mut sync_store,
            semantic_store_slot: &mut semantic_store,
            orchestration_journal: &mut journal,
            primary_run_baseline: &mut baseline,
        })
        .expect("initialize scheduler evidence directly");

        assert!(field_guide_store.is_some());
        assert!(field_guide_prompt.is_some());
        assert!(sync_store.is_some());
        assert!(semantic_store.is_some());
        assert!(journal.is_some());
        assert!(baseline.is_some());
    }

    #[test]
    fn persistence_records_gate_before_status_and_finalizes_report() {
        let (_temp, repo) = test_repository();
        let run_id = RunId::new("direct-report-persistence").expect("valid persistence run id");
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            run_id.clone(),
            "scheduler-persistence-test",
        )
        .expect("reserve persistence artifacts");
        write_supervisor_final_schema(
            &mut writer,
            Path::new("schemas/supervisor-final-report.schema.json"),
        )
        .expect("write persistence schema fixture");
        let _field_guide_store = FieldGuideStore::open(&repo, FieldGuideLimits::default())
            .expect("initialize authenticated persistence fixture");
        let mut journal = initialize_orchestration_event_journal(&repo, &run_id);
        assert!(journal.is_some());
        let plan = test_plan(Vec::new());
        let report = build_supervisor_final_report(test_report_construction(&plan, run_id.clone()));

        let persisted = persist_supervisor_final_report(report, &mut journal, writer)
            .expect("persist scheduler final report directly");

        assert_eq!(persisted.run_id, run_id);
        let reader = ArtifactRunReader::open(&repo, RunArtifactFamily::Supervise, &run_id)
            .expect("open finalized scheduler artifacts");
        let journal_bytes = reader
            .read(ORCHESTRATION_EVENT_PATH)
            .expect("read scheduler orchestration journal");
        let kinds = journal_bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| {
                serde_json::from_slice::<OrchestrationEvent>(line)
                    .expect("parse scheduler orchestration event")
                    .kind
            })
            .collect::<Vec<_>>();
        assert_eq!(
            kinds,
            vec![OrchestrationEventKind::Gate, OrchestrationEventKind::Status]
        );
    }
}
