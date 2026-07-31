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

pub(super) fn run_supervisor_plan_with_runner_and_creation(
    loaded: LoadedSupervisorPlan,
    options: SupervisorRunOptions,
    max_concurrent_children: usize,
    execution_runtime: SupervisorExecutionRuntime,
    worktree_creation: SupervisorWorktreeCreation<'_>,
    runtime_model_catalog: Result<RuntimeModelCatalog>,
    external_runner: &CancellableExternalRunner<'_>,
) -> Result<SupervisorFinalReport> {
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
    let budget_config = &plan_metadata.run_budget;
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

    let mut artifact_writer = ArtifactRunWriter::reserve(
        &repo,
        RunArtifactFamily::Supervise,
        options.run_id.clone(),
        "maco-supervise",
    )?;
    let run_dir = artifact_writer.run_dir().to_path_buf();
    let dirs = RunDirs::for_writer(&artifact_writer);
    let manager = WorktreeManager::new(&repo);
    let mut sync_store_slot = None;
    let mut semantic_store_slot = None;
    let mut field_guide_store_slot = None;
    let mut field_guide_prompt_slot = None;
    let mut orchestration_journal = None;
    let mut acquired_claim_tokens = Vec::new();
    let mut acquired_semantic_tokens = Vec::new();
    let mut concurrently_released_claims = Vec::new();
    let mut concurrent_release_errors = Vec::new();
    let mut concurrently_released_semantic_intents = Vec::new();
    let mut concurrent_semantic_release_errors = Vec::new();
    let mut command_records = Vec::new();
    let mut usage_samples = Vec::new();
    let mut usage_incomplete = false;
    let mut orchestrator_reports = Vec::new();
    let mut gate_denials = Vec::new();
    let mut pre_action_review_metrics = Vec::new();
    let mut gate_correction_outcomes = Vec::new();
    let mut candidate_inspections = BTreeMap::new();
    let mut findings = Vec::new();
    if runtime == SupervisorRuntime::Fake {
        findings.push(Finding {
            severity: FindingSeverity::Warning,
            message:
                "explicit fake supervisor runtime is simulation-only and cannot publish acceptance"
                    .to_string(),
            paths: Vec::new(),
        });
    }
    let mut primary_run_baseline = None;
    let mut assignment_execution_failed = false;
    let mut budget_prevented_dispatch = false;
    let mut budget_denied_assignment_indices = BTreeSet::new();
    let mut external_containment_failed = false;
    let mut circuit_breaker_trip = None;

    let run_result = (|| -> Result<()> {
        if !options.allow_dirty_primary {
            ensure_clean_primary(&repo, execution_runtime)?;
        }
        write_plan_snapshot(
            &mut artifact_writer,
            Path::new("assignments/supervisor-plan.json"),
            &plan,
            &consultant,
            &assignment_metadata,
            &plan_metadata,
        )?;
        write_orchestrator_schema(
            &mut artifact_writer,
            Path::new("schemas/orchestrator-review-report.schema.json"),
        )?;
        write_worker_schema(
            &mut artifact_writer,
            Path::new("schemas/worker-report.schema.json"),
        )?;
        write_auditor_schema(
            &mut artifact_writer,
            Path::new("schemas/auditor-report.schema.json"),
        )?;
        write_supervisor_final_schema(
            &mut artifact_writer,
            Path::new("schemas/supervisor-final-report.schema.json"),
        )?;
        let field_guide_store = FieldGuideStore::open(&repo, FieldGuideLimits::default())
            .context("failed to open authenticated field guide for supervise run")?;
        let field_guide_prompt = SupervisorFieldGuidePrompt::from_store(&field_guide_store)?;
        field_guide_store_slot = Some(field_guide_store);
        field_guide_prompt_slot = Some(field_guide_prompt);
        sync_store_slot = Some(SyncStore::open(&repo)?);
        semantic_store_slot = Some(SemanticIntentStore::open(&repo)?);
        orchestration_journal = initialize_orchestration_event_journal(&repo, &options.run_id);
        record_orchestration_event(
            &mut orchestration_journal,
            &mut artifact_writer,
            options.run_id.as_str(),
            None,
            OrchestrationRole::Supervisor,
            OrchestrationEventKind::Status,
            lifecycle_event_payload("running", None, None),
        );
        let sync_store = sync_store_slot
            .as_ref()
            .context("supervisor sync store was not initialized")?;
        let semantic_store = semantic_store_slot
            .as_ref()
            .context("supervisor semantic store was not initialized")?;
        let field_guide = field_guide_prompt_slot
            .as_ref()
            .context("supervisor field-guide prompt was not initialized")?;

        let baseline = primary_worktree_snapshot(&repo, execution_runtime)?;
        if let Some(error) = baseline.inspection_problem() {
            bail!(
                "refusing to launch supervised work without a complete primary integrity snapshot: {error}"
            );
        }
        primary_run_baseline = Some(baseline);

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
        let (scheduler_result, indexed_outcomes) = {
            let cancellation = ProcessCancellation::new();
            let shared_artifacts = Mutex::new(SharedSupervisorArtifacts {
                writer: &mut artifact_writer,
                journal: &mut orchestration_journal,
            });
            let mut indexed_outcomes = (0..plan.assignments.len())
                .map(|_| None)
                .collect::<Vec<Option<AssignmentExecutionOutcome>>>();
            let semantic_block_gate = SemanticBlockGate::default();
            let serial_semantic_warn_intents = Mutex::new(Vec::<(usize, SemanticIntent)>::new());
            let mut health_breaker = SwarmHealthCircuitBreaker::default();

            let scheduler_result = if max_concurrent_children == 1 {
                let mut pending = (0..plan.assignments.len()).collect::<BTreeSet<_>>();
                while !pending.is_empty() {
                    suppress_failed_descendants(
                        &mut pending,
                        &mut indexed_outcomes,
                        &plan,
                        &assignment_schedule,
                        &shared_artifacts,
                    )?;
                    if pending.is_empty() {
                        break;
                    }
                    if !health_breaker.permits_admission() {
                        break;
                    }
                    if !budget_ledger
                        .report()
                        .context("failed to inspect run budget before serial admission")?
                        .new_dispatch_allowed
                    {
                        budget_prevented_dispatch = true;
                        budget_denied_assignment_indices.extend(pending.iter().copied());
                        break;
                    }
                    let mut next = None;
                    for candidate in pending.iter().copied() {
                        if assignment_admission_state(
                            candidate,
                            &assignment_schedule,
                            &indexed_outcomes,
                        )? == AssignmentAdmissionState::Ready
                        {
                            next = Some(candidate);
                            break;
                        }
                    }
                    let Some(index) = next else {
                        bail!(
                            "supervisor scheduler could not select a hierarchy-ready pending assignment"
                        );
                    };
                    pending.remove(&index);
                    let assignment = &plan.assignments[index];
                    let outcome = execute_supervisor_assignment(AssignmentExecutionContext {
                        index,
                        concurrent_mode: false,
                        plan: &plan,
                        budget_config,
                        consultant: &consultant,
                        assignment_metadata: &assignment_metadata,
                        assignment,
                        options: &options,
                        repo: &repo,
                        run_dir: &run_dir,
                        dirs: &dirs,
                        execution_runtime,
                        worktree_creation,
                        manager: &manager,
                        reused: existing_ids.contains(&assignment.id),
                        sync_store,
                        semantic_store,
                        prepared_semantic_token: prepared_semantic_assignments[index].token,
                        prepared_semantic_findings: &prepared_semantic_assignments[index].findings,
                        prepared_semantic_signals: &prepared_semantic_assignments[index]
                            .health_signals,
                        prepared_semantic_failed: prepared_semantic_assignments[index]
                            .assignment_failed,
                        assignment_schedule: &assignment_schedule,
                        field_guide,
                        serial_semantic_warn_intents: Some(&serial_semantic_warn_intents),
                        semantic_block_order: None,
                        semantic_block_gate: None,
                        artifacts: &shared_artifacts,
                        budget_ledger: &budget_ledger,
                        runtime_model_catalog: &runtime_model_catalog,
                        cancellation: cancellation.clone(),
                        external_runner,
                    });
                    let mut outcome = outcome;
                    if release_per_assignment {
                        release_concurrent_assignment(&mut outcome, sync_store, semantic_store);
                    }
                    if circuit_breaker_trip.is_none() {
                        if let Some(trip) = observe_assignment_health(&mut health_breaker, &outcome)
                        {
                            record_breaker_trip(&shared_artifacts, &options.run_id, &trip)?;
                            circuit_breaker_trip = Some(trip);
                        }
                    }
                    let abort = outcome.requires_scheduler_abort();
                    let budget_stopped = outcome.budget_dispatch_stopped;
                    indexed_outcomes[index] = Some(outcome);
                    if abort || budget_stopped {
                        budget_prevented_dispatch |= budget_stopped;
                        if !pending.is_empty()
                            && !budget_ledger
                                .report()
                                .context(
                                    "failed to inspect run budget after aborted serial dispatch",
                                )?
                                .new_dispatch_allowed
                        {
                            budget_prevented_dispatch = true;
                            budget_denied_assignment_indices.extend(pending.iter().copied());
                        }
                        if budget_stopped {
                            budget_denied_assignment_indices.extend(pending.iter().copied());
                        }
                        break;
                    }
                    if !pending.is_empty()
                        && !budget_ledger
                            .report()
                            .context("failed to inspect run budget after serial dispatch")?
                            .new_dispatch_allowed
                    {
                        budget_prevented_dispatch = true;
                        budget_denied_assignment_indices.extend(pending.iter().copied());
                        break;
                    }
                }
                Ok(())
            } else {
                thread::scope(|scope| -> Result<()> {
                    let plan_ref = &plan;
                    let consultant_ref = &consultant;
                    let assignment_metadata_ref = &assignment_metadata;
                    let options_ref = &options;
                    let repo_ref = repo.as_path();
                    let run_dir_ref = run_dir.as_path();
                    let dirs_ref = &dirs;
                    let manager_ref = &manager;
                    let existing_ids_ref = &existing_ids;
                    let prepared_semantic_assignments_ref = &prepared_semantic_assignments;
                    let assignment_schedule_ref = &assignment_schedule;
                    let semantic_block_gate_ref = &semantic_block_gate;
                    let artifacts_ref = &shared_artifacts;
                    let budget_ledger_ref = &budget_ledger;
                    let runtime_model_catalog_ref = &runtime_model_catalog;
                    let (completion_sender, completion_receiver) = mpsc::channel::<usize>();
                    let mut pending = (0..plan.assignments.len()).collect::<BTreeSet<_>>();
                    let mut active = BTreeMap::new();
                    let mut stop_scheduling = false;
                    let mut next_semantic_block_order = 0usize;

                    while !pending.is_empty() || !active.is_empty() {
                        if !stop_scheduling {
                            suppress_failed_descendants(
                                &mut pending,
                                &mut indexed_outcomes,
                                plan_ref,
                                assignment_schedule_ref,
                                artifacts_ref,
                            )?;
                            while active.len() < max_concurrent_children {
                                if !health_breaker.permits_admission() {
                                    stop_scheduling = true;
                                    break;
                                }
                                if !budget_ledger_ref
                                    .report()
                                    .context(
                                        "failed to inspect run budget before concurrent admission",
                                    )?
                                    .new_dispatch_allowed
                                {
                                    budget_prevented_dispatch |= !pending.is_empty();
                                    budget_denied_assignment_indices
                                        .extend(pending.iter().copied());
                                    stop_scheduling = true;
                                    break;
                                }
                                let mut next = None;
                                for candidate in pending.iter().copied() {
                                    if assignment_admission_state(
                                        candidate,
                                        assignment_schedule_ref,
                                        &indexed_outcomes,
                                    )? != AssignmentAdmissionState::Ready
                                    {
                                        continue;
                                    }
                                    if active.keys().all(|active_index| {
                                        !assignments_overlap(
                                            &plan.assignments[candidate],
                                            &plan.assignments[*active_index],
                                        )
                                    }) {
                                        next = Some(candidate);
                                        break;
                                    }
                                }
                                let Some(index) = next else {
                                    break;
                                };
                                pending.remove(&index);
                                let assignment = &plan_ref.assignments[index];
                                let semantic_block_order = (plan_ref.semantic_coordination
                                    == SemanticCoordinationMode::Block)
                                    .then(|| {
                                        let order = next_semantic_block_order;
                                        next_semantic_block_order =
                                            next_semantic_block_order.saturating_add(1);
                                        order
                                    });
                                let completion_sender = completion_sender.clone();
                                let assignment_cancellation = cancellation.clone();
                                let spawn_result =
                                    thread::Builder::new().spawn_scoped(scope, move || {
                                        let _completion = CompletionSignal {
                                            index,
                                            sender: completion_sender,
                                        };
                                        execute_supervisor_assignment(AssignmentExecutionContext {
                                            index,
                                            concurrent_mode: true,
                                            plan: plan_ref,
                                            budget_config,
                                            consultant: consultant_ref,
                                            assignment_metadata: assignment_metadata_ref,
                                            assignment,
                                            options: options_ref,
                                            repo: repo_ref,
                                            run_dir: run_dir_ref,
                                            dirs: dirs_ref,
                                            execution_runtime,
                                            worktree_creation,
                                            manager: manager_ref,
                                            reused: existing_ids_ref.contains(&assignment.id),
                                            sync_store,
                                            semantic_store,
                                            prepared_semantic_token:
                                                prepared_semantic_assignments_ref[index].token,
                                            prepared_semantic_findings:
                                                &prepared_semantic_assignments_ref[index].findings,
                                            prepared_semantic_signals:
                                                &prepared_semantic_assignments_ref[index]
                                                    .health_signals,
                                            prepared_semantic_failed:
                                                prepared_semantic_assignments_ref[index]
                                                    .assignment_failed,
                                            assignment_schedule: assignment_schedule_ref,
                                            field_guide,
                                            serial_semantic_warn_intents: None,
                                            semantic_block_order,
                                            semantic_block_gate: semantic_block_order
                                                .map(|_| semantic_block_gate_ref),
                                            artifacts: artifacts_ref,
                                            budget_ledger: budget_ledger_ref,
                                            runtime_model_catalog: runtime_model_catalog_ref,
                                            cancellation: assignment_cancellation,
                                            external_runner,
                                        })
                                    });
                                match spawn_result {
                                    Ok(handle) => {
                                        active.insert(index, handle);
                                    }
                                    Err(error) => {
                                        cancellation.cancel();
                                        record_assignment_spawn_failure(
                                            &mut indexed_outcomes,
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
                            bail!(
                                "supervisor scheduler could not select a hierarchy-ready pending assignment"
                            );
                        }

                        let completed_index = match completion_receiver.recv() {
                            Ok(index) => index,
                            Err(error) => {
                                cancellation.cancel();
                                return Err(error)
                                    .context("supervisor assignment completion channel closed");
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
                                plan.assignments[completed_index].id
                            )),
                        };
                        release_concurrent_assignment(&mut outcome, sync_store, semantic_store);
                        if outcome.requires_scheduler_abort() {
                            cancellation.cancel();
                            stop_scheduling = true;
                        } else {
                            if circuit_breaker_trip.is_none() {
                                if let Some(trip) =
                                    observe_assignment_health(&mut health_breaker, &outcome)
                                {
                                    record_breaker_trip(&shared_artifacts, &options.run_id, &trip)?;
                                    circuit_breaker_trip = Some(trip);
                                    // A breaker trip is a graceful scheduler stop: pending
                                    // assignments are not admitted, while already-active children
                                    // retain their cancellation tokens and are drained.
                                    stop_scheduling = true;
                                }
                            }
                            if outcome.budget_dispatch_stopped
                                || (!pending.is_empty()
                                    && !budget_ledger_ref
                                        .report()
                                        .context(
                                            "failed to inspect run budget after concurrent dispatch",
                                        )?
                                        .new_dispatch_allowed)
                            {
                                budget_prevented_dispatch = true;
                                budget_denied_assignment_indices.extend(pending.iter().copied());
                                stop_scheduling = true;
                            }
                        }
                        indexed_outcomes[completed_index] = Some(outcome);
                    }

                    for (index, handle) in active {
                        let mut outcome = match handle.join() {
                            Ok(outcome) => outcome,
                            Err(_) => AssignmentExecutionOutcome::fatal(format!(
                                "supervisor assignment '{}' thread panicked",
                                plan.assignments[index].id
                            )),
                        };
                        release_concurrent_assignment(&mut outcome, sync_store, semantic_store);
                        indexed_outcomes[index] = Some(outcome);
                    }
                    Ok(())
                })
            };
            (scheduler_result, indexed_outcomes)
        };

        let mut fatal_errors = Vec::new();
        for outcome in indexed_outcomes.into_iter().flatten() {
            command_records.extend(outcome.command_records);
            usage_samples.extend(outcome.usage_samples);
            usage_incomplete |= outcome.usage_incomplete;
            findings.extend(outcome.findings);
            gate_denials.extend(outcome.gate_denials);
            pre_action_review_metrics.extend(outcome.pre_action_review_metrics);
            gate_correction_outcomes.extend(outcome.gate_correction_outcomes);
            assignment_execution_failed |= outcome.assignment_failed;
            external_containment_failed |= outcome.external_containment_failed;
            if !release_per_assignment {
                acquired_claim_tokens.extend(outcome.claim_tokens);
                acquired_semantic_tokens.extend(outcome.semantic_tokens);
            } else {
                concurrently_released_claims.extend(outcome.released_claims);
                concurrent_release_errors.extend(outcome.release_errors);
                concurrently_released_semantic_intents.extend(outcome.released_semantic_intents);
                concurrent_semantic_release_errors.extend(outcome.semantic_release_errors);
            }
            if let (Some(report), Some(inspection)) =
                (outcome.report.as_ref(), outcome.candidate_inspection)
            {
                candidate_inspections.insert(report.id.clone(), inspection);
            }
            if let Some(report) = outcome.report {
                orchestrator_reports.push(report);
            }
            if let Some(error) = outcome.fatal_error {
                fatal_errors.push(error);
            }
        }
        scheduler_result?;
        if let Some(error) = fatal_errors.into_iter().next() {
            bail!("{error}");
        }
        Ok(())
    })();

    if let Err(error) = &run_result {
        findings.push(Finding {
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
        findings.push(Finding {
            severity: FindingSeverity::Error,
            message: format!(
                "swarm-health circuit breaker opened and drained active assignments: {:?}",
                trip.reason
            ),
            paths: Vec::new(),
        });
    }

    let (mut released_claims, mut release_errors) = match sync_store_slot.as_ref() {
        Some(store) => release_claims(store, acquired_claim_tokens),
        None => (Vec::new(), Vec::new()),
    };
    released_claims.extend(concurrently_released_claims);
    release_errors.extend(concurrent_release_errors);
    let (mut released_semantic_intents, mut semantic_release_errors) =
        match semantic_store_slot.as_ref() {
            Some(store) => release_semantic_intents(store, acquired_semantic_tokens),
            None => (Vec::new(), Vec::new()),
        };
    released_semantic_intents.extend(concurrently_released_semantic_intents);
    semantic_release_errors.extend(concurrent_semantic_release_errors);
    let final_primary_integrity_failed = match primary_run_baseline.as_ref() {
        Some(baseline) => match primary_worktree_snapshot(&repo, execution_runtime) {
            Ok(final_snapshot) => {
                if let Some(error) = final_snapshot.inspection_problem() {
                    findings.push(Finding {
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
                        findings.push(Finding {
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
                findings.push(Finding {
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
        findings.push(Finding {
            severity: FindingSeverity::Warning,
            message: "worker usage is not process-observable because nested workers execute inside child Codex sessions; child-orchestrator and auditor process usage remains reportable, while runtime-side role-tagged usage reporting is required before worker usage or cost can be reported"
                .to_string(),
            paths: Vec::new(),
        });
    }
    let (run_budget_report, budget_accounting_failed) = match budget_ledger.report() {
        Ok(report) => (Some(report), false),
        Err(error) => {
            findings.push(Finding {
                severity: FindingSeverity::Error,
                message: format!("run budget accounting could not be finalized: {error}"),
                paths: Vec::new(),
            });
            (None, true)
        }
    };
    usage_incomplete |= budget_accounting_failed
        || run_budget_report
            .as_ref()
            .is_some_and(|report| !report.usage_complete);
    if usage_incomplete {
        findings.push(Finding {
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
            gate_denials.push(
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
        findings.push(Finding {
            severity: FindingSeverity::Error,
            message: "run budget stopped one or more new dispatches and drained already-started work; inspect typed gate_denials and the structured run_budget report"
                .to_string(),
            paths: Vec::new(),
        });
    }
    let field_guide_mutation_failed = match append_accepted_field_guide_drafts(
        &plan,
        &orchestrator_reports,
        &options.run_id,
        field_guide_store_slot.as_ref(),
        &mut orchestration_journal,
        &mut artifact_writer,
    ) {
        Ok(_) => false,
        Err(error) => {
            findings.push(Finding {
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
        aggregate_environment_failures(&command_records, &orchestrator_reports);
    let failed = run_result.is_err()
        || !release_errors.is_empty()
        || !semantic_release_errors.is_empty()
        || assignment_execution_failed
        || budget_prevented_dispatch
        || budget_accounting_failed
        || external_containment_failed
        || final_primary_integrity_failed
        || breaker_tripped
        || field_guide_mutation_failed
        || !environment_failures.is_empty()
        || orchestrator_reports.iter().any(report_failed);
    let success = !failed;
    let publishable = success && runtime == SupervisorRuntime::Codex;
    let report_plan_file = options
        .plan_file
        .strip_prefix(&repo)
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| PathBuf::from("<external-plan>"));
    let report_run_dir = run_dir
        .strip_prefix(&repo)
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| {
            RunArtifactFamily::Supervise
                .run_root()
                .join(options.run_id.as_str())
        });
    let usage_complete = !usage_incomplete;
    let RoleUsageAggregation {
        reports: mut role_usage,
        total_usage,
        total_cost_usd: observed_total_cost_usd,
    } = role_usage_report(&plan, usage_samples)?;
    let total_cost_usd =
        finalize_supervisor_cost(usage_complete, &mut role_usage, observed_total_cost_usd);
    let bloated_file_flags = accepted_bloated_file_flags(&orchestrator_reports);
    let decomposition_candidates = accepted_decomposition_candidates(&orchestrator_reports);
    let (assignment_traceability, runtime_coverage_gaps) = supervisor_assignment_traceability(
        &plan,
        &plan_metadata,
        &orchestrator_reports,
        &candidate_inspections,
    );
    let mut coverage_gaps = plan_metadata.coverage_gaps.clone();
    coverage_gaps.extend(runtime_coverage_gaps);
    let sandbox_denials = aggregate_sandbox_denials(&command_records);
    let mut final_report = SupervisorFinalReport {
        version: SUPERVISOR_SCHEMA_VERSION,
        run_id: options.run_id,
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
            plan.effective_role_economics_profile_for_runtime(&runtime_model_catalog),
        ),
        run_budget: run_budget_report,
        role_usage,
        total_usage,
        total_cost_usd,
        usage_complete,
        commands_run: command_records,
        environment_failures: environment_failures.clone(),
        sandbox_denials,
        gate_denials,
        pre_action_review_metrics,
        gate_correction_outcomes,
        files_changed: orchestrator_reports
            .iter()
            .flat_map(|report| report.files_changed.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        validation_results: orchestrator_reports
            .iter()
            .flat_map(|report| report.validation_results.iter().cloned())
            .collect(),
        findings,
        bloated_file_flags,
        decomposition_candidates,
        assignment_traceability,
        coverage_gaps: coverage_gaps.clone(),
        breaker_trip: supervisor_breaker_trip,
        orchestrator_reports,
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
    };
    enforce_supervisor_final_environment_failure_outcome(&mut final_report);
    record_orchestration_event(
        &mut orchestration_journal,
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
        &mut orchestration_journal,
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
