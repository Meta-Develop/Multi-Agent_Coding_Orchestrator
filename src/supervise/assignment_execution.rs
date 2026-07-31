use super::*;

pub(super) fn execute_supervisor_assignment(
    context: AssignmentExecutionContext<'_, '_>,
) -> AssignmentExecutionOutcome {
    let mut outcome = AssignmentExecutionOutcome {
        gate_tracker: Some(GateCorrectionTracker::new(
            context.plan.max_gate_corrections,
        )),
        ..AssignmentExecutionOutcome::default()
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        execute_supervisor_assignment_inner(&context, &mut outcome)
    }));
    match result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            outcome.fatal_error = Some(format!(
                "supervisor assignment '{}' aborted: {error:#}",
                context.assignment.id
            ));
        }
        Err(_) => {
            outcome.fatal_error = Some(format!(
                "supervisor assignment '{}' panicked",
                context.assignment.id
            ));
        }
    }
    let journal_parent_id = context
        .assignment_schedule
        .get(context.index)
        .and_then(|entry| entry.parent_assignment_id.as_deref())
        .unwrap_or_else(|| context.options.run_id.as_str());
    if let Some(tracker) = outcome.gate_tracker.as_mut() {
        if let Err(error) =
            tracker.escalate_active(context.artifacts, &context.assignment.id, journal_parent_id)
        {
            let terminalization_error = format!(
                "failed to terminalize gate correction for supervisor assignment '{}': {error:#}",
                context.assignment.id
            );
            outcome.fatal_error = Some(match outcome.fatal_error.take() {
                Some(error) => format!("{error}; {terminalization_error}"),
                None => terminalization_error,
            });
        }
    }
    if let Some(tracker) = outcome.gate_tracker.take() {
        tracker.move_into_outcome(&mut outcome);
    }
    outcome
}

fn execute_supervisor_assignment_inner(
    context: &AssignmentExecutionContext<'_, '_>,
    outcome: &mut AssignmentExecutionOutcome,
) -> Result<()> {
    let AssignmentExecutionContext {
        index,
        concurrent_mode,
        plan,
        budget_config,
        consultant,
        assignment_metadata,
        assignment,
        options,
        repo,
        run_dir,
        dirs,
        execution_runtime,
        worktree_creation,
        manager,
        reused,
        sync_store,
        semantic_store,
        prepared_semantic_token,
        prepared_semantic_findings,
        prepared_semantic_signals,
        prepared_semantic_failed,
        assignment_schedule,
        field_guide,
        serial_semantic_warn_intents,
        semantic_block_order,
        semantic_block_gate,
        artifacts,
        budget_ledger,
        runtime_model_catalog,
        cancellation,
        external_runner,
    } = context;
    outcome
        .findings
        .extend(prepared_semantic_findings.iter().cloned());
    outcome
        .health_signals
        .extend(prepared_semantic_signals.iter().copied());
    if *prepared_semantic_failed {
        outcome.assignment_failed = true;
        return Ok(());
    }
    let journal_parent_id = assignment_schedule
        .get(*index)
        .context("assignment execution index is outside the validated schedule")?
        .parent_assignment_id
        .as_deref()
        .unwrap_or_else(|| options.run_id.as_str());
    let semantic_block_turn = match (semantic_block_gate, semantic_block_order) {
        (Some(gate), Some(order)) => Some(gate.wait_for_turn(*order)?),
        _ => None,
    };
    let mut effective_assignment = (*assignment).clone();
    let claim = loop {
        match sync_store.claim_paths(
            &effective_assignment.id,
            effective_assignment.assigned_paths.iter(),
        ) {
            Ok(claim) => {
                if matches!(
                    outcome
                        .gate_tracker
                        .as_ref()
                        .and_then(GateCorrectionTracker::active_reason),
                    Some(GateDenialReason::ClaimConflict)
                ) {
                    outcome
                        .gate_tracker
                        .as_mut()
                        .context("gate correction tracker was not initialized")?
                        .self_corrected(artifacts, &effective_assignment.id, journal_parent_id)?;
                }
                break claim;
            }
            Err(error) => {
                let conflicts =
                    claim_conflict_details(sync_store, &effective_assignment.assigned_paths);
                if conflicts.is_empty() {
                    outcome
                        .health_signals
                        .push(SwarmHealthSignal::ClaimAcquisitionFailed);
                    outcome.findings.push(claim_failure_finding(
                        sync_store,
                        &effective_assignment,
                        &error,
                    ));
                    outcome.assignment_failed = true;
                    return Ok(());
                }
                outcome
                    .health_signals
                    .push(SwarmHealthSignal::ClaimAcquisitionDenied);
                let conflicted_paths = conflicts
                    .iter()
                    .map(|conflict| conflict.path.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                let correction_correlation_id = outcome
                    .gate_tracker
                    .as_ref()
                    .context("gate correction tracker was not initialized")?
                    .correlation_id_for_observation(&effective_assignment.id);
                let denial = GateDenial::from_claim_conflict(
                    correction_correlation_id,
                    &effective_assignment.id,
                    &conflicted_paths,
                )
                .context("failed to construct pre-launch claim-conflict denial")?;
                let Some(narrowed) =
                    safely_narrow_claim_scope(&effective_assignment, &conflicted_paths)
                else {
                    outcome
                        .gate_tracker
                        .as_mut()
                        .context("gate correction tracker was not initialized")?
                        .escalate(
                            denial,
                            artifacts,
                            &effective_assignment.id,
                            journal_parent_id,
                        )?;
                    outcome.findings.push(claim_failure_finding(
                        sync_store,
                        &effective_assignment,
                        &error,
                    ));
                    outcome.assignment_failed = true;
                    return Ok(());
                };
                let authorized_denial = outcome
                    .gate_tracker
                    .as_mut()
                    .context("gate correction tracker was not initialized")?
                    .authorize(
                        denial,
                        artifacts,
                        &effective_assignment.id,
                        journal_parent_id,
                        &mut outcome.health_signals,
                    )?;
                if authorized_denial.is_none() {
                    outcome.findings.push(claim_failure_finding(
                        sync_store,
                        &effective_assignment,
                        &error,
                    ));
                    outcome.assignment_failed = true;
                    return Ok(());
                }
                effective_assignment = narrowed;
            }
        }
    };
    outcome.claim_tokens.push(claim.token);
    let assignment = &effective_assignment;
    let current_primary_head = current_head_oid(repo)?;
    if !reused {
        let create_options = WorktreeCreateOptions {
            agent_id: assignment.id.clone(),
            branch: None,
            base: None,
            worktree_root: None,
        };
        let create_result = match worktree_creation {
            SupervisorWorktreeCreation::Bound(cleanliness) => manager
                .create_with_repository_cleanliness(create_options, cleanliness)
                .with_context(|| {
                    format!(
                        "failed to create capability-bound child worktree '{}'",
                        assignment.id
                    )
                }),
            #[cfg(test)]
            SupervisorWorktreeCreation::TestOnly => manager.create_for_test(create_options),
        };
        if let Err(error) = create_result {
            record_isolated_assignment_failure(outcome, assignment, "worktree creation", &error);
            return Ok(());
        }
    }
    let worktree_write_lease = match manager
        .acquire_write_execution_lease(&assignment.id)
        .with_context(|| {
            format!(
                "failed to acquire exclusive execution lease for child worktree '{}'",
                assignment.id
            )
        }) {
        Ok(lease) => lease,
        Err(error) => {
            record_isolated_assignment_failure(
                outcome,
                assignment,
                "worktree execution lease acquisition",
                &error,
            );
            return Ok(());
        }
    };
    let worktree = worktree_write_lease.record().clone();
    if *reused {
        if let Err(error) = ensure_reusable_child_worktree(&worktree, &current_primary_head) {
            record_isolated_assignment_failure(
                outcome,
                assignment,
                "reusable worktree validation",
                &error,
            );
            return Ok(());
        }
    }
    let mandatory_worktree_controls = match provision_mandatory_worktree_controls(&worktree.path) {
        Ok(controls) => controls,
        Err(error) => {
            record_isolated_assignment_failure(
                outcome,
                assignment,
                "mandatory worktree control bootstrap",
                &error,
            );
            return Ok(());
        }
    };
    if let Err(error) = assignment_worktree_control_exceptions(&assignment.assigned_paths) {
        record_isolated_assignment_failure(
            outcome,
            assignment,
            "worktree control exception derivation",
            &error,
        );
        return Ok(());
    }
    let child_base_head = match current_head_oid(&worktree.path).with_context(|| {
        format!(
            "failed to capture base HEAD for child worktree '{}' at {}",
            assignment.id,
            worktree.path.display()
        )
    }) {
        Ok(head) => head,
        Err(error) => {
            record_isolated_assignment_failure(
                outcome,
                assignment,
                "worktree HEAD capture",
                &error,
            );
            return Ok(());
        }
    };
    let semantic_token = if plan.semantic_coordination == SemanticCoordinationMode::Warn {
        if let Some(planned_intents) = serial_semantic_warn_intents {
            let coordination_result = {
                let mut planned_intents = match planned_intents.lock() {
                    Ok(planned_intents) => planned_intents,
                    Err(poisoned) => poisoned.into_inner(),
                };
                let mut relevant_intents = semantic_preview_intents_for_assignment(
                    *index,
                    assignment_schedule,
                    &planned_intents,
                );
                let prior_relevant_count = relevant_intents.len();
                let result = coordinate_semantic_assignment(
                    semantic_store,
                    assignment,
                    plan.semantic_coordination,
                    &mut outcome.semantic_tokens,
                    &mut relevant_intents,
                    &mut outcome.findings,
                    &mut outcome.health_signals,
                );
                if result.is_ok() && relevant_intents.len() > prior_relevant_count {
                    if let Some(intent) = relevant_intents.pop() {
                        planned_intents.push((*index, intent));
                    }
                }
                result
            };
            let coordination = match coordination_result {
                Ok(coordination) => coordination,
                Err(error) if semantic_resolution_error(&error) => {
                    outcome.assignment_failed = true;
                    outcome
                        .findings
                        .push(semantic_resolution_finding(assignment, &error));
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            match coordination {
                SemanticAssignmentCoordination::Ready(token) => token,
                SemanticAssignmentCoordination::Blocked(_) => {
                    bail!("warn-mode semantic preview unexpectedly blocked an assignment")
                }
            }
        } else {
            *prepared_semantic_token
        }
    } else {
        let mut planned_semantic_intents = Vec::new();
        let coordination_result = coordinate_semantic_assignment(
            semantic_store,
            assignment,
            plan.semantic_coordination,
            &mut outcome.semantic_tokens,
            &mut planned_semantic_intents,
            &mut outcome.findings,
            &mut outcome.health_signals,
        );
        drop(semantic_block_turn);
        let coordination = match coordination_result {
            Ok(coordination) => coordination,
            Err(error) if semantic_resolution_error(&error) => {
                outcome.assignment_failed = true;
                outcome
                    .findings
                    .push(semantic_resolution_finding(assignment, &error));
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        match coordination {
            SemanticAssignmentCoordination::Ready(token) => token,
            SemanticAssignmentCoordination::Blocked(conflict_count) => {
                outcome.assignment_failed = true;
                outcome.findings.push(Finding {
                    severity: FindingSeverity::Error,
                    message: format!(
                        "semantic coordination blocked assignment '{}' with {conflict_count} blocking conflict(s)",
                        assignment.id
                    ),
                    paths: assignment.assigned_paths.clone(),
                });
                return Ok(());
            }
        }
    };

    let environment_requirements = canonical_environment_requirements(assignment)?;
    let final_report_name = format!("{}.json", assignment.id);
    let final_report_relative = PathBuf::from("reports").join(&final_report_name);
    let final_report_path = dirs.reports.join(&final_report_name);
    let schema_path = dirs.schemas.join("orchestrator-review-report.schema.json");
    let worker_schema_path = dirs.schemas.join("worker-report.schema.json");
    let auditor_schema_path = dirs.schemas.join("auditor-report.schema.json");

    let mut retry_feedback: Option<ChildAttemptCorrection> = None;
    let mut attempt_history = Vec::new();
    let mut structural_attempt = 1usize;
    let max_attempts = usize::from(plan.max_child_retries)
        .saturating_add(usize::from(plan.max_gate_corrections))
        .saturating_add(1);
    let mut next_attempt = 1usize;
    let mut auditor_attempt = 0usize;
    let (child_report, completed_candidate_inspection, completed_assignment_containment) = 'gate_controller: loop {
        let mut child_report = None;
        let mut child_containment_verified = false;
        let mut child_gate_terminal = false;
        let first_attempt = next_attempt;
        for attempt in first_attempt..=max_attempts {
            next_attempt = attempt.saturating_add(1);
            if let Err(error) = mandatory_worktree_controls.revalidate() {
                record_isolated_assignment_failure(
                    outcome,
                    assignment,
                    "mandatory worktree control revalidation",
                    &error,
                );
                return Ok(());
            }
            let (incoming_name, capture_name) =
                invocation_scratch_names(*index, attempt, false, *concurrent_mode);
            let incoming_path = run_dir.join(&incoming_name);
            let capture_path = run_dir.join(&capture_name);
            let attempt_artifacts = child_attempt_artifacts(
                dirs,
                &incoming_path,
                &capture_path,
                &assignment.id,
                attempt,
                max_attempts > 1,
            );
            let corrective_retry_used = retry_feedback.is_some();
            let prompt = child_orchestrator_prompt_with_incoming_root_and_field_guide(
                ChildOrchestratorPromptContext {
                    plan,
                    assignment,
                    run_dir,
                    worktree: &worktree,
                    report_path: &attempt_artifacts.report_path,
                    schema_path: &schema_path,
                    worker_schema_path: &worker_schema_path,
                    auditor_schema_path: &auditor_schema_path,
                    consultant,
                    claim_context: ChildPromptClaimContext {
                        claim: &claim,
                        semantic_intent_token: semantic_token,
                    },
                },
                &incoming_path,
                assignment_metadata,
                field_guide,
            )?;
            record_field_guide_prompt_injection_strict(
                artifacts,
                &assignment.id,
                Some(journal_parent_id),
                OrchestrationRole::Orchestrator,
                SupervisePromptRole::O1ChildOrchestrator,
                field_guide,
                attempt,
            )?;
            for worker in &assignment.worker_assignments {
                record_field_guide_prompt_injection_strict(
                    artifacts,
                    &worker.id,
                    Some(&assignment.id),
                    OrchestrationRole::Worker,
                    SupervisePromptRole::TerminalWorker,
                    field_guide,
                    attempt,
                )?;
            }
            record_field_guide_prompt_injection_strict(
                artifacts,
                &format!("{}-review-auditor", assignment.id),
                Some(&assignment.id),
                OrchestrationRole::Auditor,
                SupervisePromptRole::ReviewAuditor,
                field_guide,
                attempt,
            )?;
            let attempt_prompt = match &retry_feedback {
                Some(ChildAttemptCorrection::StructuralReport) => {
                    prompt_with_structural_retry(&prompt)
                }
                Some(ChildAttemptCorrection::Gate(denial)) => {
                    prompt_with_gate_correction(&prompt, denial)?
                }
                None => prompt,
            };
            let prompt_relative = dirs.relative(&attempt_artifacts.prompt_path)?;
            with_supervisor_artifacts(artifacts, |writer, _| {
                write_private_prompt(writer, &prompt_relative, &attempt_prompt)
            })
            .with_context(|| {
                format!(
                    "failed to write prompt {}",
                    attempt_artifacts.prompt_path.display()
                )
            })?;

            let mut command = ExternalAgentCommand::codex(
                &options.codex_bin,
                &worktree.path,
                &attempt_artifacts.prompt_path,
                &attempt_artifacts.log_path,
                &attempt_artifacts.report_path,
                Duration::from_secs(plan.child_timeout_seconds),
            );
            command = apply_role_model_selection(
                command,
                plan,
                assignment.role,
                options.runtime,
                runtime_model_catalog,
            )?;
            command.output_schema = Some(schema_path.clone());
            command = command.with_hidden_root(repo).with_agent_lifecycle(
                repo,
                assignment.role.as_str(),
                options.run_id.as_str(),
                &assignment.id,
            );
            command = apply_canonical_environment_requirements(command, &environment_requirements);
            command = configure_writable_child_command(command, &assignment.assigned_paths)?;

            let primary_before = primary_worktree_snapshot(repo, *execution_runtime)?;
            if let Some(error) = primary_before.inspection_problem() {
                bail!(
                "refusing to launch child without a complete primary integrity snapshot: {error}"
            );
            }
            let (incoming_scratch, capture_scratch) =
                with_supervisor_artifacts(artifacts, |writer, _| {
                    create_named_invocation_scratches(writer, &incoming_name, &capture_name)
                })?;
            if incoming_scratch.path() != incoming_path || capture_scratch.path() != capture_path {
                with_supervisor_artifacts(artifacts, |writer, _| {
                    discard_invocation_scratches(writer, &incoming_scratch, &capture_scratch)
                })?;
                bail!("artifact scratch paths changed during child setup");
            }
            let incoming_output_root = match SecureOutputRoot::open_private(incoming_scratch.path())
            {
                Ok(root) => root,
                Err(error) => {
                    with_supervisor_artifacts(artifacts, |writer, _| {
                        discard_invocation_scratches(writer, &incoming_scratch, &capture_scratch)
                    })?;
                    return Err(error).context("failed to bind child incoming scratch root");
                }
            };
            let capture_output_root = match SecureOutputRoot::open_private(capture_scratch.path()) {
                Ok(root) => root,
                Err(error) => {
                    drop(incoming_output_root);
                    with_supervisor_artifacts(artifacts, |writer, _| {
                        discard_invocation_scratches(writer, &incoming_scratch, &capture_scratch)
                    })?;
                    return Err(error).context("failed to bind parent capture scratch root");
                }
            };
            if incoming_output_root.path() != incoming_scratch.path()
                || capture_output_root.path() != capture_scratch.path()
            {
                drop(incoming_output_root);
                drop(capture_output_root);
                with_supervisor_artifacts(artifacts, |writer, _| {
                    discard_invocation_scratches(writer, &incoming_scratch, &capture_scratch)
                })?;
                bail!("descriptor-held invocation scratch roots changed during setup");
            }
            let mut budget_reservation = match reserve_dispatch_budget(
                plan,
                budget_config,
                budget_ledger,
                assignment.role,
                &command,
            )? {
                DispatchBudgetAdmission::Admitted(reservation) => reservation,
                DispatchBudgetAdmission::Refused(refusal) => {
                    drop(incoming_output_root);
                    drop(capture_output_root);
                    with_supervisor_artifacts(artifacts, |writer, _| {
                        discard_invocation_scratches(writer, &incoming_scratch, &capture_scratch)
                    })?;
                    record_budget_dispatch_refusal(
                        outcome,
                        assignment,
                        &assignment.id,
                        assignment.role,
                        &refusal,
                        artifacts,
                        journal_parent_id,
                    )?;
                    return Ok(());
                }
            };

            record_shared_orchestration_event(
                artifacts,
                &assignment.id,
                Some(journal_parent_id),
                OrchestrationRole::Orchestrator,
                OrchestrationEventKind::Spawn,
                json!({
                    "attempt": attempt,
                    "corrective_retry": corrective_retry_used,
                }),
            )?;
            record_shared_orchestration_event(
                artifacts,
                &assignment.id,
                Some(journal_parent_id),
                OrchestrationRole::Orchestrator,
                OrchestrationEventKind::Status,
                lifecycle_event_payload("running", Some(attempt), None),
            )?;

            let external_run_result = match options.runtime {
                SupervisorRuntime::Codex => {
                    let review_context =
                        match pre_action_review_context(options, assignment, &worktree.path) {
                            Ok(review_context) => review_context,
                            Err(error) => {
                                drop(incoming_output_root);
                                drop(capture_output_root);
                                with_supervisor_artifacts(artifacts, |writer, _| {
                                    discard_invocation_scratches(
                                        writer,
                                        &incoming_scratch,
                                        &capture_scratch,
                                    )
                                })?;
                                return Err(error);
                            }
                        };
                    let mut review_journal = SupervisorPreActionJournalSink {
                        artifacts,
                        node: &assignment.id,
                        parent: Some(journal_parent_id),
                    };
                    // All fallible pre-dispatch preparation is complete. Mark
                    // invocation only at the external-runner call boundary.
                    if let Err(error) = budget_reservation.mark_invoked() {
                        drop(incoming_output_root);
                        drop(capture_output_root);
                        with_supervisor_artifacts(artifacts, |writer, _| {
                            discard_invocation_scratches(
                                writer,
                                &incoming_scratch,
                                &capture_scratch,
                            )
                        })?;
                        return Err(error);
                    }
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        external_runner(
                            &command,
                            cancellation,
                            Some(ExternalPreActionReviewRuntime {
                                context: &review_context,
                                journal: &mut review_journal,
                            }),
                        )
                    })) {
                        Ok(run) => Ok(run),
                        Err(payload) => {
                            drop(incoming_output_root);
                            drop(capture_output_root);
                            with_supervisor_artifacts(artifacts, |writer, _| {
                                discard_invocation_scratches(
                                    writer,
                                    &incoming_scratch,
                                    &capture_scratch,
                                )
                            })?;
                            std::panic::resume_unwind(payload);
                        }
                    }
                }
                SupervisorRuntime::Fake => {
                    if let Err(error) = budget_reservation.mark_invoked() {
                        drop(incoming_output_root);
                        drop(capture_output_root);
                        with_supervisor_artifacts(artifacts, |writer, _| {
                            discard_invocation_scratches(
                                writer,
                                &incoming_scratch,
                                &capture_scratch,
                            )
                        })?;
                        return Err(error);
                    }
                    deterministic_fake_child_run(
                        &command,
                        assignment,
                        assignment_metadata,
                        claim.token.get(),
                        semantic_token,
                    )
                }
            };
            let external_run = match external_run_result {
                Ok(run) => run,
                Err(error) => {
                    budget_reservation.settle_not_started()?;
                    drop(incoming_output_root);
                    drop(capture_output_root);
                    with_supervisor_artifacts(artifacts, |writer, _| {
                        discard_invocation_scratches(writer, &incoming_scratch, &capture_scratch)
                    })?;
                    return Err(error).context("failed to produce deterministic child output");
                }
            };
            let environment_blocked = external_run.environment_blocked();
            let usage_settlement =
                budget_reservation.settle(&external_run, options.runtime, &command)?;
            match usage_settlement.reliable_usage() {
                Some(usage) => outcome.usage_samples.push(RoleUsageSample {
                    role: assignment.role,
                    model: command.model.clone(),
                    usage,
                }),
                None if usage_settlement.is_degraded() => outcome.usage_incomplete = true,
                None => {}
            }
            drop(incoming_output_root);
            drop(capture_output_root);
            let child_thread_id = codex_thread_id_from_stdout(external_run.stdout_bytes());
            record_shared_orchestration_event(
                artifacts,
                &assignment.id,
                Some(journal_parent_id),
                OrchestrationRole::Orchestrator,
                OrchestrationEventKind::Status,
                lifecycle_event_payload(
                    if external_process_completed(&external_run) {
                        "completed"
                    } else {
                        "failed"
                    },
                    Some(attempt),
                    child_thread_id.as_deref(),
                ),
            )?;
            let attempt_containment_verified =
                external_containment_verified(&external_run, options.runtime);
            if !attempt_containment_verified {
                outcome.external_containment_failed = true;
                outcome.findings.push(Finding {
                severity: FindingSeverity::Error,
                message: format!(
                    "external child process containment was not verified empty for '{}' attempt {attempt}; evidence: {:?}; report: {}",
                    assignment.id,
                    (external_run.process_tree, external_run.side_effects),
                    attempt_artifacts.raw_report_relative.display()
                ),
                paths: vec![attempt_artifacts.raw_report_relative.clone()],
            });
            }
            outcome
                .command_records
                .push(command_record_from_external(&external_run, &command));
            let raw_report_validated = read_child_report(
                external_run.output_last_message(),
                &attempt_artifacts.raw_report_relative,
            )
            .is_ok();
            let worker_journal_evidence =
                with_supervisor_artifacts(artifacts, |writer, journal| {
                    let evidence =
                        import_worker_execution_journals(writer, assignment, &incoming_scratch)?;
                    record_worker_journal_events(journal, writer, assignment, &evidence);
                    Ok(evidence)
                })?;
            with_supervisor_artifacts(artifacts, |writer, _| {
                import_external_attempt_evidence(
                    writer,
                    ExternalAttemptEvidenceContext {
                        incoming_scratch: &incoming_scratch,
                        capture_scratch: &capture_scratch,
                        artifacts: &attempt_artifacts,
                        external_run: &external_run,
                        external_command: &command,
                        raw_report_validated,
                        runtime: options.runtime,
                    },
                )
            })?;
            let primary_after = primary_worktree_snapshot(repo, *execution_runtime)?;
            let primary_changes = primary_integrity_changes(&primary_before, &primary_after);
            let sandbox_denials = external_run.sandbox_denials().to_vec();
            outcome
                .gate_denials
                .extend(external_run.gate_denials().iter().cloned());
            if let Some(metrics) = external_run.pre_action_review_metrics() {
                outcome.pre_action_review_metrics.push(metrics.clone());
            }
            let external_side_effect_state = external_run.external_side_effect_state();
            let (mut attempt_report, report_shape_problems) =
                collect_child_report(ChildReportCollectionContext {
                    assignment,
                    assignment_metadata,
                    report_path: &attempt_artifacts.raw_report_relative,
                    external_run: &external_run,
                    external_command: &command,
                    worktree_path: &worktree.path,
                    child_base_head: &child_base_head,
                    worker_journals: &worker_journal_evidence,
                });
            let primary_integrity_failed = !primary_changes.is_empty();
            if primary_integrity_failed {
                mark_primary_integrity_violation(assignment, &primary_changes, &mut attempt_report);
                let tracker = outcome
                    .gate_tracker
                    .as_mut()
                    .context("gate correction tracker was not initialized")?;
                tracker.escalate_active(artifacts, &assignment.id, journal_parent_id)?;
                let denial_ordinal = tracker.denials.len().saturating_add(1);
                let denial = GateDenial::new(
                    gate_correlation_id(&assignment.id, denial_ordinal),
                    GateDenialReason::PrimaryIntegrityFailure,
                    VerifiedGateContext::new(
                        &assignment.id,
                        GateCheckSource::PrimaryIntegrity,
                        &primary_changes.paths,
                    )?,
                )
                .context("failed to construct primary-integrity gate denial")?;
                tracker.escalate(denial, artifacts, &assignment.id, journal_parent_id)?;
            }
            let sandbox_denied = !sandbox_denials.is_empty();
            if sandbox_denied {
                let tracker = outcome
                    .gate_tracker
                    .as_mut()
                    .context("gate correction tracker was not initialized")?;
                tracker.escalate_active(artifacts, &assignment.id, journal_parent_id)?;
                for evidence in sandbox_denials {
                    let denial_ordinal = tracker.denials.len().saturating_add(1);
                    let denial = GateDenial::from_sandbox_denial(
                        gate_correlation_id(&assignment.id, denial_ordinal),
                        &assignment.id,
                        evidence,
                    )
                    .context("failed to construct sandbox gate denial")?;
                    tracker.escalate(denial, artifacts, &assignment.id, journal_parent_id)?;
                }
                attempt_report.status = ReviewStatus::Failed;
                attempt_report.accepted = false;
                attempt_report.rejected = true;
                attempt_report.findings.push(Finding {
                    severity: FindingSeverity::Error,
                    message: "sandbox denial evidence is carry-only and cannot authorize a retry"
                        .to_string(),
                    paths: Vec::new(),
                });
            }
            if !attempt_containment_verified {
                let tracker = outcome
                    .gate_tracker
                    .as_mut()
                    .context("gate correction tracker was not initialized")?;
                tracker.escalate_active(artifacts, &assignment.id, journal_parent_id)?;
                let denial_ordinal = tracker.denials.len().saturating_add(1);
                let denial = GateDenial::new(
                    gate_correlation_id(&assignment.id, denial_ordinal),
                    GateDenialReason::ContainmentFailure,
                    VerifiedGateContext::new(
                        &assignment.id,
                        GateCheckSource::Containment,
                        &assignment.assigned_paths,
                    )?,
                )
                .context("failed to construct containment gate denial")?;
                tracker.escalate(denial, artifacts, &assignment.id, journal_parent_id)?;
                mark_child_containment_violation(
                    assignment,
                    &attempt_artifacts.raw_report_relative,
                    external_run.process_tree,
                    external_run.side_effects,
                    &mut attempt_report,
                );
                attempt_history.push(ChildAttemptHistory {
                    attempt,
                    report_path: attempt_artifacts.raw_report_relative.clone(),
                    structural_problems: report_shape_problems,
                    corrective_retry_used,
                });
                child_report = Some(attempt_report);
                break;
            }
            if sandbox_denied {
                attempt_history.push(ChildAttemptHistory {
                    attempt,
                    report_path: attempt_artifacts.raw_report_relative.clone(),
                    structural_problems: report_shape_problems,
                    corrective_retry_used,
                });
                child_report = Some(attempt_report);
                break;
            }
            if primary_integrity_failed {
                attempt_history.push(ChildAttemptHistory {
                    attempt,
                    report_path: attempt_artifacts.raw_report_relative.clone(),
                    structural_problems: report_shape_problems,
                    corrective_retry_used,
                });
                child_containment_verified = true;
                child_gate_terminal = true;
                child_report = Some(attempt_report);
                break;
            }
            if environment_blocked {
                attempt_history.push(ChildAttemptHistory {
                    attempt,
                    report_path: attempt_artifacts.raw_report_relative.clone(),
                    structural_problems: Vec::new(),
                    corrective_retry_used,
                });
                child_containment_verified = true;
                child_gate_terminal = true;
                child_report = Some(attempt_report);
                break;
            }
            if let Some(external_side_effect_state) = external_side_effect_state {
                let correction_correlation_id = outcome
                    .gate_tracker
                    .as_ref()
                    .context("gate correction tracker was not initialized")?
                    .correlation_id_for_observation(&assignment.id);
                let denial = external_side_effect_gate_denial(
                    &correction_correlation_id,
                    &assignment.id,
                    external_side_effect_state,
                    &assignment.assigned_paths,
                )
                .context("failed to construct external-side-effect gate denial")?;
                let authorized_denial = outcome
                    .gate_tracker
                    .as_mut()
                    .context("gate correction tracker was not initialized")?
                    .authorize(
                        denial,
                        artifacts,
                        &assignment.id,
                        journal_parent_id,
                        &mut outcome.health_signals,
                    )?;
                if authorized_denial.is_some() {
                    bail!("external side effect unexpectedly authorized a correction");
                }
                attempt_report.status = ReviewStatus::Failed;
                attempt_report.accepted = false;
                attempt_report.rejected = true;
                attempt_report.findings.push(Finding {
                    severity: FindingSeverity::Error,
                    message: "observed external side effect requires integration-controller reconciliation and cannot authorize another child launch"
                        .to_string(),
                    paths: assignment.assigned_paths.clone(),
                });
                attempt_history.push(ChildAttemptHistory {
                    attempt,
                    report_path: attempt_artifacts.raw_report_relative.clone(),
                    structural_problems: report_shape_problems,
                    corrective_retry_used,
                });
                child_containment_verified = true;
                child_gate_terminal = true;
                child_report = Some(attempt_report);
                break;
            }
            let retry_used = should_retry_child_report(
                &attempt_report,
                &report_shape_problems,
                structural_attempt,
                plan.max_child_retries,
            );
            attempt_history.push(ChildAttemptHistory {
                attempt,
                report_path: attempt_artifacts.raw_report_relative.clone(),
                structural_problems: report_shape_problems.clone(),
                corrective_retry_used,
            });
            if retry_used {
                outcome
                    .health_signals
                    .push(SwarmHealthSignal::AssignmentOutcome(
                        AssignmentHealthOutcome::Retried,
                    ));
                record_shared_orchestration_event(
                    artifacts,
                    &assignment.id,
                    Some(journal_parent_id),
                    OrchestrationRole::Orchestrator,
                    OrchestrationEventKind::Reject,
                    json!({
                        "scope": "attempt",
                        "attempt": attempt,
                        "reason": "structural report requires corrective retry",
                        "structural_problems": report_shape_problems,
                    }),
                )?;
                record_shared_orchestration_event(
                    artifacts,
                    &assignment.id,
                    Some(journal_parent_id),
                    OrchestrationRole::Orchestrator,
                    OrchestrationEventKind::Status,
                    lifecycle_event_payload("retrying", Some(attempt), None),
                )?;
                structural_attempt = structural_attempt.saturating_add(1);
                retry_feedback = Some(ChildAttemptCorrection::StructuralReport);
                continue;
            }
            let validation_blocker = if attempt_report.validation_results.is_empty() {
                Some(GateApplyBlocker::ValidationMissing)
            } else if attempt_report
                .validation_results
                .iter()
                .any(validation_failed)
            {
                Some(GateApplyBlocker::ValidationFailed)
            } else {
                None
            };
            if report_shape_problems.is_empty() {
                if let Some(blocker) = validation_blocker.filter(|_| report_failed(&attempt_report))
                {
                    let correction_correlation_id = outcome
                        .gate_tracker
                        .as_ref()
                        .context("gate correction tracker was not initialized")?
                        .correlation_id_for_observation(&assignment.id);
                    let denial = GateDenial::new(
                        correction_correlation_id,
                        GateDenialReason::ValidationRepair { blocker },
                        VerifiedGateContext::new(
                            &assignment.id,
                            GateCheckSource::Validation,
                            &assignment.assigned_paths,
                        )?,
                    )
                    .context("failed to construct validation gate denial")?;
                    let authorized_denial = outcome
                        .gate_tracker
                        .as_mut()
                        .context("gate correction tracker was not initialized")?
                        .authorize(
                            denial,
                            artifacts,
                            &assignment.id,
                            journal_parent_id,
                            &mut outcome.health_signals,
                        )?;
                    if let Some(authorized_denial) = authorized_denial {
                        retry_feedback = Some(ChildAttemptCorrection::Gate(authorized_denial));
                        continue;
                    }
                } else if matches!(
                    outcome
                        .gate_tracker
                        .as_ref()
                        .and_then(GateCorrectionTracker::active_reason),
                    Some(GateDenialReason::ValidationRepair { .. })
                ) {
                    outcome
                        .gate_tracker
                        .as_mut()
                        .context("gate correction tracker was not initialized")?
                        .self_corrected(artifacts, &assignment.id, journal_parent_id)?;
                }
            }
            if attempt > 1 {
                attempt_report.findings.push(Finding {
                    severity: FindingSeverity::Warning,
                    message: format!(
                        "child report accepted after corrective retry attempt {attempt}"
                    ),
                    paths: vec![attempt_artifacts.raw_report_relative.clone()],
                });
            }
            child_containment_verified = true;
            child_report = Some(attempt_report);
            break;
        }

        let Some(mut child_report) = child_report else {
            let error = anyhow!(
                "child orchestrator '{}' did not produce a collected report after retries",
                assignment.id
            );
            record_isolated_assignment_failure(
                outcome,
                assignment,
                "child report collection",
                &error,
            );
            return Ok(());
        };
        if plan.max_child_retries > 0 {
            append_child_attempt_history(&mut child_report, &attempt_history);
        }
        let pre_auditor_candidate = if child_containment_verified {
            match bind_supervisor_decomposition_candidate(
                repo,
                assignment,
                &mut child_report,
                &worktree_write_lease,
            ) {
                Ok(Some(inspection)) => Some(inspection),
                Ok(None) if !report_failed(&child_report) => {
                    inspect_supervisor_candidate(repo, assignment, &worktree_write_lease).ok()
                }
                Ok(None) => None,
                Err(error) => {
                    reject_supervisor_decomposition_binding(
                        &mut child_report,
                        &final_report_path,
                        &error,
                    );
                    None
                }
            }
        } else {
            None
        };
        with_supervisor_artifacts(artifacts, |writer, _| {
            write_child_report(writer, &final_report_relative, &child_report)
        })?;

        let mut assignment_containment_verified = child_containment_verified;
        let mut auditor_primary_integrity_failed = false;
        let mut auditor_sandbox_denied = false;
        let mut auditor_environment_blocked = false;
        if child_containment_verified
            && !child_gate_terminal
            && parent_auditor_required(assignment, &child_report)
        {
            auditor_attempt = auditor_attempt.saturating_add(1);
            if let Err(error) = mandatory_worktree_controls.revalidate() {
                record_isolated_assignment_failure(
                    outcome,
                    assignment,
                    "mandatory worktree control revalidation before auditor",
                    &error,
                );
                return Ok(());
            }
            let auditor_id = parent_auditor_id(assignment);
            let auditor_stem = if plan.max_gate_corrections > 0 {
                format!("{auditor_id}.attempt-{auditor_attempt}")
            } else {
                auditor_id.clone()
            };
            let auditor_prompt_path = dirs.assignments.join(format!("{auditor_stem}.prompt.md"));
            let (auditor_incoming_name, auditor_capture_name) =
                invocation_scratch_names(*index, auditor_attempt, true, *concurrent_mode);
            let auditor_incoming_path = run_dir.join(&auditor_incoming_name);
            let auditor_capture_path = run_dir.join(&auditor_capture_name);
            let auditor_report_path = auditor_incoming_path.join(format!("{auditor_stem}.json"));
            let auditor_log_path = auditor_capture_path.join(format!("{auditor_stem}.jsonl"));
            let auditor_artifacts = ChildAttemptArtifacts {
                prompt_path: auditor_prompt_path.clone(),
                report_path: auditor_report_path.clone(),
                log_path: auditor_log_path.clone(),
                raw_report_relative: PathBuf::from("evidence")
                    .join("incoming")
                    .join(format!("{auditor_stem}.json")),
                raw_stdout_relative: PathBuf::from("logs").join(format!("{auditor_stem}.jsonl")),
                command_record_relative: PathBuf::from("logs")
                    .join(format!("{auditor_stem}.summary.json")),
            };
            let auditor_schema_path = dirs.schemas.join("auditor-report.schema.json");
            let auditor_prompt = parent_review_auditor_prompt_with_field_guide(
                ParentReviewAuditorPromptContext {
                    plan,
                    assignment,
                    assignment_metadata,
                    run_dir,
                    worktree_path: &worktree.path,
                    child_report_path: &final_report_path,
                    auditor_report_path: &auditor_report_path,
                    schema_path: &auditor_schema_path,
                    child_report: &child_report,
                },
                field_guide,
            )?;
            record_field_guide_prompt_injection_strict(
                artifacts,
                &auditor_id,
                Some(&assignment.id),
                OrchestrationRole::Auditor,
                SupervisePromptRole::ReviewAuditor,
                field_guide,
                auditor_attempt,
            )?;
            let auditor_prompt_relative = dirs.relative(&auditor_prompt_path)?;
            with_supervisor_artifacts(artifacts, |writer, _| {
                write_private_prompt(writer, &auditor_prompt_relative, &auditor_prompt)
            })
            .with_context(|| {
                format!(
                    "failed to write auditor prompt {}",
                    auditor_prompt_path.display()
                )
            })?;

            let mut auditor_command = ExternalAgentCommand::codex(
                &options.codex_bin,
                &worktree.path,
                &auditor_prompt_path,
                &auditor_log_path,
                &auditor_report_path,
                Duration::from_secs(plan.child_timeout_seconds),
            );
            auditor_command = apply_role_model_selection(
                auditor_command,
                plan,
                AgentRole::Auditor,
                options.runtime,
                runtime_model_catalog,
            )?;
            auditor_command.output_schema = Some(auditor_schema_path);
            auditor_command = configure_read_only_auditor_command(auditor_command)?
                .with_hidden_root(repo)
                .with_agent_lifecycle(
                    repo,
                    AgentRole::Auditor.as_str(),
                    options.run_id.as_str(),
                    &auditor_id,
                );
            auditor_command = apply_canonical_environment_requirements(
                auditor_command,
                &environment_requirements,
            );

            let primary_before_auditor = primary_worktree_snapshot(repo, *execution_runtime)?;
            if let Some(error) = primary_before_auditor.inspection_problem() {
                bail!(
                "refusing to launch parent review auditor without a complete primary integrity snapshot: {error}"
            );
            }
            let (auditor_incoming_scratch, auditor_capture_scratch) =
                with_supervisor_artifacts(artifacts, |writer, _| {
                    create_named_invocation_scratches(
                        writer,
                        &auditor_incoming_name,
                        &auditor_capture_name,
                    )
                })?;
            if auditor_incoming_scratch.path() != auditor_incoming_path
                || auditor_capture_scratch.path() != auditor_capture_path
            {
                with_supervisor_artifacts(artifacts, |writer, _| {
                    discard_invocation_scratches(
                        writer,
                        &auditor_incoming_scratch,
                        &auditor_capture_scratch,
                    )
                })?;
                bail!("artifact scratch paths changed during parent auditor setup");
            }
            let auditor_incoming_root =
                match SecureOutputRoot::open_private(auditor_incoming_scratch.path()) {
                    Ok(root) => root,
                    Err(error) => {
                        with_supervisor_artifacts(artifacts, |writer, _| {
                            discard_invocation_scratches(
                                writer,
                                &auditor_incoming_scratch,
                                &auditor_capture_scratch,
                            )
                        })?;
                        return Err(error)
                            .context("failed to bind parent auditor incoming scratch root");
                    }
                };
            let auditor_capture_root =
                match SecureOutputRoot::open_private(auditor_capture_scratch.path()) {
                    Ok(root) => root,
                    Err(error) => {
                        drop(auditor_incoming_root);
                        with_supervisor_artifacts(artifacts, |writer, _| {
                            discard_invocation_scratches(
                                writer,
                                &auditor_incoming_scratch,
                                &auditor_capture_scratch,
                            )
                        })?;
                        return Err(error)
                            .context("failed to bind parent auditor capture scratch root");
                    }
                };
            if auditor_incoming_root.path() != auditor_incoming_scratch.path()
                || auditor_capture_root.path() != auditor_capture_scratch.path()
            {
                drop(auditor_incoming_root);
                drop(auditor_capture_root);
                with_supervisor_artifacts(artifacts, |writer, _| {
                    discard_invocation_scratches(
                        writer,
                        &auditor_incoming_scratch,
                        &auditor_capture_scratch,
                    )
                })?;
                bail!("descriptor-held auditor scratch roots changed during setup");
            }
            let mut auditor_budget_reservation = match reserve_dispatch_budget(
                plan,
                budget_config,
                budget_ledger,
                AgentRole::Auditor,
                &auditor_command,
            )? {
                DispatchBudgetAdmission::Admitted(reservation) => reservation,
                DispatchBudgetAdmission::Refused(refusal) => {
                    drop(auditor_incoming_root);
                    drop(auditor_capture_root);
                    with_supervisor_artifacts(artifacts, |writer, _| {
                        discard_invocation_scratches(
                            writer,
                            &auditor_incoming_scratch,
                            &auditor_capture_scratch,
                        )
                    })?;
                    record_budget_dispatch_refusal(
                        outcome,
                        assignment,
                        &auditor_id,
                        AgentRole::Auditor,
                        &refusal,
                        artifacts,
                        journal_parent_id,
                    )?;
                    child_report.status = ReviewStatus::Failed;
                    child_report.accepted = false;
                    child_report.rejected = true;
                    child_report.findings.push(Finding {
                        severity: FindingSeverity::Error,
                        message: "parent review auditor was not dispatched because typed run-budget admission denied it; inspect gate_denials and run_budget"
                            .to_string(),
                        paths: assignment.assigned_paths.clone(),
                    });
                    let tracker = outcome
                        .gate_tracker
                        .as_mut()
                        .context("gate correction tracker was not initialized")?;
                    tracker.escalate_active(artifacts, &assignment.id, journal_parent_id)?;
                    child_report.gate_denials = tracker.denials.clone();
                    child_report.gate_correction_outcomes = tracker.outcomes.clone();
                    break 'gate_controller (child_report, None, assignment_containment_verified);
                }
            };
            record_shared_orchestration_event(
                artifacts,
                &auditor_id,
                Some(&assignment.id),
                OrchestrationRole::Auditor,
                OrchestrationEventKind::Spawn,
                json!({"attempt": auditor_attempt}),
            )?;
            record_shared_orchestration_event(
                artifacts,
                &auditor_id,
                Some(&assignment.id),
                OrchestrationRole::Auditor,
                OrchestrationEventKind::Status,
                lifecycle_event_payload("running", Some(auditor_attempt), None),
            )?;

            let auditor_run_result = match options.runtime {
                SupervisorRuntime::Codex => {
                    // All fallible pre-dispatch preparation is complete. Mark
                    // invocation only at the external-runner call boundary.
                    if let Err(error) = auditor_budget_reservation.mark_invoked() {
                        drop(auditor_incoming_root);
                        drop(auditor_capture_root);
                        with_supervisor_artifacts(artifacts, |writer, _| {
                            discard_invocation_scratches(
                                writer,
                                &auditor_incoming_scratch,
                                &auditor_capture_scratch,
                            )
                        })?;
                        return Err(error);
                    }
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        external_runner(&auditor_command, cancellation, None)
                    })) {
                        Ok(run) => Ok(run),
                        Err(payload) => {
                            drop(auditor_incoming_root);
                            drop(auditor_capture_root);
                            with_supervisor_artifacts(artifacts, |writer, _| {
                                discard_invocation_scratches(
                                    writer,
                                    &auditor_incoming_scratch,
                                    &auditor_capture_scratch,
                                )
                            })?;
                            std::panic::resume_unwind(payload);
                        }
                    }
                }
                SupervisorRuntime::Fake => {
                    if let Err(error) = auditor_budget_reservation.mark_invoked() {
                        drop(auditor_incoming_root);
                        drop(auditor_capture_root);
                        with_supervisor_artifacts(artifacts, |writer, _| {
                            discard_invocation_scratches(
                                writer,
                                &auditor_incoming_scratch,
                                &auditor_capture_scratch,
                            )
                        })?;
                        return Err(error);
                    }
                    deterministic_fake_auditor_run(&auditor_command, assignment, &child_report)
                }
            };
            let auditor_run = match auditor_run_result {
                Ok(run) => run,
                Err(error) => {
                    auditor_budget_reservation.settle_not_started()?;
                    drop(auditor_incoming_root);
                    drop(auditor_capture_root);
                    with_supervisor_artifacts(artifacts, |writer, _| {
                        discard_invocation_scratches(
                            writer,
                            &auditor_incoming_scratch,
                            &auditor_capture_scratch,
                        )
                    })?;
                    return Err(error)
                        .context("failed to produce deterministic parent auditor output");
                }
            };
            auditor_environment_blocked = auditor_run.environment_blocked();
            let usage_settlement = auditor_budget_reservation.settle(
                &auditor_run,
                options.runtime,
                &auditor_command,
            )?;
            match usage_settlement.reliable_usage() {
                Some(usage) => outcome.usage_samples.push(RoleUsageSample {
                    role: AgentRole::Auditor,
                    model: auditor_command.model.clone(),
                    usage,
                }),
                None if usage_settlement.is_degraded() => outcome.usage_incomplete = true,
                None => {}
            }
            drop(auditor_incoming_root);
            drop(auditor_capture_root);
            let auditor_thread_id = codex_thread_id_from_stdout(auditor_run.stdout_bytes());
            record_shared_orchestration_event(
                artifacts,
                &auditor_id,
                Some(&assignment.id),
                OrchestrationRole::Auditor,
                OrchestrationEventKind::Status,
                lifecycle_event_payload(
                    if external_process_completed(&auditor_run) {
                        "completed"
                    } else {
                        "failed"
                    },
                    Some(auditor_attempt),
                    auditor_thread_id.as_deref(),
                ),
            )?;
            let auditor_containment_verified =
                external_containment_verified(&auditor_run, options.runtime);
            if !auditor_containment_verified {
                assignment_containment_verified = false;
                outcome.external_containment_failed = true;
                outcome.findings.push(Finding {
                severity: FindingSeverity::Error,
                message: format!(
                    "external parent auditor process containment was not verified empty for '{}'; evidence: {:?}; report: {}",
                    auditor_id,
                    (auditor_run.process_tree, auditor_run.side_effects),
                    auditor_artifacts.raw_report_relative.display()
                ),
                paths: vec![auditor_artifacts.raw_report_relative.clone()],
            });
                let tracker = outcome
                    .gate_tracker
                    .as_mut()
                    .context("gate correction tracker was not initialized")?;
                tracker.escalate_active(artifacts, &assignment.id, journal_parent_id)?;
                let denial_ordinal = tracker.denials.len().saturating_add(1);
                let denial = GateDenial::new(
                    gate_correlation_id(&assignment.id, denial_ordinal),
                    GateDenialReason::ContainmentFailure,
                    VerifiedGateContext::new(
                        &assignment.id,
                        GateCheckSource::Containment,
                        &assignment.assigned_paths,
                    )?,
                )
                .context("failed to construct auditor-containment gate denial")?;
                tracker.escalate(denial, artifacts, &assignment.id, journal_parent_id)?;
            }
            let auditor_sandbox_denials = auditor_run.sandbox_denials().to_vec();
            if !auditor_environment_blocked && !auditor_sandbox_denials.is_empty() {
                auditor_sandbox_denied = true;
                let tracker = outcome
                    .gate_tracker
                    .as_mut()
                    .context("gate correction tracker was not initialized")?;
                tracker.escalate_active(artifacts, &assignment.id, journal_parent_id)?;
                for evidence in auditor_sandbox_denials {
                    let denial_ordinal = tracker.denials.len().saturating_add(1);
                    let denial = GateDenial::from_sandbox_denial(
                        gate_correlation_id(&assignment.id, denial_ordinal),
                        &assignment.id,
                        evidence,
                    )
                    .context("failed to construct auditor sandbox gate denial")?;
                    tracker.escalate(denial, artifacts, &assignment.id, journal_parent_id)?;
                }
            }
            let auditor_command_record =
                command_record_from_external(&auditor_run, &auditor_command);
            outcome.command_records.push(auditor_command_record.clone());
            child_report.commands_run.push(auditor_command_record);
            let raw_auditor_validated = read_auditor_report(
                auditor_run.output_last_message(),
                &auditor_artifacts.raw_report_relative,
            )
            .is_ok();
            with_supervisor_artifacts(artifacts, |writer, _| {
                import_external_attempt_evidence(
                    writer,
                    ExternalAttemptEvidenceContext {
                        incoming_scratch: &auditor_incoming_scratch,
                        capture_scratch: &auditor_capture_scratch,
                        artifacts: &auditor_artifacts,
                        external_run: &auditor_run,
                        external_command: &auditor_command,
                        raw_report_validated: raw_auditor_validated,
                        runtime: options.runtime,
                    },
                )
            })?;
            let primary_after_auditor = primary_worktree_snapshot(repo, *execution_runtime)?;
            let primary_auditor_changes =
                primary_integrity_changes(&primary_before_auditor, &primary_after_auditor);
            let mut auditor_report = collect_parent_auditor_report(
                assignment,
                &auditor_artifacts.raw_report_relative,
                &auditor_run,
                &auditor_command,
            );
            if !primary_auditor_changes.is_empty() {
                auditor_primary_integrity_failed = true;
                mark_auditor_primary_integrity_violation(
                    assignment,
                    &primary_auditor_changes,
                    &mut auditor_report,
                );
                let tracker = outcome
                    .gate_tracker
                    .as_mut()
                    .context("gate correction tracker was not initialized")?;
                tracker.escalate_active(artifacts, &assignment.id, journal_parent_id)?;
                let denial_ordinal = tracker.denials.len().saturating_add(1);
                let denial = GateDenial::new(
                    gate_correlation_id(&assignment.id, denial_ordinal),
                    GateDenialReason::PrimaryIntegrityFailure,
                    VerifiedGateContext::new(
                        &assignment.id,
                        GateCheckSource::PrimaryIntegrity,
                        &primary_auditor_changes.paths,
                    )?,
                )
                .context("failed to construct auditor primary-integrity gate denial")?;
                tracker.escalate(denial, artifacts, &assignment.id, journal_parent_id)?;
            }
            child_report.audit_reports.push(auditor_report);
            enforce_orchestrator_environment_failure_outcome(&mut child_report);
        }
        if child_containment_verified
            && child_report.environment_failures.is_empty()
            && !auditor_environment_blocked
        {
            validate_auditor_reports(assignment, &final_report_path, &mut child_report);
        }
        let parent_auditor_failed = child_report
            .audit_reports
            .iter()
            .any(|report| report.id == parent_auditor_id(assignment) && report_failed(report));
        if parent_auditor_failed
            && assignment_containment_verified
            && !auditor_primary_integrity_failed
            && !auditor_sandbox_denied
            && !auditor_environment_blocked
        {
            let correction_correlation_id = outcome
                .gate_tracker
                .as_ref()
                .context("gate correction tracker was not initialized")?
                .correlation_id_for_observation(&assignment.id);
            let denial = GateDenial::new(
                correction_correlation_id,
                GateDenialReason::AuditorRepair,
                VerifiedGateContext::new(
                    &assignment.id,
                    GateCheckSource::Auditor,
                    &assignment.assigned_paths,
                )?,
            )
            .context("failed to construct parent-auditor gate denial")?;
            let authorized_denial = outcome
                .gate_tracker
                .as_mut()
                .context("gate correction tracker was not initialized")?
                .authorize(
                    denial,
                    artifacts,
                    &assignment.id,
                    journal_parent_id,
                    &mut outcome.health_signals,
                )?;
            if let Some(authorized_denial) = authorized_denial {
                retry_feedback = Some(ChildAttemptCorrection::Gate(authorized_denial));
                continue 'gate_controller;
            }
        } else if matches!(
            outcome
                .gate_tracker
                .as_ref()
                .and_then(GateCorrectionTracker::active_reason),
            Some(GateDenialReason::AuditorRepair)
        ) && !parent_auditor_failed
        {
            outcome
                .gate_tracker
                .as_mut()
                .context("gate correction tracker was not initialized")?
                .self_corrected(artifacts, &assignment.id, journal_parent_id)?;
        }
        let mut traceability_candidate = None;
        if !report_failed(&child_report) {
            let post_auditor_candidate =
                inspect_supervisor_candidate(repo, assignment, &worktree_write_lease);
            match (pre_auditor_candidate.as_ref(), post_auditor_candidate) {
                (Some(before), Ok(after)) if before == &after => {
                    traceability_candidate = Some(after);
                }
                (Some(before), Ok(after)) if !child_report.decomposition_completions.is_empty() => {
                    let error = anyhow!(
                    "candidate content, paths, or base changed across parent auditor review: before={before:?}, after={after:?}"
                );
                    reject_supervisor_decomposition_binding(
                        &mut child_report,
                        &final_report_path,
                        &error,
                    );
                }
                (Some(_), Err(error)) if !child_report.decomposition_completions.is_empty() => {
                    let error = anyhow!(
                    "failed to recapture decomposition candidate after parent auditor review: {error:#}"
                );
                    reject_supervisor_decomposition_binding(
                        &mut child_report,
                        &final_report_path,
                        &error,
                    );
                }
                (None, _) if !child_report.decomposition_completions.is_empty() => {
                    let error = anyhow!(
                    "accepted decomposition evidence has no pre-auditor supervisor candidate binding"
                );
                    reject_supervisor_decomposition_binding(
                        &mut child_report,
                        &final_report_path,
                        &error,
                    );
                }
                _ => {}
            }
        }
        if !report_failed(&child_report) {
            if let Some(candidate) = traceability_candidate.as_ref() {
                if candidate.changed_paths != child_report.files_changed {
                    let error = anyhow!(
                        "supervisor-observed candidate paths differ from the accepted child report"
                    );
                    if !child_report.decomposition_completions.is_empty() {
                        reject_supervisor_decomposition_binding(
                            &mut child_report,
                            &final_report_path,
                            &error,
                        );
                    }
                    traceability_candidate = None;
                }
            }
        }
        if report_failed(&child_report) {
            traceability_candidate = None;
        }
        let tracker = outcome
            .gate_tracker
            .as_mut()
            .context("gate correction tracker was not initialized")?;
        tracker.escalate_active(artifacts, &assignment.id, journal_parent_id)?;
        child_report.gate_denials = tracker.denials.clone();
        child_report.gate_correction_outcomes = tracker.outcomes.clone();
        break 'gate_controller (
            child_report,
            traceability_candidate,
            assignment_containment_verified,
        );
    };
    outcome.candidate_inspection = completed_candidate_inspection;
    with_supervisor_artifacts(artifacts, |writer, journal| {
        write_child_report(writer, &final_report_relative, &child_report)?;
        record_final_report_decisions(journal, writer, journal_parent_id, &child_report);
        Ok(())
    })?;
    if child_report.status != ReviewStatus::Succeeded {
        outcome.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: format!("child orchestrator '{}' failed", assignment.id),
            paths: vec![final_report_path.clone()],
        });
    }
    if child_report.audit_reports.iter().any(report_failed) {
        outcome.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: format!(
                "child orchestrator '{}' failed enforced parent review auditor gate",
                assignment.id
            ),
            paths: vec![final_report_path.clone()],
        });
    }
    if child_report.worker_reports.iter().any(report_failed) {
        outcome.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: format!(
                "child orchestrator '{}' reported failed or rejected worker output",
                assignment.id
            ),
            paths: child_report.files_changed.clone(),
        });
    }
    outcome.report = Some(child_report);
    if !completed_assignment_containment {
        outcome.external_containment_failed = true;
    }
    Ok(())
}
