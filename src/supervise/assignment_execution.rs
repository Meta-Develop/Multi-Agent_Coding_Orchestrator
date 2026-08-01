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

enum AssignmentExecutionDisposition<T> {
    Continue(T),
    Complete,
}

struct AssignmentExecutionPreflight<'a> {
    journal_parent_id: &'a str,
    environment_requirements: Vec<EnvironmentRequirement>,
    semantic_token: Option<u64>,
    child_base_head: Oid,
    mandatory_worktree_controls: MandatoryWorktreeControls,
    worktree: WorktreeRecord,
    worktree_write_lease: ManagedWorktreeWriteLease,
    claim: PathClaim,
    assignment: OrchestratorAssignment,
    _semantic_block_turn: Option<SemanticBlockTurn<'a>>,
}

fn prepare_assignment_execution<'a>(
    context: &AssignmentExecutionContext<'a, '_>,
    outcome: &mut AssignmentExecutionOutcome,
) -> Result<AssignmentExecutionDisposition<AssignmentExecutionPreflight<'a>>> {
    let AssignmentExecutionContext {
        index,
        plan,
        assignment,
        options,
        repo,
        execution_runtime: _,
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
        serial_semantic_warn_intents,
        semantic_block_order,
        semantic_block_gate,
        artifacts,
        ..
    } = context;
    outcome
        .findings
        .extend(prepared_semantic_findings.iter().cloned());
    outcome
        .health_signals
        .extend(prepared_semantic_signals.iter().copied());
    if *prepared_semantic_failed {
        outcome.assignment_failed = true;
        return Ok(AssignmentExecutionDisposition::Complete);
    }
    let journal_parent_id = assignment_schedule
        .get(*index)
        .context("assignment execution index is outside the validated schedule")?
        .parent_assignment_id
        .as_deref()
        .unwrap_or_else(|| options.run_id.as_str());
    let mut semantic_block_turn = match (semantic_block_gate, semantic_block_order) {
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
                    return Ok(AssignmentExecutionDisposition::Complete);
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
                    return Ok(AssignmentExecutionDisposition::Complete);
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
                    return Ok(AssignmentExecutionDisposition::Complete);
                }
                effective_assignment = narrowed;
            }
        }
    };
    outcome.claim_tokens.push(claim.token);
    let current_primary_head = current_head_oid(repo)?;
    if !reused {
        let create_options = WorktreeCreateOptions {
            agent_id: effective_assignment.id.clone(),
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
                        effective_assignment.id
                    )
                }),
            #[cfg(test)]
            SupervisorWorktreeCreation::TestOnly => manager.create_for_test(create_options),
        };
        if let Err(error) = create_result {
            record_isolated_assignment_failure(
                outcome,
                &effective_assignment,
                "worktree creation",
                &error,
            );
            return Ok(AssignmentExecutionDisposition::Complete);
        }
    }
    let worktree_write_lease = match manager
        .acquire_write_execution_lease(&effective_assignment.id)
        .with_context(|| {
            format!(
                "failed to acquire exclusive execution lease for child worktree '{}'",
                effective_assignment.id
            )
        }) {
        Ok(lease) => lease,
        Err(error) => {
            record_isolated_assignment_failure(
                outcome,
                &effective_assignment,
                "worktree execution lease acquisition",
                &error,
            );
            return Ok(AssignmentExecutionDisposition::Complete);
        }
    };
    let worktree = worktree_write_lease.record().clone();
    if *reused {
        if let Err(error) = ensure_reusable_child_worktree(&worktree, &current_primary_head) {
            record_isolated_assignment_failure(
                outcome,
                &effective_assignment,
                "reusable worktree validation",
                &error,
            );
            return Ok(AssignmentExecutionDisposition::Complete);
        }
    }
    let mandatory_worktree_controls = match provision_mandatory_worktree_controls(&worktree.path) {
        Ok(controls) => controls,
        Err(error) => {
            record_isolated_assignment_failure(
                outcome,
                &effective_assignment,
                "mandatory worktree control bootstrap",
                &error,
            );
            return Ok(AssignmentExecutionDisposition::Complete);
        }
    };
    if let Err(error) = assignment_worktree_control_exceptions(&effective_assignment.assigned_paths)
    {
        record_isolated_assignment_failure(
            outcome,
            &effective_assignment,
            "worktree control exception derivation",
            &error,
        );
        return Ok(AssignmentExecutionDisposition::Complete);
    }
    let child_base_head = match current_head_oid(&worktree.path).with_context(|| {
        format!(
            "failed to capture base HEAD for child worktree '{}' at {}",
            effective_assignment.id,
            worktree.path.display()
        )
    }) {
        Ok(head) => head,
        Err(error) => {
            record_isolated_assignment_failure(
                outcome,
                &effective_assignment,
                "worktree HEAD capture",
                &error,
            );
            return Ok(AssignmentExecutionDisposition::Complete);
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
                    &effective_assignment,
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
                        .push(semantic_resolution_finding(&effective_assignment, &error));
                    return Ok(AssignmentExecutionDisposition::Complete);
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
            &effective_assignment,
            plan.semantic_coordination,
            &mut outcome.semantic_tokens,
            &mut planned_semantic_intents,
            &mut outcome.findings,
            &mut outcome.health_signals,
        );
        drop(semantic_block_turn.take());
        let coordination = match coordination_result {
            Ok(coordination) => coordination,
            Err(error) if semantic_resolution_error(&error) => {
                outcome.assignment_failed = true;
                outcome
                    .findings
                    .push(semantic_resolution_finding(&effective_assignment, &error));
                return Ok(AssignmentExecutionDisposition::Complete);
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
                        effective_assignment.id
                    ),
                    paths: effective_assignment.assigned_paths.clone(),
                });
                return Ok(AssignmentExecutionDisposition::Complete);
            }
        }
    };
    let environment_requirements = canonical_environment_requirements(&effective_assignment)?;
    Ok(AssignmentExecutionDisposition::Continue(
        AssignmentExecutionPreflight {
            journal_parent_id,
            environment_requirements,
            semantic_token,
            child_base_head,
            mandatory_worktree_controls,
            worktree,
            worktree_write_lease,
            claim,
            assignment: effective_assignment,
            _semantic_block_turn: semantic_block_turn,
        },
    ))
}

struct PreparedChildAttempt<'a> {
    attempt_artifacts: ChildAttemptArtifacts,
    corrective_retry_used: bool,
    command: ExternalAgentCommand,
    primary_before: PrimaryWorktreeSnapshot,
    incoming_scratch: ArtifactScratchDirectory,
    capture_scratch: ArtifactScratchDirectory,
    incoming_output_root: SecureOutputRoot,
    capture_output_root: SecureOutputRoot,
    budget_reservation: DispatchBudgetReservation<'a>,
}

#[allow(clippy::too_many_arguments)]
fn prepare_child_attempt<'a>(
    context: &AssignmentExecutionContext<'a, '_>,
    outcome: &mut AssignmentExecutionOutcome,
    preflight: &AssignmentExecutionPreflight<'_>,
    journal_parent_id: &str,
    attempt: usize,
    max_attempts: usize,
    retry_feedback: &Option<ChildAttemptCorrection>,
    schema_path: &Path,
    worker_schema_path: &Path,
    auditor_schema_path: &Path,
) -> Result<AssignmentExecutionDisposition<PreparedChildAttempt<'a>>> {
    let AssignmentExecutionContext {
        index,
        concurrent_mode,
        plan,
        budget_config,
        consultant,
        assignment_metadata,
        options,
        repo,
        run_dir,
        dirs,
        execution_runtime,
        field_guide,
        artifacts,
        budget_ledger,
        runtime_model_catalog,
        ..
    } = context;
    let assignment = &preflight.assignment;
    let worktree = &preflight.worktree;
    if let Err(error) = preflight.mandatory_worktree_controls.revalidate() {
        record_isolated_assignment_failure(
            outcome,
            assignment,
            "mandatory worktree control revalidation",
            &error,
        );
        return Ok(AssignmentExecutionDisposition::Complete);
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
    let RenderedPromptWithMeasurements {
        prompt,
        mut measurements,
    } = render_child_orchestrator_prompt_with_incoming_root_and_field_guide(
        ChildOrchestratorPromptContext {
            plan,
            assignment,
            run_dir,
            worktree,
            report_path: &attempt_artifacts.report_path,
            schema_path,
            worker_schema_path,
            auditor_schema_path,
            consultant,
            claim_context: ChildPromptClaimContext {
                claim: &preflight.claim,
                semantic_intent_token: preflight.semantic_token,
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
    let attempt_prompt = match retry_feedback {
        Some(ChildAttemptCorrection::StructuralReport) => prompt_with_structural_retry(&prompt),
        Some(ChildAttemptCorrection::Gate(denial)) => prompt_with_gate_correction(&prompt, denial)?,
        None => prompt,
    };
    measurements.record_final_launch_prompt_bytes(&attempt_prompt)?;
    let prompt_relative = dirs.relative(&attempt_artifacts.prompt_path)?;
    let measurements_relative = prompt_measurements_relative(&prompt_relative);
    with_supervisor_artifacts(artifacts, |writer, _| {
        write_private_prompt(writer, &prompt_relative, &attempt_prompt)?;
        write_artifact_json(
            writer,
            &measurements_relative,
            &measurements,
            MAX_SUPERVISOR_PROMPT_BYTES,
            ArtifactFileDisposition::PrivateEvidence,
        )
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
    command.output_schema = Some(schema_path.to_path_buf());
    command = command.with_hidden_root(repo).with_agent_lifecycle(
        repo,
        assignment.role.as_str(),
        options.run_id.as_str(),
        &assignment.id,
    );
    command = bind_supervisor_machine_global_staging_cleanup(command, options)?;
    command =
        apply_canonical_environment_requirements(command, &preflight.environment_requirements);
    command = configure_writable_child_command(command, &assignment.assigned_paths)?;

    let primary_before = primary_worktree_snapshot(repo, *execution_runtime)?;
    if let Some(error) = primary_before.inspection_problem() {
        bail!("refusing to launch child without a complete primary integrity snapshot: {error}");
    }
    let (incoming_scratch, capture_scratch) = with_supervisor_artifacts(artifacts, |writer, _| {
        create_named_invocation_scratches(writer, &incoming_name, &capture_name)
    })?;
    if incoming_scratch.path() != incoming_path || capture_scratch.path() != capture_path {
        with_supervisor_artifacts(artifacts, |writer, _| {
            discard_invocation_scratches(writer, &incoming_scratch, &capture_scratch)
        })?;
        bail!("artifact scratch paths changed during child setup");
    }
    let incoming_output_root = match SecureOutputRoot::open_private(incoming_scratch.path()) {
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
    let budget_reservation = match reserve_dispatch_budget(
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
            return Ok(AssignmentExecutionDisposition::Complete);
        }
    };
    Ok(AssignmentExecutionDisposition::Continue(
        PreparedChildAttempt {
            attempt_artifacts,
            corrective_retry_used,
            command,
            primary_before,
            incoming_scratch,
            capture_scratch,
            incoming_output_root,
            capture_output_root,
            budget_reservation,
        },
    ))
}

struct CollectedChildAttempt<'a> {
    attempt_report: OrchestratorReviewReport,
    report_shape_problems: Vec<String>,
    primary_changes: PrimaryIntegrityChanges,
    sandbox_denials: Vec<SandboxDenialEvidence>,
    pre_action_refusals: Vec<GateDenial>,
    external_side_effect_state: Option<ExternalSideEffectState>,
    environment_blocked: bool,
    attempt_containment_verified: bool,
    attempt_artifacts: ChildAttemptArtifacts,
    corrective_retry_used: bool,
    external_run: ExternalAgentRun,
    _worker_journal_evidence: WorkerExecutionJournalEvidenceSet,
    _primary_after: PrimaryWorktreeSnapshot,
    _budget_reservation: DispatchBudgetReservation<'a>,
    _capture_scratch: ArtifactScratchDirectory,
    _incoming_scratch: ArtifactScratchDirectory,
    _primary_before: PrimaryWorktreeSnapshot,
    _command: ExternalAgentCommand,
}

fn dispatch_and_collect_child_attempt<'a>(
    context: &AssignmentExecutionContext<'a, '_>,
    outcome: &mut AssignmentExecutionOutcome,
    preflight: &AssignmentExecutionPreflight<'_>,
    journal_parent_id: &str,
    attempt: usize,
    prepared: PreparedChildAttempt<'a>,
) -> Result<CollectedChildAttempt<'a>> {
    let AssignmentExecutionContext {
        assignment_metadata,
        options,
        repo,
        execution_runtime,
        artifacts,
        cancellation,
        external_runner,
        ..
    } = context;
    let assignment = &preflight.assignment;
    let worktree = &preflight.worktree;
    let attempt_artifacts = prepared.attempt_artifacts;
    let corrective_retry_used = prepared.corrective_retry_used;
    let command = prepared.command;
    let primary_before = prepared.primary_before;
    let incoming_scratch = prepared.incoming_scratch;
    let capture_scratch = prepared.capture_scratch;
    let incoming_output_root = prepared.incoming_output_root;
    let capture_output_root = prepared.capture_output_root;
    let mut budget_reservation = prepared.budget_reservation;

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
                    discard_invocation_scratches(writer, &incoming_scratch, &capture_scratch)
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
                        discard_invocation_scratches(writer, &incoming_scratch, &capture_scratch)
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
                    discard_invocation_scratches(writer, &incoming_scratch, &capture_scratch)
                })?;
                return Err(error);
            }
            deterministic_fake_child_run(
                &command,
                assignment,
                assignment_metadata,
                preflight.claim.token.get(),
                preflight.semantic_token,
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
    let usage_settlement = budget_reservation.settle(&external_run, options.runtime, &command)?;
    match usage_settlement.reliable_usage() {
        Some(usage) => outcome.usage_samples.push(RoleUsageSample {
            role: assignment.role,
            lens_id: None,
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
    let worker_journal_evidence = with_supervisor_artifacts(artifacts, |writer, journal| {
        let evidence = import_worker_execution_journals(writer, assignment, &incoming_scratch)?;
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
    let (pre_action_refusals, retryable_gate_denials): (Vec<_>, Vec<_>) = external_run
        .gate_denials()
        .iter()
        .cloned()
        .partition(is_child_pre_action_refusal);
    outcome.gate_denials.extend(retryable_gate_denials);
    if let Some(metrics) = external_run.pre_action_review_metrics() {
        outcome.pre_action_review_metrics.push(metrics.clone());
    }
    let external_side_effect_state = external_run.external_side_effect_state();
    let (attempt_report, report_shape_problems) =
        collect_child_report(ChildReportCollectionContext {
            assignment,
            assignment_metadata,
            report_path: &attempt_artifacts.raw_report_relative,
            external_run: &external_run,
            external_command: &command,
            worktree_path: &worktree.path,
            child_base_head: &preflight.child_base_head,
            worker_journals: &worker_journal_evidence,
        });
    Ok(CollectedChildAttempt {
        attempt_report,
        report_shape_problems,
        primary_changes,
        sandbox_denials,
        pre_action_refusals,
        external_side_effect_state,
        environment_blocked,
        attempt_containment_verified,
        attempt_artifacts,
        corrective_retry_used,
        external_run,
        _worker_journal_evidence: worker_journal_evidence,
        _primary_after: primary_after,
        _budget_reservation: budget_reservation,
        _capture_scratch: capture_scratch,
        _incoming_scratch: incoming_scratch,
        _primary_before: primary_before,
        _command: command,
    })
}

#[allow(clippy::large_enum_variant)]
enum ChildAttemptDisposition {
    Retry,
    Finish {
        report: OrchestratorReviewReport,
        containment_verified: bool,
        gate_terminal: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChildGateTerminalReason {
    Containment,
    Sandbox,
    PrimaryIntegrity,
    Environment,
    PreActionReview,
    ExternalSideEffect,
}

fn is_child_pre_action_refusal(denial: &GateDenial) -> bool {
    matches!(
        denial.reason,
        GateDenialReason::ApprovalReview {
            denial: crate::gate_denial::ApprovalReviewDenial::LatencyBudgetExceeded
                | crate::gate_denial::ApprovalReviewDenial::DuplexFallbackRequired,
        }
    )
}

fn child_gate_terminal_reason(
    containment_verified: bool,
    sandbox_denied: bool,
    primary_integrity_failed: bool,
    environment_blocked: bool,
    pre_action_refused: bool,
    external_side_effect_observed: bool,
) -> Option<ChildGateTerminalReason> {
    if !containment_verified {
        Some(ChildGateTerminalReason::Containment)
    } else if sandbox_denied {
        Some(ChildGateTerminalReason::Sandbox)
    } else if primary_integrity_failed {
        Some(ChildGateTerminalReason::PrimaryIntegrity)
    } else if environment_blocked {
        Some(ChildGateTerminalReason::Environment)
    } else if pre_action_refused {
        Some(ChildGateTerminalReason::PreActionReview)
    } else if external_side_effect_observed {
        Some(ChildGateTerminalReason::ExternalSideEffect)
    } else {
        None
    }
}

#[allow(clippy::too_many_arguments)]
fn decide_child_attempt(
    context: &AssignmentExecutionContext<'_, '_>,
    outcome: &mut AssignmentExecutionOutcome,
    preflight: &AssignmentExecutionPreflight<'_>,
    journal_parent_id: &str,
    attempt: usize,
    structural_attempt: &mut usize,
    retry_feedback: &mut Option<ChildAttemptCorrection>,
    attempt_history: &mut Vec<ChildAttemptHistory>,
    collected: CollectedChildAttempt<'_>,
) -> Result<ChildAttemptDisposition> {
    let AssignmentExecutionContext {
        plan, artifacts, ..
    } = context;
    let assignment = &preflight.assignment;
    let CollectedChildAttempt {
        mut attempt_report,
        report_shape_problems,
        primary_changes,
        sandbox_denials,
        pre_action_refusals,
        external_side_effect_state,
        environment_blocked,
        attempt_containment_verified,
        attempt_artifacts,
        corrective_retry_used,
        external_run,
        _worker_journal_evidence,
        _primary_after,
        _budget_reservation,
        _capture_scratch,
        _incoming_scratch,
        _primary_before,
        _command,
    } = collected;
    let pre_action_refused = !pre_action_refusals.is_empty();
    if pre_action_refused {
        let tracker = outcome
            .gate_tracker
            .as_mut()
            .context("gate correction tracker was not initialized")?;
        tracker.escalate_active(artifacts, &assignment.id, journal_parent_id)?;
        for denial in pre_action_refusals {
            tracker.escalate(denial, artifacts, &assignment.id, journal_parent_id)?;
        }
        attempt_report.status = ReviewStatus::Failed;
        attempt_report.accepted = false;
        attempt_report.rejected = true;
        attempt_report.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: "pre-action review refused the child result; restore the review service before beginning a new child operation"
                .to_string(),
            paths: assignment.assigned_paths.clone(),
        });
    }
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
    let terminal_reason = child_gate_terminal_reason(
        attempt_containment_verified,
        sandbox_denied,
        primary_integrity_failed,
        environment_blocked,
        pre_action_refused,
        external_side_effect_state.is_some(),
    );
    if terminal_reason == Some(ChildGateTerminalReason::Containment) {
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
            raw_stdout_path: attempt_artifacts.raw_stdout_relative.clone(),
            structural_problems: report_shape_problems,
            corrective_retry_used,
        });
        return Ok(ChildAttemptDisposition::Finish {
            report: attempt_report,
            containment_verified: false,
            gate_terminal: false,
        });
    }
    if terminal_reason == Some(ChildGateTerminalReason::Sandbox) {
        attempt_history.push(ChildAttemptHistory {
            attempt,
            report_path: attempt_artifacts.raw_report_relative.clone(),
            raw_stdout_path: attempt_artifacts.raw_stdout_relative.clone(),
            structural_problems: report_shape_problems,
            corrective_retry_used,
        });
        return Ok(ChildAttemptDisposition::Finish {
            report: attempt_report,
            containment_verified: false,
            gate_terminal: false,
        });
    }
    if terminal_reason == Some(ChildGateTerminalReason::PrimaryIntegrity) {
        attempt_history.push(ChildAttemptHistory {
            attempt,
            report_path: attempt_artifacts.raw_report_relative.clone(),
            raw_stdout_path: attempt_artifacts.raw_stdout_relative.clone(),
            structural_problems: report_shape_problems,
            corrective_retry_used,
        });
        return Ok(ChildAttemptDisposition::Finish {
            report: attempt_report,
            containment_verified: true,
            gate_terminal: true,
        });
    }
    if terminal_reason == Some(ChildGateTerminalReason::Environment) {
        attempt_history.push(ChildAttemptHistory {
            attempt,
            report_path: attempt_artifacts.raw_report_relative.clone(),
            raw_stdout_path: attempt_artifacts.raw_stdout_relative.clone(),
            structural_problems: Vec::new(),
            corrective_retry_used,
        });
        return Ok(ChildAttemptDisposition::Finish {
            report: attempt_report,
            containment_verified: true,
            gate_terminal: true,
        });
    }
    if terminal_reason == Some(ChildGateTerminalReason::PreActionReview) {
        attempt_history.push(ChildAttemptHistory {
            attempt,
            report_path: attempt_artifacts.raw_report_relative.clone(),
            raw_stdout_path: attempt_artifacts.raw_stdout_relative.clone(),
            structural_problems: report_shape_problems,
            corrective_retry_used,
        });
        return Ok(ChildAttemptDisposition::Finish {
            report: attempt_report,
            containment_verified: true,
            gate_terminal: true,
        });
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
            raw_stdout_path: attempt_artifacts.raw_stdout_relative.clone(),
            structural_problems: report_shape_problems,
            corrective_retry_used,
        });
        return Ok(ChildAttemptDisposition::Finish {
            report: attempt_report,
            containment_verified: true,
            gate_terminal: true,
        });
    }
    let retry_used = should_retry_child_report(
        &attempt_report,
        &report_shape_problems,
        *structural_attempt,
        plan.max_child_retries,
    );
    attempt_history.push(ChildAttemptHistory {
        attempt,
        report_path: attempt_artifacts.raw_report_relative.clone(),
        raw_stdout_path: attempt_artifacts.raw_stdout_relative.clone(),
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
        *structural_attempt = structural_attempt.saturating_add(1);
        *retry_feedback = Some(ChildAttemptCorrection::StructuralReport);
        return Ok(ChildAttemptDisposition::Retry);
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
        if let Some(blocker) = validation_blocker.filter(|_| report_failed(&attempt_report)) {
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
                *retry_feedback = Some(ChildAttemptCorrection::Gate(authorized_denial));
                return Ok(ChildAttemptDisposition::Retry);
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
            message: format!("child report accepted after corrective retry attempt {attempt}"),
            paths: vec![attempt_artifacts.raw_report_relative.clone()],
        });
    }
    Ok(ChildAttemptDisposition::Finish {
        report: attempt_report,
        containment_verified: true,
        gate_terminal: false,
    })
}

#[allow(clippy::large_enum_variant)]
enum ParentAuditorPreparation<'a> {
    Ready(PreparedParentAuditor<'a>),
    AssignmentComplete,
    GateComplete { verdict: ReviewLensVerdict },
}

struct PreparedParentAuditor<'a> {
    lens: ReviewLensConfig,
    expected_request: ReviewLensRequest,
    auditor_id: String,
    auditor_artifacts: ChildAttemptArtifacts,
    auditor_command: ExternalAgentCommand,
    primary_before_auditor: PrimaryWorktreeSnapshot,
    auditor_incoming_scratch: ArtifactScratchDirectory,
    auditor_capture_scratch: ArtifactScratchDirectory,
    auditor_incoming_root: SecureOutputRoot,
    auditor_capture_root: SecureOutputRoot,
    auditor_budget_reservation: DispatchBudgetReservation<'a>,
    scope_workspace: tempfile::TempDir,
}

struct ParentAuditorLensExecution<'a> {
    lens: &'a ReviewLensConfig,
    lens_index: usize,
    expected_request: &'a ReviewLensRequest,
    required_coverage: &'a ReviewCoverageRequirement,
}

pub(super) fn create_review_lens_scope_workspace() -> Result<tempfile::TempDir> {
    let workspace = tempfile::Builder::new()
        .prefix("maco-review-lens-")
        .tempdir()
        .context("failed to create isolated review-lens workspace")?;
    Repository::init(workspace.path())
        .context("failed to initialize isolated review-lens workspace")?;
    for protected_root in [".maco", ".maco-cache", ".codex", ".agents"] {
        fs::create_dir(workspace.path().join(protected_root)).with_context(|| {
            format!("failed to create isolated review-lens protected root '{protected_root}'")
        })?;
    }
    Ok(workspace)
}

pub(super) fn configure_review_lens_execution_boundary(
    command: ExternalAgentCommand,
    primary_root: &Path,
    child_root: &Path,
) -> Result<ExternalAgentCommand> {
    Ok(configure_read_only_auditor_command(command)?
        .with_hidden_root(primary_root)
        .with_hidden_root(child_root))
}

fn bind_supervisor_machine_global_staging_cleanup(
    command: ExternalAgentCommand,
    options: &SupervisorRunOptions,
) -> Result<ExternalAgentCommand> {
    let binding = options.machine_global_retention.as_ref().context(
        "supervise dispatch requires --machine-global-config and \
         --machine-global-runtime-root-id for private output-staging cleanup",
    )?;
    Ok(command.with_machine_global_retention(binding.clone()))
}

fn prepare_parent_auditor<'a>(
    context: &AssignmentExecutionContext<'a, '_>,
    outcome: &mut AssignmentExecutionOutcome,
    preflight: &AssignmentExecutionPreflight<'_>,
    journal_parent_id: &str,
    child_report: &mut OrchestratorReviewReport,
    auditor_attempt: &mut usize,
    execution: ParentAuditorLensExecution<'_>,
) -> Result<ParentAuditorPreparation<'a>> {
    let ParentAuditorLensExecution {
        lens,
        lens_index,
        expected_request,
        required_coverage,
    } = execution;
    let AssignmentExecutionContext {
        index,
        concurrent_mode,
        plan,
        budget_config,
        options,
        repo,
        run_dir,
        dirs,
        execution_runtime,
        artifacts,
        budget_ledger,
        runtime_model_catalog,
        ..
    } = context;
    let assignment = &preflight.assignment;
    let worktree = &preflight.worktree;
    *auditor_attempt = auditor_attempt.saturating_add(1);
    if let Err(error) = preflight.mandatory_worktree_controls.revalidate() {
        record_isolated_assignment_failure(
            outcome,
            assignment,
            "mandatory worktree control revalidation before auditor",
            &error,
        );
        return Ok(ParentAuditorPreparation::AssignmentComplete);
    }
    let auditor_id = review_lens_auditor_id(assignment, lens_index);
    let auditor_stem = if plan.max_gate_corrections > 0 {
        format!("{auditor_id}.attempt-{auditor_attempt}")
    } else {
        auditor_id.clone()
    };
    let auditor_prompt_path = dirs.assignments.join(format!("{auditor_stem}.prompt.md"));
    let (auditor_incoming_name, auditor_capture_name) =
        invocation_scratch_names(*index, *auditor_attempt, true, *concurrent_mode);
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
        command_record_relative: PathBuf::from("logs").join(format!("{auditor_stem}.summary.json")),
    };
    let auditor_schema_path = dirs.schemas.join("auditor-report.schema.json");
    let RenderedPromptWithMeasurements {
        prompt: auditor_prompt,
        mut measurements,
    } = render_review_lens_auditor_prompt(
        ReviewLensAuditorPromptContext {
            assignment,
            lens,
            request: expected_request,
            required_coverage,
        },
        lens_index,
    )?;
    measurements.record_final_launch_prompt_bytes(&auditor_prompt)?;
    let auditor_prompt_relative = dirs.relative(&auditor_prompt_path)?;
    let measurements_relative = prompt_measurements_relative(&auditor_prompt_relative);
    with_supervisor_artifacts(artifacts, |writer, _| {
        write_private_prompt(writer, &auditor_prompt_relative, &auditor_prompt)?;
        write_artifact_json(
            writer,
            &measurements_relative,
            &measurements,
            MAX_SUPERVISOR_PROMPT_BYTES,
            ArtifactFileDisposition::PrivateEvidence,
        )
    })
    .with_context(|| {
        format!(
            "failed to write auditor prompt {}",
            auditor_prompt_path.display()
        )
    })?;

    let scope_workspace = create_review_lens_scope_workspace()?;
    let mut auditor_command = ExternalAgentCommand::codex(
        &options.codex_bin,
        scope_workspace.path(),
        &auditor_prompt_path,
        &auditor_log_path,
        &auditor_report_path,
        Duration::from_secs(plan.child_timeout_seconds),
    );
    auditor_command = apply_review_lens_model_selection(
        auditor_command,
        lens,
        options.runtime,
        runtime_model_catalog,
    )?;
    auditor_command.output_schema = Some(auditor_schema_path);
    auditor_command =
        configure_review_lens_execution_boundary(auditor_command, repo, &worktree.path)?
            .with_agent_lifecycle(
                repo,
                AgentRole::Auditor.as_str(),
                options.run_id.as_str(),
                &auditor_id,
            );
    auditor_command = bind_supervisor_machine_global_staging_cleanup(auditor_command, options)?;
    auditor_command = apply_canonical_environment_requirements(
        auditor_command,
        &preflight.environment_requirements,
    );

    let primary_before_auditor = primary_worktree_snapshot(repo, *execution_runtime)?;
    if let Some(error) = primary_before_auditor.inspection_problem() {
        bail!(
            "refusing to launch parent review auditor without a complete primary integrity snapshot: {error}"
        );
    }
    let (auditor_incoming_scratch, auditor_capture_scratch) =
        with_supervisor_artifacts(artifacts, |writer, _| {
            create_named_invocation_scratches(writer, &auditor_incoming_name, &auditor_capture_name)
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
                return Err(error).context("failed to bind parent auditor incoming scratch root");
            }
        };
    let auditor_capture_root = match SecureOutputRoot::open_private(auditor_capture_scratch.path())
    {
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
            return Err(error).context("failed to bind parent auditor capture scratch root");
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
    let auditor_budget_reservation = match reserve_dispatch_budget(
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
            let verdict = ReviewLensVerdict::for_lens(
                lens,
                expected_request.request_binding.clone(),
                ReviewLensVerdictStatus::ProceduralFailure,
                ReviewLensCoverage::default(),
                Vec::new(),
            )?;
            return Ok(ParentAuditorPreparation::GateComplete { verdict });
        }
    };
    Ok(ParentAuditorPreparation::Ready(PreparedParentAuditor {
        lens: lens.clone(),
        expected_request: expected_request.clone(),
        auditor_id,
        auditor_artifacts,
        auditor_command,
        primary_before_auditor,
        auditor_incoming_scratch,
        auditor_capture_scratch,
        auditor_incoming_root,
        auditor_capture_root,
        auditor_budget_reservation,
        scope_workspace,
    }))
}

struct ParentAuditorCollection {
    containment_verified: bool,
    primary_integrity_failed: bool,
    sandbox_denied: bool,
    environment_blocked: bool,
    verdict: ReviewLensVerdict,
}

fn dispatch_and_collect_parent_auditor(
    context: &AssignmentExecutionContext<'_, '_>,
    outcome: &mut AssignmentExecutionOutcome,
    preflight: &AssignmentExecutionPreflight<'_>,
    journal_parent_id: &str,
    auditor_attempt: usize,
    child_report: &mut OrchestratorReviewReport,
    prepared: PreparedParentAuditor<'_>,
) -> Result<ParentAuditorCollection> {
    let AssignmentExecutionContext {
        options,
        repo,
        execution_runtime,
        artifacts,
        cancellation,
        external_runner,
        ..
    } = context;
    let assignment = &preflight.assignment;
    let PreparedParentAuditor {
        lens,
        expected_request,
        auditor_id,
        auditor_artifacts,
        auditor_command,
        primary_before_auditor,
        auditor_incoming_scratch,
        auditor_capture_scratch,
        auditor_incoming_root,
        auditor_capture_root,
        mut auditor_budget_reservation,
        scope_workspace: _scope_workspace,
    } = prepared;
    record_shared_orchestration_event(
        artifacts,
        &auditor_id,
        Some(&assignment.id),
        OrchestrationRole::Auditor,
        OrchestrationEventKind::Spawn,
        json!({
            "attempt": auditor_attempt,
            "review_lens_id": lens.id,
            "backend_id": lens.backend.backend_id(),
            "model": lens.backend.model(),
            "reasoning_effort": lens.backend.reasoning_effort(),
            "information_scope": lens.information_scope,
            "request_binding": expected_request.request_binding,
        }),
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
            deterministic_fake_auditor_run(&auditor_command, &auditor_id, assignment, child_report)
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
            return Err(error).context("failed to produce deterministic parent auditor output");
        }
    };
    let auditor_environment_blocked = auditor_run.environment_blocked();
    outcome
        .gate_denials
        .extend(auditor_run.gate_denials().iter().cloned());
    let usage_settlement =
        auditor_budget_reservation.settle(&auditor_run, options.runtime, &auditor_command)?;
    match usage_settlement.reliable_usage() {
        Some(usage) => outcome.usage_samples.push(RoleUsageSample {
            role: AgentRole::Auditor,
            lens_id: Some(lens.id.clone()),
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
    let auditor_containment_verified = external_containment_verified(&auditor_run, options.runtime);
    if !auditor_containment_verified {
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
    let auditor_sandbox_denied =
        !auditor_environment_blocked && !auditor_sandbox_denials.is_empty();
    if auditor_sandbox_denied {
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
    let auditor_command_record = command_record_from_external(&auditor_run, &auditor_command);
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
        &auditor_id,
        &auditor_artifacts.raw_report_relative,
        &auditor_run,
        &auditor_command,
    );
    let auditor_primary_integrity_failed = !primary_auditor_changes.is_empty();
    if auditor_primary_integrity_failed {
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
    let verdict = review_lens_verdict_from_auditor(
        &lens,
        &expected_request,
        &auditor_id,
        &auditor_report,
        !auditor_containment_verified
            || auditor_primary_integrity_failed
            || auditor_sandbox_denied
            || auditor_environment_blocked,
    )?;
    child_report.audit_reports.push(auditor_report);
    enforce_orchestrator_environment_failure_outcome(child_report);
    Ok(ParentAuditorCollection {
        containment_verified: auditor_containment_verified,
        primary_integrity_failed: auditor_primary_integrity_failed,
        sandbox_denied: auditor_sandbox_denied,
        environment_blocked: auditor_environment_blocked,
        verdict,
    })
}

#[allow(clippy::large_enum_variant)]
enum ParentAuditorGateDisposition {
    Retry,
    Complete {
        report: OrchestratorReviewReport,
        candidate: Option<SupervisorCandidateInspection>,
        containment_verified: bool,
    },
}

fn parent_auditor_repair_eligible(
    parent_auditor_failed: bool,
    assignment_containment_verified: bool,
    auditor_primary_integrity_failed: bool,
    auditor_sandbox_denied: bool,
    auditor_environment_blocked: bool,
) -> bool {
    parent_auditor_failed
        && assignment_containment_verified
        && !auditor_primary_integrity_failed
        && !auditor_sandbox_denied
        && !auditor_environment_blocked
}

#[allow(clippy::too_many_arguments)]
fn decide_parent_auditor_gate(
    context: &AssignmentExecutionContext<'_, '_>,
    outcome: &mut AssignmentExecutionOutcome,
    preflight: &AssignmentExecutionPreflight<'_>,
    journal_parent_id: &str,
    final_report_path: &Path,
    child_containment_verified: bool,
    assignment_containment_verified: bool,
    auditor_primary_integrity_failed: bool,
    auditor_sandbox_denied: bool,
    auditor_environment_blocked: bool,
    pre_auditor_candidate: Option<SupervisorCandidateInspection>,
    mut child_report: OrchestratorReviewReport,
    retry_feedback: &mut Option<ChildAttemptCorrection>,
) -> Result<ParentAuditorGateDisposition> {
    let AssignmentExecutionContext {
        repo, artifacts, ..
    } = context;
    let assignment = &preflight.assignment;
    if child_containment_verified
        && child_report.environment_failures.is_empty()
        && !auditor_environment_blocked
        && child_report.review_lens_aggregate.is_none()
    {
        validate_auditor_reports(assignment, final_report_path, &mut child_report);
    }
    let parent_auditor_failed = child_report
        .review_lens_aggregate
        .as_ref()
        .map(|aggregate| aggregate.decision != ReviewAggregationDecision::Accept)
        .unwrap_or_else(|| {
            child_report
                .audit_reports
                .iter()
                .any(|report| report.id == parent_auditor_id(assignment) && report_failed(report))
        });
    if parent_auditor_repair_eligible(
        parent_auditor_failed,
        assignment_containment_verified,
        auditor_primary_integrity_failed,
        auditor_sandbox_denied,
        auditor_environment_blocked,
    ) && child_report.gate_denials.is_empty()
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
            *retry_feedback = Some(ChildAttemptCorrection::Gate(authorized_denial));
            return Ok(ParentAuditorGateDisposition::Retry);
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
            inspect_supervisor_candidate(repo, assignment, &preflight.worktree_write_lease);
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
                    final_report_path,
                    &error,
                );
            }
            (Some(_), Err(error)) if !child_report.decomposition_completions.is_empty() => {
                let error = anyhow!(
                    "failed to recapture decomposition candidate after parent auditor review: {error:#}"
                );
                reject_supervisor_decomposition_binding(
                    &mut child_report,
                    final_report_path,
                    &error,
                );
            }
            (None, _) if !child_report.decomposition_completions.is_empty() => {
                let error = anyhow!(
                    "accepted decomposition evidence has no pre-auditor supervisor candidate binding"
                );
                reject_supervisor_decomposition_binding(
                    &mut child_report,
                    final_report_path,
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
                        final_report_path,
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
    Ok(ParentAuditorGateDisposition::Complete {
        report: child_report,
        candidate: traceability_candidate,
        containment_verified: assignment_containment_verified,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FinalReportFailureFlags {
    assignment_failed: bool,
    auditor_failed: bool,
    worker_failed: bool,
}

fn final_report_failure_flags(
    assignment_succeeded: bool,
    auditor_failed: bool,
    worker_failed: bool,
) -> FinalReportFailureFlags {
    FinalReportFailureFlags {
        assignment_failed: !assignment_succeeded,
        auditor_failed,
        worker_failed,
    }
}

#[allow(clippy::too_many_arguments)]
fn publish_assignment_report(
    context: &AssignmentExecutionContext<'_, '_>,
    outcome: &mut AssignmentExecutionOutcome,
    preflight: &AssignmentExecutionPreflight<'_>,
    journal_parent_id: &str,
    final_report_relative: &Path,
    final_report_path: &Path,
    child_report: OrchestratorReviewReport,
    completed_candidate_inspection: Option<SupervisorCandidateInspection>,
    completed_assignment_containment: bool,
) -> Result<()> {
    let assignment = &preflight.assignment;
    outcome.candidate_inspection = completed_candidate_inspection;
    with_supervisor_artifacts(context.artifacts, |writer, journal| {
        write_child_report(writer, final_report_relative, &child_report)?;
        record_final_report_decisions(journal, writer, journal_parent_id, &child_report);
        Ok(())
    })?;
    let failure_flags = final_report_failure_flags(
        child_report.status == ReviewStatus::Succeeded,
        child_report
            .review_lens_aggregate
            .as_ref()
            .map(|aggregate| aggregate.decision != ReviewAggregationDecision::Accept)
            .unwrap_or_else(|| child_report.audit_reports.iter().any(report_failed)),
        child_report.worker_reports.iter().any(report_failed),
    );
    if failure_flags.assignment_failed {
        outcome.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: format!("child orchestrator '{}' failed", assignment.id),
            paths: vec![final_report_path.to_path_buf()],
        });
    }
    if failure_flags.auditor_failed {
        outcome.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: format!(
                "child orchestrator '{}' failed enforced parent review auditor gate",
                assignment.id
            ),
            paths: vec![final_report_path.to_path_buf()],
        });
    }
    if failure_flags.worker_failed {
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

fn execute_supervisor_assignment_inner(
    context: &AssignmentExecutionContext<'_, '_>,
    outcome: &mut AssignmentExecutionOutcome,
) -> Result<()> {
    let AssignmentExecutionContext {
        plan,
        options,
        repo,
        run_dir,
        dirs,
        artifacts,
        runtime_model_catalog,
        ..
    } = context;
    let preflight = match prepare_assignment_execution(context, outcome)? {
        AssignmentExecutionDisposition::Continue(preflight) => preflight,
        AssignmentExecutionDisposition::Complete => return Ok(()),
    };
    let journal_parent_id = preflight.journal_parent_id;
    let assignment = &preflight.assignment;
    let worktree_write_lease = &preflight.worktree_write_lease;
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
            let prepared = match prepare_child_attempt(
                context,
                outcome,
                &preflight,
                journal_parent_id,
                attempt,
                max_attempts,
                &retry_feedback,
                &schema_path,
                &worker_schema_path,
                &auditor_schema_path,
            )? {
                AssignmentExecutionDisposition::Continue(prepared) => prepared,
                AssignmentExecutionDisposition::Complete => return Ok(()),
            };
            let collected = dispatch_and_collect_child_attempt(
                context,
                outcome,
                &preflight,
                journal_parent_id,
                attempt,
                prepared,
            )?;
            match decide_child_attempt(
                context,
                outcome,
                &preflight,
                journal_parent_id,
                attempt,
                &mut structural_attempt,
                &mut retry_feedback,
                &mut attempt_history,
                collected,
            )? {
                ChildAttemptDisposition::Retry => continue,
                ChildAttemptDisposition::Finish {
                    report,
                    containment_verified,
                    gate_terminal,
                } => {
                    child_report = Some(report);
                    child_containment_verified = containment_verified;
                    child_gate_terminal = gate_terminal;
                    break;
                }
            }
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
                worktree_write_lease,
            ) {
                Ok(Some(inspection)) => Some(inspection),
                Ok(None) if !report_failed(&child_report) => {
                    inspect_supervisor_candidate(repo, assignment, worktree_write_lease).ok()
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
            let transcript_path = attempt_history
                .last()
                .map(|history| run_dir.join(&history.raw_stdout_path))
                .context("successful child attempt has no retained transcript evidence")?;
            let transcript_probe_limit = REVIEW_LENS_REQUEST_LIMIT_BYTES
                .checked_add(1)
                .context("review-lens transcript probe limit overflowed")?;
            let child_transcript_bytes =
                read_bounded_regular_file_nofollow(&transcript_path, transcript_probe_limit)
                    .with_context(|| {
                        format!(
                            "failed to read bounded child transcript {}",
                            transcript_path.display()
                        )
                    })?;
            if child_transcript_bytes.len() > REVIEW_LENS_REQUEST_LIMIT_BYTES {
                bail!(
                    "child transcript exceeds its {} byte review-lens input limit",
                    REVIEW_LENS_REQUEST_LIMIT_BYTES
                );
            }
            let child_transcript = String::from_utf8(child_transcript_bytes)
                .context("child transcript evidence is not valid UTF-8")?;
            let diff = collect_diff_since_base(
                &preflight.worktree.path,
                &preflight.child_base_head,
                REVIEW_LENS_REQUEST_LIMIT_BYTES,
            )?;
            let output_report = serde_json::to_string(&child_report)
                .context("failed to serialize child output report for review lenses")?;
            let sources = ReviewLensRequestSources {
                child_transcript: &child_transcript,
                diff: &diff,
                output_report: &output_report,
            };
            let required_coverage =
                supervisor_review_coverage_requirement(assignment, &child_report);
            let mut expected_requests = Vec::with_capacity(plan.review_lenses.len());
            let mut verdicts = Vec::with_capacity(plan.review_lenses.len());
            for (lens_index, lens) in plan.review_lenses.iter().enumerate() {
                let expected_request = build_review_lens_request(lens, sources)?;
                if let Err(error) = validate_review_lens_runtime_selection(
                    lens,
                    options.runtime,
                    runtime_model_catalog,
                ) {
                    child_report.findings.push(Finding {
                        severity: FindingSeverity::Error,
                        message: format!(
                            "review lens '{}' could not be dispatched with its configured runtime selection: {error:#}",
                            lens.id
                        ),
                        paths: assignment.assigned_paths.clone(),
                    });
                    verdicts.push(ReviewLensVerdict::for_lens(
                        lens,
                        expected_request.request_binding.clone(),
                        ReviewLensVerdictStatus::ProceduralFailure,
                        ReviewLensCoverage::default(),
                        Vec::new(),
                    )?);
                    expected_requests.push(expected_request);
                    continue;
                }
                let prepared_auditor = match prepare_parent_auditor(
                    context,
                    outcome,
                    &preflight,
                    journal_parent_id,
                    &mut child_report,
                    &mut auditor_attempt,
                    ParentAuditorLensExecution {
                        lens,
                        lens_index,
                        expected_request: &expected_request,
                        required_coverage: &required_coverage,
                    },
                )? {
                    ParentAuditorPreparation::Ready(prepared) => prepared,
                    ParentAuditorPreparation::AssignmentComplete => return Ok(()),
                    ParentAuditorPreparation::GateComplete { verdict } => {
                        expected_requests.push(expected_request);
                        verdicts.push(verdict);
                        for remaining_lens in plan.review_lenses.iter().skip(lens_index + 1) {
                            let remaining_request =
                                build_review_lens_request(remaining_lens, sources)?;
                            verdicts.push(ReviewLensVerdict::for_lens(
                                remaining_lens,
                                remaining_request.request_binding.clone(),
                                ReviewLensVerdictStatus::ProceduralFailure,
                                ReviewLensCoverage::default(),
                                Vec::new(),
                            )?);
                            expected_requests.push(remaining_request);
                        }
                        break;
                    }
                };
                let auditor_collection = dispatch_and_collect_parent_auditor(
                    context,
                    outcome,
                    &preflight,
                    journal_parent_id,
                    auditor_attempt,
                    &mut child_report,
                    prepared_auditor,
                )?;
                assignment_containment_verified &= auditor_collection.containment_verified;
                auditor_primary_integrity_failed |= auditor_collection.primary_integrity_failed;
                auditor_sandbox_denied |= auditor_collection.sandbox_denied;
                auditor_environment_blocked |= auditor_collection.environment_blocked;
                expected_requests.push(expected_request);
                verdicts.push(auditor_collection.verdict);
            }
            let aggregate = aggregate_review_lenses_against_requests(
                &plan.review_lenses,
                &expected_requests,
                plan.review_aggregation_policy,
                required_coverage,
                verdicts,
            )?;
            with_supervisor_artifacts(artifacts, |writer, journal| {
                record_gate_correction_event_strict(
                    journal,
                    writer,
                    &assignment.id,
                    Some(journal_parent_id),
                    OrchestrationRole::Auditor,
                    json!({"review_lens_aggregate": &aggregate}),
                )
            })?;
            if aggregate.decision != ReviewAggregationDecision::Accept {
                child_report.status = ReviewStatus::Failed;
                child_report.accepted = false;
                child_report.rejected = true;
                child_report.findings.push(Finding {
                    severity: FindingSeverity::Error,
                    message: format!(
                        "stacked review-lens gate did not accept: {:?}",
                        aggregate.decision
                    ),
                    paths: assignment.assigned_paths.clone(),
                });
            }
            child_report.review_lens_aggregate = Some(aggregate);
        }
        match decide_parent_auditor_gate(
            context,
            outcome,
            &preflight,
            journal_parent_id,
            &final_report_path,
            child_containment_verified,
            assignment_containment_verified,
            auditor_primary_integrity_failed,
            auditor_sandbox_denied,
            auditor_environment_blocked,
            pre_auditor_candidate,
            child_report,
            &mut retry_feedback,
        )? {
            ParentAuditorGateDisposition::Retry => continue 'gate_controller,
            ParentAuditorGateDisposition::Complete {
                report,
                candidate,
                containment_verified,
            } => {
                break 'gate_controller (report, candidate, containment_verified);
            }
        }
    };
    publish_assignment_report(
        context,
        outcome,
        &preflight,
        journal_parent_id,
        &final_report_relative,
        &final_report_path,
        child_report,
        completed_candidate_inspection,
        completed_assignment_containment,
    )
}

#[cfg(test)]
mod decomposition_tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use crate::external_agent::run_external_agent_nonpublishable_simulation;
    #[cfg(target_os = "linux")]
    use crate::machine_global::{GateOutcome, MachineGlobalStore};
    use git2::Signature;
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(target_os = "linux")]
    use std::time::Instant;

    fn commit_fixture_repository(path: &Path) {
        let repo = Repository::open(path).expect("open fixture repository");
        let mut index = repo.index().expect("open fixture index");
        index
            .add_path(Path::new("README.md"))
            .expect("stage fixture file");
        index.write().expect("write fixture index");
        let tree_id = index.write_tree().expect("write fixture tree");
        let tree = repo.find_tree(tree_id).expect("find fixture tree");
        let signature =
            Signature::now("maco test", "maco-test@example.invalid").expect("fixture signature");
        repo.commit(Some("HEAD"), &signature, &signature, "baseline", &tree, &[])
            .expect("commit fixture baseline");
    }

    fn unused_external_runner(
        _command: &ExternalAgentCommand,
        _cancellation: &ProcessCancellation,
        _review: Option<ExternalPreActionReviewRuntime<'_>>,
    ) -> ExternalAgentRun {
        panic!("fake-runtime phase fixture must not invoke the external runner")
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn review_lens_execution_boundary_hides_primary_and_child_roots_from_hostile_process(
    ) -> Result<()> {
        const CHILD_ENV: &str = "MACO_TEST_REVIEW_LENS_BOUNDARY_CHILD";
        const PRIMARY_SECRET_ENV: &str = "MACO_TEST_REVIEW_LENS_PRIMARY_SECRET";
        const CHILD_SECRET_ENV: &str = "MACO_TEST_REVIEW_LENS_CHILD_SECRET";

        if std::env::var_os(CHILD_ENV).is_some() {
            for environment_name in [PRIMARY_SECRET_ENV, CHILD_SECRET_ENV] {
                let secret = PathBuf::from(
                    std::env::var_os(environment_name)
                        .with_context(|| format!("missing hostile probe {environment_name}"))?,
                );
                assert!(
                    fs::read_to_string(&secret).is_err(),
                    "review lens process read hidden root {}",
                    secret.display()
                );
            }
            return Ok(());
        }

        let test_binary = std::env::current_exe()?;
        let test_output_root = test_binary
            .parent()
            .and_then(Path::parent)
            .context("test binary omitted its target output root")?;
        let temp = tempfile::tempdir_in(test_output_root)?;
        let primary_root = temp.path().join("primary");
        let child_root = temp.path().join("child");
        for root in [&primary_root, &child_root] {
            fs::create_dir(root)?;
        }
        let primary_secret = primary_root.join("primary-secret.txt");
        let child_secret = child_root.join("child-secret.txt");
        fs::write(&primary_secret, "PRIMARY_SECRET_MUST_BE_HIDDEN\n")?;
        fs::write(&child_secret, "CHILD_SECRET_MUST_BE_HIDDEN\n")?;

        let scope_workspace = create_review_lens_scope_workspace()?;
        let prompt = scope_workspace.path().join("prompt.md");
        fs::write(&prompt, "Attempt hostile access to omitted lens inputs.\n")?;
        let command = ExternalAgentCommand::codex(
            "codex",
            scope_workspace.path(),
            &prompt,
            scope_workspace.path().join("events.jsonl"),
            scope_workspace.path().join("report.json"),
            Duration::from_secs(10),
        );
        let command =
            configure_review_lens_execution_boundary(command, &primary_root, &child_root)?;

        let mut profile = crate::process_runner::ExternalCodexProfile::read_only(&command.cwd);
        for hidden_root in &command.hidden_roots {
            profile = profile.with_hidden_root(hidden_root);
        }
        let environment = BTreeMap::from([
            (CHILD_ENV.to_string(), "1".to_string()),
            (
                PRIMARY_SECRET_ENV.to_string(),
                primary_secret.display().to_string(),
            ),
            (
                CHILD_SECRET_ENV.to_string(),
                child_secret.display().to_string(),
            ),
        ]);
        let output = match run_process(
            ProcessSpec::direct(
                "review lens hostile hidden-root probe",
                std::env::current_exe()?,
                [
                    OsStr::new("--exact"),
                    OsStr::new(
                        "supervise::assignment_execution::decomposition_tests::review_lens_execution_boundary_hides_primary_and_child_roots_from_hostile_process",
                    ),
                ],
                &command.cwd,
                4 * 1024,
            )
            .with_environment(EnvironmentMode::InheritAndSet(environment))
            .with_stdin(StdinMode::Null)
            .with_timeout(Some(Duration::from_secs(30)))
            .with_side_effect_confinement(SideEffectConfinementProfile::ExternalCodex(profile)),
        ) {
            Ok(output) => output,
            Err(error)
                if matches!(
                    error,
                    crate::process_runner::ProcessRunError::ProcessOwnership { .. }
                ) && [
                    "inaccessible path remained",
                    "inaccessible path placeholder",
                    "could not inspect inaccessible-path",
                ]
                .iter()
                .any(|diagnostic| error.to_string().contains(diagnostic)) =>
            {
                eprintln!("strict sandbox unavailable; hostile lens boundary probe did not launch");
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };

        assert!(
            output.status.is_some_and(|status| status.success()),
            "hostile boundary process failed: {output:#?}"
        );
        assert!(output.safety_evidence_verified());
        assert_eq!(
            fs::read_to_string(primary_secret)?,
            "PRIMARY_SECRET_MUST_BE_HIDDEN\n"
        );
        assert_eq!(
            fs::read_to_string(child_secret)?,
            "CHILD_SECRET_MUST_BE_HIDDEN\n"
        );
        Ok(())
    }

    #[test]
    fn extracted_assignment_units_are_directly_exercised_in_phase_order() {
        let temp = tempfile::tempdir().expect("temporary phase fixture");
        let repo = temp.path().join("repo");
        Repository::init(&repo).expect("initialize phase fixture repository");
        fs::write(repo.join("README.md"), "baseline\n").expect("write fixture file");
        commit_fixture_repository(&repo);

        let assignment = OrchestratorAssignment {
            id: "phase-child".to_string(),
            role: AgentRole::ChildOrchestrator,
            assigned_paths: vec![PathBuf::from("README.md")],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            task: None,
            worker_assignments: Vec::new(),
            environment_requirements: Vec::new(),
            notes: None,
        };
        let plan = SupervisorPlan {
            version: SUPERVISOR_SCHEMA_VERSION,
            task: "direct phase exercise".to_string(),
            task_file: None,
            max_depth: 2,
            max_child_assignments: 1,
            max_child_retries: 0,
            max_gate_corrections: 0,
            child_timeout_seconds: 10,
            semantic_coordination: SemanticCoordinationMode::Off,
            role_models: BTreeMap::new(),
            model_pricing: BTreeMap::new(),
            review_lenses: default_supervisor_review_lenses(),
            review_aggregation_policy: ReviewAggregationPolicy::AllMustAccept,
            assignments: vec![assignment.clone()],
        };
        let budget_config = SupervisorBudgetConfig::default();
        let consultant = SupervisorConsultantPlan::default();
        let assignment_metadata = AssignmentMetadata::new();
        let options = SupervisorRunOptions {
            repo: repo.clone(),
            plan_file: temp.path().join("plan.json"),
            run_id: RunId::new("direct-assignment-phases").expect("valid fixture run id"),
            codex_bin: PathBuf::from("unused-codex"),
            runtime: SupervisorRuntime::Fake,
            allow_dirty_primary: false,
            machine_global_retention: Some(crate::machine_global::MachineGlobalRetentionBinding {
                config: temp.path().join("unused-machine-global.json"),
                root_id: "runtime".to_string(),
                owner: "maco-supervise".to_string(),
                correction_correlation_id: "direct-assignment-phases".to_string(),
            }),
        };
        let mut artifact_writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            options.run_id.clone(),
            "assignment-phase-test",
        )
        .expect("reserve phase artifacts");
        let run_dir = artifact_writer.run_dir().to_path_buf();
        let dirs = RunDirs::for_writer(&artifact_writer);
        let manager = WorktreeManager::new(&repo);
        let sync_store = SyncStore::open(&repo).expect("open fixture sync store");
        let semantic_store = SemanticIntentStore::open(&repo).expect("open fixture semantic store");
        let assignment_schedule = vec![AssignmentScheduleEntry {
            assignment_id: assignment.id.clone(),
            parent_assignment_id: None,
            depth: 1,
            flattened_index: 0,
        }];
        let field_guide = SupervisorFieldGuidePrompt::empty().expect("empty fixture field guide");
        let budget_ledger =
            RunBudgetLedger::new(RunBudgetLimits::default()).expect("fixture budget ledger");
        let runtime_model_catalog = RuntimeModelCatalog::LocalDeterministicFake;
        let cancellation = ProcessCancellation::new();
        let mut journal = initialize_orchestration_event_journal(&repo, &options.run_id);
        let artifacts = Mutex::new(SharedSupervisorArtifacts {
            writer: &mut artifact_writer,
            journal: &mut journal,
        });
        let runner = unused_external_runner;
        let context = AssignmentExecutionContext {
            index: 0,
            concurrent_mode: false,
            plan: &plan,
            budget_config: &budget_config,
            consultant: &consultant,
            assignment_metadata: &assignment_metadata,
            assignment: &assignment,
            options: &options,
            repo: &repo,
            run_dir: &run_dir,
            dirs: &dirs,
            execution_runtime: SupervisorExecutionRuntime::NonpublishableSimulation,
            worktree_creation: SupervisorWorktreeCreation::TestOnly,
            manager: &manager,
            reused: false,
            sync_store: &sync_store,
            semantic_store: &semantic_store,
            prepared_semantic_token: None,
            prepared_semantic_findings: &[],
            prepared_semantic_signals: &[],
            prepared_semantic_failed: false,
            assignment_schedule: &assignment_schedule,
            field_guide: &field_guide,
            serial_semantic_warn_intents: None,
            semantic_block_order: None,
            semantic_block_gate: None,
            artifacts: &artifacts,
            budget_ledger: &budget_ledger,
            runtime_model_catalog: &runtime_model_catalog,
            cancellation,
            external_runner: &runner,
        };
        let mut outcome = AssignmentExecutionOutcome {
            gate_tracker: Some(GateCorrectionTracker::new(plan.max_gate_corrections)),
            ..AssignmentExecutionOutcome::default()
        };
        let preflight = match prepare_assignment_execution(&context, &mut outcome)
            .expect("direct preflight invocation")
        {
            AssignmentExecutionDisposition::Continue(preflight) => preflight,
            AssignmentExecutionDisposition::Complete => panic!("preflight unexpectedly completed"),
        };
        assert_eq!(preflight.claim.agent_id, assignment.id);
        assert_eq!(outcome.claim_tokens, vec![preflight.claim.token]);

        let schema_path = dirs.schemas.join("orchestrator-review-report.schema.json");
        let worker_schema_path = dirs.schemas.join("worker-report.schema.json");
        let auditor_schema_path = dirs.schemas.join("auditor-report.schema.json");
        let prepared = match prepare_child_attempt(
            &context,
            &mut outcome,
            &preflight,
            options.run_id.as_str(),
            1,
            1,
            &None,
            &schema_path,
            &worker_schema_path,
            &auditor_schema_path,
        )
        .expect("direct child preparation invocation")
        {
            AssignmentExecutionDisposition::Continue(prepared) => prepared,
            AssignmentExecutionDisposition::Complete => {
                panic!("child preparation unexpectedly completed")
            }
        };
        assert!(prepared.attempt_artifacts.prompt_path.exists());
        assert!(!prepared.corrective_retry_used);
        assert_eq!(
            prepared.command.machine_global_retention,
            options.machine_global_retention
        );
        let collected = dispatch_and_collect_child_attempt(
            &context,
            &mut outcome,
            &preflight,
            options.run_id.as_str(),
            1,
            prepared,
        )
        .expect("direct child dispatch invocation");
        assert!(collected.attempt_containment_verified);
        assert_eq!(outcome.command_records.len(), 1);

        let mut structural_attempt = 1;
        let mut retry_feedback = None;
        let mut attempt_history = Vec::new();
        let mut child_report = match decide_child_attempt(
            &context,
            &mut outcome,
            &preflight,
            options.run_id.as_str(),
            1,
            &mut structural_attempt,
            &mut retry_feedback,
            &mut attempt_history,
            collected,
        )
        .expect("direct child gate invocation")
        {
            ChildAttemptDisposition::Finish {
                report,
                containment_verified,
                gate_terminal,
            } => {
                assert!(containment_verified);
                assert!(!gate_terminal);
                report
            }
            ChildAttemptDisposition::Retry => panic!("child gate unexpectedly retried"),
        };
        assert_eq!(attempt_history.len(), 1);

        let final_report_relative = PathBuf::from("reports").join("phase-child.json");
        let final_report_path = dirs.reports.join("phase-child.json");
        with_supervisor_artifacts(&artifacts, |writer, _| {
            write_child_report(writer, &final_report_relative, &child_report)
        })
        .expect("write interim child report");
        let mut auditor_attempt = 0;
        let lens = plan.review_lenses[0].clone();
        let output_report = serde_json::to_string(&child_report).expect("serialize child report");
        let expected_request = build_review_lens_request(
            &lens,
            ReviewLensRequestSources {
                child_transcript: "direct phase transcript",
                diff: "direct phase diff",
                output_report: &output_report,
            },
        )
        .expect("build direct phase review request");
        let required_coverage = ReviewCoverageRequirement {
            worker_ids: assignment
                .worker_assignments
                .iter()
                .map(|worker| worker.id.clone())
                .collect(),
            paths: assignment.assigned_paths.clone(),
        };
        let prepared_auditor = match prepare_parent_auditor(
            &context,
            &mut outcome,
            &preflight,
            options.run_id.as_str(),
            &mut child_report,
            &mut auditor_attempt,
            ParentAuditorLensExecution {
                lens: &lens,
                lens_index: 0,
                expected_request: &expected_request,
                required_coverage: &required_coverage,
            },
        )
        .expect("direct auditor preparation invocation")
        {
            ParentAuditorPreparation::Ready(prepared) => prepared,
            ParentAuditorPreparation::AssignmentComplete => {
                panic!("auditor preparation unexpectedly completed assignment")
            }
            ParentAuditorPreparation::GateComplete { .. } => {
                panic!("auditor preparation unexpectedly terminalized gate")
            }
        };
        assert_eq!(auditor_attempt, 1);
        assert!(prepared_auditor.auditor_artifacts.prompt_path.exists());
        assert_eq!(
            prepared_auditor.auditor_command.machine_global_retention,
            options.machine_global_retention
        );
        let auditor_collection = dispatch_and_collect_parent_auditor(
            &context,
            &mut outcome,
            &preflight,
            options.run_id.as_str(),
            auditor_attempt,
            &mut child_report,
            prepared_auditor,
        )
        .expect("direct auditor dispatch invocation");
        assert!(auditor_collection.containment_verified);
        assert_eq!(child_report.audit_reports.len(), 1);

        let (child_report, candidate, containment_verified) = match decide_parent_auditor_gate(
            &context,
            &mut outcome,
            &preflight,
            options.run_id.as_str(),
            &final_report_path,
            true,
            auditor_collection.containment_verified,
            auditor_collection.primary_integrity_failed,
            auditor_collection.sandbox_denied,
            auditor_collection.environment_blocked,
            None,
            child_report,
            &mut retry_feedback,
        )
        .expect("direct auditor gate invocation")
        {
            ParentAuditorGateDisposition::Complete {
                report,
                candidate,
                containment_verified,
            } => (report, candidate, containment_verified),
            ParentAuditorGateDisposition::Retry => {
                panic!("auditor gate unexpectedly retried")
            }
        };
        assert!(containment_verified);
        publish_assignment_report(
            &context,
            &mut outcome,
            &preflight,
            options.run_id.as_str(),
            &final_report_relative,
            &final_report_path,
            child_report,
            candidate,
            containment_verified,
        )
        .expect("direct final publication invocation");
        assert!(outcome.report.is_some());
        assert_eq!(outcome.command_records.len(), 2);
        assert!(!outcome.external_containment_failed);
    }

    #[test]
    fn supervise_dispatch_refuses_a_missing_staging_cleanup_binding() {
        let options = SupervisorRunOptions {
            repo: PathBuf::from("/unused/repo"),
            plan_file: PathBuf::from("/unused/plan.json"),
            run_id: RunId::new("missing-machine-global-binding").expect("valid run id"),
            codex_bin: PathBuf::from("unused-codex"),
            runtime: SupervisorRuntime::Codex,
            allow_dirty_primary: false,
            machine_global_retention: None,
        };
        let command = ExternalAgentCommand::codex(
            "unused-codex",
            "/unused/worktree",
            "/unused/prompt.md",
            "/unused/events.jsonl",
            "/unused/report.json",
            Duration::from_secs(1),
        );
        let error = bind_supervisor_machine_global_staging_cleanup(command, &options)
            .expect_err("supervise cleanup must not take the unbound bypass");
        let rendered = error.to_string();
        assert!(rendered.contains("--machine-global-config"));
        assert!(rendered.contains("--machine-global-runtime-root-id"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn supervise_bound_staging_cleanup_refuses_active_claim_and_preserves_content() -> Result<()> {
        let runtime_root = crate::process_runner::trusted_linux_runtime_root()?;
        let temp = tempfile::tempdir()?;
        let workspace = temp.path().join("workspace");
        let state_root = temp.path().join("machine-global-state");
        let output_root = temp.path().join("output");
        for path in [&workspace, &state_root, &output_root] {
            fs::create_dir(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        Repository::init(&workspace)?;
        for protected_root in [".maco", ".maco-cache", ".codex", ".agents"] {
            fs::create_dir(workspace.join(protected_root))?;
        }

        let config = temp.path().join("machine-global.json");
        fs::write(
            &config,
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": 1,
                "state_root": state_root,
                "roots": [{
                    "id": "runtime",
                    "path": runtime_root,
                    "protected_paths": [],
                    "quarantine_grace_seconds": 60
                }]
            }))?,
        )?;
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600))?;

        let ready = temp.path().join("agent-ready");
        let release = temp.path().join("agent-release");
        let marker = format!("issue54-preserved-staging-{}", std::process::id());
        let agent = workspace.join("staging-agent.sh");
        fs::write(
            &agent,
            format!(
                r#"#!/bin/sh
set -eu
report=
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output-last-message" ]; then
    shift
    report=$1
  fi
  shift
done
while IFS= read -r _line; do
  :
done
printf '%s' '{marker}' > "$report"
: > '{}'
while [ ! -e '{}' ]; do
  /run/current-system/sw/bin/sleep 0.01
done
"#,
                ready.display(),
                release.display()
            ),
        )?;
        fs::set_permissions(&agent, fs::Permissions::from_mode(0o755))?;
        let prompt = workspace.join("prompt.md");
        fs::write(&prompt, "exercise supervise staging cleanup\n")?;

        let options = SupervisorRunOptions {
            repo: workspace.clone(),
            plan_file: workspace.join("plan.json"),
            run_id: RunId::new("active-claim-preserves-supervise-staging")?,
            codex_bin: agent.clone(),
            runtime: SupervisorRuntime::Codex,
            allow_dirty_primary: false,
            machine_global_retention: Some(crate::machine_global::MachineGlobalRetentionBinding {
                config: config.clone(),
                root_id: "runtime".to_string(),
                owner: "maco-supervise".to_string(),
                correction_correlation_id: "active-claim-preserves-supervise-staging".to_string(),
            }),
        };
        let command = bind_supervisor_machine_global_staging_cleanup(
            ExternalAgentCommand::codex(
                &agent,
                &workspace,
                &prompt,
                output_root.join("events.jsonl"),
                output_root.join("report.json"),
                Duration::from_secs(10),
            ),
            &options,
        )?;
        assert_eq!(
            command.machine_global_retention,
            options.machine_global_retention
        );

        let worker =
            std::thread::spawn(move || run_external_agent_nonpublishable_simulation(&command));
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() && !worker.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        if !ready.exists() {
            fs::write(&release, b"release failed setup\n")?;
            let report = worker
                .join()
                .unwrap_or_else(|_| panic!("staging agent thread panicked during setup"));
            panic!("staging agent did not reach the claim rendezvous: {report:?}");
        }

        let staging_root = fs::read_dir(&runtime_root)?
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.path())
            .find(|candidate| {
                candidate
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(".maco-external-output-"))
                    && fs::read(candidate.join("last-message.raw"))
                        .is_ok_and(|contents| contents == marker.as_bytes())
            })
            .context("could not locate the supervised runtime staging directory")?;
        let store = MachineGlobalStore::open_config(&config)?;
        let coordinate = store.coordinate_for_existing_directory("runtime", &staging_root)?;
        let claim = match store.claim(
            "repair-agent",
            "repairing-supervise-staging",
            vec![coordinate.clone()],
        )? {
            GateOutcome::Allowed(claim) => claim,
            GateOutcome::Denied(denial) => {
                panic!("fixture repair claim was unexpectedly denied: {denial:?}")
            }
        };
        fs::write(&release, b"release staged agent\n")?;
        let report = worker
            .join()
            .unwrap_or_else(|_| panic!("staging agent thread panicked"));

        assert!(report.machine_global_bypasses().is_empty());
        assert_eq!(report.gate_denials().len(), 1, "{report:?}");
        assert!(matches!(
            &report.gate_denials()[0].reason,
            GateDenialReason::DestructiveTarget { denial }
                if matches!(
                    denial.as_ref(),
                    crate::gate_denial::DestructiveTargetDenial::ActiveClaimIntersection {
                        target,
                        active_claim
                    } if target == &coordinate && active_claim == &coordinate
                )
        ));
        assert!(
            report
                .error
                .as_deref()
                .is_some_and(|error| error
                    .contains("machine-global gate denied private output-staging cleanup")),
            "{report:?}"
        );
        assert_eq!(
            fs::read(staging_root.join("last-message.raw"))?,
            marker.as_bytes()
        );
        assert!(staging_root.exists());
        assert!(store.status()?.retention_operations.is_empty());

        assert!(store.release("repair-agent", claim.token)?);
        fs::remove_file(staging_root.join("last-message.raw"))?;
        fs::remove_dir(staging_root)?;
        Ok(())
    }

    #[test]
    fn child_gate_terminal_reason_preserves_exact_precedence() {
        assert_eq!(
            child_gate_terminal_reason(false, true, true, true, true, true),
            Some(ChildGateTerminalReason::Containment)
        );
        assert_eq!(
            child_gate_terminal_reason(true, true, true, true, true, true),
            Some(ChildGateTerminalReason::Sandbox)
        );
        assert_eq!(
            child_gate_terminal_reason(true, false, true, true, true, true),
            Some(ChildGateTerminalReason::PrimaryIntegrity)
        );
        assert_eq!(
            child_gate_terminal_reason(true, false, false, true, true, true),
            Some(ChildGateTerminalReason::Environment)
        );
        assert_eq!(
            child_gate_terminal_reason(true, false, false, false, true, true),
            Some(ChildGateTerminalReason::PreActionReview)
        );
        assert_eq!(
            child_gate_terminal_reason(true, false, false, false, false, true),
            Some(ChildGateTerminalReason::ExternalSideEffect)
        );
        assert_eq!(
            child_gate_terminal_reason(true, false, false, false, false, false),
            None
        );
    }

    #[test]
    fn latency_and_fallback_denials_are_terminal_child_refusals() {
        for (index, denial) in [
            crate::gate_denial::ApprovalReviewDenial::LatencyBudgetExceeded,
            crate::gate_denial::ApprovalReviewDenial::DuplexFallbackRequired,
        ]
        .into_iter()
        .enumerate()
        {
            let denial = GateDenial::from_approval_review(
                format!("pre-action-refusal-{index}"),
                "child-a",
                denial,
                ["src/lib.rs"],
            )
            .expect("typed pre-action refusal");
            assert!(is_child_pre_action_refusal(&denial));
            assert_eq!(denial.retryability, GateRetryability::NotRetryable);
        }

        let correctable = GateDenial::from_approval_review(
            "pre-action-correctable",
            "child-a",
            crate::gate_denial::ApprovalReviewDenial::SensitiveRead,
            ["private/token.txt"],
        )
        .expect("typed correctable denial");
        assert!(!is_child_pre_action_refusal(&correctable));
        assert_eq!(
            correctable.retryability,
            GateRetryability::RetryAfterCorrection
        );
    }

    #[test]
    fn parent_auditor_repair_requires_every_safety_precondition() {
        assert!(parent_auditor_repair_eligible(
            true, true, false, false, false
        ));
        for blocked in [
            (false, true, false, false, false),
            (true, false, false, false, false),
            (true, true, true, false, false),
            (true, true, false, true, false),
            (true, true, false, false, true),
        ] {
            assert!(!parent_auditor_repair_eligible(
                blocked.0, blocked.1, blocked.2, blocked.3, blocked.4
            ));
        }
    }

    #[test]
    fn final_report_failure_flags_keep_independent_findings() {
        assert_eq!(
            final_report_failure_flags(true, false, false),
            FinalReportFailureFlags {
                assignment_failed: false,
                auditor_failed: false,
                worker_failed: false,
            }
        );
        assert_eq!(
            final_report_failure_flags(false, true, true),
            FinalReportFailureFlags {
                assignment_failed: true,
                auditor_failed: true,
                worker_failed: true,
            }
        );
        assert_eq!(
            final_report_failure_flags(true, true, false),
            FinalReportFailureFlags {
                assignment_failed: false,
                auditor_failed: true,
                worker_failed: false,
            }
        );
    }
}
