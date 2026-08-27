use super::*;

fn live_invocation_started_millis(duration_ms: u64) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(1)
        .max(1);
    now.saturating_sub(duration_ms).max(1)
}

fn record_and_persist_live_invocation(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    observation: LiveInvocationObservation<'_>,
) -> Result<()> {
    let record = record_supervisor_invocation_observation(observation)?;
    with_supervisor_artifacts(artifacts, |writer, _| {
        persist_live_invocation_row(writer, &record)?;
        persist_live_switch_cost_snapshot(writer)
    })
}

fn assignment_launch_runtime(
    assignment: &OrchestratorAssignment,
    options: &SupervisorRunOptions,
    budget_policy: &AssignmentBudgetPolicy,
) -> SupervisorRuntime {
    budget_policy
        .selected_runtime_for(assignment.role)
        .or(assignment.runtime)
        .unwrap_or(options.runtime)
}

fn nested_worker_launch_runtime(
    enclosing_child_runtime: SupervisorRuntime,
    budget_policy: &AssignmentBudgetPolicy,
) -> SupervisorRuntime {
    budget_policy
        .selected_runtime_for(AgentRole::Worker)
        .unwrap_or(enclosing_child_runtime)
}

fn runtime_model_catalog_for_launch(
    catalog: &RuntimeModelCatalog,
    run_runtime: SupervisorRuntime,
    launch_runtime: SupervisorRuntime,
) -> Result<RuntimeModelCatalog> {
    if launch_runtime == run_runtime {
        return Ok(catalog.clone());
    }
    if launch_runtime.is_adapter_subprocess() {
        return Ok(RuntimeModelCatalog::OperatorDeclared);
    }
    bail!(
        "selected runtime '{}' has no authenticated model catalog in a '{}' supervisor run",
        runtime_name(launch_runtime),
        runtime_name(run_runtime)
    )
}

fn selected_runtime_program(
    launch_runtime: SupervisorRuntime,
    options: &SupervisorRunOptions,
) -> PathBuf {
    match launch_runtime {
        SupervisorRuntime::Codex if options.runtime == SupervisorRuntime::Codex => {
            options.codex_bin.clone()
        }
        SupervisorRuntime::Grok
        | SupervisorRuntime::Cursor
        | SupervisorRuntime::ClaudeCode
        | SupervisorRuntime::GeminiCli => {
            crate::runtime_adapter::RuntimeAdapterConfig::from_environment(launch_runtime)
                .binary
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or_else(|| PathBuf::from(launch_runtime.default_binary()))
        }
        SupervisorRuntime::Codex | SupervisorRuntime::Fake => {
            PathBuf::from(launch_runtime.default_binary())
        }
    }
}

fn bind_runtime_output_schema(
    mut command: ExternalAgentCommand,
    runtime: SupervisorRuntime,
    schema_path: &Path,
) -> Result<ExternalAgentCommand> {
    command.output_schema = match runtime {
        SupervisorRuntime::Codex => Some(codex_output_schema_path(schema_path)?),
        SupervisorRuntime::Fake => Some(schema_path.to_path_buf()),
        SupervisorRuntime::Grok
        | SupervisorRuntime::Cursor
        | SupervisorRuntime::ClaudeCode
        | SupervisorRuntime::GeminiCli => None,
    };
    Ok(command)
}

fn codex_output_schema_path(authoritative: &Path) -> Result<PathBuf> {
    let parent = authoritative
        .parent()
        .context("authoritative report schema path has no parent")?;
    let file_name = authoritative
        .file_name()
        .and_then(OsStr::to_str)
        .context("authoritative report schema file name is not UTF-8")?;
    let stem = file_name
        .strip_suffix(".schema.json")
        .context("authoritative report schema must end in .schema.json")?;
    Ok(parent.join(format!("{stem}.codex-output.schema.json")))
}

fn bind_runtime_read_only_schema_files(
    mut command: ExternalAgentCommand,
    runtime: SupervisorRuntime,
    schema_paths: &[&Path],
) -> ExternalAgentCommand {
    if runtime != SupervisorRuntime::Fake {
        for schema_path in schema_paths {
            command = command.with_read_only_input_file((*schema_path).to_path_buf());
        }
    }
    command
}

fn requires_hosted_pre_action_review(command: &ExternalAgentCommand) -> bool {
    command.workspace_access == WorkspaceAccess::ReadOnly
        || command.writable_launch_target
            == crate::runtime_adapter::WritableLaunchTarget::PrimaryWorktree
}

fn configure_assignment_phase_command(
    command: ExternalAgentCommand,
    phase: AssignmentPhase,
    assigned_paths: &[PathBuf],
) -> Result<ExternalAgentCommand> {
    match phase {
        AssignmentPhase::Planning => {
            if !command.worktree_control_exceptions.is_empty() {
                bail!("planning child command may not contain writable control exceptions");
            }
            Ok(command.with_workspace_access(WorkspaceAccess::ReadOnly))
        }
        AssignmentPhase::Execution => configure_writable_child_command(command, assigned_paths),
    }
}

#[cfg(test)]
pub(crate) fn configure_assignment_phase_command_for_test(
    command: ExternalAgentCommand,
    phase: AssignmentPhase,
    assigned_paths: &[PathBuf],
) -> Result<ExternalAgentCommand> {
    configure_assignment_phase_command(command, phase, assigned_paths)
}

fn validated_assignment_phase_for_launch(
    assignment: &OrchestratorAssignment,
    index: usize,
    assignment_schedule: &[AssignmentScheduleEntry],
) -> Result<AssignmentPhase> {
    assignment_schedule
        .get(index)
        .filter(|entry| entry.assignment_id == assignment.id && entry.flattened_index == index)
        .context("assignment launch is not bound to its validated schedule entry")?;
    Ok(assignment.phase)
}

#[allow(clippy::too_many_arguments)]
fn worktree_writable_admission_record(
    assignment_id: &str,
    assigned_paths: &[PathBuf],
    attempt: usize,
    worktree: &WorktreeRecord,
    claim: &PathClaim,
    authenticated_claims: &[PathClaim],
    command: &ExternalAgentCommand,
    runtime: SupervisorRuntime,
    phase: AssignmentPhase,
) -> Result<Option<crate::external_agent::WorktreeWritableAdmission>> {
    if phase == AssignmentPhase::Planning {
        if command.workspace_access != WorkspaceAccess::ReadOnly {
            bail!(
                "planning assignment '{}' attempted to request writable workspace admission",
                assignment_id
            );
        }
        return Ok(None);
    }
    if command.workspace_access == WorkspaceAccess::ReadOnly
        || command.writable_launch_target
            == crate::runtime_adapter::WritableLaunchTarget::PrimaryWorktree
    {
        return Ok(None);
    }
    if command.writable_launch_target
        != crate::runtime_adapter::WritableLaunchTarget::ManagedChildWorktree
    {
        bail!("writable child launch has an unsupported workspace target");
    }
    if worktree.name != assignment_id || command.cwd != worktree.path {
        bail!(
            "writable child launch is not bound to assignment '{}' managed worktree",
            assignment_id
        );
    }
    if claim.agent_id != assignment_id || claim.paths != assigned_paths {
        bail!(
            "writable child launch claim does not exactly bind assignment '{}' paths",
            assignment_id
        );
    }
    if !authenticated_claims.iter().any(|held| held == claim) {
        bail!(
            "writable child launch claim for assignment '{}' is not held in authenticated state",
            assignment_id
        );
    }
    let capabilities = runtime.capabilities();
    if let Some(reason) = capabilities.writable_launch_refusal(command.writable_launch_target) {
        bail!(
            "writable child launch for assignment '{}' lacks verified native sandbox admission: {}",
            assignment_id,
            reason
        );
    }
    if capabilities.side_effect_confinement
        != crate::runtime_adapter::SideEffectConfinement::Verified
    {
        bail!(
            "writable child launch for assignment '{}' lacks verified side-effect confinement",
            assignment_id
        );
    }

    Ok(Some(crate::external_agent::WorktreeWritableAdmission {
        version: crate::external_agent::WORKTREE_WRITABLE_ADMISSION_SCHEMA_VERSION,
        assignment_id: assignment_id.to_string(),
        attempt,
        target: command.writable_launch_target,
        worktree: crate::external_agent::ManagedWorktreeAdmission {
            kind: crate::external_agent::ManagedWorktreeAdmissionKind::ManagedDisposable,
            worktree_id: worktree.name.clone(),
        },
        claims: crate::external_agent::HeldPathClaimsAdmission {
            state: crate::external_agent::HeldPathClaimsAdmissionState::Held,
            token: claim.token.get(),
            paths: claim.paths.clone(),
        },
        native_sandbox: crate::external_agent::NativeSandboxAdmission {
            runtime,
            workspace_access: command.workspace_access,
            side_effect_confinement: capabilities.side_effect_confinement,
        },
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CompletedLaunchModelProvenance {
    launch_runtime: SupervisorRuntime,
    configured_model: Option<String>,
    launched_model: Option<String>,
    resolution_observation: ModelResolutionObservation,
}

impl CompletedLaunchModelProvenance {
    fn from_resolution(
        launch_runtime: SupervisorRuntime,
        configured: &RoleModelSelection,
        resolution: &RoleModelResolution,
    ) -> Self {
        Self {
            launch_runtime,
            configured_model: configured.model.clone(),
            launched_model: resolution.selection.model.clone(),
            resolution_observation: resolution.observation,
        }
    }

    fn transition_subject_model(&self) -> Option<&str> {
        if let Some(model) = self.launched_model.as_deref() {
            return Some(model);
        }
        if self.launch_runtime == SupervisorRuntime::Fake
            && matches!(
                self.resolution_observation,
                ModelResolutionObservation::RuntimeDefault
                    | ModelResolutionObservation::LocalDeterministicFake
            )
        {
            return self.configured_model.as_deref();
        }
        None
    }
}

// Keep the established command-only helper type-checked for its direct policy
// regressions. Attempt publication must use the complete resolution below so
// launch provenance is not recomputed after the command is bound.
const _: fn(
    ExternalAgentCommand,
    &SupervisorPlan,
    AgentRole,
    SupervisorRuntime,
    &RuntimeModelCatalog,
) -> Result<ExternalAgentCommand> = apply_role_model_selection;

struct BoundSelectedRuntimeLaunch {
    command: ExternalAgentCommand,
    model_provenance: CompletedLaunchModelProvenance,
}

fn admit_assignment_role_category(
    assignment: &OrchestratorAssignment,
    launch_runtime: SupervisorRuntime,
    resolution: &RoleModelResolution,
) -> Result<()> {
    let category = assignment.effective_role_category();
    match launch_runtime {
        // The fake runtime never executes a provider model. Catalog observation
        // may be `runtime_default` on the CLI path; still skip capability
        // admission so simulation-only runs can store and exercise categories.
        SupervisorRuntime::Fake => Ok(()),
        _ => admit_role_category(category, resolution.selection.model.as_deref()),
    }
    .with_context(|| {
        format!(
            "assignment '{}' category '{}' refused at execution admission",
            assignment.id,
            category.as_str()
        )
    })
}

fn bind_selected_runtime_launch(
    mut command: ExternalAgentCommand,
    assignment: &OrchestratorAssignment,
    plan: &SupervisorPlan,
    options: &SupervisorRunOptions,
    launch_runtime: SupervisorRuntime,
    catalog: &RuntimeModelCatalog,
) -> Result<BoundSelectedRuntimeLaunch> {
    let configured = effective_role_model_selection(plan, assignment.role);
    let resolution = catalog.resolve_role_model_selection(&configured, launch_runtime)?;
    let model_provenance =
        CompletedLaunchModelProvenance::from_resolution(launch_runtime, &configured, &resolution);
    admit_assignment_role_category(assignment, launch_runtime, &resolution)?;
    if launch_runtime.is_adapter_subprocess() {
        authorize_bounded_leaf_runtime_role(assignment.role).with_context(|| {
            format!(
                "selected runtime '{}' cannot launch judgment or delegating role '{}'",
                crate::runtime_adapter::AdapterId::from_runtime(launch_runtime),
                assignment.role.as_str()
            )
        })?;
        command.program = selected_runtime_program(launch_runtime, options);
        command = command.with_runtime_adapter(
            launch_runtime,
            crate::runtime_adapter::RuntimeAdapterConfig::from_environment(launch_runtime),
        );
        if command.runtime_adapter.is_none() {
            bail!(
                "selected runtime '{}' could not be translated into a supported executable command",
                crate::runtime_adapter::AdapterId::from_runtime(launch_runtime)
            );
        }
        let model = resolution.selection.model.clone().with_context(|| {
            format!(
                "selected runtime '{}' assignment '{}' has no model",
                crate::runtime_adapter::AdapterId::from_runtime(launch_runtime),
                assignment.id
            )
        })?;
        command = command
            .with_model_selection(Some(model), resolution.selection.reasoning_effort.clone());
        prerender_selected_runtime_adapter_command(&command, launch_runtime)?;
        return Ok(BoundSelectedRuntimeLaunch {
            command,
            model_provenance,
        });
    }
    authorize_resolved_judgment_model(
        assignment.role,
        configured.model.as_deref(),
        resolution.selection.model.as_deref(),
        resolution.observation,
        launch_runtime,
    )?;
    command = command.with_model_selection(
        resolution.selection.model.clone(),
        resolution.selection.reasoning_effort.clone(),
    );
    Ok(BoundSelectedRuntimeLaunch {
        command,
        model_provenance,
    })
}

#[cfg(test)]
pub(super) fn bind_selected_assignment_launch_for_test(
    command: ExternalAgentCommand,
    assignment: &OrchestratorAssignment,
    budget_policy: &AssignmentBudgetPolicy,
    plan: &SupervisorPlan,
    options: &SupervisorRunOptions,
    catalog: &RuntimeModelCatalog,
) -> Result<(SupervisorRuntime, ExternalAgentCommand)> {
    let launch_runtime = assignment_launch_runtime(assignment, options, budget_policy);
    let launch_catalog =
        runtime_model_catalog_for_launch(catalog, options.runtime, launch_runtime)?;
    let bound_launch = bind_selected_runtime_launch(
        command,
        assignment,
        plan,
        options,
        launch_runtime,
        &launch_catalog,
    )?;
    Ok((launch_runtime, bound_launch.command))
}

pub(super) fn prerender_selected_runtime_adapter_command(
    command: &ExternalAgentCommand,
    launch_runtime: SupervisorRuntime,
) -> Result<()> {
    if !launch_runtime.is_adapter_subprocess() {
        return Ok(());
    }
    let config = command.runtime_adapter.as_ref().with_context(|| {
        format!(
            "selected runtime '{}' is missing its adapter command configuration",
            crate::runtime_adapter::AdapterId::from_runtime(launch_runtime)
        )
    })?;
    let launch = config
        .render(&crate::runtime_adapter::LaunchContext {
            prompt: &command.prompt,
            model: command.model.as_deref(),
            effort: command.reasoning_effort.as_deref(),
            cwd: &command.cwd,
            output: &command.output_last_message,
        })
        .with_context(|| {
            format!(
                "selected runtime '{}' adapter command could not be rendered; refusing to launch",
                crate::runtime_adapter::AdapterId::from_runtime(launch_runtime)
            )
        })?;
    if launch.program.as_os_str().is_empty() {
        bail!(
            "selected runtime '{}' adapter binary is not configured; refusing to launch",
            crate::runtime_adapter::AdapterId::from_runtime(launch_runtime)
        );
    }
    if launch.argv.is_empty() {
        bail!(
            "selected runtime '{}' produced an empty adapter command; refusing to launch",
            crate::runtime_adapter::AdapterId::from_runtime(launch_runtime)
        );
    }
    Ok(())
}

pub(super) fn execute_supervisor_assignment(
    context: AssignmentExecutionContext<'_, '_>,
) -> AssignmentExecutionOutcome {
    let mut outcome = AssignmentExecutionOutcome {
        gate_tracker: Some(GateCorrectionTracker::new(
            context.plan.max_gate_corrections,
        )),
        selection_decisions: context.budget_policy.selector_decisions.clone(),
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
    if let Some(signal) = &context.admission_commit {
        signal.notify();
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
    worktree_write_lease: Option<ManagedWorktreeWriteLease>,
    primary_scope_baseline: Option<PrimaryScopeSnapshot>,
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
        evidence_only_reaudit,
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
        match sync_store.claim_paths_for_run(
            &options.run_id,
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
                if matches!(
                    worktree_creation,
                    SupervisorWorktreeCreation::PrimaryWorktree
                ) {
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
                }
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
    outcome.claimed_paths = claim.paths.clone();
    let current_primary_head = current_head_oid(repo)?;
    let primary_scope_baseline = if matches!(
        worktree_creation,
        SupervisorWorktreeCreation::PrimaryWorktree
    ) {
        match capture_primary_scope_snapshot(repo, &claim.paths, true, context.execution_runtime) {
            Ok(snapshot) => Some(snapshot),
            Err(error) => {
                record_isolated_assignment_failure(
                    outcome,
                    &effective_assignment,
                    "primary-worktree declared-scope cleanliness preflight",
                    &error,
                );
                return Ok(AssignmentExecutionDisposition::Complete);
            }
        }
    } else {
        None
    };
    if !reused
        && !matches!(
            worktree_creation,
            SupervisorWorktreeCreation::PrimaryWorktree
        )
    {
        if evidence_only_reaudit.is_some() {
            record_isolated_assignment_failure(
                outcome,
                &effective_assignment,
                "preserved worktree lookup",
                &anyhow!("evidence-only re-audit requires the preserved managed child worktree"),
            );
            return Ok(AssignmentExecutionDisposition::Complete);
        }
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
            SupervisorWorktreeCreation::ExistingOnly => {
                bail!("existing-only supervisor operation cannot create a child worktree")
            }
            SupervisorWorktreeCreation::PrimaryWorktree => {
                bail!("primary-worktree execution does not create a managed child worktree")
            }
            SupervisorWorktreeCreation::NonpublishableSimulation => {
                manager.create_for_nonpublishable_simulation(create_options)
            }
            #[cfg(test)]
            SupervisorWorktreeCreation::TestOnly | SupervisorWorktreeCreation::VerifiedTestOnly => {
                manager.create_for_test(create_options)
            }
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
    let worktree_write_lease = if matches!(
        worktree_creation,
        SupervisorWorktreeCreation::PrimaryWorktree
    ) {
        None
    } else {
        match manager
            .acquire_write_execution_lease(&effective_assignment.id)
            .with_context(|| {
                format!(
                    "failed to acquire exclusive execution lease for child worktree '{}'",
                    effective_assignment.id
                )
            }) {
            Ok(lease) => Some(lease),
            Err(error) => {
                record_isolated_assignment_failure(
                    outcome,
                    &effective_assignment,
                    "worktree execution lease acquisition",
                    &error,
                );
                return Ok(AssignmentExecutionDisposition::Complete);
            }
        }
    };
    let worktree = match worktree_write_lease.as_ref() {
        Some(lease) => lease.record().clone(),
        None => WorktreeRecord {
            name: effective_assignment.id.clone(),
            path: repo.to_path_buf(),
            branch: "primary_worktree".to_string(),
        },
    };
    if *reused && worktree_write_lease.is_some() {
        let lease = worktree_write_lease
            .as_ref()
            .context("managed child worktree lease disappeared")?;
        let reusable = if let Some(source) = evidence_only_reaudit {
            inspect_supervisor_candidate(repo, &effective_assignment, lease).and_then(
                |inspection| {
                    if inspection.binding != source.operation.preserved_candidate_binding {
                        bail!(
                            "preserved candidate binding changed: expected {:?}, observed {:?}",
                            source.operation.preserved_candidate_binding,
                            inspection.binding
                        );
                    }
                    Ok(())
                },
            )
        } else {
            ensure_reusable_child_worktree(&worktree, &current_primary_head)
        };
        if let Err(error) = reusable {
            if evidence_only_reaudit.is_some() {
                let denial = GateDenial::new(
                    gate_correlation_id(&effective_assignment.id, 1),
                    GateDenialReason::MergeRemediation {
                        blocker: GateApplyBlocker::StaleBase,
                    },
                    VerifiedGateContext::new(
                        &effective_assignment.id,
                        GateCheckSource::ValidationBinding,
                        &effective_assignment.assigned_paths,
                    )?,
                )
                .context("failed to construct preserved-candidate binding denial")?;
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
            }
            record_isolated_assignment_failure(
                outcome,
                &effective_assignment,
                if evidence_only_reaudit.is_some() {
                    "preserved candidate content binding"
                } else {
                    "reusable worktree validation"
                },
                &error,
            );
            return Ok(AssignmentExecutionDisposition::Complete);
        }
    }
    let mandatory_worktree_controls = match if primary_scope_baseline.is_some() {
        bind_primary_worktree_controls(&worktree.path)
    } else {
        provision_mandatory_worktree_controls(&worktree.path)
    } {
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
            primary_scope_baseline,
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
    model_provenance: CompletedLaunchModelProvenance,
    primary_before: PrimaryWorktreeSnapshot,
    primary_scope_before: Option<PrimaryScopeSnapshot>,
    incoming_scratch: ArtifactScratchDirectory,
    capture_scratch: ArtifactScratchDirectory,
    incoming_output_root: SecureOutputRoot,
    capture_output_root: SecureOutputRoot,
    launch_runtime: SupervisorRuntime,
    budget_reservation: DispatchBudgetReservation<'a>,
    pre_action_review_context: Option<ReviewContext>,
}

#[allow(clippy::too_many_arguments)]
fn prepare_child_attempt<'a>(
    context: &AssignmentExecutionContext<'a, '_>,
    outcome: &mut AssignmentExecutionOutcome,
    budget_policy: &AssignmentBudgetPolicy,
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
        assignment_schedule,
        evidence_only_reaudit,
        options,
        repo,
        run_dir,
        dirs,
        execution_runtime,
        execution_target,
        field_guide,
        artifacts,
        budget_ledger,
        runtime_model_catalog,
        ..
    } = context;
    let assignment = &preflight.assignment;
    let launch_runtime = assignment_launch_runtime(assignment, options, budget_policy);
    let launch_catalog =
        runtime_model_catalog_for_launch(runtime_model_catalog, options.runtime, launch_runtime)?;
    let mut runtime_assignment = assignment.clone();
    runtime_assignment.runtime = Some(launch_runtime);
    let assignment = &runtime_assignment;
    let assignment_phase =
        validated_assignment_phase_for_launch(assignment, *index, assignment_schedule)?;
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
    let budget_plan = budget_policy.apply(plan);
    let launch_runtime = assignment_launch_runtime(assignment, options, budget_policy);
    let nested_worker_runtime = nested_worker_launch_runtime(launch_runtime, budget_policy);
    let resolved_prompt_plan = evidence_only_reaudit
        .is_none()
        .then(|| runtime_resolved_prompt_plan(&budget_plan, launch_runtime, &launch_catalog))
        .transpose()?;
    let RenderedPromptWithMeasurements {
        prompt,
        mut measurements,
    } = if let Some(source) = evidence_only_reaudit {
        let preserved_base = source
            .operation
            .preserved_candidate_binding
            .primary_head
            .as_deref()
            .context("preserved candidate binding has no primary HEAD")?
            .parse::<Oid>()
            .context("preserved candidate binding primary HEAD is invalid")?;
        let diff = collect_diff_since_base(
            &worktree.path,
            &preserved_base,
            REVIEW_LENS_REQUEST_LIMIT_BYTES,
        )?;
        render_evidence_only_reaudit_prompt(
            assignment,
            worktree,
            &attempt_artifacts.report_path,
            schema_path,
            source,
            &diff,
        )?
    } else {
        render_child_orchestrator_prompt_with_incoming_root_and_field_guide(
            ChildOrchestratorPromptContext {
                plan: resolved_prompt_plan.as_ref().unwrap_or(&budget_plan),
                execution_target: context.execution_target,
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
            launch_runtime,
            nested_worker_runtime,
        )?
    };
    if evidence_only_reaudit.is_none() {
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
    }
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
        Duration::from_secs(budget_plan.child_timeout_seconds),
    );
    let bound_launch = bind_selected_runtime_launch(
        command,
        assignment,
        &budget_plan,
        options,
        launch_runtime,
        &launch_catalog,
    )?;
    command = bound_launch.command;
    command = bind_runtime_output_schema(command, launch_runtime, schema_path)?;
    command = bind_runtime_read_only_schema_files(
        command,
        launch_runtime,
        &[schema_path, worker_schema_path, auditor_schema_path],
    );
    // Agent lifecycle records and binds repository metadata. Child-visible Git paths are
    // derived separately from `command.cwd` as an exact linked-worktree allowlist; the
    // owning primary/common checkout is not made visible.
    command = command.with_agent_lifecycle(
        repo,
        assignment.role.as_str(),
        options.run_id.as_str(),
        &assignment.id,
    );
    command = command.with_agent_parent(journal_parent_id);
    command = bind_supervisor_machine_global_staging_cleanup(command, options)?;
    command =
        apply_canonical_environment_requirements(command, &preflight.environment_requirements);
    command = if evidence_only_reaudit.is_some() {
        configure_read_only_auditor_command(command)?
    } else {
        configure_assignment_phase_command(command, assignment_phase, &assignment.assigned_paths)?
    };
    command = command.with_writable_launch_target(match execution_target {
        Some(SupervisorExecutionTarget::PrimaryWorktree { .. }) => {
            crate::runtime_adapter::WritableLaunchTarget::PrimaryWorktree
        }
        None => crate::runtime_adapter::WritableLaunchTarget::ManagedChildWorktree,
    });

    let primary_before = primary_worktree_snapshot(repo, *execution_runtime)?;
    if let Some(error) = primary_before.inspection_problem() {
        bail!("refusing to launch child without a complete primary integrity snapshot: {error}");
    }
    let primary_scope_before = preflight
        .primary_scope_baseline
        .as_ref()
        .map(|_| {
            capture_primary_scope_snapshot(
                repo,
                &assignment.assigned_paths,
                false,
                *execution_runtime,
            )
        })
        .transpose()?;
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
    if evidence_only_reaudit.is_none() {
        let journal_paths = match precreate_worker_execution_journals(assignment, &incoming_scratch)
        {
            Ok(paths) => paths,
            Err(error) => {
                drop(incoming_output_root);
                drop(capture_output_root);
                with_supervisor_artifacts(artifacts, |writer, _| {
                    discard_invocation_scratches(writer, &incoming_scratch, &capture_scratch)
                })?;
                return Err(error).context("failed to reserve exact worker journal artifacts");
            }
        };
        if journal_paths.len() != assignment.worker_assignments.len() {
            drop(incoming_output_root);
            drop(capture_output_root);
            with_supervisor_artifacts(artifacts, |writer, _| {
                discard_invocation_scratches(writer, &incoming_scratch, &capture_scratch)
            })?;
            bail!("worker journal reservation count did not match the assignment contract");
        }
        for (worker, journal_path) in assignment.worker_assignments.iter().zip(journal_paths) {
            command = command.with_worker_journal_artifact(
                worker.id.clone(),
                incoming_scratch.path(),
                journal_path,
            );
        }
    }
    let budget_reservation = match reserve_dispatch_budget(
        &budget_plan,
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
    let pre_action_review_context = if launch_runtime == SupervisorRuntime::Codex {
        match pre_action_review_context(options, assignment, &worktree.path) {
            Ok(review_context) => Some(review_context),
            Err(error) => {
                drop(incoming_output_root);
                drop(capture_output_root);
                with_supervisor_artifacts(artifacts, |writer, _| {
                    discard_invocation_scratches(writer, &incoming_scratch, &capture_scratch)
                })?;
                return Err(error);
            }
        }
    } else {
        None
    };
    if *execution_runtime == SupervisorExecutionRuntime::Verified
        && !context
            .worktree_creation
            .bypass_verified_admission_for_test()
    {
        let authenticated_claims = context
            .sync_store
            .snapshot()
            .context("failed to revalidate authenticated claims before writable launch")?;
        if let Some(admission) = worktree_writable_admission_record(
            &assignment.id,
            &assignment.assigned_paths,
            attempt,
            worktree,
            &preflight.claim,
            &authenticated_claims,
            &command,
            launch_runtime,
            assignment_phase,
        )? {
            let relative = PathBuf::from("assignments").join(format!(
                "{}.attempt-{attempt}.worktree-writable-admission.json",
                assignment.id
            ));
            let schema_relative = PathBuf::from("schemas").join(format!(
                "{}.attempt-{attempt}.worktree-writable-admission.schema.json",
                assignment.id
            ));
            with_supervisor_artifacts(artifacts, |writer, _| {
                write_worktree_writable_admission_schema(writer, &schema_relative)?;
                write_artifact_json(
                    writer,
                    &relative,
                    &admission,
                    MAX_SUPERVISOR_REPORT_BYTES,
                    ArtifactFileDisposition::PrivateEvidence,
                )
            })
            .with_context(|| {
                format!(
                    "failed to persist worktree writable admission for assignment '{}' attempt {}",
                    assignment.id, attempt
                )
            })?;
        }
    }
    if let Some(signal) = &context.admission_commit {
        signal.notify();
    }
    Ok(AssignmentExecutionDisposition::Continue(
        PreparedChildAttempt {
            attempt_artifacts,
            corrective_retry_used,
            command,
            model_provenance: bound_launch.model_provenance,
            primary_before,
            primary_scope_before,
            incoming_scratch,
            capture_scratch,
            incoming_output_root,
            capture_output_root,
            launch_runtime,
            budget_reservation,
            pre_action_review_context,
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
    model_provenance: CompletedLaunchModelProvenance,
    external_run: ExternalAgentRun,
    _worker_journal_evidence: WorkerExecutionJournalEvidenceSet,
    _primary_after: PrimaryWorktreeSnapshot,
    _primary_scope_after: Option<PrimaryScopeSnapshot>,
    _budget_reservation: DispatchBudgetReservation<'a>,
    _capture_scratch: ArtifactScratchDirectory,
    _incoming_scratch: ArtifactScratchDirectory,
    _primary_before: PrimaryWorktreeSnapshot,
    _primary_scope_before: Option<PrimaryScopeSnapshot>,
    _command: ExternalAgentCommand,
}

fn verify_imported_managed_child_candidate(
    repo: &Path,
    assignment: &OrchestratorAssignment,
    write_lease: &ManagedWorktreeWriteLease,
    imported: &ManagedChildGitImport,
) -> Result<()> {
    let candidate = collect_agent_result_with_evidence_and_write_lease(
        MergeCollectOptions {
            repo: repo.to_path_buf(),
            agent_id: assignment.id.clone(),
            claimed_paths: assignment.assigned_paths.clone(),
            include_full_diff: false,
            diff_summary_char_limit: 1,
            validations: Vec::new(),
        },
        ValidationEvidenceBundle::default(),
        write_lease,
    )
    .context("failed to capture the imported managed child candidate")?;
    if !candidate.unclaimed_changed_paths.is_empty() {
        bail!(
            "imported managed child candidate contains unclaimed paths: {}",
            display_paths(&candidate.unclaimed_changed_paths)
        );
    }
    let candidate_paths = normalize_paths(candidate.changed_paths)
        .context("imported managed child candidate paths are invalid")?;
    if candidate_paths != imported.final_changed_paths {
        bail!(
            "imported managed child commit paths differ from the collected worktree candidate: commit [{}], worktree [{}]",
            display_paths(&imported.final_changed_paths),
            display_paths(&candidate_paths)
        );
    }
    if candidate.snapshot_tree != imported.head_tree_oid {
        bail!(
            "imported managed child commit tree {} differs from collected worktree tree {}",
            imported.head_tree_oid,
            candidate.snapshot_tree
        );
    }
    Ok(())
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
    let model_provenance = prepared.model_provenance;
    let primary_before = prepared.primary_before;
    let primary_scope_before = prepared.primary_scope_before;
    let incoming_scratch = prepared.incoming_scratch;
    let capture_scratch = prepared.capture_scratch;
    let incoming_output_root = prepared.incoming_output_root;
    let capture_output_root = prepared.capture_output_root;
    let launch_runtime = prepared.launch_runtime;
    let mut budget_reservation = prepared.budget_reservation;
    let pre_action_review_context = prepared.pre_action_review_context;

    record_shared_orchestration_event(
        artifacts,
        &assignment.id,
        Some(journal_parent_id),
        OrchestrationRole::Orchestrator,
        OrchestrationEventKind::Spawn,
        record_supervision_spawn_payload_with_category(
            &assignment.id,
            journal_parent_id,
            OrchestrationRole::Orchestrator,
            assignment.role,
            assignment.category_override(),
            write_boundary_refs(&assignment.assigned_paths),
            &assignment_scope_ref(&assignment.id),
            json!({
                "attempt": attempt,
                "corrective_retry": corrective_retry_used,
                "runtime": launch_runtime,
            }),
        )?,
    )?;
    if attempt == 1 {
        let (owner_role, owner_legacy_role) = if journal_parent_id == options.run_id.as_str() {
            (OrchestrationRole::Supervisor, "supervisor")
        } else {
            (OrchestrationRole::Orchestrator, "child_orchestrator")
        };
        record_shared_gate_ownership(
            artifacts,
            journal_parent_id,
            None,
            owner_role,
            GateOwnershipRecord::assign(
                &assignment.id,
                journal_parent_id,
                owner_role,
                owner_legacy_role,
                "initial_parent_gate",
            )?,
        )?;
    }
    record_shared_orchestration_event(
        artifacts,
        &assignment.id,
        Some(journal_parent_id),
        OrchestrationRole::Orchestrator,
        OrchestrationEventKind::Status,
        lifecycle_event_payload("running", Some(attempt), None),
    )?;

    let external_run_result = match launch_runtime {
        SupervisorRuntime::Codex => {
            let review_context = if requires_hosted_pre_action_review(&command) {
                pre_action_review_context.as_ref()
            } else {
                None
            };
            // All fallible pre-dispatch preparation is complete. Mark
            // invocation only at the external-runner call boundary.
            if let Err(error) = budget_reservation.mark_invoked_for_runtime(launch_runtime) {
                drop(incoming_output_root);
                drop(capture_output_root);
                with_supervisor_artifacts(artifacts, |writer, _| {
                    discard_invocation_scratches(writer, &incoming_scratch, &capture_scratch)
                })?;
                return Err(error);
            }
            record_dispatch_checkpoint(artifacts, false, false, &assignment.id, attempt)?;
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if let Some(review_context) = review_context.as_ref() {
                    let mut review_journal = SupervisorPreActionJournalSink {
                        artifacts,
                        node: &assignment.id,
                        parent: Some(journal_parent_id),
                    };
                    external_runner(
                        &command,
                        cancellation,
                        Some(ExternalPreActionReviewRuntime {
                            context: review_context,
                            journal: &mut review_journal,
                        }),
                    )
                } else {
                    external_runner(&command, cancellation, None)
                }
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
        SupervisorRuntime::Grok
        | SupervisorRuntime::Cursor
        | SupervisorRuntime::ClaudeCode
        | SupervisorRuntime::GeminiCli => {
            if let Err(error) = budget_reservation.mark_invoked_for_runtime(launch_runtime) {
                drop(incoming_output_root);
                drop(capture_output_root);
                with_supervisor_artifacts(artifacts, |writer, _| {
                    discard_invocation_scratches(writer, &incoming_scratch, &capture_scratch)
                })?;
                return Err(error);
            }
            record_dispatch_checkpoint(artifacts, false, false, &assignment.id, attempt)?;
            Ok(external_runner(&command, cancellation, None))
        }
        SupervisorRuntime::Fake => {
            if let Err(error) = budget_reservation.mark_invoked_for_runtime(launch_runtime) {
                drop(incoming_output_root);
                drop(capture_output_root);
                with_supervisor_artifacts(artifacts, |writer, _| {
                    discard_invocation_scratches(writer, &incoming_scratch, &capture_scratch)
                })?;
                return Err(error);
            }
            record_dispatch_checkpoint(artifacts, false, false, &assignment.id, attempt)?;
            deterministic_fake_child_run(
                &command,
                assignment,
                assignment_metadata,
                preflight.claim.token.get(),
                preflight.semantic_token,
            )
        }
    };
    record_dispatch_checkpoint(artifacts, false, true, &assignment.id, attempt)?;
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
    let usage_settlement = budget_reservation.settle_bound_runtime(&external_run, &command)?;
    match usage_settlement.reliable_usage() {
        Some(usage) => {
            outcome.usage_samples.push(RoleUsageSample {
                role: AgentRole::ChildOrchestrator,
                lens_id: None,
                model: command.model.clone(),
                usage,
            });
            record_and_persist_live_invocation(
                artifacts,
                LiveInvocationObservation {
                    run_id: options.run_id.as_str(),
                    assignment_id: &assignment.id,
                    attempt,
                    role: assignment.role,
                    runtime: launch_runtime,
                    model: command.model.as_deref(),
                    effort: command.reasoning_effort.as_deref(),
                    worktree_id: &worktree.name,
                    usage: Some(&usage),
                    duration_ms: Some(external_run.duration_ms),
                    started_at_unix_millis: live_invocation_started_millis(
                        external_run.duration_ms,
                    ),
                },
            )?;
        }
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
    let attempt_containment_verified = external_containment_verified(&external_run, launch_runtime);
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
    let worker_journal_result = with_supervisor_artifacts(artifacts, |writer, journal| {
        let evidence =
            import_worker_execution_journals(writer, assignment, &incoming_scratch, &external_run)?;
        record_worker_journal_events(journal, writer, assignment, &evidence);
        Ok(evidence)
    });
    let attempt_import_result = with_supervisor_artifacts(artifacts, |writer, _| {
        import_external_attempt_evidence(
            writer,
            ExternalAttemptEvidenceContext {
                incoming_scratch: &incoming_scratch,
                capture_scratch: &capture_scratch,
                artifacts: &attempt_artifacts,
                external_run: &external_run,
                external_command: &command,
                raw_report_validated,
                runtime: launch_runtime,
            },
        )
    });
    let worker_journal_evidence = match (worker_journal_result, attempt_import_result) {
        (Ok(evidence), Ok(())) => evidence,
        (Err(error), Ok(())) => {
            return Err(error).context("trusted worker journal evidence import failed")
        }
        (Ok(_), Err(error)) => return Err(error),
        (Err(error), Err(import_error)) => {
            return Err(error).context(format!(
                "external attempt evidence import and scratch cleanup also failed: {import_error:#}"
            ))
        }
    };
    let managed_child_git_import = if options.runtime == SupervisorRuntime::Codex
        && *execution_runtime == SupervisorExecutionRuntime::Verified
        && external_process_completed(&external_run)
        && attempt_containment_verified
        && external_run.publishable
        && raw_report_validated
        && preflight.primary_scope_baseline.is_none()
    {
        let write_lease = preflight
            .worktree_write_lease
            .as_ref()
            .context("verified managed child Git collection has no write lease")?;
        Some(
            collect_and_import_managed_child_git_commit(
                repo,
                &worktree.path,
                preflight.child_base_head,
                &assignment.assigned_paths,
            )
            .and_then(|imported| {
                verify_imported_managed_child_candidate(repo, assignment, write_lease, &imported)?;
                Ok(imported)
            }),
        )
    } else {
        None
    };
    let primary_after = primary_worktree_snapshot(repo, *execution_runtime)?;
    let primary_changes = primary_integrity_changes(&primary_before, &primary_after);
    let primary_scope_after = primary_scope_before
        .as_ref()
        .map(|_| {
            capture_primary_scope_snapshot(
                repo,
                &assignment.assigned_paths,
                false,
                *execution_runtime,
            )
        })
        .transpose()?;
    let observed_primary_scope_changes = primary_scope_before
        .as_ref()
        .zip(primary_scope_after.as_ref())
        .map(|(before, after)| primary_scope_changed_paths(before, after));
    let primary_changes = if primary_scope_before.is_some() {
        primary_integrity_changes_outside_scope(&primary_changes, &assignment.assigned_paths)
    } else {
        primary_changes
    };
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
    let (mut attempt_report, report_shape_problems) =
        collect_child_report(ChildReportCollectionContext {
            assignment,
            assignment_metadata,
            report_path: &attempt_artifacts.raw_report_relative,
            external_run: &external_run,
            external_command: &command,
            worktree_path: &worktree.path,
            child_base_head: &preflight.child_base_head,
            worker_journals: &worker_journal_evidence,
            evidence_only_source: context.evidence_only_reaudit.map(|source| &source.report),
            observed_changed_paths: observed_primary_scope_changes.as_deref(),
        });
    if let Some(import) = managed_child_git_import {
        match import {
            Ok(imported) => attempt_report.findings.push(Finding {
                severity: FindingSeverity::Info,
                message: format!(
                    "verified managed child commit {} from base {} and imported {}/{} reachable objects ({} / {} bytes)",
                    imported.head_oid,
                    imported.base_oid,
                    imported.imported_object_count,
                    imported.closure_object_count,
                    imported.imported_bytes,
                    imported.closure_bytes,
                ),
                paths: imported.touched_paths,
            }),
            Err(error) => {
                attempt_report.status = ReviewStatus::Failed;
                attempt_report.accepted = false;
                attempt_report.rejected = true;
                attempt_report.findings.push(Finding {
                    severity: FindingSeverity::Error,
                    message: format!(
                        "managed child private Git collection/import was rejected: {error:#}"
                    ),
                    paths: assignment.assigned_paths.clone(),
                });
                attempt_report.remaining_risk =
                    "managed child commit provenance or object import is unverified".to_string();
                attempt_report.next_safe_action =
                    "inspect the preserved private Git boundary and start a fixed-cause run"
                        .to_string();
            }
        }
    }
    if preflight.primary_scope_baseline.is_some() {
        attempt_report.findings.push(Finding {
            severity: FindingSeverity::Info,
            message: format!(
                "child execution targeted the existing primary checkout with declared scope: {}",
                display_paths(&assignment.assigned_paths)
            ),
            paths: assignment.assigned_paths.clone(),
        });
    }
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
        model_provenance,
        external_run,
        _worker_journal_evidence: worker_journal_evidence,
        _primary_after: primary_after,
        _primary_scope_after: primary_scope_after,
        _budget_reservation: budget_reservation,
        _capture_scratch: capture_scratch,
        _incoming_scratch: incoming_scratch,
        _primary_before: primary_before,
        _primary_scope_before: primary_scope_before,
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
        model_provenance: _,
        external_run,
        _worker_journal_evidence,
        _primary_after,
        _budget_reservation,
        _capture_scratch,
        _incoming_scratch,
        _primary_before,
        _primary_scope_after,
        _primary_scope_before,
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
    launch_runtime: SupervisorRuntime,
    scope_workspace: tempfile::TempDir,
}

struct ParentAuditorLensExecution<'a> {
    budget_policy: &'a AssignmentBudgetPolicy,
    lens: &'a ReviewLensConfig,
    lens_index: usize,
    expected_request: &'a ReviewLensRequest,
    required_coverage: &'a ReviewCoverageRequirement,
}

/// Creates a process-owned, uniquely named workspace for one review-lens run.
///
/// `TempDir::drop` recursively removes this workspace. That machine-global
/// cleanup is an audited known bypass: unlike external-agent output staging,
/// no caller selects or adopts this path. Keep the operator inventory in the
/// README in sync if this ownership or cleanup mechanism changes.
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

fn materialize_review_lens_auditor_schema_input(
    authoritative_schema: &Path,
    scope_workspace: &Path,
    runtime: SupervisorRuntime,
) -> Result<PathBuf> {
    let schema_input = scope_workspace.join("auditor-report.schema.json");
    fs::copy(authoritative_schema, &schema_input)
        .context("failed to materialize the isolated authoritative auditor schema input")?;
    if runtime == SupervisorRuntime::Codex {
        let codex_source = codex_output_schema_path(authoritative_schema)?;
        let codex_input = codex_output_schema_path(&schema_input)?;
        fs::copy(&codex_source, &codex_input).with_context(|| {
            format!(
                "failed to materialize isolated Codex auditor schema {} from {}",
                codex_input.display(),
                codex_source.display()
            )
        })?;
    }
    Ok(schema_input)
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

fn bind_active_review_lens_command(
    command: ExternalAgentCommand,
    lens: &ReviewLensConfig,
    assignment_reasoning_effort: Option<ReasoningEffort>,
    launch_runtime: SupervisorRuntime,
    runtime_model_catalog: &RuntimeModelCatalog,
) -> Result<ExternalAgentCommand> {
    apply_review_lens_model_selection(
        command,
        lens,
        assignment_reasoning_effort,
        launch_runtime,
        runtime_model_catalog,
    )
}

fn parent_auditor_spawn_payload(
    auditor_id: &str,
    assignment: &OrchestratorAssignment,
    auditor_attempt: usize,
    lens: &ReviewLensConfig,
    expected_request: &ReviewLensRequest,
    auditor_command: &ExternalAgentCommand,
    launch_runtime: SupervisorRuntime,
) -> Result<serde_json::Value> {
    record_supervision_spawn_payload(
        auditor_id,
        &assignment.id,
        OrchestrationRole::Auditor,
        AgentRole::Auditor,
        Vec::new(),
        &assignment_scope_ref(&assignment.id),
        json!({
            "attempt": auditor_attempt,
            "review_lens_id": lens.id,
            "backend_id": auditor_command.model_provider.as_deref(),
            "model": auditor_command.model.as_deref(),
            "reasoning_effort": auditor_command.reasoning_effort.as_deref(),
            "runtime": launch_runtime,
            "information_scope": lens.information_scope,
            "request_binding": expected_request.request_binding,
        }),
    )
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
        budget_policy,
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
    let launch_runtime = budget_policy
        .selected_runtime_for(AgentRole::Auditor)
        .unwrap_or(options.runtime);
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
    let assignment_reasoning_effort = context.assignment_metadata.reasoning_effort(&assignment.id);
    let resolved_auditor_effort = resolve_reasoning_effort(
        AgentRole::Auditor,
        assignment_reasoning_effort,
        lens.backend.reasoning_effort(),
        0,
    );
    let RenderedPromptWithMeasurements {
        prompt: auditor_prompt,
        mut measurements,
    } = render_review_lens_auditor_prompt(
        ReviewLensAuditorPromptContext {
            assignment,
            lens,
            resolved_reasoning_effort: Some(&resolved_auditor_effort.resolved),
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
    let auditor_schema_input = materialize_review_lens_auditor_schema_input(
        &auditor_schema_path,
        scope_workspace.path(),
        launch_runtime,
    )?;
    let mut auditor_command = ExternalAgentCommand::codex(
        &options.codex_bin,
        scope_workspace.path(),
        &auditor_prompt_path,
        &auditor_log_path,
        &auditor_report_path,
        Duration::from_secs(plan.child_timeout_seconds),
    );
    if launch_runtime.is_adapter_subprocess() {
        auditor_command.program = selected_runtime_program(launch_runtime, options);
        auditor_command = auditor_command.with_runtime_adapter(
            launch_runtime,
            crate::runtime_adapter::RuntimeAdapterConfig::from_environment(launch_runtime),
        );
    }
    // `lens` already comes from the active budget-policy plan. Keep its per-lens model and
    // effort authoritative even when the selector overrides the auditor runtime: heterogeneous
    // custom lenses are not aliases for the global Auditor role selection.
    auditor_command = bind_active_review_lens_command(
        auditor_command,
        lens,
        assignment_reasoning_effort,
        launch_runtime,
        runtime_model_catalog,
    )?;
    auditor_command =
        bind_runtime_output_schema(auditor_command, launch_runtime, &auditor_schema_input)?;
    auditor_command = bind_runtime_read_only_schema_files(
        auditor_command,
        launch_runtime,
        &[&auditor_schema_input],
    );
    auditor_command =
        configure_review_lens_execution_boundary(auditor_command, repo, &worktree.path)?
            .with_agent_lifecycle(
                repo,
                AgentRole::Auditor.as_str(),
                options.run_id.as_str(),
                &auditor_id,
            )
            .with_agent_parent(&assignment.id);
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
        launch_runtime,
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
        repo,
        execution_runtime,
        artifacts,
        cancellation,
        external_runner,
        options,
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
        launch_runtime,
        scope_workspace: _scope_workspace,
    } = prepared;
    record_shared_orchestration_event(
        artifacts,
        &auditor_id,
        Some(&assignment.id),
        OrchestrationRole::Auditor,
        OrchestrationEventKind::Spawn,
        parent_auditor_spawn_payload(
            &auditor_id,
            assignment,
            auditor_attempt,
            &lens,
            &expected_request,
            &auditor_command,
            launch_runtime,
        )?,
    )?;
    record_shared_orchestration_event(
        artifacts,
        &auditor_id,
        Some(&assignment.id),
        OrchestrationRole::Auditor,
        OrchestrationEventKind::Status,
        lifecycle_event_payload("running", Some(auditor_attempt), None),
    )?;

    let auditor_run_result = match launch_runtime {
        SupervisorRuntime::Codex => {
            // All fallible pre-dispatch preparation is complete. Mark
            // invocation only at the external-runner call boundary.
            if let Err(error) = auditor_budget_reservation.mark_invoked_for_runtime(options.runtime)
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
                return Err(error);
            }
            record_dispatch_checkpoint(artifacts, true, false, &auditor_id, auditor_attempt)?;
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
        SupervisorRuntime::Grok
        | SupervisorRuntime::Cursor
        | SupervisorRuntime::ClaudeCode
        | SupervisorRuntime::GeminiCli => {
            if let Err(error) = auditor_budget_reservation.mark_invoked_for_runtime(options.runtime)
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
                return Err(error);
            }
            record_dispatch_checkpoint(artifacts, true, false, &auditor_id, auditor_attempt)?;
            Ok(external_runner(&auditor_command, cancellation, None))
        }
        SupervisorRuntime::Fake => {
            if let Err(error) = auditor_budget_reservation.mark_invoked_for_runtime(options.runtime)
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
                return Err(error);
            }
            record_dispatch_checkpoint(artifacts, true, false, &auditor_id, auditor_attempt)?;
            deterministic_fake_auditor_run(&auditor_command, &auditor_id, assignment, child_report)
        }
    };
    record_dispatch_checkpoint(artifacts, true, true, &auditor_id, auditor_attempt)?;
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
        auditor_budget_reservation.settle_bound_runtime(&auditor_run, &auditor_command)?;
    match usage_settlement.reliable_usage() {
        Some(usage) => {
            outcome.usage_samples.push(RoleUsageSample {
                role: AgentRole::Auditor,
                lens_id: Some(lens.id.clone()),
                model: auditor_command.model.clone(),
                usage,
            });
            record_and_persist_live_invocation(
                artifacts,
                LiveInvocationObservation {
                    run_id: options.run_id.as_str(),
                    assignment_id: &assignment.id,
                    attempt: auditor_attempt,
                    role: AgentRole::Auditor,
                    runtime: options.runtime,
                    model: auditor_command.model.as_deref(),
                    effort: auditor_command.reasoning_effort.as_deref(),
                    worktree_id: &assignment.id,
                    usage: Some(&usage),
                    duration_ms: Some(auditor_run.duration_ms),
                    started_at_unix_millis: live_invocation_started_millis(auditor_run.duration_ms),
                },
            )?;
        }
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
    let auditor_containment_verified = external_containment_verified(&auditor_run, launch_runtime);
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
                runtime: launch_runtime,
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
        child_report.licensed_breakage_review.as_ref(),
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

fn inspect_assignment_candidate(
    context: &AssignmentExecutionContext<'_, '_>,
    preflight: &AssignmentExecutionPreflight<'_>,
) -> Result<SupervisorCandidateInspection> {
    if let Some(baseline) = preflight.primary_scope_baseline.as_ref() {
        return inspect_primary_scope_candidate(
            context.repo,
            &preflight.assignment,
            baseline,
            context.execution_runtime,
        );
    }
    let lease = preflight
        .worktree_write_lease
        .as_ref()
        .context("managed child candidate inspection has no write lease")?;
    // Fake + NonpublishableSimulation never launches a child and must not depend
    // on isolated git / delegated systemd. Production Verified collect stays on
    // the writable fail-closed snapshot path.
    if context.options.runtime == SupervisorRuntime::Fake
        && context.execution_runtime == SupervisorExecutionRuntime::NonpublishableSimulation
    {
        return inspect_fake_simulation_candidate(context.repo, &preflight.assignment, lease);
    }
    inspect_supervisor_candidate(context.repo, &preflight.assignment, lease)
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

fn parent_auditor_rejection_kind(
    assignment: &OrchestratorAssignment,
    child_report: &OrchestratorReviewReport,
) -> Option<AuditorRejectionKind> {
    let rejecting = child_report
        .audit_reports
        .iter()
        .filter(|report| is_parent_auditor_id(assignment, &report.id) && report_failed(*report))
        .collect::<Vec<_>>();
    if !rejecting.is_empty()
        && rejecting
            .iter()
            .all(|report| report.rejection_kind == Some(AuditorRejectionKind::EvidenceQuality))
    {
        Some(AuditorRejectionKind::EvidenceQuality)
    } else if !rejecting.is_empty() {
        Some(AuditorRejectionKind::ImplementationDefect)
    } else {
        None
    }
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
    let AssignmentExecutionContext { artifacts, .. } = context;
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
    let auditor_rejection_kind = parent_auditor_rejection_kind(assignment, &child_report);
    let evidence_only_rejection = parent_auditor_failed
        && auditor_rejection_kind == Some(AuditorRejectionKind::EvidenceQuality);
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
            GateDenialReason::AuditorRepair {
                rejection: auditor_rejection_kind
                    .unwrap_or(AuditorRejectionKind::ImplementationDefect),
            },
            VerifiedGateContext::new(
                &assignment.id,
                GateCheckSource::Auditor,
                &assignment.assigned_paths,
            )?,
        )
        .context("failed to construct parent-auditor gate denial")?;
        if evidence_only_rejection {
            outcome
                .gate_tracker
                .as_mut()
                .context("gate correction tracker was not initialized")?
                .escalate(denial, artifacts, &assignment.id, journal_parent_id)?;
        } else {
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
        }
    } else if matches!(
        outcome
            .gate_tracker
            .as_ref()
            .and_then(GateCorrectionTracker::active_reason),
        Some(GateDenialReason::AuditorRepair { .. })
    ) && !parent_auditor_failed
    {
        outcome
            .gate_tracker
            .as_mut()
            .context("gate correction tracker was not initialized")?
            .self_corrected(artifacts, &assignment.id, journal_parent_id)?;
    }
    let mut traceability_candidate = None;
    if !report_failed(&child_report) || evidence_only_rejection {
        let post_auditor_candidate = inspect_assignment_candidate(context, preflight);
        match (pre_auditor_candidate.as_ref(), post_auditor_candidate) {
            (Some(before), Ok(after)) if before == &after => {
                traceability_candidate = Some(after);
            }
            (Some(before), Ok(after)) => {
                let error = anyhow!(
                    "candidate content, paths, or base changed across parent auditor review: before={before:?}, after={after:?}"
                );
                reject_supervisor_candidate_binding(&mut child_report, final_report_path, &error);
            }
            (Some(_), Err(error)) => {
                let error =
                    anyhow!("failed to recapture candidate after parent auditor review: {error:#}");
                reject_supervisor_candidate_binding(&mut child_report, final_report_path, &error);
            }
            (None, _) => {
                let error =
                    anyhow!("accepted report has no pre-auditor supervisor candidate binding");
                reject_supervisor_candidate_binding(&mut child_report, final_report_path, &error);
            }
        }
    }
    if !report_failed(&child_report) || evidence_only_rejection {
        if let Some(candidate) = traceability_candidate.as_ref() {
            if candidate.changed_paths != child_report.files_changed {
                let error = anyhow!(
                    "supervisor-observed candidate paths differ from the accepted child report"
                );
                reject_supervisor_candidate_binding(&mut child_report, final_report_path, &error);
                traceability_candidate = None;
            }
        }
    }
    if !parent_auditor_failed
        && child_report
            .licensed_breakage_review
            .as_ref()
            .is_some_and(|review| !review.failures.is_empty())
    {
        let candidate = traceability_candidate.as_ref().context(
            "accepted licensed breakage has no supervisor-inspected breaking-change identity",
        )?;
        let tasks = generated_licensed_follow_up_tasks(
            context.requested_plan,
            context.consultant,
            context.budget_config,
            assignment,
            &child_report,
            &candidate.binding,
        )?;
        let review = child_report
            .licensed_breakage_review
            .as_ref()
            .context("licensed breakage review packet disappeared before task journaling")?;
        record_licensed_breakage_follow_up_tasks(artifacts, &assignment.id, review, &tasks)?;
        child_report.generated_follow_up_tasks = tasks;
    }
    if report_failed(&child_report) && !evidence_only_rejection {
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

fn aggregate_active_parent_review_lenses(
    active_plan: &SupervisorPlan,
    expected_requests: &[ReviewLensRequest],
    required_coverage: ReviewCoverageRequirement,
    verdicts: Vec<ReviewLensVerdict>,
) -> Result<ReviewLensAggregate> {
    aggregate_review_lenses_against_requests(
        &active_plan.review_lenses,
        expected_requests,
        active_plan.review_aggregation_policy,
        required_coverage,
        verdicts,
    )
}

#[allow(clippy::too_many_arguments)]
fn publish_assignment_report(
    context: &AssignmentExecutionContext<'_, '_>,
    outcome: &mut AssignmentExecutionOutcome,
    preflight: &AssignmentExecutionPreflight<'_>,
    completed_launch_model_provenance: Option<&CompletedLaunchModelProvenance>,
    journal_parent_id: &str,
    final_report_relative: &Path,
    final_report_path: &Path,
    child_report: OrchestratorReviewReport,
    completed_candidate_inspection: Option<SupervisorCandidateInspection>,
    completed_assignment_containment: bool,
) -> Result<()> {
    let assignment = &preflight.assignment;
    outcome.candidate_inspection = completed_candidate_inspection;
    let auditor_selection = effective_role_model_selection(context.plan, AgentRole::Auditor);
    let subject_authority = model_capability_or_weak(
        completed_launch_model_provenance
            .and_then(CompletedLaunchModelProvenance::transition_subject_model),
    );
    let auditor_capability = model_capability_or_weak(
        context
            .plan
            .review_lenses
            .first()
            .map(|lens| lens.backend.model())
            .or(auditor_selection.model.as_deref()),
    )
    .capability;
    let role_transition = consider_assignment_role_transition(
        assignment,
        journal_parent_id,
        &child_report,
        subject_authority,
        auditor_capability,
    )?;
    with_supervisor_artifacts(context.artifacts, |writer, journal| {
        write_child_report(writer, final_report_relative, &child_report)?;
        record_final_report_decisions(journal, writer, journal_parent_id, &child_report);
        if let Some(executed) = &role_transition {
            record_orchestration_event(
                journal,
                writer,
                &assignment.id,
                Some(journal_parent_id),
                OrchestrationRole::Orchestrator,
                OrchestrationEventKind::Journal,
                role_transition_payload(&executed.record)?,
            );
        }
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
    let final_report_name = format!("{}.json", assignment.id);
    let final_report_relative = PathBuf::from("reports").join(&final_report_name);
    let final_report_path = dirs.reports.join(&final_report_name);
    let schema_path = dirs.schemas.join("orchestrator-review-report.schema.json");
    let worker_schema_path = dirs.schemas.join("worker-report.schema.json");
    let auditor_schema_path = dirs.schemas.join("auditor-report.schema.json");

    let mut retry_feedback: Option<ChildAttemptCorrection> = None;
    let mut active_budget_policy = context.budget_policy.clone();
    let mut attempt_history = Vec::new();
    let mut structural_attempt = 1usize;
    let max_attempts = usize::from(plan.max_child_retries)
        .saturating_add(usize::from(plan.max_gate_corrections))
        .saturating_add(1);
    let mut next_attempt = 1usize;
    let mut auditor_attempt = 0usize;
    let (
        child_report,
        completed_candidate_inspection,
        completed_assignment_containment,
        completed_launch_model_provenance,
    ) = 'gate_controller: loop {
        let mut child_result = None;
        let mut child_containment_verified = false;
        let mut child_gate_terminal = false;
        let first_attempt = next_attempt;
        for attempt in first_attempt..=max_attempts {
            next_attempt = attempt.saturating_add(1);
            if attempt > 1 {
                let retry_count = u32::try_from(attempt.saturating_sub(1))
                    .context("assignment retry count does not fit selector input")?;
                let decisions = active_budget_policy.reselect(
                    options.runtime,
                    runtime_model_catalog,
                    SelectorReselectionRequest {
                        roles: &[assignment.role],
                        assignment_id: Some(&assignment.id),
                        attempt,
                        primary_cause: SupervisorSelectionEventCause::Retry,
                        retry_count,
                        budget_signal: crate::selection::BudgetSignal::Continue,
                        environment_rejections: &[],
                    },
                )?;
                outcome.selection_decisions.extend(decisions);
            }
            let prepared = match prepare_child_attempt(
                context,
                outcome,
                &active_budget_policy,
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
            let attempted_launch_model_provenance = collected.model_provenance.clone();
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
                    child_result = Some((report, attempted_launch_model_provenance));
                    child_containment_verified = containment_verified;
                    child_gate_terminal = gate_terminal;
                    break;
                }
            }
        }

        let Some((mut child_report, child_launch_model_provenance)) = child_result else {
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
            if preflight.primary_scope_baseline.is_some() {
                if !child_report.decomposition_completions.is_empty() {
                    let error = anyhow!(
                        "primary-worktree execution does not support megafile decomposition evidence"
                    );
                    reject_supervisor_candidate_binding(
                        &mut child_report,
                        &final_report_path,
                        &error,
                    );
                    None
                } else if !report_failed(&child_report) {
                    inspect_assignment_candidate(context, &preflight).ok()
                } else {
                    None
                }
            } else {
                let lease = preflight
                    .worktree_write_lease
                    .as_ref()
                    .context("managed decomposition candidate has no worktree lease")?;
                match bind_supervisor_decomposition_candidate(
                    repo,
                    assignment,
                    &mut child_report,
                    lease,
                ) {
                    Ok(Some(inspection)) => Some(inspection),
                    Ok(None) if !report_failed(&child_report) => {
                        inspect_assignment_candidate(context, &preflight).ok()
                    }
                    Ok(None) => None,
                    Err(error) => {
                        reject_supervisor_candidate_binding(
                            &mut child_report,
                            &final_report_path,
                            &error,
                        );
                        None
                    }
                }
            }
        } else {
            None
        };
        if let Some(source) = context.evidence_only_reaudit {
            let binding_matches = pre_auditor_candidate.as_ref().is_some_and(|inspection| {
                inspection.binding == source.operation.preserved_candidate_binding
            });
            if !binding_matches {
                let denial = GateDenial::new(
                    gate_correlation_id(&assignment.id, 1),
                    GateDenialReason::MergeRemediation {
                        blocker: GateApplyBlocker::StaleBase,
                    },
                    VerifiedGateContext::new(
                        &assignment.id,
                        GateCheckSource::ValidationBinding,
                        &assignment.assigned_paths,
                    )?,
                )
                .context("failed to construct evidence-only content-binding denial")?;
                outcome
                    .gate_tracker
                    .as_mut()
                    .context("gate correction tracker was not initialized")?
                    .escalate(denial, artifacts, &assignment.id, journal_parent_id)?;
                child_report.status = ReviewStatus::Failed;
                child_report.accepted = false;
                child_report.rejected = true;
                child_report.findings.push(Finding {
                    severity: FindingSeverity::Error,
                    message:
                        "evidence-only report stage changed or lost the preserved candidate binding"
                            .to_string(),
                    paths: assignment.assigned_paths.clone(),
                });
                child_gate_terminal = true;
            }
        }
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
            let review_base = context
                .evidence_only_reaudit
                .and_then(|source| {
                    source
                        .operation
                        .preserved_candidate_binding
                        .primary_head
                        .as_deref()
                })
                .map(str::parse::<Oid>)
                .transpose()
                .context("preserved candidate binding primary HEAD is invalid")?
                .unwrap_or(preflight.child_base_head);
            let diff = if let Some(baseline) = preflight.primary_scope_baseline.as_ref() {
                let current = capture_primary_scope_snapshot(
                    repo,
                    &assignment.assigned_paths,
                    false,
                    context.execution_runtime,
                )?;
                render_primary_scope_diff(baseline, &current)?
            } else {
                collect_diff_since_base(
                    &preflight.worktree.path,
                    &review_base,
                    REVIEW_LENS_REQUEST_LIMIT_BYTES,
                )?
            };
            let output_report = serde_json::to_string(&child_report)
                .context("failed to serialize child output report for review lenses")?;
            let sources = ReviewLensRequestSources {
                child_transcript: &child_transcript,
                diff: &diff,
                output_report: &output_report,
            };
            let required_coverage =
                supervisor_review_coverage_requirement(assignment, &child_report);
            let active_plan = active_budget_policy.apply(plan);
            let auditor_launch_runtime = active_budget_policy
                .selected_runtime_for(AgentRole::Auditor)
                .unwrap_or(options.runtime);
            let mut expected_requests = Vec::with_capacity(active_plan.review_lenses.len());
            let mut verdicts = Vec::with_capacity(active_plan.review_lenses.len());
            for (lens_index, lens) in active_plan.review_lenses.iter().enumerate() {
                let expected_request = build_review_lens_request(lens, sources)?;
                let runtime_validation = validate_review_lens_runtime_selection(
                    lens,
                    auditor_launch_runtime,
                    runtime_model_catalog,
                );
                if let Err(error) = runtime_validation {
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
                        budget_policy: &active_budget_policy,
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
                        for remaining_lens in active_plan.review_lenses.iter().skip(lens_index + 1)
                        {
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
            let aggregate = aggregate_active_parent_review_lenses(
                &active_plan,
                &expected_requests,
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
                break 'gate_controller (
                    report,
                    candidate,
                    containment_verified,
                    child_launch_model_provenance,
                );
            }
        }
    };
    publish_assignment_report(
        context,
        outcome,
        &preflight,
        Some(&completed_launch_model_provenance),
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
        let repo = crate::git_repository::open(path).expect("open fixture repository");
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
        skip_without_containment!(ok);
        const CHILD_ENV: &str = "MACO_TEST_REVIEW_LENS_BOUNDARY_CHILD";
        const PRIMARY_SECRET_ENV: &str = "MACO_TEST_REVIEW_LENS_PRIMARY_SECRET";
        const CHILD_SECRET_ENV: &str = "MACO_TEST_REVIEW_LENS_CHILD_SECRET";
        const SCHEMA_ENV: &str = "MACO_TEST_REVIEW_LENS_SCHEMA";

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
            let schema = PathBuf::from(
                std::env::var_os(SCHEMA_ENV).context("missing hostile probe schema path")?,
            );
            assert_eq!(fs::read_to_string(schema)?, "{\"type\":\"object\"}\n");
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

        let schema_root = primary_root.join("schemas");
        fs::create_dir(&schema_root)?;
        let authoritative_schema = schema_root.join("auditor-report.schema.json");
        let codex_schema = codex_output_schema_path(&authoritative_schema)?;
        fs::write(&authoritative_schema, "{\"title\":\"authoritative\"}\n")?;
        fs::write(&codex_schema, "{\"type\":\"object\"}\n")?;
        let scope_workspace = create_review_lens_scope_workspace()?;
        let schema = materialize_review_lens_auditor_schema_input(
            &authoritative_schema,
            scope_workspace.path(),
            SupervisorRuntime::Codex,
        )?;
        let prompt = scope_workspace.path().join("prompt.md");
        fs::write(&prompt, "Attempt hostile access to omitted lens inputs.\n")?;
        let command = bind_runtime_read_only_schema_files(
            bind_runtime_output_schema(
                ExternalAgentCommand::codex(
                    "codex",
                    scope_workspace.path(),
                    &prompt,
                    scope_workspace.path().join("events.jsonl"),
                    scope_workspace.path().join("report.json"),
                    Duration::from_secs(10),
                ),
                SupervisorRuntime::Codex,
                &schema,
            )?,
            SupervisorRuntime::Codex,
            &[&schema],
        );
        let command =
            configure_review_lens_execution_boundary(command, &primary_root, &child_root)?;
        let output_schema = command
            .output_schema
            .as_ref()
            .context("isolated review lens omitted Codex output schema")?;
        assert!(output_schema.starts_with(scope_workspace.path()));
        assert!(!output_schema.starts_with(&primary_root));

        let mut profile = crate::process_runner::ExternalCodexProfile::read_only(&command.cwd);
        profile = profile.with_visible_read_only_file(output_schema);
        for input in &command.read_only_input_files {
            profile = profile.with_visible_read_only_file(input);
        }
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
            (SCHEMA_ENV.to_string(), output_schema.display().to_string()),
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
            Err(error) if crate::process_runner::is_verified_backend_unavailable(&error) => {
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
            phase: AssignmentPhase::Execution,
            runtime: None,
            role: AgentRole::ChildOrchestrator,
            role_category: None,
            selection_source: None,
            assigned_paths: vec![PathBuf::from("README.md")],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            task: None,
            worker_assignments: Vec::new(),
            environment_requirements: Vec::new(),
            licensed_breakage: None,
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
            parent_node: None,
            codex_bin: PathBuf::from("unused-codex"),
            runtime: SupervisorRuntime::Fake,
            allow_dirty_primary: false,
            allow_live_run_collision: false,
            admission_overrides: crate::supervise::SupervisorAdmissionConfig::default(),
            budget_overrides: crate::supervise::RunBudgetLimits::default(),
            budget_max_duration_seconds: None,
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
        // Fake catalog hides the slug; the provisional default (sol) is still
        // configured capability evidence. Runtime-default with no configured
        // model would be refused.
        let runtime_model_catalog = RuntimeModelCatalog::LocalDeterministicFake;
        let cancellation = ProcessCancellation::new();
        let mut journal = initialize_orchestration_event_journal(
            &repo,
            &options.run_id,
            options.parent_node.as_deref(),
        );
        let mut autonomy_kpis = AutonomyKpiCollector::default();
        let artifacts = Mutex::new(SharedSupervisorArtifacts {
            writer: &mut artifact_writer,
            journal: &mut journal,
            autonomy_kpis: &mut autonomy_kpis,
            checkpoint: None,
        });
        let runner = unused_external_runner;
        let context = AssignmentExecutionContext {
            index: 0,
            concurrent_mode: false,
            plan: &plan,
            requested_plan: &plan,
            execution_target: None,
            budget_config: &budget_config,
            consultant: &consultant,
            assignment_metadata: &assignment_metadata,
            assignment: &assignment,
            evidence_only_reaudit: None,
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
            budget_policy: AssignmentBudgetPolicy::default(),
            admission_commit: None,
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
        fs::create_dir_all(&dirs.schemas).expect("create direct phase schema directory");
        fs::write(&auditor_schema_path, "{\"type\":\"object\"}\n")
            .expect("materialize direct phase auditor schema");
        let prepared = match prepare_child_attempt(
            &context,
            &mut outcome,
            &context.budget_policy,
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
        assert!(prepared.command.read_only_input_files.is_empty());
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
                budget_policy: &context.budget_policy,
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
            None,
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
    fn real_runtime_default_launch_provenance_cannot_recover_coordinator_authority() {
        let provenance = CompletedLaunchModelProvenance {
            launch_runtime: SupervisorRuntime::Codex,
            configured_model: Some("gpt-5.6-sol".to_string()),
            launched_model: None,
            resolution_observation: ModelResolutionObservation::RuntimeDefault,
        };
        let subject = model_capability_or_weak(provenance.transition_subject_model());
        assert_eq!(subject.model, None);
        assert_eq!(subject.capability, ModelCapabilityClass::WeakMechanical);

        let transition = execute_judged_role_transition(
            "phase-child",
            RoleCategory::NonDelegatingTerminalWorker,
            RoleCategory::DelegatingCoordinator,
            "supervisor",
            "supervisor",
            subject,
            &RoleTransitionJudgeVerdict {
                judge_agent_id: "phase-child-review-auditor-lens-0".to_string(),
                judge_role: AgentRole::Auditor,
                judge_capability: ModelCapabilityClass::CriticalJudgment,
                accepted: true,
                uncertain: false,
            },
        )
        .expect("weak real-runtime transition must be recorded");
        assert!(!transition.granted);
        assert_eq!(transition.record.reason, "weak_model_cannot_delegate");
        assert_eq!(
            transition.effective_category,
            RoleCategory::NonDelegatingTerminalWorker
        );
    }

    #[test]
    fn fake_launch_provenance_reuses_configured_model_only_for_explicit_fake_resolution() {
        for resolution_observation in [
            ModelResolutionObservation::RuntimeDefault,
            ModelResolutionObservation::LocalDeterministicFake,
        ] {
            let provenance = CompletedLaunchModelProvenance {
                launch_runtime: SupervisorRuntime::Fake,
                configured_model: Some("gpt-5.6-sol".to_string()),
                launched_model: None,
                resolution_observation,
            };
            let subject = model_capability_or_weak(provenance.transition_subject_model());
            assert_eq!(subject.model, Some("gpt-5.6-sol"));
            assert_ne!(subject.capability, ModelCapabilityClass::WeakMechanical);
        }

        let unresolved = CompletedLaunchModelProvenance {
            launch_runtime: SupervisorRuntime::Fake,
            configured_model: Some("gpt-5.6-sol".to_string()),
            launched_model: None,
            resolution_observation: ModelResolutionObservation::NotResolved,
        };
        let unresolved_subject = model_capability_or_weak(unresolved.transition_subject_model());
        assert_eq!(unresolved_subject.model, None);
        assert_eq!(
            unresolved_subject.capability,
            ModelCapabilityClass::WeakMechanical
        );

        let unknown = CompletedLaunchModelProvenance {
            launch_runtime: SupervisorRuntime::Fake,
            configured_model: Some("unknown-model".to_string()),
            launched_model: None,
            resolution_observation: ModelResolutionObservation::RuntimeDefault,
        };
        let unknown_subject = model_capability_or_weak(unknown.transition_subject_model());
        assert_eq!(unknown_subject.model, Some("unknown-model"));
        assert_eq!(
            unknown_subject.capability,
            ModelCapabilityClass::WeakMechanical
        );
    }

    #[test]
    fn publication_uses_final_launch_bound_subject_model_for_transition() {
        let temp = tempfile::tempdir().expect("temporary phase fixture");
        let repo = temp.path().join("repo");
        Repository::init(&repo).expect("initialize phase fixture repository");
        fs::write(repo.join("README.md"), "baseline\n").expect("write fixture file");
        commit_fixture_repository(&repo);

        let assignment = OrchestratorAssignment {
            id: "phase-child".to_string(),
            phase: AssignmentPhase::Execution,
            runtime: None,
            role: AgentRole::ChildOrchestrator,
            role_category: None,
            selection_source: None,
            assigned_paths: vec![PathBuf::from("README.md")],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            task: None,
            worker_assignments: Vec::new(),
            environment_requirements: Vec::new(),
            licensed_breakage: None,
            notes: None,
        };
        let mut plan = SupervisorPlan {
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
        plan.role_models.insert(
            AgentRole::ChildOrchestrator,
            RoleModelSelection {
                model: Some("gpt-5.6-luna".to_string()),
                reasoning_effort: Some("xhigh".to_string()),
                unavailable_model_fallback: UnavailableModelFallback::FailClosed,
            },
        );
        let budget_config = SupervisorBudgetConfig::default();
        let consultant = SupervisorConsultantPlan::default();
        let assignment_metadata = AssignmentMetadata::new();
        let options = SupervisorRunOptions {
            repo: repo.clone(),
            plan_file: temp.path().join("plan.json"),
            run_id: RunId::new("direct-assignment-phases").expect("valid fixture run id"),
            parent_node: None,
            codex_bin: PathBuf::from("unused-codex"),
            runtime: SupervisorRuntime::Codex,
            allow_dirty_primary: false,
            allow_live_run_collision: false,
            admission_overrides: crate::supervise::SupervisorAdmissionConfig::default(),
            budget_overrides: crate::supervise::RunBudgetLimits::default(),
            budget_max_duration_seconds: None,
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
        let runtime_model_catalog = RuntimeModelCatalog::Codex(
            CodexRuntimeModelCatalog::from_slugs(["gpt-5.6-luna", "gpt-5.6-sol"])
                .expect("fixture runtime model catalog"),
        );
        let cancellation = ProcessCancellation::new();
        let mut journal = initialize_orchestration_event_journal(
            &repo,
            &options.run_id,
            options.parent_node.as_deref(),
        );
        let mut autonomy_kpis = AutonomyKpiCollector::default();
        let artifacts = Mutex::new(SharedSupervisorArtifacts {
            writer: &mut artifact_writer,
            journal: &mut journal,
            autonomy_kpis: &mut autonomy_kpis,
            checkpoint: None,
        });
        let runner = |command: &ExternalAgentCommand,
                      _cancellation: &ProcessCancellation,
                      _review: Option<ExternalPreActionReviewRuntime<'_>>| {
            let mut report_command = command.clone();
            report_command.model = None;
            let mut run = deterministic_fake_child_run(
                &report_command,
                &assignment,
                &assignment_metadata,
                1,
                None,
            )
            .expect("fixture child report");
            run.process_tree = Some(ProcessTreeEvidence::VerifiedEmpty(
                crate::process_runner::ContainmentBackend::SystemdUserService,
            ));
            run.side_effects = Some(SideEffectConfinementEvidence::Verified(
                crate::process_runner::SideEffectConfinementProfileKind::ExternalCodex,
            ));
            run.publishable = true;
            run.program_trust = ExternalProgramTrust::TrustedSystemCodex;
            run.codex_permissions = Some(crate::external_agent::CodexPermissionEvidence {
                codex_version: "0.142.3".to_string(),
                minimum_version: "0.138.0".to_string(),
                permission_profile: "maco_external_codex".to_string(),
                workspace_access: command.workspace_access,
                network_enabled: false,
                argv_digest: "fixture-digest".to_string(),
                executable_identity: "fixture-identity".to_string(),
            });
            run
        };
        let mut launch_budget_policy = AssignmentBudgetPolicy::default();
        launch_budget_policy.set_selector_binding_for_test(
            AgentRole::ChildOrchestrator,
            SupervisorRuntime::Codex,
            RoleModelSelection {
                model: Some("gpt-5.6-sol".to_string()),
                reasoning_effort: Some("xhigh".to_string()),
                unavailable_model_fallback: UnavailableModelFallback::FailClosed,
            },
        );
        assert_eq!(
            effective_role_model_selection(&plan, AgentRole::ChildOrchestrator)
                .model
                .as_deref(),
            Some("gpt-5.6-luna")
        );
        let context = AssignmentExecutionContext {
            index: 0,
            concurrent_mode: false,
            plan: &plan,
            requested_plan: &plan,
            execution_target: None,
            budget_config: &budget_config,
            consultant: &consultant,
            assignment_metadata: &assignment_metadata,
            assignment: &assignment,
            evidence_only_reaudit: None,
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
            budget_policy: launch_budget_policy,
            admission_commit: None,
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
        fs::create_dir_all(&dirs.schemas).expect("create direct phase schema directory");
        fs::write(&auditor_schema_path, "{\"type\":\"object\"}\n")
            .expect("materialize direct phase auditor schema");
        let prepared = match prepare_child_attempt(
            &context,
            &mut outcome,
            &context.budget_policy,
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
        assert_eq!(prepared.command.model.as_deref(), Some("gpt-5.6-sol"));
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
        assert_eq!(
            collected.model_provenance.configured_model.as_deref(),
            Some("gpt-5.6-sol")
        );
        assert_eq!(
            collected.model_provenance.launched_model.as_deref(),
            Some("gpt-5.6-sol")
        );
        let completed_launch_model_provenance = collected.model_provenance.clone();
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
        child_report.audit_reports.push(AuditorReport {
            id: review_lens_auditor_id(&assignment, 0),
            role: AgentRole::Auditor,
            reviewed_worker_ids: Vec::new(),
            reviewed_paths: assignment.assigned_paths.clone(),
            commands_run: Vec::new(),
            environment_failures: Vec::new(),
            validation_results: vec![ValidationResult {
                name: "fixture auditor validation".to_string(),
                status: ReviewStatus::Succeeded,
                command: Vec::new(),
                message: None,
            }],
            findings: Vec::new(),
            rejection_kind: None,
            no_further_delegation: Some(true),
            read_only: true,
            accepted: true,
            rejected: false,
            status: ReviewStatus::Succeeded,
            remaining_risk: "none".to_string(),
            next_safe_action: "publish".to_string(),
        });
        publish_assignment_report(
            &context,
            &mut outcome,
            &preflight,
            Some(&completed_launch_model_provenance),
            options.run_id.as_str(),
            &final_report_relative,
            &final_report_path,
            child_report,
            None,
            true,
        )
        .expect("direct final publication invocation");
        assert!(outcome.report.is_some());
        assert_eq!(outcome.command_records.len(), 1);
        assert!(!outcome.external_containment_failed);
        let journal_contents =
            fs::read_to_string(run_dir.join(crate::orchestration_event::ORCHESTRATION_EVENT_PATH))
                .expect("read direct phase orchestration journal");
        let transition = journal_contents
            .lines()
            .map(|line| {
                serde_json::from_str::<crate::orchestration_event::OrchestrationEvent>(line)
                    .expect("parse direct phase orchestration event")
            })
            .find_map(|event| {
                event
                    .payload
                    .get(crate::hierarchy_ledger::ROLE_TRANSITION_FIELD)
                    .cloned()
            })
            .expect("publication must record a role transition");
        assert_eq!(transition["decision"], "granted");
        assert_eq!(transition["reason"], "granted_promotion");
    }

    #[test]
    fn supervise_dispatch_refuses_a_missing_staging_cleanup_binding() {
        let options = SupervisorRunOptions {
            repo: PathBuf::from("/unused/repo"),
            plan_file: PathBuf::from("/unused/plan.json"),
            run_id: RunId::new("missing-machine-global-binding").expect("valid run id"),
            parent_node: None,
            codex_bin: PathBuf::from("unused-codex"),
            runtime: SupervisorRuntime::Codex,
            allow_dirty_primary: false,
            allow_live_run_collision: false,
            admission_overrides: crate::supervise::SupervisorAdmissionConfig::default(),
            budget_overrides: crate::supervise::RunBudgetLimits::default(),
            budget_max_duration_seconds: None,
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
            parent_node: None,
            codex_bin: agent.clone(),
            runtime: SupervisorRuntime::Codex,
            allow_dirty_primary: false,
            allow_live_run_collision: false,
            admission_overrides: crate::supervise::SupervisorAdmissionConfig::default(),
            budget_overrides: crate::supervise::RunBudgetLimits::default(),
            budget_max_duration_seconds: None,
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

    fn launch_fixture_command() -> ExternalAgentCommand {
        ExternalAgentCommand::codex(
            Path::new("unused-codex"),
            Path::new("/tmp/work"),
            Path::new("prompt.txt"),
            Path::new("log.jsonl"),
            Path::new("out.txt"),
            Duration::from_secs(1),
        )
    }

    fn quota_runtime_config(runtimes: &[&str]) -> crate::optimizer::quota_pools::QuotaConfig {
        use crate::optimizer::quota_pools::{
            AccountId, EntitlementDescriptor, ExhaustionBehavior, NominalCapacity, PoolKind,
            QuotaConfig, RateLimits, ResetWindow, QUOTA_CONFIG_VERSION,
        };
        QuotaConfig {
            version: QUOTA_CONFIG_VERSION,
            pools: runtimes
                .iter()
                .map(|runtime| EntitlementDescriptor {
                    runtime: crate::optimizer::ids::RuntimeSlug::new(*runtime)
                        .expect("quota runtime"),
                    account: AccountId::new(format!("{runtime}-account")).expect("quota account"),
                    pool_kind: PoolKind::Metered,
                    window: ResetWindow::None,
                    nominal_capacity: NominalCapacity::Unknown,
                    rate_limits: RateLimits::default(),
                    priority_tier: None,
                    exhaustion_behavior: ExhaustionBehavior::FailClosed,
                    authorized_alternatives: Vec::new(),
                    declared_list_price_microunits: Some(1),
                })
                .collect(),
        }
    }

    fn quota_usage_command(root: &Path) -> ExternalAgentCommand {
        ExternalAgentCommand::codex(
            Path::new("unused-codex"),
            root,
            root.join("prompt.txt"),
            root.join("usage.jsonl"),
            root.join("output.json"),
            Duration::from_secs(1),
        )
    }

    fn launch_fixture_options(runtime: SupervisorRuntime) -> SupervisorRunOptions {
        SupervisorRunOptions {
            repo: PathBuf::from("."),
            plan_file: PathBuf::from("plan.json"),
            run_id: RunId::new("selected-runtime-launch").expect("valid run id"),
            parent_node: None,
            codex_bin: PathBuf::from("unused-codex"),
            runtime,
            allow_dirty_primary: false,
            allow_live_run_collision: false,
            admission_overrides: SupervisorAdmissionConfig::default(),
            budget_overrides: RunBudgetLimits::default(),
            budget_max_duration_seconds: None,
            machine_global_retention: None,
        }
    }

    fn phase_fixture_assignment(id: &str, phase: AssignmentPhase) -> OrchestratorAssignment {
        OrchestratorAssignment {
            id: id.to_string(),
            phase,
            runtime: None,
            role: AgentRole::ChildOrchestrator,
            role_category: None,
            selection_source: None,
            assigned_paths: vec![PathBuf::from("README.md")],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            task: None,
            worker_assignments: Vec::new(),
            environment_requirements: Vec::new(),
            licensed_breakage: None,
            notes: None,
        }
    }

    #[test]
    fn typed_assignment_phase_selects_workspace_access_independent_of_id() {
        let planning = phase_fixture_assignment("execution-looking-id", AssignmentPhase::Planning);
        let planning_schedule = [AssignmentScheduleEntry {
            assignment_id: planning.id.clone(),
            parent_assignment_id: None,
            depth: MIN_SUPERVISOR_DEPTH,
            flattened_index: 0,
        }];
        let planning_phase =
            validated_assignment_phase_for_launch(&planning, 0, &planning_schedule)
                .expect("planning assignment is bound to its validated schedule entry");
        let planning_command = configure_assignment_phase_command(
            launch_fixture_command(),
            planning_phase,
            &planning.assigned_paths,
        )
        .expect("planning command is read-only");
        assert_eq!(planning_command.workspace_access, WorkspaceAccess::ReadOnly);
        assert!(planning_command.worktree_control_exceptions.is_empty());

        let execution = phase_fixture_assignment("planning-looking-id", AssignmentPhase::Execution);
        let execution_schedule = [AssignmentScheduleEntry {
            assignment_id: execution.id.clone(),
            parent_assignment_id: None,
            depth: MIN_SUPERVISOR_DEPTH,
            flattened_index: 0,
        }];
        let execution_phase =
            validated_assignment_phase_for_launch(&execution, 0, &execution_schedule)
                .expect("execution assignment is bound to its validated schedule entry");
        let execution_command = configure_assignment_phase_command(
            launch_fixture_command(),
            execution_phase,
            &execution.assigned_paths,
        )
        .expect("execution command retains bounded writes");
        assert_eq!(
            execution_command.workspace_access,
            WorkspaceAccess::ReadWrite
        );
        assert!(execution_command.worktree_control_exceptions.is_empty());
    }

    #[test]
    fn assignment_phase_launch_rejects_schedule_id_mismatch() {
        let assignment = phase_fixture_assignment("child-a", AssignmentPhase::Planning);
        let schedule = [AssignmentScheduleEntry {
            assignment_id: "child-b".to_string(),
            parent_assignment_id: None,
            depth: MIN_SUPERVISOR_DEPTH,
            flattened_index: 0,
        }];
        let error = validated_assignment_phase_for_launch(&assignment, 0, &schedule)
            .expect_err("mismatched schedule identity must fail closed");
        assert!(error
            .to_string()
            .contains("not bound to its validated schedule entry"));
    }

    #[test]
    fn assignment_phase_launch_rejects_schedule_index_mismatch() {
        let assignment = phase_fixture_assignment("child-a", AssignmentPhase::Planning);
        let schedule = [AssignmentScheduleEntry {
            assignment_id: assignment.id.clone(),
            parent_assignment_id: None,
            depth: MIN_SUPERVISOR_DEPTH,
            flattened_index: 1,
        }];
        let error = validated_assignment_phase_for_launch(&assignment, 0, &schedule)
            .expect_err("mismatched flattened index must fail closed");
        assert!(error
            .to_string()
            .contains("not bound to its validated schedule entry"));
    }

    fn worker_plan(model: &str) -> SupervisorPlan {
        let mut plan = SupervisorPlan {
            version: SUPERVISOR_SCHEMA_VERSION,
            task: "selected runtime launch".to_string(),
            task_file: None,
            max_depth: MIN_SUPERVISOR_DEPTH,
            max_child_assignments: 1,
            max_child_retries: 0,
            max_gate_corrections: 0,
            child_timeout_seconds: DEFAULT_CHILD_TIMEOUT_SECONDS,
            semantic_coordination: SemanticCoordinationMode::Off,
            role_models: BTreeMap::new(),
            model_pricing: BTreeMap::new(),
            review_lenses: default_supervisor_review_lenses(),
            review_aggregation_policy: ReviewAggregationPolicy::AllMustAccept,
            assignments: Vec::new(),
        };
        plan.role_models.insert(
            AgentRole::Worker,
            RoleModelSelection {
                model: Some(model.to_string()),
                reasoning_effort: Some("high".to_string()),
                unavailable_model_fallback: UnavailableModelFallback::FailClosed,
            },
        );
        plan
    }

    fn valid_child_plan_with_nested_worker() -> Result<SupervisorPlan> {
        let assignment = OrchestratorAssignment {
            id: "child-with-worker".to_string(),
            phase: AssignmentPhase::Execution,
            runtime: None,
            role: AgentRole::ChildOrchestrator,
            role_category: None,
            selection_source: None,
            assigned_paths: vec![PathBuf::from("README.md")],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            task: None,
            worker_assignments: vec![WorkerAssignment {
                id: "nested-worker".to_string(),
                role: AgentRole::Worker,
                role_category: None,
                selection_source: None,
                assigned_paths: vec![PathBuf::from("README.md")],
                semantic_symbols: Vec::new(),
                semantic_modules: Vec::new(),
                task: None,
                environment_requirements: Vec::new(),
                report_path: None,
            }],
            environment_requirements: Vec::new(),
            licensed_breakage: None,
            notes: None,
        };
        let mut plan = worker_plan("gpt-5.6-codex");
        plan.assignments = vec![assignment];
        let metadata = SupervisorPlanMetadata {
            assignment_schedule: vec![AssignmentScheduleEntry {
                assignment_id: "child-with-worker".to_string(),
                parent_assignment_id: None,
                depth: MIN_SUPERVISOR_DEPTH,
                flattened_index: 0,
            }],
            ..SupervisorPlanMetadata::default()
        };
        validate_supervisor_plan(plan, metadata).map(|(plan, _)| plan)
    }

    #[test]
    fn only_verified_confinement_admits_worktree_writes_and_primary_stays_refused() {
        assert!(SupervisorRuntime::Codex
            .capabilities()
            .admits_worktree_writable());
        for runtime in [
            SupervisorRuntime::Grok,
            SupervisorRuntime::Cursor,
            SupervisorRuntime::ClaudeCode,
            SupervisorRuntime::GeminiCli,
        ] {
            assert!(!runtime.capabilities().admits_worktree_writable());
            assert_eq!(
                crate::runtime_adapter::AdapterId::from_runtime(runtime)
                    .writable_leaf_launch_refusal(),
                Some("side_effect_confinement != verified")
            );
        }
        assert!(!SupervisorRuntime::Codex
            .capabilities()
            .admits_writable_release());
        assert!(!SupervisorRuntime::Fake
            .capabilities()
            .admits_worktree_writable());
        assert_eq!(
            crate::runtime_adapter::AdapterId::Fake.writable_leaf_launch_refusal(),
            Some("writable_workspace == unsupported")
        );
        let worktree = launch_fixture_command();
        assert_eq!(
            worktree.writable_launch_target,
            crate::runtime_adapter::WritableLaunchTarget::ManagedChildWorktree
        );
        assert_eq!(
            crate::runtime_adapter::AdapterId::Codex
                .writable_launch_refusal(worktree.writable_launch_target),
            None
        );
        assert!(worktree.hidden_roots.is_empty());
        assert!(
            !requires_hosted_pre_action_review(&worktree),
            "managed-worktree Codex must use native workspace-write instead of optional duplex review"
        );
        let evidence_reaudit = worktree
            .clone()
            .with_workspace_access(WorkspaceAccess::ReadOnly);
        assert!(requires_hosted_pre_action_review(&evidence_reaudit));
        let primary = launch_fixture_command().with_writable_launch_target(
            crate::runtime_adapter::WritableLaunchTarget::PrimaryWorktree,
        );
        assert_eq!(
            crate::runtime_adapter::AdapterId::Codex
                .writable_launch_refusal(primary.writable_launch_target),
            Some("blocking_pre_action_callback != All")
        );
        assert!(requires_hosted_pre_action_review(&primary));
    }

    #[test]
    fn worktree_writable_admission_requires_all_three_authenticated_factors() {
        let assigned_paths = vec![PathBuf::from("README.md")];
        let worktree = WorktreeRecord {
            name: "child-a".to_string(),
            path: PathBuf::from("/tmp/work"),
            branch: "maco/child-a".to_string(),
        };
        let claim = PathClaim {
            token: crate::sync::ClaimToken::from_u64(7),
            agent_id: "child-a".to_string(),
            paths: assigned_paths.clone(),
        };
        let command = launch_fixture_command();

        let admission = worktree_writable_admission_record(
            "child-a",
            &assigned_paths,
            2,
            &worktree,
            &claim,
            std::slice::from_ref(&claim),
            &command,
            SupervisorRuntime::Codex,
            AssignmentPhase::Execution,
        )
        .expect("all three factors admit the managed worktree")
        .expect("writable managed worktree produces admission evidence");
        assert_eq!(
            admission,
            crate::external_agent::WorktreeWritableAdmission {
                version: crate::external_agent::WORKTREE_WRITABLE_ADMISSION_SCHEMA_VERSION,
                assignment_id: "child-a".to_string(),
                attempt: 2,
                target: crate::runtime_adapter::WritableLaunchTarget::ManagedChildWorktree,
                worktree: crate::external_agent::ManagedWorktreeAdmission {
                    kind: crate::external_agent::ManagedWorktreeAdmissionKind::ManagedDisposable,
                    worktree_id: "child-a".to_string(),
                },
                claims: crate::external_agent::HeldPathClaimsAdmission {
                    state: crate::external_agent::HeldPathClaimsAdmissionState::Held,
                    token: 7,
                    paths: assigned_paths.clone(),
                },
                native_sandbox: crate::external_agent::NativeSandboxAdmission {
                    runtime: SupervisorRuntime::Codex,
                    workspace_access: WorkspaceAccess::ReadWrite,
                    side_effect_confinement:
                        crate::runtime_adapter::SideEffectConfinement::Verified,
                },
            }
        );

        let mut serialized = serde_json::to_value(&admission).expect("serialize admission");
        serialized
            .as_object_mut()
            .expect("admission is an object")
            .insert("untrusted".to_string(), serde_json::Value::Bool(true));
        assert!(
            serde_json::from_value::<crate::external_agent::WorktreeWritableAdmission>(serialized)
                .is_err(),
            "typed admission evidence must reject unknown fields"
        );

        let primary = command.clone().with_writable_launch_target(
            crate::runtime_adapter::WritableLaunchTarget::PrimaryWorktree,
        );
        assert!(worktree_writable_admission_record(
            "child-a",
            &assigned_paths,
            2,
            &worktree,
            &claim,
            std::slice::from_ref(&claim),
            &primary,
            SupervisorRuntime::Codex,
            AssignmentPhase::Execution,
        )
        .expect("primary targets use the separate universal callback gate")
        .is_none());

        let missing_claim = worktree_writable_admission_record(
            "child-a",
            &assigned_paths,
            2,
            &worktree,
            &claim,
            &[],
            &command,
            SupervisorRuntime::Codex,
            AssignmentPhase::Execution,
        )
        .expect_err("an unauthenticated claim must fail closed");
        assert!(format!("{missing_claim:#}").contains("not held in authenticated state"));

        let mismatched_worktree = WorktreeRecord {
            name: "unmanaged-child".to_string(),
            ..worktree.clone()
        };
        let worktree_error = worktree_writable_admission_record(
            "child-a",
            &assigned_paths,
            2,
            &mismatched_worktree,
            &claim,
            std::slice::from_ref(&claim),
            &command,
            SupervisorRuntime::Codex,
            AssignmentPhase::Execution,
        )
        .expect_err("a mismatched worktree binding must fail closed");
        assert!(format!("{worktree_error:#}").contains("managed worktree"));

        let confinement_error = worktree_writable_admission_record(
            "child-a",
            &assigned_paths,
            2,
            &worktree,
            &claim,
            std::slice::from_ref(&claim),
            &command,
            SupervisorRuntime::Cursor,
            AssignmentPhase::Execution,
        )
        .expect_err("unverified native confinement must fail closed");
        assert!(format!("{confinement_error:#}").contains("verified native sandbox admission"));
    }

    #[test]
    fn planning_phase_never_produces_writable_admission() {
        let assigned_paths = vec![PathBuf::from("README.md")];
        let worktree = WorktreeRecord {
            name: "planning-child".to_string(),
            path: PathBuf::from("/tmp/work"),
            branch: "maco/planning-child".to_string(),
        };
        let claim = PathClaim {
            token: crate::sync::ClaimToken::from_u64(7),
            agent_id: "planning-child".to_string(),
            paths: assigned_paths.clone(),
        };
        let read_only = launch_fixture_command().with_workspace_access(WorkspaceAccess::ReadOnly);
        assert!(worktree_writable_admission_record(
            "planning-child",
            &assigned_paths,
            1,
            &worktree,
            &claim,
            std::slice::from_ref(&claim),
            &read_only,
            SupervisorRuntime::Codex,
            AssignmentPhase::Planning,
        )
        .expect("read-only planning launch requires no writable admission")
        .is_none());

        let error = worktree_writable_admission_record(
            "planning-child",
            &assigned_paths,
            1,
            &worktree,
            &claim,
            std::slice::from_ref(&claim),
            &launch_fixture_command(),
            SupervisorRuntime::Codex,
            AssignmentPhase::Planning,
        )
        .expect_err("planning phase must reject writable workspace admission");
        assert!(error
            .to_string()
            .contains("attempted to request writable workspace admission"));
    }

    #[test]
    fn codex_binds_compatible_output_schema_without_weakening_local_schema() -> Result<()> {
        let schema = Path::new("/hidden-primary/schemas/orchestrator-review-report.schema.json");
        let worker_schema = Path::new("/hidden-primary/schemas/worker.json");
        let auditor_schema = Path::new("/hidden-primary/schemas/auditor.json");
        let schemas = [schema, worker_schema, auditor_schema];
        let codex = bind_runtime_read_only_schema_files(
            bind_runtime_output_schema(launch_fixture_command(), SupervisorRuntime::Codex, schema)?,
            SupervisorRuntime::Codex,
            &schemas,
        );
        assert_eq!(
            codex.output_schema.as_deref(),
            Some(Path::new(
                "/hidden-primary/schemas/orchestrator-review-report.codex-output.schema.json"
            ))
        );
        assert_eq!(
            codex.read_only_input_files,
            schemas
                .iter()
                .map(|path| path.to_path_buf())
                .collect::<Vec<_>>()
        );

        for runtime in [
            SupervisorRuntime::Grok,
            SupervisorRuntime::Cursor,
            SupervisorRuntime::ClaudeCode,
            SupervisorRuntime::GeminiCli,
        ] {
            let adapter = bind_runtime_read_only_schema_files(
                bind_runtime_output_schema(launch_fixture_command(), runtime, schema)?,
                runtime,
                &schemas,
            );
            assert!(
                adapter.output_schema.is_none(),
                "{runtime:?} must not inherit Codex-only output schema staging"
            );
            assert_eq!(
                adapter.read_only_input_files,
                schemas
                    .iter()
                    .map(|path| path.to_path_buf())
                    .collect::<Vec<_>>()
            );
        }

        let fake = bind_runtime_read_only_schema_files(
            bind_runtime_output_schema(launch_fixture_command(), SupervisorRuntime::Fake, schema)?,
            SupervisorRuntime::Fake,
            &schemas,
        );
        assert_eq!(fake.output_schema.as_deref(), Some(schema));
        assert!(fake.read_only_input_files.is_empty());
        Ok(())
    }

    #[test]
    fn supervise_plan_parses_claude_code_but_managed_writes_remain_refused() -> Result<()> {
        let assignment: OrchestratorAssignment = serde_json::from_str(
            r#"{
                "id": "worker-claude",
                "phase": "execution",
                "runtime": "claude-code",
                "role": "worker",
                "assigned_paths": ["README.md"]
            }"#,
        )?;
        assert_eq!(assignment.runtime, Some(SupervisorRuntime::ClaudeCode));
        assert_eq!(
            SupervisorRuntime::ClaudeCode
                .capabilities()
                .writable_refusal(),
            Some("blocking_pre_action_callback != All")
        );
        assert!(!SupervisorRuntime::ClaudeCode
            .capabilities()
            .admits_writable_release());
        assert!(!SupervisorRuntime::ClaudeCode
            .capabilities()
            .admits_worktree_writable());
        assert_eq!(
            crate::runtime_adapter::AdapterId::from_runtime(SupervisorRuntime::ClaudeCode)
                .writable_leaf_launch_refusal(),
            Some("side_effect_confinement != verified")
        );
        Ok(())
    }

    #[test]
    fn supervise_plan_parses_gemini_cli_but_managed_writes_remain_refused() -> Result<()> {
        let assignment: OrchestratorAssignment = serde_json::from_str(
            r#"{
                "id": "worker-gemini",
                "phase": "execution",
                "runtime": "gemini-cli",
                "role": "worker",
                "assigned_paths": ["README.md"]
            }"#,
        )?;
        assert_eq!(assignment.runtime, Some(SupervisorRuntime::GeminiCli));
        assert_eq!(
            SupervisorRuntime::GeminiCli
                .capabilities()
                .writable_refusal(),
            Some("blocking_pre_action_callback != All")
        );
        assert!(!SupervisorRuntime::GeminiCli
            .capabilities()
            .admits_writable_release());
        assert!(!SupervisorRuntime::GeminiCli
            .capabilities()
            .admits_worktree_writable());
        assert_eq!(
            crate::runtime_adapter::AdapterId::from_runtime(SupervisorRuntime::GeminiCli)
                .writable_leaf_launch_refusal(),
            Some("side_effect_confinement != verified")
        );
        Ok(())
    }

    #[test]
    fn retry_selector_binding_routes_a_nested_worker_without_changing_the_child_runtime(
    ) -> Result<()> {
        let plan = valid_child_plan_with_nested_worker()?;
        let assignment = &plan.assignments[0];
        let options = launch_fixture_options(SupervisorRuntime::Codex);
        let mut active_policy = AssignmentBudgetPolicy::default();
        let enclosing_child_runtime =
            assignment_launch_runtime(assignment, &options, &active_policy);
        assert_eq!(enclosing_child_runtime, SupervisorRuntime::Codex);
        assert_eq!(
            nested_worker_launch_runtime(enclosing_child_runtime, &active_policy),
            SupervisorRuntime::Codex
        );

        active_policy.set_selector_binding_for_test(
            AgentRole::Worker,
            SupervisorRuntime::Cursor,
            RoleModelSelection {
                model: Some("composer-2.5".to_string()),
                reasoning_effort: Some("high".to_string()),
                unavailable_model_fallback: UnavailableModelFallback::FailClosed,
            },
        );
        let retry_plan = active_policy.apply(&plan);
        assert_eq!(
            assignment_launch_runtime(assignment, &options, &active_policy),
            SupervisorRuntime::Codex
        );
        assert_eq!(
            nested_worker_launch_runtime(enclosing_child_runtime, &active_policy),
            SupervisorRuntime::Cursor
        );
        let worker_selection = effective_role_model_selection(&retry_plan, AgentRole::Worker);
        assert_eq!(worker_selection.model.as_deref(), Some("composer-2.5"));
        assert_eq!(worker_selection.reasoning_effort.as_deref(), Some("high"));
        Ok(())
    }

    #[test]
    fn assignment_launch_uses_selected_runtime_pair_not_run_global() -> Result<()> {
        let mut assignment = OrchestratorAssignment {
            id: "worker-a".to_string(),
            phase: AssignmentPhase::Execution,
            runtime: Some(SupervisorRuntime::Cursor),
            role: AgentRole::Worker,
            role_category: None,
            selection_source: None,
            assigned_paths: vec![PathBuf::from("README.md")],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            task: None,
            worker_assignments: Vec::new(),
            environment_requirements: Vec::new(),
            licensed_breakage: None,
            notes: None,
        };
        let options = launch_fixture_options(SupervisorRuntime::Codex);
        let budget_policy = AssignmentBudgetPolicy::default();
        assert_eq!(
            assignment_launch_runtime(&assignment, &options, &budget_policy),
            SupervisorRuntime::Cursor
        );
        assignment.runtime = Some(SupervisorRuntime::ClaudeCode);
        assignment.role = AgentRole::Worker;
        assert_eq!(
            assignment_launch_runtime(&assignment, &options, &budget_policy),
            SupervisorRuntime::ClaudeCode
        );
        Ok(())
    }

    #[test]
    fn admission_consumes_stored_category_and_refuses_luna_coordinator() -> Result<()> {
        let mut assignment = OrchestratorAssignment {
            id: "leaf-worker".to_string(),
            phase: AssignmentPhase::Execution,
            runtime: None,
            role: AgentRole::Worker,
            role_category: None,
            selection_source: None,
            assigned_paths: vec![PathBuf::from("README.md")],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            task: None,
            worker_assignments: Vec::new(),
            environment_requirements: Vec::new(),
            licensed_breakage: None,
            notes: None,
        };
        assignment.role_category = Some(RoleCategory::DelegatingCoordinator);
        assignment.selection_source = Some(AssignmentSelectionSource::OperatorOverride);
        let mut plan = SupervisorPlan {
            version: SUPERVISOR_SCHEMA_VERSION,
            task: "admit stored category".to_string(),
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
        plan.role_models.insert(
            AgentRole::Worker,
            RoleModelSelection {
                model: Some("gpt-5.6-luna".to_string()),
                reasoning_effort: Some("high".to_string()),
                unavailable_model_fallback: UnavailableModelFallback::FailClosed,
            },
        );
        let catalog = RuntimeModelCatalog::Codex(
            CodexRuntimeModelCatalog::from_slugs(["gpt-5.6-luna", "gpt-5.6-sol"])
                .context("fixture catalog")?,
        );
        let options = launch_fixture_options(SupervisorRuntime::Codex);
        let budget_policy = AssignmentBudgetPolicy::default();
        let error = bind_selected_assignment_launch_for_test(
            launch_fixture_command(),
            &assignment,
            &budget_policy,
            &plan,
            &options,
            &catalog,
        )
        .expect_err("luna cannot hold coordinator category at admission");
        let message = format!("{error:#}");
        assert!(
            message.contains("ineligible by measured catalog/evidence")
                || message.contains("cannot hold")
                || message.contains("refused at execution admission"),
            "{message}"
        );

        assignment.role_category = Some(RoleCategory::NonDelegatingTerminalWorker);
        assignment.selection_source = None;
        plan.assignments[0] = assignment.clone();
        bind_selected_assignment_launch_for_test(
            launch_fixture_command(),
            &assignment,
            &budget_policy,
            &plan,
            &options,
            &catalog,
        )
        .context("luna remains eligible for a terminal worker category")?;
        Ok(())
    }

    #[test]
    fn auditor_runtime_override_preserves_active_heterogeneous_lens_contract() -> Result<()> {
        let mut plan = valid_child_plan_with_nested_worker()?;
        let (initial_model, initial_effort) = match &plan.review_lenses[0].backend {
            ReviewLensBackendConfig::Model {
                model,
                reasoning_effort,
                ..
            } => (model.clone(), reasoning_effort.clone()),
            ReviewLensBackendConfig::Precomputed { .. } => {
                bail!("default review lens must be model-backed")
            }
        };
        plan.role_models.insert(
            AgentRole::Auditor,
            RoleModelSelection {
                model: Some(initial_model),
                reasoning_effort: initial_effort,
                unavailable_model_fallback: UnavailableModelFallback::FailClosed,
            },
        );
        plan.review_lenses.push(ReviewLensConfig {
            id: "custom-heterogeneous-lens".to_string(),
            backend: ReviewLensBackendConfig::Model {
                backend_id: "custom-provider".to_string(),
                model: "custom-auditor-model".to_string(),
                reasoning_effort: Some("ultra".to_string()),
            },
            information_scope: ReviewInformationScope::OutputReportOnly,
        });
        let metadata = SupervisorPlanMetadata {
            assignment_schedule: vec![AssignmentScheduleEntry {
                assignment_id: "child-with-worker".to_string(),
                parent_assignment_id: None,
                depth: MIN_SUPERVISOR_DEPTH,
                flattened_index: 0,
            }],
            ..SupervisorPlanMetadata::default()
        };
        let _capability = install_test_fixture_models(&[
            (
                "selected-auditor-model",
                ModelCapabilityClass::CriticalJudgment,
            ),
            (
                "custom-auditor-model",
                ModelCapabilityClass::CriticalJudgment,
            ),
        ])?;
        let (plan, _) = validate_supervisor_plan(plan, metadata)?;
        let mut active_policy = AssignmentBudgetPolicy::default();
        let assignment_reasoning_effort = Some(ReasoningEffort::Low);
        active_policy.set_assignment_reasoning_effort_for_test(assignment_reasoning_effort);
        active_policy.set_selector_binding_for_test(
            AgentRole::Auditor,
            SupervisorRuntime::Codex,
            RoleModelSelection {
                model: Some("selected-auditor-model".to_string()),
                reasoning_effort: Some("xhigh".to_string()),
                unavailable_model_fallback: UnavailableModelFallback::FailClosed,
            },
        );
        let active_plan = active_policy.apply(&plan);
        assert_ne!(active_plan.review_lenses, plan.review_lenses);
        assert_eq!(active_plan.review_lenses.len(), 2);
        assert_eq!(
            active_plan.review_lenses[0].backend.model(),
            "selected-auditor-model"
        );
        assert_eq!(
            active_plan.review_lenses[0].backend.reasoning_effort(),
            Some("xhigh")
        );
        assert_eq!(
            active_plan.review_lenses[1].backend.model(),
            "custom-auditor-model"
        );
        assert_eq!(
            active_plan.review_lenses[1].backend.reasoning_effort(),
            Some("xhigh")
        );
        assert_eq!(
            active_policy.selected_runtime_for(AgentRole::Auditor),
            Some(SupervisorRuntime::Codex)
        );
        let catalog = RuntimeModelCatalog::Codex(CodexRuntimeModelCatalog::from_slugs([
            "selected-auditor-model",
            "custom-auditor-model",
        ])?);
        let incomplete_catalog =
            RuntimeModelCatalog::Codex(CodexRuntimeModelCatalog::from_slugs([
                "selected-auditor-model",
            ])?);
        let unavailable_error = validate_review_lens_runtime_selection(
            &active_plan.review_lenses[1],
            SupervisorRuntime::Codex,
            &incomplete_catalog,
        )
        .expect_err("runtime override must not bypass custom-lens catalog validation");
        assert!(unavailable_error
            .to_string()
            .contains("lens dispatch fails closed"));

        let sources = ReviewLensRequestSources {
            child_transcript: "retry transcript",
            diff: "retry diff",
            output_report: "retry output report",
        };
        let raw_custom_request = build_review_lens_request(&plan.review_lenses[1], sources)?;
        let assignment = &active_plan.assignments[0];
        let required_coverage = ReviewCoverageRequirement {
            worker_ids: vec!["nested-worker".to_string()],
            paths: vec![PathBuf::from("README.md")],
        };
        let mut requests = Vec::new();
        let mut verdicts = Vec::new();
        let mut usage_samples = Vec::new();
        for (lens_index, lens) in active_plan.review_lenses.iter().enumerate() {
            validate_review_lens_runtime_selection(lens, SupervisorRuntime::Codex, &catalog)?;
            let request = build_review_lens_request(lens, sources)?;
            if lens_index == 1 {
                assert_ne!(
                    request.request_binding, raw_custom_request.request_binding,
                    "the active request binding must seal the final assignment-clamped effort"
                );
            }
            let resolved_effort = resolve_reasoning_effort(
                AgentRole::Auditor,
                assignment_reasoning_effort,
                lens.backend.reasoning_effort(),
                0,
            );
            let rendered = render_review_lens_auditor_prompt(
                ReviewLensAuditorPromptContext {
                    assignment,
                    lens,
                    resolved_reasoning_effort: Some(&resolved_effort.resolved),
                    request: &request,
                    required_coverage: &required_coverage,
                },
                lens_index,
            )?;
            let command = bind_active_review_lens_command(
                launch_fixture_command(),
                lens,
                assignment_reasoning_effort,
                active_policy
                    .selected_runtime_for(AgentRole::Auditor)
                    .context("active auditor runtime override")?,
                &catalog,
            )?;
            assert!(rendered
                .prompt
                .contains(&format!("- Model: {}", lens.backend.model())));
            assert!(rendered
                .prompt
                .contains(&format!("- Reasoning effort: {}", resolved_effort.resolved)));
            assert_eq!(request.backend_id, lens.backend.backend_id());
            assert_eq!(request.model, lens.backend.model());
            assert_eq!(
                command.model_provider.as_deref(),
                Some(lens.backend.backend_id())
            );
            assert_eq!(command.model.as_deref(), Some(lens.backend.model()));
            assert_eq!(
                command.reasoning_effort.as_deref(),
                Some(resolved_effort.resolved.as_str())
            );
            let spawn_payload = parent_auditor_spawn_payload(
                &review_lens_auditor_id(assignment, lens_index),
                assignment,
                lens_index + 1,
                lens,
                &request,
                &command,
                SupervisorRuntime::Codex,
            )?;
            assert_eq!(spawn_payload["review_lens_id"], lens.id);
            assert_eq!(spawn_payload["backend_id"], lens.backend.backend_id());
            assert_eq!(spawn_payload["model"], lens.backend.model());
            assert_eq!(spawn_payload["reasoning_effort"], resolved_effort.resolved);
            assert_eq!(spawn_payload["runtime"], "codex");
            assert_eq!(spawn_payload["request_binding"], request.request_binding);
            usage_samples.push(RoleUsageSample {
                role: AgentRole::Auditor,
                lens_id: Some(lens.id.clone()),
                model: command.model.clone(),
                usage: Usage {
                    input_tokens: (lens_index + 1) * 10,
                    output_tokens: lens_index + 1,
                    total_tokens: (lens_index + 1) * 11,
                },
            });
            verdicts.push(ReviewLensVerdict::for_lens(
                lens,
                request.request_binding.clone(),
                ReviewLensVerdictStatus::Accept,
                ReviewLensCoverage {
                    worker_ids: required_coverage.worker_ids.clone(),
                    paths: required_coverage.paths.clone(),
                },
                vec![(
                    ReviewLensEvidenceKind::ModelReview,
                    format!("active heterogeneous lens {lens_index} reviewed"),
                )],
            )?);
            requests.push(request);
        }

        let aggregate = aggregate_active_parent_review_lenses(
            &active_plan,
            &requests,
            required_coverage,
            verdicts,
        )?;
        assert_eq!(aggregate.decision, ReviewAggregationDecision::Accept);
        assert_eq!(aggregate.policy, active_plan.review_aggregation_policy);
        assert_eq!(aggregate.lens_verdicts.len(), 2);
        assert_eq!(
            aggregate.lens_verdicts[0].lens.model,
            "selected-auditor-model"
        );
        assert_eq!(
            aggregate.lens_verdicts[1].lens.model,
            "custom-auditor-model"
        );
        let usage = role_usage_report(&active_plan, usage_samples)?;
        for lens in &active_plan.review_lenses {
            let report = usage
                .lens_reports
                .iter()
                .find(|report| report.lens_id == lens.id)
                .with_context(|| format!("final usage for lens '{}'", lens.id))?;
            assert_eq!(report.backend_id, lens.backend.backend_id());
            assert_eq!(report.model, lens.backend.model());
            assert_eq!(report.observation, RoleUsageObservation::ProcessObserved);
        }
        Ok(())
    }

    #[test]
    fn retry_selected_runtime_supersedes_the_assignment_initial_runtime() {
        let assignment = OrchestratorAssignment {
            id: "worker-retry".to_string(),
            phase: AssignmentPhase::Execution,
            runtime: Some(SupervisorRuntime::Codex),
            role: AgentRole::Worker,
            role_category: None,
            selection_source: None,
            assigned_paths: vec![PathBuf::from("README.md")],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            task: None,
            worker_assignments: Vec::new(),
            environment_requirements: Vec::new(),
            licensed_breakage: None,
            notes: None,
        };
        let options = launch_fixture_options(SupervisorRuntime::Codex);
        let mut retry_policy = AssignmentBudgetPolicy::default();
        retry_policy.set_selected_runtime_for_test(AgentRole::Worker, SupervisorRuntime::Cursor);

        assert_eq!(
            assignment_launch_runtime(&assignment, &options, &retry_policy),
            SupervisorRuntime::Cursor
        );
    }

    #[test]
    fn selected_cross_runtime_settlement_persists_only_the_actual_launch_pool() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let repo = temp.path().join("repo");
        Repository::init(&repo)?;
        let config = quota_runtime_config(&["codex", "cursor"]);
        let mut ledger = RunBudgetLedger::new(RunBudgetLimits::default())?;
        ledger.attach_quota_config(&repo, "cross-runtime", &config)?;
        let plan = worker_plan("composer-2.5");
        let budget = SupervisorBudgetConfig::default();
        let command = quota_usage_command(temp.path());
        let mut reservation =
            match reserve_dispatch_budget(&plan, &budget, &ledger, AgentRole::Worker, &command)? {
                DispatchBudgetAdmission::Admitted(reservation) => reservation,
                DispatchBudgetAdmission::Refused(refusal) => {
                    bail!("unexpected cross-runtime budget refusal: {refusal:?}")
                }
            };
        reservation.mark_invoked_for_runtime(SupervisorRuntime::Cursor)?;
        write_injected_usage(&command, 7, 3);
        let run = injected_verified_run(&command);
        let settlement = reservation.settle_bound_runtime(&run, &command)?;
        assert_eq!(
            settlement.reliable_usage().map(|usage| usage.total_tokens),
            Some(10)
        );
        drop(reservation);
        drop(ledger);

        let workspace = crate::budget_ledger::WorkspaceBudgetLedger::open_or_create(&repo)?;
        let now = crate::budget_ledger::unix_now()?;
        let codex = workspace.pool_usage(&config.pools[0].key(), now)?;
        let cursor = workspace.pool_usage(&config.pools[1].key(), now)?;
        assert_eq!(codex.tokens, 0);
        assert_eq!(codex.requests, 0);
        assert_eq!(cursor.tokens, 10);
        assert_eq!(cursor.requests, 1);
        Ok(())
    }

    #[test]
    fn invoked_drop_persists_missing_usage_to_retained_runtime_for_next_run() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let repo = temp.path().join("repo");
        Repository::init(&repo)?;
        let config = quota_runtime_config(&["cursor"]);
        let mut first = RunBudgetLedger::new(RunBudgetLimits::default())?;
        first.attach_quota_config(&repo, "drop-first", &config)?;
        let plan = worker_plan("composer-2.5");
        let budget = SupervisorBudgetConfig::default();
        let command = quota_usage_command(temp.path());
        let expected_tokens = budget
            .reservation_tokens(AgentRole::Worker)
            .context("worker reservation tokens")?;
        let mut reservation =
            match reserve_dispatch_budget(&plan, &budget, &first, AgentRole::Worker, &command)? {
                DispatchBudgetAdmission::Admitted(reservation) => reservation,
                DispatchBudgetAdmission::Refused(refusal) => {
                    bail!("unexpected dropped-dispatch budget refusal: {refusal:?}")
                }
            };
        reservation.mark_invoked_for_runtime(SupervisorRuntime::Cursor)?;
        drop(reservation);
        assert_eq!(first.report()?.active_reservations, 0);
        drop(first);

        let mut next = RunBudgetLedger::new(RunBudgetLimits::default())?;
        next.attach_quota_config(&repo, "drop-next", &config)?;
        let projected =
            next.quota_consumption_ledger(&config, crate::budget_ledger::unix_now()?)?;
        let entry = projected
            .entries
            .get(&config.pools[0].key())
            .context("next run must observe dropped invocation consumption")?;
        assert_eq!(entry.tokens, u64::try_from(expected_tokens)?);
        assert_eq!(entry.requests, 1);
        Ok(())
    }

    #[test]
    fn failed_durable_settlement_keeps_invoked_state_until_cleanup_succeeds() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let repo = temp.path().join("repo");
        Repository::init(&repo)?;
        let config = quota_runtime_config(&["codex"]);
        let mut ledger = RunBudgetLedger::new(RunBudgetLimits::default())?;
        ledger.attach_quota_config(&repo, "settlement-failure", &config)?;
        let plan = worker_plan("composer-2.5");
        let budget = SupervisorBudgetConfig::default();
        let command = quota_usage_command(temp.path());
        let mut reservation =
            match reserve_dispatch_budget(&plan, &budget, &ledger, AgentRole::Worker, &command)? {
                DispatchBudgetAdmission::Admitted(reservation) => reservation,
                DispatchBudgetAdmission::Refused(refusal) => {
                    bail!("unexpected settlement fixture refusal: {refusal:?}")
                }
            };
        reservation.mark_invoked_for_runtime(SupervisorRuntime::Cursor)?;
        write_injected_usage(&command, 1, 1);
        let run = injected_verified_run(&command);
        assert!(matches!(
            reservation.settle_bound_runtime(&run, &command),
            Err(error) if format!("{error:#}").contains("cursor")
        ));
        assert_eq!(
            reservation.state,
            DispatchBudgetReservationState::Invoked(SupervisorRuntime::Cursor)
        );

        ledger.release(reservation.reservation.id)?;
        reservation.state = DispatchBudgetReservationState::Settled;
        assert_eq!(ledger.report()?.active_reservations, 0);
        Ok(())
    }

    #[test]
    fn selected_runtime_prerender_fails_closed_on_empty_adapter_command() {
        let mut command = launch_fixture_command();
        command.runtime_adapter = Some(crate::runtime_adapter::RuntimeAdapterConfig {
            binary: Some(PathBuf::from("cursor-agent")),
            argument_template: Vec::new(),
            env_passthrough: Vec::new(),
            working_dir_flag: None,
            output_capture: crate::runtime_adapter::OutputCaptureMode::Stdout,
            feed_prompt_on_stdin: true,
        });
        let error = prerender_selected_runtime_adapter_command(&command, SupervisorRuntime::Cursor)
            .expect_err("empty adapter argv must fail closed");
        assert!(error.to_string().contains("empty adapter command"));
    }
}
