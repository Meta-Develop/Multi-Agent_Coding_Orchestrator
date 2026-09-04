use super::*;
use crate::{
    artifacts::repository_authenticator_key_only,
    follow_up_queue::{
        generated_follow_up_item_set_sha256, generated_follow_up_task_batch_sha256,
        GeneratedFollowUpDispatchObservation, GeneratedFollowUpQueue, GeneratedFollowUpQueueBounds,
        GeneratedFollowUpQueueEntrypoint, GeneratedFollowUpQueuePhase,
        GeneratedFollowUpQueueRootInput, GeneratedFollowUpQueueSource,
        GeneratedFollowUpRetentionBinding,
    },
    gate_denial::ApprovalReviewDenial,
    machine_global::MachineGlobalRetentionBinding,
    mutation_taxonomy::{
        EffectiveGeneratedFollowUpQueueManifestInput, EffectiveSupervisorDispatchIdentity,
        EffectiveSupervisorExecutionRuntime, EffectiveSupervisorMutationIdentityInput,
        EffectiveSupervisorMutationManifest, EffectiveSupervisorWorktreeMode,
    },
};
use std::io::Write;

const FOLLOW_UP_CASCADE_VERSION: u32 = 1;

pub(super) struct GeneratedQueueManifestContext<'a> {
    pub(super) source_run_id: &'a RunId,
    pub(super) source_plan_sha256: &'a str,
    pub(super) task_count: usize,
    pub(super) repository_identity: String,
    pub(super) primary_baseline_sha256: String,
    pub(super) retention_binding_sha256: String,
    pub(super) item_set_sha256: String,
    pub(super) task_batch_sha256: String,
    pub(super) outer_entrypoint: GeneratedFollowUpQueueEntrypoint,
    pub(super) outer_run_id: &'a str,
    pub(super) bounds_identity: String,
}

pub(super) fn effective_generated_follow_up_queue_mutation_manifest(
    context: GeneratedQueueManifestContext<'_>,
) -> EffectiveSupervisorMutationManifest {
    EffectiveSupervisorMutationManifest::generated_follow_up_queue(
        EffectiveGeneratedFollowUpQueueManifestInput {
            identity: EffectiveSupervisorMutationIdentityInput {
                run_id: context.source_run_id.as_str().to_string(),
                parent_node: None,
                normalized_plan_sha256: context.source_plan_sha256.to_string(),
                dispatch_identity: EffectiveSupervisorDispatchIdentity::GeneratedFollowUpQueue {
                    source_run_id: context.source_run_id.as_str().to_string(),
                    task_count: context.task_count,
                },
                execution_runtime: EffectiveSupervisorExecutionRuntime::Verified,
                worktree_mode: EffectiveSupervisorWorktreeMode::NotApplicable,
                runtime_adapter: None,
                repository_identity: context.repository_identity,
                artifact_family: "generated-follow-up-queue".to_string(),
                delivery_identity: context.bounds_identity,
                machine_global_retention_sha256: Some(context.retention_binding_sha256),
                queue_item_sha256: Some(context.item_set_sha256),
                task_batch_sha256: Some(context.task_batch_sha256),
                primary_baseline_sha256: Some(context.primary_baseline_sha256),
                outer_entrypoint: Some(context.outer_entrypoint.as_str().to_string()),
                outer_run_id: Some(context.outer_run_id.to_string()),
            },
        },
    )
}

pub(super) struct FollowUpCascadeInvocation<'a> {
    pub(super) outer_entrypoint: GeneratedFollowUpQueueEntrypoint,
    pub(super) outer_command_run_id: &'a RunId,
    pub(super) concurrency_policy: SupervisorConcurrencyPolicy,
    pub(super) runtime_catalog: FollowUpRuntimeCatalog,
}

#[derive(Clone, Copy)]
pub(super) enum FollowUpRuntimeCatalog {
    Production,
    #[cfg(test)]
    Injected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GeneratedFollowUpDispatchEvidence {
    NoDurableDispatchStart,
    DurableDispatchStart { observation: RoleUsageObservation },
}

/// Opaque proof that a finalized subordinate report was authenticated and its
/// normalized plan exactly matched one immutable queued follow-up item.
///
/// Only this module can construct the proof. The queue consumes it while
/// applying the private observation and acknowledgement reducers.
pub(crate) struct AuthenticatedGeneratedFollowUpTerminal {
    queue_instance_id: String,
    item_id: String,
    observation: GeneratedFollowUpDispatchObservation,
}

impl AuthenticatedGeneratedFollowUpTerminal {
    pub(crate) fn into_parts(self) -> (String, String, GeneratedFollowUpDispatchObservation) {
        (self.queue_instance_id, self.item_id, self.observation)
    }
}

enum FollowUpPreparation {
    Ready {
        plan_file: tempfile::NamedTempFile,
        loaded: Box<LoadedSupervisorPlan>,
    },
    Refused(GateDenial),
    Cancelled,
    EnvironmentFailed(EnvironmentFailure),
}

pub(super) fn source_only_cascade_outcome(
    source_report: SupervisorFinalReport,
) -> SupervisorCascadeOutcome {
    let follow_up_cascade_success =
        source_report.success && source_report.generated_follow_up_tasks.is_empty();
    SupervisorCascadeOutcome {
        source_report,
        follow_up_cascade_version: FOLLOW_UP_CASCADE_VERSION,
        follow_up_cascade_success,
        follow_up_primary_worktree_untouched: None,
        follow_up_queue: None,
        follow_up_reports: Vec::new(),
        follow_up_gate_denials: Vec::new(),
        follow_up_environment_failures: Vec::new(),
    }
}

pub(super) fn ensure_generated_follow_up_cascade_needs_resume(
    repo: &Path,
    source_loaded: &LoadedSupervisorPlan,
    source_report: &SupervisorFinalReport,
) -> Result<()> {
    let source_plan_sha256 = normalized_supervisor_plan_sha256(
        &source_loaded.plan,
        &source_loaded.consultant,
        &source_loaded.assignment_metadata,
        &source_loaded.plan_metadata,
    )?;
    verify_authenticated_source_basis(repo, source_loaded, source_report, &source_plan_sha256)?;
    if source_report.generated_follow_up_tasks.is_empty() {
        bail!(
            "supervise run '{}' already exists and has no generated follow-up queue to resume",
            source_report.run_id.as_str()
        );
    }
    let authenticator = repository_authenticator_key_only(repo)?;
    let Some(queue) = GeneratedFollowUpQueue::open_existing_for_source_execution(
        authenticator,
        source_report.run_id.as_str(),
        &source_plan_sha256,
    )?
    else {
        // A crash after source finalization but before queue creation is safe to
        // resume: the authenticated source report is the immutable enqueue basis.
        return Ok(());
    };
    let summary = queue.summary();
    let complete = summary.acknowledged_terminal == summary.capacity
        && summary.staged == 0
        && summary.enqueued == 0
        && summary.claimed == 0
        && summary.dispatch_started == 0
        && summary.dispatch_observed == 0
        && summary.held_ambiguous == 0;
    if complete {
        bail!(
            "supervise run '{}' already exists and its generated follow-up queue is complete",
            source_report.run_id.as_str()
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run_generated_follow_up_cascade(
    repo: &Path,
    source_loaded: &LoadedSupervisorPlan,
    source_report: SupervisorFinalReport,
    supervisor_template: &SupervisorRunOptions,
    invocation: FollowUpCascadeInvocation<'_>,
    caller_cancellation: Option<&ProcessCancellation>,
    cancellation_observed: &AtomicBool,
    before_dispatch: &mut dyn FnMut(&SupervisorPlan) -> Result<Option<GateDenial>>,
    external_runner: &CancellableExternalRunner<'_>,
) -> Result<SupervisorCascadeOutcome> {
    let source_plan_sha256 = normalized_supervisor_plan_sha256(
        &source_loaded.plan,
        &source_loaded.consultant,
        &source_loaded.assignment_metadata,
        &source_loaded.plan_metadata,
    )?;
    verify_authenticated_source_basis(repo, source_loaded, &source_report, &source_plan_sha256)?;
    observe_caller_cancellation(caller_cancellation, cancellation_observed);
    // Authentication precedes every early return. Resume is therefore bound
    // to the immutable finalized source artifact even when that source has no
    // generated work, failed, or was not publishable.
    if source_report.generated_follow_up_tasks.is_empty() {
        return Ok(source_only_cascade_outcome(source_report));
    }
    if !source_report.success || !source_report.accepted || !source_report.publishable {
        return Ok(source_only_cascade_outcome(source_report));
    }
    let primary_baseline =
        primary_worktree_snapshot_sha256(repo, SupervisorExecutionRuntime::Verified)?;
    let retention = supervisor_template
        .machine_global_retention
        .as_ref()
        .context(
            "generated follow-up cascade requires the inherited machine-global retention binding",
        )?;
    let retained_binding = match GeneratedFollowUpRetentionBinding::from_machine_global(retention) {
        Ok(binding) => binding,
        Err(error) => {
            let mut outcome = source_only_cascade_outcome(source_report);
            outcome.follow_up_cascade_success = false;
            outcome
                .follow_up_environment_failures
                .push(retention_probe_failure(&error));
            return Ok(outcome);
        }
    };
    let authenticator = repository_authenticator_key_only(repo)?;
    let repository_id = authenticator.binding().repository_id.clone();
    let existing_queue = GeneratedFollowUpQueue::open_existing_for_source_execution(
        repository_authenticator_key_only(repo)?,
        source_report.run_id.as_str(),
        &source_plan_sha256,
    )?;
    let (outer_entrypoint, outer_run_id) = existing_queue.as_ref().map_or_else(
        || {
            (
                invocation.outer_entrypoint,
                invocation.outer_command_run_id.as_str().to_string(),
            )
        },
        |inspection| {
            let source = inspection.snapshot().source();
            (
                source.outer_entrypoint(),
                source.outer_command_run_id().to_string(),
            )
        },
    );
    drop(existing_queue);
    let bounds = GeneratedFollowUpQueueBounds::from_validated_source_plan_and_tasks(
        &source_loaded.plan,
        &source_report.generated_follow_up_tasks,
    )?;
    let task_batch_sha256 =
        generated_follow_up_task_batch_sha256(&source_report.generated_follow_up_tasks)?;
    let item_set_sha256 =
        generated_follow_up_item_set_sha256(&source_report.generated_follow_up_tasks)?;
    let effective_queue_manifest =
        effective_generated_follow_up_queue_mutation_manifest(GeneratedQueueManifestContext {
            source_run_id: &source_report.run_id,
            source_plan_sha256: &source_plan_sha256,
            task_count: source_report.generated_follow_up_tasks.len(),
            repository_identity: repository_id.clone(),
            primary_baseline_sha256: primary_baseline.clone(),
            retention_binding_sha256: retained_binding.binding_sha256().to_string(),
            item_set_sha256,
            task_batch_sha256,
            outer_entrypoint,
            outer_run_id: &outer_run_id,
            bounds_identity: serde_json::to_string(&bounds)
                .context("failed to encode generated queue bounds identity")?,
        });
    let authorized_queue = authorize_effective_supervisor_manifest(effective_queue_manifest)?;
    let (effective_queue_evidence, queue_mutation_permit) =
        authorized_queue.into_generated_follow_up_queue()?;
    let source = GeneratedFollowUpQueueSource::root(GeneratedFollowUpQueueRootInput {
        source_supervisor_run_id: source_report.run_id.as_str().to_string(),
        source_normalized_plan_sha256: source_plan_sha256,
        effective_mutation_manifest_sha256: effective_queue_evidence
            .canonical_manifest_sha256()
            .to_string(),
        source_report_accepted: source_report.accepted,
        source_report_publishable: source_report.publishable,
        outer_entrypoint,
        outer_command_run_id: outer_run_id,
        repository_id,
        whole_primary_baseline_sha256: primary_baseline.clone(),
        machine_global_retention: retained_binding,
    })?;
    let mut queue = GeneratedFollowUpQueue::create_or_open_authorized(
        authenticator,
        source,
        bounds,
        queue_mutation_permit,
    )?;
    #[cfg(test)]
    record_queue_test_observation("created_or_opened", &queue, 0);
    if !queue.snapshot().enqueue_committed() {
        if queue.snapshot().staged_count() == 0 {
            queue.enqueue_all_before_dispatch(&source_report.generated_follow_up_tasks)?;
        } else {
            queue.complete_staged_batch(&source_report.generated_follow_up_tasks)?;
        }
    } else {
        queue.enqueue_all_before_dispatch(&source_report.generated_follow_up_tasks)?;
    }
    #[cfg(test)]
    record_queue_test_observation("enqueued", &queue, 0);
    #[cfg(test)]
    interrupt_after_follow_up_enqueue()?;

    queue.release_claimed_before_dispatch()?;
    let mut follow_up_reports = Vec::new();
    let mut authenticated_child_dispatch_started_count = 0_usize;
    let mut cascade_success = true;
    let mut cascade_gate_denials = Vec::new();
    let mut cascade_environment_failures = Vec::new();

    reconcile_started_items(
        repo,
        &mut queue,
        &mut follow_up_reports,
        &mut authenticated_child_dispatch_started_count,
        &mut cascade_success,
        &mut cascade_gate_denials,
    )?;

    // Never overtake an unresolved earlier effect. In particular an Active
    // subordinate remains DispatchStarted and blocks every pending sibling
    // until a later invocation can authenticate a terminal report.
    let reconciled_summary = queue.summary();
    let unresolved = reconciled_summary.claimed > 0
        || reconciled_summary.dispatch_started > 0
        || reconciled_summary.dispatch_observed > 0
        || reconciled_summary.held_ambiguous > 0;
    if unresolved {
        cascade_success = false;
    }
    let pending = if unresolved {
        Vec::new()
    } else {
        queue
            .snapshot()
            .pending_item_ids()
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    for item_id in pending {
        queue.claim(&item_id)?;
        let preparation = (|| -> Result<FollowUpPreparation> {
            if primary_worktree_snapshot_sha256(repo, SupervisorExecutionRuntime::Verified)?
                != primary_baseline
            {
                return Ok(FollowUpPreparation::Refused(primary_integrity_denial(
                    &item_id,
                )?));
            }
            match retention_binding_matches(retention, &queue) {
                Ok(true) => {}
                Ok(false) => {
                    return Ok(FollowUpPreparation::Refused(permission_expansion_denial(
                        &item_id,
                    )?));
                }
                Err(error) => {
                    return Ok(FollowUpPreparation::EnvironmentFailed(
                        retention_probe_failure(&error),
                    ));
                }
            }

            let task = queue
                .snapshot()
                .item(&item_id)
                .context("claimed generated follow-up item disappeared")?
                .task()
                .clone();
            if task.cascade_depth != LICENSED_BREAKAGE_CASCADE_DEPTH {
                return Ok(FollowUpPreparation::Refused(permission_expansion_denial(
                    &item_id,
                )?));
            }
            let effective = validate_generated_follow_up_plan_document(&task.supervisor_plan)?;
            let plan_stage_permit = queue.generated_plan_stage_permit()?;
            let plan_file = generated_plan_file(repo, &task.supervisor_plan, &plan_stage_permit)?;
            #[cfg(test)]
            run_before_generated_follow_up_plan_load_hook(plan_file.path());
            let Some(reloaded) =
                load_exact_generated_plan_file(plan_file.path(), &task.supervisor_plan)?
            else {
                return Ok(FollowUpPreparation::Refused(permission_expansion_denial(
                    &item_id,
                )?));
            };
            if reloaded.plan != effective {
                bail!("generated follow-up ordinary plan file changed before dispatch");
            }
            if observe_caller_cancellation(caller_cancellation, cancellation_observed) {
                return Ok(FollowUpPreparation::Cancelled);
            }
            if let Some(denial) = before_dispatch(&reloaded.plan)? {
                return Ok(FollowUpPreparation::Refused(denial));
            }

            // These are the last effectful-path checks. They run after the
            // full loader and caller-specific profile callback, immediately
            // before the durable dispatch-start marker and subordinate call.
            if primary_worktree_snapshot_sha256(repo, SupervisorExecutionRuntime::Verified)?
                != primary_baseline
            {
                return Ok(FollowUpPreparation::Refused(primary_integrity_denial(
                    &item_id,
                )?));
            }
            match retention_binding_matches(retention, &queue) {
                Ok(true) => {}
                Ok(false) => {
                    return Ok(FollowUpPreparation::Refused(permission_expansion_denial(
                        &item_id,
                    )?));
                }
                Err(error) => {
                    return Ok(FollowUpPreparation::EnvironmentFailed(
                        retention_probe_failure(&error),
                    ));
                }
            }
            if observe_caller_cancellation(caller_cancellation, cancellation_observed) {
                return Ok(FollowUpPreparation::Cancelled);
            }
            Ok(FollowUpPreparation::Ready {
                plan_file,
                loaded: Box::new(reloaded),
            })
        })();
        let (mut plan_file, reloaded) = match preparation {
            Ok(FollowUpPreparation::Ready { plan_file, loaded }) => (plan_file, *loaded),
            Ok(FollowUpPreparation::Refused(denial)) => {
                queue.release_before_dispatch(&item_id, Some(denial.clone()), Vec::new())?;
                cascade_gate_denials.push(denial);
                cascade_success = false;
                break;
            }
            Ok(FollowUpPreparation::Cancelled) => {
                queue.release_before_dispatch(&item_id, None, Vec::new())?;
                cascade_success = false;
                break;
            }
            Ok(FollowUpPreparation::EnvironmentFailed(failure)) => {
                queue.release_before_dispatch(&item_id, None, vec![failure.clone()])?;
                cascade_environment_failures.push(failure);
                cascade_success = false;
                #[cfg(test)]
                record_queue_test_observation(
                    "environment_failed",
                    &queue,
                    authenticated_child_dispatch_started_count,
                );
                break;
            }
            Err(error) => {
                // No dispatch marker exists yet, so an injected crash or
                // validation/read error can be made explicitly retryable.
                queue.release_before_dispatch(&item_id, None, Vec::new())?;
                return Err(error.context(
                    "generated follow-up preparation failed before durable dispatch start",
                ));
            }
        };
        let subordinate_run_id = RunId::new(queue.planned_subordinate_run_id(&item_id)?)?;
        let subordinate_options = SupervisorRunOptions {
            repo: repo.to_path_buf(),
            plan_file: plan_file.path().to_path_buf(),
            run_id: subordinate_run_id.clone(),
            parent_node: Some(supervisor_template.run_id.as_str().to_string()),
            codex_bin: supervisor_template.codex_bin.clone(),
            runtime: supervisor_template.runtime,
            allow_dirty_primary: supervisor_template.allow_dirty_primary,
            allow_live_run_collision: supervisor_template.allow_live_run_collision,
            admission_overrides: supervisor_template.admission_overrides,
            budget_overrides: supervisor_template.budget_overrides,
            budget_max_duration_seconds: supervisor_template.budget_max_duration_seconds,
            machine_global_retention: Some(retention.clone()),
        };
        let max_concurrent_children = invocation
            .concurrency_policy
            .resolve(HostProcessCapacity::measured());
        validate_max_concurrent_children(max_concurrent_children)?;
        let manager = WorktreeManager::new(repo);
        let cleanliness = manager.acquire_repository_cleanliness()?;
        let runtime_preflight = match invocation.runtime_catalog {
            FollowUpRuntimeCatalog::Production => acquire_runtime_model_catalog_with_permit(
                &reloaded,
                &subordinate_options,
                repo,
                max_concurrent_children,
                SupervisorExecutionRuntime::Verified,
                SupervisorWorktreeCreation::Bound(&cleanliness),
            )
            .map(
                |RuntimeModelCatalogPreflight {
                     acquisition,
                     evidence,
                     session,
                     process_launch_evidence,
                 }| {
                    (
                        acquisition,
                        Some(evidence),
                        Some(session),
                        process_launch_evidence,
                    )
                },
            ),
            #[cfg(test)]
            FollowUpRuntimeCatalog::Injected => Ok((
                Ok(test_runtime_model_catalog(
                    &reloaded.plan,
                    subordinate_options.runtime,
                )?),
                None,
                None,
                Vec::new(),
            )),
        };
        let (
            runtime_model_catalog,
            preflight_evidence,
            catalog_preflight_session,
            preflight_process_evidence,
        ) = match runtime_preflight {
            Ok(preflight) => preflight,
            Err(error) => {
                let gate_id = supervisor_mutation_admission_gate_id(&error)
                    .unwrap_or(crate::mutation_taxonomy::TAXONOMY_REVIEW_REQUIRED_GATE_ID);
                let denial = GateDenial::from_approval_review(
                    &item_id,
                    gate_id,
                    ApprovalReviewDenial::HumanReviewRequired,
                    reloaded
                        .plan
                        .assignments
                        .iter()
                        .flat_map(|assignment| assignment.assigned_paths.iter().cloned()),
                )?;
                queue.release_before_dispatch(&item_id, Some(denial), Vec::new())?;
                return Err(error.context(
                    "generated follow-up catalog preflight failed before durable dispatch start",
                ));
            }
        };
        let mut durable_dispatch_started = false;
        let mut mark_dispatch_authorized = || -> Result<()> {
            queue.mark_dispatch_started(&item_id)?;
            durable_dispatch_started = true;
            #[cfg(test)]
            record_queue_test_observation(
                "dispatch_started",
                &queue,
                authenticated_child_dispatch_started_count,
            );
            #[cfg(test)]
            if take_interrupt_after_follow_up_dispatch_started() {
                let denial = ambiguous_dispatch_denial(&item_id)?;
                queue.mark_held_ambiguous(&item_id, Some(denial), Vec::new())?;
                record_queue_test_observation(
                    "held_ambiguous",
                    &queue,
                    authenticated_child_dispatch_started_count,
                );
                bail!("injected interruption after durable generated follow-up ambiguous hold");
            }
            Ok(())
        };
        let result = run_supervisor_plan_with_runner_and_creation(SupervisorRunExecution {
            loaded: reloaded,
            options: subordinate_options,
            max_concurrent_children,
            execution_runtime: SupervisorExecutionRuntime::Verified,
            worktree_creation: SupervisorWorktreeCreation::Bound(&cleanliness),
            runtime_model_catalog,
            preflight_evidence,
            catalog_preflight_session,
            preflight_process_evidence,
            dispatch_started: None,
            dispatch_authorized: Some(&mut mark_dispatch_authorized),
            external_runner,
        });
        drop(mark_dispatch_authorized);
        #[cfg(test)]
        if result.is_err()
            && durable_dispatch_started
            && queue
                .snapshot()
                .item(&item_id)
                .is_some_and(|item| item.phase() == GeneratedFollowUpQueuePhase::HeldAmbiguous)
        {
            return result.map(|_| unreachable!()).context(
                "injected interruption after admitted durable generated follow-up dispatch start",
            );
        }
        if result.is_err() && !durable_dispatch_started {
            let gate_id = result
                .as_ref()
                .err()
                .and_then(supervisor_mutation_admission_gate_id)
                .unwrap_or(crate::mutation_taxonomy::TAXONOMY_REVIEW_REQUIRED_GATE_ID);
            let denial = GateDenial::from_approval_review(
                &item_id,
                gate_id,
                ApprovalReviewDenial::HumanReviewRequired,
                std::iter::empty::<PathBuf>(),
            )?;
            queue.release_before_dispatch(&item_id, Some(denial), Vec::new())?;
            return result.map(|_| unreachable!()).context(
                "generated follow-up Supervisor failed before admitted durable dispatch start",
            );
        }
        #[cfg(test)]
        interrupt_after_authenticated_follow_up_child_start(repo, &subordinate_run_id)?;
        // The loader no longer needs the private file once the ordinary call
        // returns; keeping the handle alive across the call prevents path reuse.
        plan_file.as_file_mut().flush()?;
        match result {
            Ok(report) => {
                let child_started = match observe_and_acknowledge(
                    repo,
                    &mut queue,
                    &item_id,
                    &subordinate_run_id,
                    &report,
                )? {
                    FinalizedTerminalTransition::Acknowledged { child_started } => child_started,
                    FinalizedTerminalTransition::PlanMismatch(denial) => {
                        cascade_gate_denials.push(denial);
                        cascade_success = false;
                        break;
                    }
                };
                if child_started {
                    authenticated_child_dispatch_started_count =
                        authenticated_child_dispatch_started_count
                            .checked_add(1)
                            .context("generated follow-up dispatch evidence count overflowed")?;
                }
                #[cfg(test)]
                record_queue_test_observation(
                    "acknowledged_terminal",
                    &queue,
                    authenticated_child_dispatch_started_count,
                );
                cascade_gate_denials.extend(report.gate_denials.iter().cloned());
                if !report.generated_follow_up_tasks.is_empty() {
                    cascade_gate_denials.push(permission_expansion_denial(&item_id)?);
                    cascade_success = false;
                }
                cascade_success &= report.success;
                follow_up_reports.push(report);
                if !cascade_gate_denials.is_empty() {
                    break;
                }
            }
            Err(_error) => match subordinate_reconciliation(repo, &subordinate_run_id)? {
                SubordinateReconciliation::Finalized(report) => {
                    let child_started = match observe_and_acknowledge(
                        repo,
                        &mut queue,
                        &item_id,
                        &subordinate_run_id,
                        &report,
                    )? {
                        FinalizedTerminalTransition::Acknowledged { child_started } => {
                            child_started
                        }
                        FinalizedTerminalTransition::PlanMismatch(denial) => {
                            cascade_gate_denials.push(denial);
                            cascade_success = false;
                            break;
                        }
                    };
                    if child_started {
                        authenticated_child_dispatch_started_count =
                            authenticated_child_dispatch_started_count
                                .checked_add(1)
                                .context(
                                    "generated follow-up dispatch evidence count overflowed",
                                )?;
                    }
                    #[cfg(test)]
                    record_queue_test_observation(
                        "acknowledged_terminal",
                        &queue,
                        authenticated_child_dispatch_started_count,
                    );
                    cascade_gate_denials.extend(report.gate_denials.iter().cloned());
                    cascade_success &=
                        report.success && report.generated_follow_up_tasks.is_empty();
                    if !report.generated_follow_up_tasks.is_empty() {
                        cascade_gate_denials.push(permission_expansion_denial(&item_id)?);
                    }
                    follow_up_reports.push(*report);
                }
                SubordinateReconciliation::Active
                | SubordinateReconciliation::RetryableStatusRead => {
                    cascade_gate_denials.push(ambiguous_dispatch_denial(&item_id)?);
                    cascade_success = false;
                    break;
                }
                SubordinateReconciliation::Ambiguous => {
                    let denial = ambiguous_dispatch_denial(&item_id)?;
                    queue.mark_held_ambiguous(&item_id, Some(denial.clone()), Vec::new())?;
                    cascade_gate_denials.push(denial);
                    cascade_success = false;
                    break;
                }
            },
        }
        if !cascade_success {
            // A failed/refused generated subordinate never authorizes a later
            // sibling effect. Remaining work stays durably Enqueued for an
            // explicit later reconciliation decision.
            break;
        }
    }

    let final_primary =
        primary_worktree_snapshot_sha256(repo, SupervisorExecutionRuntime::Verified)?;
    let follow_up_primary_worktree_untouched = final_primary == primary_baseline;
    if !follow_up_primary_worktree_untouched {
        cascade_gate_denials.push(primary_integrity_denial(source_report.run_id.as_str())?);
        cascade_success = false;
    }
    let queue_summary = queue.summary();
    cascade_success &= queue_summary.acknowledged_terminal == queue_summary.capacity
        && queue_summary.enqueued == 0
        && queue_summary.claimed == 0
        && queue_summary.dispatch_started == 0
        && queue_summary.dispatch_observed == 0
        && queue_summary.held_ambiguous == 0;
    Ok(SupervisorCascadeOutcome {
        source_report,
        follow_up_cascade_version: FOLLOW_UP_CASCADE_VERSION,
        follow_up_cascade_success: cascade_success,
        follow_up_primary_worktree_untouched: Some(follow_up_primary_worktree_untouched),
        follow_up_queue: Some(SupervisorFollowUpQueueSummary {
            queue_instance_id: queue_summary.queue_instance_id,
            source_supervisor_run_id: queue_summary.source_supervisor_run_id,
            enqueue_committed: queue.snapshot().enqueue_committed(),
            item_count: queue_summary.capacity,
            pending_count: queue_summary.enqueued,
            claimed_count: queue_summary.claimed,
            dispatch_started_count: queue_summary.dispatch_started,
            dispatch_observed_count: queue_summary.dispatch_observed,
            acknowledged_terminal_count: queue_summary.acknowledged_terminal,
            held_ambiguous_count: queue_summary.held_ambiguous,
            authenticated_child_dispatch_started_count,
        }),
        follow_up_reports,
        follow_up_gate_denials: cascade_gate_denials,
        follow_up_environment_failures: cascade_environment_failures,
    })
}

fn retention_probe_failure(error: &anyhow::Error) -> EnvironmentFailure {
    let diagnostic = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<std::io::Error>())
        .map(|error| format!("I/O error kind {:?}", error.kind()))
        .unwrap_or_else(|| "content or identity validation failed".to_string());
    EnvironmentFailure::probe_failed(format!(
        "machine-global retention config probe failed before generated follow-up dispatch: {diagnostic}"
    ))
}

pub(crate) fn generated_follow_up_dispatch_evidence_after_cascade_error(
    repo: &Path,
    pre_dispatch_source_plan_sha256: &str,
    source_supervisor_run_id: &RunId,
    outer_command_run_id: &RunId,
) -> Result<GeneratedFollowUpDispatchEvidence> {
    let (source_plan_sha256, source_lifecycle_observed) =
        match supervisor_status(repo, source_supervisor_run_id.clone()) {
            Ok(status) if status.lifecycle == SupervisorRunLifecycle::Finalized => {
                let finalized = status
                    .final_report
                    .context("finalized cascade source has no authenticated final report")?;
                // Queue creation consumes only generated tasks from the finalized source.
                // An authenticated empty set proves that this source could not have opened
                // or started a generated follow-up queue, even when an earlier supervisor
                // preflight failed before persisting the normalized plan artifact.
                if finalized.generated_follow_up_tasks.is_empty() {
                    return Ok(GeneratedFollowUpDispatchEvidence::NoDurableDispatchStart);
                }
                let reader = ArtifactRunReader::open(
                    repo,
                    RunArtifactFamily::Supervise,
                    source_supervisor_run_id,
                )
                .context("finalized cascade source artifact is not authenticated")?;
                let plan_bytes = reader
                    .read("assignments/supervisor-plan.json")
                    .context("finalized cascade source has no authenticated normalized plan")?;
                let plan_text = String::from_utf8(plan_bytes)
                    .context("authenticated cascade source plan is not UTF-8")?;
                let loaded = parse_supervisor_plan_with_consultant(&plan_text)?;
                (
                    normalized_supervisor_plan_sha256(
                        &loaded.plan,
                        &loaded.consultant,
                        &loaded.assignment_metadata,
                        &loaded.plan_metadata,
                    )?,
                    true,
                )
            }
            Ok(_) => {
                // Queue creation is strictly after a finalized source return.
                return Ok(GeneratedFollowUpDispatchEvidence::NoDurableDispatchStart);
            }
            Err(_) => (pre_dispatch_source_plan_sha256.to_string(), false),
        };
    let authenticator = repository_authenticator_key_only(repo)?;
    let Some(queue) = GeneratedFollowUpQueue::open_existing_for_source_execution(
        authenticator,
        source_supervisor_run_id.as_str(),
        &source_plan_sha256,
    )?
    else {
        return Ok(if source_lifecycle_observed {
            GeneratedFollowUpDispatchEvidence::NoDurableDispatchStart
        } else {
            GeneratedFollowUpDispatchEvidence::DurableDispatchStart {
                observation: RoleUsageObservation::NotProcessObservable,
            }
        });
    };
    let source = queue.snapshot().source();
    if source.outer_entrypoint() != GeneratedFollowUpQueueEntrypoint::AutopilotRun
        || source.outer_command_run_id() != outer_command_run_id.as_str()
    {
        bail!("generated follow-up error evidence belongs to a different outer command");
    }

    let mut authenticated_start = false;
    let mut started_but_not_process_observable = false;
    for item in queue.snapshot().items().values() {
        if matches!(
            item.phase(),
            GeneratedFollowUpQueuePhase::Enqueued | GeneratedFollowUpQueuePhase::Claimed
        ) {
            continue;
        }
        let subordinate_run_id = RunId::new(
            item.subordinate_run_id()
                .context("durably started generated follow-up has no subordinate run id")?,
        )?;
        match authenticated_child_dispatch_started(repo, &subordinate_run_id) {
            Ok(true) => authenticated_start = true,
            Ok(false) | Err(_) => started_but_not_process_observable = true,
        }
    }
    if authenticated_start {
        Ok(GeneratedFollowUpDispatchEvidence::DurableDispatchStart {
            observation: RoleUsageObservation::SupervisorAggregate,
        })
    } else if started_but_not_process_observable {
        Ok(GeneratedFollowUpDispatchEvidence::DurableDispatchStart {
            observation: RoleUsageObservation::NotProcessObservable,
        })
    } else {
        Ok(GeneratedFollowUpDispatchEvidence::NoDurableDispatchStart)
    }
}

pub(crate) fn normalized_supervisor_plan_file_sha256(path: &Path) -> Result<String> {
    let loaded = load_supervisor_plan_file_with_consultant(path)?;
    normalized_supervisor_plan_sha256(
        &loaded.plan,
        &loaded.consultant,
        &loaded.assignment_metadata,
        &loaded.plan_metadata,
    )
}

fn retention_binding_matches(
    retention: &MachineGlobalRetentionBinding,
    queue: &GeneratedFollowUpQueue,
) -> Result<bool> {
    // Both exact config contents and stable file identity are represented in
    // this digest. Reconstructing it from the inherited binding prevents a
    // generated round from bypassing the machine-global retention boundary.
    let observed = GeneratedFollowUpRetentionBinding::from_machine_global(retention)?;
    Ok(observed.binding_sha256() == queue.snapshot().source().retention_binding_sha256())
}

fn reconcile_started_items(
    repo: &Path,
    queue: &mut GeneratedFollowUpQueue,
    reports: &mut Vec<SupervisorFinalReport>,
    authenticated_dispatches: &mut usize,
    cascade_success: &mut bool,
    cascade_gate_denials: &mut Vec<GateDenial>,
) -> Result<()> {
    let items = queue
        .snapshot()
        .items()
        .values()
        .map(|item| {
            (
                item.item_id().to_string(),
                item.phase(),
                item.subordinate_run_id().map(str::to_string),
                item.last_gate_denial().cloned(),
            )
        })
        .collect::<Vec<_>>();
    for (item_id, phase, subordinate_run_id, prior_gate_denial) in items {
        match phase {
            GeneratedFollowUpQueuePhase::DispatchStarted => {
                let run_id = RunId::new(
                    subordinate_run_id
                        .as_deref()
                        .context("started generated follow-up has no subordinate run id")?,
                )?;
                match subordinate_reconciliation(repo, &run_id)? {
                    SubordinateReconciliation::Finalized(report) => {
                        let child_started =
                            match observe_and_acknowledge(repo, queue, &item_id, &run_id, &report)?
                            {
                                FinalizedTerminalTransition::Acknowledged { child_started } => {
                                    child_started
                                }
                                FinalizedTerminalTransition::PlanMismatch(denial) => {
                                    cascade_gate_denials.push(denial);
                                    *cascade_success = false;
                                    continue;
                                }
                            };
                        if child_started {
                            *authenticated_dispatches =
                                authenticated_dispatches.checked_add(1).context(
                                    "generated follow-up dispatch evidence count overflowed",
                                )?;
                        }
                        #[cfg(test)]
                        record_queue_test_observation(
                            "acknowledged_terminal",
                            queue,
                            *authenticated_dispatches,
                        );
                        cascade_gate_denials.extend(report.gate_denials.iter().cloned());
                        if !report.generated_follow_up_tasks.is_empty() {
                            cascade_gate_denials.push(permission_expansion_denial(&item_id)?);
                        }
                        *cascade_success &=
                            report.success && report.generated_follow_up_tasks.is_empty();
                        reports.push(*report);
                    }
                    SubordinateReconciliation::Active
                    | SubordinateReconciliation::RetryableStatusRead => {
                        if authenticated_child_dispatch_started(repo, &run_id)? {
                            *authenticated_dispatches =
                                authenticated_dispatches.checked_add(1).context(
                                    "generated follow-up dispatch evidence count overflowed",
                                )?;
                        }
                        cascade_gate_denials.push(ambiguous_dispatch_denial(&item_id)?);
                        *cascade_success = false;
                    }
                    SubordinateReconciliation::Ambiguous => {
                        if authenticated_child_dispatch_started(repo, &run_id)? {
                            *authenticated_dispatches =
                                authenticated_dispatches.checked_add(1).context(
                                    "generated follow-up dispatch evidence count overflowed",
                                )?;
                        }
                        let denial = ambiguous_dispatch_denial(&item_id)?;
                        queue.mark_held_ambiguous(&item_id, Some(denial.clone()), Vec::new())?;
                        cascade_gate_denials.push(denial);
                        *cascade_success = false;
                    }
                }
            }
            GeneratedFollowUpQueuePhase::DispatchObserved => {
                let run_id = RunId::new(
                    subordinate_run_id
                        .as_deref()
                        .context("observed generated follow-up has no subordinate run id")?,
                )?;
                if let Some(report) = conclusive_finalized_report(repo, &run_id)? {
                    let child_started =
                        match observe_and_acknowledge(repo, queue, &item_id, &run_id, &report)? {
                            FinalizedTerminalTransition::Acknowledged { child_started } => {
                                child_started
                            }
                            FinalizedTerminalTransition::PlanMismatch(denial) => {
                                cascade_gate_denials.push(denial);
                                *cascade_success = false;
                                continue;
                            }
                        };
                    if child_started {
                        *authenticated_dispatches = authenticated_dispatches
                            .checked_add(1)
                            .context("generated follow-up dispatch evidence count overflowed")?;
                    }
                    #[cfg(test)]
                    record_queue_test_observation(
                        "acknowledged_terminal",
                        queue,
                        *authenticated_dispatches,
                    );
                    cascade_gate_denials.extend(report.gate_denials.iter().cloned());
                    *cascade_success &=
                        report.success && report.generated_follow_up_tasks.is_empty();
                    if !report.generated_follow_up_tasks.is_empty() {
                        cascade_gate_denials.push(permission_expansion_denial(&item_id)?);
                    }
                    reports.push(report);
                } else {
                    if authenticated_child_dispatch_started(repo, &run_id)? {
                        *authenticated_dispatches = authenticated_dispatches
                            .checked_add(1)
                            .context("generated follow-up dispatch evidence count overflowed")?;
                    }
                    cascade_gate_denials.push(ambiguous_dispatch_denial(&item_id)?);
                    *cascade_success = false;
                }
            }
            GeneratedFollowUpQueuePhase::HeldAmbiguous => {
                let run_id = RunId::new(
                    subordinate_run_id
                        .as_deref()
                        .context("held generated follow-up has no subordinate run id")?,
                )?;
                match subordinate_reconciliation(repo, &run_id)? {
                    SubordinateReconciliation::Finalized(report) => {
                        let child_started =
                            match observe_and_acknowledge(repo, queue, &item_id, &run_id, &report)?
                            {
                                FinalizedTerminalTransition::Acknowledged { child_started } => {
                                    child_started
                                }
                                FinalizedTerminalTransition::PlanMismatch(denial) => {
                                    cascade_gate_denials.push(denial);
                                    *cascade_success = false;
                                    continue;
                                }
                            };
                        if child_started {
                            *authenticated_dispatches =
                                authenticated_dispatches.checked_add(1).context(
                                    "generated follow-up dispatch evidence count overflowed",
                                )?;
                        }
                        #[cfg(test)]
                        record_queue_test_observation(
                            "acknowledged_terminal",
                            queue,
                            *authenticated_dispatches,
                        );
                        cascade_gate_denials.extend(report.gate_denials.iter().cloned());
                        if !report.generated_follow_up_tasks.is_empty() {
                            cascade_gate_denials.push(permission_expansion_denial(&item_id)?);
                        }
                        *cascade_success &=
                            report.success && report.generated_follow_up_tasks.is_empty();
                        reports.push(*report);
                    }
                    SubordinateReconciliation::Active
                    | SubordinateReconciliation::Ambiguous
                    | SubordinateReconciliation::RetryableStatusRead => {
                        if authenticated_child_dispatch_started(repo, &run_id)? {
                            *authenticated_dispatches =
                                authenticated_dispatches.checked_add(1).context(
                                    "generated follow-up dispatch evidence count overflowed",
                                )?;
                        }
                        cascade_gate_denials.push(match prior_gate_denial {
                            Some(denial) => denial,
                            None => ambiguous_dispatch_denial(&item_id)?,
                        });
                        *cascade_success = false;
                    }
                }
            }
            GeneratedFollowUpQueuePhase::AcknowledgedTerminal => {
                let run_id = RunId::new(
                    subordinate_run_id
                        .as_deref()
                        .context("acknowledged generated follow-up has no subordinate run id")?,
                )?;
                if let Some(report) = conclusive_finalized_report(repo, &run_id)? {
                    let queued_plan = &queue
                        .snapshot()
                        .item(&item_id)
                        .context("acknowledged generated follow-up item disappeared")?
                        .task()
                        .supervisor_plan;
                    if !authenticated_subordinate_plan_matches(repo, &run_id, queued_plan, &report)?
                    {
                        cascade_gate_denials.push(permission_expansion_denial(&item_id)?);
                        *cascade_success = false;
                        continue;
                    }
                    if authenticated_child_dispatch_started(repo, &run_id)? {
                        *authenticated_dispatches = authenticated_dispatches
                            .checked_add(1)
                            .context("generated follow-up dispatch evidence count overflowed")?;
                    }
                    cascade_gate_denials.extend(report.gate_denials.iter().cloned());
                    *cascade_success &=
                        report.success && report.generated_follow_up_tasks.is_empty();
                    if !report.generated_follow_up_tasks.is_empty() {
                        cascade_gate_denials.push(permission_expansion_denial(&item_id)?);
                    }
                    reports.push(report);
                } else {
                    cascade_gate_denials.push(ambiguous_dispatch_denial(&item_id)?);
                    *cascade_success = false;
                }
            }
            GeneratedFollowUpQueuePhase::Enqueued | GeneratedFollowUpQueuePhase::Claimed => {}
        }
    }
    Ok(())
}

enum FinalizedTerminalTransition {
    Acknowledged { child_started: bool },
    PlanMismatch(GateDenial),
}

enum SubordinateReconciliation {
    Finalized(Box<SupervisorFinalReport>),
    Active,
    Ambiguous,
    RetryableStatusRead,
}

fn subordinate_reconciliation(repo: &Path, run_id: &RunId) -> Result<SubordinateReconciliation> {
    let Ok(status) = supervisor_status(repo, run_id.clone()) else {
        // Preserve DispatchStarted so a later invocation can retry the
        // authenticated status read. A transient read failure is not evidence
        // that the external effect is permanently ambiguous.
        return Ok(SubordinateReconciliation::RetryableStatusRead);
    };
    match status.lifecycle {
        SupervisorRunLifecycle::Finalized => status
            .final_report
            .map(Box::new)
            .map(SubordinateReconciliation::Finalized)
            .context("finalized generated follow-up has no authenticated report"),
        SupervisorRunLifecycle::Resumable => {
            match resume_supervisor_run(repo, run_id.clone())?.final_report {
                Some(report) => Ok(SubordinateReconciliation::Finalized(Box::new(report))),
                None => Ok(SubordinateReconciliation::Ambiguous),
            }
        }
        SupervisorRunLifecycle::Active => Ok(SubordinateReconciliation::Active),
        SupervisorRunLifecycle::Interrupted | SupervisorRunLifecycle::Uncertain => {
            Ok(SubordinateReconciliation::Ambiguous)
        }
    }
}

fn conclusive_finalized_report(
    repo: &Path,
    run_id: &RunId,
) -> Result<Option<SupervisorFinalReport>> {
    match subordinate_reconciliation(repo, run_id)? {
        SubordinateReconciliation::Finalized(report) => Ok(Some(*report)),
        SubordinateReconciliation::Active
        | SubordinateReconciliation::Ambiguous
        | SubordinateReconciliation::RetryableStatusRead => Ok(None),
    }
}

fn observe_and_acknowledge(
    repo: &Path,
    queue: &mut GeneratedFollowUpQueue,
    item_id: &str,
    run_id: &RunId,
    report: &SupervisorFinalReport,
) -> Result<FinalizedTerminalTransition> {
    let item = queue
        .snapshot()
        .item(item_id)
        .context("finalized generated follow-up item disappeared")?;
    let phase = item.phase();
    if !authenticated_subordinate_plan_matches(repo, run_id, &item.task().supervisor_plan, report)?
    {
        let denial = permission_expansion_denial(item_id)?;
        if phase == GeneratedFollowUpQueuePhase::DispatchStarted {
            queue.mark_held_ambiguous(item_id, Some(denial.clone()), Vec::new())?;
        }
        return Ok(FinalizedTerminalTransition::PlanMismatch(denial));
    }
    let child_started = authenticated_child_dispatch_started(repo, run_id)?;
    let observation = GeneratedFollowUpDispatchObservation::new(
        run_id.as_str(),
        report.gate_denials.first().cloned(),
        report.environment_failures.clone(),
        Some(ExternalSideEffectState::Completed),
    )?;
    let authenticated = AuthenticatedGeneratedFollowUpTerminal {
        queue_instance_id: queue.snapshot().queue_instance_id().to_string(),
        item_id: item_id.to_string(),
        observation,
    };
    queue.apply_authenticated_terminal(authenticated)?;
    Ok(FinalizedTerminalTransition::Acknowledged { child_started })
}

fn verify_authenticated_source_basis(
    repo: &Path,
    supplied: &LoadedSupervisorPlan,
    source: &SupervisorFinalReport,
    supplied_sha256: &str,
) -> Result<()> {
    let reader = ArtifactRunReader::open(repo, RunArtifactFamily::Supervise, &source.run_id)
        .context("generated follow-up source is not an authenticated finalized run")?;
    let final_report_relative = RunArtifactFamily::Supervise.final_report_relative_path();
    let authenticated_report_bytes = reader
        .read(&final_report_relative)
        .context("generated follow-up source has no authenticated final report")?;
    let supplied_report_bytes = encode_final_report(source)?;
    let authenticated = read_supervisor_final_report(&reader)?;
    // The finalized bytes are the authenticated execution basis. Comparing
    // them with the same canonical encoder used by persistence covers every
    // report field without depending on whether serde's decode defaults are
    // structurally PartialEq-stable. The typed read above still rejects a
    // malformed report before any queue state is opened.
    if authenticated_report_bytes != supplied_report_bytes {
        bail!("supplied generated follow-up source report differs from the authenticated canonical final-report bytes");
    }
    if authenticated.run_id != source.run_id
        || authenticated.run_lifecycle != SupervisorRunLifecycle::Finalized
    {
        bail!("authenticated generated follow-up source report is not the expected finalized run");
    }
    // A finalized empty generated-task set is sufficient for the source-only
    // outcome. Runtime-catalog preflight failures intentionally finalize before
    // the normalized plan artifact exists, and there is no queue input to bind.
    if authenticated.generated_follow_up_tasks.is_empty() {
        return Ok(());
    }
    let plan_bytes = reader
        .read("assignments/supervisor-plan.json")
        .context("generated follow-up source has no authenticated normalized plan")?;
    let plan_text = String::from_utf8(plan_bytes)
        .context("authenticated generated follow-up source plan is not UTF-8")?;
    let authenticated_loaded = parse_supervisor_plan_with_consultant(&plan_text)?;
    let authenticated_sha256 = normalized_supervisor_plan_sha256(
        &authenticated_loaded.plan,
        &authenticated_loaded.consultant,
        &authenticated_loaded.assignment_metadata,
        &authenticated_loaded.plan_metadata,
    )?;
    if &authenticated_loaded != supplied || authenticated_sha256 != supplied_sha256 {
        bail!("supplied generated follow-up source plan differs from its authenticated finalized plan");
    }
    Ok(())
}

fn authenticated_subordinate_plan_matches(
    repo: &Path,
    run_id: &RunId,
    queued: &GeneratedFollowUpSupervisorPlan,
    report: &SupervisorFinalReport,
) -> Result<bool> {
    let reader = ArtifactRunReader::open(repo, RunArtifactFamily::Supervise, run_id)
        .context("generated follow-up subordinate is not an authenticated finalized run")?;
    let report_bytes = reader
        .read(RunArtifactFamily::Supervise.final_report_relative_path())
        .context("generated follow-up subordinate has no authenticated final report")?;
    if report_bytes != encode_final_report(report)? {
        bail!("generated follow-up subordinate report differs from its authenticated finalized report");
    }
    let plan_bytes = reader
        .read("assignments/supervisor-plan.json")
        .context("generated follow-up subordinate has no authenticated normalized plan")?;
    let plan_text = String::from_utf8(plan_bytes)
        .context("authenticated generated follow-up subordinate plan is not UTF-8")?;
    let loaded = parse_supervisor_plan_with_consultant(&plan_text)?;
    loaded_generated_plan_matches(&loaded, queued)
}

fn generated_plan_file(
    repo: &Path,
    plan: &GeneratedFollowUpSupervisorPlan,
    permit: &crate::mutation_taxonomy::SupervisorOperationPermit<'_>,
) -> Result<tempfile::NamedTempFile> {
    permit
        .verify(crate::mutation_taxonomy::MutationOperation::GeneratedSupervisorPlanStage)
        .map_err(anyhow::Error::from)?;
    let repository = crate::git_repository::open(repo)?;
    let mut file = tempfile::Builder::new()
        .prefix("maco-generated-follow-up-")
        .suffix(".json")
        .tempfile_in(repository.path())?;
    serde_json::to_writer(file.as_file_mut(), plan)?;
    file.as_file_mut().flush()?;
    file.as_file().sync_all()?;
    Ok(file)
}

fn load_exact_generated_plan_file(
    path: &Path,
    generated: &GeneratedFollowUpSupervisorPlan,
) -> Result<Option<LoadedSupervisorPlan>> {
    let loaded = load_supervisor_plan_file_with_consultant(path)?;
    if !loaded_generated_plan_matches(&loaded, generated)? {
        return Ok(None);
    }
    Ok(Some(loaded))
}

fn loaded_generated_plan_matches(
    loaded: &LoadedSupervisorPlan,
    generated: &GeneratedFollowUpSupervisorPlan,
) -> Result<bool> {
    let encoded = serde_json::to_string(generated)
        .context("failed to encode the immutable queued generated follow-up plan")?;
    let expected = parse_supervisor_plan_with_consultant(&encoded)
        .context("immutable queued generated follow-up plan no longer parses")?;
    Ok(loaded == &expected)
}

#[cfg(test)]
type BeforeGeneratedFollowUpPlanLoadHook = Box<dyn FnMut(&Path)>;

#[cfg(test)]
thread_local! {
    static BEFORE_GENERATED_FOLLOW_UP_PLAN_LOAD_HOOK: std::cell::RefCell<Option<BeforeGeneratedFollowUpPlanLoadHook>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
pub(crate) fn set_before_generated_follow_up_plan_load_hook(hook: impl FnMut(&Path) + 'static) {
    BEFORE_GENERATED_FOLLOW_UP_PLAN_LOAD_HOOK
        .with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
thread_local! {
    static INTERRUPT_AFTER_FOLLOW_UP_ENQUEUE: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
}

#[cfg(test)]
pub(crate) fn set_interrupt_after_follow_up_enqueue() {
    INTERRUPT_AFTER_FOLLOW_UP_ENQUEUE.with(|slot| slot.set(true));
}

#[cfg(test)]
fn interrupt_after_follow_up_enqueue() -> Result<()> {
    let interrupted = INTERRUPT_AFTER_FOLLOW_UP_ENQUEUE.with(|slot| slot.replace(false));
    if interrupted {
        bail!("injected interruption after durable generated follow-up enqueue");
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    static INTERRUPT_AFTER_FOLLOW_UP_DISPATCH_STARTED: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
}

#[cfg(test)]
pub(crate) fn set_interrupt_after_follow_up_dispatch_started() {
    INTERRUPT_AFTER_FOLLOW_UP_DISPATCH_STARTED.with(|slot| slot.set(true));
}

#[cfg(test)]
fn take_interrupt_after_follow_up_dispatch_started() -> bool {
    INTERRUPT_AFTER_FOLLOW_UP_DISPATCH_STARTED.with(|slot| slot.replace(false))
}

#[cfg(test)]
thread_local! {
    static INTERRUPT_AFTER_AUTHENTICATED_FOLLOW_UP_CHILD_START: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
}

#[cfg(test)]
pub(crate) fn set_interrupt_after_authenticated_follow_up_child_start() {
    INTERRUPT_AFTER_AUTHENTICATED_FOLLOW_UP_CHILD_START.with(|slot| slot.set(true));
}

#[cfg(test)]
fn interrupt_after_authenticated_follow_up_child_start(repo: &Path, run_id: &RunId) -> Result<()> {
    let interrupted =
        INTERRUPT_AFTER_AUTHENTICATED_FOLLOW_UP_CHILD_START.with(|slot| slot.replace(false));
    if interrupted {
        if !authenticated_child_dispatch_started(repo, run_id)? {
            bail!("injected post-start interruption did not observe an authenticated child start");
        }
        bail!("injected interruption after authenticated generated follow-up child start");
    }
    Ok(())
}

#[cfg(test)]
fn run_before_generated_follow_up_plan_load_hook(path: &Path) {
    BEFORE_GENERATED_FOLLOW_UP_PLAN_LOAD_HOOK.with(|slot| {
        if let Some(mut hook) = slot.borrow_mut().take() {
            hook(path);
        }
    });
}

#[cfg(test)]
type GeneratedFollowUpQueueObserver = Box<dyn FnMut(GeneratedFollowUpQueueTestObservation)>;

#[cfg(test)]
thread_local! {
    static GENERATED_FOLLOW_UP_QUEUE_OBSERVER: std::cell::RefCell<Option<GeneratedFollowUpQueueObserver>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
pub(crate) fn set_generated_follow_up_queue_observer(
    observer: impl FnMut(GeneratedFollowUpQueueTestObservation) + 'static,
) {
    GENERATED_FOLLOW_UP_QUEUE_OBSERVER.with(|slot| *slot.borrow_mut() = Some(Box::new(observer)));
}

#[cfg(test)]
pub(crate) fn clear_generated_follow_up_queue_observer() {
    GENERATED_FOLLOW_UP_QUEUE_OBSERVER.with(|slot| *slot.borrow_mut() = None);
}

#[cfg(test)]
pub(crate) fn clear_follow_up_cascade_test_isolation() {
    BEFORE_GENERATED_FOLLOW_UP_PLAN_LOAD_HOOK.with(|slot| *slot.borrow_mut() = None);
    INTERRUPT_AFTER_FOLLOW_UP_ENQUEUE.with(|slot| slot.set(false));
    INTERRUPT_AFTER_FOLLOW_UP_DISPATCH_STARTED.with(|slot| slot.set(false));
    INTERRUPT_AFTER_AUTHENTICATED_FOLLOW_UP_CHILD_START.with(|slot| slot.set(false));
    clear_generated_follow_up_queue_observer();
}

#[cfg(test)]
fn record_queue_test_observation(
    label: &'static str,
    queue: &GeneratedFollowUpQueue,
    authenticated_child_dispatch_started_count: usize,
) {
    let summary = queue.summary();
    let item_ids = queue.snapshot().items().keys().cloned().collect();
    let subordinate_run_ids = queue
        .snapshot()
        .items()
        .values()
        .filter_map(|item| item.subordinate_run_id().map(str::to_string))
        .collect();
    let environment_failures = queue
        .snapshot()
        .items()
        .values()
        .flat_map(|item| item.last_environment_failures().iter().cloned())
        .collect();
    let observation = GeneratedFollowUpQueueTestObservation {
        label,
        queue_instance_id: summary.queue_instance_id.clone(),
        outer_entrypoint: summary.outer_entrypoint.as_str().to_string(),
        outer_command_run_id: summary.outer_command_run_id.clone(),
        item_ids,
        subordinate_run_ids,
        environment_failures,
        pending_count: summary.enqueued,
        claimed_count: summary.claimed,
        dispatch_started_count: summary.dispatch_started,
        dispatch_observed_count: summary.dispatch_observed,
        acknowledged_terminal_count: summary.acknowledged_terminal,
        held_ambiguous_count: summary.held_ambiguous,
        authenticated_child_dispatch_started_count,
    };
    GENERATED_FOLLOW_UP_QUEUE_OBSERVER.with(|slot| {
        if let Some(observer) = slot.borrow_mut().as_mut() {
            observer(observation);
        }
    });
}

fn primary_integrity_denial(correlation_id: &str) -> Result<GateDenial> {
    Ok(GateDenial::new(
        correlation_id,
        GateDenialReason::PrimaryIntegrityFailure,
        VerifiedGateContext::new(
            correlation_id,
            GateCheckSource::PrimaryIntegrity,
            std::iter::empty::<&Path>(),
        )?,
    )?)
}

fn ambiguous_dispatch_denial(correlation_id: &str) -> Result<GateDenial> {
    Ok(GateDenial::new(
        correlation_id,
        GateDenialReason::ExternalSideEffect {
            state: ExternalSideEffectState::Ambiguous,
        },
        VerifiedGateContext::new(
            correlation_id,
            GateCheckSource::ExternalSideEffect,
            std::iter::empty::<&Path>(),
        )?,
    )?)
}

fn permission_expansion_denial(correlation_id: &str) -> Result<GateDenial> {
    Ok(GateDenial::new(
        correlation_id,
        GateDenialReason::ApprovalReview {
            denial: crate::gate_denial::ApprovalReviewDenial::PermissionExpansion,
        },
        VerifiedGateContext::new(
            correlation_id,
            GateCheckSource::FutureApprovalReview,
            std::iter::empty::<&Path>(),
        )?,
    )?)
}
