use super::*;

const HUMAN_INTERRUPTION_RATE_GAP: &str =
    "the run was interrupted by required human intervention before its rate denominators could be finalized";
const BREAKER_SNAPSHOT_RATE_GAP: &str =
    "the breaker-trip health artifact is a point-in-time snapshot emitted before active assignments finish draining";

#[derive(Clone, Copy, Debug)]
pub(super) enum GateCorrectionJournalState {
    Blocked,
    CorrectionAttempt,
    Terminal(GateCorrectionTerminalClass),
}

impl GateCorrectionJournalState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::CorrectionAttempt => "correction_attempt",
            Self::Terminal(GateCorrectionTerminalClass::SelfCorrected) => "self_corrected",
            Self::Terminal(GateCorrectionTerminalClass::Exhausted) => "exhausted",
            Self::Terminal(GateCorrectionTerminalClass::Escalated) => "escalated",
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct AutonomyKpiCollector {
    reviewed_actions: BTreeMap<String, ReviewedGateActionKpi>,
    gate_lifecycles: BTreeMap<(String, String), GateCorrectionLifecycleKpi>,
    eligible_reviewed_runs: BTreeSet<String>,
    human_interrupted_runs: BTreeSet<String>,
    licensed_dependent_failures: u64,
    generated_follow_up_tasks: u64,
}

impl AutonomyKpiCollector {
    pub(super) fn observe_pre_action_event(&mut self, record: &PreActionJournalRecord) {
        if record.phase != PreActionJournalPhase::ReviewDecision {
            return;
        }
        let (Some(request), Some(allowed)) = (record.request.as_ref(), record.allowed) else {
            return;
        };
        let human_intervention = matches!(
            record.rationale,
            PreActionJournalRationale::HumanInterventionRequired
        )
        .then_some(HumanInterventionRecord {
            target: HumanInterventionTarget::Human,
            outcome: HumanInterventionOutcome::InterventionRequired,
        });
        let (correction_correlation_id, denial_id) = record
            .denial
            .as_ref()
            .map(|denial| {
                (
                    Some(denial.correction_correlation_id.as_str().to_string()),
                    Some(denial.denial_id.as_str().to_string()),
                )
            })
            .unwrap_or((None, None));
        self.reviewed_actions.insert(
            request.request_id.clone(),
            ReviewedGateActionKpi {
                action_gate_id: request.request_id.clone(),
                correction_correlation_id,
                denial_id,
                allowed,
                human_intervention,
            },
        );
        self.eligible_reviewed_runs.insert(record.run_id.clone());
        if matches!(
            record.rationale,
            PreActionJournalRationale::HumanInterventionRequired
        ) {
            self.human_interrupted_runs.insert(record.run_id.clone());
        }
    }

    pub(super) fn observe_gate_correction_event(
        &mut self,
        denial: &GateDenial,
        state: GateCorrectionJournalState,
        correction_attempt: Option<u8>,
    ) {
        let lifecycle = self
            .gate_lifecycles
            .entry((
                denial.denial_id.as_str().to_string(),
                denial.correction_correlation_id.as_str().to_string(),
            ))
            .or_insert_with(|| GateCorrectionLifecycleKpi {
                denial_id: denial.denial_id.as_str().to_string(),
                correction_correlation_id: denial.correction_correlation_id.as_str().to_string(),
                route: denial.route,
                correction_attempts: 0,
                terminal_outcome: None,
            });
        if let Some(attempt) = correction_attempt {
            lifecycle.correction_attempts = lifecycle.correction_attempts.max(attempt);
        }
        if let GateCorrectionJournalState::Terminal(outcome) = state {
            lifecycle.terminal_outcome = Some(outcome);
        }
    }

    pub(super) fn report(&self, journal_observable: bool) -> AutonomyKpiReport {
        self.report_with_rate_gap(journal_observable, None)
    }

    pub(super) fn observe_licensed_breakage(
        &mut self,
        licensed_dependent_failures: usize,
        generated_follow_up_tasks: usize,
    ) {
        let licensed_dependent_failures =
            u64::try_from(licensed_dependent_failures).unwrap_or(u64::MAX);
        let generated_follow_up_tasks =
            u64::try_from(generated_follow_up_tasks).unwrap_or(u64::MAX);
        self.licensed_dependent_failures = self
            .licensed_dependent_failures
            .saturating_add(licensed_dependent_failures);
        self.generated_follow_up_tasks = self
            .generated_follow_up_tasks
            .saturating_add(generated_follow_up_tasks);
    }

    fn breaker_trip_report(&self, journal_observable: bool) -> AutonomyKpiReport {
        self.report_with_rate_gap(journal_observable, Some(BREAKER_SNAPSHOT_RATE_GAP))
    }

    fn report_with_rate_gap(
        &self,
        journal_observable: bool,
        point_in_time_rate_gap: Option<&'static str>,
    ) -> AutonomyKpiReport {
        if !journal_observable {
            return AutonomyKpiReport::not_process_observable();
        }
        let actions_reviewed = self.reviewed_actions.len() as u64;
        let denials = self
            .reviewed_actions
            .values()
            .filter(|action| !action.allowed)
            .count() as u64;
        // Self-correction is defined only over reviewed denials. Requiring both typed
        // correlation fields prevents unrelated gate populations from entering either
        // the numerator or denominator merely because they also produce lifecycle events.
        let reviewed_denials = self
            .reviewed_actions
            .values()
            .filter(|action| !action.allowed)
            .filter_map(|action| {
                action
                    .denial_id
                    .as_deref()
                    .zip(action.correction_correlation_id.as_deref())
            })
            .collect::<BTreeSet<_>>();
        let reviewed_gate_lifecycles = self
            .gate_lifecycles
            .values()
            .filter(|lifecycle| {
                reviewed_denials.contains(&(
                    lifecycle.denial_id.as_str(),
                    lifecycle.correction_correlation_id.as_str(),
                ))
            })
            .cloned()
            .collect::<Vec<_>>();
        let terminal_denials = reviewed_gate_lifecycles
            .iter()
            .filter(|lifecycle| lifecycle.terminal_outcome.is_some())
            .count() as u64;
        let self_corrections = reviewed_gate_lifecycles
            .iter()
            .filter(|lifecycle| {
                lifecycle.terminal_outcome == Some(GateCorrectionTerminalClass::SelfCorrected)
            })
            .count() as u64;
        let human_escalations = self
            .reviewed_actions
            .values()
            .filter(|action| action.human_intervention.is_some())
            .count() as u64;
        let eligible_reviewed_runs = self.eligible_reviewed_runs.len() as u64;
        let interrupted_runs = self.human_interrupted_runs.len() as u64;
        let interrupted = interrupted_runs > 0;
        // A human-required review cancels its turn at the producer. Its raw typed events
        // remain sound, but the stopped run cannot establish complete rate denominators.
        // A breaker transition artifact has the same limitation until active work drains.
        let rate_denominators_unavailable_reason = if interrupted {
            Some(HUMAN_INTERRUPTION_RATE_GAP)
        } else {
            point_in_time_rate_gap
        };
        let rate_denominators_observable = rate_denominators_unavailable_reason.is_none();
        AutonomyKpiReport {
            observation: RoleUsageObservation::SupervisorAggregate,
            population: AutonomyKpiPopulation::ReviewedGateActions,
            coverage: AutonomyKpiCoverage::journal_observable(rate_denominators_unavailable_reason),
            actions_reviewed: Some(actions_reviewed),
            denials: Some(denials),
            self_corrections: Some(self_corrections),
            human_escalations: Some(human_escalations),
            interrupted: Some(interrupted),
            licensed_dependent_failures: Some(self.licensed_dependent_failures),
            generated_follow_up_tasks: Some(self.generated_follow_up_tasks),
            denial_rate: (rate_denominators_observable && actions_reviewed > 0).then_some(
                RatioMetric {
                    numerator: denials,
                    denominator: actions_reviewed,
                },
            ),
            self_correction_rate: (rate_denominators_observable && terminal_denials > 0).then_some(
                RatioMetric {
                    numerator: self_corrections,
                    denominator: terminal_denials,
                },
            ),
            interruption_rate: (rate_denominators_observable && eligible_reviewed_runs > 0)
                .then_some(RatioMetric {
                    numerator: interrupted_runs,
                    denominator: eligible_reviewed_runs,
                }),
            reviewed_actions: self.reviewed_actions.values().cloned().collect(),
            gate_lifecycles: reviewed_gate_lifecycles,
            unavailable_reason: None,
        }
    }
}

pub(super) fn record_licensed_breakage_follow_up_tasks(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    source_assignment_id: &str,
    review: &LicensedBreakageReview,
    tasks: &[GeneratedFollowUpTaskRecord],
) -> Result<()> {
    if tasks.is_empty() || tasks.len() != review.failures.len() {
        bail!("licensed dependent failures must produce exactly one durable follow-up task each");
    }
    for (failure, task) in review.failures.iter().zip(tasks) {
        let follow_up_assignment = task.supervisor_plan.assignment().with_context(|| {
            format!(
                "licensed dependent failure '{}' has no sole generated assignment",
                failure.dependent_id
            )
        })?;
        let generated_context = &task.supervisor_plan.generated_follow_up;
        if task.breaking_assignment_id != source_assignment_id
            || task.breaking_change.agent_id != source_assignment_id
            || task.breaking_change.diff_oid.is_empty()
            || task.declaration_sha256 != review.declaration_sha256
            || task.failure_signature != failure.failure_signature
            || task.migration_rationale != review.migration_rationale
            || follow_up_assignment.assigned_paths != failure.paths
            || follow_up_assignment.semantic_symbols != failure.interfaces
            || follow_up_assignment.licensed_breakage.is_some()
            || follow_up_assignment
                .task
                .as_deref()
                .is_none_or(str::is_empty)
            || generated_context.breaking_assignment_id != task.breaking_assignment_id
            || generated_context.breaking_change != task.breaking_change
            || generated_context.declaration_sha256 != task.declaration_sha256
            || generated_context.failure_signature != task.failure_signature
            || generated_context.migration_rationale != task.migration_rationale
            || generated_context.cascade_depth != task.cascade_depth
            || generated_context.dispatch_status != task.dispatch_status
            || generated_context.handoff != task.handoff
            || task.cascade_depth != LICENSED_BREAKAGE_CASCADE_DEPTH
            || task.dispatch_status != GeneratedFollowUpDispatchStatus::DeferredForPlannedRun
            || task.handoff.trim().is_empty()
        {
            bail!(
                "licensed dependent failure '{}' has an incomplete or misattributed follow-up task",
                failure.dependent_id
            );
        }
    }
    let mut guard = artifacts
        .lock()
        .map_err(|_| anyhow!("supervisor artifact writer mutex was poisoned"))?;
    guard
        .mutation_session
        .permit(MutationOperation::SupervisorRunArtifactWriteAppend)?
        .verify(MutationOperation::SupervisorRunArtifactWriteAppend)?;
    guard
        .mutation_session
        .permit(MutationOperation::SupervisorOrchestrationJournalLifecycle)?
        .verify(MutationOperation::SupervisorOrchestrationJournalLifecycle)?;
    let SharedSupervisorArtifacts {
        writer,
        journal,
        autonomy_kpis,
        ..
    } = &mut *guard;
    let active_journal = journal
        .as_mut()
        .context("licensed breakage requires an enabled orchestration event journal")?;
    if !active_journal.is_enabled() {
        bail!("licensed breakage orchestration event journal is disabled");
    }
    for task in tasks {
        let follow_up_assignment = task.supervisor_plan.assignment()?;
        active_journal
            .append(
                writer,
                &follow_up_assignment.id,
                Some(source_assignment_id),
                OrchestrationRole::Orchestrator,
                OrchestrationEventKind::Journal,
                json!({
                    "licensed_breakage_follow_up": task,
                }),
            )
            .context("failed to journal licensed breakage follow-up task")?;
        if !active_journal.is_enabled() {
            bail!("licensed breakage orchestration event journal became disabled");
        }
    }
    autonomy_kpis.observe_licensed_breakage(review.failures.len(), tasks.len());
    Ok(())
}

pub(super) fn orchestration_journal_observable(
    journal: &Option<OrchestrationEventJournal>,
) -> bool {
    journal
        .as_ref()
        .is_some_and(OrchestrationEventJournal::is_enabled)
}

pub(super) fn with_supervisor_artifacts<T>(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    operation: impl FnOnce(&mut ArtifactRunWriter, &mut Option<OrchestrationEventJournal>) -> Result<T>,
) -> Result<T> {
    let mut guard = artifacts
        .lock()
        .map_err(|_| anyhow!("supervisor artifact writer mutex was poisoned"))?;
    guard
        .mutation_session
        .permit(MutationOperation::SupervisorRunArtifactWriteAppend)?
        .verify(MutationOperation::SupervisorRunArtifactWriteAppend)?;
    guard
        .mutation_session
        .permit(MutationOperation::SupervisorOrchestrationJournalLifecycle)?
        .verify(MutationOperation::SupervisorOrchestrationJournalLifecycle)?;
    let SharedSupervisorArtifacts {
        writer, journal, ..
    } = &mut *guard;
    operation(writer, journal)
}

pub(super) fn record_shared_orchestration_event(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    node: &str,
    parent: Option<&str>,
    role: OrchestrationRole,
    kind: OrchestrationEventKind,
    payload: Value,
) -> Result<()> {
    with_supervisor_artifacts(artifacts, |writer, journal| {
        record_orchestration_event(journal, writer, node, parent, role, kind, payload);
        Ok(())
    })
}

pub(super) fn record_gate_correction_event(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    entity_id: &str,
    parent_id: &str,
    denial: &GateDenial,
    state: GateCorrectionJournalState,
    correction_attempt: Option<u8>,
) -> Result<()> {
    let mut guard = artifacts
        .lock()
        .map_err(|_| anyhow!("supervisor artifact writer mutex was poisoned"))?;
    guard
        .mutation_session
        .permit(MutationOperation::SupervisorRunArtifactWriteAppend)?
        .verify(MutationOperation::SupervisorRunArtifactWriteAppend)?;
    guard
        .mutation_session
        .permit(MutationOperation::SupervisorOrchestrationJournalLifecycle)?
        .verify(MutationOperation::SupervisorOrchestrationJournalLifecycle)?;
    let SharedSupervisorArtifacts {
        writer,
        journal,
        autonomy_kpis,
        ..
    } = &mut *guard;
    record_gate_correction_event_strict(
        journal,
        writer,
        entity_id,
        Some(parent_id),
        OrchestrationRole::Orchestrator,
        json!({
            "state": state.as_str(),
            "denial_id": denial.denial_id.as_str(),
            "correction_correlation_id": denial.correction_correlation_id.as_str(),
            "route": denial.route,
            "correction_attempt": correction_attempt,
        }),
    )?;
    autonomy_kpis.observe_gate_correction_event(denial, state, correction_attempt);
    Ok(())
}

pub(super) fn gate_correlation_id(assignment_id: &str, ordinal: usize) -> String {
    format!("{assignment_id}-gate-{ordinal}")
}

pub(super) fn safely_narrow_claim_scope(
    assignment: &OrchestratorAssignment,
    conflicted_paths: &[PathBuf],
) -> Option<OrchestratorAssignment> {
    if conflicted_paths.is_empty() {
        return None;
    }
    let mut narrowed = assignment.clone();
    narrowed.assigned_paths.retain(|path| {
        !conflicted_paths
            .iter()
            .any(|conflicted| paths_overlap(path, conflicted))
    });
    if narrowed.assigned_paths.is_empty() || narrowed.assigned_paths == assignment.assigned_paths {
        return None;
    }
    for (narrowed_worker, original_worker) in narrowed
        .worker_assignments
        .iter_mut()
        .zip(&assignment.worker_assignments)
    {
        narrowed_worker.assigned_paths.retain(|path| {
            !conflicted_paths
                .iter()
                .any(|conflicted| paths_overlap(path, conflicted))
                && narrowed
                    .assigned_paths
                    .iter()
                    .any(|assigned| paths_overlap(path, assigned))
        });
        if !original_worker.assigned_paths.is_empty() && narrowed_worker.assigned_paths.is_empty() {
            return None;
        }
    }
    Some(narrowed)
}

pub fn structured_merge_gate_denial(
    correction_correlation_id: &str,
    owner: &str,
    source: GateCheckSource,
    detail: &ApplyBlockerDetail,
) -> Result<GateDenial> {
    let denial =
        GateDenial::from_apply_blocker_detail(correction_correlation_id, owner, source, detail)
            .context("failed to adapt structured merge blocker into gate denial")?;
    if denial.route != GateDenialRoute::IntegrationController {
        bail!("merge blocker denial did not route to the integration controller");
    }
    Ok(denial)
}

pub fn external_side_effect_gate_denial<I, P>(
    correction_correlation_id: &str,
    owner: &str,
    state: ExternalSideEffectState,
    paths: I,
) -> Result<GateDenial>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    let denial = GateDenial::new(
        correction_correlation_id,
        GateDenialReason::ExternalSideEffect { state },
        VerifiedGateContext::new(owner, GateCheckSource::ExternalSideEffect, paths)?,
    )
    .context("failed to construct external-side-effect gate denial")?;
    if denial.retryability != GateRetryability::NotRetryable
        || denial.route != GateDenialRoute::IntegrationController
    {
        bail!("external side effect did not fail closed to the integration controller");
    }
    Ok(denial)
}

pub(super) fn release_concurrent_assignment(
    outcome: &mut AssignmentExecutionOutcome,
    sync_store: &SyncStore,
    semantic_store: &SemanticIntentStore,
    claim_release_permit: &crate::mutation_taxonomy::SupervisorOperationPermit<'_>,
    semantic_release_permit: &crate::mutation_taxonomy::SupervisorOperationPermit<'_>,
) -> Result<()> {
    claim_release_permit
        .verify(MutationOperation::ClaimRelease)
        .map_err(anyhow::Error::from)?;
    semantic_release_permit
        .verify(MutationOperation::SemanticIntentRelease)
        .map_err(anyhow::Error::from)?;
    let (released_claims, release_errors) = release_claims(
        sync_store,
        std::mem::take(&mut outcome.claim_tokens),
        claim_release_permit,
    );
    let (released_semantic_intents, semantic_release_errors) = release_semantic_intents(
        semantic_store,
        std::mem::take(&mut outcome.semantic_tokens),
        semantic_release_permit,
    );
    outcome.released_claims = released_claims;
    outcome.release_errors = release_errors;
    outcome.released_semantic_intents = released_semantic_intents;
    outcome.semantic_release_errors = semantic_release_errors;
    if outcome.fatal_error.is_none()
        && (!outcome.release_errors.is_empty() || !outcome.semantic_release_errors.is_empty())
    {
        outcome.fatal_error = Some(
            "supervisor assignment cleanup failed; scheduling stopped after joining active assignments"
                .to_string(),
        );
    }
    Ok(())
}

pub(super) fn assignment_outcome_succeeded(outcome: &AssignmentExecutionOutcome) -> bool {
    !outcome.assignment_failed
        && !outcome.external_containment_failed
        && outcome.fatal_error.is_none()
        && outcome.release_errors.is_empty()
        && outcome.semantic_release_errors.is_empty()
        && outcome
            .report
            .as_ref()
            .is_some_and(|report| !report_failed(report))
}

pub(super) fn assignment_admission_state(
    index: usize,
    schedule: &[AssignmentScheduleEntry],
    indexed_outcomes: &[Option<AssignmentExecutionOutcome>],
) -> Result<AssignmentAdmissionState> {
    let entry = schedule
        .get(index)
        .context("assignment admission referenced an index outside the validated schedule")?;
    let Some(parent_assignment_id) = entry.parent_assignment_id.as_deref() else {
        return Ok(AssignmentAdmissionState::Ready);
    };
    let parent_index = schedule
        .iter()
        .position(|candidate| candidate.assignment_id == parent_assignment_id)
        .with_context(|| {
            format!(
                "assignment '{}' references missing parent '{}'",
                entry.assignment_id, parent_assignment_id
            )
        })?;
    match indexed_outcomes.get(parent_index).and_then(Option::as_ref) {
        None => Ok(AssignmentAdmissionState::Waiting),
        Some(outcome) if assignment_outcome_succeeded(outcome) => {
            Ok(AssignmentAdmissionState::Ready)
        }
        Some(_) => Ok(AssignmentAdmissionState::Suppressed {
            parent_assignment_id: parent_assignment_id.to_string(),
        }),
    }
}

pub(super) fn suppressed_descendant_outcome(
    assignment: &OrchestratorAssignment,
    parent_assignment_id: &str,
) -> AssignmentExecutionOutcome {
    AssignmentExecutionOutcome {
        findings: vec![Finding {
            severity: FindingSeverity::Error,
            message: format!(
                "supervisor assignment '{}' was not dispatched because parent '{}' did not complete successfully",
                assignment.id, parent_assignment_id
            ),
            paths: assignment.assigned_paths.clone(),
        }],
        assignment_failed: true,
        ..AssignmentExecutionOutcome::default()
    }
}

pub(super) fn suppress_failed_descendants(
    pending: &mut BTreeSet<usize>,
    indexed_outcomes: &mut [Option<AssignmentExecutionOutcome>],
    plan: &SupervisorPlan,
    schedule: &[AssignmentScheduleEntry],
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
) -> Result<()> {
    loop {
        let mut suppressed = None;
        for index in pending.iter().copied() {
            if let AssignmentAdmissionState::Suppressed {
                parent_assignment_id,
            } = assignment_admission_state(index, schedule, indexed_outcomes)?
            {
                suppressed = Some((index, parent_assignment_id));
                break;
            }
        }
        let Some((index, parent_assignment_id)) = suppressed else {
            return Ok(());
        };
        pending.remove(&index);
        let assignment = plan
            .assignments
            .get(index)
            .context("suppressed assignment index is outside the supervisor plan")?;
        record_shared_orchestration_event(
            artifacts,
            &assignment.id,
            Some(&parent_assignment_id),
            OrchestrationRole::Orchestrator,
            OrchestrationEventKind::Reject,
            json!({
                "status": "suppressed",
                "reason": "parent_assignment_failed",
                "parent_assignment_id": parent_assignment_id,
            }),
        )?;
        let slot = indexed_outcomes
            .get_mut(index)
            .context("suppressed assignment index is outside scheduler outcomes")?;
        *slot = Some(suppressed_descendant_outcome(
            assignment,
            &parent_assignment_id,
        ));
    }
}

fn assignment_health_outcome(outcome: &AssignmentExecutionOutcome) -> AssignmentHealthOutcome {
    match outcome.report.as_ref() {
        Some(report)
            if report.rejected
                || report.status == ReviewStatus::Rejected
                || report.status == ReviewStatus::Missing =>
        {
            AssignmentHealthOutcome::Rejected
        }
        Some(report) if report_failed(report) => AssignmentHealthOutcome::Failed,
        Some(_) => AssignmentHealthOutcome::Accepted,
        None => AssignmentHealthOutcome::Failed,
    }
}

pub(super) fn observe_assignment_health(
    breaker: &mut SwarmHealthCircuitBreaker,
    outcome: &AssignmentExecutionOutcome,
) -> Option<CircuitBreakerTrip> {
    let final_outcome = SwarmHealthSignal::AssignmentOutcome(assignment_health_outcome(outcome));
    outcome
        .health_signals
        .iter()
        .copied()
        .chain(std::iter::once(final_outcome))
        .find_map(|signal| match breaker.observe(signal) {
            Some(CircuitBreakerTransition::Opened(trip)) => Some(trip),
            Some(CircuitBreakerTransition::EnteredHalfOpen | CircuitBreakerTransition::Closed)
            | None => None,
        })
}

pub(super) fn record_breaker_trip(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    run_id: &RunId,
    trip: &CircuitBreakerTrip,
) -> Result<()> {
    let mut guard = artifacts
        .lock()
        .map_err(|_| anyhow!("supervisor artifact writer mutex was poisoned"))?;
    guard
        .mutation_session
        .permit(MutationOperation::SupervisorRunArtifactWriteAppend)?
        .verify(MutationOperation::SupervisorRunArtifactWriteAppend)?;
    guard
        .mutation_session
        .permit(MutationOperation::SupervisorOrchestrationJournalLifecycle)?
        .verify(MutationOperation::SupervisorOrchestrationJournalLifecycle)?;
    let SharedSupervisorArtifacts {
        writer,
        journal,
        autonomy_kpis,
        ..
    } = &mut *guard;
    // The transition event precedes the scheduler's active-assignment drain, so its KPI
    // payload is deliberately a counter-only snapshot. Final reporting runs after the
    // drain and may expose rates for its closed, strictly journaled event population.
    let autonomy_kpis =
        autonomy_kpis.breaker_trip_report(orchestration_journal_observable(journal));
    record_orchestration_event(
        journal,
        writer,
        run_id.as_str(),
        None,
        OrchestrationRole::Supervisor,
        OrchestrationEventKind::Gate,
        json!({
            "gate": "swarm_health_circuit_breaker",
            "transition": "closed_to_open",
            "trip": trip,
            "autonomy_kpis": autonomy_kpis,
            "drain_policy": "finish_active_without_admitting_pending",
        }),
    );
    Ok(())
}

pub(super) fn record_assignment_spawn_failure(
    indexed_outcomes: &mut [Option<AssignmentExecutionOutcome>],
    stop_scheduling: &mut bool,
    index: usize,
    assignment_id: &str,
    error: &std::io::Error,
) -> Result<()> {
    *stop_scheduling = true;
    let slot = indexed_outcomes
        .get_mut(index)
        .context("spawn failure referenced an assignment outside the scheduler plan")?;
    *slot = Some(AssignmentExecutionOutcome::fatal(format!(
        "failed to spawn supervisor assignment '{assignment_id}' thread: {error}"
    )));
    Ok(())
}
