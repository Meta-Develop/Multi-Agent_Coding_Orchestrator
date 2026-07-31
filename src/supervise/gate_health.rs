use super::*;

pub(super) fn with_supervisor_artifacts<T>(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    operation: impl FnOnce(&mut ArtifactRunWriter, &mut Option<OrchestrationEventJournal>) -> Result<T>,
) -> Result<T> {
    let mut guard = artifacts
        .lock()
        .map_err(|_| anyhow!("supervisor artifact writer mutex was poisoned"))?;
    let SharedSupervisorArtifacts { writer, journal } = &mut *guard;
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
    state: &str,
    correction_attempt: Option<u8>,
) -> Result<()> {
    with_supervisor_artifacts(artifacts, |writer, journal| {
        record_gate_correction_event_strict(
            journal,
            writer,
            entity_id,
            Some(parent_id),
            OrchestrationRole::Orchestrator,
            json!({
                "state": state,
                "denial_id": denial.denial_id.as_str(),
                "correction_correlation_id": denial.correction_correlation_id.as_str(),
                "route": denial.route,
                "correction_attempt": correction_attempt,
            }),
        )
    })
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
) {
    let (released_claims, release_errors) =
        release_claims(sync_store, std::mem::take(&mut outcome.claim_tokens));
    let (released_semantic_intents, semantic_release_errors) =
        release_semantic_intents(semantic_store, std::mem::take(&mut outcome.semantic_tokens));
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
    record_shared_orchestration_event(
        artifacts,
        run_id.as_str(),
        None,
        OrchestrationRole::Supervisor,
        OrchestrationEventKind::Gate,
        json!({
            "gate": "swarm_health_circuit_breaker",
            "transition": "closed_to_open",
            "trip": trip,
            "drain_policy": "finish_active_without_admitting_pending",
        }),
    )
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
