use super::*;

pub(super) fn reserve_dispatch_budget<'a>(
    plan: &SupervisorPlan,
    budget_config: &SupervisorBudgetConfig,
    ledger: &'a RunBudgetLedger,
    role: AgentRole,
    command: &ExternalAgentCommand,
) -> Result<DispatchBudgetAdmission<'a>> {
    let tokens = budget_config.reservation_tokens(role).with_context(|| {
        format!(
            "run_budget has no token reservation for dispatched role '{}'",
            role.as_str()
        )
    })?;
    let pricing = command.model.as_ref().and_then(|model| {
        crate::llm::provider::resolve_model_pricing(&plan.model_pricing, model)
            .map(|resolved| resolved.pricing)
    });
    let cost_usd = pricing
        .map(|pricing| {
            const TOKENS_PER_MILLION: f64 = 1_000_000.0;
            let conservative_rate = pricing
                .input_usd_per_million_tokens
                .max(pricing.output_usd_per_million_tokens);
            tokens as f64 * conservative_rate / TOKENS_PER_MILLION
        })
        .filter(|cost| cost.is_finite());
    match ledger
        .reserve(BudgetReservationRequest {
            role,
            tokens,
            cost_usd,
        })
        .context("run budget admission failed")?
    {
        BudgetAdmission::Admitted { reservation, .. } => Ok(DispatchBudgetAdmission::Admitted(
            DispatchBudgetReservation {
                ledger,
                reservation,
                pricing,
                state: DispatchBudgetReservationState::Reserved,
            },
        )),
        BudgetAdmission::Refused { refusal, .. } => Ok(DispatchBudgetAdmission::Refused(refusal)),
    }
}

pub(super) fn external_dispatch_may_have_started(
    run: &ExternalAgentRun,
    runtime: SupervisorRuntime,
) -> bool {
    runtime == SupervisorRuntime::Fake
        || run.process_tree.is_some()
        || !run.scratch_quiescence_verified()
}

pub(super) fn record_budget_dispatch_refusal(
    outcome: &mut AssignmentExecutionOutcome,
    assignment: &OrchestratorAssignment,
    owner: &str,
    role: AgentRole,
    refusal: &BudgetAdmissionRefusal,
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    journal_parent_id: &str,
) -> Result<()> {
    let denial = GateDenial::new(
        outcome
            .gate_tracker
            .as_ref()
            .context("gate correction tracker was not initialized")?
            .correlation_id_for_observation(&assignment.id),
        GateDenialReason::BudgetAdmission {
            denial: match refusal {
                BudgetAdmissionRefusal::NewDispatchStopped => {
                    BudgetAdmissionDenial::NewDispatchStopped
                }
                BudgetAdmissionRefusal::MissingCostEstimate => {
                    BudgetAdmissionDenial::MissingCostEstimate
                }
                BudgetAdmissionRefusal::HardTokenCeiling { .. } => {
                    BudgetAdmissionDenial::HardTokenCeiling
                }
                BudgetAdmissionRefusal::HardCostCeiling { .. } => {
                    BudgetAdmissionDenial::HardCostCeiling
                }
            },
        },
        VerifiedGateContext::new(
            owner,
            GateCheckSource::BudgetAdmission,
            &assignment.assigned_paths,
        )?,
    )
    .context("failed to construct budget-admission gate denial")?;
    outcome
        .gate_tracker
        .as_mut()
        .context("gate correction tracker was not initialized")?
        .escalate(denial, artifacts, &assignment.id, journal_parent_id)?;
    outcome.assignment_failed = true;
    outcome.budget_dispatch_stopped = true;
    outcome.findings.push(Finding {
        severity: FindingSeverity::Error,
        message: format!(
            "run budget denied new '{}' dispatch for assignment '{}'; inspect the typed gate denial and run_budget report",
            role.as_str(),
            assignment.id
        ),
        paths: assignment.assigned_paths.clone(),
    });
    Ok(())
}

pub(super) fn record_isolated_assignment_failure(
    outcome: &mut AssignmentExecutionOutcome,
    assignment: &OrchestratorAssignment,
    stage: &str,
    error: &anyhow::Error,
) {
    outcome.assignment_failed = true;
    outcome.findings.push(Finding {
        severity: FindingSeverity::Error,
        message: format!(
            "supervisor assignment '{}' failed during {stage}: {error:#}",
            assignment.id
        ),
        paths: assignment.assigned_paths.clone(),
    });
}

pub(super) fn semantic_resolution_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let message = cause.to_string();
        message.starts_with("unresolved semantic symbol:")
            || message.starts_with("ambiguous semantic symbol ")
            || message.starts_with("unresolved semantic module:")
            || message == "symbol query cannot be empty"
            || message == "module query cannot be empty"
    })
}

pub(super) fn semantic_resolution_finding(
    assignment: &OrchestratorAssignment,
    error: &anyhow::Error,
) -> Finding {
    Finding {
        severity: FindingSeverity::Error,
        message: format!(
            "supervisor assignment '{}' failed during semantic resolution: {error:#}",
            assignment.id
        ),
        paths: assignment.assigned_paths.clone(),
    }
}
