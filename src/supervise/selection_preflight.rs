//! Evaluation of frozen selection inputs without launch or selection authority.

use super::*;

const MAX_PREFLIGHT_ENTRIES: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenRoleSelectionInput {
    pub input: SelectionInput,
    pub routing_policy: Option<crate::selection::routing_policy::RoutingPolicyReceipt>,
    #[serde(default)]
    pub switch_cost_evidence: Vec<CandidateSwitchCostEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenSupervisorSelectionInputs {
    pub schema_version: u32,
    pub plan_sha256: String,
    pub roles: BTreeMap<AgentRole, FrozenRoleSelectionInput>,
    #[serde(default)]
    pub unavailable: BTreeMap<AgentRole, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionPreflightStatus {
    Compatible,
    Rejected,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionPreflightRejection {
    UnavailableInput,
    InvalidInput,
    InvalidContract,
    ModelUnavailable,
    EffortIncompatible,
    Eligibility,
    UnexecutableRuntime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionPreflightRequested {
    pub runtime: String,
    pub model: Option<String>,
    pub effort: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionPreflightDiagnostic {
    pub role: AgentRole,
    pub lens_id: Option<String>,
    pub requested: Option<SelectionPreflightRequested>,
    pub task: Option<TaskProfile>,
    pub status: SelectionPreflightStatus,
    pub rejection: Option<SelectionPreflightRejection>,
    pub message: String,
    /// Only efforts for the requested runtime/model that passed every hard gate.
    /// None means the frozen evidence could not establish eligibility.
    pub eligible_efforts: Option<Vec<SelectorEffort>>,
    pub ineligibility_reasons: Vec<selection::IneligibilityReason>,
    pub decision: Option<SelectionProvenance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupervisorSelectionPreflightReport {
    pub schema_version: u32,
    pub compatible: bool,
    pub diagnostics: Vec<SelectionPreflightDiagnostic>,
    pub frozen_inputs: FrozenSupervisorSelectionInputs,
}

pub(super) fn plan_digest(plan: &SupervisorPlan) -> Result<String> {
    Ok(crate::artifacts::state_auth::sha256_hex(
        &serde_json::to_vec(plan)?,
    ))
}

pub(super) fn refusal_message(report: &SupervisorSelectionPreflightReport) -> Result<String> {
    let failures: Vec<_> = report
        .diagnostics
        .iter()
        .filter(|entry| entry.status != SelectionPreflightStatus::Compatible)
        .map(|entry| {
            serde_json::json!({
                "role": entry.role, "lens_id": entry.lens_id, "requested": entry.requested,
                "task": entry.task, "status": entry.status, "rejection": entry.rejection,
                "message": entry.message, "eligible_efforts": entry.eligible_efforts,
                "ineligibility_reasons": entry.ineligibility_reasons,
                "input_digests": entry.decision.as_ref().map(|decision| &decision.input_digests),
            })
        })
        .collect();
    Ok(format!(
        "selection preflight refused: {}",
        serde_json::to_string(&failures)?
    ))
}

pub(super) fn freeze_role_input(
    mut input: SelectionInput,
    routing_policy: Option<crate::selection::routing_policy::RoutingPolicyReceipt>,
) -> FrozenRoleSelectionInput {
    selection::runtime_model_policy::constrain(&mut input);
    if super::super::runtime_executables::captured_binding().is_some() {
        super::super::runtime_executables::constrain_selection(&mut input);
    }
    let switch_cost_evidence = live_switch_cost_evidence(&input);
    FrozenRoleSelectionInput {
        input,
        routing_policy,
        switch_cost_evidence,
    }
}

pub(super) fn freeze_quota_ledger(
    context: Option<&LiveQuotaSelectionContext>,
    ledger: Option<&RunBudgetLedger>,
) -> Result<Option<crate::optimizer::quota_pools::ConsumptionLedger>> {
    context
        .map(|context| {
            ledger
                .context(
                    "operator quota selection requires the scheduler's attached run budget ledger",
                )?
                .quota_consumption_ledger(&context.config, crate::budget_ledger::unix_now()?)
                .map_err(|error| {
                    anyhow!("failed to project attached operator quota ledger: {error}")
                })
        })
        .transpose()
}

pub(super) fn apply_frozen_quota(
    input: &mut SelectionInput,
    runtime: SupervisorRuntime,
    context: Option<&LiveQuotaSelectionContext>,
    ledger: Option<&crate::optimizer::quota_pools::ConsumptionLedger>,
) -> Result<()> {
    if let Some(context) = context {
        let source = live_quota_pool_for_runtime(context, runtime.as_str())?;
        input.quota_source = Some(crate::optimizer::quota_pools::PoolReference {
            runtime: source.runtime.clone(),
            account: source.account.clone(),
            window: source.window,
        });
        selection::apply_fail_closed_quota_pools(
            input,
            &context.config.pools,
            ledger.context("frozen quota ledger is unavailable")?,
        )?;
        input.operational_observations = Some(live_operational_observations(input));
    }
    Ok(())
}

fn requested(
    plan: &SupervisorPlan,
    role: AgentRole,
    runtime: SupervisorRuntime,
) -> Option<SelectionPreflightRequested> {
    plan.role_models
        .get(&role)
        .map(|value| SelectionPreflightRequested {
            runtime: authored_override_runtime(plan, role, runtime)
                .unwrap_or(runtime)
                .as_str()
                .to_string(),
            model: value.model.clone(),
            effort: value.reasoning_effort.clone(),
        })
}

fn unavailable_diagnostic(
    role: AgentRole,
    lens_id: Option<String>,
    requested: Option<SelectionPreflightRequested>,
    message: String,
) -> SelectionPreflightDiagnostic {
    SelectionPreflightDiagnostic {
        role,
        lens_id,
        requested,
        task: None,
        status: SelectionPreflightStatus::Unknown,
        rejection: Some(SelectionPreflightRejection::UnavailableInput),
        message,
        eligible_efforts: None,
        ineligibility_reasons: Vec::new(),
        decision: None,
    }
}

pub(in crate::supervise) fn selected_choice_rejection(
    decision: &SelectionProvenance,
) -> Option<SelectionPreflightRejection> {
    match decision.choice.as_ref() {
        None => Some(SelectionPreflightRejection::InvalidContract),
        Some(choice) if runtime_from_name(&choice.candidate.runtime).is_err() => {
            Some(SelectionPreflightRejection::UnexecutableRuntime)
        }
        Some(choice)
            if decision
                .normalized_input
                .debug_override
                .as_ref()
                .is_some_and(|request| request.candidate != choice.candidate) =>
        {
            Some(SelectionPreflightRejection::InvalidContract)
        }
        Some(_) => None,
    }
}

fn evaluate(
    role: AgentRole,
    lens_id: Option<String>,
    requested: Option<SelectionPreflightRequested>,
    frozen: &FrozenRoleSelectionInput,
) -> SelectionPreflightDiagnostic {
    let mut diagnostic = unavailable_diagnostic(role, lens_id, requested, String::new());
    diagnostic.task = Some(frozen.input.task.clone());
    if frozen.input.catalogs.is_empty() {
        diagnostic.message =
            "frozen model catalog is unavailable; eligibility is unknown".to_string();
        return diagnostic;
    }
    let result = selection::select_with_loaded_routing_policy(
        &frozen.input,
        &frozen.switch_cost_evidence,
        frozen.routing_policy.as_ref(),
    );
    let decision = match result {
        Ok(decision) => decision,
        Err(error) => {
            diagnostic.status = SelectionPreflightStatus::Rejected;
            diagnostic.rejection = Some(SelectionPreflightRejection::InvalidInput);
            diagnostic.message = error.to_string();
            return diagnostic;
        }
    };
    let input = &decision.normalized_input;
    let candidate = input
        .debug_override
        .as_ref()
        .map(|request| &request.candidate);
    let model = candidate.and_then(|candidate| {
        input
            .catalogs
            .iter()
            .find(|catalog| catalog.runtime == candidate.runtime)
            .and_then(|catalog| {
                catalog
                    .models
                    .iter()
                    .find(|model| model.model == candidate.model)
            })
    });
    let eligible_efforts = candidate.map(|requested| {
        decision
            .candidate_set
            .iter()
            .filter(|entry| {
                entry.eligible
                    && entry.candidate.runtime == requested.runtime
                    && entry.candidate.model == requested.model
            })
            .map(|entry| entry.candidate.effort)
            .collect()
    });
    diagnostic.eligible_efforts = eligible_efforts;
    diagnostic.ineligibility_reasons = candidate
        .and_then(|requested| {
            decision
                .candidate_set
                .iter()
                .find(|entry| &entry.candidate == requested)
        })
        .map(|entry| entry.ineligibility_reasons.clone())
        .unwrap_or_default();
    if decision.status != DecisionStatus::Selected {
        diagnostic.status = SelectionPreflightStatus::Rejected;
        diagnostic.rejection = Some(
            if candidate.is_some()
                && model.is_none_or(|model| {
                    !model.available
                        || model.access == Some(selection::ModelAccessOutcome::Unavailable)
                })
            {
                SelectionPreflightRejection::ModelUnavailable
            } else if candidate.zip(model).is_some_and(|(candidate, model)| {
                !model.supported_efforts.contains(&candidate.effort)
            }) {
                SelectionPreflightRejection::EffortIncompatible
            } else {
                SelectionPreflightRejection::Eligibility
            },
        );
        diagnostic.message = selection_refusal_message(&decision, role);
    } else if let Some(rejection) = selected_choice_rejection(&decision) {
        diagnostic.status = SelectionPreflightStatus::Rejected;
        diagnostic.rejection = Some(rejection);
        diagnostic.message = match rejection {
            SelectionPreflightRejection::UnexecutableRuntime => {
                "selected choice uses an unexecutable runtime"
            }
            _ => "selected choice is missing or differs from the explicit override",
        }
        .to_string();
    } else {
        diagnostic.status = SelectionPreflightStatus::Compatible;
        diagnostic.rejection = None;
        diagnostic.message = decision.decision_reason.clone();
    }
    diagnostic.decision = Some(decision);
    diagnostic
}

/// Evaluate an exact plan and frozen evidence. This function performs no I/O,
/// selection sealing, budget reservation, or workload dispatch.
pub fn evaluate_supervisor_selection_preflight(
    plan: &SupervisorPlan,
    runtime: SupervisorRuntime,
    frozen: FrozenSupervisorSelectionInputs,
) -> Result<SupervisorSelectionPreflightReport> {
    if frozen.schema_version != 1 || frozen.plan_sha256 != plan_digest(plan)? {
        bail!("selection preflight snapshot version or plan digest does not match");
    }
    let roles = required_selector_roles(plan);
    if roles.len().saturating_add(plan.review_lenses.len()) > MAX_PREFLIGHT_ENTRIES {
        bail!("selection preflight exceeds the diagnostic entry limit");
    }
    // A snapshot cannot mix policy, assessment, objective, or prior revisions.
    if let Some((_, first)) = frozen.roles.iter().find(|(role, _)| roles.contains(role)) {
        for (role, entry) in frozen.roles.iter().filter(|(role, _)| roles.contains(role)) {
            if entry.input.priors != first.input.priors
                || entry.input.objective_profile != first.input.objective_profile
                || entry.input.resolved_objective_profile != first.input.resolved_objective_profile
                || entry
                    .routing_policy
                    .as_ref()
                    .map(|receipt| (&receipt.frozen, &receipt.features))
                    != first
                        .routing_policy
                        .as_ref()
                        .map(|receipt| (&receipt.frozen, &receipt.features))
                || role_for_task_profile(&entry.input.task)? != *role
                || entry
                    .routing_policy
                    .as_ref()
                    .is_some_and(|receipt| receipt.role != role.as_str())
            {
                bail!("selection preflight snapshot mixes frozen inputs or role authority");
            }
        }
    }
    let mut diagnostics = Vec::new();
    for role in roles {
        let request = requested(plan, role, runtime);
        let Some(entry) = frozen.roles.get(&role) else {
            let mut diagnostic =
                unavailable_diagnostic(
                    role,
                    None,
                    request,
                    frozen.unavailable.get(&role).cloned().unwrap_or_else(|| {
                        "frozen role selection input is unavailable".to_string()
                    }),
                );
            if let Some(selection) = plan.role_models.get(&role) {
                if let Err(error) = authored_override_runtime(plan, role, runtime)
                    .and_then(|runtime| debug_override_for_role(role, runtime, selection))
                {
                    diagnostic.status = SelectionPreflightStatus::Rejected;
                    diagnostic.rejection = Some(SelectionPreflightRejection::InvalidContract);
                    diagnostic.message = error.to_string();
                }
            }
            diagnostics.push(diagnostic);
            continue;
        };
        let mut entry = entry.clone();
        // Saved evidence supplies capabilities, never an alternative override.
        match plan
            .role_models
            .get(&role)
            .map(|value| {
                debug_override_for_role(
                    role,
                    authored_override_runtime(plan, role, runtime)?,
                    value,
                )
            })
            .transpose()
        {
            Ok(value) => entry.input.debug_override = value,
            Err(error) => {
                let mut diagnostic = unavailable_diagnostic(role, None, request, error.to_string());
                diagnostic.task = Some(entry.input.task.clone());
                diagnostic.status = SelectionPreflightStatus::Rejected;
                diagnostic.rejection = Some(SelectionPreflightRejection::InvalidContract);
                diagnostics.push(diagnostic);
                continue;
            }
        }
        diagnostics.push(evaluate(role, None, request, &entry));
    }
    if plan.review_lenses != default_supervisor_review_lenses() {
        for lens in &plan.review_lenses {
            let runtime_name = diagnostics
                .iter()
                .find(|entry| entry.role == AgentRole::Auditor && entry.lens_id.is_none())
                .and_then(|entry| entry.decision.as_ref())
                .and_then(|decision| decision.choice.as_ref())
                .map(|choice| choice.candidate.runtime.as_str())
                .unwrap_or(
                    authored_override_runtime(plan, AgentRole::Auditor, runtime)
                        .unwrap_or(runtime)
                        .as_str(),
                )
                .to_string();
            let request = match &lens.backend {
                ReviewLensBackendConfig::Model {
                    model,
                    reasoning_effort,
                    ..
                } => Some(SelectionPreflightRequested {
                    runtime: runtime_name.clone(),
                    model: Some(model.clone()),
                    effort: reasoning_effort.clone(),
                }),
                ReviewLensBackendConfig::Precomputed { .. } => None,
            };
            let Some(baseline) = frozen.roles.get(&AgentRole::Auditor) else {
                diagnostics.push(unavailable_diagnostic(
                    AgentRole::Auditor,
                    Some(lens.id.clone()),
                    request,
                    "custom review lens requires the frozen Auditor selection input".to_string(),
                ));
                continue;
            };
            let mut entry = baseline.clone();
            let contract = request.as_ref().and_then(|request| {
                Some(CandidateKey {
                    runtime: request.runtime.clone(),
                    model: request.model.clone()?,
                    effort: selector_effort_from_str(request.effort.as_deref()?)?,
                })
            });
            let Some(candidate) = contract.filter(|candidate| !candidate.model.is_empty()) else {
                let mut diagnostic = unavailable_diagnostic(AgentRole::Auditor, Some(lens.id.clone()), request,
                    format!("custom review lens '{}' requires an explicit model and supported effort; precomputed lenses have no executable reasoning-effort field", lens.id));
                diagnostic.task = Some(entry.input.task.clone());
                diagnostic.status = SelectionPreflightStatus::Rejected;
                diagnostic.rejection = Some(SelectionPreflightRejection::InvalidContract);
                diagnostics.push(diagnostic);
                continue;
            };
            entry
                .input
                .constraints
                .allowed_runtimes
                .retain(|allowed| allowed == &runtime_name);
            entry.input.constraints.allow_debug_override = true;
            entry.input.debug_override = Some(DebugOverride {
                candidate,
                requested_by: "supervisor_plan.review_lenses".to_string(),
                reason: format!(
                    "exact authored review lens '{}' after all hard eligibility gates",
                    lens.id
                ),
            });
            let mut diagnostic =
                evaluate(AgentRole::Auditor, Some(lens.id.clone()), request, &entry);
            if diagnostics.iter().any(|entry| {
                entry.role == AgentRole::Auditor
                    && entry.lens_id.is_none()
                    && entry.status != SelectionPreflightStatus::Compatible
            }) && diagnostic.status == SelectionPreflightStatus::Compatible
            {
                diagnostic.status = SelectionPreflightStatus::Rejected;
                diagnostic.rejection = Some(SelectionPreflightRejection::InvalidContract);
                diagnostic.message =
                    "custom review lens requires a selector-validated Auditor contract".to_string();
            }
            diagnostics.push(diagnostic);
        }
    }
    Ok(SupervisorSelectionPreflightReport {
        schema_version: 1,
        compatible: diagnostics
            .iter()
            .all(|entry| entry.status == SelectionPreflightStatus::Compatible),
        diagnostics,
        frozen_inputs: frozen,
    })
}

/// Read only the supplied plan and optional frozen inputs. Missing live data
/// remains unknown; this entrypoint never acquires catalogs or account data.
pub fn supervisor_selection_preflight_file(
    plan_file: &Path,
    runtime: SupervisorRuntime,
    frozen_inputs_file: Option<&Path>,
) -> Result<SupervisorSelectionPreflightReport> {
    let plan = super::super::plan_api::load_supervisor_plan_file(plan_file)?;
    let frozen = match frozen_inputs_file {
        Some(path) => serde_json::from_str(&BoundedRegularReader::read_tree_no_follow_utf8(
            path,
            16 * 1024 * 1024,
        )?)?,
        None => FrozenSupervisorSelectionInputs {
            schema_version: 1,
            plan_sha256: plan_digest(&plan)?,
            roles: BTreeMap::new(),
            unavailable: BTreeMap::new(),
        },
    };
    evaluate_supervisor_selection_preflight(&plan, runtime, frozen)
}
