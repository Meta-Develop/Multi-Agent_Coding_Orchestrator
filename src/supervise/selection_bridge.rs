//! Supervisor integration for the pure runtime/model/effort selector.
//!
//! The bridge is intentionally the only place where supervisor runtime state
//! is translated into selector input. The selector remains deterministic and
//! cannot inspect the host, clock, catalog, or supervisor plan directly.

use super::*;
use crate::selection::{
    self, AuthorityRole, Boundedness, BudgetSignal, CandidateCapabilities, CandidateKey,
    CatalogModel, ContextSize, DebugOverride, DecisionStatus, DynamicSignals, ObjectiveProfileRef,
    OperatorConstraints, ReasoningEffort as SelectorEffort, RiskLevel, RuntimeCatalog,
    RuntimePoolState, SelectionInput, SelectionProvenance, TaskHorizon, TaskProfile,
};

const AUTOMATIC_SELECTION_TASK_CLASS: &str = "localized_code_change";
const JUDGMENT_SELECTION_TASK_CLASS: &str = "review_gate";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SupervisorSelectionMode {
    Automatic,
    DebugOverride,
    LegacyFake,
    LegacyNonpublishableSimulation,
}

pub(super) fn uses_legacy_nonpublishable_explicit_selection(
    execution_runtime: SupervisorExecutionRuntime,
    _plan: &SupervisorPlan,
) -> bool {
    execution_runtime == SupervisorExecutionRuntime::NonpublishableSimulation
}

#[derive(Debug, Clone)]
pub(super) struct SupervisorSelectionResolution {
    pub(super) mode: SupervisorSelectionMode,
    pub(super) decisions: Vec<SupervisorSelectionEvent>,
    pub(super) automatic_state: Option<SupervisorAutomaticSelectionState>,
    pub(super) selection_preflight_failure: Option<SupervisorSelectionPreflightFailure>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SupervisorSelectionPreflightFailureKind {
    FailClosed,
    ActiveRuntimeMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SupervisorSelectionPreflightFailure {
    pub(super) role: AgentRole,
    pub(super) kind: SupervisorSelectionPreflightFailureKind,
    pub(super) message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SupervisorAutomaticSelectionState {
    decisions: BTreeMap<AgentRole, SelectionProvenance>,
}

#[derive(Debug, Clone)]
pub(super) struct TypedSelectorEnvironmentRejection {
    pub(super) role: AgentRole,
    pub(super) rejection: selection::EnvironmentRejectionState,
}

#[derive(Debug, Clone)]
pub(super) struct SupervisorReselection {
    pub(super) overrides: BTreeMap<AgentRole, RoleModelSelection>,
    pub(super) decisions: Vec<(AgentRole, SelectionProvenance)>,
}

pub(super) fn initialize_supervisor_selection(
    plan: &mut SupervisorPlan,
    runtime: SupervisorRuntime,
    catalog: &RuntimeModelCatalog,
    admission: &SupervisorAdmissionPolicyInput,
) -> Result<SupervisorSelectionResolution> {
    if runtime == SupervisorRuntime::Fake {
        return Ok(SupervisorSelectionResolution {
            mode: SupervisorSelectionMode::LegacyFake,
            decisions: Vec::new(),
            automatic_state: None,
            selection_preflight_failure: None,
        });
    }

    let automatic = plan.role_models.is_empty();
    let roles = if automatic {
        all_selector_roles().to_vec()
    } else {
        plan.role_models.keys().copied().collect()
    };
    let mut resolved = BTreeMap::new();
    let mut decisions = Vec::with_capacity(roles.len());
    for role in roles {
        let configured = plan.role_models.get(&role);
        let debug_override = configured
            .map(|selection| debug_override_for_role(role, runtime, selection))
            .transpose()?;
        let input = selection_input_for_role(
            role,
            runtime,
            catalog,
            admission,
            DynamicSignals {
                retry_count: 0,
                budget_signal: BudgetSignal::Continue,
                previous_choice: None,
                previous_catalog_digest: None,
                environment_rejections: Vec::new(),
            },
            debug_override,
        )?;
        let decision = selection::select(&input).map_err(|error| {
            anyhow!(
                "automatic selector rejected role '{}': {error}",
                role.as_str()
            )
        })?;
        let primary_cause = if automatic {
            SupervisorSelectionEventCause::Initial
        } else {
            SupervisorSelectionEventCause::DebugOverride
        };
        let event = SupervisorSelectionEvent {
            assignment_id: None,
            attempt: 0,
            role,
            primary_cause,
            provenance: decision,
        };
        let choice = match executable_choice(&event.provenance, runtime, role)? {
            ExecutableChoiceResolution::Executable(choice) => choice,
            ExecutableChoiceResolution::PreflightFailure(failure) => {
                decisions.push(event);
                return Ok(SupervisorSelectionResolution {
                    mode: if automatic {
                        SupervisorSelectionMode::Automatic
                    } else {
                        SupervisorSelectionMode::DebugOverride
                    },
                    decisions,
                    automatic_state: None,
                    selection_preflight_failure: Some(failure),
                });
            }
        };
        if configured.is_some() {
            let requested = &input
                .debug_override
                .as_ref()
                .context("explicit role_models entry lost its selector debug override")?
                .candidate;
            if requested != &choice.candidate {
                bail!(
                    "debug runtime/model/effort override for role '{}' was not applied exactly by the selector: requested '{}:{}:{:?}', selected '{}:{}:{:?}'",
                    role.as_str(),
                    requested.runtime,
                    requested.model,
                    requested.effort,
                    choice.candidate.runtime,
                    choice.candidate.model,
                    choice.candidate.effort,
                );
            }
        }
        resolved.insert(role, role_selection_from_choice(choice));
        decisions.push(event);
    }

    plan.role_models = resolved;
    if automatic {
        if plan.review_lenses == default_supervisor_review_lenses() {
            bind_automatic_review_lenses_to_auditor_selection(plan)?;
        } else {
            validate_custom_review_lenses_against_auditor_selection(plan, runtime)?;
        }
    } else if plan.review_lenses == default_supervisor_review_lenses() {
        if plan.role_models.contains_key(&AgentRole::Auditor) {
            bind_automatic_review_lenses_to_auditor_selection(plan)?;
        }
    } else {
        validate_custom_review_lenses_against_auditor_selection(plan, runtime)?;
    }

    let automatic_state = automatic
        .then(|| SupervisorAutomaticSelectionState::from_initial_decisions(&decisions))
        .transpose()?;
    Ok(SupervisorSelectionResolution {
        mode: if automatic {
            SupervisorSelectionMode::Automatic
        } else {
            SupervisorSelectionMode::DebugOverride
        },
        decisions,
        automatic_state,
        selection_preflight_failure: None,
    })
}

impl SupervisorAutomaticSelectionState {
    fn from_initial_decisions(decisions: &[SupervisorSelectionEvent]) -> Result<Self> {
        let mut by_role = BTreeMap::new();
        for decision in decisions {
            let normalized_role = role_for_task_profile(&decision.provenance.normalized_task)?;
            if normalized_role != decision.role {
                bail!(
                    "automatic selector event role '{}' disagrees with normalized task role '{}'",
                    decision.role.as_str(),
                    normalized_role.as_str()
                );
            }
            if by_role
                .insert(decision.role, decision.provenance.clone())
                .is_some()
            {
                bail!(
                    "automatic selector produced duplicate initial provenance for role '{}'",
                    decision.role.as_str()
                );
            }
        }
        for role in all_selector_roles() {
            if !by_role.contains_key(role) {
                bail!(
                    "automatic selector omitted initial provenance for role '{}'",
                    role.as_str()
                );
            }
        }
        Ok(Self { decisions: by_role })
    }
}

pub(super) fn reselect_roles_from_supplied_catalog_snapshot(
    state: &mut SupervisorAutomaticSelectionState,
    runtime: SupervisorRuntime,
    catalog: &RuntimeModelCatalog,
    roles: &[AgentRole],
    retry_count: u32,
    budget_signal: BudgetSignal,
    environment_rejections: &[TypedSelectorEnvironmentRejection],
) -> Result<SupervisorReselection> {
    let mut ordered_roles = roles.to_vec();
    ordered_roles.sort();
    ordered_roles.dedup();
    let mut overrides = BTreeMap::new();
    let mut decisions = Vec::with_capacity(ordered_roles.len());
    for role in ordered_roles {
        let previous = state.decisions.get(&role).with_context(|| {
            format!(
                "automatic selector has no replay state for role '{}'",
                role.as_str()
            )
        })?;
        let mut input = previous.normalized_input.clone();
        let runtime_name = runtime_name(runtime);
        input.catalogs = vec![runtime_catalog_from_priors(
            runtime_name,
            catalog,
            &input.task,
            &input.priors,
        )?];
        input.constraints.allowed_runtimes = [runtime_name.to_string()].into_iter().collect();
        input.constraints.allow_debug_override = false;
        input.debug_override = None;
        input.signals.retry_count = retry_count;
        input.signals.budget_signal = budget_signal;
        input.signals.previous_choice = previous
            .choice
            .as_ref()
            .map(|choice| choice.candidate.clone());
        input.signals.previous_catalog_digest = Some(previous.input_digests.catalogs.value.clone());
        input.signals.environment_rejections = environment_rejections
            .iter()
            .filter(|rejection| rejection.role == role)
            .map(|rejection| rejection.rejection.clone())
            .collect();

        let decision = selection::select(&input).map_err(|error| {
            anyhow!(
                "automatic selector replay rejected role '{}': {error}",
                role.as_str()
            )
        })?;
        let choice = match executable_choice(&decision, runtime, role)? {
            ExecutableChoiceResolution::Executable(choice) => choice,
            ExecutableChoiceResolution::PreflightFailure(failure) => {
                bail!(
                    "automatic selector replay failed preflight: {}",
                    failure.message
                )
            }
        };
        overrides.insert(role, role_selection_from_choice(choice));
        state.decisions.insert(role, decision.clone());
        decisions.push((role, decision));
    }
    Ok(SupervisorReselection {
        overrides,
        decisions,
    })
}

fn role_for_task_profile(task: &TaskProfile) -> Result<AgentRole> {
    match task.authority_role {
        AuthorityRole::AcceptanceGate => Ok(AgentRole::Supervisor),
        AuthorityRole::Delegating => Ok(AgentRole::ChildOrchestrator),
        AuthorityRole::TerminalLeaf => Ok(AgentRole::Worker),
        AuthorityRole::FailureClassification => Ok(AgentRole::GateClassifier),
        AuthorityRole::ReviewAuditor => Ok(AgentRole::Auditor),
        authority => {
            bail!("selector task authority '{authority:?}' does not map to a supervisor role")
        }
    }
}

fn all_selector_roles() -> &'static [AgentRole] {
    &[
        AgentRole::Supervisor,
        AgentRole::ChildOrchestrator,
        AgentRole::Worker,
        AgentRole::GateClassifier,
        AgentRole::Auditor,
    ]
}

fn bind_automatic_review_lenses_to_auditor_selection(plan: &mut SupervisorPlan) -> Result<()> {
    let selection = plan
        .role_models
        .get(&AgentRole::Auditor)
        .context("automatic selector did not resolve an auditor model")?;
    let model = selection
        .model
        .as_ref()
        .context("automatic selector returned a runtime-default auditor model")?;
    for lens in &mut plan.review_lenses {
        if let ReviewLensBackendConfig::Model {
            model: lens_model,
            reasoning_effort,
            ..
        } = &mut lens.backend
        {
            *lens_model = model.clone();
            *reasoning_effort = selection.reasoning_effort.clone();
        }
    }
    Ok(())
}

fn validate_custom_review_lenses_against_auditor_selection(
    plan: &SupervisorPlan,
    runtime: SupervisorRuntime,
) -> Result<()> {
    let auditor = plan.role_models.get(&AgentRole::Auditor).context(
        "custom review lenses require an explicit selector-validated auditor role_models override",
    )?;
    let auditor_model = auditor
        .model
        .as_deref()
        .context("selector-validated auditor override has no explicit model")?;
    let auditor_effort = auditor
        .reasoning_effort
        .as_deref()
        .context("selector-validated auditor override has no explicit reasoning effort")?;
    for lens in &plan.review_lenses {
        match &lens.backend {
            ReviewLensBackendConfig::Model {
                model,
                reasoning_effort,
                ..
            } if model == auditor_model
                && reasoning_effort.as_deref() == Some(auditor_effort) => {}
            ReviewLensBackendConfig::Model {
                model,
                reasoning_effort,
                ..
            } => bail!(
                "custom review lens '{}' runtime/model/effort '{}:{}:{}' does not exactly match selector-validated auditor triple '{}:{}:{}'",
                lens.id,
                runtime_name(runtime),
                model,
                reasoning_effort.as_deref().unwrap_or("<missing>"),
                runtime_name(runtime),
                auditor_model,
                auditor_effort,
            ),
            ReviewLensBackendConfig::Precomputed { .. } => bail!(
                "custom precomputed review lens '{}' cannot be selector-bound safely because it has no executable reasoning-effort field",
                lens.id
            ),
        }
    }
    Ok(())
}

fn debug_override_for_role(
    role: AgentRole,
    runtime: SupervisorRuntime,
    configured: &RoleModelSelection,
) -> Result<DebugOverride> {
    let model = configured
        .model
        .clone()
        .context("explicit role_models entries are debug overrides and require a model")?;
    let requested_effort = configured
        .reasoning_effort
        .as_deref()
        .context("explicit role_models debug overrides require a reasoning_effort")?;
    let effort = selector_effort_from_str(requested_effort).with_context(|| {
        format!(
            "explicit role_models debug override for role '{}' has unsupported reasoning_effort '{}'",
            role.as_str(), requested_effort
        )
    })?;
    Ok(DebugOverride {
        candidate: CandidateKey {
            runtime: runtime_name(runtime).to_string(),
            model,
            effort,
        },
        requested_by: "supervisor_plan.role_models".to_string(),
        reason: format!(
            "explicit role_models binding for {} is a debug-only selector override",
            role.as_str()
        ),
    })
}

fn selection_input_for_role(
    role: AgentRole,
    runtime: SupervisorRuntime,
    catalog: &RuntimeModelCatalog,
    admission: &SupervisorAdmissionPolicyInput,
    signals: DynamicSignals,
    debug_override: Option<DebugOverride>,
) -> Result<SelectionInput> {
    let priors = selection::built_in_prior_dataset()?;
    let task = task_profile_for_role(role);
    let runtime_name = runtime_name(runtime);
    let runtime_catalog = runtime_catalog_from_priors(runtime_name, catalog, &task, &priors)?;
    let profile = priors
        .objective_profiles
        .first()
        .context("built-in selector data has no objective profile")?;
    let profile_name = profile.name.clone();
    let profile_version = profile.version;
    let capacity = u64::try_from(admission.provider_inflight_bound)
        .context("provider inflight bound does not fit selector pool units")?;
    let admission_bytes = serde_json::to_vec(admission)
        .context("failed to normalize supervisor admission input for selection")?;
    let pool = RuntimePoolState {
        runtime: runtime_name.to_string(),
        admission_open: admission.resolved_bound > 0,
        entitlement_capacity_units: capacity,
        entitlement_remaining_units: capacity,
        pool_pressure_basis_points: 0,
        observed_consumption_units: 0,
        marginal_cost_microunits: 0,
        observation_revision: format!(
            "supervisor-admission-sha256:{}",
            crate::artifacts::state_auth::sha256_hex(&admission_bytes)
        ),
        admission_provenance: "supervisor admission supplies a bounded active-runtime inflight pool; external account quota and marginal-price observations were unavailable"
            .to_string(),
        failover_provenance: Some(
            "run-global runtime execution constrains automatic dispatch to the active runtime"
                .to_string(),
        ),
    };
    Ok(SelectionInput {
        task,
        catalogs: vec![runtime_catalog],
        pools: vec![pool],
        constraints: OperatorConstraints {
            allowed_runtimes: [runtime_name.to_string()].into_iter().collect(),
            allowed_models: BTreeSet::new(),
            forbidden_runtimes: BTreeSet::new(),
            forbidden_models: BTreeSet::new(),
            forbidden_candidates: BTreeSet::new(),
            allow_debug_override: debug_override.is_some(),
        },
        priors,
        objective_profile: ObjectiveProfileRef {
            name: profile_name,
            version: profile_version,
            expected_digest: None,
        },
        outcomes: Vec::new(),
        signals,
        debug_override,
    })
}

fn runtime_catalog_from_priors(
    runtime_name: &str,
    catalog: &RuntimeModelCatalog,
    task: &TaskProfile,
    priors: &selection::PriorDataset,
) -> Result<RuntimeCatalog> {
    let mut models = Vec::new();
    for prior in priors
        .models
        .iter()
        .filter(|prior| prior.runtime == runtime_name)
    {
        let available = catalog
            .availability(Some(&prior.model), runtime_from_name(runtime_name)?)?
            == RoleModelAvailability::Available;
        let mut supported_efforts = prior
            .class_fit
            .iter()
            .filter(|class_fit| class_fit.task_class == task.task_class)
            .map(|class_fit| class_fit.effort)
            .chain(
                prior
                    .authority_evidence
                    .iter()
                    .filter(|evidence| {
                        evidence.task_class == task.task_class
                            && evidence.role == task.authority_role
                    })
                    .map(|evidence| evidence.effort),
            )
            .chain(prior.strong_gate_fallback_efforts.iter().copied())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        supported_efforts.sort();
        if supported_efforts.is_empty() {
            continue;
        }
        let mut authority_roles = prior
            .authority_evidence
            .iter()
            .map(|evidence| evidence.role)
            .collect::<BTreeSet<_>>();
        if !prior.class_fit.is_empty() {
            authority_roles.insert(AuthorityRole::TerminalLeaf);
        }
        if !prior.strong_gate_fallback_efforts.is_empty()
            && !prior
                .prohibited_authority_roles
                .contains(&task.authority_role)
        {
            authority_roles.insert(task.authority_role);
        }
        models.push(CatalogModel {
            model: prior.model.clone(),
            available,
            supported_efforts,
            capabilities: CandidateCapabilities {
                task_classes: prior
                    .class_fit
                    .iter()
                    .map(|class_fit| class_fit.task_class.clone())
                    .collect(),
                authority_roles,
                boundedness: [
                    Boundedness::TightlyBounded,
                    Boundedness::Bounded,
                    Boundedness::CrossCutting,
                ]
                .into_iter()
                .collect(),
                maximum_risk: RiskLevel::Critical,
                maximum_context: ContextSize::Long,
                maximum_horizon: TaskHorizon::Long,
                long_context: prior.long_context_eligible,
            },
        });
    }
    models.sort_by(|left, right| left.model.cmp(&right.model));
    let revision_material =
        serde_json::to_vec(&models).context("failed to normalize runtime catalog membership")?;
    Ok(RuntimeCatalog {
        runtime: runtime_name.to_string(),
        revision: format!(
            "prior-backed-membership-sha256:{}",
            crate::artifacts::state_auth::sha256_hex(&revision_material)
        ),
        advertised_at: "live-membership-observation-undated".to_string(),
        models,
    })
}

fn task_profile_for_role(role: AgentRole) -> TaskProfile {
    match role {
        AgentRole::Worker => TaskProfile {
            task_class: AUTOMATIC_SELECTION_TASK_CLASS.to_string(),
            risk: RiskLevel::Medium,
            boundedness: Boundedness::Bounded,
            context: ContextSize::Medium,
            horizon: TaskHorizon::Medium,
            authority_role: AuthorityRole::TerminalLeaf,
        },
        AgentRole::ChildOrchestrator => TaskProfile {
            task_class: AUTOMATIC_SELECTION_TASK_CLASS.to_string(),
            risk: RiskLevel::High,
            boundedness: Boundedness::CrossCutting,
            context: ContextSize::Large,
            horizon: TaskHorizon::Long,
            authority_role: AuthorityRole::Delegating,
        },
        AgentRole::Supervisor => judgment_task_profile(AuthorityRole::AcceptanceGate),
        AgentRole::GateClassifier => judgment_task_profile(AuthorityRole::FailureClassification),
        AgentRole::Auditor => judgment_task_profile(AuthorityRole::ReviewAuditor),
    }
}

fn judgment_task_profile(authority_role: AuthorityRole) -> TaskProfile {
    TaskProfile {
        task_class: JUDGMENT_SELECTION_TASK_CLASS.to_string(),
        risk: RiskLevel::Critical,
        boundedness: Boundedness::CrossCutting,
        context: ContextSize::Long,
        horizon: TaskHorizon::Long,
        authority_role,
    }
}

enum ExecutableChoiceResolution<'a> {
    Executable(&'a selection::SelectedChoice),
    PreflightFailure(SupervisorSelectionPreflightFailure),
}

fn executable_choice<'a>(
    decision: &'a SelectionProvenance,
    runtime: SupervisorRuntime,
    role: AgentRole,
) -> Result<ExecutableChoiceResolution<'a>> {
    if decision.status != DecisionStatus::Selected {
        return Ok(ExecutableChoiceResolution::PreflightFailure(
            SupervisorSelectionPreflightFailure {
                role,
                kind: SupervisorSelectionPreflightFailureKind::FailClosed,
                message: format!(
                    "selector failed closed for role '{}': {}",
                    role.as_str(),
                    decision.decision_reason
                ),
            },
        ));
    }
    let choice = decision.choice.as_ref().with_context(|| {
        format!(
            "selector reported selected status without a choice for role '{}'",
            role.as_str()
        )
    })?;
    if choice.candidate.runtime != runtime_name(runtime) {
        return Ok(ExecutableChoiceResolution::PreflightFailure(
            SupervisorSelectionPreflightFailure {
                role,
                kind: SupervisorSelectionPreflightFailureKind::ActiveRuntimeMismatch,
                message: format!(
                    "selector chose runtime '{}' for role '{}', but supervisor execution is constrained to run-global runtime '{}'; cross-runtime dispatch is unsupported",
                    choice.candidate.runtime,
                    role.as_str(),
                    runtime_name(runtime)
                ),
            },
        ));
    }
    Ok(ExecutableChoiceResolution::Executable(choice))
}

fn role_selection_from_choice(choice: &selection::SelectedChoice) -> RoleModelSelection {
    RoleModelSelection {
        model: Some(choice.candidate.model.clone()),
        reasoning_effort: Some(selector_effort_as_str(choice.candidate.effort).to_string()),
        unavailable_model_fallback: UnavailableModelFallback::FailClosed,
    }
}

fn runtime_name(runtime: SupervisorRuntime) -> &'static str {
    match runtime {
        SupervisorRuntime::Codex => "codex",
        SupervisorRuntime::Fake => "fake",
        SupervisorRuntime::Grok => "grok",
        SupervisorRuntime::Cursor => "cursor",
    }
}

fn runtime_from_name(runtime: &str) -> Result<SupervisorRuntime> {
    match runtime {
        "codex" => Ok(SupervisorRuntime::Codex),
        "fake" => Ok(SupervisorRuntime::Fake),
        "grok" => Ok(SupervisorRuntime::Grok),
        "cursor" => Ok(SupervisorRuntime::Cursor),
        _ => bail!("selector runtime '{runtime}' is not executable by the supervisor"),
    }
}

fn selector_effort_from_str(value: &str) -> Option<SelectorEffort> {
    match value {
        "minimal" | "low" => Some(SelectorEffort::Low),
        "medium" => Some(SelectorEffort::Medium),
        "high" => Some(SelectorEffort::High),
        "xhigh" => Some(SelectorEffort::Xhigh),
        "max" => Some(SelectorEffort::Max),
        "ultra" => Some(SelectorEffort::Ultra),
        _ => None,
    }
}

fn selector_effort_as_str(effort: SelectorEffort) -> &'static str {
    match effort {
        SelectorEffort::Low => "low",
        SelectorEffort::Medium => "medium",
        SelectorEffort::High => "high",
        SelectorEffort::Xhigh => "xhigh",
        SelectorEffort::Max => "max",
        SelectorEffort::Ultra => "ultra",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codex_catalog() -> Result<RuntimeModelCatalog> {
        let priors = selection::built_in_prior_dataset()?;
        Ok(RuntimeModelCatalog::Codex(
            CodexRuntimeModelCatalog::from_slugs(
                priors
                    .models
                    .iter()
                    .filter(|prior| prior.runtime == runtime_name(SupervisorRuntime::Codex))
                    .map(|prior| prior.model.clone()),
            )?,
        ))
    }

    fn test_plan() -> SupervisorPlan {
        SupervisorPlan {
            version: SUPERVISOR_SCHEMA_VERSION,
            task: "exercise automatic role selection".to_string(),
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
        }
    }

    fn test_admission() -> SupervisorAdmissionPolicyInput {
        SupervisorAdmissionPolicyInput {
            entrypoint_bound: 1,
            plan: SupervisorAdmissionConfig::default(),
            cli: SupervisorAdmissionConfig::default(),
            effective: SupervisorAdmissionConfig::default(),
            provider_inflight_bound: 1,
            provider_inflight_source: AdmissionInputSource::ConservativeDefault,
            host: SupervisorHostResourcePolicyInput {
                memory_available_mib: None,
                memory_available_source: AdmissionInputSource::ConservativeDefault,
                memory_per_child_mib: DEFAULT_HOST_MEMORY_PER_CHILD_MIB,
                memory_bound: None,
                fd_available: None,
                fd_available_source: AdmissionInputSource::ConservativeDefault,
                fds_per_child: DEFAULT_HOST_FDS_PER_CHILD,
                fd_bound: None,
                disk_available_mib: None,
                disk_available_source: AdmissionInputSource::ConservativeDefault,
                disk_per_child_mib: DEFAULT_HOST_DISK_PER_CHILD_MIB,
                disk_bound: None,
                fallback_children: DEFAULT_HOST_FALLBACK_CHILDREN,
                resolved_bound: 1,
            },
            resolved_bound: 1,
        }
    }

    fn role_selection(model: String, reasoning_effort: Option<&str>) -> RoleModelSelection {
        RoleModelSelection {
            model: Some(model),
            reasoning_effort: reasoning_effort.map(str::to_string),
            unavailable_model_fallback: UnavailableModelFallback::FailClosed,
        }
    }

    fn codex_prior_for(
        predicate: impl Fn(&selection::ModelPrior) -> bool,
    ) -> Result<selection::ModelPrior> {
        selection::built_in_prior_dataset()?
            .models
            .into_iter()
            .find(|prior| {
                prior.runtime == runtime_name(SupervisorRuntime::Codex) && predicate(prior)
            })
            .context("built-in selector data has no matching Codex prior")
    }

    fn automatic_state() -> Result<(RuntimeModelCatalog, SupervisorAutomaticSelectionState)> {
        let catalog = codex_catalog()?;
        let mut plan = test_plan();
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
        )?;
        Ok((
            catalog,
            resolution
                .automatic_state
                .context("automatic selection replay state")?,
        ))
    }

    #[test]
    fn automatic_empty_role_models_resolve_all_roles_from_eligible_catalog() -> Result<()> {
        let catalog = codex_catalog()?;
        let mut plan = test_plan();
        let admission = test_admission();

        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &admission,
        )?;

        assert_eq!(resolution.mode, SupervisorSelectionMode::Automatic);
        assert_eq!(resolution.decisions.len(), all_selector_roles().len());
        assert_eq!(plan.role_models.len(), all_selector_roles().len());
        for role in all_selector_roles() {
            assert!(plan.role_models.contains_key(role));
        }
        assert!(resolution.decisions.iter().all(|decision| {
            decision.assignment_id.is_none()
                && decision.attempt == 0
                && decision.primary_cause == SupervisorSelectionEventCause::Initial
                && decision.provenance.status == DecisionStatus::Selected
                && decision.provenance.choice.is_some()
        }));
        Ok(())
    }

    #[test]
    fn explicit_debug_override_requires_parseable_effort() -> Result<()> {
        let catalog = codex_catalog()?;
        let prior = codex_prior_for(|prior| {
            prior
                .class_fit
                .iter()
                .any(|class_fit| class_fit.task_class == AUTOMATIC_SELECTION_TASK_CLASS)
        })?;
        let admission = test_admission();
        let mut missing = test_plan();
        missing
            .role_models
            .insert(AgentRole::Worker, role_selection(prior.model.clone(), None));
        let error = initialize_supervisor_selection(
            &mut missing,
            SupervisorRuntime::Codex,
            &catalog,
            &admission,
        )
        .expect_err("missing debug effort must fail closed");
        assert!(error
            .to_string()
            .contains("debug overrides require a reasoning_effort"));

        let mut invalid = test_plan();
        invalid.role_models.insert(
            AgentRole::Worker,
            role_selection(prior.model, Some("not-an-effort")),
        );
        let error = initialize_supervisor_selection(
            &mut invalid,
            SupervisorRuntime::Codex,
            &catalog,
            &admission,
        )
        .expect_err("unparseable debug effort must fail closed");
        assert!(error.to_string().contains("unsupported reasoning_effort"));
        Ok(())
    }

    #[test]
    fn debug_mode_applies_exact_selector_triple_to_plan() -> Result<()> {
        let catalog = codex_catalog()?;
        let prior = codex_prior_for(|prior| {
            prior.class_fit.iter().any(|class_fit| {
                class_fit.task_class == AUTOMATIC_SELECTION_TASK_CLASS
                    && class_fit.effort == SelectorEffort::High
            })
        })?;
        let requested = CandidateKey {
            runtime: runtime_name(SupervisorRuntime::Codex).to_string(),
            model: prior.model.clone(),
            effort: SelectorEffort::High,
        };
        let mut plan = test_plan();
        plan.role_models
            .insert(AgentRole::Worker, role_selection(prior.model, Some("high")));

        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
        )?;

        assert_eq!(resolution.mode, SupervisorSelectionMode::DebugOverride);
        assert_eq!(resolution.decisions.len(), 1);
        assert_eq!(resolution.decisions[0].role, AgentRole::Worker);
        assert_eq!(resolution.decisions[0].attempt, 0);
        assert!(resolution.decisions[0].assignment_id.is_none());
        assert_eq!(
            resolution.decisions[0].primary_cause,
            SupervisorSelectionEventCause::DebugOverride
        );
        assert_eq!(
            resolution.decisions[0]
                .provenance
                .choice
                .as_ref()
                .context("debug choice")?
                .candidate,
            requested
        );
        assert_eq!(
            plan.role_models
                .get(&AgentRole::Worker)
                .and_then(|selection| selection.reasoning_effort.as_deref()),
            Some("high")
        );
        Ok(())
    }

    #[test]
    fn custom_review_lens_must_match_selector_validated_auditor() -> Result<()> {
        let catalog = codex_catalog()?;
        let auditor_prior = codex_prior_for(|prior| {
            prior
                .strong_gate_fallback_efforts
                .contains(&SelectorEffort::Xhigh)
        })?;
        let other_prior = codex_prior_for(|prior| prior.model != auditor_prior.model)?;
        let mut plan = test_plan();
        plan.role_models.insert(
            AgentRole::Auditor,
            role_selection(auditor_prior.model, Some("xhigh")),
        );
        plan.review_lenses = vec![ReviewLensConfig {
            id: "custom-auditor".to_string(),
            backend: ReviewLensBackendConfig::Model {
                backend_id: "openai".to_string(),
                model: other_prior.model,
                reasoning_effort: Some("high".to_string()),
            },
            information_scope: ReviewInformationScope::FullChildTranscript,
        }];

        let error = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
        )
        .expect_err("mismatched custom review lens must fail closed");
        assert!(error
            .to_string()
            .contains("does not exactly match selector-validated auditor triple"));
        Ok(())
    }

    #[test]
    fn legacy_explicit_selection_bypass_is_nonpublishable_and_never_automatic() {
        let empty = test_plan();
        assert!(uses_legacy_nonpublishable_explicit_selection(
            SupervisorExecutionRuntime::NonpublishableSimulation,
            &empty,
        ));
        assert!(!uses_legacy_nonpublishable_explicit_selection(
            SupervisorExecutionRuntime::Verified,
            &empty,
        ));

        let mut explicit = test_plan();
        explicit.role_models.insert(
            AgentRole::Worker,
            role_selection("legacy-injected-model".to_string(), Some("high")),
        );
        assert!(uses_legacy_nonpublishable_explicit_selection(
            SupervisorExecutionRuntime::NonpublishableSimulation,
            &explicit,
        ));
        assert!(!uses_legacy_nonpublishable_explicit_selection(
            SupervisorExecutionRuntime::Verified,
            &explicit,
        ));
    }

    #[test]
    fn degrade_reselection_is_deterministic_and_returns_exact_executable_overrides() -> Result<()> {
        let (catalog, state) = automatic_state()?;
        let mut first_state = state.clone();
        let first = reselect_roles_from_supplied_catalog_snapshot(
            &mut first_state,
            SupervisorRuntime::Codex,
            &catalog,
            &[
                AgentRole::Auditor,
                AgentRole::Worker,
                AgentRole::ChildOrchestrator,
                AgentRole::Worker,
            ],
            0,
            BudgetSignal::Degrade,
            &[],
        )?;
        let mut second_state = state;
        let second = reselect_roles_from_supplied_catalog_snapshot(
            &mut second_state,
            SupervisorRuntime::Codex,
            &catalog,
            &[
                AgentRole::ChildOrchestrator,
                AgentRole::Worker,
                AgentRole::Auditor,
            ],
            0,
            BudgetSignal::Degrade,
            &[],
        )?;

        assert_eq!(first.decisions, second.decisions);
        assert_eq!(
            first
                .decisions
                .iter()
                .map(|(role, _)| *role)
                .collect::<Vec<_>>(),
            vec![
                AgentRole::ChildOrchestrator,
                AgentRole::Worker,
                AgentRole::Auditor,
            ]
        );
        for (role, decision) in &first.decisions {
            assert!(decision
                .triggers
                .contains(&selection::SelectionTrigger::BudgetDegrade));
            let choice = decision.choice.as_ref().context("degrade choice")?;
            let override_selection = first.overrides.get(role).context("role override")?;
            assert_eq!(
                override_selection.model.as_deref(),
                Some(choice.candidate.model.as_str())
            );
            assert_eq!(
                override_selection.reasoning_effort.as_deref(),
                Some(selector_effort_as_str(choice.candidate.effort))
            );
        }
        Ok(())
    }

    #[test]
    fn retry_penalizes_only_previous_choice_and_changes_worker_choice() -> Result<()> {
        let (catalog, mut state) = automatic_state()?;
        let previous = state
            .decisions
            .get(&AgentRole::Worker)
            .and_then(|decision| decision.choice.as_ref())
            .context("initial worker choice")?
            .candidate
            .clone();

        let reselection = reselect_roles_from_supplied_catalog_snapshot(
            &mut state,
            SupervisorRuntime::Codex,
            &catalog,
            &[AgentRole::Worker],
            1,
            BudgetSignal::Continue,
            &[],
        )?;
        let decision = &reselection.decisions[0].1;
        let choice = decision.choice.as_ref().context("retry worker choice")?;

        assert!(decision
            .triggers
            .contains(&selection::SelectionTrigger::Retry));
        assert_ne!(choice.candidate, previous);
        let previous_score = decision
            .candidate_set
            .iter()
            .find(|evaluation| evaluation.candidate == previous)
            .and_then(|evaluation| evaluation.score.as_ref())
            .context("previous candidate retry score")?;
        let selected_score = decision
            .candidate_set
            .iter()
            .find(|evaluation| evaluation.candidate == choice.candidate)
            .and_then(|evaluation| evaluation.score.as_ref())
            .context("selected candidate retry score")?;
        assert!(previous_score.retry_cost_microunits > 0);
        assert_eq!(selected_score.retry_cost_microunits, 0);
        Ok(())
    }

    #[test]
    fn supplied_catalog_withdrawal_records_change_and_reselects() -> Result<()> {
        let (_, mut state) = automatic_state()?;
        let previous = state
            .decisions
            .get(&AgentRole::Worker)
            .and_then(|decision| decision.choice.as_ref())
            .context("initial worker choice")?
            .candidate
            .clone();
        let priors = selection::built_in_prior_dataset()?;
        let withdrawn_catalog = RuntimeModelCatalog::Codex(CodexRuntimeModelCatalog::from_slugs(
            priors
                .models
                .iter()
                .filter(|prior| {
                    prior.runtime == runtime_name(SupervisorRuntime::Codex)
                        && prior.model != previous.model
                })
                .map(|prior| prior.model.clone()),
        )?);

        let reselection = reselect_roles_from_supplied_catalog_snapshot(
            &mut state,
            SupervisorRuntime::Codex,
            &withdrawn_catalog,
            &[AgentRole::Worker],
            0,
            BudgetSignal::Continue,
            &[],
        )?;
        let decision = &reselection.decisions[0].1;

        assert!(decision
            .triggers
            .contains(&selection::SelectionTrigger::CatalogChange));
        assert_ne!(
            decision
                .choice
                .as_ref()
                .context("replacement choice")?
                .candidate,
            previous
        );
        Ok(())
    }

    #[test]
    fn typed_environment_rejection_uses_one_shot_data_declared_fallback() -> Result<()> {
        let (catalog, mut state) = automatic_state()?;
        let previous = state
            .decisions
            .get(&AgentRole::Worker)
            .and_then(|decision| decision.choice.as_ref())
            .context("initial worker choice")?
            .candidate
            .clone();
        let prior = codex_prior_for(|prior| prior.model == previous.model)?;
        let fallback = prior
            .one_shot_environment_fallbacks
            .first()
            .context("initial worker has no data-declared environment fallback")?;
        let rejection = TypedSelectorEnvironmentRejection {
            role: AgentRole::Worker,
            rejection: selection::EnvironmentRejectionState {
                candidate: previous.clone(),
                rejection_code: fallback.rejection_code.clone(),
                evidence_id: "typed-runtime-rejection-1".to_string(),
                fallback_transition_used: false,
            },
        };

        let reselection = reselect_roles_from_supplied_catalog_snapshot(
            &mut state,
            SupervisorRuntime::Codex,
            &catalog,
            &[AgentRole::Worker],
            0,
            BudgetSignal::Continue,
            &[rejection],
        )?;
        let decision = &reselection.decisions[0].1;
        let transition = decision
            .environment_fallback
            .as_ref()
            .context("typed one-shot fallback transition")?;

        assert!(decision
            .triggers
            .contains(&selection::SelectionTrigger::EnvironmentFallback));
        assert_eq!(transition.source, previous);
        assert_eq!(transition.target.runtime, fallback.target_runtime);
        assert_eq!(transition.target.model, fallback.target_model);
        assert_eq!(transition.target.effort, fallback.target_effort);
        assert_eq!(transition.transition_ordinal, 1);
        assert_eq!(transition.maximum_transitions, 1);
        Ok(())
    }
}
