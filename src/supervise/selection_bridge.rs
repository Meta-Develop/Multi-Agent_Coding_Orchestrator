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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct AdvertisedCatalogSet {
    pub cursor: Option<crate::runtime_adapter::cursor::CursorAdvertisedCatalogObservation>,
    pub grok: Option<crate::runtime_adapter::grok::GrokAdvertisedCatalogObservation>,
}

impl AdvertisedCatalogSet {
    pub(super) fn empty() -> Self {
        Self {
            cursor: None,
            grok: None,
        }
    }
}

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
    advertised: AdvertisedCatalogSet,
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
    advertised: &AdvertisedCatalogSet,
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
            advertised,
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
        .then(|| {
            SupervisorAutomaticSelectionState::from_initial_decisions(
                &decisions,
                advertised.clone(),
            )
        })
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
    fn from_initial_decisions(
        decisions: &[SupervisorSelectionEvent],
        advertised: AdvertisedCatalogSet,
    ) -> Result<Self> {
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
        Ok(Self {
            decisions: by_role,
            advertised,
        })
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
    let advertised = state.advertised.clone();
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
        let constructed = constructed_selection_catalogs(
            runtime,
            catalog,
            &advertised,
            &input.task,
            &input.priors,
        )?;
        input.constraints.allowed_runtimes = constructed
            .iter()
            .map(|runtime_catalog| runtime_catalog.runtime.clone())
            .collect();
        input.catalogs = constructed;
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
    advertised: &AdvertisedCatalogSet,
    admission: &SupervisorAdmissionPolicyInput,
    signals: DynamicSignals,
    debug_override: Option<DebugOverride>,
) -> Result<SelectionInput> {
    let priors = selection::built_in_prior_dataset()?;
    let task = task_profile_for_role(role);
    let runtime_name = runtime_name(runtime);
    let catalogs = constructed_selection_catalogs(runtime, catalog, advertised, &task, &priors)?;
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
    let primary_pool = RuntimePoolState {
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
            "advertised runtime catalogs participate in selection; launch uses the selected pair"
                .to_string(),
        ),
    };
    let pools = pools_for_constructed_catalogs(&catalogs, runtime_name, primary_pool);
    let allowed_runtimes = catalogs
        .iter()
        .map(|runtime_catalog| runtime_catalog.runtime.clone())
        .collect();
    Ok(SelectionInput {
        task,
        catalogs,
        pools,
        constraints: OperatorConstraints {
            allowed_runtimes,
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

fn constructed_selection_catalogs(
    runtime: SupervisorRuntime,
    catalog: &RuntimeModelCatalog,
    advertised: &AdvertisedCatalogSet,
    task: &TaskProfile,
    priors: &selection::PriorDataset,
) -> Result<Vec<RuntimeCatalog>> {
    let mut catalogs = vec![runtime_catalog_from_priors(
        runtime_name(runtime),
        catalog,
        task,
        priors,
    )?];
    if let Some(observation) = &advertised.cursor {
        catalogs.push(runtime_catalog_from_advertised_slugs(
            "cursor",
            observation.catalog().slugs(),
            format!("cursor-advertised-sha256:{}", observation.source_sha256()),
            observation.observed_at_unix_millis().to_string(),
            task,
            priors,
        )?);
    }
    if let Some(observation) = &advertised.grok {
        catalogs.push(runtime_catalog_from_advertised_slugs(
            "grok",
            observation.catalog().slugs(),
            format!("grok-advertised-sha256:{}", observation.source_sha256()),
            observation.observed_at_unix_millis().to_string(),
            task,
            priors,
        )?);
    }
    Ok(catalogs)
}

fn pools_for_constructed_catalogs(
    catalogs: &[RuntimeCatalog],
    primary_runtime: &str,
    primary_pool: RuntimePoolState,
) -> Vec<RuntimePoolState> {
    catalogs
        .iter()
        .map(|runtime_catalog| {
            if runtime_catalog.runtime == primary_runtime {
                RuntimePoolState {
                    runtime: runtime_catalog.runtime.clone(),
                    ..primary_pool.clone()
                }
            } else {
                RuntimePoolState {
                    runtime: runtime_catalog.runtime.clone(),
                    observation_revision: format!(
                        "{}:{}",
                        primary_pool.observation_revision, runtime_catalog.runtime
                    ),
                    pool_pressure_basis_points: 0,
                    failover_provenance: Some(
                        "advertised runtime catalogs participate in selection; launch uses the selected pair"
                            .to_string(),
                    ),
                    ..primary_pool.clone()
                }
            }
        })
        .collect()
}

fn runtime_catalog_from_advertised_slugs<'a>(
    runtime_name: &str,
    advertised_slugs: impl IntoIterator<Item = &'a str>,
    revision: String,
    advertised_at: String,
    task: &TaskProfile,
    priors: &selection::PriorDataset,
) -> Result<RuntimeCatalog> {
    let advertised = advertised_slugs
        .into_iter()
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    let mut models = Vec::new();
    for prior in priors
        .models
        .iter()
        .filter(|prior| prior.runtime == runtime_name)
    {
        if !advertised.contains(&prior.model) {
            continue;
        }
        if let Some(model) = catalog_model_from_prior(prior, task, true) {
            models.push(model);
        }
    }
    models.sort_by(|left, right| left.model.cmp(&right.model));
    Ok(RuntimeCatalog {
        runtime: runtime_name.to_string(),
        revision,
        advertised_at,
        models,
    })
}

fn catalog_model_from_prior(
    prior: &selection::ModelPrior,
    task: &TaskProfile,
    available: bool,
) -> Option<CatalogModel> {
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
                    evidence.task_class == task.task_class && evidence.role == task.authority_role
                })
                .map(|evidence| evidence.effort),
        )
        .chain(prior.strong_gate_fallback_efforts.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    supported_efforts.sort();
    if supported_efforts.is_empty() {
        return None;
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
    Some(CatalogModel {
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
    if runtime_from_name(&choice.candidate.runtime).is_err() {
        return Ok(ExecutableChoiceResolution::PreflightFailure(
            SupervisorSelectionPreflightFailure {
                role,
                kind: SupervisorSelectionPreflightFailureKind::ActiveRuntimeMismatch,
                message: format!(
                    "selector chose unexecutable runtime '{}' for role '{}' while constructing the assignment-launch binding; run-global runtime was '{}'",
                    choice.candidate.runtime,
                    role.as_str(),
                    runtime_name(runtime)
                ),
            },
        ));
    }
    Ok(ExecutableChoiceResolution::Executable(choice))
}

pub(super) fn bind_selected_assignment_runtimes(
    plan: &mut SupervisorPlan,
    decisions: &[SupervisorSelectionEvent],
) -> Result<()> {
    let mut selected = BTreeMap::new();
    for decision in decisions {
        let Some(choice) = &decision.provenance.choice else {
            continue;
        };
        selected.insert(
            decision.role,
            runtime_from_name(&choice.candidate.runtime).with_context(|| {
                format!(
                    "selector choice for role '{}' used unexecutable runtime '{}'",
                    decision.role.as_str(),
                    choice.candidate.runtime
                )
            })?,
        );
    }
    for assignment in &mut plan.assignments {
        let Some(selected_runtime) = selected.get(&assignment.role).copied() else {
            continue;
        };
        match assignment.runtime {
            Some(existing) if existing != selected_runtime => {
                bail!(
                    "assignment '{}' runtime '{}' contradicts selected runtime '{}' for role '{}'",
                    assignment.id,
                    runtime_name(existing),
                    runtime_name(selected_runtime),
                    assignment.role.as_str()
                );
            }
            Some(_) => {}
            None => assignment.runtime = Some(selected_runtime),
        }
    }
    Ok(())
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
            &AdvertisedCatalogSet::empty(),
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
            &AdvertisedCatalogSet::empty(),
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
            &AdvertisedCatalogSet::empty(),
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
            &AdvertisedCatalogSet::empty(),
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
            &AdvertisedCatalogSet::empty(),
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
            &AdvertisedCatalogSet::empty(),
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

    const CAPTURED_CURSOR_CATALOG: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/runtime_adapter/cursor/captured-minimal-20260820.txt"
    ));
    const WITHDRAWN_CURSOR_CATALOG: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/runtime_adapter/cursor/hand-authored-withdrawn.txt"
    ));
    const CAPTURED_CURSOR_AT_UNIX_MILLIS: u64 = 1_787_240_463_000;

    struct FakeCursorRunner {
        output: crate::runtime_adapter::cursor::CursorCatalogCommandOutput,
    }

    impl FakeCursorRunner {
        fn successful(stdout: &[u8]) -> Self {
            Self {
                output: crate::runtime_adapter::cursor::CursorCatalogCommandOutput {
                    status: Some(0),
                    stdout: stdout.to_vec(),
                    stderr: Vec::new(),
                    stdout_truncated: false,
                    stderr_truncated: false,
                    timed_out: false,
                    process_tree: crate::process_runner::ProcessTreeEvidence::VerifiedEmpty(
                        crate::process_runner::ContainmentBackend::DirectChild,
                    ),
                    side_effects: crate::process_runner::SideEffectConfinementEvidence::Verified(
                        crate::process_runner::SideEffectConfinementProfileKind::TrustedFixedNetwork,
                    ),
                },
            }
        }
    }

    impl crate::runtime_adapter::cursor::CursorCatalogCommandRunner for FakeCursorRunner {
        fn run(
            &self,
            _spec: &crate::runtime_adapter::cursor::CursorCatalogCommandSpec,
        ) -> Result<crate::runtime_adapter::cursor::CursorCatalogCommandOutput> {
            Ok(self.output.clone())
        }
    }

    fn captured_cursor_observation(
    ) -> Result<crate::runtime_adapter::cursor::CursorAdvertisedCatalogObservation> {
        crate::runtime_adapter::cursor::discover_cursor_model_catalog(
            &FakeCursorRunner::successful(CAPTURED_CURSOR_CATALOG),
            &crate::runtime_adapter::cursor::CursorCatalogCommandSpec::new("/workspace"),
            Some(CAPTURED_CURSOR_AT_UNIX_MILLIS),
        )
    }

    fn withdrawn_cursor_observation(
    ) -> Result<crate::runtime_adapter::cursor::CursorAdvertisedCatalogObservation> {
        crate::runtime_adapter::cursor::discover_cursor_model_catalog(
            &FakeCursorRunner::successful(WITHDRAWN_CURSOR_CATALOG),
            &crate::runtime_adapter::cursor::CursorCatalogCommandSpec::new("/workspace"),
            Some(CAPTURED_CURSOR_AT_UNIX_MILLIS),
        )
    }

    fn advertised_with_cursor(
        observation: crate::runtime_adapter::cursor::CursorAdvertisedCatalogObservation,
    ) -> AdvertisedCatalogSet {
        AdvertisedCatalogSet {
            cursor: Some(observation),
            grok: None,
        }
    }

    struct FakeGrokRunner {
        output: crate::runtime_adapter::grok::GrokCatalogCommandOutput,
    }

    impl FakeGrokRunner {
        fn successful(stdout: &[u8]) -> Self {
            Self {
                output: crate::runtime_adapter::grok::GrokCatalogCommandOutput {
                    status: Some(0),
                    stdout: stdout.to_vec(),
                    stderr: Vec::new(),
                    stdout_truncated: false,
                    stderr_truncated: false,
                    timed_out: false,
                    process_tree: crate::process_runner::ProcessTreeEvidence::VerifiedEmpty(
                        crate::process_runner::ContainmentBackend::DirectChild,
                    ),
                    side_effects: crate::process_runner::SideEffectConfinementEvidence::Verified(
                        crate::process_runner::SideEffectConfinementProfileKind::TrustedFixedNetwork,
                    ),
                },
            }
        }
    }

    impl crate::runtime_adapter::grok::GrokCatalogCommandRunner for FakeGrokRunner {
        fn run(
            &self,
            _spec: &crate::runtime_adapter::grok::GrokCatalogCommandSpec,
        ) -> Result<crate::runtime_adapter::grok::GrokCatalogCommandOutput> {
            Ok(self.output.clone())
        }
    }

    fn grok_listing(default: &str, model_lines: &[&str]) -> Vec<u8> {
        let mut text = format!(
            "You are logged in with grok.com.\n\nDefault model: {default}\n\nAvailable models:\n"
        );
        if !model_lines.is_empty() {
            text.push_str(&model_lines.join("\n"));
            text.push('\n');
        }
        text.into_bytes()
    }

    fn discover_grok_observation(
        stdout: &[u8],
    ) -> Result<crate::runtime_adapter::grok::GrokAdvertisedCatalogObservation> {
        crate::runtime_adapter::grok::discover_grok_model_catalog(
            &FakeGrokRunner::successful(stdout),
            &crate::runtime_adapter::grok::GrokCatalogCommandSpec::new("/workspace"),
            Some(CAPTURED_CURSOR_AT_UNIX_MILLIS),
        )
    }

    fn advertised_with_grok(
        observation: crate::runtime_adapter::grok::GrokAdvertisedCatalogObservation,
    ) -> AdvertisedCatalogSet {
        AdvertisedCatalogSet {
            cursor: None,
            grok: Some(observation),
        }
    }

    fn worker_assignment() -> OrchestratorAssignment {
        OrchestratorAssignment {
            id: "worker-a".to_string(),
            runtime: None,
            role: AgentRole::Worker,
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
    fn captured_cursor_catalog_makes_composer_slugs_selectable_without_operator_lists() -> Result<()>
    {
        let observation = captured_cursor_observation()?;
        assert!(observation.catalog().contains("composer-2.5"));
        assert!(observation.catalog().contains("composer-2.5-fast"));

        let catalog = codex_catalog()?;
        let mut plan = test_plan();
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &advertised_with_cursor(observation),
        )?;
        let worker = resolution
            .decisions
            .iter()
            .find(|decision| decision.role == AgentRole::Worker)
            .context("worker decision")?;
        for slug in ["composer-2.5", "composer-2.5-fast"] {
            assert!(
                worker
                    .provenance
                    .candidate_set
                    .iter()
                    .any(|evaluation| evaluation.candidate.runtime == "cursor"
                        && evaluation.candidate.model == slug
                        && evaluation.eligible),
                "{slug} must be an eligible advertised Worker candidate"
            );
        }
        let fresh = worker
            .provenance
            .choice
            .as_ref()
            .context("fresh worker choice")?;
        assert_eq!(fresh.candidate.runtime, "codex");

        let mut pressured = worker.provenance.normalized_input.clone();
        pressured
            .pools
            .iter_mut()
            .find(|pool| pool.runtime == "codex")
            .context("Codex pool")?
            .pool_pressure_basis_points = 10_000;
        let pressured = selection::select(&pressured)?;
        let choice = pressured.choice.as_ref().context("pressured choice")?;
        assert_eq!(choice.candidate.runtime, "cursor");
        assert!(
            choice.candidate.model == "composer-2.5"
                || choice.candidate.model == "composer-2.5-fast"
        );
        Ok(())
    }

    #[test]
    fn withdrawn_cursor_catalog_removes_composer_candidates() -> Result<()> {
        let catalog = codex_catalog()?;
        let mut plan = test_plan();
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &advertised_with_cursor(withdrawn_cursor_observation()?),
        )?;
        let worker = resolution
            .decisions
            .iter()
            .find(|decision| decision.role == AgentRole::Worker)
            .context("worker decision")?;
        assert!(worker.provenance.candidate_set.iter().all(|evaluation| {
            evaluation.candidate.runtime != "cursor"
                || !evaluation.candidate.model.starts_with("composer-2.5")
        }));
        Ok(())
    }

    #[test]
    fn composer_stays_fail_closed_for_judgment_roles_under_codex_pressure() -> Result<()> {
        let catalog = codex_catalog()?;
        let mut plan = test_plan();
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &advertised_with_cursor(captured_cursor_observation()?),
        )?;
        for role in [
            AgentRole::Supervisor,
            AgentRole::Auditor,
            AgentRole::GateClassifier,
            AgentRole::ChildOrchestrator,
        ] {
            let decision = resolution
                .decisions
                .iter()
                .find(|decision| decision.role == role)
                .with_context(|| format!("{} decision", role.as_str()))?;
            let mut pressured = decision.provenance.normalized_input.clone();
            if let Some(pool) = pressured
                .pools
                .iter_mut()
                .find(|pool| pool.runtime == "codex")
            {
                pool.pool_pressure_basis_points = 10_000;
            }
            let pressured = selection::select(&pressured)?;
            if let Some(choice) = &pressured.choice {
                assert_ne!(choice.candidate.runtime, "cursor", "{}", role.as_str());
                assert!(!choice.candidate.model.starts_with("composer-2.5"));
            }
        }
        Ok(())
    }

    #[test]
    fn injected_grok_catalog_joins_without_hardcoded_slug_lists() -> Result<()> {
        use crate::runtime_adapter::grok::{
            inject_grok_advertised_catalog, GrokModelCatalog, GrokModelCatalogEntry,
        };
        let catalog = codex_catalog()?;
        let priors = selection::built_in_prior_dataset()?;
        let grok_prior = priors
            .models
            .iter()
            .find(|prior| prior.runtime == "grok")
            .context("built-in Grok prior")?;
        let observation = inject_grok_advertised_catalog(
            GrokModelCatalog::from_injected_entries([GrokModelCatalogEntry::new(
                grok_prior.model.clone(),
                "Injected Grok Worker",
            )?])?,
            Some(CAPTURED_CURSOR_AT_UNIX_MILLIS),
            b"opaque-injected-grok-payload",
        )?;
        let mut plan = test_plan();
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &AdvertisedCatalogSet {
                cursor: None,
                grok: Some(observation),
            },
        )?;
        let worker = resolution
            .decisions
            .iter()
            .find(|decision| decision.role == AgentRole::Worker)
            .context("worker decision")?;
        assert!(worker.provenance.candidate_set.iter().any(|evaluation| {
            evaluation.candidate.runtime == "grok"
                && evaluation.candidate.model == grok_prior.model
                && evaluation.eligible
        }));

        let withdrawn = inject_grok_advertised_catalog(
            GrokModelCatalog::from_injected_entries([GrokModelCatalogEntry::new(
                "worker-stable",
                "Worker Stable",
            )?])?,
            Some(CAPTURED_CURSOR_AT_UNIX_MILLIS + 1),
            b"withdrawn-injected-grok-payload",
        )?;
        let mut withdrawn_plan = test_plan();
        let withdrawn_resolution = initialize_supervisor_selection(
            &mut withdrawn_plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &AdvertisedCatalogSet {
                cursor: None,
                grok: Some(withdrawn),
            },
        )?;
        let withdrawn_worker = withdrawn_resolution
            .decisions
            .iter()
            .find(|decision| decision.role == AgentRole::Worker)
            .context("withdrawn worker decision")?;
        assert!(withdrawn_worker
            .provenance
            .candidate_set
            .iter()
            .all(|evaluation| evaluation.candidate.model != grok_prior.model));
        Ok(())
    }

    #[test]
    fn observed_grok_catalog_joins_and_withdrawal_removes_membership() -> Result<()> {
        let catalog = codex_catalog()?;
        let priors = selection::built_in_prior_dataset()?;
        let grok_prior = priors
            .models
            .iter()
            .find(|prior| prior.runtime == "grok")
            .context("built-in Grok prior")?;
        let observed = discover_grok_observation(&grok_listing(
            &grok_prior.model,
            &[&format!("  * {} (default)", grok_prior.model)],
        ))?;
        assert!(observed.catalog().contains(&grok_prior.model));

        let mut plan = test_plan();
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &advertised_with_grok(observed),
        )?;
        let worker = resolution
            .decisions
            .iter()
            .find(|decision| decision.role == AgentRole::Worker)
            .context("worker decision")?;
        assert!(worker.provenance.candidate_set.iter().any(|evaluation| {
            evaluation.candidate.runtime == "grok"
                && evaluation.candidate.model == grok_prior.model
                && evaluation.eligible
        }));
        assert!(worker
            .provenance
            .normalized_input
            .catalogs
            .iter()
            .any(|runtime_catalog| runtime_catalog
                .revision
                .starts_with("grok-advertised-sha256:")));

        let withdrawn = discover_grok_observation(&grok_listing(
            "worker-stable",
            &["  * worker-stable (default)"],
        ))?;
        assert!(!withdrawn.catalog().contains(&grok_prior.model));
        let mut withdrawn_plan = test_plan();
        let withdrawn_resolution = initialize_supervisor_selection(
            &mut withdrawn_plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &advertised_with_grok(withdrawn),
        )?;
        let withdrawn_worker = withdrawn_resolution
            .decisions
            .iter()
            .find(|decision| decision.role == AgentRole::Worker)
            .context("withdrawn worker decision")?;
        assert!(withdrawn_worker
            .provenance
            .candidate_set
            .iter()
            .all(|evaluation| evaluation.candidate.model != grok_prior.model));
        Ok(())
    }

    #[test]
    fn observed_grok_catalog_stays_fail_closed_for_judgment_roles() -> Result<()> {
        let catalog = codex_catalog()?;
        let priors = selection::built_in_prior_dataset()?;
        let grok_prior = priors
            .models
            .iter()
            .find(|prior| prior.runtime == "grok")
            .context("built-in Grok prior")?;
        let observation = discover_grok_observation(&grok_listing(
            &grok_prior.model,
            &[&format!("  * {} (default)", grok_prior.model)],
        ))?;
        let mut plan = test_plan();
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &advertised_with_grok(observation),
        )?;
        for role in [
            AgentRole::Supervisor,
            AgentRole::Auditor,
            AgentRole::GateClassifier,
            AgentRole::ChildOrchestrator,
        ] {
            let decision = resolution
                .decisions
                .iter()
                .find(|decision| decision.role == role)
                .with_context(|| format!("{} decision", role.as_str()))?;
            let mut pressured = decision.provenance.normalized_input.clone();
            if let Some(pool) = pressured
                .pools
                .iter_mut()
                .find(|pool| pool.runtime == "codex")
            {
                pool.pool_pressure_basis_points = 10_000;
            }
            let pressured = selection::select(&pressured)?;
            if let Some(choice) = &pressured.choice {
                assert_ne!(choice.candidate.runtime, "grok", "{}", role.as_str());
                assert_ne!(
                    choice.candidate.model,
                    grok_prior.model,
                    "{}",
                    role.as_str()
                );
            }
        }
        Ok(())
    }

    #[test]
    fn selected_runtime_is_stamped_onto_the_assignment() -> Result<()> {
        let catalog = codex_catalog()?;
        let mut plan = test_plan();
        plan.assignments = vec![worker_assignment()];
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &advertised_with_cursor(captured_cursor_observation()?),
        )?;
        bind_selected_assignment_runtimes(&mut plan, &resolution.decisions)?;
        assert_eq!(
            plan.assignments[0].runtime,
            Some(runtime_from_name(
                &resolution
                    .decisions
                    .iter()
                    .find(|decision| decision.role == AgentRole::Worker)
                    .and_then(|decision| decision.provenance.choice.as_ref())
                    .context("worker choice")?
                    .candidate
                    .runtime
            )?)
        );
        Ok(())
    }
}
