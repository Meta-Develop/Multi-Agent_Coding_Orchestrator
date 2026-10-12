//! Loaded routing preferences. Catalog access and launch authority remain separate facts.

use std::{collections::BTreeMap, path::Path};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use super::{CandidateKey, ReasoningEffort};
use crate::safe_state::BoundedRegularReader;

const DEFAULT_POLICY: &str = include_str!("data/routing-policy.json");
pub const ROUTING_POLICY_FILE: &str = "maco-routing-policy.json";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRoutingFeatures {
    pub scope_paths: usize,
    pub scope_modules: usize,
    pub complexity: u16,
    pub risk: u16,
    pub horizon: u16,
    pub context_tokens: u64,
    pub dependency_edges: usize,
    pub independent_groups: usize,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskGrain {
    DirectWorker,
    CoordinatedWorkers,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TreeRoutingPolicy {
    pub coordinated_complexity_min: u16,
    pub coordinated_risk_min: u16,
    pub coordinated_horizon_min: u16,
    pub coordinated_context_tokens_min: u64,
    pub coordinated_scope_paths_min: usize,
    pub min_independent_groups: usize,
    pub max_workers: usize,
    pub max_depth: usize,
}

/// Adapter protocol, not model quality or an assertion of vendor-native tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlTransport {
    AdapterDynamicTool,
    SupervisorCapturedEnvelope,
}

/// Required evidence basis, never evidence that a launch actually satisfied it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionEvidenceBasis {
    /// An actual native observation retained by the owning execution path.
    NativeObserved,
    /// A qualified executable/protocol contract applied to the exact owned launch.
    /// Requested or configured controls alone do not satisfy this basis.
    SourceQualifiedApplied,
}

/// Every aspect is required. This data cannot waive readonly or other security gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoleExecutionEvidenceRequirements {
    pub model: ExecutionEvidenceBasis,
    pub effort: ExecutionEvidenceBasis,
    pub permissions: ExecutionEvidenceBasis,
}

fn deserialize_execution_evidence_requirements<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<RoleExecutionEvidenceRequirements>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    // Missing uses serde's default; explicit null must not select legacy behavior.
    RoleExecutionEvidenceRequirements::deserialize(deserializer).map(Some)
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoleRoutingPreference {
    /// Optional loaded effort preference; supported account metadata is authoritative.
    pub preferred_effort: Option<ReasoningEffort>,
    pub minimum_effort: Option<ReasoningEffort>,
    pub require_measured_quality: bool,
    pub minimum_quality_basis_points: u16,
    pub minimum_samples: u32,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_execution_evidence_requirements"
    )]
    pub execution_evidence_requirements: Option<RoleExecutionEvidenceRequirements>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingObjective {
    pub accepted_cycle_cost_weight: u64,
    pub rejected_attempt_weight: u64,
    pub effort_distance_weight: u64,
    /// An inference penalty for missing evidence, never a measured token price or quality.
    pub unknown_evidence_penalty: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadedRoutingPolicy {
    pub schema_version: u32,
    pub policy_id: String,
    pub tree: TreeRoutingPolicy,
    pub default_role: RoleRoutingPreference,
    pub role_preferences: BTreeMap<String, RoleRoutingPreference>,
    pub objective: RoutingObjective,
    #[serde(default)]
    pub unknown_access_policy: UnknownAccessPolicy,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_task_estimation"
    )]
    pub task_estimation: Option<TaskEstimationPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskScoreWeights {
    pub base: u64,
    pub per_declared_kib: u64,
    pub per_fragment: u64,
    pub per_assignment: u64,
    pub per_scope_path: u64,
    pub per_scope_module: u64,
    pub per_dependency_edge: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskEstimateMatch {
    DeclaredTaskContainsAsciiInsensitive,
    ScopePathPrefix,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskEstimateRule {
    pub id: String,
    pub match_kind: TaskEstimateMatch,
    pub pattern: String,
    pub complexity_basis_points: u16,
    pub risk_basis_points: u16,
    pub horizon_basis_points: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskScoreBand<T> {
    pub max_inclusive: u16,
    pub value: T,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskContextBand {
    pub max_inclusive: u64,
    pub value: super::ContextSize,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskBoundednessBand {
    pub max_scope_paths: u64,
    pub max_scope_modules: u64,
    pub max_dependency_edges: u64,
    pub max_complexity: u16,
    pub value: super::Boundedness,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskContextEstimatePolicy {
    pub bytes_per_estimated_token: u64,
    pub base_tokens: u64,
    pub per_scope_path_tokens: u64,
    pub per_scope_module_tokens: u64,
    pub per_assignment_tokens: u64,
    pub max_estimated_tokens: u64,
}

/// Loaded heuristic data, never observed complexity, tokens, permissions or model quality.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskEstimationPolicy {
    pub max_declaration_bytes: u64,
    pub max_fragments: u64,
    pub max_assignments: u64,
    pub max_scope_items: u64,
    pub max_rules: u64,
    pub score_cap_basis_points: u16,
    pub complexity: TaskScoreWeights,
    pub risk: TaskScoreWeights,
    pub horizon: TaskScoreWeights,
    pub rules: Vec<TaskEstimateRule>,
    pub context: TaskContextEstimatePolicy,
    pub risk_bands: Vec<TaskScoreBand<super::RiskLevel>>,
    pub horizon_bands: Vec<TaskScoreBand<super::TaskHorizon>>,
    pub context_bands: Vec<TaskContextBand>,
    pub boundedness_bands: Vec<TaskBoundednessBand>,
}

fn deserialize_task_estimation<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<TaskEstimationPolicy>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    TaskEstimationPolicy::deserialize(deserializer).map(Some)
}

impl TaskEstimationPolicy {
    pub fn validate(&self) -> Result<()> {
        // Resource ceilings and basis-point units are invariants, not semantic weights.
        if self.max_declaration_bytes == 0
            || self.max_declaration_bytes > 256 * 1024
            || self.max_fragments == 0
            || self.max_fragments > self.max_declaration_bytes
            || self.max_assignments == 0
            || self.max_assignments > self.max_declaration_bytes
            || self.max_scope_items == 0
            || self.max_scope_items > self.max_declaration_bytes
            || self.max_rules == 0
            || self.max_rules > 1024
            || self.rules.len() as u64 > self.max_rules
            || self.score_cap_basis_points == 0
            || self.score_cap_basis_points > 10_000
            || self.context.bytes_per_estimated_token == 0
            || self.context.max_estimated_tokens == 0
        {
            bail!("task estimator has invalid bounds, units or context divisor");
        }
        let mut ids = std::collections::BTreeSet::new();
        for rule in &self.rules {
            if rule.id.trim().is_empty()
                || !ids.insert(&rule.id)
                || rule.pattern.trim().is_empty()
                || rule.pattern.len() > 1024
                || [
                    rule.complexity_basis_points,
                    rule.risk_basis_points,
                    rule.horizon_basis_points,
                ]
                .into_iter()
                .any(|value| value > 10_000)
            {
                bail!("task estimator has an invalid or duplicate rule");
            }
            if rule.match_kind == TaskEstimateMatch::ScopePathPrefix {
                let normalized =
                    crate::sync::normalize_repo_relative_path(Path::new(&rule.pattern))?;
                if normalized
                    .to_str()
                    .context("task estimator rule path is not UTF-8")?
                    .replace('\\', "/")
                    != rule.pattern
                {
                    bail!("task estimator scope rule must use a canonical relative path");
                }
            }
        }
        for weights in [&self.complexity, &self.risk, &self.horizon] {
            if weights.base > u64::from(self.score_cap_basis_points) {
                bail!("task estimator base exceeds its declared score cap");
            }
            let mut maximum = weights.base;
            for (weight, bound) in [
                (
                    weights.per_declared_kib,
                    self.max_declaration_bytes.div_ceil(1024),
                ),
                (weights.per_fragment, self.max_fragments),
                (weights.per_assignment, self.max_assignments),
                (weights.per_scope_path, self.max_scope_items),
                (weights.per_scope_module, self.max_scope_items),
                (weights.per_dependency_edge, self.max_scope_items),
            ] {
                maximum = maximum
                    .checked_add(
                        weight
                            .checked_mul(bound)
                            .context("task estimator score multiplication overflow")?,
                    )
                    .context("task estimator score addition overflow")?;
            }
            maximum
                .checked_add(
                    self.max_rules
                        .checked_mul(10_000)
                        .context("task estimator rule multiplication overflow")?,
                )
                .context("task estimator rule addition overflow")?;
        }
        let mut maximum_context = self
            .context
            .base_tokens
            .checked_add(
                self.max_declaration_bytes
                    .div_ceil(self.context.bytes_per_estimated_token),
            )
            .context("task estimator context addition overflow")?;
        for (weight, bound) in [
            (self.context.per_scope_path_tokens, self.max_scope_items),
            (self.context.per_scope_module_tokens, self.max_scope_items),
            (self.context.per_assignment_tokens, self.max_assignments),
        ] {
            maximum_context = maximum_context
                .checked_add(
                    weight
                        .checked_mul(bound)
                        .context("task estimator context multiplication overflow")?,
                )
                .context("task estimator context addition overflow")?;
        }
        if maximum_context > self.context.max_estimated_tokens {
            bail!("task estimator maximum declared-input context exceeds its configured cap");
        }
        validate_score_bands(&self.risk_bands, self.score_cap_basis_points)?;
        validate_score_bands(&self.horizon_bands, self.score_cap_basis_points)?;
        if self.context_bands.is_empty()
            || self.context_bands.last().map(|band| band.max_inclusive)
                != Some(self.context.max_estimated_tokens)
            || self
                .context_bands
                .windows(2)
                .any(|bands| bands[0].max_inclusive >= bands[1].max_inclusive)
        {
            bail!("task estimator context bands must be ordered and cover its accepted range");
        }
        if self.boundedness_bands.is_empty()
            || self
                .boundedness_bands
                .iter()
                .any(|band| band.max_complexity > self.score_cap_basis_points)
            || self.boundedness_bands.windows(2).any(|bands| {
                let (a, b) = (&bands[0], &bands[1]);
                a.max_scope_paths > b.max_scope_paths
                    || a.max_scope_modules > b.max_scope_modules
                    || a.max_dependency_edges > b.max_dependency_edges
                    || a.max_complexity > b.max_complexity
                    || (
                        a.max_scope_paths,
                        a.max_scope_modules,
                        a.max_dependency_edges,
                        a.max_complexity,
                    ) == (
                        b.max_scope_paths,
                        b.max_scope_modules,
                        b.max_dependency_edges,
                        b.max_complexity,
                    )
            })
            || !self.boundedness_bands.last().is_some_and(|band| {
                band.max_scope_paths >= self.max_scope_items
                    && band.max_scope_modules >= self.max_scope_items
                    && band.max_dependency_edges >= self.max_scope_items
                    && band.max_complexity == self.score_cap_basis_points
            })
        {
            bail!("task estimator boundedness bands must be nested and cover validated scope");
        }
        Ok(())
    }
}

fn validate_score_bands<T>(bands: &[TaskScoreBand<T>], cap: u16) -> Result<()> {
    if bands.is_empty()
        || bands.last().map(|band| band.max_inclusive) != Some(cap)
        || bands
            .windows(2)
            .any(|pair| pair[0].max_inclusive >= pair[1].max_inclusive)
        || bands.iter().any(|band| band.max_inclusive > cap)
    {
        bail!("task estimator score bands must be ordered and cover its accepted range");
    }
    Ok(())
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownAccessPolicy {
    #[default]
    Reject,
    UnknownAccessForProductiveAttempt,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenRoutingPolicy {
    pub policy: LoadedRoutingPolicy,
    pub sha256: String,
    pub source: String,
}

/// Compatibility is explicit: absence preserves all existing strict execution gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleExecutionEvidenceResolution {
    LegacyStrict,
    Required(RoleExecutionEvidenceRequirements),
}

/// Validated policy data, not selection authorization or execution evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRoleExecutionEvidence {
    role: String,
    policy_sha256: String,
    resolution: RoleExecutionEvidenceResolution,
}

impl ResolvedRoleExecutionEvidence {
    pub fn role(&self) -> &str {
        &self.role
    }

    pub fn policy_sha256(&self) -> &str {
        &self.policy_sha256
    }

    pub fn resolution(&self) -> RoleExecutionEvidenceResolution {
        self.resolution
    }
}

impl FrozenRoutingPolicy {
    pub fn resolve_role_execution_evidence(
        &self,
        role: &str,
    ) -> Result<ResolvedRoleExecutionEvidence> {
        if role.trim().is_empty() || role != role.trim() {
            bail!("execution evidence requirements need an exact nonempty role");
        }
        self.policy.validate()?;
        let digest = crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(&self.policy)?);
        if digest != self.sha256 {
            bail!("frozen routing policy digest differs from its content");
        }
        // Use the existing whole-role fallback. A present legacy role stays strict
        // even when the default role contains explicit evidence requirements.
        let resolution = match self.policy.role(role).execution_evidence_requirements {
            Some(requirements) => RoleExecutionEvidenceResolution::Required(requirements),
            None => RoleExecutionEvidenceResolution::LegacyStrict,
        };
        Ok(ResolvedRoleExecutionEvidence {
            role: role.to_string(),
            policy_sha256: digest,
            resolution,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingPolicyReceipt {
    pub frozen: FrozenRoutingPolicy,
    pub role: String,
    pub features: TaskRoutingFeatures,
}

thread_local! {
    static ACTIVE_POLICY: std::cell::RefCell<Option<FrozenRoutingPolicy>> = const { std::cell::RefCell::new(None) };
    static SELECTED_AUTHORIZATIONS: std::cell::RefCell<BTreeMap<String, CandidateKey>> = const { std::cell::RefCell::new(BTreeMap::new()) };
}

pub struct RoutingPolicyGuard {
    previous: Option<FrozenRoutingPolicy>,
    previous_authorizations: BTreeMap<String, CandidateKey>,
    _thread_affine: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl Drop for RoutingPolicyGuard {
    fn drop(&mut self) {
        ACTIVE_POLICY.with(|slot| *slot.borrow_mut() = self.previous.take());
        SELECTED_AUTHORIZATIONS
            .with(|slot| *slot.borrow_mut() = std::mem::take(&mut self.previous_authorizations));
    }
}

pub fn bind_routing_policy(policy: Option<FrozenRoutingPolicy>) -> Result<RoutingPolicyGuard> {
    if let Some(frozen) = &policy {
        frozen.policy.validate()?;
        let digest = crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(&frozen.policy)?);
        if digest != frozen.sha256 {
            bail!("frozen routing policy digest differs from its content");
        }
    }
    let previous_authorizations =
        SELECTED_AUTHORIZATIONS.with(|slot| std::mem::take(&mut *slot.borrow_mut()));
    Ok(ACTIVE_POLICY.with(|slot| RoutingPolicyGuard {
        previous_authorizations,
        previous: slot.replace(policy),
        _thread_affine: std::marker::PhantomData,
    }))
}

pub fn current_routing_policy() -> Option<FrozenRoutingPolicy> {
    ACTIVE_POLICY.with(|slot| slot.borrow().clone())
}

pub(crate) fn captured_selected_authorizations() -> BTreeMap<String, CandidateKey> {
    SELECTED_AUTHORIZATIONS.with(|slot| slot.borrow().clone())
}

pub(crate) fn install_selected_authorizations(authorizations: BTreeMap<String, CandidateKey>) {
    SELECTED_AUTHORIZATIONS.with(|slot| *slot.borrow_mut() = authorizations);
}

/// Only a successful pure-selector result can seal an in-process launch triple.
/// The policy file itself and a deserialized model name grant no authorization.
pub(crate) fn seal_selected_candidate(
    role: &str,
    decision: &super::SelectionProvenance,
) -> Result<()> {
    let Some(receipt) = &decision.routing_policy else {
        return Ok(());
    };
    let active =
        current_routing_policy().context("selected candidate has no active frozen policy")?;
    if active != receipt.frozen
        || receipt.role != role
        || decision.status != super::DecisionStatus::Selected
    {
        bail!("selected candidate policy or role binding mismatch");
    }
    let chosen = &decision
        .choice
        .as_ref()
        .context("selected candidate has no choice")?
        .candidate;
    if !decision
        .candidate_set
        .iter()
        .any(|entry| entry.candidate == *chosen && entry.eligible)
    {
        bail!("chosen candidate has no eligible selector evaluation");
    }
    SELECTED_AUTHORIZATIONS.with(|slot| slot.borrow_mut().insert(role.to_string(), chosen.clone()));
    Ok(())
}

pub(crate) fn validate_selected_model(role: &str, model: &str) -> Result<()> {
    let authorized = SELECTED_AUTHORIZATIONS.with(|slot| slot.borrow().get(role).cloned());
    if authorized.is_none_or(|candidate| candidate.model != model) {
        bail!("role/model has no current selector-authorized loaded-policy binding");
    }
    Ok(())
}

pub(crate) fn validate_selected_launch(
    role: &str,
    runtime: &str,
    model: &str,
    effort: &str,
) -> Result<()> {
    let authorized = SELECTED_AUTHORIZATIONS.with(|slot| slot.borrow().get(role).cloned());
    if !authorized.is_some_and(|candidate| {
        candidate.runtime == runtime
            && candidate.model == model
            && candidate.effort.as_str() == effort
    }) {
        bail!("launch runtime/model/effort differs from its current selector authorization");
    }
    Ok(())
}

impl LoadedRoutingPolicy {
    pub fn role(&self, role: &str) -> &RoleRoutingPreference {
        self.role_preferences
            .get(role)
            .unwrap_or(&self.default_role)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 || self.policy_id.trim().is_empty() {
            bail!("routing policy requires schema version 1 and a nonempty identity");
        }
        validate_tree(&self.tree)?;
        if let Some(estimator) = &self.task_estimation {
            estimator.validate()?;
        }
        for role in std::iter::once(&self.default_role).chain(self.role_preferences.values()) {
            if role.minimum_quality_basis_points > 10_000
                || (role.require_measured_quality && role.minimum_samples == 0)
                || role
                    .preferred_effort
                    .zip(role.minimum_effort)
                    .is_some_and(|(preferred, minimum)| preferred < minimum)
            {
                bail!("routing policy has invalid role effort or quality preferences");
            }
        }
        if self.objective.accepted_cycle_cost_weight == 0
            || self.objective.unknown_evidence_penalty == 0
        {
            bail!("routing policy must account for accepted-cycle cost and evidence uncertainty");
        }
        Ok(())
    }
}

fn validate_tree(tree: &TreeRoutingPolicy) -> Result<()> {
    if [
        tree.coordinated_complexity_min,
        tree.coordinated_risk_min,
        tree.coordinated_horizon_min,
    ]
    .into_iter()
    .any(|value| value > 10_000)
        || tree.max_workers == 0
        || tree.max_depth == 0
        || tree.min_independent_groups == 0
    {
        bail!("routing tree policy has invalid thresholds or limits");
    }
    Ok(())
}

pub fn evaluate_task_grain(
    features: &TaskRoutingFeatures,
    tree: &TreeRoutingPolicy,
) -> Result<TaskGrain> {
    validate_tree(tree)?;
    if [features.complexity, features.risk, features.horizon]
        .into_iter()
        .any(|value| value > 10_000)
    {
        bail!("task routing feature scores must be basis points");
    }
    let coordinated = features.scope_paths >= tree.coordinated_scope_paths_min
        || features.scope_modules > 1
        || features.dependency_edges > 0
        || features.complexity >= tree.coordinated_complexity_min
        || features.risk >= tree.coordinated_risk_min
        || features.horizon >= tree.coordinated_horizon_min
        || features.context_tokens >= tree.coordinated_context_tokens_min;
    Ok(
        if coordinated
            && features.independent_groups >= tree.min_independent_groups
            && tree.max_workers > 1
        {
            TaskGrain::CoordinatedWorkers
        } else {
            TaskGrain::DirectWorker
        },
    )
}

/// Read once and freeze the effective policy; callers persist this receipt with run evidence.
pub fn load_routing_policy(repo: &Path) -> Result<FrozenRoutingPolicy> {
    let (bytes, source) =
        match BoundedRegularReader::read_relative(repo, ROUTING_POLICY_FILE, 256 * 1024) {
            Ok(bytes) => (bytes, ROUTING_POLICY_FILE.to_string()),
            Err(error)
                if error
                    .root_cause()
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                (
                    DEFAULT_POLICY.as_bytes().to_vec(),
                    "bundled-routing-policy".to_string(),
                )
            }
            Err(error) => return Err(error).context("failed to read bounded routing policy"),
        };
    let policy: LoadedRoutingPolicy =
        serde_json::from_slice(&bytes).context("invalid routing policy")?;
    policy.validate()?;
    let normalized = serde_json::to_vec(&policy)?;
    Ok(FrozenRoutingPolicy {
        policy,
        sha256: crate::artifacts::state_auth::sha256_hex(&normalized),
        source,
    })
}

/// Exact GUI principal identity, without credential material. Equality tokens stay opaque.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccountBinding {
    pub provider_id: String,
    pub account_id: String,
    pub account_incarnation: String,
    pub selection_revision: u64,
}

#[cfg(target_os = "linux")]
impl From<&coding_agent_manager_lib::account_authority::SelectedAccountBinding> for AccountBinding {
    fn from(binding: &coding_agent_manager_lib::account_authority::SelectedAccountBinding) -> Self {
        Self {
            provider_id: binding.provider_id.clone(),
            account_id: binding.account_id.clone(),
            account_incarnation: binding.account_incarnation.clone(),
            selection_revision: binding.selection_revision,
        }
    }
}

/// Immutable selection receipt. Does not grant filesystem, credentials, budget or publication authority.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedLaunchRequest {
    candidate: CandidateKey,
    account_binding: AccountBinding,
    pub catalog_revision: String,
    pub catalog_digest: String,
    pub policy_digest: String,
    pub task_features: TaskRoutingFeatures,
    pub control_transport: Option<ControlTransport>,
    #[serde(default)]
    pub access_uncertainty: Vec<String>,
}

impl SelectedLaunchRequest {
    pub fn candidate(&self) -> &CandidateKey {
        &self.candidate
    }
    pub fn account_binding(&self) -> &AccountBinding {
        &self.account_binding
    }
    pub fn validate_binding(&self, binding: &AccountBinding) -> Result<()> {
        if &self.account_binding != binding {
            bail!("selected launch account binding changed");
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn from_observation(
        candidate: CandidateKey,
        observation: &coding_agent_manager_lib::account_authority::AccountObserveResult,
        policy: &FrozenRoutingPolicy,
        features: TaskRoutingFeatures,
        control_transport: Option<ControlTransport>,
    ) -> Result<Self> {
        use coding_agent_manager_lib::account_authority::{
            validate_observed_models_for_binding, ModelAccessOutcome, ObservationOutcome,
        };
        policy.policy.validate()?;
        if crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(&policy.policy)?)
            != policy.sha256
        {
            bail!("selected launch routing policy digest mismatch");
        }
        evaluate_task_grain(&features, &policy.policy.tree)?;
        let runtime = match observation.binding.provider_id.as_str() {
            "codex-cli" => "codex",
            "grok-cli" => "grok",
            "cursor" => "cursor",
            "claude-code" => "claude-code",
            "gemini-cli" => "gemini-cli",
            _ => bail!("selected account has no supported runtime protocol mapping"),
        };
        if candidate.runtime != runtime {
            bail!("selected runtime differs from the observed account protocol");
        }
        let models = observation
            .models
            .as_ref()
            .filter(|category| matches!(category.outcome, ObservationOutcome::Observed))
            .and_then(|category| category.content.as_ref())
            .context("selected launch requires observed account-bound model metadata")?;
        validate_observed_models_for_binding(models, &observation.binding)
            .map_err(anyhow::Error::msg)?;
        let model = models
            .models
            .iter()
            .find(|model| model.model_id == candidate.model)
            .context("selected model is absent from the account catalog")?;
        let access_uncertainty = match model.access {
            ModelAccessOutcome::Unavailable => {
                bail!("selected model has known unavailable account access")
            }
            ModelAccessOutcome::Available => Vec::new(),
            ModelAccessOutcome::UnknownAccess => {
                if policy.policy.unknown_access_policy
                    != UnknownAccessPolicy::UnknownAccessForProductiveAttempt
                {
                    bail!("loaded policy refuses unknown account access");
                }
                let mut uncertainty = vec!["Account access is unknown; policy admits a legitimate productive attempt, not an access probe.".into()];
                if models.provenance.as_ref().is_none_or(|source| source.stale) {
                    uncertainty.push("Catalog freshness is stale or unqualified.".into());
                }
                if models
                    .provenance
                    .as_ref()
                    .and_then(|source| source.principal_binding.as_ref())
                    .is_none()
                {
                    uncertainty.push("Catalog source principal is unqualified; the outer selected-account binding is separate.".into());
                }
                uncertainty
            }
        };
        if !model.supported_efforts.as_ref().is_some_and(|efforts| {
            efforts
                .iter()
                .any(|effort| effort == candidate.effort.as_str())
        }) {
            bail!("selected effort is unsupported or unknown in the account catalog");
        }
        // Hash the binding and timestamp as well as metadata: equal slugs do not imply equal principals.
        let catalog_digest =
            crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(observation)?);
        Ok(Self {
            candidate,
            account_binding: (&observation.binding).into(),
            catalog_revision: format!("account-observe-sha256:{catalog_digest}"),
            catalog_digest,
            policy_digest: policy.sha256.clone(),
            task_features: features,
            control_transport,
            access_uncertainty,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_estimation_missing_field_preserves_legacy_json_and_digest() -> Result<()> {
        let policy: LoadedRoutingPolicy = serde_json::from_str(LEGACY_POLICY_JSON)?;
        policy.validate()?;
        assert!(policy.task_estimation.is_none());
        assert_eq!(serde_json::to_vec(&policy)?, LEGACY_POLICY_JSON.as_bytes());
        assert_eq!(
            freeze_test_policy(policy)?.sha256,
            crate::artifacts::state_auth::sha256_hex(LEGACY_POLICY_JSON.as_bytes())
        );
        Ok(())
    }

    #[test]
    fn task_estimation_rejects_null_unknown_malformed_bounds_and_overflow() -> Result<()> {
        let policy: LoadedRoutingPolicy = serde_json::from_str(DEFAULT_POLICY)?;
        policy.validate()?;
        let value = serde_json::to_value(&policy)?;
        for malformed in [serde_json::Value::Null, serde_json::json!({}), {
            let mut estimator = value["task_estimation"].clone();
            estimator["unexpected"] = serde_json::json!(true);
            estimator
        }] {
            let mut changed = value.clone();
            changed["task_estimation"] = malformed;
            assert!(serde_json::from_value::<LoadedRoutingPolicy>(changed).is_err());
        }
        let original = policy.task_estimation.as_ref().unwrap();
        for changed in [
            {
                let mut p = original.clone();
                p.context.bytes_per_estimated_token = 0;
                p
            },
            {
                let mut p = original.clone();
                p.complexity.per_assignment = u64::MAX;
                p
            },
            {
                let mut p = original.clone();
                p.max_declaration_bytes = 0;
                p
            },
            {
                let mut p = original.clone();
                p.score_cap_basis_points = 10_001;
                p
            },
            {
                let mut p = original.clone();
                p.risk_bands[1].max_inclusive = p.risk_bands[0].max_inclusive;
                p
            },
            {
                let mut p = original.clone();
                p.rules[1].id = p.rules[0].id.clone();
                p
            },
            {
                let mut p = original.clone();
                p.boundedness_bands.last_mut().unwrap().max_complexity -= 1;
                p
            },
        ] {
            assert!(changed.validate().is_err());
        }
        let mut negative = value;
        negative["task_estimation"]["risk"]["base"] = serde_json::json!(-1);
        assert!(serde_json::from_value::<LoadedRoutingPolicy>(negative).is_err());
        Ok(())
    }

    // Exact normalized bytes of the historical schema, without execution requirements.
    const LEGACY_POLICY_JSON: &str = concat!(
        r#"{"schema_version":1,"policy_id":"legacy-fixture","tree":{"coordinated_complexity_min":5000,"coordinated_risk_min":5000,"coordinated_horizon_min":5000,"coordinated_context_tokens_min":1000,"coordinated_scope_paths_min":2,"min_independent_groups":2,"max_workers":2,"max_depth":2},"#,
        r#""default_role":{"preferred_effort":null,"minimum_effort":null,"require_measured_quality":false,"minimum_quality_basis_points":0,"minimum_samples":0},"role_preferences":{},"#,
        r#""objective":{"accepted_cycle_cost_weight":1,"rejected_attempt_weight":1,"effort_distance_weight":1,"unknown_evidence_penalty":1},"unknown_access_policy":"reject"}"#,
    );

    fn freeze_test_policy(policy: LoadedRoutingPolicy) -> Result<FrozenRoutingPolicy> {
        Ok(FrozenRoutingPolicy {
            sha256: crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(&policy)?),
            policy,
            source: "test-data-only".to_string(),
        })
    }

    #[test]
    fn legacy_missing_execution_requirements_preserve_json_and_digest() -> Result<()> {
        let policy: LoadedRoutingPolicy = serde_json::from_str(LEGACY_POLICY_JSON)?;
        policy.validate()?;
        assert!(policy
            .default_role
            .execution_evidence_requirements
            .is_none());
        let normalized = serde_json::to_vec(&policy)?;
        assert_eq!(normalized, LEGACY_POLICY_JSON.as_bytes());
        let historical_digest =
            crate::artifacts::state_auth::sha256_hex(LEGACY_POLICY_JSON.as_bytes());
        assert_eq!(
            crate::artifacts::state_auth::sha256_hex(&normalized),
            historical_digest
        );
        let frozen = freeze_test_policy(policy)?;
        let resolved = frozen.resolve_role_execution_evidence("Auditor")?;
        assert_eq!(resolved.role(), "Auditor");
        assert_eq!(resolved.policy_sha256(), historical_digest);
        assert_eq!(
            resolved.resolution(),
            RoleExecutionEvidenceResolution::LegacyStrict
        );
        Ok(())
    }

    #[test]
    fn execution_requirements_roundtrip_bind_role_fallback_and_policy_digest() -> Result<()> {
        let mut policy: LoadedRoutingPolicy = serde_json::from_str(LEGACY_POLICY_JSON)?;
        let legacy_digest = freeze_test_policy(policy.clone())?.sha256;
        policy
            .role_preferences
            .insert("LegacyRole".to_string(), policy.default_role.clone());
        let default_requirements = RoleExecutionEvidenceRequirements {
            model: ExecutionEvidenceBasis::SourceQualifiedApplied,
            effort: ExecutionEvidenceBasis::NativeObserved,
            permissions: ExecutionEvidenceBasis::SourceQualifiedApplied,
        };
        policy.default_role.execution_evidence_requirements = Some(default_requirements);
        let auditor_requirements = RoleExecutionEvidenceRequirements {
            model: ExecutionEvidenceBasis::NativeObserved,
            effort: ExecutionEvidenceBasis::NativeObserved,
            permissions: ExecutionEvidenceBasis::NativeObserved,
        };
        let mut auditor = policy.default_role.clone();
        auditor.execution_evidence_requirements = Some(auditor_requirements);
        policy
            .role_preferences
            .insert("Auditor".to_string(), auditor);
        let frozen = freeze_test_policy(policy)?;
        assert_ne!(frozen.sha256, legacy_digest);
        let wire = serde_json::to_vec(&frozen)?;
        let restored: FrozenRoutingPolicy = serde_json::from_slice(&wire)?;
        assert_eq!(restored, frozen);
        let resolved = restored.resolve_role_execution_evidence("Auditor")?;
        assert_eq!(resolved.role(), "Auditor");
        assert_eq!(resolved.policy_sha256(), restored.sha256);
        assert_eq!(
            resolved.resolution(),
            RoleExecutionEvidenceResolution::Required(auditor_requirements)
        );
        assert_eq!(
            restored
                .resolve_role_execution_evidence("OtherRole")?
                .resolution(),
            RoleExecutionEvidenceResolution::Required(default_requirements)
        );
        // A present role with a missing field retains its own legacy strict gates.
        assert_eq!(
            restored
                .resolve_role_execution_evidence("LegacyRole")?
                .resolution(),
            RoleExecutionEvidenceResolution::LegacyStrict
        );
        Ok(())
    }

    #[test]
    fn execution_requirements_resolution_refuses_drift_and_invalid_policy() -> Result<()> {
        let policy: LoadedRoutingPolicy = serde_json::from_str(LEGACY_POLICY_JSON)?;
        let mut frozen = freeze_test_policy(policy)?;
        assert!(frozen.resolve_role_execution_evidence("").is_err());
        assert!(frozen.resolve_role_execution_evidence(" Auditor").is_err());
        frozen.policy.default_role.execution_evidence_requirements =
            Some(RoleExecutionEvidenceRequirements {
                model: ExecutionEvidenceBasis::NativeObserved,
                effort: ExecutionEvidenceBasis::NativeObserved,
                permissions: ExecutionEvidenceBasis::SourceQualifiedApplied,
            });
        assert!(frozen.resolve_role_execution_evidence("Auditor").is_err());
        frozen.policy.schema_version = 2;
        frozen.sha256 =
            crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(&frozen.policy)?);
        assert!(frozen.resolve_role_execution_evidence("Auditor").is_err());
        Ok(())
    }

    #[test]
    fn execution_requirements_reject_malformed_fields_and_requested_only_waivers() -> Result<()> {
        let policy: LoadedRoutingPolicy = serde_json::from_str(LEGACY_POLICY_JSON)?;
        let role = serde_json::to_value(&policy.default_role)?;
        let valid = serde_json::json!({
            "model": "native_observed",
            "effort": "native_observed",
            "permissions": "source_qualified_applied"
        });
        for malformed in [
            serde_json::Value::Null,
            serde_json::json!({}),
            serde_json::json!({"model": "native_observed", "effort": "native_observed"}),
            serde_json::json!({
                "model": "native_observed", "effort": "native_observed",
                "permissions": "source_qualified_applied", "disabled_security": false
            }),
        ] {
            let mut value = role.clone();
            value["execution_evidence_requirements"] = malformed;
            assert!(serde_json::from_value::<RoleRoutingPreference>(value).is_err());
        }
        for field in ["model", "effort", "permissions"] {
            for unsupported in [
                serde_json::json!("requested_only"),
                serde_json::json!("configured"),
                serde_json::json!("disabled_security"),
                serde_json::json!(true),
                serde_json::Value::Null,
            ] {
                let mut requirements = valid.clone();
                requirements[field] = unsupported;
                let mut value = role.clone();
                value["execution_evidence_requirements"] = requirements;
                assert!(serde_json::from_value::<RoleRoutingPreference>(value).is_err());
            }
        }
        Ok(())
    }

    #[test]
    fn structural_routing_uses_loaded_thresholds_and_independence() -> Result<()> {
        let policy: LoadedRoutingPolicy = serde_json::from_str(DEFAULT_POLICY)?;
        policy.validate()?;
        let mut features = TaskRoutingFeatures {
            scope_paths: 1,
            scope_modules: 1,
            complexity: 0,
            risk: 0,
            horizon: 0,
            context_tokens: 0,
            dependency_edges: 0,
            independent_groups: 1,
            evidence: vec![],
        };
        assert_eq!(
            evaluate_task_grain(&features, &policy.tree)?,
            TaskGrain::DirectWorker
        );
        features.scope_paths = policy.tree.coordinated_scope_paths_min;
        features.independent_groups = policy.tree.min_independent_groups;
        assert_eq!(
            evaluate_task_grain(&features, &policy.tree)?,
            TaskGrain::CoordinatedWorkers
        );
        features.independent_groups = 1;
        assert_eq!(
            evaluate_task_grain(&features, &policy.tree)?,
            TaskGrain::DirectWorker
        );
        features.risk = 10_001;
        assert!(evaluate_task_grain(&features, &policy.tree).is_err());
        Ok(())
    }
}
