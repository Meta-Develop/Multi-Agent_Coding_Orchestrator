//! Provider-neutral actions and search-space dimensions.
//!
//! Backend adapters implement [`EffortMapper`]. Unsupported efforts are
//! unrepresentable (`Err`) rather than silently coerced. Later phases add
//! backends by supplying a mapper; they do not edit this module.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

use super::error::OptimizerError;
use super::ids::{
    BackendId, CatalogVersion, ModelFamilyId, ProviderId, RoleId, RuntimeSlug, TimestampMillis,
    VerifierProfileId,
};

/// Canonical reasoning effort. `model@effort` pairs are distinct actions;
/// higher effort is never assumed to dominate lower effort.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CanonicalEffort {
    Minimal,
    Low,
    Medium,
    High,
    XHigh,
    Max,
    ProviderNative(String),
}

impl CanonicalEffort {
    pub fn as_label(&self) -> &str {
        match self {
            Self::Minimal => "minimal",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::XHigh => "xhigh",
            Self::Max => "max",
            Self::ProviderNative(native) => native.as_str(),
        }
    }
}

impl fmt::Display for CanonicalEffort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_label())
    }
}

/// Native effort parameter a backend adapter actually sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeEffort {
    pub parameter_name: String,
    pub parameter_value: String,
}

/// Maps [`CanonicalEffort`] onto one backend's native parameter space.
///
/// Object-safe so adapters live outside the optimizer core.
pub trait EffortMapper {
    fn backend_id(&self) -> &BackendId;

    /// Return the native parameter, or [`OptimizerError::UnsupportedEffort`].
    /// Never coerce an unsupported effort onto a nearby supported one.
    fn map_effort(&self, effort: &CanonicalEffort) -> Result<NativeEffort, OptimizerError>;
}

/// Fixed mapping table for one backend. Later adapters can reuse this type
/// without editing optimizer core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticEffortMapper {
    backend: BackendId,
    mapping: BTreeMap<CanonicalEffort, NativeEffort>,
}

impl StaticEffortMapper {
    pub fn new(
        backend: BackendId,
        mapping: BTreeMap<CanonicalEffort, NativeEffort>,
    ) -> Result<Self, OptimizerError> {
        if mapping.is_empty() {
            return Err(OptimizerError::invalid(
                "effort mapper must declare at least one supported effort",
            ));
        }
        Ok(Self { backend, mapping })
    }

    pub fn supported_efforts(&self) -> impl Iterator<Item = &CanonicalEffort> {
        self.mapping.keys()
    }
}

impl EffortMapper for StaticEffortMapper {
    fn backend_id(&self) -> &BackendId {
        &self.backend
    }

    fn map_effort(&self, effort: &CanonicalEffort) -> Result<NativeEffort, OptimizerError> {
        self.mapping
            .get(effort)
            .cloned()
            .ok_or_else(|| OptimizerError::UnsupportedEffort {
                backend: self.backend.to_string(),
                effort: effort.to_string(),
            })
    }
}

/// Registry of per-backend mappers. New backends register here; the
/// enumerator never invents a mapping.
#[derive(Default)]
pub struct EffortMapperRegistry {
    mappers: BTreeMap<BackendId, Box<dyn EffortMapper + Send + Sync>>,
}

impl EffortMapperRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, mapper: Box<dyn EffortMapper + Send + Sync>) {
        let backend = mapper.backend_id().clone();
        self.mappers.insert(backend, mapper);
    }

    pub fn mapper(&self, backend: &BackendId) -> Result<&dyn EffortMapper, OptimizerError> {
        self.mappers
            .get(backend)
            .map(|mapper| mapper.as_ref() as &dyn EffortMapper)
            .ok_or_else(|| OptimizerError::MissingEffortMapper(backend.to_string()))
    }

    pub fn map(
        &self,
        backend: &BackendId,
        effort: &CanonicalEffort,
    ) -> Result<NativeEffort, OptimizerError> {
        self.mapper(backend)?.map_effort(effort)
    }
}

/// Optimizer-local role. Distinct from `supervise::AgentRole` so later
/// phases can add roles via [`AgentRole::Extension`] without editing
/// supervise or this enum's existing variants.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AgentRole {
    Planner,
    Supervisor,
    ChildOrchestrator,
    Worker,
    Repairer,
    Researcher,
    GateClassifier,
    Auditor,
    Certifier,
    Extension(RoleId),
}

/// Runtime model identity. The runtime slug is never silently substituted;
/// requested versus resolved slugs live in distinct fields.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RuntimeModelId {
    pub provider: ProviderId,
    pub backend: BackendId,
    pub model_family: ModelFamilyId,
    pub runtime_slug: RuntimeSlug,
    pub catalog_version: CatalogVersion,
    pub observation_timestamp: TimestampMillis,
}

/// Requested slug plus the catalog-resolved identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedRuntimeModel {
    pub requested_slug: RuntimeSlug,
    pub resolved: RuntimeModelId,
}

impl ResolvedRuntimeModel {
    pub fn slugs_match_request(&self) -> bool {
        self.requested_slug == self.resolved.runtime_slug
    }
}

/// One searchable action. A model at `medium` and the same model at `xhigh`
/// are distinct actions with independently learned distributions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelAction {
    pub backend_id: BackendId,
    pub provider_id: ProviderId,
    pub runtime_model: RuntimeModelId,
    pub requested_slug: RuntimeSlug,
    pub effort: CanonicalEffort,
    pub role: AgentRole,
    pub max_turns: u32,
    pub timeout_seconds: u64,
    pub tool_budget: Option<u32>,
    pub output_token_budget: Option<u64>,
    pub concurrency: u32,
    pub verifier_profile: VerifierProfileId,
}

/// Shared budget fields applied when enumerating actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionBudget {
    pub max_turns: u32,
    pub max_tool_calls: Option<u32>,
    pub timeout_seconds: u64,
    pub output_token_ceiling: Option<u64>,
    pub context_ceiling: Option<u64>,
    pub validation_retries: u32,
    pub self_repair_count: u32,
    pub escalation_count: u32,
    pub hedge_delay_seconds: Option<u64>,
    pub concurrency: u32,
}

impl Default for ExecutionBudget {
    fn default() -> Self {
        Self {
            max_turns: 8,
            max_tool_calls: None,
            timeout_seconds: 600,
            output_token_ceiling: None,
            context_ceiling: None,
            validation_retries: 1,
            self_repair_count: 1,
            escalation_count: 1,
            hedge_delay_seconds: None,
            concurrency: 1,
        }
    }
}

/// Topology is a first-class search dimension, stored on the policy graph
/// rather than baked into a single action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologySpec {
    pub planner: PlannerTopology,
    pub workers: WorkerTopology,
    pub hedge: HedgeTopology,
    pub review: ReviewTopology,
    pub restart: RestartMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlannerTopology {
    None,
    Single,
    Hierarchical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerTopology {
    One,
    Parallel { count: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HedgeTopology {
    None,
    Delayed { delay_seconds: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReviewTopology {
    None,
    Independent,
    Ensemble,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RestartMode {
    Continuation,
    CleanRestart,
}

/// Verification configuration. Search may add gates and never remove one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierProfile {
    id: VerifierProfileId,
    gates: Vec<VerificationGate>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum VerificationGate {
    DeterministicTests,
    HeldOutTests,
    StaticAnalysis,
    Benchmarks,
    SecurityScan,
    MutationTests,
    Reviewer {
        model: RuntimeSlug,
        effort: CanonicalEffort,
    },
    ReviewerCount(u32),
    Aggregation(AggregationRule),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AggregationRule {
    Unanimous,
    Majority,
    AllMandatory,
}

impl VerifierProfile {
    pub fn new(id: VerifierProfileId, gates: Vec<VerificationGate>) -> Self {
        Self { id, gates }
    }

    pub fn id(&self) -> &VerifierProfileId {
        &self.id
    }

    pub fn gates(&self) -> &[VerificationGate] {
        &self.gates
    }

    /// Search may add a gate. There is no corresponding remove API.
    pub fn add_gate(&mut self, gate: VerificationGate) {
        if !self.gates.contains(&gate) {
            self.gates.push(gate);
        }
    }
}

/// Shared fields used when exploding a catalog into distinct actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionTemplate {
    pub role: AgentRole,
    pub budget: ExecutionBudget,
    pub verifier_profile: VerifierProfileId,
    pub requested_slug_override: Option<RuntimeSlug>,
}

impl ModelAction {
    pub fn from_model_effort(
        model: RuntimeModelId,
        requested_slug: RuntimeSlug,
        effort: CanonicalEffort,
        template: &ActionTemplate,
    ) -> Self {
        Self {
            backend_id: model.backend.clone(),
            provider_id: model.provider.clone(),
            runtime_model: model,
            requested_slug,
            effort,
            role: template.role.clone(),
            max_turns: template.budget.max_turns,
            timeout_seconds: template.budget.timeout_seconds,
            tool_budget: template.budget.max_tool_calls,
            output_token_budget: template.budget.output_token_ceiling,
            concurrency: template.budget.concurrency,
            verifier_profile: template.verifier_profile.clone(),
        }
    }

    /// Distinctness key: model identity + effort + role, not a scalar tier.
    pub fn action_key(&self) -> ActionKey {
        ActionKey {
            runtime_model: self.runtime_model.clone(),
            effort: self.effort.clone(),
            role: self.role.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActionKey {
    pub runtime_model: RuntimeModelId,
    pub effort: CanonicalEffort,
    pub role: AgentRole,
}

/// Enumerate compatible `model × effort` pairs as distinct actions.
///
/// A pair is compatible only when the backend mapper represents the effort.
/// Unsupported efforts are omitted, never coerced.
pub fn enumerate_compatible_actions(
    models: &[RuntimeModelId],
    efforts: &[CanonicalEffort],
    mappers: &EffortMapperRegistry,
    template: &ActionTemplate,
) -> Result<Vec<ModelAction>, OptimizerError> {
    let mut actions = Vec::new();
    for model in models {
        let mapper = mappers.mapper(&model.backend)?;
        for effort in efforts {
            match mapper.map_effort(effort) {
                Ok(_) => {
                    let requested = template
                        .requested_slug_override
                        .clone()
                        .unwrap_or_else(|| model.runtime_slug.clone());
                    actions.push(ModelAction::from_model_effort(
                        model.clone(),
                        requested,
                        effort.clone(),
                        template,
                    ));
                }
                Err(OptimizerError::UnsupportedEffort { .. }) => {}
                Err(error) => return Err(error),
            }
        }
    }
    Ok(actions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::ids::TimestampMillis;

    fn slug(value: &str) -> RuntimeSlug {
        RuntimeSlug::new(value).expect("slug")
    }

    fn model(backend: &str, provider: &str, slug_value: &str) -> RuntimeModelId {
        RuntimeModelId {
            provider: ProviderId::new(provider).expect("provider"),
            backend: BackendId::new(backend).expect("backend"),
            model_family: ModelFamilyId::new("family").expect("family"),
            runtime_slug: slug(slug_value),
            catalog_version: CatalogVersion::new("cat-1").expect("catalog"),
            observation_timestamp: TimestampMillis::from_millis(1_700_000_000_000),
        }
    }

    fn mapper(backend: &str, efforts: &[CanonicalEffort]) -> StaticEffortMapper {
        let mapping = efforts
            .iter()
            .map(|effort| {
                (
                    effort.clone(),
                    NativeEffort {
                        parameter_name: "reasoning_effort".to_string(),
                        parameter_value: effort.to_string(),
                    },
                )
            })
            .collect();
        StaticEffortMapper::new(BackendId::new(backend).expect("backend"), mapping).expect("mapper")
    }

    fn template() -> ActionTemplate {
        ActionTemplate {
            role: AgentRole::Worker,
            budget: ExecutionBudget::default(),
            verifier_profile: VerifierProfileId::new("default").expect("profile"),
            requested_slug_override: None,
        }
    }

    #[test]
    fn two_models_and_three_efforts_enumerate_six_distinct_actions() {
        let models = vec![
            model("codex_cli", "openai", "model-a"),
            model("codex_cli", "openai", "model-b"),
        ];
        let efforts = vec![
            CanonicalEffort::Low,
            CanonicalEffort::Medium,
            CanonicalEffort::High,
        ];
        let mut registry = EffortMapperRegistry::new();
        registry.register(Box::new(mapper(
            "codex_cli",
            &[
                CanonicalEffort::Low,
                CanonicalEffort::Medium,
                CanonicalEffort::High,
            ],
        )));

        let actions =
            enumerate_compatible_actions(&models, &efforts, &registry, &template()).expect("enum");
        assert_eq!(actions.len(), 6);
        let mut keys: Vec<_> = actions.iter().map(ModelAction::action_key).collect();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), 6);
        assert!(actions.iter().any(|action| {
            action.runtime_model.runtime_slug.as_str() == "model-a"
                && action.effort == CanonicalEffort::Low
        }));
        assert!(actions.iter().any(|action| {
            action.runtime_model.runtime_slug.as_str() == "model-b"
                && action.effort == CanonicalEffort::High
        }));
    }

    #[test]
    fn unsupported_effort_is_omitted_not_coerced() {
        let models = vec![model("grok_build_cli", "xai", "grok-4.6")];
        let efforts = vec![CanonicalEffort::High, CanonicalEffort::XHigh];
        let mut registry = EffortMapperRegistry::new();
        registry.register(Box::new(mapper("grok_build_cli", &[CanonicalEffort::High])));

        let actions =
            enumerate_compatible_actions(&models, &efforts, &registry, &template()).expect("enum");
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].effort, CanonicalEffort::High);
        let mapper = registry
            .mapper(&BackendId::new("grok_build_cli").expect("backend"))
            .expect("mapper");
        let error = mapper
            .map_effort(&CanonicalEffort::XHigh)
            .expect_err("unsupported");
        assert!(matches!(error, OptimizerError::UnsupportedEffort { .. }));
    }

    #[test]
    fn requested_and_resolved_slugs_are_distinct_fields() {
        let resolved = model("codex_cli", "openai", "gpt-5.6-sol");
        let requested = slug("gpt-5.6-sol-alias");
        let action = ModelAction::from_model_effort(
            resolved.clone(),
            requested.clone(),
            CanonicalEffort::Medium,
            &template(),
        );
        assert_eq!(action.requested_slug, requested);
        assert_eq!(action.runtime_model.runtime_slug.as_str(), "gpt-5.6-sol");
        assert_ne!(action.requested_slug, action.runtime_model.runtime_slug);
        assert_eq!(action.runtime_model.catalog_version.as_str(), "cat-1");
        assert_eq!(
            action.runtime_model.observation_timestamp.as_millis(),
            1_700_000_000_000
        );
    }

    #[test]
    fn verifier_profile_is_append_only() {
        let mut profile = VerifierProfile::new(
            VerifierProfileId::new("v1").expect("id"),
            vec![VerificationGate::DeterministicTests],
        );
        profile.add_gate(VerificationGate::SecurityScan);
        profile.add_gate(VerificationGate::DeterministicTests);
        assert_eq!(
            profile.gates(),
            &[
                VerificationGate::DeterministicTests,
                VerificationGate::SecurityScan
            ]
        );
    }

    #[test]
    fn effort_mapper_trait_is_object_safe() {
        fn assert_object_safe(_: &dyn EffortMapper) {}
        let mapper = mapper("fake_provider", &[CanonicalEffort::Low]);
        assert_object_safe(&mapper);
    }
}
