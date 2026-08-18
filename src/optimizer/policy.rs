//! Policy graphs: directed actions with evidence-dependent transitions.
//!
//! Candidate generation (#165) and the online router (#167) consume this
//! type. They add graphs; they do not need to edit the node/edge vocabulary.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::action::{
    AgentRole, CanonicalEffort, ExecutionBudget, HedgeTopology, ModelAction, PlannerTopology,
    RestartMode, ReviewTopology, TopologySpec, WorkerTopology,
};
use super::catalog::{CapabilityCatalog, CapabilityClass, ModelCapability};
use super::certification::CertificationPlan;
use super::error::OptimizerError;
use super::ids::{
    BackendId, CatalogVersion, ModelFamilyId, PolicyId, PolicyNodeId, ProviderId, RuntimeSlug,
    TimestampMillis, VerifierProfileId,
};

pub const POLICY_LIBRARY_VERSION: u32 = 1;
pub const COLD_START_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyGraph {
    pub policy_id: PolicyId,
    pub version: u32,
    pub start_node: PolicyNodeId,
    pub nodes: BTreeMap<PolicyNodeId, PolicyNode>,
    pub edges: Vec<PolicyEdge>,
    pub topology: TopologySpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyNode {
    Probe(ModelAction),
    Plan(ModelAction),
    Execute(ModelAction),
    Repair(ModelAction),
    Audit(ModelAction),
    Certify(CertificationPlan),
    Stop,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEdge {
    pub from: PolicyNodeId,
    pub to: PolicyNodeId,
    pub condition: TransitionCondition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransitionCondition {
    Always,
    CertificationPassed,
    CertificationFailed,
    ProgressAboveThreshold,
    NoProgress,
    LocalizedFailure,
    StructuralFailure,
    QuotaPressure,
    TimeoutRisk,
    HumanEscalationRequired,
}

/// Evidence observed at a decision point. Later classifiers (#164) fill this
/// without changing the condition vocabulary.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionEvidence {
    pub certification_passed: Option<bool>,
    pub progress_above_threshold: bool,
    pub no_progress: bool,
    pub localized_failure: bool,
    pub structural_failure: bool,
    pub quota_pressure: bool,
    pub timeout_risk: bool,
    pub human_escalation_required: bool,
}

impl TransitionCondition {
    pub fn matches(&self, evidence: &TransitionEvidence) -> bool {
        match self {
            Self::Always => true,
            Self::CertificationPassed => evidence.certification_passed == Some(true),
            Self::CertificationFailed => evidence.certification_passed == Some(false),
            Self::ProgressAboveThreshold => evidence.progress_above_threshold,
            Self::NoProgress => evidence.no_progress,
            Self::LocalizedFailure => evidence.localized_failure,
            Self::StructuralFailure => evidence.structural_failure,
            Self::QuotaPressure => evidence.quota_pressure,
            Self::TimeoutRisk => evidence.timeout_risk,
            Self::HumanEscalationRequired => evidence.human_escalation_required,
        }
    }
}

impl PolicyGraph {
    pub fn new(
        policy_id: PolicyId,
        version: u32,
        start_node: PolicyNodeId,
        topology: TopologySpec,
    ) -> Self {
        Self {
            policy_id,
            version,
            start_node,
            nodes: BTreeMap::new(),
            edges: Vec::new(),
            topology,
        }
    }

    pub fn insert_node(
        &mut self,
        id: PolicyNodeId,
        node: PolicyNode,
    ) -> Result<(), OptimizerError> {
        if self.nodes.contains_key(&id) {
            return Err(OptimizerError::DuplicatePolicyNode(id.to_string()));
        }
        self.nodes.insert(id, node);
        Ok(())
    }

    pub fn add_edge(&mut self, edge: PolicyEdge) -> Result<(), OptimizerError> {
        if !self.nodes.contains_key(&edge.from) {
            return Err(OptimizerError::UnknownEdgeEndpoint(edge.from.to_string()));
        }
        if !self.nodes.contains_key(&edge.to) {
            return Err(OptimizerError::UnknownEdgeEndpoint(edge.to.to_string()));
        }
        self.edges.push(edge);
        Ok(())
    }

    pub fn validate(&self) -> Result<(), OptimizerError> {
        if !self.nodes.contains_key(&self.start_node) {
            return Err(OptimizerError::MissingStartNode(
                self.start_node.to_string(),
            ));
        }
        for edge in &self.edges {
            if !self.nodes.contains_key(&edge.from) {
                return Err(OptimizerError::UnknownEdgeEndpoint(edge.from.to_string()));
            }
            if !self.nodes.contains_key(&edge.to) {
                return Err(OptimizerError::UnknownEdgeEndpoint(edge.to.to_string()));
            }
        }
        Ok(())
    }

    pub fn matching_edges(
        &self,
        from: &PolicyNodeId,
        evidence: &TransitionEvidence,
    ) -> Result<Vec<&PolicyEdge>, OptimizerError> {
        if !self.nodes.contains_key(from) {
            return Err(OptimizerError::MissingPolicyNode(from.to_string()));
        }
        Ok(self
            .edges
            .iter()
            .filter(|edge| &edge.from == from && edge.condition.matches(evidence))
            .collect())
    }

    pub fn next_nodes(
        &self,
        from: &PolicyNodeId,
        evidence: &TransitionEvidence,
    ) -> Result<Vec<PolicyNodeId>, OptimizerError> {
        Ok(self
            .matching_edges(from, evidence)?
            .into_iter()
            .map(|edge| edge.to.clone())
            .collect())
    }

    /// First matching successor in edge-list order. Deterministic.
    pub fn take_transition(
        &self,
        from: &PolicyNodeId,
        evidence: &TransitionEvidence,
    ) -> Result<PolicyNodeId, OptimizerError> {
        self.matching_edges(from, evidence)?
            .first()
            .map(|edge| edge.to.clone())
            .ok_or_else(|| OptimizerError::NoMatchingTransition(from.to_string()))
    }
}

/// Policy grammar templates. Instantiated across compatible catalog evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyGrammar {
    Direct,
    PlanThenExecute,
    ProbeThenContinue,
    ProbeThenSwitch,
    ProbeThenCleanRestart,
    ParallelWorkers,
    DelayedHedge,
    ExecuteThenRepair,
    ExecuteThenAuditThenRepair,
}

impl PolicyGrammar {
    pub const ALL: [Self; 9] = [
        Self::Direct,
        Self::PlanThenExecute,
        Self::ProbeThenContinue,
        Self::ProbeThenSwitch,
        Self::ProbeThenCleanRestart,
        Self::ParallelWorkers,
        Self::DelayedHedge,
        Self::ExecuteThenRepair,
        Self::ExecuteThenAuditThenRepair,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::PlanThenExecute => "plan-then-execute",
            Self::ProbeThenContinue => "probe-then-continue",
            Self::ProbeThenSwitch => "probe-then-switch",
            Self::ProbeThenCleanRestart => "probe-then-clean-restart",
            Self::ParallelWorkers => "parallel-workers",
            Self::DelayedHedge => "delayed-hedge",
            Self::ExecuteThenRepair => "execute-then-repair",
            Self::ExecuteThenAuditThenRepair => "execute-then-audit-then-repair",
        }
    }
}

impl fmt::Display for PolicyGrammar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Cold-start operational prior. Configurable data, not a hardcoded hierarchy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColdStartDefaults {
    pub schema_version: u32,
    pub planner_class: CapabilityClass,
    pub worker_class: CapabilityClass,
    pub repair_class: CapabilityClass,
    pub restart_class: CapabilityClass,
    pub verifier_profile: VerifierProfileId,
}

impl ColdStartDefaults {
    pub fn shipped() -> Self {
        Self {
            schema_version: COLD_START_SCHEMA_VERSION,
            planner_class: CapabilityClass::Frontier,
            worker_class: CapabilityClass::Worker,
            repair_class: CapabilityClass::Precision,
            restart_class: CapabilityClass::Frontier,
            verifier_profile: VerifierProfileId::new("deterministic-plus-independent-audit")
                .expect("verifier profile"),
        }
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, OptimizerError> {
        let defaults: Self = serde_json::from_slice(bytes).map_err(|error| {
            OptimizerError::invalid(format!("cold-start defaults JSON: {error}"))
        })?;
        if defaults.schema_version != COLD_START_SCHEMA_VERSION {
            return Err(OptimizerError::invalid(format!(
                "unsupported cold-start schema version {}",
                defaults.schema_version
            )));
        }
        Ok(defaults)
    }
}

/// Static compatibility context applied before any prediction.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskCompatibility {
    pub offline: bool,
    pub restricted_workspace: bool,
    pub sequential_inseparable: bool,
    #[serde(default)]
    pub required_tool_capabilities: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityFilter {
    UnsupportedEffort,
    MissingToolCapability,
    NetworkDependentOffline,
    UntrustedRestricted,
    ParallelInseparable,
}

impl CompatibilityFilter {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedEffort => "unsupported_effort",
            Self::MissingToolCapability => "missing_tool_capability",
            Self::NetworkDependentOffline => "network_dependent_offline",
            Self::UntrustedRestricted => "untrusted_restricted",
            Self::ParallelInseparable => "parallel_inseparable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterRejection {
    pub filter: CompatibilityFilter,
    pub detail: String,
}

pub fn check_model_compatibility(
    model: &ModelCapability,
    effort: &CanonicalEffort,
    context: &TaskCompatibility,
) -> Result<(), FilterRejection> {
    if !model.supports_effort(effort) {
        return Err(FilterRejection {
            filter: CompatibilityFilter::UnsupportedEffort,
            detail: format!(
                "{} does not support effort {effort}",
                model.identity.runtime_slug
            ),
        });
    }
    if !model.has_tools(&context.required_tool_capabilities) {
        return Err(FilterRejection {
            filter: CompatibilityFilter::MissingToolCapability,
            detail: format!(
                "{} lacks required tool capabilities",
                model.identity.runtime_slug
            ),
        });
    }
    if context.offline && model.network_dependent {
        return Err(FilterRejection {
            filter: CompatibilityFilter::NetworkDependentOffline,
            detail: format!(
                "{} is network-dependent and the task is offline",
                model.identity.runtime_slug
            ),
        });
    }
    if context.restricted_workspace && !model.trusted {
        return Err(FilterRejection {
            filter: CompatibilityFilter::UntrustedRestricted,
            detail: format!(
                "{} is untrusted in a restricted workspace",
                model.identity.runtime_slug
            ),
        });
    }
    Ok(())
}

pub fn check_grammar_compatibility(
    grammar: PolicyGrammar,
    context: &TaskCompatibility,
) -> Result<(), FilterRejection> {
    if context.sequential_inseparable && grammar == PolicyGrammar::ParallelWorkers {
        return Err(FilterRejection {
            filter: CompatibilityFilter::ParallelInseparable,
            detail: "parallel workers are incompatible with an inseparable sequential task"
                .to_string(),
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationBudget {
    pub max_candidates: usize,
}

impl Default for GenerationBudget {
    fn default() -> Self {
        Self { max_candidates: 32 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PruneReason {
    Filter {
        filter: CompatibilityFilter,
        detail: String,
    },
    BudgetTruncation {
        rank: usize,
        budget: usize,
    },
}

impl fmt::Display for PruneReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Filter { filter, detail } => write!(f, "{}:{detail}", filter.as_str()),
            Self::BudgetTruncation { rank, budget } => {
                write!(f, "budget_truncation:rank={rank}:budget={budget}")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrunedCandidate {
    pub policy_id: PolicyId,
    pub reason: PruneReason,
}

/// Bounded generation result. The budget and what was pruned are recorded
/// so a decision explanation can cite them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationReport {
    pub library_version: u32,
    pub candidates: Vec<PolicyGraph>,
    pub pruned: Vec<PrunedCandidate>,
    pub truncated: bool,
    pub budget: GenerationBudget,
}

impl GenerationReport {
    pub fn explanation_notes(&self) -> Vec<String> {
        let mut notes = vec![
            format!("policy_library_version:{}", self.library_version),
            format!("candidates:{}", self.candidates.len()),
            format!("pruned:{}", self.pruned.len()),
            format!("truncated:{}", self.truncated),
            format!("candidate_budget:{}", self.budget.max_candidates),
        ];
        for pruned in &self.pruned {
            notes.push(format!("pruned:{}:{}", pruned.policy_id, pruned.reason));
        }
        notes
    }
}

/// Hand-defined starter library. Names are capability-class routes, not vendors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyLibrary {
    pub version: u32,
    pub entries: BTreeMap<String, PolicyGraph>,
}

impl PolicyLibrary {
    pub fn starter() -> Result<Self, OptimizerError> {
        let defaults = ColdStartDefaults::shipped();
        let mut entries = BTreeMap::new();
        insert_library_graph(
            &mut entries,
            starter_direct("frontier-direct", CapabilityClass::Frontier, &defaults)?,
        );
        insert_library_graph(
            &mut entries,
            starter_direct("precision-direct", CapabilityClass::Precision, &defaults)?,
        );
        insert_library_graph(
            &mut entries,
            starter_direct("worker-direct", CapabilityClass::Worker, &defaults)?,
        );
        insert_library_graph(
            &mut entries,
            build_plan_then_execute(
                policy_id("frontier-plan-worker-execute")?,
                class_action(CapabilityClass::Frontier, AgentRole::Planner, &defaults),
                class_action(CapabilityClass::Worker, AgentRole::Worker, &defaults),
                sequential_topology(RestartMode::Continuation),
            )?,
        );
        insert_library_graph(
            &mut entries,
            build_probe_then_continue(
                policy_id("worker-probe-worker-continue")?,
                class_action(CapabilityClass::Worker, AgentRole::Worker, &defaults),
                class_action(CapabilityClass::Worker, AgentRole::Worker, &defaults),
                sequential_topology(RestartMode::Continuation),
            )?,
        );
        insert_library_graph(
            &mut entries,
            build_probe_then_switch(
                policy_id("worker-probe-precision-repair")?,
                class_action(CapabilityClass::Worker, AgentRole::Worker, &defaults),
                class_action(CapabilityClass::Precision, AgentRole::Repairer, &defaults),
                sequential_topology(RestartMode::Continuation),
            )?,
        );
        insert_library_graph(
            &mut entries,
            build_probe_then_clean_restart(
                policy_id("worker-probe-frontier-clean-restart")?,
                class_action(CapabilityClass::Worker, AgentRole::Worker, &defaults),
                class_action(CapabilityClass::Frontier, AgentRole::Planner, &defaults),
                sequential_topology(RestartMode::CleanRestart),
            )?,
        );
        insert_library_graph(
            &mut entries,
            build_parallel_workers(
                policy_id("frontier-plan-parallel-workers-precision-repair-frontier-audit")?,
                class_action(CapabilityClass::Frontier, AgentRole::Planner, &defaults),
                class_action(CapabilityClass::Worker, AgentRole::Worker, &defaults),
                class_action(CapabilityClass::Precision, AgentRole::Repairer, &defaults),
                class_action(CapabilityClass::Frontier, AgentRole::Auditor, &defaults),
                parallel_topology(),
            )?,
        );
        insert_library_graph(
            &mut entries,
            build_delayed_hedge(
                policy_id("worker-delayed-precision-hedge")?,
                class_action(CapabilityClass::Worker, AgentRole::Worker, &defaults),
                class_action(CapabilityClass::Precision, AgentRole::Repairer, &defaults),
                delayed_hedge_topology(),
            )?,
        );
        Ok(Self {
            version: POLICY_LIBRARY_VERSION,
            entries,
        })
    }

    pub fn get(&self, id: &PolicyId) -> Option<&PolicyGraph> {
        self.entries.get(id.as_str())
    }

    pub fn graphs(&self) -> impl Iterator<Item = &PolicyGraph> {
        self.entries.values()
    }

    pub fn to_json(&self) -> Result<String, OptimizerError> {
        serde_json::to_string_pretty(self)
            .map_err(|error| OptimizerError::invalid(format!("serialize policy library: {error}")))
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, OptimizerError> {
        serde_json::from_slice(bytes)
            .map_err(|error| OptimizerError::invalid(format!("parse policy library: {error}")))
    }
}

fn insert_library_graph(entries: &mut BTreeMap<String, PolicyGraph>, graph: PolicyGraph) {
    entries.insert(graph.policy_id.as_str().to_string(), graph);
}

fn policy_id(value: &str) -> Result<PolicyId, OptimizerError> {
    PolicyId::new(value)
}

fn starter_direct(
    id: &str,
    class: CapabilityClass,
    defaults: &ColdStartDefaults,
) -> Result<PolicyGraph, OptimizerError> {
    build_direct(
        policy_id(id)?,
        class_action(class, AgentRole::Worker, defaults),
        sequential_topology(RestartMode::Continuation),
    )
}

/// Bounded candidate generator over the policy grammar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateGenerator {
    pub budget: GenerationBudget,
    pub cold_start: ColdStartDefaults,
    pub efforts: Vec<CanonicalEffort>,
    pub grammars: Vec<PolicyGrammar>,
}

impl CandidateGenerator {
    pub fn new(budget: GenerationBudget, cold_start: ColdStartDefaults) -> Self {
        Self {
            budget,
            cold_start,
            efforts: vec![
                CanonicalEffort::Low,
                CanonicalEffort::Medium,
                CanonicalEffort::High,
            ],
            grammars: PolicyGrammar::ALL.to_vec(),
        }
    }

    pub fn generate(
        &self,
        catalog: &CapabilityCatalog,
        context: &TaskCompatibility,
    ) -> Result<GenerationReport, OptimizerError> {
        let mut produced = Vec::new();
        let mut pruned = Vec::new();
        for grammar in &self.grammars {
            match check_grammar_compatibility(*grammar, context) {
                Ok(()) => {
                    produced.extend(instantiate_grammar(
                        *grammar,
                        catalog,
                        &self.efforts,
                        context,
                        &self.cold_start,
                        &mut pruned,
                    )?);
                }
                Err(rejection) => {
                    pruned.push(PrunedCandidate {
                        policy_id: policy_id(grammar.as_str())?,
                        reason: PruneReason::Filter {
                            filter: rejection.filter,
                            detail: rejection.detail,
                        },
                    });
                }
            }
        }
        produced.sort_by(|left, right| left.policy_id.as_str().cmp(right.policy_id.as_str()));
        let mut candidates = Vec::new();
        let mut truncated = false;
        for (rank, graph) in produced.into_iter().enumerate() {
            if candidates.len() < self.budget.max_candidates {
                candidates.push(graph);
            } else {
                truncated = true;
                pruned.push(PrunedCandidate {
                    policy_id: graph.policy_id,
                    reason: PruneReason::BudgetTruncation {
                        rank,
                        budget: self.budget.max_candidates,
                    },
                });
            }
        }
        Ok(GenerationReport {
            library_version: POLICY_LIBRARY_VERSION,
            candidates,
            pruned,
            truncated,
            budget: self.budget,
        })
    }
}

/// Instantiate one grammar across compatible model×effort bindings.
pub fn instantiate_grammar(
    grammar: PolicyGrammar,
    catalog: &CapabilityCatalog,
    efforts: &[CanonicalEffort],
    context: &TaskCompatibility,
    defaults: &ColdStartDefaults,
    pruned: &mut Vec<PrunedCandidate>,
) -> Result<Vec<PolicyGraph>, OptimizerError> {
    match grammar {
        PolicyGrammar::Direct => instantiate_direct(catalog, efforts, context, defaults, pruned),
        PolicyGrammar::PlanThenExecute => instantiate_two_slot(
            grammar,
            defaults.planner_class,
            AgentRole::Planner,
            defaults.worker_class,
            AgentRole::Worker,
            catalog,
            efforts,
            context,
            defaults,
            pruned,
            |id, first, second| {
                build_plan_then_execute(
                    id,
                    first,
                    second,
                    sequential_topology(RestartMode::Continuation),
                )
            },
        ),
        PolicyGrammar::ProbeThenContinue => instantiate_two_slot(
            grammar,
            defaults.worker_class,
            AgentRole::Worker,
            defaults.worker_class,
            AgentRole::Worker,
            catalog,
            efforts,
            context,
            defaults,
            pruned,
            |id, first, second| {
                build_probe_then_continue(
                    id,
                    first,
                    second,
                    sequential_topology(RestartMode::Continuation),
                )
            },
        ),
        PolicyGrammar::ProbeThenSwitch => instantiate_two_slot(
            grammar,
            defaults.worker_class,
            AgentRole::Worker,
            defaults.repair_class,
            AgentRole::Repairer,
            catalog,
            efforts,
            context,
            defaults,
            pruned,
            |id, first, second| {
                build_probe_then_switch(
                    id,
                    first,
                    second,
                    sequential_topology(RestartMode::Continuation),
                )
            },
        ),
        PolicyGrammar::ProbeThenCleanRestart => instantiate_two_slot(
            grammar,
            defaults.worker_class,
            AgentRole::Worker,
            defaults.restart_class,
            AgentRole::Planner,
            catalog,
            efforts,
            context,
            defaults,
            pruned,
            |id, first, second| {
                build_probe_then_clean_restart(
                    id,
                    first,
                    second,
                    sequential_topology(RestartMode::CleanRestart),
                )
            },
        ),
        PolicyGrammar::ParallelWorkers => {
            instantiate_parallel(catalog, efforts, context, defaults, pruned)
        }
        PolicyGrammar::DelayedHedge => instantiate_two_slot(
            grammar,
            defaults.worker_class,
            AgentRole::Worker,
            defaults.repair_class,
            AgentRole::Repairer,
            catalog,
            efforts,
            context,
            defaults,
            pruned,
            |id, first, second| build_delayed_hedge(id, first, second, delayed_hedge_topology()),
        ),
        PolicyGrammar::ExecuteThenRepair => instantiate_two_slot(
            grammar,
            defaults.worker_class,
            AgentRole::Worker,
            defaults.repair_class,
            AgentRole::Repairer,
            catalog,
            efforts,
            context,
            defaults,
            pruned,
            |id, first, second| {
                build_execute_then_repair(
                    id,
                    first,
                    second,
                    sequential_topology(RestartMode::Continuation),
                )
            },
        ),
        PolicyGrammar::ExecuteThenAuditThenRepair => instantiate_three_slot(
            grammar,
            defaults.worker_class,
            AgentRole::Worker,
            defaults.planner_class,
            AgentRole::Auditor,
            defaults.repair_class,
            AgentRole::Repairer,
            catalog,
            efforts,
            context,
            defaults,
            pruned,
        ),
    }
}

fn instantiate_direct(
    catalog: &CapabilityCatalog,
    efforts: &[CanonicalEffort],
    context: &TaskCompatibility,
    defaults: &ColdStartDefaults,
    pruned: &mut Vec<PrunedCandidate>,
) -> Result<Vec<PolicyGraph>, OptimizerError> {
    let mut graphs = Vec::new();
    for (model, effort) in compatible_pairs(catalog, None, efforts, context, pruned)? {
        let id = instance_id(
            PolicyGrammar::Direct,
            &[binding_label(&model.identity, &effort)],
        )?;
        let action = bind_action(
            &class_action(model.capability_class, AgentRole::Worker, defaults),
            model,
            effort.clone(),
        );
        graphs.push(build_direct(
            id,
            action,
            sequential_topology(RestartMode::Continuation),
        )?);
    }
    Ok(graphs)
}

#[allow(clippy::too_many_arguments)]
fn instantiate_two_slot<F>(
    grammar: PolicyGrammar,
    first_class: CapabilityClass,
    first_role: AgentRole,
    second_class: CapabilityClass,
    second_role: AgentRole,
    catalog: &CapabilityCatalog,
    efforts: &[CanonicalEffort],
    context: &TaskCompatibility,
    defaults: &ColdStartDefaults,
    pruned: &mut Vec<PrunedCandidate>,
    build: F,
) -> Result<Vec<PolicyGraph>, OptimizerError>
where
    F: Fn(PolicyId, ModelAction, ModelAction) -> Result<PolicyGraph, OptimizerError>,
{
    let first_pairs = compatible_pairs(catalog, Some(first_class), efforts, context, pruned)?;
    let second_pairs = compatible_pairs(catalog, Some(second_class), efforts, context, pruned)?;
    let mut graphs = Vec::new();
    for (first_model, first_effort) in &first_pairs {
        for (second_model, second_effort) in &second_pairs {
            let id = instance_id(
                grammar,
                &[
                    binding_label(&first_model.identity, first_effort),
                    binding_label(&second_model.identity, second_effort),
                ],
            )?;
            graphs.push(build(
                id,
                bind_action(
                    &class_action(first_class, first_role.clone(), defaults),
                    first_model,
                    first_effort.clone(),
                ),
                bind_action(
                    &class_action(second_class, second_role.clone(), defaults),
                    second_model,
                    second_effort.clone(),
                ),
            )?);
        }
    }
    Ok(graphs)
}

fn instantiate_parallel(
    catalog: &CapabilityCatalog,
    efforts: &[CanonicalEffort],
    context: &TaskCompatibility,
    defaults: &ColdStartDefaults,
    pruned: &mut Vec<PrunedCandidate>,
) -> Result<Vec<PolicyGraph>, OptimizerError> {
    let planners = compatible_pairs(
        catalog,
        Some(defaults.planner_class),
        efforts,
        context,
        pruned,
    )?;
    let workers = compatible_pairs(
        catalog,
        Some(defaults.worker_class),
        efforts,
        context,
        pruned,
    )?;
    let repairs = compatible_pairs(
        catalog,
        Some(defaults.repair_class),
        efforts,
        context,
        pruned,
    )?;
    let mut graphs = Vec::new();
    for (planner, planner_effort) in &planners {
        for (worker, worker_effort) in &workers {
            for (repair, repair_effort) in &repairs {
                let id = instance_id(
                    PolicyGrammar::ParallelWorkers,
                    &[
                        binding_label(&planner.identity, planner_effort),
                        binding_label(&worker.identity, worker_effort),
                        binding_label(&repair.identity, repair_effort),
                    ],
                )?;
                graphs.push(build_parallel_workers(
                    id,
                    bind_action(
                        &class_action(defaults.planner_class, AgentRole::Planner, defaults),
                        planner,
                        planner_effort.clone(),
                    ),
                    bind_action(
                        &class_action(defaults.worker_class, AgentRole::Worker, defaults),
                        worker,
                        worker_effort.clone(),
                    ),
                    bind_action(
                        &class_action(defaults.repair_class, AgentRole::Repairer, defaults),
                        repair,
                        repair_effort.clone(),
                    ),
                    bind_action(
                        &class_action(defaults.planner_class, AgentRole::Auditor, defaults),
                        planner,
                        planner_effort.clone(),
                    ),
                    parallel_topology(),
                )?);
            }
        }
    }
    Ok(graphs)
}

#[allow(clippy::too_many_arguments)]
fn instantiate_three_slot(
    grammar: PolicyGrammar,
    first_class: CapabilityClass,
    first_role: AgentRole,
    second_class: CapabilityClass,
    second_role: AgentRole,
    third_class: CapabilityClass,
    third_role: AgentRole,
    catalog: &CapabilityCatalog,
    efforts: &[CanonicalEffort],
    context: &TaskCompatibility,
    defaults: &ColdStartDefaults,
    pruned: &mut Vec<PrunedCandidate>,
) -> Result<Vec<PolicyGraph>, OptimizerError> {
    let first = compatible_pairs(catalog, Some(first_class), efforts, context, pruned)?;
    let second = compatible_pairs(catalog, Some(second_class), efforts, context, pruned)?;
    let third = compatible_pairs(catalog, Some(third_class), efforts, context, pruned)?;
    let mut graphs = Vec::new();
    for (a, ae) in &first {
        for (b, be) in &second {
            for (c, ce) in &third {
                let id = instance_id(
                    grammar,
                    &[
                        binding_label(&a.identity, ae),
                        binding_label(&b.identity, be),
                        binding_label(&c.identity, ce),
                    ],
                )?;
                graphs.push(build_execute_then_audit_then_repair(
                    id,
                    bind_action(
                        &class_action(first_class, first_role.clone(), defaults),
                        a,
                        ae.clone(),
                    ),
                    bind_action(
                        &class_action(second_class, second_role.clone(), defaults),
                        b,
                        be.clone(),
                    ),
                    bind_action(
                        &class_action(third_class, third_role.clone(), defaults),
                        c,
                        ce.clone(),
                    ),
                    sequential_topology(RestartMode::Continuation),
                )?);
            }
        }
    }
    Ok(graphs)
}

fn compatible_pairs<'a>(
    catalog: &'a CapabilityCatalog,
    class: Option<CapabilityClass>,
    efforts: &[CanonicalEffort],
    context: &TaskCompatibility,
    pruned: &mut Vec<PrunedCandidate>,
) -> Result<Vec<(&'a ModelCapability, CanonicalEffort)>, OptimizerError> {
    let mut pairs = Vec::new();
    let mut models: Vec<&ModelCapability> = match class {
        Some(class) => catalog.class_members(class).collect(),
        None => catalog.models.iter().collect(),
    };
    models.sort_by_key(|model| model.identity.runtime_slug.as_str().to_string());
    for model in models {
        for effort in efforts {
            match check_model_compatibility(model, effort, context) {
                Ok(()) => pairs.push((model, effort.clone())),
                Err(rejection) => {
                    let id = PolicyId::new(format!(
                        "rejected:{}@{}",
                        model.identity.runtime_slug, effort
                    ))
                    .unwrap_or_else(|_| PolicyId::new("rejected").expect("rejected policy id"));
                    pruned.push(PrunedCandidate {
                        policy_id: id,
                        reason: PruneReason::Filter {
                            filter: rejection.filter,
                            detail: rejection.detail,
                        },
                    });
                }
            }
        }
    }
    Ok(pairs)
}

fn instance_id(grammar: PolicyGrammar, bindings: &[String]) -> Result<PolicyId, OptimizerError> {
    PolicyId::new(format!("{}:{}", grammar.as_str(), bindings.join("+")))
}

fn binding_label(identity: &super::action::RuntimeModelId, effort: &CanonicalEffort) -> String {
    format!("{}@{effort}", identity.runtime_slug)
}

fn class_action(
    class: CapabilityClass,
    role: AgentRole,
    defaults: &ColdStartDefaults,
) -> ModelAction {
    let identity = unbound_identity(class);
    ModelAction {
        backend_id: identity.backend.clone(),
        provider_id: identity.provider.clone(),
        requested_slug: identity.runtime_slug.clone(),
        runtime_model: identity,
        effort: CanonicalEffort::Medium,
        role,
        max_turns: ExecutionBudget::default().max_turns,
        timeout_seconds: ExecutionBudget::default().timeout_seconds,
        tool_budget: None,
        output_token_budget: None,
        concurrency: 1,
        verifier_profile: defaults.verifier_profile.clone(),
    }
}

fn unbound_identity(class: CapabilityClass) -> super::action::RuntimeModelId {
    super::action::RuntimeModelId {
        provider: ProviderId::new("unbound").expect("provider"),
        backend: BackendId::new("unbound").expect("backend"),
        model_family: ModelFamilyId::new(class.as_str()).expect("family"),
        runtime_slug: RuntimeSlug::new(class.as_str()).expect("slug"),
        catalog_version: CatalogVersion::new("library-v1").expect("catalog"),
        observation_timestamp: TimestampMillis::from_millis(0),
    }
}

fn bind_action(
    template: &ModelAction,
    model: &ModelCapability,
    effort: CanonicalEffort,
) -> ModelAction {
    let mut action = template.clone();
    action.backend_id = model.identity.backend.clone();
    action.provider_id = model.identity.provider.clone();
    action.runtime_model = model.identity.clone();
    action.requested_slug = model.identity.runtime_slug.clone();
    action.effort = effort;
    action
}

fn sequential_topology(restart: RestartMode) -> TopologySpec {
    TopologySpec {
        planner: PlannerTopology::Single,
        workers: WorkerTopology::One,
        hedge: HedgeTopology::None,
        review: ReviewTopology::Independent,
        restart,
    }
}

fn parallel_topology() -> TopologySpec {
    TopologySpec {
        planner: PlannerTopology::Single,
        workers: WorkerTopology::Parallel { count: 2 },
        hedge: HedgeTopology::None,
        review: ReviewTopology::Independent,
        restart: RestartMode::Continuation,
    }
}

fn delayed_hedge_topology() -> TopologySpec {
    TopologySpec {
        planner: PlannerTopology::None,
        workers: WorkerTopology::One,
        hedge: HedgeTopology::Delayed { delay_seconds: 30 },
        review: ReviewTopology::Independent,
        restart: RestartMode::Continuation,
    }
}

fn node_id(name: &str) -> Result<PolicyNodeId, OptimizerError> {
    PolicyNodeId::new(name)
}

fn insert_stop(graph: &mut PolicyGraph) -> Result<PolicyNodeId, OptimizerError> {
    let stop = node_id("stop")?;
    graph.insert_node(stop.clone(), PolicyNode::Stop)?;
    Ok(stop)
}

fn add_edge(
    graph: &mut PolicyGraph,
    from: &PolicyNodeId,
    to: PolicyNodeId,
    condition: TransitionCondition,
) -> Result<(), OptimizerError> {
    graph.add_edge(PolicyEdge {
        from: from.clone(),
        to,
        condition,
    })
}

fn build_direct(
    policy_id: PolicyId,
    action: ModelAction,
    topology: TopologySpec,
) -> Result<PolicyGraph, OptimizerError> {
    let start = node_id("execute")?;
    let mut graph = PolicyGraph::new(policy_id, POLICY_LIBRARY_VERSION, start.clone(), topology);
    graph.insert_node(start.clone(), PolicyNode::Execute(action))?;
    let stop = insert_stop(&mut graph)?;
    add_edge(&mut graph, &start, stop, TransitionCondition::Always)?;
    graph.validate()?;
    Ok(graph)
}

fn build_plan_then_execute(
    policy_id: PolicyId,
    planner: ModelAction,
    worker: ModelAction,
    topology: TopologySpec,
) -> Result<PolicyGraph, OptimizerError> {
    let plan = node_id("plan")?;
    let execute = node_id("execute")?;
    let mut graph = PolicyGraph::new(policy_id, POLICY_LIBRARY_VERSION, plan.clone(), topology);
    graph.insert_node(plan.clone(), PolicyNode::Plan(planner))?;
    graph.insert_node(execute.clone(), PolicyNode::Execute(worker))?;
    let stop = insert_stop(&mut graph)?;
    add_edge(
        &mut graph,
        &plan,
        execute.clone(),
        TransitionCondition::Always,
    )?;
    add_edge(&mut graph, &execute, stop, TransitionCondition::Always)?;
    graph.validate()?;
    Ok(graph)
}

fn build_probe_then_continue(
    policy_id: PolicyId,
    probe: ModelAction,
    cont: ModelAction,
    topology: TopologySpec,
) -> Result<PolicyGraph, OptimizerError> {
    let start = node_id("probe")?;
    let cont_id = node_id("continue")?;
    let mut graph = PolicyGraph::new(policy_id, POLICY_LIBRARY_VERSION, start.clone(), topology);
    graph.insert_node(start.clone(), PolicyNode::Probe(probe))?;
    graph.insert_node(cont_id.clone(), PolicyNode::Execute(cont))?;
    let stop = insert_stop(&mut graph)?;
    add_edge(
        &mut graph,
        &start,
        cont_id.clone(),
        TransitionCondition::ProgressAboveThreshold,
    )?;
    add_edge(&mut graph, &start, cont_id, TransitionCondition::NoProgress)?;
    add_edge(
        &mut graph,
        &node_id("continue")?,
        stop,
        TransitionCondition::Always,
    )?;
    graph.validate()?;
    Ok(graph)
}

fn build_probe_then_switch(
    policy_id: PolicyId,
    probe: ModelAction,
    repair: ModelAction,
    topology: TopologySpec,
) -> Result<PolicyGraph, OptimizerError> {
    let start = node_id("probe")?;
    let repair_id = node_id("repair")?;
    let mut graph = PolicyGraph::new(policy_id, POLICY_LIBRARY_VERSION, start.clone(), topology);
    graph.insert_node(start.clone(), PolicyNode::Probe(probe))?;
    graph.insert_node(repair_id.clone(), PolicyNode::Repair(repair))?;
    let stop = insert_stop(&mut graph)?;
    add_edge(
        &mut graph,
        &start,
        repair_id,
        TransitionCondition::LocalizedFailure,
    )?;
    add_edge(
        &mut graph,
        &start,
        stop.clone(),
        TransitionCondition::ProgressAboveThreshold,
    )?;
    add_edge(
        &mut graph,
        &node_id("repair")?,
        stop,
        TransitionCondition::Always,
    )?;
    graph.validate()?;
    Ok(graph)
}

fn build_probe_then_clean_restart(
    policy_id: PolicyId,
    probe: ModelAction,
    restart: ModelAction,
    topology: TopologySpec,
) -> Result<PolicyGraph, OptimizerError> {
    let start = node_id("probe")?;
    let restart_id = node_id("restart")?;
    let mut graph = PolicyGraph::new(policy_id, POLICY_LIBRARY_VERSION, start.clone(), topology);
    graph.insert_node(start.clone(), PolicyNode::Probe(probe))?;
    graph.insert_node(restart_id.clone(), PolicyNode::Plan(restart))?;
    let stop = insert_stop(&mut graph)?;
    add_edge(
        &mut graph,
        &start,
        restart_id,
        TransitionCondition::StructuralFailure,
    )?;
    add_edge(
        &mut graph,
        &node_id("restart")?,
        stop,
        TransitionCondition::Always,
    )?;
    graph.validate()?;
    Ok(graph)
}

fn build_parallel_workers(
    policy_id: PolicyId,
    planner: ModelAction,
    worker: ModelAction,
    repair: ModelAction,
    auditor: ModelAction,
    topology: TopologySpec,
) -> Result<PolicyGraph, OptimizerError> {
    let plan = node_id("plan")?;
    let execute = node_id("execute")?;
    let repair_id = node_id("repair")?;
    let audit = node_id("audit")?;
    let mut graph = PolicyGraph::new(policy_id, POLICY_LIBRARY_VERSION, plan.clone(), topology);
    graph.insert_node(plan.clone(), PolicyNode::Plan(planner))?;
    graph.insert_node(execute.clone(), PolicyNode::Execute(worker))?;
    graph.insert_node(repair_id.clone(), PolicyNode::Repair(repair))?;
    graph.insert_node(audit.clone(), PolicyNode::Audit(auditor))?;
    let stop = insert_stop(&mut graph)?;
    add_edge(
        &mut graph,
        &plan,
        execute.clone(),
        TransitionCondition::Always,
    )?;
    add_edge(
        &mut graph,
        &execute,
        repair_id.clone(),
        TransitionCondition::LocalizedFailure,
    )?;
    add_edge(
        &mut graph,
        &execute,
        audit.clone(),
        TransitionCondition::ProgressAboveThreshold,
    )?;
    add_edge(
        &mut graph,
        &repair_id,
        audit.clone(),
        TransitionCondition::Always,
    )?;
    add_edge(&mut graph, &audit, stop, TransitionCondition::Always)?;
    graph.validate()?;
    Ok(graph)
}

fn build_delayed_hedge(
    policy_id: PolicyId,
    worker: ModelAction,
    hedge: ModelAction,
    topology: TopologySpec,
) -> Result<PolicyGraph, OptimizerError> {
    let execute = node_id("execute")?;
    let hedge_id = node_id("hedge")?;
    let mut graph = PolicyGraph::new(policy_id, POLICY_LIBRARY_VERSION, execute.clone(), topology);
    graph.insert_node(execute.clone(), PolicyNode::Execute(worker))?;
    graph.insert_node(hedge_id.clone(), PolicyNode::Repair(hedge))?;
    let stop = insert_stop(&mut graph)?;
    add_edge(
        &mut graph,
        &execute,
        hedge_id,
        TransitionCondition::TimeoutRisk,
    )?;
    add_edge(
        &mut graph,
        &execute,
        stop.clone(),
        TransitionCondition::ProgressAboveThreshold,
    )?;
    add_edge(
        &mut graph,
        &node_id("hedge")?,
        stop,
        TransitionCondition::Always,
    )?;
    graph.validate()?;
    Ok(graph)
}

fn build_execute_then_repair(
    policy_id: PolicyId,
    worker: ModelAction,
    repair: ModelAction,
    topology: TopologySpec,
) -> Result<PolicyGraph, OptimizerError> {
    let execute = node_id("execute")?;
    let repair_id = node_id("repair")?;
    let mut graph = PolicyGraph::new(policy_id, POLICY_LIBRARY_VERSION, execute.clone(), topology);
    graph.insert_node(execute.clone(), PolicyNode::Execute(worker))?;
    graph.insert_node(repair_id.clone(), PolicyNode::Repair(repair))?;
    let stop = insert_stop(&mut graph)?;
    add_edge(
        &mut graph,
        &execute,
        repair_id,
        TransitionCondition::LocalizedFailure,
    )?;
    add_edge(
        &mut graph,
        &execute,
        stop.clone(),
        TransitionCondition::ProgressAboveThreshold,
    )?;
    add_edge(
        &mut graph,
        &node_id("repair")?,
        stop,
        TransitionCondition::Always,
    )?;
    graph.validate()?;
    Ok(graph)
}

fn build_execute_then_audit_then_repair(
    policy_id: PolicyId,
    worker: ModelAction,
    auditor: ModelAction,
    repair: ModelAction,
    topology: TopologySpec,
) -> Result<PolicyGraph, OptimizerError> {
    let execute = node_id("execute")?;
    let audit = node_id("audit")?;
    let repair_id = node_id("repair")?;
    let mut graph = PolicyGraph::new(policy_id, POLICY_LIBRARY_VERSION, execute.clone(), topology);
    graph.insert_node(execute.clone(), PolicyNode::Execute(worker))?;
    graph.insert_node(audit.clone(), PolicyNode::Audit(auditor))?;
    graph.insert_node(repair_id.clone(), PolicyNode::Repair(repair))?;
    let stop = insert_stop(&mut graph)?;
    add_edge(
        &mut graph,
        &execute,
        audit.clone(),
        TransitionCondition::Always,
    )?;
    add_edge(
        &mut graph,
        &audit,
        stop.clone(),
        TransitionCondition::CertificationPassed,
    )?;
    add_edge(
        &mut graph,
        &audit,
        repair_id,
        TransitionCondition::CertificationFailed,
    )?;
    add_edge(
        &mut graph,
        &node_id("repair")?,
        stop,
        TransitionCondition::Always,
    )?;
    graph.validate()?;
    Ok(graph)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::action::{
        AgentRole, CanonicalEffort, ExecutionBudget, HedgeTopology, ModelAction, PlannerTopology,
        RestartMode, ReviewTopology, WorkerTopology,
    };
    use crate::optimizer::catalog::ModelCapability;
    use crate::optimizer::ids::{
        BackendId, CatalogVersion, ModelFamilyId, ProviderId, RuntimeSlug, TimestampMillis,
        VerifierProfileId,
    };

    fn topology() -> TopologySpec {
        TopologySpec {
            planner: PlannerTopology::Single,
            workers: WorkerTopology::One,
            hedge: HedgeTopology::None,
            review: ReviewTopology::Independent,
            restart: RestartMode::Continuation,
        }
    }

    fn action(slug: &str) -> ModelAction {
        ModelAction {
            backend_id: BackendId::well_known(BackendId::FAKE_PROVIDER),
            provider_id: ProviderId::new("local").expect("provider"),
            runtime_model: crate::optimizer::action::RuntimeModelId {
                provider: ProviderId::new("local").expect("provider"),
                backend: BackendId::well_known(BackendId::FAKE_PROVIDER),
                model_family: ModelFamilyId::new("fake").expect("family"),
                runtime_slug: RuntimeSlug::new(slug).expect("slug"),
                catalog_version: CatalogVersion::new("v1").expect("cat"),
                observation_timestamp: TimestampMillis::from_millis(1),
            },
            requested_slug: RuntimeSlug::new(slug).expect("slug"),
            effort: CanonicalEffort::Medium,
            role: AgentRole::Worker,
            max_turns: ExecutionBudget::default().max_turns,
            timeout_seconds: 60,
            tool_budget: None,
            output_token_budget: None,
            concurrency: 1,
            verifier_profile: VerifierProfileId::new("default").expect("profile"),
        }
    }

    fn node(name: &str) -> PolicyNodeId {
        PolicyNodeId::new(name).expect("node")
    }

    fn capability(
        slug: &str,
        class: CapabilityClass,
        efforts: &[CanonicalEffort],
        tools: &[&str],
        network_dependent: bool,
        trusted: bool,
    ) -> ModelCapability {
        ModelCapability {
            identity: crate::optimizer::action::RuntimeModelId {
                provider: ProviderId::new("local").expect("provider"),
                backend: BackendId::well_known(BackendId::FAKE_PROVIDER),
                model_family: ModelFamilyId::new(class.as_str()).expect("family"),
                runtime_slug: RuntimeSlug::new(slug).expect("slug"),
                catalog_version: CatalogVersion::new("cat-1").expect("catalog"),
                observation_timestamp: TimestampMillis::from_millis(1),
            },
            supported_efforts: efforts.to_vec(),
            tool_capabilities: tools.iter().map(|tool| (*tool).to_string()).collect(),
            network_dependent,
            trusted,
            capability_class: class,
        }
    }

    fn two_model_catalog() -> CapabilityCatalog {
        let efforts = [
            CanonicalEffort::Low,
            CanonicalEffort::Medium,
            CanonicalEffort::High,
        ];
        CapabilityCatalog::from_capabilities(
            CatalogVersion::new("cat-1").expect("catalog"),
            TimestampMillis::from_millis(1),
            vec![
                capability(
                    "alpha",
                    CapabilityClass::Worker,
                    &efforts,
                    &["edit", "test"],
                    false,
                    true,
                ),
                capability(
                    "beta",
                    CapabilityClass::Frontier,
                    &efforts,
                    &["edit", "test", "web"],
                    true,
                    true,
                ),
            ],
        )
    }

    #[test]
    fn constructs_and_validates_a_probe_then_repair_graph() {
        let start = node("start");
        let mut graph = PolicyGraph::new(
            PolicyId::new("probe-repair").expect("policy"),
            1,
            start.clone(),
            topology(),
        );
        graph
            .insert_node(start.clone(), PolicyNode::Probe(action("probe")))
            .expect("start");
        graph
            .insert_node(node("repair"), PolicyNode::Repair(action("repair")))
            .expect("repair");
        graph
            .insert_node(node("stop"), PolicyNode::Stop)
            .expect("stop");
        graph
            .add_edge(PolicyEdge {
                from: start.clone(),
                to: node("repair"),
                condition: TransitionCondition::LocalizedFailure,
            })
            .expect("edge");
        graph
            .add_edge(PolicyEdge {
                from: start.clone(),
                to: node("stop"),
                condition: TransitionCondition::ProgressAboveThreshold,
            })
            .expect("edge");
        graph.validate().expect("valid");

        let evidence = TransitionEvidence {
            localized_failure: true,
            ..TransitionEvidence::default()
        };
        let next = graph.take_transition(&start, &evidence).expect("next");
        assert_eq!(next.as_str(), "repair");
    }

    #[test]
    fn structural_failure_does_not_match_localized_repair_edge() {
        let start = node("start");
        let mut graph = PolicyGraph::new(
            PolicyId::new("branch").expect("policy"),
            1,
            start.clone(),
            topology(),
        );
        graph
            .insert_node(start.clone(), PolicyNode::Execute(action("work")))
            .expect("start");
        graph
            .insert_node(node("repair"), PolicyNode::Repair(action("repair")))
            .expect("repair");
        graph
            .insert_node(node("restart"), PolicyNode::Plan(action("restart")))
            .expect("restart");
        graph
            .add_edge(PolicyEdge {
                from: start.clone(),
                to: node("repair"),
                condition: TransitionCondition::LocalizedFailure,
            })
            .expect("edge");
        graph
            .add_edge(PolicyEdge {
                from: start.clone(),
                to: node("restart"),
                condition: TransitionCondition::StructuralFailure,
            })
            .expect("edge");

        let evidence = TransitionEvidence {
            structural_failure: true,
            ..TransitionEvidence::default()
        };
        let next = graph.take_transition(&start, &evidence).expect("next");
        assert_eq!(next.as_str(), "restart");
        assert_eq!(
            graph
                .next_nodes(&start, &evidence)
                .expect("nodes")
                .iter()
                .map(PolicyNodeId::as_str)
                .collect::<Vec<_>>(),
            vec!["restart"]
        );
    }

    #[test]
    fn always_matches_regardless_of_evidence() {
        assert!(TransitionCondition::Always.matches(&TransitionEvidence::default()));
    }

    #[test]
    fn missing_start_node_fails_validation() {
        let graph = PolicyGraph::new(
            PolicyId::new("empty").expect("policy"),
            1,
            node("missing"),
            topology(),
        );
        assert!(matches!(
            graph.validate(),
            Err(OptimizerError::MissingStartNode(_))
        ));
    }

    #[test]
    fn two_models_and_three_efforts_enumerate_distinct_direct_candidates() {
        let catalog = two_model_catalog();
        let mut pruned = Vec::new();
        let graphs = instantiate_grammar(
            PolicyGrammar::Direct,
            &catalog,
            &[
                CanonicalEffort::Low,
                CanonicalEffort::Medium,
                CanonicalEffort::High,
            ],
            &TaskCompatibility::default(),
            &ColdStartDefaults::shipped(),
            &mut pruned,
        )
        .expect("instantiate");
        assert!(pruned.is_empty());
        assert_eq!(graphs.len(), 6);
        let mut keys: Vec<_> = graphs
            .iter()
            .map(|graph| graph.policy_id.as_str().to_string())
            .collect();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), 6);
        assert!(graphs.iter().any(|graph| {
            graph.policy_id.as_str() == "direct:alpha@low"
                && graph.nodes.values().any(|node| matches!(node, PolicyNode::Execute(action) if action.effort == CanonicalEffort::Low && action.runtime_model.runtime_slug.as_str() == "alpha"))
        }));
        assert!(graphs
            .iter()
            .any(|graph| graph.policy_id.as_str() == "direct:beta@high"));
    }

    #[test]
    fn each_static_filter_rejects_and_records_why() {
        let defaults = ColdStartDefaults::shipped();
        let efforts = [CanonicalEffort::Medium, CanonicalEffort::XHigh];
        let catalog = CapabilityCatalog::from_capabilities(
            CatalogVersion::new("cat-1").expect("catalog"),
            TimestampMillis::from_millis(1),
            vec![
                capability(
                    "offline-net",
                    CapabilityClass::Frontier,
                    &[CanonicalEffort::Medium],
                    &["edit"],
                    true,
                    true,
                ),
                capability(
                    "no-web",
                    CapabilityClass::Worker,
                    &[CanonicalEffort::Medium],
                    &["edit"],
                    false,
                    true,
                ),
                capability(
                    "untrusted",
                    CapabilityClass::Precision,
                    &[CanonicalEffort::Medium],
                    &["edit"],
                    false,
                    false,
                ),
            ],
        );

        let mut unsupported = Vec::new();
        instantiate_direct(
            &catalog,
            &efforts,
            &TaskCompatibility::default(),
            &defaults,
            &mut unsupported,
        )
        .expect("direct");
        assert!(unsupported.iter().any(|pruned| matches!(
            &pruned.reason,
            PruneReason::Filter {
                filter: CompatibilityFilter::UnsupportedEffort,
                ..
            }
        )));

        let mut missing_tool = Vec::new();
        let mut need_web = TaskCompatibility::default();
        need_web
            .required_tool_capabilities
            .insert("web".to_string());
        instantiate_direct(
            &catalog,
            &[CanonicalEffort::Medium],
            &need_web,
            &defaults,
            &mut missing_tool,
        )
        .expect("tools");
        assert!(missing_tool.iter().any(|pruned| matches!(
            &pruned.reason,
            PruneReason::Filter {
                filter: CompatibilityFilter::MissingToolCapability,
                ..
            }
        )));

        let mut offline = Vec::new();
        instantiate_direct(
            &catalog,
            &[CanonicalEffort::Medium],
            &TaskCompatibility {
                offline: true,
                ..TaskCompatibility::default()
            },
            &defaults,
            &mut offline,
        )
        .expect("offline");
        assert!(offline.iter().any(|pruned| matches!(
            &pruned.reason,
            PruneReason::Filter {
                filter: CompatibilityFilter::NetworkDependentOffline,
                ..
            }
        )));

        let mut restricted = Vec::new();
        instantiate_direct(
            &catalog,
            &[CanonicalEffort::Medium],
            &TaskCompatibility {
                restricted_workspace: true,
                ..TaskCompatibility::default()
            },
            &defaults,
            &mut restricted,
        )
        .expect("restricted");
        assert!(restricted.iter().any(|pruned| matches!(
            &pruned.reason,
            PruneReason::Filter {
                filter: CompatibilityFilter::UntrustedRestricted,
                ..
            }
        )));

        let mut generator =
            CandidateGenerator::new(GenerationBudget { max_candidates: 32 }, defaults);
        generator.grammars = vec![PolicyGrammar::ParallelWorkers];
        let report = generator
            .generate(
                &catalog,
                &TaskCompatibility {
                    sequential_inseparable: true,
                    ..TaskCompatibility::default()
                },
            )
            .expect("parallel");
        assert!(report.pruned.iter().any(|pruned| matches!(
            &pruned.reason,
            PruneReason::Filter {
                filter: CompatibilityFilter::ParallelInseparable,
                ..
            }
        )));
    }

    #[test]
    fn starter_library_round_trips_with_stable_ids_and_versions() {
        let library = PolicyLibrary::starter().expect("starter");
        assert_eq!(library.version, POLICY_LIBRARY_VERSION);
        assert_eq!(library.entries.len(), 9);
        for expected in [
            "frontier-direct",
            "precision-direct",
            "worker-direct",
            "frontier-plan-worker-execute",
            "worker-probe-worker-continue",
            "worker-probe-precision-repair",
            "worker-probe-frontier-clean-restart",
            "frontier-plan-parallel-workers-precision-repair-frontier-audit",
            "worker-delayed-precision-hedge",
        ] {
            let graph = library
                .get(&PolicyId::new(expected).expect("id"))
                .expect(expected);
            assert_eq!(graph.policy_id.as_str(), expected);
            assert_eq!(graph.version, POLICY_LIBRARY_VERSION);
            graph.validate().expect("valid library graph");
        }
        let json = library.to_json().expect("json");
        let restored = PolicyLibrary::from_json(json.as_bytes()).expect("restore");
        assert_eq!(restored, library);
    }

    #[test]
    fn generation_respects_candidate_budget_and_records_truncation() {
        let mut generator = CandidateGenerator::new(
            GenerationBudget { max_candidates: 3 },
            ColdStartDefaults::shipped(),
        );
        generator.grammars = vec![PolicyGrammar::Direct];
        let report = generator
            .generate(&two_model_catalog(), &TaskCompatibility::default())
            .expect("generate");
        assert_eq!(report.candidates.len(), 3);
        assert!(report.truncated);
        assert!(report.pruned.iter().any(|pruned| matches!(
            pruned.reason,
            PruneReason::BudgetTruncation { budget: 3, .. }
        )));
        let notes = report.explanation_notes();
        assert!(notes.iter().any(|note| note == "truncated:true"));
        assert!(notes
            .iter()
            .any(|note| note.starts_with("candidate_budget:3")));
    }

    #[test]
    fn cold_start_defaults_are_configurable_data() {
        let shipped = ColdStartDefaults::shipped();
        let json = serde_json::to_vec(&shipped).expect("json");
        let loaded = ColdStartDefaults::from_json(&json).expect("load");
        assert_eq!(loaded, shipped);
        let displaced = ColdStartDefaults {
            planner_class: CapabilityClass::Worker,
            ..shipped
        };
        assert_ne!(displaced.planner_class, CapabilityClass::Frontier);
    }
}
