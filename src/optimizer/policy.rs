//! Policy graphs: directed actions with evidence-dependent transitions.
//!
//! Candidate generation (#165) and the online router (#167) consume this
//! type. They add graphs; they do not need to edit the node/edge vocabulary.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::action::{ModelAction, TopologySpec};
use super::certification::CertificationPlan;
use super::error::OptimizerError;
use super::ids::{PolicyId, PolicyNodeId};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::action::{
        AgentRole, CanonicalEffort, ExecutionBudget, HedgeTopology, ModelAction, PlannerTopology,
        RestartMode, ReviewTopology, WorkerTopology,
    };
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

        let mut evidence = TransitionEvidence::default();
        evidence.localized_failure = true;
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

        let mut evidence = TransitionEvidence::default();
        evidence.structural_failure = true;
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
}
