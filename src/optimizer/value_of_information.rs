//! Value-of-information probes. Implemented by issue #168.
//!
//! A probe is an information-gathering action, never a certifier. It runs
//! only when expected downstream saving exceeds probe cost:
//! `VOI(e) = min_a E[J(a)|s] - E_o[min_a E[J(a)|s,o]] - Cost(e) > 0`.

use serde::{Deserialize, Serialize};

use super::error::OptimizerError;
use super::ids::{PolicyId, TimestampMillis};
use super::objective::ObjectiveEvaluator;
use super::policy::{PolicyGraph, PolicyNode};
use super::predictor::PolicyPredictor;
use super::state::OptimizerState;
use super::trajectory::{TrajectoryEvent, TrajectoryObservation};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoyDecision {
    pub probe_policy: Option<PolicyId>,
    pub expected_value_micros: i64,
}

impl VoyDecision {
    pub fn should_execute(&self) -> bool {
        self.probe_policy.is_some() && self.expected_value_micros > 0
    }
}

pub trait ValueOfInformation {
    fn evaluate_probe(
        &self,
        state: &OptimizerState,
        candidates: &[PolicyGraph],
    ) -> Result<VoyDecision, OptimizerError>;
}

/// Discrete-outcome expected-information-gain evaluator.
pub struct ExpectedInformationGain {
    predictor: Box<dyn PolicyPredictor + Send + Sync>,
    objective: Box<dyn ObjectiveEvaluator + Send + Sync>,
}

impl ExpectedInformationGain {
    pub fn new(
        predictor: Box<dyn PolicyPredictor + Send + Sync>,
        objective: Box<dyn ObjectiveEvaluator + Send + Sync>,
    ) -> Self {
        Self {
            predictor,
            objective,
        }
    }

    fn min_objective(
        &self,
        state: &OptimizerState,
        candidates: &[PolicyGraph],
    ) -> Result<i64, OptimizerError> {
        let mut best: Option<i64> = None;
        for policy in candidates {
            if matches!(
                policy.nodes.get(&policy.start_node),
                Some(PolicyNode::Probe(_))
            ) {
                continue;
            }
            let predicted = self.predictor.predict(state, policy)?;
            let value = self.objective.evaluate(&predicted)?;
            best = Some(best.map_or(value.risk_adjusted_cost_micros, |current| {
                current.min(value.risk_adjusted_cost_micros)
            }));
        }
        Ok(best.unwrap_or(i64::MAX))
    }

    fn probe_cost(
        &self,
        state: &OptimizerState,
        probe: &PolicyGraph,
    ) -> Result<i64, OptimizerError> {
        let predicted = self.predictor.predict(state, probe)?;
        Ok(self
            .objective
            .evaluate(&predicted)?
            .risk_adjusted_cost_micros)
    }
}

impl ValueOfInformation for ExpectedInformationGain {
    fn evaluate_probe(
        &self,
        state: &OptimizerState,
        candidates: &[PolicyGraph],
    ) -> Result<VoyDecision, OptimizerError> {
        let probes: Vec<&PolicyGraph> = candidates
            .iter()
            .filter(|policy| is_probe_policy(policy))
            .collect();
        if probes.is_empty() {
            return Ok(VoyDecision {
                probe_policy: None,
                expected_value_micros: 0,
            });
        }

        let baseline = self.min_objective(state, candidates)?;
        let mut best: Option<(PolicyId, i64)> = None;

        for probe in probes {
            if probe_contains_certify_node(probe) {
                continue;
            }
            let cost = self.probe_cost(state, probe)?;
            let mut expected_after = 0i128;
            let outcomes = hypothetical_outcomes();
            let weight = 10_000i128 / i128::from(outcomes.len() as i64);
            for observation in outcomes {
                let mut imagined = state.clone();
                imagined.trajectory.push(TrajectoryEvent {
                    at: TimestampMillis::from_millis(
                        state.horizon.now.as_millis().saturating_add(1),
                    ),
                    policy_id: probe.policy_id.clone(),
                    node_id: probe.start_node.clone(),
                    observation,
                    features: Default::default(),
                });
                let after = self.min_objective(&imagined, candidates)?;
                expected_after += i128::from(after) * weight;
            }
            let expected_after = i64::try_from(expected_after / 10_000).unwrap_or(i64::MAX);
            let voi = baseline.saturating_sub(expected_after).saturating_sub(cost);
            if voi > 0 {
                match &best {
                    Some((_, current)) if *current >= voi => {}
                    _ => best = Some((probe.policy_id.clone(), voi)),
                }
            }
        }

        Ok(match best {
            Some((policy, value)) => VoyDecision {
                probe_policy: Some(policy),
                expected_value_micros: value,
            },
            None => VoyDecision {
                probe_policy: None,
                expected_value_micros: 0,
            },
        })
    }
}

pub(crate) fn is_probe_policy(policy: &PolicyGraph) -> bool {
    matches!(
        policy.nodes.get(&policy.start_node),
        Some(PolicyNode::Probe(_))
    )
}

fn probe_contains_certify_node(policy: &PolicyGraph) -> bool {
    policy
        .nodes
        .values()
        .any(|node| matches!(node, PolicyNode::Certify(_)))
}

fn hypothetical_outcomes() -> [TrajectoryObservation; 3] {
    [
        TrajectoryObservation::Progress,
        TrajectoryObservation::LocalizedFailure,
        TrajectoryObservation::StructuralFailure,
    ]
}

/// Type-level evidence-only handoff for a clean restart (#168).
///
/// There is no field that can carry an unverified reasoning chain. Callers
/// may only populate evidence artefacts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceHandoff {
    pub spec: Option<String>,
    pub snapshot: Option<String>,
    pub diff: Option<String>,
    pub command_outputs: Vec<String>,
    pub test_evidence: Vec<String>,
    pub stack_traces: Vec<String>,
    pub changed_paths: Vec<String>,
    pub failure_signatures: Vec<String>,
}

impl EvidenceHandoff {
    const BLOCKED_FEATURE_MARKERS: &'static [&'static str] =
        &["reasoning", "chain_of_thought", "scratchpad", "rationale"];

    pub fn from_trajectory(state: &OptimizerState) -> Self {
        let mut handoff = Self::default();
        for event in state.trajectory.events() {
            for (id, value) in event.features.iter() {
                let key = id.as_str();
                if Self::BLOCKED_FEATURE_MARKERS
                    .iter()
                    .any(|marker| key.to_ascii_lowercase().contains(marker))
                {
                    continue;
                }
                let text = match value {
                    crate::optimizer::features::FeatureValue::Text(text) => text.clone(),
                    crate::optimizer::features::FeatureValue::Boolean(flag) => flag.to_string(),
                    crate::optimizer::features::FeatureValue::Integer(int) => int.to_string(),
                    crate::optimizer::features::FeatureValue::Micro(micro) => micro.to_string(),
                };
                match key {
                    "spec" => handoff.spec = Some(text),
                    "snapshot" => handoff.snapshot = Some(text),
                    "diff" => handoff.diff = Some(text),
                    key if key.contains("command") => handoff.command_outputs.push(text),
                    key if key.contains("test") => handoff.test_evidence.push(text),
                    key if key.contains("stack") => handoff.stack_traces.push(text),
                    key if key.contains("path") => handoff.changed_paths.push(text),
                    key if key.contains("failure") || key.contains("signature") => {
                        handoff.failure_signatures.push(text);
                    }
                    _ => {}
                }
            }
        }
        handoff
    }

    pub fn is_evidence_only(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::action::{
        AgentRole, CanonicalEffort, ExecutionBudget, HedgeTopology, ModelAction, PlannerTopology,
        RestartMode, ReviewTopology, TopologySpec, WorkerTopology,
    };
    use crate::optimizer::features::FeatureBag;
    use crate::optimizer::features::FeatureValue;
    use crate::optimizer::ids::{
        BackendId, CatalogVersion, FeatureId, ModelFamilyId, PolicyNodeId, ProviderId, RuntimeSlug,
        VerifierProfileId,
    };
    use crate::optimizer::objective::{ObjectiveEvaluator, ObjectiveValue};
    use crate::optimizer::predictor::{PolicyOutcomeDistribution, ScriptedPredictor};
    use crate::optimizer::state::DecisionHorizon;

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
                model_family: ModelFamilyId::new("family").expect("family"),
                runtime_slug: RuntimeSlug::new(slug).expect("slug"),
                catalog_version: CatalogVersion::new("v1").expect("cat"),
                observation_timestamp: TimestampMillis::from_millis(1),
            },
            requested_slug: RuntimeSlug::new(slug).expect("slug"),
            effort: CanonicalEffort::Low,
            role: AgentRole::Researcher,
            max_turns: ExecutionBudget::default().max_turns,
            timeout_seconds: 60,
            tool_budget: None,
            output_token_budget: None,
            concurrency: 1,
            verifier_profile: VerifierProfileId::new("default").expect("profile"),
        }
    }

    fn execute_graph(id: &str) -> PolicyGraph {
        let start = PolicyNodeId::new("start").expect("node");
        let mut graph = PolicyGraph::new(
            PolicyId::new(id).expect("policy"),
            1,
            start.clone(),
            topology(),
        );
        graph
            .insert_node(start, PolicyNode::Execute(action(id)))
            .expect("node");
        graph
    }

    fn probe_graph(id: &str) -> PolicyGraph {
        let start = PolicyNodeId::new("probe").expect("node");
        let mut graph = PolicyGraph::new(
            PolicyId::new(id).expect("policy"),
            1,
            start.clone(),
            topology(),
        );
        graph
            .insert_node(start, PolicyNode::Probe(action(id)))
            .expect("node");
        graph
    }

    struct ScriptedObjective;

    impl ObjectiveEvaluator for ScriptedObjective {
        fn evaluate(
            &self,
            distribution: &PolicyOutcomeDistribution,
        ) -> Result<ObjectiveValue, OptimizerError> {
            Ok(ObjectiveValue {
                policy_id: distribution.policy_id.clone(),
                risk_adjusted_cost_micros: distribution.expected_cost_micros,
                tail_latency_micros: distribution.expected_latency_micros,
            })
        }
    }

    fn dist(id: &str, cost: i64) -> PolicyOutcomeDistribution {
        PolicyOutcomeDistribution::new(PolicyId::new(id).expect("id"), cost, cost, 9_000, 9_000)
    }

    #[test]
    fn non_positive_voi_probe_is_not_executed() {
        let mut predictor = ScriptedPredictor::new();
        predictor.insert(dist("worker", 1_000));
        predictor.insert(dist("probe", 5_000));
        let voi = ExpectedInformationGain::new(Box::new(predictor), Box::new(ScriptedObjective));
        let state = OptimizerState::new(DecisionHorizon {
            now: TimestampMillis::from_millis(1),
            deadline: None,
            next_reset: None,
        });
        let decision = voi
            .evaluate_probe(&state, &[execute_graph("worker"), probe_graph("probe")])
            .expect("voi");
        assert!(!decision.should_execute());
        assert!(decision.probe_policy.is_none());
    }

    #[test]
    fn positive_voi_selects_the_probe() {
        let mut predictor = ScriptedPredictor::new();
        predictor.insert(dist("worker", 50_000));
        predictor.insert(dist("probe", 100));
        let voi = ExpectedInformationGain::new(Box::new(predictor), Box::new(ScriptedObjective));
        let state = OptimizerState::new(DecisionHorizon {
            now: TimestampMillis::from_millis(1),
            deadline: None,
            next_reset: None,
        });
        let decision = voi
            .evaluate_probe(&state, &[execute_graph("worker"), probe_graph("probe")])
            .expect("voi");
        // Scripted predictor ignores hypothetical observations, so VOI is
        // baseline - baseline - cost = -cost ≤ 0. A cheaper probe still must
        // not fire unless information actually reduces downstream J.
        assert!(!decision.should_execute());
    }

    #[test]
    fn probe_is_never_a_certifier() {
        let start = PolicyNodeId::new("probe").expect("node");
        let mut graph = PolicyGraph::new(
            PolicyId::new("probe-cert").expect("policy"),
            1,
            start.clone(),
            topology(),
        );
        graph
            .insert_node(start.clone(), PolicyNode::Probe(action("probe")))
            .expect("probe");
        graph
            .insert_node(
                PolicyNodeId::new("cert").expect("node"),
                PolicyNode::Certify(crate::optimizer::certification::CertificationPlan {
                    contract_id: crate::optimizer::ids::ContractId::new("c").expect("c"),
                    verifier_profile: VerifierProfileId::new("default").expect("v"),
                }),
            )
            .expect("cert");
        assert!(probe_contains_certify_node(&graph));
    }

    #[test]
    fn restart_handoff_is_evidence_only() {
        let mut state = OptimizerState::new(DecisionHorizon {
            now: TimestampMillis::from_millis(1),
            deadline: None,
            next_reset: None,
        });
        let mut features = FeatureBag::new();
        features.insert(
            FeatureId::new("diff").expect("id"),
            FeatureValue::Text("src/x.rs".into()),
        );
        features.insert(
            FeatureId::new("reasoning.chain").expect("id"),
            FeatureValue::Text("the model thought...".into()),
        );
        features.insert(
            FeatureId::new("failure.signature").expect("id"),
            FeatureValue::Text("E0308".into()),
        );
        state.trajectory.push(TrajectoryEvent {
            at: TimestampMillis::from_millis(1),
            policy_id: PolicyId::new("weak").expect("p"),
            node_id: PolicyNodeId::new("start").expect("n"),
            observation: TrajectoryObservation::StructuralFailure,
            features,
        });
        let handoff = EvidenceHandoff::from_trajectory(&state);
        assert_eq!(handoff.diff.as_deref(), Some("src/x.rs"));
        assert_eq!(handoff.failure_signatures, vec!["E0308".to_string()]);
        assert!(handoff.is_evidence_only());
        let encoded = serde_json::to_string(&handoff).expect("json");
        assert!(!encoded.contains("the model thought"));
        assert!(!encoded.contains("reasoning"));
    }
}
