//! Chance-constrained feasibility. Implemented by issue #167.
//!
//! A candidate is feasible only after quality LCB, per-provider resource
//! chance constraints, deadline, capability, and frontier-reserve filters
//! all pass. Quality is never relaxed to make a cheaper policy feasible.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::action::AgentRole;
use super::error::OptimizerError;
use super::ids::PolicyId;
use super::policy::PolicyGraph;
use super::predictor::{
    feature_bool, feature_int, feature_keys, is_frontier_role, primary_action,
    PolicyOutcomeDistribution, PolicyPredictor,
};
use super::resources::{DispatchClass, DispatchRequest, Quantity};
use super::state::OptimizerState;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeasibilityResult {
    pub policy_id: PolicyId,
    pub feasible: bool,
    pub rejection_reasons: Vec<String>,
}

impl FeasibilityResult {
    pub fn rejected(policy_id: PolicyId, reason: impl Into<String>) -> Self {
        Self {
            policy_id,
            feasible: false,
            rejection_reasons: vec![reason.into()],
        }
    }

    pub fn admitted(policy_id: PolicyId) -> Self {
        Self {
            policy_id,
            feasible: true,
            rejection_reasons: Vec::new(),
        }
    }
}

pub trait FeasibilityChecker {
    fn check(
        &self,
        state: &OptimizerState,
        policy: &PolicyGraph,
    ) -> Result<FeasibilityResult, OptimizerError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeasibilityConfig {
    /// `δ_Q` in basis points. Overridden to 0 on deterministic-guarantee tasks.
    pub quality_delta_q_bp: u16,
    /// Maximum tolerated P(deadline miss) in basis points.
    pub deadline_epsilon_bp: u16,
    /// When true, missing capability features fail closed.
    pub fail_closed_on_unobservable_capability: bool,
}

impl Default for FeasibilityConfig {
    fn default() -> Self {
        Self {
            quality_delta_q_bp: 200,
            deadline_epsilon_bp: 1_000,
            fail_closed_on_unobservable_capability: true,
        }
    }
}

/// Quality LCB ∘ resource chance ∘ deadline ∘ static capability filters.
pub struct ChanceConstraintChecker {
    predictor: Option<Box<dyn PolicyPredictor + Send + Sync>>,
    config: FeasibilityConfig,
}

impl ChanceConstraintChecker {
    pub fn new(config: FeasibilityConfig) -> Self {
        Self {
            predictor: None,
            config,
        }
    }

    pub fn with_predictor(mut self, predictor: Box<dyn PolicyPredictor + Send + Sync>) -> Self {
        self.predictor = Some(predictor);
        self
    }

    pub fn quality_threshold_bp(&self, state: &OptimizerState) -> u16 {
        if feature_bool(&state.task_features, feature_keys::DETERMINISTIC_GUARANTEE) == Some(true) {
            return 10_000;
        }
        let delta = feature_int(&state.task_features, feature_keys::QUALITY_DELTA_Q_BP)
            .and_then(|value| u16::try_from(value).ok())
            .unwrap_or(self.config.quality_delta_q_bp);
        10_000u16.saturating_sub(delta.min(10_000))
    }

    pub fn check_predicted(
        &self,
        state: &OptimizerState,
        policy: &PolicyGraph,
        predicted: &PolicyOutcomeDistribution,
    ) -> Result<FeasibilityResult, OptimizerError> {
        policy.validate()?;
        let mut reasons = Vec::new();
        self.push_static_reasons(state, policy, &mut reasons);
        self.push_quality_reasons(state, predicted, &mut reasons);
        self.push_deadline_reasons(predicted, &mut reasons);
        self.push_resource_reasons(state, policy, predicted, &mut reasons)?;

        Ok(FeasibilityResult {
            policy_id: policy.policy_id.clone(),
            feasible: reasons.is_empty(),
            rejection_reasons: reasons,
        })
    }

    fn push_static_reasons(
        &self,
        state: &OptimizerState,
        policy: &PolicyGraph,
        reasons: &mut Vec<String>,
    ) {
        reject_flag(
            state,
            feature_keys::VERIFIER_AVAILABLE,
            false,
            "mandatory_verifier_unavailable",
            self.config.fail_closed_on_unobservable_capability,
            reasons,
        );
        reject_flag(
            state,
            feature_keys::MODEL_AVAILABLE,
            false,
            "required_model_unavailable",
            self.config.fail_closed_on_unobservable_capability,
            reasons,
        );
        reject_flag(
            state,
            feature_keys::BACKEND_OK,
            false,
            "backend_capability_mismatch",
            self.config.fail_closed_on_unobservable_capability,
            reasons,
        );
        reject_flag(
            state,
            feature_keys::CONTAINMENT_OK,
            false,
            "security_containment_unsatisfied",
            self.config.fail_closed_on_unobservable_capability,
            reasons,
        );

        let formal_required =
            feature_bool(&state.task_features, feature_keys::FORMAL_PROOF_REQUIRED) == Some(true)
                || feature_bool(&state.task_features, feature_keys::DETERMINISTIC_GUARANTEE)
                    == Some(true);
        if formal_required {
            match feature_bool(&state.task_features, feature_keys::FORMAL_TOOL_AVAILABLE) {
                Some(true) => {}
                Some(false) | None => {
                    reasons.push("formal_proof_required_but_unproducible".to_string());
                }
            }
        }

        if policy.validate().is_err() {
            reasons.push("policy_graph_invalid".to_string());
        }
    }

    fn push_quality_reasons(
        &self,
        state: &OptimizerState,
        predicted: &PolicyOutcomeDistribution,
        reasons: &mut Vec<String>,
    ) {
        let threshold = self.quality_threshold_bp(state);
        let lcb = predicted
            .details
            .certified_by_deadline_lcb_bp
            .max(predicted.quality_lower_confidence_bp);
        if lcb < threshold {
            reasons.push(format!("quality_lcb_below_threshold:{lcb}<{threshold}"));
        }
    }

    fn push_deadline_reasons(
        &self,
        predicted: &PolicyOutcomeDistribution,
        reasons: &mut Vec<String>,
    ) {
        if predicted.details.deadline_miss_probability_bp > self.config.deadline_epsilon_bp {
            reasons.push(format!(
                "deadline_miss_probability_too_high:{}",
                predicted.details.deadline_miss_probability_bp
            ));
        }
    }

    fn push_resource_reasons(
        &self,
        state: &OptimizerState,
        policy: &PolicyGraph,
        predicted: &PolicyOutcomeDistribution,
        reasons: &mut Vec<String>,
    ) -> Result<(), OptimizerError> {
        if !predicted.details.consumption.is_empty() {
            let mut known = BTreeMap::new();
            for (dimension, forecast) in &predicted.details.consumption {
                if state.budget.get(dimension).is_none() {
                    reasons.push(format!("unknown_resource_dimension:{dimension}"));
                    continue;
                }
                known.insert(dimension.clone(), forecast.clone());
            }
            if !known.is_empty() {
                let chance = state.budget.chance_feasibility(&known)?;
                for (dimension, feasible) in chance {
                    if !feasible {
                        reasons.push(format!(
                            "provider_quota_overrun_probability_too_high:{dimension}"
                        ));
                    }
                }
            }
        }

        if let Some(action) = primary_action(policy) {
            for (dimension, forecast) in &predicted.details.consumption {
                if state.budget.get(dimension).is_none() {
                    continue;
                }
                let demand = forecast
                    .samples
                    .iter()
                    .max_by_key(|sample| sample.as_i64())
                    .copied()
                    .unwrap_or(Quantity::ZERO);
                let class = dispatch_class(&action.role);
                let decision = state.budget.admit_dispatch(&DispatchRequest {
                    class,
                    pool: dimension.clone(),
                    demand,
                })?;
                if !decision.is_admit() {
                    let reason = decision
                        .rejection_reason()
                        .unwrap_or("frontier_reserve_violated");
                    if reason.contains("frontier reserve") {
                        reasons.push(format!("frontier_reserve_violated:{dimension}"));
                    } else {
                        reasons.push(reason.to_string());
                    }
                }
            }
        }
        Ok(())
    }
}

impl FeasibilityChecker for ChanceConstraintChecker {
    fn check(
        &self,
        state: &OptimizerState,
        policy: &PolicyGraph,
    ) -> Result<FeasibilityResult, OptimizerError> {
        let Some(predictor) = self.predictor.as_ref() else {
            return Ok(FeasibilityResult::rejected(
                policy.policy_id.clone(),
                "prediction_unobservable_fail_closed",
            ));
        };
        let predicted = predictor.predict(state, policy)?;
        self.check_predicted(state, policy, &predicted)
    }
}

fn dispatch_class(role: &AgentRole) -> DispatchClass {
    if is_frontier_role(role) {
        DispatchClass::MandatoryFrontier
    } else {
        DispatchClass::OptionalWorker
    }
}

fn reject_flag(
    state: &OptimizerState,
    key: &str,
    bad_value: bool,
    reason: &str,
    fail_closed_missing: bool,
    reasons: &mut Vec<String>,
) {
    match feature_bool(&state.task_features, key) {
        Some(value) if value == bad_value => reasons.push(reason.to_string()),
        None if fail_closed_missing => reasons.push(format!("{reason}:unobservable")),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::action::{
        CanonicalEffort, ExecutionBudget, HedgeTopology, ModelAction, PlannerTopology, RestartMode,
        ReviewTopology, TopologySpec, WorkerTopology,
    };
    use crate::optimizer::ids::{
        BackendId, CatalogVersion, ModelFamilyId, PolicyNodeId, ProviderId, ResourceDimensionId,
        RuntimeSlug, TimestampMillis, VerifierProfileId,
    };
    use crate::optimizer::policy::PolicyNode;
    use crate::optimizer::predictor::{insert_bool, insert_int, OutcomeDistributionDetails};
    use crate::optimizer::resources::{
        ConsumptionForecast, ObservationKind, ResourceDimension, ResourceObservation,
        ResourceVector,
    };
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

    fn action(role: AgentRole) -> ModelAction {
        ModelAction {
            backend_id: BackendId::well_known(BackendId::FAKE_PROVIDER),
            provider_id: ProviderId::new("local").expect("provider"),
            runtime_model: crate::optimizer::action::RuntimeModelId {
                provider: ProviderId::new("local").expect("provider"),
                backend: BackendId::well_known(BackendId::FAKE_PROVIDER),
                model_family: ModelFamilyId::new("family").expect("family"),
                runtime_slug: RuntimeSlug::new("model-a").expect("slug"),
                catalog_version: CatalogVersion::new("v1").expect("cat"),
                observation_timestamp: TimestampMillis::from_millis(1),
            },
            requested_slug: RuntimeSlug::new("model-a").expect("slug"),
            effort: CanonicalEffort::Low,
            role,
            max_turns: ExecutionBudget::default().max_turns,
            timeout_seconds: 60,
            tool_budget: None,
            output_token_budget: None,
            concurrency: 1,
            verifier_profile: VerifierProfileId::new("default").expect("profile"),
        }
    }

    fn graph(id: &str, role: AgentRole) -> PolicyGraph {
        let start = PolicyNodeId::new("start").expect("node");
        let mut graph = PolicyGraph::new(
            PolicyId::new(id).expect("policy"),
            1,
            start.clone(),
            topology(),
        );
        graph
            .insert_node(start, PolicyNode::Execute(action(role)))
            .expect("node");
        graph
    }

    fn capable_state() -> OptimizerState {
        let mut state = OptimizerState::new(DecisionHorizon {
            now: TimestampMillis::from_millis(1),
            deadline: Some(TimestampMillis::from_millis(1_000_000)),
            next_reset: None,
        });
        insert_bool(
            &mut state.task_features,
            feature_keys::VERIFIER_AVAILABLE,
            true,
        );
        insert_bool(
            &mut state.task_features,
            feature_keys::MODEL_AVAILABLE,
            true,
        );
        insert_bool(&mut state.task_features, feature_keys::BACKEND_OK, true);
        insert_bool(&mut state.task_features, feature_keys::CONTAINMENT_OK, true);
        let mut budget = ResourceVector::new();
        budget.insert(ResourceDimension {
            id: ResourceDimensionId::well_known(ResourceDimensionId::API_COST_USD),
            remaining: Quantity::new(100),
            reset_at: None,
            frontier_reserve: Quantity::new(20),
            emergency_margin: Quantity::new(5),
            uncertainty: Quantity::ZERO,
            shadow_price: 10,
            observation: ResourceObservation {
                kind: ObservationKind::Measured,
                confidence_bp: 10_000,
            },
            chance_epsilon_bp: 1_000,
            target_usage_bp: 5_000,
            learning_rate: 1_000,
        });
        budget.insert(ResourceDimension {
            id: ResourceDimensionId::well_known(ResourceDimensionId::LOCAL_COMPUTE_SECONDS),
            remaining: Quantity::new(200),
            reset_at: None,
            frontier_reserve: Quantity::new(10),
            emergency_margin: Quantity::new(0),
            uncertainty: Quantity::ZERO,
            shadow_price: 1,
            observation: ResourceObservation {
                kind: ObservationKind::Measured,
                confidence_bp: 10_000,
            },
            chance_epsilon_bp: 1_000,
            target_usage_bp: 5_000,
            learning_rate: 1_000,
        });
        state.budget = budget;
        state
    }

    fn predicted(id: &str, lcb: u16, miss_bp: u16, demand: i64) -> PolicyOutcomeDistribution {
        let mut details = OutcomeDistributionDetails {
            certified_by_deadline_lcb_bp: lcb,
            deadline_miss_probability_bp: miss_bp,
            ..OutcomeDistributionDetails::default()
        };
        details.consumption.insert(
            ResourceDimensionId::well_known(ResourceDimensionId::API_COST_USD),
            ConsumptionForecast {
                samples: vec![Quantity::new(demand), Quantity::new(demand)],
            },
        );
        PolicyOutcomeDistribution::new(PolicyId::new(id).expect("id"), 1, 1, lcb, lcb)
            .with_details(details)
    }

    #[test]
    fn quality_lcb_below_threshold_is_infeasible() {
        let checker = ChanceConstraintChecker::new(FeasibilityConfig::default());
        let state = capable_state();
        let policy = graph("cheap", AgentRole::Worker);
        let result = checker
            .check_predicted(&state, &policy, &predicted("cheap", 4_000, 0, 1))
            .expect("check");
        assert!(!result.feasible);
        assert!(result
            .rejection_reasons
            .iter()
            .any(|reason| reason.starts_with("quality_lcb_below_threshold")));
    }

    #[test]
    fn deterministic_guarantee_requires_delta_q_zero_and_formal_tool() {
        let checker = ChanceConstraintChecker::new(FeasibilityConfig::default());
        let mut state = capable_state();
        insert_bool(
            &mut state.task_features,
            feature_keys::DETERMINISTIC_GUARANTEE,
            true,
        );
        insert_bool(
            &mut state.task_features,
            feature_keys::FORMAL_TOOL_AVAILABLE,
            false,
        );
        let policy = graph("formal", AgentRole::Worker);
        let result = checker
            .check_predicted(&state, &policy, &predicted("formal", 10_000, 0, 1))
            .expect("check");
        assert!(!result.feasible);
        assert!(result
            .rejection_reasons
            .iter()
            .any(|reason| reason == "formal_proof_required_but_unproducible"));
        assert_eq!(checker.quality_threshold_bp(&state), 10_000);
    }

    #[test]
    fn resource_chance_constraints_are_independent_per_provider() {
        let checker = ChanceConstraintChecker::new(FeasibilityConfig::default());
        let state = capable_state();
        let policy = graph("quota", AgentRole::Worker);
        let mut over = predicted("quota", 9_900, 0, 1);
        over.details.consumption.insert(
            ResourceDimensionId::well_known(ResourceDimensionId::API_COST_USD),
            ConsumptionForecast {
                samples: vec![Quantity::new(10_000), Quantity::new(10_000)],
            },
        );
        over.details.consumption.insert(
            ResourceDimensionId::well_known(ResourceDimensionId::LOCAL_COMPUTE_SECONDS),
            ConsumptionForecast {
                samples: vec![Quantity::new(1), Quantity::new(1)],
            },
        );
        let result = checker
            .check_predicted(&state, &policy, &over)
            .expect("check");
        assert!(!result.feasible);
        let quota_hits: Vec<_> = result
            .rejection_reasons
            .iter()
            .filter(|reason| reason.contains("quota_overrun"))
            .collect();
        assert_eq!(quota_hits.len(), 1);
        assert!(quota_hits[0].contains(ResourceDimensionId::API_COST_USD));
    }

    #[test]
    fn frontier_reserve_violation_rejects_optional_policy() {
        let checker = ChanceConstraintChecker::new(FeasibilityConfig::default());
        let state = capable_state();
        let policy = graph("optional", AgentRole::Worker);
        let result = checker
            .check_predicted(&state, &policy, &predicted("optional", 9_900, 0, 80))
            .expect("check");
        assert!(!result.feasible);
        assert!(result
            .rejection_reasons
            .iter()
            .any(|reason| reason.contains("frontier_reserve")));
    }

    #[test]
    fn missing_capability_features_fail_closed() {
        let checker = ChanceConstraintChecker::new(FeasibilityConfig::default());
        let state = OptimizerState::new(DecisionHorizon {
            now: TimestampMillis::from_millis(1),
            deadline: None,
            next_reset: None,
        });
        let policy = graph("unknown", AgentRole::Worker);
        let result = checker
            .check_predicted(&state, &policy, &predicted("unknown", 9_900, 0, 1))
            .expect("check");
        assert!(!result.feasible);
        assert!(result
            .rejection_reasons
            .iter()
            .any(|reason| reason.contains("unobservable")));
    }

    #[test]
    fn configured_delta_q_is_honoured_when_not_deterministic() {
        let checker = ChanceConstraintChecker::new(FeasibilityConfig::default());
        let mut state = capable_state();
        insert_int(
            &mut state.task_features,
            feature_keys::QUALITY_DELTA_Q_BP,
            500,
        );
        assert_eq!(checker.quality_threshold_bp(&state), 9_500);
    }
}
