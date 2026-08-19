//! Context-switch cost as a first-class objective term (issue #201).
//!
//! Switching runtime, model, or session invalidates prompt cache and forces
//! re-priming. Offline replay cannot reconstruct cache state, so replay
//! estimates are labelled `switch-cost-uncorrected` and cannot promote a
//! policy into the safe set on their own.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::action::{ModelAction, RestartMode};
use super::error::OptimizerError;
use super::ids::TimestampMillis;
use super::objective::{ObjectiveEvaluator, ObjectiveValue};
use super::policy::PolicyGraph;
use super::predictor::{feature_keys, feature_text, primary_action, SampleCell};
use super::resources::ObservationKind;
use super::state::OptimizerState;

pub const REPLAY_UNCORRECTED_LABEL: &str = "switch-cost-uncorrected";
pub const DEFAULT_HYSTERESIS_BP: u16 = 1_000;
pub const DEFAULT_OSCILLATION_ALARM: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionClass {
    Continue,
    ModelChangeSameRuntime,
    RuntimeAdapterChange,
    FreshSessionOrWorktree,
}

impl TransitionClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Continue => "continue",
            Self::ModelChangeSameRuntime => "model_change_same_runtime",
            Self::RuntimeAdapterChange => "runtime_adapter_change",
            Self::FreshSessionOrWorktree => "fresh_session_or_worktree",
        }
    }

    pub fn is_switch(self) -> bool {
        !matches!(self, Self::Continue)
    }
}

/// Classify a candidate relative to the currently active action.
pub fn classify_transition(
    previous: Option<&ModelAction>,
    next: Option<&ModelAction>,
    restart: RestartMode,
) -> TransitionClass {
    if restart == RestartMode::CleanRestart {
        return TransitionClass::FreshSessionOrWorktree;
    }
    match (previous, next) {
        (None, Some(_)) => TransitionClass::FreshSessionOrWorktree,
        (Some(_), None) => TransitionClass::Continue,
        (Some(prev), Some(next)) => {
            if prev.backend_id != next.backend_id {
                TransitionClass::RuntimeAdapterChange
            } else if prev.runtime_model.runtime_slug != next.runtime_model.runtime_slug {
                TransitionClass::ModelChangeSameRuntime
            } else {
                TransitionClass::Continue
            }
        }
        (None, None) => TransitionClass::Continue,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwitchCostEstimate {
    pub class: TransitionClass,
    pub cached_prefix_invalidation_tokens: i64,
    pub context_reprime_tokens: i64,
    pub runtime_startup_micros: i64,
    pub lost_checkpoint_cost_micros: i64,
    pub total_cost_micros: i64,
    pub observation: ObservationKind,
}

impl SwitchCostEstimate {
    pub fn zero(class: TransitionClass) -> Self {
        Self {
            class,
            cached_prefix_invalidation_tokens: 0,
            context_reprime_tokens: 0,
            runtime_startup_micros: 0,
            lost_checkpoint_cost_micros: 0,
            total_cost_micros: 0,
            observation: ObservationKind::Measured,
        }
    }

    pub fn observation_label(&self) -> &'static str {
        match self.observation {
            ObservationKind::Measured => "measured",
            ObservationKind::Inferred => "inferred",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwitchHysteresis {
    pub margin_bp: u16,
}

impl Default for SwitchHysteresis {
    fn default() -> Self {
        Self {
            margin_bp: DEFAULT_HYSTERESIS_BP,
        }
    }
}

impl SwitchHysteresis {
    pub fn priced_switch_cost(self, switch_cost_micros: i64) -> i64 {
        switch_cost_micros.saturating_mul(i64::from(10_000u16.saturating_add(self.margin_bp)))
            / 10_000
    }

    pub fn should_switch(self, predicted_improvement_micros: i64, switch_cost_micros: i64) -> bool {
        predicted_improvement_micros > self.priced_switch_cost(switch_cost_micros)
    }
}

/// Hierarchical per-class switch costs fitted from #159 cache-token fields.
#[derive(Debug, Clone)]
pub struct SwitchCostModel {
    cells: BTreeMap<TransitionClass, SampleCell>,
    hysteresis: SwitchHysteresis,
}

impl Default for SwitchCostModel {
    fn default() -> Self {
        let mut cells = BTreeMap::new();
        cells.insert(
            TransitionClass::Continue,
            SampleCell {
                samples: vec![0],
                observations: 0,
            },
        );
        cells.insert(
            TransitionClass::ModelChangeSameRuntime,
            SampleCell {
                samples: wide_model_switch_prior(),
                observations: 0,
            },
        );
        cells.insert(
            TransitionClass::RuntimeAdapterChange,
            SampleCell {
                samples: wide_runtime_switch_prior(),
                observations: 0,
            },
        );
        cells.insert(
            TransitionClass::FreshSessionOrWorktree,
            SampleCell {
                samples: wide_fresh_session_prior(),
                observations: 0,
            },
        );
        Self {
            cells,
            hysteresis: SwitchHysteresis::default(),
        }
    }
}

impl SwitchCostModel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_hysteresis(mut self, hysteresis: SwitchHysteresis) -> Self {
        self.hysteresis = hysteresis;
        self
    }

    pub fn hysteresis(&self) -> SwitchHysteresis {
        self.hysteresis
    }

    pub fn observe(
        &mut self,
        class: TransitionClass,
        cached_miss_tokens: i64,
        reprime_tokens: i64,
        startup_micros: i64,
        lost_checkpoint_micros: i64,
    ) {
        let total = token_cost_micros(cached_miss_tokens)
            .saturating_add(token_cost_micros(reprime_tokens))
            .saturating_add(startup_micros)
            .saturating_add(lost_checkpoint_micros);
        self.cells.entry(class).or_default().observe(total);
    }

    pub fn estimate(&self, class: TransitionClass) -> SwitchCostEstimate {
        if class == TransitionClass::Continue {
            return SwitchCostEstimate::zero(class);
        }
        let cell = self.cells.get(&class);
        let (samples, observations) = match cell {
            Some(cell) => (cell.samples.as_slice(), cell.observations),
            None => ([].as_slice(), 0),
        };
        let inferred = observations == 0;
        let total = if samples.is_empty() {
            mean_prior(class)
        } else {
            super::predictor::mean_i64(samples)
        };
        let (cache, reprime, startup, checkpoint) = split_components(class, total);
        SwitchCostEstimate {
            class,
            cached_prefix_invalidation_tokens: cache,
            context_reprime_tokens: reprime,
            runtime_startup_micros: startup,
            lost_checkpoint_cost_micros: checkpoint,
            total_cost_micros: total,
            observation: if inferred {
                ObservationKind::Inferred
            } else {
                ObservationKind::Measured
            },
        }
    }
}

/// Resolve the currently active action from the candidate set when the
/// caller supplies the live policy id as a feature.
pub fn current_action_from_candidates<'a>(
    state: &OptimizerState,
    candidates: &'a [PolicyGraph],
) -> Option<&'a ModelAction> {
    let current_id = feature_text(&state.task_features, feature_keys::CURRENT_POLICY);
    current_id
        .as_deref()
        .and_then(|id| {
            candidates
                .iter()
                .find(|policy| policy.policy_id.as_str() == id)
        })
        .and_then(primary_action)
        .or_else(|| {
            state
                .trajectory
                .events()
                .last()
                .and_then(|event| {
                    candidates
                        .iter()
                        .find(|policy| policy.policy_id == event.policy_id)
                })
                .and_then(primary_action)
        })
}

pub fn estimate_switch(
    model: &SwitchCostModel,
    previous: Option<&ModelAction>,
    policy: &PolicyGraph,
) -> SwitchCostEstimate {
    let class = classify_transition(previous, primary_action(policy), policy.topology.restart);
    model.estimate(class)
}

/// Objective wrapper that adds `S(a_prev -> a)` after the inner evaluator.
pub struct SwitchAwareObjective {
    inner: Box<dyn ObjectiveEvaluator + Send + Sync>,
    switch: SwitchCostEstimate,
}

impl SwitchAwareObjective {
    pub fn new(
        inner: Box<dyn ObjectiveEvaluator + Send + Sync>,
        switch: SwitchCostEstimate,
    ) -> Self {
        Self { inner, switch }
    }
}

impl ObjectiveEvaluator for SwitchAwareObjective {
    fn evaluate(
        &self,
        distribution: &super::predictor::PolicyOutcomeDistribution,
    ) -> Result<ObjectiveValue, OptimizerError> {
        let mut value = self.inner.evaluate(distribution)?;
        value.risk_adjusted_cost_micros = value
            .risk_adjusted_cost_micros
            .saturating_add(self.switch.total_cost_micros);
        Ok(value)
    }
}

pub fn apply_switch_cost(
    value: &mut ObjectiveValue,
    estimate: &SwitchCostEstimate,
    hysteresis: SwitchHysteresis,
) {
    value.risk_adjusted_cost_micros = value
        .risk_adjusted_cost_micros
        .saturating_add(hysteresis.priced_switch_cost(estimate.total_cost_micros));
}

/// Replay cannot reconstruct cache state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplaySwitchEstimate {
    pub label: String,
    pub uncorrected: bool,
    pub replay_cost_micros: i64,
    pub correction_milli: Option<i64>,
    pub corrected_cost_micros: Option<i64>,
}

impl ReplaySwitchEstimate {
    pub fn from_replay(replay_cost_micros: i64, production_correction_milli: Option<i64>) -> Self {
        match production_correction_milli {
            Some(milli) if milli > 0 => Self {
                label: "switch-cost-corrected".to_string(),
                uncorrected: false,
                replay_cost_micros,
                correction_milli: Some(milli),
                corrected_cost_micros: Some(replay_cost_micros.saturating_mul(milli) / 1_000),
            },
            _ => Self {
                label: REPLAY_UNCORRECTED_LABEL.to_string(),
                uncorrected: true,
                replay_cost_micros,
                correction_milli: None,
                corrected_cost_micros: None,
            },
        }
    }

    /// Safe-set promotion must not rest on an uncorrected offline estimate.
    pub fn may_promote(&self) -> bool {
        !self.uncorrected
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OscillationTracker {
    pub sequence: Vec<String>,
    pub alarm_threshold: u32,
}

impl OscillationTracker {
    pub fn new(alarm_threshold: u32) -> Self {
        Self {
            sequence: Vec::new(),
            alarm_threshold,
        }
    }

    pub fn push(&mut self, identity: impl Into<String>) {
        self.sequence.push(identity.into());
    }

    pub fn count(&self) -> u32 {
        oscillation_count(&self.sequence)
    }

    pub fn alarmed(&self) -> bool {
        self.count() >= self.alarm_threshold.max(1)
    }
}

pub fn oscillation_count(sequence: &[String]) -> u32 {
    sequence
        .windows(3)
        .filter(|window| window[0] == window[2] && window[0] != window[1])
        .count() as u32
}

pub fn identity_of(action: &ModelAction) -> String {
    format!(
        "{}:{}",
        action.backend_id, action.runtime_model.runtime_slug
    )
}

fn token_cost_micros(tokens: i64) -> i64 {
    tokens.saturating_mul(50)
}

fn mean_prior(class: TransitionClass) -> i64 {
    let samples = match class {
        TransitionClass::Continue => vec![0],
        TransitionClass::ModelChangeSameRuntime => wide_model_switch_prior(),
        TransitionClass::RuntimeAdapterChange => wide_runtime_switch_prior(),
        TransitionClass::FreshSessionOrWorktree => wide_fresh_session_prior(),
    };
    super::predictor::mean_i64(&samples)
}

fn split_components(class: TransitionClass, total: i64) -> (i64, i64, i64, i64) {
    match class {
        TransitionClass::Continue => (0, 0, 0, 0),
        TransitionClass::ModelChangeSameRuntime => {
            (total * 4 / 10, total * 4 / 10, total / 10, total / 10)
        }
        TransitionClass::RuntimeAdapterChange => {
            (total * 3 / 10, total * 3 / 10, total * 3 / 10, total / 10)
        }
        TransitionClass::FreshSessionOrWorktree => (total / 5, total * 2 / 5, total / 5, total / 5),
    }
}

fn wide_model_switch_prior() -> Vec<i64> {
    vec![80_000, 120_000, 200_000, 350_000, 500_000]
}

fn wide_runtime_switch_prior() -> Vec<i64> {
    vec![400_000, 800_000, 1_500_000, 3_000_000, 6_000_000]
}

fn wide_fresh_session_prior() -> Vec<i64> {
    vec![2_000_000, 5_000_000, 10_000_000, 20_000_000, 40_000_000]
}

pub fn trajectory_identities(state: &OptimizerState, candidates: &[PolicyGraph]) -> Vec<String> {
    state
        .trajectory
        .events()
        .iter()
        .filter_map(|event| {
            candidates
                .iter()
                .find(|policy| policy.policy_id == event.policy_id)
                .and_then(primary_action)
                .map(identity_of)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::action::{
        AgentRole, CanonicalEffort, ExecutionBudget, HedgeTopology, PlannerTopology,
        ReviewTopology, RuntimeModelId, TopologySpec, WorkerTopology,
    };
    use crate::optimizer::ids::{
        BackendId, CatalogVersion, ModelFamilyId, PolicyId, PolicyNodeId, ProviderId, RuntimeSlug,
        VerifierProfileId,
    };
    use crate::optimizer::policy::PolicyNode;
    use crate::optimizer::predictor::{insert_text, PolicyOutcomeDistribution};
    use crate::optimizer::state::DecisionHorizon;

    fn action(backend: &str, slug: &str) -> ModelAction {
        ModelAction {
            backend_id: BackendId::new(backend).expect("backend"),
            provider_id: ProviderId::new("local").expect("provider"),
            runtime_model: RuntimeModelId {
                provider: ProviderId::new("local").expect("provider"),
                backend: BackendId::new(backend).expect("backend"),
                model_family: ModelFamilyId::new("family").expect("family"),
                runtime_slug: RuntimeSlug::new(slug).expect("slug"),
                catalog_version: CatalogVersion::new("v1").expect("cat"),
                observation_timestamp: TimestampMillis::from_millis(1),
            },
            requested_slug: RuntimeSlug::new(slug).expect("slug"),
            effort: CanonicalEffort::Low,
            role: AgentRole::Worker,
            max_turns: ExecutionBudget::default().max_turns,
            timeout_seconds: 60,
            tool_budget: None,
            output_token_budget: None,
            concurrency: 1,
            verifier_profile: VerifierProfileId::new("default").expect("profile"),
        }
    }

    fn graph(id: &str, backend: &str, slug: &str, restart: RestartMode) -> PolicyGraph {
        let start = PolicyNodeId::new("start").expect("node");
        let mut graph = PolicyGraph::new(
            PolicyId::new(id).expect("policy"),
            1,
            start.clone(),
            TopologySpec {
                planner: PlannerTopology::Single,
                workers: WorkerTopology::One,
                hedge: HedgeTopology::None,
                review: ReviewTopology::Independent,
                restart,
            },
        );
        graph
            .insert_node(start, PolicyNode::Execute(action(backend, slug)))
            .expect("node");
        graph
    }

    #[test]
    fn unobserved_transition_uses_wide_prior_and_is_inferred() {
        let model = SwitchCostModel::new();
        let estimate = model.estimate(TransitionClass::ModelChangeSameRuntime);
        assert_eq!(estimate.observation, ObservationKind::Inferred);
        assert!(estimate.total_cost_micros > 0);
        let fresh = model.estimate(TransitionClass::FreshSessionOrWorktree);
        let runtime = model.estimate(TransitionClass::RuntimeAdapterChange);
        assert!(fresh.total_cost_micros > runtime.total_cost_micros);
        assert!(runtime.total_cost_micros > estimate.total_cost_micros);
        assert_eq!(
            model.estimate(TransitionClass::Continue).total_cost_micros,
            0
        );
    }

    #[test]
    fn measured_observations_narrow_the_prior() {
        let mut model = SwitchCostModel::new();
        let before = model
            .estimate(TransitionClass::ModelChangeSameRuntime)
            .total_cost_micros;
        for _ in 0..20 {
            model.observe(TransitionClass::ModelChangeSameRuntime, 10, 10, 1, 1);
        }
        let after = model.estimate(TransitionClass::ModelChangeSameRuntime);
        assert_eq!(after.observation, ObservationKind::Measured);
        assert!(after.total_cost_micros < before);
    }

    #[test]
    fn replay_only_estimate_is_uncorrected_and_cannot_promote() {
        let estimate = ReplaySwitchEstimate::from_replay(1_000, None);
        assert!(estimate.uncorrected);
        assert_eq!(estimate.label, REPLAY_UNCORRECTED_LABEL);
        assert!(!estimate.may_promote());
        let corrected = ReplaySwitchEstimate::from_replay(1_000, Some(2_500));
        assert!(!corrected.uncorrected);
        assert!(corrected.may_promote());
        assert_eq!(corrected.corrected_cost_micros, Some(2_500));
    }

    #[test]
    fn oscillation_a_b_a_is_observable() {
        let mut tracker = OscillationTracker::new(DEFAULT_OSCILLATION_ALARM);
        tracker.push("runtime-a:model-a");
        tracker.push("runtime-a:model-b");
        tracker.push("runtime-a:model-a");
        assert_eq!(tracker.count(), 1);
        assert!(tracker.alarmed());
    }

    #[test]
    fn hysteresis_blocks_a_switch_whose_gain_is_below_margin() {
        let hysteresis = SwitchHysteresis { margin_bp: 1_000 };
        assert!(!hysteresis.should_switch(100, 100));
        assert!(hysteresis.should_switch(200, 100));
        assert_eq!(hysteresis.priced_switch_cost(100), 110);
    }

    #[test]
    fn transition_classes_are_distinct() {
        let current = action("adapter-a", "model-a");
        let same = action("adapter-a", "model-a");
        let other_model = action("adapter-a", "model-b");
        let other_runtime = action("adapter-b", "model-a");
        assert_eq!(
            classify_transition(Some(&current), Some(&same), RestartMode::Continuation),
            TransitionClass::Continue
        );
        assert_eq!(
            classify_transition(
                Some(&current),
                Some(&other_model),
                RestartMode::Continuation
            ),
            TransitionClass::ModelChangeSameRuntime
        );
        assert_eq!(
            classify_transition(
                Some(&current),
                Some(&other_runtime),
                RestartMode::Continuation
            ),
            TransitionClass::RuntimeAdapterChange
        );
        assert_eq!(
            classify_transition(Some(&current), Some(&same), RestartMode::CleanRestart),
            TransitionClass::FreshSessionOrWorktree
        );
    }

    struct ConstantObjective;

    impl ObjectiveEvaluator for ConstantObjective {
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

    #[test]
    fn switch_aware_objective_adds_the_term() {
        let switch = SwitchCostEstimate {
            class: TransitionClass::ModelChangeSameRuntime,
            cached_prefix_invalidation_tokens: 10,
            context_reprime_tokens: 10,
            runtime_startup_micros: 0,
            lost_checkpoint_cost_micros: 0,
            total_cost_micros: 500,
            observation: ObservationKind::Measured,
        };
        let objective = SwitchAwareObjective::new(Box::new(ConstantObjective), switch);
        let value = objective
            .evaluate(&PolicyOutcomeDistribution::new(
                PolicyId::new("p").expect("id"),
                100,
                100,
                9_000,
                9_000,
            ))
            .expect("eval");
        assert_eq!(value.risk_adjusted_cost_micros, 600);
    }

    #[test]
    fn current_action_reads_live_policy_feature() {
        let continue_policy = graph("keep", "adapter-a", "model-a", RestartMode::Continuation);
        let switch_policy = graph("swap", "adapter-a", "model-b", RestartMode::Continuation);
        let mut state = OptimizerState::new(DecisionHorizon {
            now: TimestampMillis::from_millis(1),
            deadline: None,
            next_reset: None,
        });
        insert_text(
            &mut state.task_features,
            feature_keys::CURRENT_POLICY,
            "keep",
        );
        let candidates = [continue_policy.clone(), switch_policy.clone()];
        let previous = current_action_from_candidates(&state, &candidates);
        let estimate = estimate_switch(&SwitchCostModel::new(), previous, &switch_policy);
        assert_eq!(estimate.class, TransitionClass::ModelChangeSameRuntime);
        let stay = estimate_switch(&SwitchCostModel::new(), previous, &continue_policy);
        assert_eq!(stay.class, TransitionClass::Continue);
        assert_eq!(stay.total_cost_micros, 0);
    }
}
