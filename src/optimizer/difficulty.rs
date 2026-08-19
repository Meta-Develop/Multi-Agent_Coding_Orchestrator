//! Two-stage routing: a cheap calibrated difficulty predictor in front of
//! the full router, plus an explicit budget for the decision itself (#200).
//!
//! Stage 1 is one-directional. It may spend less on deliberation; it may
//! never select a policy outside the current safe set, relax a quality
//! constraint, or veto certification.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use super::error::OptimizerError;
use super::explanation::DecisionDiagnostics;
use super::features::{keys, FeatureBag};
use super::ids::PolicyId;
use super::online_router::{
    CheckpointDecision, CheckpointRouter, ContinuationKind, OnlineRouter, RouterDecision,
    SafeContextualRouter,
};
use super::operator_labels::{LearnedPolicyOutcome, OperatorSignalKind};
use super::policy::PolicyGraph;
use super::predictor::{wilson_lcb_bp, BetaBinomialCell};
use super::safe_set::{SafeSet, SafeSetStore};
use super::state::OptimizerState;

pub const DEFAULT_DIFFICULTY_THRESHOLD_BP: u16 = 3_500;
pub const DEFAULT_OVERHEAD_FRACTION_BP: u16 = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StagePath {
    Stage1ShortCircuit,
    Stage2Full,
    OverheadDegraded,
}

impl StagePath {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stage1ShortCircuit => "stage1_short_circuit",
            Self::Stage2Full => "stage2_full",
            Self::OverheadDegraded => "overhead_degraded",
        }
    }
}

/// Policy that has already been admitted by the current safe set.
/// Stage 1 can only return this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafePolicy {
    policy: PolicyGraph,
}

impl SafePolicy {
    pub fn admit(policy: PolicyGraph, store: &dyn SafeSetStore) -> Result<Self, OptimizerError> {
        if !store.contains(&policy.policy_id)? {
            return Err(OptimizerError::invalid(format!(
                "stage1 cannot select policy {} outside the safe set",
                policy.policy_id
            )));
        }
        Ok(Self { policy })
    }

    pub fn policy(&self) -> &PolicyGraph {
        &self.policy
    }

    pub fn into_policy(self) -> PolicyGraph {
        self.policy
    }
}

/// In-memory safe-set used by fixtures and the two-stage gate.
#[derive(Debug, Clone, Default)]
pub struct MemorySafeSet {
    ids: BTreeSet<PolicyId>,
}

impl MemorySafeSet {
    pub fn new(ids: impl IntoIterator<Item = PolicyId>) -> Self {
        Self {
            ids: ids.into_iter().collect(),
        }
    }

    pub fn insert(&mut self, id: PolicyId) {
        self.ids.insert(id);
    }
}

impl SafeSetStore for MemorySafeSet {
    fn contains(&self, policy_id: &PolicyId) -> Result<bool, OptimizerError> {
        Ok(self.ids.contains(policy_id))
    }

    fn snapshot(&self) -> Result<SafeSet, OptimizerError> {
        Ok(SafeSet {
            policy_ids: self.ids.iter().cloned().collect(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DifficultyPrediction {
    pub score_bp: u16,
    pub lower_bp: u16,
    pub upper_bp: u16,
    pub success_probability_bp: u16,
}

impl DifficultyPrediction {
    pub fn confidently_below(&self, threshold_bp: u16) -> bool {
        self.upper_bp < threshold_bp
    }

    pub fn straddles(&self, threshold_bp: u16) -> bool {
        self.lower_bp < threshold_bp && self.upper_bp >= threshold_bp
    }
}

/// Cheap, deterministic predictor over static #163 features only.
#[derive(Debug, Clone)]
pub struct CheapDifficultyPredictor {
    cells: BTreeMap<u64, BetaBinomialCell>,
    threshold_bp: u16,
    short_circuits: u32,
    misroutes: u32,
}

impl Default for CheapDifficultyPredictor {
    fn default() -> Self {
        Self {
            cells: BTreeMap::new(),
            threshold_bp: DEFAULT_DIFFICULTY_THRESHOLD_BP,
            short_circuits: 0,
            misroutes: 0,
        }
    }
}

impl CheapDifficultyPredictor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_threshold(mut self, threshold_bp: u16) -> Self {
        self.threshold_bp = threshold_bp.min(10_000);
        self
    }

    pub fn threshold_bp(&self) -> u16 {
        self.threshold_bp
    }

    pub fn predict(&self, task: &FeatureBag, repo: &FeatureBag) -> DifficultyPrediction {
        let (prior_score, width) = static_difficulty(task, repo);
        let key = feature_bucket(task, repo);
        let cell = self
            .cells
            .get(&key)
            .cloned()
            .unwrap_or_else(BetaBinomialCell::jeffreys);
        let success = if cell.observations == 0 {
            10_000u16.saturating_sub(prior_score)
        } else {
            cell.mean_bp()
        };
        let lcb = wilson_lcb_bp(
            cell.alpha_milli / 1_000,
            cell.alpha_milli.saturating_add(cell.beta_milli) / 1_000,
            196,
        );
        let score = if cell.observations == 0 {
            prior_score
        } else {
            10_000u16.saturating_sub(success)
        };
        let band = if cell.observations == 0 {
            width
        } else {
            success.saturating_sub(lcb).max(200)
        };
        let lower = score.saturating_sub(band);
        let upper = score.saturating_add(band).min(10_000);
        DifficultyPrediction {
            score_bp: score,
            lower_bp: lower,
            upper_bp: upper,
            success_probability_bp: success,
        }
    }

    pub fn observe_outcome(&mut self, task: &FeatureBag, repo: &FeatureBag, easy_success: bool) {
        let key = feature_bucket(task, repo);
        self.cells
            .entry(key)
            .or_insert_with(BetaBinomialCell::jeffreys)
            .observe(easy_success);
        if easy_success {
            self.threshold_bp = self.threshold_bp.saturating_add(50).min(6_000);
        } else {
            self.threshold_bp = self.threshold_bp.saturating_sub(150).max(1_000);
        }
    }

    pub fn record_short_circuit(&mut self, later_misroute: bool) {
        self.short_circuits = self.short_circuits.saturating_add(1);
        if later_misroute {
            self.misroutes = self.misroutes.saturating_add(1);
            self.threshold_bp = self.threshold_bp.saturating_sub(200).max(1_000);
        }
    }

    pub fn observe_labels(&mut self, outcomes: &[LearnedPolicyOutcome]) {
        for outcome in outcomes {
            let misroute = outcome.rework.as_ref().is_some_and(|rework| {
                rework.kinds.iter().any(|kind| {
                    matches!(
                        kind,
                        OperatorSignalKind::ManualRedispatch
                            | OperatorSignalKind::OperatorInterrupt
                            | OperatorSignalKind::HumanFixupOnProducedPaths
                    )
                })
            });
            if outcome.certification.certified() && !misroute {
                self.threshold_bp = self.threshold_bp.saturating_add(25).min(6_000);
            } else if misroute {
                self.threshold_bp = self.threshold_bp.saturating_sub(200).max(1_000);
            }
        }
    }

    pub fn misroute_rate_bp(&self) -> Option<u16> {
        if self.short_circuits == 0 {
            return None;
        }
        Some(
            ((u64::from(self.misroutes).saturating_mul(10_000)) / u64::from(self.short_circuits))
                .min(10_000) as u16,
        )
    }
}

fn static_difficulty(task: &FeatureBag, repo: &FeatureBag) -> (u16, u16) {
    let mut score: i64 = 1_500;
    let mut signals = 0u32;
    let bump = |score: &mut i64, signals: &mut u32, amount: i64| {
        *score = (*score + amount).clamp(0, 10_000);
        *signals += 1;
    };
    if let Some(files) = task.integer(keys::TASK_ESTIMATED_FILES_AFFECTED) {
        bump(
            &mut score,
            &mut signals,
            files.saturating_mul(400).min(3_000),
        );
    }
    if let Some(modules) = task.integer(keys::TASK_ESTIMATED_MODULES_AFFECTED) {
        bump(
            &mut score,
            &mut signals,
            modules.saturating_mul(250).min(2_000),
        );
    }
    if let Some(fanout) = task.integer(keys::TASK_DEPENDENCY_FAN_OUT) {
        bump(
            &mut score,
            &mut signals,
            fanout.saturating_mul(200).min(1_500),
        );
    }
    if task.boolean(keys::TASK_PUBLIC_API_IMPACT) == Some(true) {
        bump(&mut score, &mut signals, 800);
    }
    if task.boolean(keys::TASK_SCHEMA_OR_MIGRATION_IMPACT) == Some(true) {
        bump(&mut score, &mut signals, 900);
    }
    if task.boolean(keys::TASK_CONCURRENCY_INVOLVEMENT) == Some(true) {
        bump(&mut score, &mut signals, 700);
    }
    if task.boolean(keys::TASK_SECURITY_SENSITIVITY) == Some(true) {
        bump(&mut score, &mut signals, 800);
    }
    if let Some(context) = task.integer(keys::TASK_ESTIMATED_CONTEXT_SIZE) {
        bump(&mut score, &mut signals, (context / 2_000).min(1_500));
    }
    if let Some(steps) = task.integer(keys::TASK_ESTIMATED_TOOL_STEP_COUNT) {
        bump(
            &mut score,
            &mut signals,
            steps.saturating_mul(80).min(1_200),
        );
    }
    if let Some(rollback) = task.integer(keys::TASK_ROLLBACK_DIFFICULTY_MICRO) {
        bump(&mut score, &mut signals, rollback / 2_000);
    }
    if let Some(size) = repo.integer(keys::REPO_SIZE_BYTES) {
        bump(&mut score, &mut signals, (size / 50_000).min(800));
    }
    let width = if signals == 0 {
        4_000
    } else {
        (2_400u16)
            .saturating_sub(u16::try_from(signals.saturating_mul(200)).unwrap_or(2_000))
            .max(400)
    };
    (u16::try_from(score).unwrap_or(10_000), width)
}

fn feature_bucket(task: &FeatureBag, repo: &FeatureBag) -> u64 {
    let files = task
        .integer(keys::TASK_ESTIMATED_FILES_AFFECTED)
        .unwrap_or(0);
    let fanout = task.integer(keys::TASK_DEPENDENCY_FAN_OUT).unwrap_or(0);
    let flags = u64::from(task.boolean(keys::TASK_PUBLIC_API_IMPACT) == Some(true))
        | u64::from(task.boolean(keys::TASK_SCHEMA_OR_MIGRATION_IMPACT) == Some(true)) << 1
        | u64::from(task.boolean(keys::TASK_SECURITY_SENSITIVITY) == Some(true)) << 2;
    let size_bin = repo.integer(keys::REPO_SIZE_BYTES).unwrap_or(0) / 100_000;
    (files as u64)
        .wrapping_mul(1_009)
        .wrapping_add((fanout as u64).wrapping_mul(17))
        .wrapping_add(flags.wrapping_mul(101))
        .wrapping_add(size_bin as u64)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwoStageConfig {
    pub overhead_fraction_bp: u16,
    pub predicted_task_cost_micros: i64,
    pub scripted_overhead_micros: i64,
}

impl Default for TwoStageConfig {
    fn default() -> Self {
        Self {
            overhead_fraction_bp: DEFAULT_OVERHEAD_FRACTION_BP,
            predicted_task_cost_micros: 10_000_000,
            scripted_overhead_micros: 0,
        }
    }
}

impl TwoStageConfig {
    pub fn budget_micros(&self) -> i64 {
        self.predicted_task_cost_micros
            .saturating_mul(i64::from(self.overhead_fraction_bp))
            / 10_000
    }

    pub fn overhead_exceeded(&self) -> bool {
        self.scripted_overhead_micros > self.budget_micros()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionOverhead {
    pub wall_clock_micros: i64,
    pub predicted_task_cost_micros: i64,
    pub budget_micros: i64,
    pub exceeded: bool,
}

impl DecisionOverhead {
    pub fn from_config(config: &TwoStageConfig) -> Self {
        Self {
            wall_clock_micros: config.scripted_overhead_micros,
            predicted_task_cost_micros: config.predicted_task_cost_micros,
            budget_micros: config.budget_micros(),
            exceeded: config.overhead_exceeded(),
        }
    }
}

/// Stage-1 gate. Enumerates nothing; it either admits a safe economical
/// policy or falls through.
pub struct Stage1Gate {
    pub predictor: CheapDifficultyPredictor,
    pub safe_set: Box<dyn SafeSetStore + Send + Sync>,
    pub economical: PolicyGraph,
    pub baseline: PolicyGraph,
    pub config: TwoStageConfig,
}

impl Stage1Gate {
    pub fn decide(&mut self, state: &OptimizerState) -> Result<Stage1Decision, OptimizerError> {
        let economical = SafePolicy::admit(self.economical.clone(), self.safe_set.as_ref())?;
        let baseline = SafePolicy::admit(self.baseline.clone(), self.safe_set.as_ref())?;
        let prediction = self
            .predictor
            .predict(&state.task_features, &state.repo_features);
        if self.config.predicted_task_cost_micros <= 0 {
            self.config.predicted_task_cost_micros = predicted_task_cost_micros(state);
        }
        let overhead = DecisionOverhead::from_config(&self.config);
        if overhead.exceeded {
            return Ok(Stage1Decision {
                path: StagePath::OverheadDegraded,
                policy: Some(baseline),
                prediction,
                overhead,
                enumerated_candidates: false,
            });
        }
        if prediction.confidently_below(self.predictor.threshold_bp()) {
            self.predictor.record_short_circuit(false);
            return Ok(Stage1Decision {
                path: StagePath::Stage1ShortCircuit,
                policy: Some(economical),
                prediction,
                overhead,
                enumerated_candidates: false,
            });
        }
        Ok(Stage1Decision {
            path: StagePath::Stage2Full,
            policy: None,
            prediction,
            overhead,
            enumerated_candidates: true,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage1Decision {
    pub path: StagePath,
    pub policy: Option<SafePolicy>,
    pub prediction: DifficultyPrediction,
    pub overhead: DecisionOverhead,
    pub enumerated_candidates: bool,
}

pub fn annotate_stage(diagnostics: &mut DecisionDiagnostics, decision: &Stage1Decision) {
    diagnostics.stage_path = Some(decision.path.as_str().to_string());
    diagnostics.difficulty_score_bp = Some(decision.prediction.score_bp);
    diagnostics.difficulty_lower_bp = Some(decision.prediction.lower_bp);
    diagnostics.difficulty_upper_bp = Some(decision.prediction.upper_bp);
    diagnostics.decision_overhead_micros = Some(decision.overhead.wall_clock_micros);
    diagnostics.overhead_degraded = Some(decision.overhead.exceeded);
}

/// Full two-stage router. Stage 2 is the existing contextual router.
pub struct TwoStageRouter {
    pub stage1: Stage1Gate,
    pub stage2: SafeContextualRouter,
}

impl TwoStageRouter {
    pub fn select_staged(
        &mut self,
        state: &OptimizerState,
        candidates: &[PolicyGraph],
    ) -> Result<RouterDecision, OptimizerError> {
        let front = self.stage1.decide(state)?;
        if let Some(policy) = front.policy.as_ref() {
            let mut diagnostics = DecisionDiagnostics::new(
                state.horizon.now,
                vec![policy.policy().policy_id.clone()],
            );
            annotate_stage(&mut diagnostics, &front);
            return Ok(select_policy_for_tests(
                state,
                policy.policy(),
                diagnostics,
                Some(front.path.as_str()),
            ));
        }
        let mut decision = self.stage2.select(state, candidates)?;
        annotate_router(&mut decision, &front);
        Ok(decision)
    }
}

impl OnlineRouter for TwoStageRouter {
    fn select(
        &self,
        state: &OptimizerState,
        candidates: &[PolicyGraph],
    ) -> Result<RouterDecision, OptimizerError> {
        let mut gate = Stage1Gate {
            predictor: self.stage1.predictor.clone(),
            safe_set: Box::new(MemorySafeSet::new(
                self.stage1.safe_set.snapshot()?.policy_ids,
            )),
            economical: self.stage1.economical.clone(),
            baseline: self.stage1.baseline.clone(),
            config: self.stage1.config.clone(),
        };
        let front = gate.decide(state)?;
        if let Some(policy) = front.policy.as_ref() {
            let mut diagnostics = DecisionDiagnostics::new(
                state.horizon.now,
                vec![policy.policy().policy_id.clone()],
            );
            annotate_stage(&mut diagnostics, &front);
            return Ok(select_policy_for_tests(
                state,
                policy.policy(),
                diagnostics,
                Some(front.path.as_str()),
            ));
        }
        let mut decision = self.stage2.select(state, candidates)?;
        annotate_router(&mut decision, &front);
        Ok(decision)
    }
}

fn annotate_router(decision: &mut RouterDecision, front: &Stage1Decision) {
    match decision {
        RouterDecision::Select {
            diagnostics,
            explanation,
            ..
        }
        | RouterDecision::Infeasible {
            diagnostics,
            explanation,
            ..
        } => {
            annotate_stage(diagnostics, front);
            *explanation = super::explanation::DecisionExplanation::from_diagnostics(
                diagnostics,
                explanation.resources.clone(),
            );
        }
    }
}

impl CheckpointRouter {
    pub fn reoptimize_two_stage(
        &self,
        stage1: &mut Stage1Gate,
        state: &mut OptimizerState,
        candidates: &[PolicyGraph],
    ) -> Result<CheckpointDecision, OptimizerError> {
        let front = stage1.decide(state)?;
        if let Some(policy) = front.policy.as_ref() {
            let mut diagnostics = DecisionDiagnostics::new(
                state.horizon.now,
                vec![policy.policy().policy_id.clone()],
            );
            annotate_stage(&mut diagnostics, &front);
            let router = select_policy_for_tests(
                state,
                policy.policy(),
                diagnostics,
                Some(front.path.as_str()),
            );
            return Ok(CheckpointDecision {
                kind: ContinuationKind::Continue,
                router,
                escalation: None,
                handoff: None,
                hedge: None,
            });
        }
        let mut decision = self.reoptimize(state, candidates)?;
        match &mut decision.router {
            RouterDecision::Select {
                diagnostics,
                explanation,
                ..
            }
            | RouterDecision::Infeasible {
                diagnostics,
                explanation,
                ..
            } => {
                annotate_stage(diagnostics, &front);
                *explanation = super::explanation::DecisionExplanation::from_diagnostics(
                    diagnostics,
                    explanation.resources.clone(),
                );
            }
        }
        Ok(decision)
    }
}

/// Narrow helper so stage 1 can emit a `RouterDecision` without exposing
/// the private `select_policy` constructor. Tests also use this.
pub fn select_policy_for_tests(
    state: &OptimizerState,
    policy: &PolicyGraph,
    mut diagnostics: DecisionDiagnostics,
    continuation: Option<&str>,
) -> RouterDecision {
    diagnostics.selected_policy = Some(policy.policy_id.clone());
    if let Some(action) = super::predictor::primary_action(policy) {
        diagnostics.selected_action = Some(super::explanation::SelectedAction::from_model_action(
            action,
        ));
    }
    diagnostics.continuation = continuation.map(str::to_string);
    let explanation = super::explanation::DecisionExplanation::from_diagnostics(
        &diagnostics,
        state.budget.snapshot(state.horizon.now),
    );
    RouterDecision::Select {
        policy_id: policy.policy_id.clone(),
        explanation,
        diagnostics,
    }
}

pub fn predicted_task_cost_micros(state: &OptimizerState) -> i64 {
    state
        .task_features
        .integer(keys::TASK_ESTIMATED_TOOL_STEP_COUNT)
        .unwrap_or(10)
        .saturating_mul(1_000_000)
        .max(1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::action::{
        AgentRole, CanonicalEffort, ExecutionBudget, HedgeTopology, ModelAction, PlannerTopology,
        RestartMode, ReviewTopology, RuntimeModelId, TopologySpec, WorkerTopology,
    };
    use crate::optimizer::features::FeatureValue;
    use crate::optimizer::ids::{
        BackendId, CatalogVersion, FeatureId, ModelFamilyId, PolicyNodeId, ProviderId, RuntimeSlug,
        TimestampMillis, VerifierProfileId,
    };
    use crate::optimizer::online_router::{RouterConfig, TailRiskObjective};
    use crate::optimizer::policy::PolicyNode;
    use crate::optimizer::predictor::ScriptedPredictor;
    use crate::optimizer::state::DecisionHorizon;

    fn put_int(bag: &mut FeatureBag, key: &str, value: i64) {
        bag.insert(
            FeatureId::new(key).expect("id"),
            FeatureValue::Integer(value),
        );
    }

    fn action(slug: &str) -> ModelAction {
        ModelAction {
            backend_id: BackendId::well_known(BackendId::FAKE_PROVIDER),
            provider_id: ProviderId::new("local").expect("provider"),
            runtime_model: RuntimeModelId {
                provider: ProviderId::new("local").expect("provider"),
                backend: BackendId::well_known(BackendId::FAKE_PROVIDER),
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

    fn graph(id: &str, slug: &str) -> PolicyGraph {
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
                restart: RestartMode::Continuation,
            },
        );
        graph
            .insert_node(start, PolicyNode::Execute(action(slug)))
            .expect("node");
        graph
    }

    fn easy_state() -> OptimizerState {
        let mut state = OptimizerState::new(DecisionHorizon {
            now: TimestampMillis::from_millis(1),
            deadline: None,
            next_reset: None,
        });
        put_int(
            &mut state.task_features,
            keys::TASK_ESTIMATED_FILES_AFFECTED,
            1,
        );
        put_int(
            &mut state.task_features,
            keys::TASK_ESTIMATED_TOOL_STEP_COUNT,
            2,
        );
        state
    }

    fn hard_state() -> OptimizerState {
        let mut state = easy_state();
        put_int(
            &mut state.task_features,
            keys::TASK_ESTIMATED_FILES_AFFECTED,
            20,
        );
        put_int(
            &mut state.task_features,
            keys::TASK_ESTIMATED_MODULES_AFFECTED,
            12,
        );
        put_int(&mut state.task_features, keys::TASK_DEPENDENCY_FAN_OUT, 10);
        put_int(
            &mut state.task_features,
            keys::TASK_ESTIMATED_CONTEXT_SIZE,
            80_000,
        );
        state.task_features.insert(
            FeatureId::new(keys::TASK_SECURITY_SENSITIVITY).expect("id"),
            FeatureValue::Boolean(true),
        );
        state.task_features.insert(
            FeatureId::new(keys::TASK_PUBLIC_API_IMPACT).expect("id"),
            FeatureValue::Boolean(true),
        );
        state
    }

    fn gate(threshold: u16, overhead: i64) -> Stage1Gate {
        let economical = graph("cheap", "model-a");
        let baseline = graph("baseline", "model-a");
        let safe = MemorySafeSet::new([economical.policy_id.clone(), baseline.policy_id.clone()]);
        Stage1Gate {
            predictor: CheapDifficultyPredictor::new().with_threshold(threshold),
            safe_set: Box::new(safe),
            economical,
            baseline,
            config: TwoStageConfig {
                overhead_fraction_bp: 500,
                predicted_task_cost_micros: 10_000_000,
                scripted_overhead_micros: overhead,
            },
        }
    }

    #[test]
    fn confidently_easy_task_short_circuits_without_enumeration() {
        let mut gate = gate(8_000, 0);
        let decision = gate.decide(&easy_state()).expect("decide");
        assert_eq!(decision.path, StagePath::Stage1ShortCircuit);
        assert!(!decision.enumerated_candidates);
        assert_eq!(
            decision
                .policy
                .as_ref()
                .map(|policy| policy.policy().policy_id.as_str()),
            Some("cheap")
        );
        assert!(decision.prediction.confidently_below(8_000));
    }

    #[test]
    fn hard_task_escalates_to_stage2() {
        let mut gate = gate(3_500, 0);
        let decision = gate.decide(&hard_state()).expect("decide");
        assert_eq!(decision.path, StagePath::Stage2Full);
        assert!(decision.enumerated_candidates);
        assert!(decision.policy.is_none());
        assert!(!decision.prediction.confidently_below(3_500));
    }

    #[test]
    fn straddling_uncertainty_escalates_to_full_router() {
        let predictor = CheapDifficultyPredictor::new().with_threshold(2_000);
        let prediction = predictor.predict(&FeatureBag::new(), &FeatureBag::new());
        assert!(
            prediction.straddles(2_000) || prediction.lower_bp < 2_000,
            "empty features must be uncertain: {prediction:?}"
        );
        let mut gate = gate(2_000, 0);
        let mut state = OptimizerState::new(DecisionHorizon {
            now: TimestampMillis::from_millis(1),
            deadline: None,
            next_reset: None,
        });
        // One weak signal so the band is wide enough to straddle 2000.
        put_int(
            &mut state.task_features,
            keys::TASK_ESTIMATED_FILES_AFFECTED,
            2,
        );
        let decision = gate.decide(&state).expect("decide");
        assert!(
            decision.path == StagePath::Stage2Full || decision.prediction.straddles(2_000),
            "path={:?} pred={:?}",
            decision.path,
            decision.prediction
        );
        if decision.prediction.straddles(gate.predictor.threshold_bp()) {
            assert_eq!(decision.path, StagePath::Stage2Full);
            assert!(decision.enumerated_candidates);
            assert!(decision.policy.is_none());
        }
    }

    #[test]
    fn over_budget_decision_degrades_to_baseline() {
        let mut gate = gate(9_000, 9_000_000);
        let decision = gate.decide(&easy_state()).expect("decide");
        assert_eq!(decision.path, StagePath::OverheadDegraded);
        assert!(decision.overhead.exceeded);
        assert_eq!(
            decision
                .policy
                .as_ref()
                .map(|policy| policy.policy().policy_id.as_str()),
            Some("baseline")
        );
        assert!(!decision.enumerated_candidates);
    }

    #[test]
    fn stage1_cannot_return_a_policy_outside_the_safe_set() {
        let mut gate = gate(9_000, 0);
        gate.economical = graph("unsafe", "model-z");
        let err = gate.decide(&easy_state()).expect_err("outside");
        assert!(err.to_string().contains("outside the safe set"));
    }

    #[test]
    fn short_circuit_misroute_rate_is_derivable() {
        let mut predictor = CheapDifficultyPredictor::new();
        predictor.record_short_circuit(false);
        predictor.record_short_circuit(false);
        predictor.record_short_circuit(true);
        assert_eq!(predictor.misroute_rate_bp(), Some(3_333));
    }

    #[test]
    fn two_stage_router_records_stage1_path() {
        let mut predictor = ScriptedPredictor::new();
        predictor.insert(crate::optimizer::predictor::PolicyOutcomeDistribution::new(
            PolicyId::new("expensive").expect("id"),
            10,
            10,
            9_500,
            9_500,
        ));
        let stage2 = SafeContextualRouter::new(
            Box::new(predictor),
            Box::new(TailRiskObjective::new()),
            RouterConfig::default(),
        );
        let mut router = TwoStageRouter {
            stage1: gate(8_000, 0),
            stage2,
        };
        let decision = router
            .select_staged(&easy_state(), &[graph("expensive", "model-b")])
            .expect("select");
        assert_eq!(
            decision.selected_policy().map(PolicyId::as_str),
            Some("cheap")
        );
        assert_eq!(
            decision.diagnostics().stage_path.as_deref(),
            Some("stage1_short_circuit")
        );
        assert!(decision.diagnostics().difficulty_upper_bp.is_some());
    }
}
