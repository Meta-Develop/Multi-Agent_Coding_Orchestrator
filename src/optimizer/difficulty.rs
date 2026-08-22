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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// Which predictor stage produced a difficulty verdict.
///
/// [`PredictorStage::Cheap`] is the calibrated first stage. It never calls a
/// model. [`PredictorStage::Full`] is the existing phase-4 router.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PredictorStage {
    Cheap,
    Full,
}

impl PredictorStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cheap => "cheap",
            Self::Full => "full",
        }
    }
}

/// Verdict from [`CheapPredictorStage`]. Candidates are never enumerated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PredictorStageVerdict {
    pub stage: PredictorStage,
    pub prediction: DifficultyPrediction,
    pub short_circuit: bool,
}

/// Cheap first-stage difficulty predictor (#200).
///
/// Pure and deterministic over static #163 features only. It may skip full
/// deliberation; it never selects a policy or relaxes a quality constraint.
#[derive(Debug, Clone)]
pub struct CheapPredictorStage {
    predictor: CheapDifficultyPredictor,
}

impl Default for CheapPredictorStage {
    fn default() -> Self {
        Self {
            predictor: CheapDifficultyPredictor::new(),
        }
    }
}

impl CheapPredictorStage {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_predictor(predictor: CheapDifficultyPredictor) -> Self {
        Self { predictor }
    }

    pub fn with_threshold(mut self, threshold_bp: u16) -> Self {
        self.predictor = self.predictor.with_threshold(threshold_bp);
        self
    }

    pub fn threshold_bp(&self) -> u16 {
        self.predictor.threshold_bp()
    }

    pub fn predictor(&self) -> &CheapDifficultyPredictor {
        &self.predictor
    }

    pub fn predictor_mut(&mut self) -> &mut CheapDifficultyPredictor {
        &mut self.predictor
    }

    pub fn into_predictor(self) -> CheapDifficultyPredictor {
        self.predictor
    }

    pub fn predict(&self, task: &FeatureBag, repo: &FeatureBag) -> DifficultyPrediction {
        self.predictor.predict(task, repo)
    }

    /// Classify the task. Confidently-easy work stays on the cheap stage;
    /// a straddling or high band escalates to the full router.
    pub fn decide(&self, task: &FeatureBag, repo: &FeatureBag) -> PredictorStageVerdict {
        let prediction = self.predict(task, repo);
        if prediction.confidently_below(self.threshold_bp()) {
            PredictorStageVerdict {
                stage: PredictorStage::Cheap,
                prediction,
                short_circuit: true,
            }
        } else {
            PredictorStageVerdict {
                stage: PredictorStage::Full,
                prediction,
                short_circuit: false,
            }
        }
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

/// Explicit ceiling on the router's own decision cost (#200).
///
/// The ceiling is a fraction of predicted task cost. Wall-clock microseconds
/// and any tokens spent on the decision itself are recorded; exceeding the
/// ceiling is a measured degradation, not a free routing step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterCostBudget {
    pub fraction_bp: u16,
    pub predicted_task_cost_micros: i64,
    pub wall_clock_micros: i64,
    #[serde(default)]
    pub decision_tokens: i64,
}

impl Default for RouterCostBudget {
    fn default() -> Self {
        Self {
            fraction_bp: DEFAULT_OVERHEAD_FRACTION_BP,
            predicted_task_cost_micros: 10_000_000,
            wall_clock_micros: 0,
            decision_tokens: 0,
        }
    }
}

impl RouterCostBudget {
    pub fn new(fraction_bp: u16, predicted_task_cost_micros: i64) -> Self {
        Self {
            fraction_bp: fraction_bp.min(10_000),
            predicted_task_cost_micros,
            wall_clock_micros: 0,
            decision_tokens: 0,
        }
    }

    pub fn with_wall_clock(mut self, wall_clock_micros: i64) -> Self {
        self.wall_clock_micros = wall_clock_micros;
        self
    }

    pub fn with_decision_tokens(mut self, decision_tokens: i64) -> Self {
        self.decision_tokens = decision_tokens;
        self
    }

    pub fn ceiling_micros(&self) -> i64 {
        self.predicted_task_cost_micros
            .saturating_mul(i64::from(self.fraction_bp))
            / 10_000
    }

    pub fn exceeded(&self) -> bool {
        self.wall_clock_micros > self.ceiling_micros()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwoStageConfig {
    pub overhead_fraction_bp: u16,
    pub predicted_task_cost_micros: i64,
    pub scripted_overhead_micros: i64,
    /// Explicit ceiling on the cost of the routing decision itself.
    #[serde(default)]
    pub router_cost_budget: RouterCostBudget,
}

impl Default for TwoStageConfig {
    fn default() -> Self {
        let router_cost_budget = RouterCostBudget::default();
        Self {
            overhead_fraction_bp: router_cost_budget.fraction_bp,
            predicted_task_cost_micros: router_cost_budget.predicted_task_cost_micros,
            scripted_overhead_micros: router_cost_budget.wall_clock_micros,
            router_cost_budget,
        }
    }
}

impl TwoStageConfig {
    pub fn budget_micros(&self) -> i64 {
        self.resolved_router_cost_budget().ceiling_micros()
    }

    pub fn overhead_exceeded(&self) -> bool {
        self.resolved_router_cost_budget().exceeded()
    }

    /// Prefer the explicit [`Self::router_cost_budget`] field; fill gaps from
    /// the older scripted fields so existing fixtures keep working.
    pub fn resolved_router_cost_budget(&self) -> RouterCostBudget {
        let mut budget = self.router_cost_budget;
        if budget.fraction_bp == 0 {
            budget.fraction_bp = self.overhead_fraction_bp;
        }
        if budget.predicted_task_cost_micros <= 0 {
            budget.predicted_task_cost_micros = self.predicted_task_cost_micros;
        }
        if budget.wall_clock_micros == 0 {
            budget.wall_clock_micros = self.scripted_overhead_micros;
        }
        budget
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionOverhead {
    pub wall_clock_micros: i64,
    #[serde(default)]
    pub decision_tokens: i64,
    pub predicted_task_cost_micros: i64,
    pub budget_micros: i64,
    pub exceeded: bool,
}

impl DecisionOverhead {
    pub fn from_config(config: &TwoStageConfig) -> Self {
        Self::from_budget(&config.resolved_router_cost_budget())
    }

    pub fn from_budget(budget: &RouterCostBudget) -> Self {
        Self {
            wall_clock_micros: budget.wall_clock_micros,
            decision_tokens: budget.decision_tokens,
            predicted_task_cost_micros: budget.predicted_task_cost_micros,
            budget_micros: budget.ceiling_micros(),
            exceeded: budget.exceeded(),
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
    pub fn cheap_predictor_stage(&self) -> CheapPredictorStage {
        CheapPredictorStage::from_predictor(self.predictor.clone())
    }

    pub fn decide(&mut self, state: &OptimizerState) -> Result<Stage1Decision, OptimizerError> {
        let economical = SafePolicy::admit(self.economical.clone(), self.safe_set.as_ref())?;
        let baseline = SafePolicy::admit(self.baseline.clone(), self.safe_set.as_ref())?;
        let verdict = self
            .cheap_predictor_stage()
            .decide(&state.task_features, &state.repo_features);
        let prediction = verdict.prediction;
        if self.config.predicted_task_cost_micros <= 0 {
            self.config.predicted_task_cost_micros = predicted_task_cost_micros(state);
        }
        if self.config.router_cost_budget.predicted_task_cost_micros <= 0 {
            self.config.router_cost_budget.predicted_task_cost_micros =
                self.config.predicted_task_cost_micros;
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
        if verdict.short_circuit {
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
            return Ok(select_resolved_policy(
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
            return Ok(select_resolved_policy(
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
            let router = select_resolved_policy(
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
pub fn select_resolved_policy(
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
                router_cost_budget: RouterCostBudget::new(500, 10_000_000)
                    .with_wall_clock(overhead),
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
    fn cheap_predictor_stage_short_circuits_confidently_easy_tasks() {
        let stage = CheapPredictorStage::new().with_threshold(8_000);
        let state = easy_state();
        let verdict = stage.decide(&state.task_features, &state.repo_features);
        assert_eq!(verdict.stage, PredictorStage::Cheap);
        assert!(verdict.short_circuit);
        assert!(verdict.prediction.confidently_below(8_000));
        assert!(verdict.prediction.upper_bp >= verdict.prediction.score_bp);
    }

    #[test]
    fn cheap_predictor_stage_escalates_when_uncertainty_straddles() {
        let stage = CheapPredictorStage::new().with_threshold(2_000);
        let mut task = FeatureBag::new();
        put_int(&mut task, keys::TASK_ESTIMATED_FILES_AFFECTED, 2);
        let verdict = stage.decide(&task, &FeatureBag::new());
        assert!(
            verdict.prediction.straddles(2_000) || !verdict.prediction.confidently_below(2_000),
            "pred={:?}",
            verdict.prediction
        );
        if verdict.prediction.straddles(2_000) {
            assert_eq!(verdict.stage, PredictorStage::Full);
            assert!(!verdict.short_circuit);
        }
    }

    #[test]
    fn router_cost_budget_is_an_explicit_fraction_of_predicted_task_cost() {
        let budget = RouterCostBudget::new(500, 10_000_000)
            .with_wall_clock(9_000_000)
            .with_decision_tokens(12);
        assert_eq!(budget.ceiling_micros(), 500_000);
        assert!(budget.exceeded());
        assert_eq!(budget.decision_tokens, 12);

        let config = TwoStageConfig {
            overhead_fraction_bp: 500,
            predicted_task_cost_micros: 10_000_000,
            scripted_overhead_micros: 9_000_000,
            router_cost_budget: budget,
        };
        assert_eq!(config.router_cost_budget, budget);
        assert_eq!(config.budget_micros(), 500_000);
        let overhead = DecisionOverhead::from_config(&config);
        assert!(overhead.exceeded);
        assert_eq!(overhead.decision_tokens, 12);
        assert_eq!(overhead.budget_micros, 500_000);
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
