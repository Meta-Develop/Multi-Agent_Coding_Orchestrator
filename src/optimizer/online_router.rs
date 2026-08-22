//! Online policy selection. Implemented by issues #167 and #168.
//!
//! Feasibility filtering runs before objective comparison. Quality is a hard
//! constraint: the router never silently weakens a contract, and an empty
//! feasible set is an explicit infeasible result that must not publish.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::action::CanonicalEffort;
use super::calibration::{constrain_candidates, CalibrationAuditor, CalibrationResponse};
use super::error::OptimizerError;
use super::explanation::{
    effort_rank, CandidatePrediction, ComparedPolicy, DecisionDiagnostics, DecisionExplanation,
    EscalationComparison, SelectedAction,
};
use super::feasibility::{ChanceConstraintChecker, FeasibilityConfig};
use super::hedge::{DelayedHedgePlanner, HedgePlan, HedgePlanner};
use super::ids::{PolicyId, ResourceDimensionId};
use super::objective::{ObjectiveEvaluator, ObjectiveValue};
use super::policy::{PolicyGraph, PolicyNode};
use super::predictor::{
    feature_bool, feature_keys, feature_text, insert_text, is_frontier_role, mean_i64,
    primary_action, PolicyOutcomeDistribution, PolicyPredictor,
};
use super::resources::Quantity;
use super::state::{OptimizerState, PosteriorSummary};
use super::switch_cost::{
    apply_switch_cost, current_action_from_candidates, estimate_switch, oscillation_count,
    trajectory_identities, SwitchCostEstimate, SwitchCostModel,
};
use super::taxonomy::{classify, TaxonomySpec};
use super::trajectory::{TrajectoryEvent, TrajectoryObservation};
use super::value_of_information::{
    is_probe_policy, EvidenceHandoff, ValueOfInformation, VoyDecision,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouterDecision {
    Select {
        policy_id: PolicyId,
        explanation: DecisionExplanation,
        diagnostics: DecisionDiagnostics,
    },
    Infeasible {
        reason: String,
        explanation: DecisionExplanation,
        diagnostics: DecisionDiagnostics,
    },
}

impl RouterDecision {
    pub fn may_merge(&self) -> bool {
        matches!(self, Self::Select { .. })
    }

    pub fn may_publish(&self) -> bool {
        self.may_merge()
    }

    pub fn explanation(&self) -> &DecisionExplanation {
        match self {
            Self::Select { explanation, .. } | Self::Infeasible { explanation, .. } => explanation,
        }
    }

    pub fn diagnostics(&self) -> &DecisionDiagnostics {
        match self {
            Self::Select { diagnostics, .. } | Self::Infeasible { diagnostics, .. } => diagnostics,
        }
    }

    pub fn selected_policy(&self) -> Option<&PolicyId> {
        match self {
            Self::Select { policy_id, .. } => Some(policy_id),
            Self::Infeasible { .. } => None,
        }
    }
}

pub trait OnlineRouter {
    fn select(
        &self,
        state: &OptimizerState,
        candidates: &[PolicyGraph],
    ) -> Result<RouterDecision, OptimizerError>;
}

/// Tail-risk-aware, shadow-priced objective.
///
/// `J = CVaR_0.95(T_cert) + Σ_p λ_p E[C_p] + λ_H E[H] + λ_U U`
///
/// Quality is not a term. Shadow prices are taken from the resource vector
/// at construction time because [`ObjectiveEvaluator::evaluate`] does not
/// receive `s_t` (that trait is owned by another lane).
#[derive(Debug, Clone, Default)]
pub struct TailRiskObjective {
    shadow_prices: BTreeMap<ResourceDimensionId, i64>,
    human_price: i64,
    uncertainty_price: i64,
}

impl TailRiskObjective {
    pub fn new() -> Self {
        Self {
            shadow_prices: BTreeMap::new(),
            human_price: 1,
            uncertainty_price: 1,
        }
    }

    pub fn from_state(state: &OptimizerState) -> Self {
        let mut objective = Self::new();
        for dimension in state.budget.dimensions() {
            objective
                .shadow_prices
                .insert(dimension.id.clone(), dimension.shadow_price);
        }
        if let Some(human) = state.budget.get(&ResourceDimensionId::well_known(
            ResourceDimensionId::HUMAN_MINUTES,
        )) {
            objective.human_price = human.shadow_price.max(1);
        }
        objective
    }

    pub fn set_uncertainty_price(&mut self, price: i64) {
        self.uncertainty_price = price.max(0);
    }

    pub fn set_human_price(&mut self, price: i64) {
        self.human_price = price.max(0);
    }
}

impl ObjectiveEvaluator for TailRiskObjective {
    fn evaluate(
        &self,
        distribution: &PolicyOutcomeDistribution,
    ) -> Result<ObjectiveValue, OptimizerError> {
        let cvar = if distribution.details.cvar95_latency_micros > 0 {
            distribution.details.cvar95_latency_micros
        } else {
            distribution.expected_latency_micros
        };
        let mut total = cvar;
        for (dimension, forecast) in &distribution.details.consumption {
            let expected = if forecast.samples.is_empty() {
                0
            } else {
                mean_i64(
                    &forecast
                        .samples
                        .iter()
                        .map(|sample| sample.as_i64())
                        .collect::<Vec<_>>(),
                )
            };
            let lambda = self.shadow_prices.get(dimension).copied().unwrap_or(0);
            total = total.saturating_add(lambda.saturating_mul(expected));
        }
        total = total.saturating_add(
            self.human_price
                .saturating_mul(distribution.details.expected_human_micros),
        );
        total = total.saturating_add(
            self.uncertainty_price
                .saturating_mul(distribution.details.uncertainty_micros),
        );
        Ok(ObjectiveValue {
            policy_id: distribution.policy_id.clone(),
            risk_adjusted_cost_micros: total,
            tail_latency_micros: cvar,
        })
    }
}

#[derive(Debug, Clone)]
pub struct RouterConfig {
    pub feasibility: FeasibilityConfig,
    pub permit_high_capability_fallback: bool,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            feasibility: FeasibilityConfig::default(),
            permit_high_capability_fallback: true,
        }
    }
}

/// Production contextual router. Provider-neutral: selection inputs are
/// evidence, constraints, and measured outcomes.
pub struct SafeContextualRouter {
    predictor: Box<dyn PolicyPredictor + Send + Sync>,
    feasibility: ChanceConstraintChecker,
    objective: Box<dyn ObjectiveEvaluator + Send + Sync>,
    voi: Option<Box<dyn ValueOfInformation + Send + Sync>>,
    config: RouterConfig,
    switch_costs: SwitchCostModel,
    calibration: Option<CalibrationResponse>,
    baseline_policy: Option<PolicyId>,
}

impl SafeContextualRouter {
    pub fn new(
        predictor: Box<dyn PolicyPredictor + Send + Sync>,
        objective: Box<dyn ObjectiveEvaluator + Send + Sync>,
        config: RouterConfig,
    ) -> Self {
        let feasibility = ChanceConstraintChecker::new(config.feasibility.clone());
        Self {
            predictor,
            feasibility,
            objective,
            voi: None,
            config,
            switch_costs: SwitchCostModel::new(),
            calibration: None,
            baseline_policy: None,
        }
    }

    pub fn with_voi(mut self, voi: Box<dyn ValueOfInformation + Send + Sync>) -> Self {
        self.voi = Some(voi);
        self
    }

    pub fn with_switch_costs(mut self, switch_costs: SwitchCostModel) -> Self {
        self.switch_costs = switch_costs;
        self
    }

    pub fn with_calibration(
        mut self,
        response: CalibrationResponse,
        baseline: Option<PolicyId>,
    ) -> Self {
        self.calibration = Some(response);
        self.baseline_policy = baseline;
        self
    }

    fn predict_all(
        &self,
        state: &OptimizerState,
        candidates: &[PolicyGraph],
    ) -> Result<Vec<(usize, PolicyOutcomeDistribution)>, OptimizerError> {
        let mut out = Vec::with_capacity(candidates.len());
        for (index, policy) in candidates.iter().enumerate() {
            out.push((index, self.predictor.predict(state, policy)?));
        }
        Ok(out)
    }

    fn classify(
        &self,
        state: &OptimizerState,
        candidates: &[PolicyGraph],
        predicted: &[(usize, PolicyOutcomeDistribution)],
    ) -> Result<ClassifiedCandidates, OptimizerError> {
        let mut classified = ClassifiedCandidates::default();
        let previous = current_action_from_candidates(state, candidates);
        for (index, distribution) in predicted {
            let policy = &candidates[*index];
            let feasibility = self
                .feasibility
                .check_predicted(state, policy, distribution)?;
            let switch = estimate_switch(&self.switch_costs, previous, policy);
            let objective = if feasibility.feasible {
                let mut value = self.objective.evaluate(distribution)?;
                apply_switch_cost(&mut value, &switch, self.switch_costs.hysteresis());
                Some(value)
            } else {
                None
            };
            classified.entries.push(ClassifiedCandidate {
                index: *index,
                distribution: distribution.clone(),
                feasibility,
                objective,
                switch,
            });
        }
        Ok(classified)
    }

    fn fallback_pass(
        &self,
        state: &OptimizerState,
        candidates: &[PolicyGraph],
        classified: &mut ClassifiedCandidates,
    ) -> Result<(), OptimizerError> {
        if classified.feasible().next().is_some() {
            return Ok(());
        }
        if !self.config.permit_high_capability_fallback {
            return Ok(());
        }

        // (1) permitted high-capability fallback — never a quality relaxation.
        for entry in &mut classified.entries {
            let policy = &candidates[entry.index];
            if entry.feasibility.feasible {
                continue;
            }
            if !quality_only_failed(&entry.feasibility.rejection_reasons)
                && is_high_capability_policy(policy)
                && !has_quality_rejection(&entry.feasibility.rejection_reasons)
            {
                entry.feasibility.rejection_reasons.push(
                    "considered_high_capability_fallback_but_resource_or_capability_blocked".into(),
                );
            }
        }

        // (2) increase verification strength where possible (prefer Audit/Certify).
        // (3) reduce nonessential concurrency — prefer policies whose actions
        // already have concurrency == 1.
        // Neither step may re-admit a quality-LCB failure.
        let _ = state;
        Ok(())
    }

    fn maybe_probe(
        &self,
        state: &OptimizerState,
        candidates: &[PolicyGraph],
        classified: &ClassifiedCandidates,
    ) -> Result<Option<VoyDecision>, OptimizerError> {
        let Some(voi) = self.voi.as_ref() else {
            return Ok(None);
        };
        let feasible_ids: Vec<PolicyId> = classified
            .feasible()
            .map(|entry| entry.distribution.policy_id.clone())
            .collect();
        let subset: Vec<PolicyGraph> = candidates
            .iter()
            .filter(|policy| feasible_ids.contains(&policy.policy_id) || is_probe_policy(policy))
            .cloned()
            .collect();
        match voi.evaluate_probe(state, &subset) {
            Ok(decision) if decision.should_execute() => Ok(Some(decision)),
            Ok(_) | Err(_) => Ok(None),
        }
    }
}

impl OnlineRouter for SafeContextualRouter {
    fn select(
        &self,
        state: &OptimizerState,
        candidates: &[PolicyGraph],
    ) -> Result<RouterDecision, OptimizerError> {
        let candidate_ids: Vec<PolicyId> = candidates
            .iter()
            .map(|policy| policy.policy_id.clone())
            .collect();
        let mut diagnostics = DecisionDiagnostics::new(state.horizon.now, candidate_ids);
        diagnostics.fill_reserves(&state.budget.snapshot(state.horizon.now));
        classify(
            &state.task_features,
            &state.repo_features,
            &TaxonomySpec::v1(),
        )
        .record_on(&mut diagnostics, None);
        diagnostics.oscillation_count =
            Some(oscillation_count(&trajectory_identities(state, candidates)));

        let restricted;
        let candidates: &[PolicyGraph] = if let Some(response) = &self.calibration {
            CalibrationAuditor::record_on(&mut diagnostics, response);
            match response.selection_constraint() {
                super::calibration::SelectionConstraint::FailClosed => {
                    return Ok(infeasible(state, diagnostics, "calibration_fail_closed"));
                }
                super::calibration::SelectionConstraint::RestrictToBaseline => {
                    restricted =
                        constrain_candidates(candidates, response, self.baseline_policy.as_ref())
                            .into_iter()
                            .cloned()
                            .collect::<Vec<_>>();
                    if restricted.is_empty() {
                        return Ok(infeasible(state, diagnostics, "calibration_no_baseline"));
                    }
                    &restricted
                }
                super::calibration::SelectionConstraint::Unrestricted => candidates,
            }
        } else {
            candidates
        };

        if candidates.is_empty() {
            return Ok(infeasible(state, diagnostics, "no_candidates"));
        }

        let predicted = self.predict_all(state, candidates)?;
        let mut classified = self.classify(state, candidates, &predicted)?;
        self.fallback_pass(state, candidates, &mut classified)?;

        for entry in &classified.entries {
            diagnostics.record_prediction(CandidatePrediction {
                policy: entry.distribution.policy_id.clone(),
                quality_lcb_bp: entry.distribution.quality_lower_confidence_bp,
                certified_probability_bp: entry.distribution.certified_probability_bp,
                expected_cost_micros: entry.distribution.expected_cost_micros,
                expected_latency_micros: entry.distribution.expected_latency_micros,
                tail_latency_p95_micros: entry.distribution.details.tail_latency_p95_micros,
                cvar95_latency_micros: entry.distribution.details.cvar95_latency_micros,
                objective_value_micros: entry
                    .objective
                    .as_ref()
                    .map(|value| value.risk_adjusted_cost_micros),
                feasible: entry.feasibility.feasible,
            });
            if !entry.feasibility.feasible {
                let reason = entry
                    .feasibility
                    .rejection_reasons
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "infeasible".into());
                diagnostics.reject(entry.distribution.policy_id.clone(), reason);
            }
        }

        if let Some(probe) = self.maybe_probe(state, candidates, &classified)? {
            if let Some(policy_id) = probe.probe_policy.clone() {
                if let Some(policy) = candidates
                    .iter()
                    .find(|policy| policy.policy_id == policy_id)
                {
                    return Ok(select_policy(
                        state,
                        policy,
                        classified.by_id(&policy_id),
                        diagnostics,
                        Some("probe"),
                        None,
                    ));
                }
            }
        }

        let mut feasible: Vec<&ClassifiedCandidate> = classified.feasible().collect();
        if feasible.is_empty() {
            diagnostics.continuation = Some("fail_closed".into());
            return Ok(infeasible(
                state,
                diagnostics,
                "no candidate satisfies the quality contract",
            ));
        }

        feasible.sort_by_key(|entry| {
            let objective = entry
                .objective
                .as_ref()
                .map(|value| value.risk_adjusted_cost_micros)
                .unwrap_or(i64::MAX);
            (objective, entry.distribution.policy_id.as_str().to_string())
        });
        let winner = feasible[0];
        for dominated in feasible.iter().skip(1) {
            diagnostics.reject(
                dominated.distribution.policy_id.clone(),
                "feasible_but_dominated_on_time_and_resource_use",
            );
        }
        let policy = &candidates[winner.index];
        Ok(select_policy(
            state,
            policy,
            Some(winner),
            diagnostics,
            Some("argmin_objective"),
            None,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContinuationKind {
    Continue,
    EscalateEffort,
    SwitchModel,
    PrecisionRepair,
    CleanRestart,
    Probe,
    Hedge,
    FailClosed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointDecision {
    pub kind: ContinuationKind,
    pub router: RouterDecision,
    pub escalation: Option<EscalationComparison>,
    pub handoff: Option<EvidenceHandoff>,
    pub hedge: Option<HedgePlan>,
}

/// Sequential selector: re-evaluate after every checkpoint using live trajectory.
pub struct CheckpointRouter {
    router: SafeContextualRouter,
    hedge: Option<DelayedHedgePlanner>,
}

impl CheckpointRouter {
    pub fn new(router: SafeContextualRouter) -> Self {
        Self {
            router,
            hedge: None,
        }
    }

    pub fn with_hedge(mut self, hedge: DelayedHedgePlanner) -> Self {
        self.hedge = Some(hedge);
        self
    }

    pub fn reoptimize(
        &self,
        state: &mut OptimizerState,
        candidates: &[PolicyGraph],
    ) -> Result<CheckpointDecision, OptimizerError> {
        update_posteriors(state);
        let evidence = classify_from_trajectory(state);
        let comparison = four_way_comparison(&self.router, state, candidates)?;
        let hedge = match self.hedge.as_ref() {
            Some(planner) => planner.plan(state)?,
            None => None,
        };

        if let Some(plan) = hedge.as_ref() {
            if plan.cancellation.is_none() {
                if let Some(policy) = candidates
                    .iter()
                    .find(|policy| policy.policy_id == plan.delayed_policy)
                {
                    let decision = self.router.select(state, std::slice::from_ref(policy))?;
                    return Ok(CheckpointDecision {
                        kind: ContinuationKind::Hedge,
                        router: annotate(decision, "hedge", Some(comparison.clone())),
                        escalation: Some(comparison),
                        handoff: None,
                        hedge,
                    });
                }
            }
        }

        let filtered = filter_candidates_for_evidence(candidates, &evidence);
        let decision = self.router.select(state, &filtered)?;
        let kind = continuation_kind(&decision, &evidence, candidates);
        let handoff = matches!(kind, ContinuationKind::CleanRestart)
            .then(|| EvidenceHandoff::from_trajectory(state));
        Ok(CheckpointDecision {
            kind,
            router: annotate(decision, kind_label(&kind), Some(comparison.clone())),
            escalation: Some(comparison),
            handoff,
            hedge,
        })
    }
}

impl OnlineRouter for CheckpointRouter {
    fn select(
        &self,
        state: &OptimizerState,
        candidates: &[PolicyGraph],
    ) -> Result<RouterDecision, OptimizerError> {
        let mut owned = state.clone();
        Ok(self.reoptimize(&mut owned, candidates)?.router)
    }
}

#[derive(Default)]
struct ClassifiedCandidates {
    entries: Vec<ClassifiedCandidate>,
}

impl ClassifiedCandidates {
    fn feasible(&self) -> impl Iterator<Item = &ClassifiedCandidate> {
        self.entries
            .iter()
            .filter(|entry| entry.feasibility.feasible)
    }

    fn by_id(&self, id: &PolicyId) -> Option<&ClassifiedCandidate> {
        self.entries
            .iter()
            .find(|entry| &entry.distribution.policy_id == id)
    }
}

struct ClassifiedCandidate {
    index: usize,
    distribution: PolicyOutcomeDistribution,
    feasibility: super::feasibility::FeasibilityResult,
    objective: Option<ObjectiveValue>,
    switch: SwitchCostEstimate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrajectoryClass {
    Progressing,
    LocalizedFailure,
    StructuralFailure,
    Stalled,
    Certified,
    Unknown,
}

fn classify_from_trajectory(state: &OptimizerState) -> TrajectoryClass {
    let Some(last) = state.trajectory.events().last() else {
        return TrajectoryClass::Unknown;
    };
    match last.observation {
        TrajectoryObservation::Progress | TrajectoryObservation::Started => {
            if continue_eligible(state) {
                TrajectoryClass::Progressing
            } else {
                TrajectoryClass::Stalled
            }
        }
        TrajectoryObservation::LocalizedFailure => TrajectoryClass::LocalizedFailure,
        TrajectoryObservation::StructuralFailure => TrajectoryClass::StructuralFailure,
        TrajectoryObservation::Certified => TrajectoryClass::Certified,
        TrajectoryObservation::NoProgress
        | TrajectoryObservation::QuotaPressure
        | TrajectoryObservation::TimeoutRisk
        | TrajectoryObservation::FailedCertification
        | TrajectoryObservation::HumanEscalationRequired => TrajectoryClass::Stalled,
    }
}

fn continue_eligible(state: &OptimizerState) -> bool {
    if feature_bool(&state.task_features, feature_keys::REPEATED_FAILURE) == Some(true) {
        return false;
    }
    let positives = [
        feature_keys::TEST_FAILURES_DECREASING,
        feature_keys::COMPILER_FAILURES_DECREASING,
        feature_keys::COVERAGE_INCREASING,
        feature_keys::DIFF_CHURN_BOUNDED,
    ];
    let known: Vec<bool> = positives
        .iter()
        .filter_map(|key| feature_bool(&state.task_features, key))
        .collect();
    if !known.is_empty() {
        return known.iter().all(|value| *value);
    }
    !repeated_failure_signature(state)
}

fn repeated_failure_signature(state: &OptimizerState) -> bool {
    let events = state.trajectory.events();
    if events.len() < 2 {
        return false;
    }
    let last = &events[events.len() - 1].observation;
    let prev = &events[events.len() - 2].observation;
    matches!(
        (last, prev),
        (
            TrajectoryObservation::LocalizedFailure,
            TrajectoryObservation::LocalizedFailure
        ) | (
            TrajectoryObservation::StructuralFailure,
            TrajectoryObservation::StructuralFailure
        )
    )
}

fn filter_candidates_for_evidence(
    candidates: &[PolicyGraph],
    evidence: &TrajectoryClass,
) -> Vec<PolicyGraph> {
    let filtered: Vec<PolicyGraph> = candidates
        .iter()
        .filter(|policy| match evidence {
            TrajectoryClass::LocalizedFailure => {
                is_precision_repair(policy) || !is_clean_restart(policy)
            }
            TrajectoryClass::StructuralFailure => {
                is_clean_restart(policy) || is_probe_policy(policy)
            }
            TrajectoryClass::Progressing => !is_clean_restart(policy),
            _ => true,
        })
        .cloned()
        .collect();
    if filtered.is_empty() {
        candidates.to_vec()
    } else {
        filtered
    }
}

fn is_precision_repair(policy: &PolicyGraph) -> bool {
    policy
        .nodes
        .values()
        .any(|node| matches!(node, PolicyNode::Repair(_)))
        && policy.topology.restart == super::action::RestartMode::Continuation
}

fn is_clean_restart(policy: &PolicyGraph) -> bool {
    policy.topology.restart == super::action::RestartMode::CleanRestart
}

fn is_high_capability_policy(policy: &PolicyGraph) -> bool {
    primary_action(policy).is_some_and(|action| is_frontier_role(&action.role))
}

fn has_quality_rejection(reasons: &[String]) -> bool {
    reasons
        .iter()
        .any(|reason| reason.starts_with("quality_lcb_below_threshold"))
}

fn quality_only_failed(reasons: &[String]) -> bool {
    !reasons.is_empty()
        && reasons
            .iter()
            .all(|reason| reason.starts_with("quality_lcb"))
}

fn continuation_kind(
    decision: &RouterDecision,
    evidence: &TrajectoryClass,
    candidates: &[PolicyGraph],
) -> ContinuationKind {
    let Some(policy_id) = decision.selected_policy() else {
        return ContinuationKind::FailClosed;
    };
    let Some(policy) = candidates
        .iter()
        .find(|policy| &policy.policy_id == policy_id)
    else {
        return ContinuationKind::FailClosed;
    };
    if is_probe_policy(policy) {
        return ContinuationKind::Probe;
    }
    if is_clean_restart(policy) {
        return ContinuationKind::CleanRestart;
    }
    if is_precision_repair(policy) && *evidence == TrajectoryClass::LocalizedFailure {
        return ContinuationKind::PrecisionRepair;
    }
    match evidence {
        TrajectoryClass::Progressing => ContinuationKind::Continue,
        TrajectoryClass::StructuralFailure => ContinuationKind::CleanRestart,
        TrajectoryClass::LocalizedFailure => ContinuationKind::PrecisionRepair,
        TrajectoryClass::Stalled => {
            if primary_action(policy).is_some_and(|action| {
                effort_rank(&action.effort) > effort_rank(&CanonicalEffort::Medium)
            }) {
                ContinuationKind::EscalateEffort
            } else {
                ContinuationKind::SwitchModel
            }
        }
        TrajectoryClass::Certified | TrajectoryClass::Unknown => ContinuationKind::Continue,
    }
}

fn kind_label(kind: &ContinuationKind) -> &'static str {
    match kind {
        ContinuationKind::Continue => "continue",
        ContinuationKind::EscalateEffort => "escalate_effort",
        ContinuationKind::SwitchModel => "switch_model",
        ContinuationKind::PrecisionRepair => "precision_repair",
        ContinuationKind::CleanRestart => "clean_restart",
        ContinuationKind::Probe => "probe",
        ContinuationKind::Hedge => "hedge",
        ContinuationKind::FailClosed => "fail_closed",
    }
}

fn four_way_comparison(
    router: &SafeContextualRouter,
    state: &OptimizerState,
    candidates: &[PolicyGraph],
) -> Result<EscalationComparison, OptimizerError> {
    let current_slug = feature_text(&state.task_features, feature_keys::CURRENT_POLICY);
    let current = current_slug
        .as_deref()
        .and_then(|id| {
            candidates
                .iter()
                .find(|policy| policy.policy_id.as_str() == id)
        })
        .or_else(|| candidates.first());
    let current_action = current.and_then(primary_action);
    let previous = current_action_from_candidates(state, candidates);

    let mut comparison = EscalationComparison {
        same_model_higher_effort: None,
        different_model_same_effort: None,
        different_model_higher_effort: None,
        clean_restart: None,
        selected: None,
    };

    for policy in candidates {
        let Some(action) = primary_action(policy) else {
            if is_clean_restart(policy) {
                if let Ok(predicted) = router.predictor.predict(state, policy) {
                    if let Ok(mut objective) = router.objective.evaluate(&predicted) {
                        let switch = estimate_switch(&router.switch_costs, previous, policy);
                        apply_switch_cost(
                            &mut objective,
                            &switch,
                            router.switch_costs.hysteresis(),
                        );
                        comparison.clean_restart =
                            Some(compared(policy, &predicted, &objective, &switch));
                    }
                }
            }
            continue;
        };
        let Some(current_action) = current_action else {
            continue;
        };
        let same_model =
            action.runtime_model.runtime_slug == current_action.runtime_model.runtime_slug;
        let higher = effort_rank(&action.effort) > effort_rank(&current_action.effort);
        let same_effort = action.effort == current_action.effort;
        let Ok(predicted) = router.predictor.predict(state, policy) else {
            continue;
        };
        let Ok(mut objective) = router.objective.evaluate(&predicted) else {
            continue;
        };
        let switch = estimate_switch(&router.switch_costs, previous, policy);
        apply_switch_cost(&mut objective, &switch, router.switch_costs.hysteresis());
        let slot = compared(policy, &predicted, &objective, &switch);
        if is_clean_restart(policy) {
            comparison.clean_restart = Some(slot);
        } else if same_model && higher {
            comparison.same_model_higher_effort = Some(slot);
        } else if !same_model && same_effort {
            comparison.different_model_same_effort = Some(slot);
        } else if !same_model && higher {
            comparison.different_model_higher_effort = Some(slot);
        }
    }
    Ok(comparison)
}

fn compared(
    policy: &PolicyGraph,
    predicted: &PolicyOutcomeDistribution,
    objective: &ObjectiveValue,
    switch: &SwitchCostEstimate,
) -> ComparedPolicy {
    let action = primary_action(policy);
    ComparedPolicy {
        policy: policy.policy_id.clone(),
        model: action
            .map(|action| action.runtime_model.runtime_slug.to_string())
            .unwrap_or_default(),
        effort: action
            .map(|action| action.effort.as_label().to_string())
            .unwrap_or_default(),
        objective_value_micros: objective.risk_adjusted_cost_micros,
        quality_lcb_bp: predicted.quality_lower_confidence_bp,
        switch_cost_micros: switch.total_cost_micros,
    }
}

fn update_posteriors(state: &mut OptimizerState) {
    if let Some(last) = state.trajectory.events().last() {
        let count = state
            .posteriors
            .get(&last.policy_id)
            .map(|summary| summary.observation_count.saturating_add(1))
            .unwrap_or(1);
        state.posteriors.insert(
            last.policy_id.clone(),
            PosteriorSummary {
                observation_count: count,
                last_updated: last.at,
            },
        );
        if let Ok(id) = super::ids::FeatureId::new(feature_keys::CURRENT_POLICY) {
            if state.task_features.get(&id).is_none() {
                insert_text(
                    &mut state.task_features,
                    feature_keys::CURRENT_POLICY,
                    last.policy_id.to_string(),
                );
            }
        }
    }
}

fn select_policy(
    state: &OptimizerState,
    policy: &PolicyGraph,
    classified: Option<&ClassifiedCandidate>,
    mut diagnostics: DecisionDiagnostics,
    continuation: Option<&str>,
    escalation: Option<EscalationComparison>,
) -> RouterDecision {
    diagnostics.selected_policy = Some(policy.policy_id.clone());
    if let Some(action) = primary_action(policy) {
        diagnostics.selected_action = Some(SelectedAction::from_model_action(action));
    }
    if let Some(entry) = classified {
        diagnostics.quality_lcb_bp = Some(entry.distribution.quality_lower_confidence_bp);
        diagnostics.predicted_p95_time_to_certification_micros =
            Some(entry.distribution.details.tail_latency_p95_micros);
        diagnostics.objective_value_micros = entry
            .objective
            .as_ref()
            .map(|value| value.risk_adjusted_cost_micros);
        for (dimension, forecast) in &entry.distribution.details.consumption {
            let expected = mean_i64(
                &forecast
                    .samples
                    .iter()
                    .map(|sample| sample.as_i64())
                    .collect::<Vec<_>>(),
            );
            diagnostics.record_consumption(dimension.as_str(), Quantity::new(expected));
        }
        diagnostics.switch_cost_micros = Some(entry.switch.total_cost_micros);
        diagnostics.switch_class = Some(entry.switch.class.as_str().to_string());
        diagnostics.switch_observation = Some(entry.switch.observation_label().to_string());
    }
    diagnostics.continuation = continuation.map(str::to_string);
    diagnostics.escalation_comparison = escalation;
    let explanation = DecisionExplanation::from_diagnostics(
        &diagnostics,
        state.budget.snapshot(state.horizon.now),
    );
    RouterDecision::Select {
        policy_id: policy.policy_id.clone(),
        explanation,
        diagnostics,
    }
}

fn infeasible(
    state: &OptimizerState,
    diagnostics: DecisionDiagnostics,
    reason: &str,
) -> RouterDecision {
    let explanation = DecisionExplanation::from_diagnostics(
        &diagnostics,
        state.budget.snapshot(state.horizon.now),
    );
    RouterDecision::Infeasible {
        reason: reason.to_string(),
        explanation,
        diagnostics,
    }
}

fn annotate(
    mut decision: RouterDecision,
    continuation: &str,
    escalation: Option<EscalationComparison>,
) -> RouterDecision {
    match &mut decision {
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
            diagnostics.continuation = Some(continuation.to_string());
            diagnostics.escalation_comparison = escalation;
            *explanation =
                DecisionExplanation::from_diagnostics(diagnostics, explanation.resources.clone());
        }
    }
    decision
}

pub fn push_observation(
    state: &mut OptimizerState,
    policy: PolicyId,
    observation: TrajectoryObservation,
) {
    state.trajectory.push(TrajectoryEvent {
        at: state.horizon.now,
        policy_id: policy,
        node_id: super::ids::PolicyNodeId::new("live").expect("node"),
        observation,
        features: Default::default(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::action::{
        AgentRole, ExecutionBudget, HedgeTopology, ModelAction, PlannerTopology, RestartMode,
        ReviewTopology, TopologySpec, WorkerTopology,
    };
    use crate::optimizer::feasibility::FeasibilityConfig;
    use crate::optimizer::ids::{
        BackendId, CatalogVersion, ModelFamilyId, PolicyNodeId, ProviderId, RuntimeSlug,
        TimestampMillis, VerifierProfileId,
    };
    use crate::optimizer::predictor::{
        insert_bool, insert_int, OutcomeDistributionDetails, ScriptedPredictor,
    };
    use crate::optimizer::resources::{
        ConsumptionForecast, ObservationKind, ResourceDimension, ResourceObservation,
        ResourceVector,
    };
    use crate::optimizer::state::DecisionHorizon;
    use crate::optimizer::value_of_information::ExpectedInformationGain;

    fn topology(restart: RestartMode) -> TopologySpec {
        TopologySpec {
            planner: PlannerTopology::Single,
            workers: WorkerTopology::One,
            hedge: HedgeTopology::None,
            review: ReviewTopology::Independent,
            restart,
        }
    }

    fn action(slug: &str, effort: CanonicalEffort, role: AgentRole) -> ModelAction {
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
            effort,
            role,
            max_turns: ExecutionBudget::default().max_turns,
            timeout_seconds: 60,
            tool_budget: None,
            output_token_budget: None,
            concurrency: 1,
            verifier_profile: VerifierProfileId::new("default").expect("profile"),
        }
    }

    fn execute_policy(
        id: &str,
        slug: &str,
        effort: CanonicalEffort,
        restart: RestartMode,
    ) -> PolicyGraph {
        node_policy(
            id,
            slug,
            effort,
            AgentRole::Worker,
            PolicyKind::Execute,
            restart,
        )
    }

    enum PolicyKind {
        Execute,
        Repair,
        Probe,
        Plan,
    }

    fn node_policy(
        id: &str,
        slug: &str,
        effort: CanonicalEffort,
        role: AgentRole,
        kind: PolicyKind,
        restart: RestartMode,
    ) -> PolicyGraph {
        let start = PolicyNodeId::new("start").expect("node");
        let mut graph = PolicyGraph::new(
            PolicyId::new(id).expect("policy"),
            1,
            start.clone(),
            topology(restart),
        );
        let model = action(slug, effort, role);
        let node = match kind {
            PolicyKind::Execute => PolicyNode::Execute(model),
            PolicyKind::Repair => PolicyNode::Repair(model),
            PolicyKind::Probe => PolicyNode::Probe(model),
            PolicyKind::Plan => PolicyNode::Plan(model),
        };
        graph.insert_node(start, node).expect("node");
        graph
    }

    fn capable_state() -> OptimizerState {
        let mut state = OptimizerState::new(DecisionHorizon {
            now: TimestampMillis::from_millis(1_000),
            deadline: Some(TimestampMillis::from_millis(1_000 + 3_600_000)),
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
        insert_text(&mut state.task_features, feature_keys::TASK_CLASS, "repair");
        insert_int(
            &mut state.task_features,
            feature_keys::QUALITY_DELTA_Q_BP,
            1_000,
        );
        let mut budget = ResourceVector::new();
        budget.insert(ResourceDimension {
            id: ResourceDimensionId::well_known(ResourceDimensionId::API_COST_USD),
            remaining: Quantity::new(1_000),
            reset_at: None,
            frontier_reserve: Quantity::new(10),
            emergency_margin: Quantity::new(0),
            uncertainty: Quantity::ZERO,
            shadow_price: 5,
            observation: ResourceObservation {
                kind: ObservationKind::Measured,
                confidence_bp: 10_000,
            },
            chance_epsilon_bp: 2_000,
            target_usage_bp: 5_000,
            learning_rate: 1_000,
        });
        state.budget = budget;
        state
    }

    fn dist(
        id: &str,
        lcb: u16,
        mean_latency: i64,
        cvar: i64,
        cost: i64,
        demand: i64,
    ) -> PolicyOutcomeDistribution {
        let mut details = OutcomeDistributionDetails {
            certified_by_deadline_lcb_bp: lcb,
            deadline_miss_probability_bp: 0,
            tail_latency_p95_micros: cvar.min(cvar),
            cvar95_latency_micros: cvar,
            expected_human_micros: 0,
            uncertainty_micros: (cvar - mean_latency).abs().max(1),
            ..OutcomeDistributionDetails::default()
        };
        details.consumption.insert(
            ResourceDimensionId::well_known(ResourceDimensionId::API_COST_USD),
            ConsumptionForecast {
                samples: vec![Quantity::new(demand), Quantity::new(demand)],
            },
        );
        details.time_to_cert_samples_micros = vec![mean_latency, cvar];
        PolicyOutcomeDistribution::new(PolicyId::new(id).expect("id"), cost, mean_latency, lcb, lcb)
            .with_details(details)
    }

    fn router(predictor: ScriptedPredictor) -> SafeContextualRouter {
        let mut objective = TailRiskObjective::new();
        objective.set_uncertainty_price(1);
        SafeContextualRouter::new(
            Box::new(predictor),
            Box::new(objective),
            RouterConfig {
                feasibility: FeasibilityConfig {
                    fail_closed_on_unobservable_capability: false,
                    ..FeasibilityConfig::default()
                },
                permit_high_capability_fallback: true,
            },
        )
    }

    #[test]
    fn lower_effort_selected_when_cheaper_cost_to_certification() {
        let mut predictor = ScriptedPredictor::new();
        predictor.insert(dist("low", 9_500, 4_000, 5_000, 100, 2));
        predictor.insert(dist("high", 9_500, 8_000, 9_000, 400, 6));
        let decision = router(predictor)
            .select(
                &capable_state(),
                &[
                    execute_policy(
                        "low",
                        "model-a",
                        CanonicalEffort::Low,
                        RestartMode::Continuation,
                    ),
                    execute_policy(
                        "high",
                        "model-a",
                        CanonicalEffort::High,
                        RestartMode::Continuation,
                    ),
                ],
            )
            .expect("select");
        assert_eq!(
            decision.selected_policy().map(PolicyId::as_str),
            Some("low")
        );
        assert!(decision.may_publish());
    }

    #[test]
    fn cheaper_below_quality_lcb_never_beats_certified() {
        let mut predictor = ScriptedPredictor::new();
        predictor.insert(dist("cheap", 4_000, 100, 100, 1, 1));
        predictor.insert(dist("certified", 9_200, 8_000, 8_500, 400, 3));
        let decision = router(predictor)
            .select(
                &capable_state(),
                &[
                    execute_policy(
                        "cheap",
                        "model-a",
                        CanonicalEffort::Low,
                        RestartMode::Continuation,
                    ),
                    execute_policy(
                        "certified",
                        "model-b",
                        CanonicalEffort::Medium,
                        RestartMode::Continuation,
                    ),
                ],
            )
            .expect("select");
        assert_eq!(
            decision.selected_policy().map(PolicyId::as_str),
            Some("certified")
        );
        assert!(decision
            .diagnostics()
            .rejected_candidates
            .iter()
            .any(|rejected| rejected.policy.as_str() == "cheap"
                && rejected.reason.contains("quality_lcb")));
    }

    #[test]
    fn no_feasible_candidate_is_infeasible_and_cannot_publish() {
        let mut predictor = ScriptedPredictor::new();
        predictor.insert(dist("cheap", 1_000, 10, 10, 1, 1));
        let decision = router(predictor)
            .select(
                &capable_state(),
                &[execute_policy(
                    "cheap",
                    "model-a",
                    CanonicalEffort::Low,
                    RestartMode::Continuation,
                )],
            )
            .expect("select");
        assert!(matches!(decision, RouterDecision::Infeasible { .. }));
        assert!(!decision.may_merge());
        assert!(!decision.may_publish());
    }

    #[test]
    fn worse_cvar_is_penalised_over_lower_mean() {
        let mut predictor = ScriptedPredictor::new();
        predictor.insert(dist("fast-tail", 9_500, 100, 50_000, 10, 1));
        predictor.insert(dist("steady", 9_500, 300, 400, 10, 1));
        let decision = router(predictor)
            .select(
                &capable_state(),
                &[
                    execute_policy(
                        "fast-tail",
                        "model-a",
                        CanonicalEffort::Low,
                        RestartMode::Continuation,
                    ),
                    execute_policy(
                        "steady",
                        "model-b",
                        CanonicalEffort::Low,
                        RestartMode::Continuation,
                    ),
                ],
            )
            .expect("select");
        assert_eq!(
            decision.selected_policy().map(PolicyId::as_str),
            Some("steady")
        );
    }

    #[test]
    fn decision_records_predictions_feasibility_objective_and_rejections() {
        let mut predictor = ScriptedPredictor::new();
        predictor.insert(dist("keep", 9_800, 1_000, 1_100, 20, 1));
        predictor.insert(dist("drop", 3_000, 10, 10, 1, 1));
        let decision = router(predictor)
            .select(
                &capable_state(),
                &[
                    execute_policy(
                        "keep",
                        "model-a",
                        CanonicalEffort::Medium,
                        RestartMode::Continuation,
                    ),
                    execute_policy(
                        "drop",
                        "model-b",
                        CanonicalEffort::High,
                        RestartMode::Continuation,
                    ),
                ],
            )
            .expect("select");
        let diagnostics = decision.diagnostics();
        assert_eq!(diagnostics.candidate_predictions.len(), 2);
        assert!(diagnostics.quality_lcb_bp.unwrap() >= 9_800);
        assert!(diagnostics.objective_value_micros.is_some());
        assert!(diagnostics.selected_action.is_some());
        assert!(decision.explanation().diagnostics_json().is_some());
        let json = decision.explanation().diagnostics_json().expect("json");
        assert!(json.contains("selected_policy"));
        assert!(json.contains("rejected_candidates"));
    }

    #[test]
    fn quality_is_never_weakened_in_fallback() {
        let mut predictor = ScriptedPredictor::new();
        predictor.insert(dist("weak", 1_000, 10, 10, 1, 1));
        let mut config = RouterConfig::default();
        config.feasibility.fail_closed_on_unobservable_capability = false;
        let router = SafeContextualRouter::new(
            Box::new(predictor),
            Box::new(TailRiskObjective::new()),
            config,
        );
        let decision = router
            .select(
                &capable_state(),
                &[execute_policy(
                    "weak",
                    "model-a",
                    CanonicalEffort::Low,
                    RestartMode::Continuation,
                )],
            )
            .expect("select");
        assert!(matches!(decision, RouterDecision::Infeasible { .. }));
    }

    struct FlipPredictor;

    impl PolicyPredictor for FlipPredictor {
        fn predict(
            &self,
            state: &OptimizerState,
            policy: &PolicyGraph,
        ) -> Result<PolicyOutcomeDistribution, OptimizerError> {
            let informed = !state.trajectory.is_empty();
            let cost = if is_probe_policy(policy) {
                50
            } else if informed {
                200
            } else {
                10_000
            };
            Ok(dist(policy.policy_id.as_str(), 9_500, cost, cost, cost, 1))
        }
    }

    #[test]
    fn positive_voi_probe_is_selected() {
        let voi = ExpectedInformationGain::new(
            Box::new(FlipPredictor),
            Box::new(TailRiskObjective::new()),
        );
        let mut predictor = ScriptedPredictor::new();
        predictor.insert(dist("worker", 9_500, 10_000, 10_000, 10_000, 1));
        predictor.insert(dist("probe", 9_500, 50, 50, 50, 1));
        let router = router(predictor).with_voi(Box::new(voi));
        let decision = router
            .select(
                &capable_state(),
                &[
                    execute_policy(
                        "worker",
                        "model-a",
                        CanonicalEffort::Low,
                        RestartMode::Continuation,
                    ),
                    node_policy(
                        "probe",
                        "model-a",
                        CanonicalEffort::Minimal,
                        AgentRole::Researcher,
                        PolicyKind::Probe,
                        RestartMode::Continuation,
                    ),
                ],
            )
            .expect("select");
        assert_eq!(
            decision.selected_policy().map(PolicyId::as_str),
            Some("probe")
        );
    }

    #[test]
    fn localized_failure_is_eligible_for_precision_repair() {
        let mut predictor = ScriptedPredictor::new();
        predictor.insert(dist("continue", 9_500, 5_000, 5_000, 50, 1));
        predictor.insert(dist("repair", 9_500, 800, 900, 10, 1));
        let checkpoint = CheckpointRouter::new(router(predictor));
        let mut state = capable_state();
        push_observation(
            &mut state,
            PolicyId::new("continue").expect("p"),
            TrajectoryObservation::LocalizedFailure,
        );
        let decision = checkpoint
            .reoptimize(
                &mut state,
                &[
                    execute_policy(
                        "continue",
                        "model-a",
                        CanonicalEffort::Medium,
                        RestartMode::Continuation,
                    ),
                    node_policy(
                        "repair",
                        "model-a",
                        CanonicalEffort::Low,
                        AgentRole::Repairer,
                        PolicyKind::Repair,
                        RestartMode::Continuation,
                    ),
                ],
            )
            .expect("reopt");
        assert_eq!(decision.kind, ContinuationKind::PrecisionRepair);
        assert_eq!(
            decision.router.selected_policy().map(PolicyId::as_str),
            Some("repair")
        );
        assert!(
            decision
                .router
                .diagnostics()
                .escalation_comparison
                .is_some()
                || decision.escalation.is_some()
        );
        assert!(decision.router.may_publish());
    }

    #[test]
    fn structural_failure_is_eligible_for_clean_restart() {
        let mut predictor = ScriptedPredictor::new();
        predictor.insert(dist("stuck", 9_500, 9_000, 9_000, 80, 1));
        predictor.insert(dist("restart", 9_500, 2_000, 2_200, 30, 1));
        let checkpoint = CheckpointRouter::new(router(predictor));
        let mut state = capable_state();
        push_observation(
            &mut state,
            PolicyId::new("stuck").expect("p"),
            TrajectoryObservation::StructuralFailure,
        );
        let decision = checkpoint
            .reoptimize(
                &mut state,
                &[
                    execute_policy(
                        "stuck",
                        "model-a",
                        CanonicalEffort::Medium,
                        RestartMode::Continuation,
                    ),
                    node_policy(
                        "restart",
                        "model-b",
                        CanonicalEffort::High,
                        AgentRole::Planner,
                        PolicyKind::Plan,
                        RestartMode::CleanRestart,
                    ),
                ],
            )
            .expect("reopt");
        assert_eq!(decision.kind, ContinuationKind::CleanRestart);
        assert_eq!(
            decision.router.selected_policy().map(PolicyId::as_str),
            Some("restart")
        );
        assert!(decision.handoff.is_some());
        assert!(decision.handoff.expect("handoff").is_evidence_only());
    }

    #[test]
    fn escalation_records_four_way_comparison() {
        let mut predictor = ScriptedPredictor::new();
        predictor.insert(dist("current", 9_500, 4_000, 4_000, 40, 1));
        predictor.insert(dist("same-hi", 9_500, 3_500, 3_500, 35, 1));
        predictor.insert(dist("other", 9_500, 3_000, 3_000, 30, 1));
        predictor.insert(dist("other-hi", 9_500, 2_800, 2_800, 28, 1));
        predictor.insert(dist("restart", 9_500, 6_000, 6_000, 60, 1));
        let checkpoint = CheckpointRouter::new(router(predictor));
        let mut state = capable_state();
        insert_text(
            &mut state.task_features,
            feature_keys::CURRENT_POLICY,
            "current",
        );
        push_observation(
            &mut state,
            PolicyId::new("current").expect("p"),
            TrajectoryObservation::NoProgress,
        );
        let decision = checkpoint
            .reoptimize(
                &mut state,
                &[
                    execute_policy(
                        "current",
                        "model-a",
                        CanonicalEffort::Low,
                        RestartMode::Continuation,
                    ),
                    execute_policy(
                        "same-hi",
                        "model-a",
                        CanonicalEffort::High,
                        RestartMode::Continuation,
                    ),
                    execute_policy(
                        "other",
                        "model-b",
                        CanonicalEffort::Low,
                        RestartMode::Continuation,
                    ),
                    execute_policy(
                        "other-hi",
                        "model-b",
                        CanonicalEffort::High,
                        RestartMode::Continuation,
                    ),
                    node_policy(
                        "restart",
                        "model-c",
                        CanonicalEffort::Max,
                        AgentRole::Planner,
                        PolicyKind::Plan,
                        RestartMode::CleanRestart,
                    ),
                ],
            )
            .expect("reopt");
        let comparison = decision.escalation.expect("comparison");
        assert!(comparison.same_model_higher_effort.is_some());
        assert!(comparison.different_model_same_effort.is_some());
        assert!(comparison.different_model_higher_effort.is_some());
        assert!(comparison.clean_restart.is_some());
        assert_eq!(
            comparison
                .same_model_higher_effort
                .as_ref()
                .expect("same")
                .switch_cost_micros,
            0
        );
        assert!(
            comparison
                .different_model_same_effort
                .as_ref()
                .expect("other")
                .switch_cost_micros
                > 0
        );
        assert!(
            comparison
                .clean_restart
                .as_ref()
                .expect("restart")
                .switch_cost_micros
                > 0
        );
        assert!(decision.router.explanation().diagnostics_json().is_some());
    }

    #[test]
    fn switch_smaller_than_switch_cost_is_not_selected() {
        let mut predictor = ScriptedPredictor::new();
        predictor.insert(dist("keep", 9_500, 5_000, 5_000, 50, 1));
        predictor.insert(dist("swap", 9_500, 4_900, 4_900, 40, 1));
        let mut state = capable_state();
        insert_text(
            &mut state.task_features,
            feature_keys::CURRENT_POLICY,
            "keep",
        );
        let decision = router(predictor)
            .select(
                &state,
                &[
                    execute_policy(
                        "keep",
                        "model-a",
                        CanonicalEffort::Low,
                        RestartMode::Continuation,
                    ),
                    execute_policy(
                        "swap",
                        "model-b",
                        CanonicalEffort::Low,
                        RestartMode::Continuation,
                    ),
                ],
            )
            .expect("select");
        assert_eq!(
            decision.selected_policy().map(PolicyId::as_str),
            Some("keep")
        );
        let swap = decision
            .diagnostics()
            .candidate_predictions
            .iter()
            .find(|pred| pred.policy.as_str() == "swap")
            .expect("swap pred");
        let keep = decision
            .diagnostics()
            .candidate_predictions
            .iter()
            .find(|pred| pred.policy.as_str() == "keep")
            .expect("keep pred");
        assert!(
            swap.objective_value_micros.unwrap_or(0) > keep.objective_value_micros.unwrap_or(0),
            "switch cost must dominate the 100µs predicted gain"
        );
        assert_eq!(
            decision.diagnostics().switch_class.as_deref(),
            Some("continue")
        );
        assert_eq!(decision.diagnostics().switch_cost_micros, Some(0));
    }

    #[test]
    fn continue_when_progress_is_improving() {
        let mut predictor = ScriptedPredictor::new();
        predictor.insert(dist("current", 9_800, 1_000, 1_100, 10, 1));
        predictor.insert(dist("restart", 9_500, 900, 1_000, 9, 1));
        let checkpoint = CheckpointRouter::new(router(predictor));
        let mut state = capable_state();
        insert_bool(
            &mut state.task_features,
            feature_keys::TEST_FAILURES_DECREASING,
            true,
        );
        insert_bool(
            &mut state.task_features,
            feature_keys::COMPILER_FAILURES_DECREASING,
            true,
        );
        insert_bool(
            &mut state.task_features,
            feature_keys::COVERAGE_INCREASING,
            true,
        );
        insert_bool(
            &mut state.task_features,
            feature_keys::DIFF_CHURN_BOUNDED,
            true,
        );
        insert_text(
            &mut state.task_features,
            feature_keys::CURRENT_POLICY,
            "current",
        );
        push_observation(
            &mut state,
            PolicyId::new("current").expect("p"),
            TrajectoryObservation::Progress,
        );
        let decision = checkpoint
            .reoptimize(
                &mut state,
                &[
                    execute_policy(
                        "current",
                        "model-a",
                        CanonicalEffort::Medium,
                        RestartMode::Continuation,
                    ),
                    node_policy(
                        "restart",
                        "model-b",
                        CanonicalEffort::High,
                        AgentRole::Planner,
                        PolicyKind::Plan,
                        RestartMode::CleanRestart,
                    ),
                ],
            )
            .expect("reopt");
        assert_eq!(decision.kind, ContinuationKind::Continue);
        assert_eq!(
            decision.router.selected_policy().map(PolicyId::as_str),
            Some("current")
        );
    }

    #[test]
    fn calibration_fail_closed_is_infeasible_and_records_the_metric() {
        let mut predictor = ScriptedPredictor::new();
        predictor.insert(dist("cheap", 9_500, 10, 10, 1, 1));
        let response = crate::optimizer::calibration::CalibrationResponse {
            fail_closed: true,
            triggering_metric: Some("ece_bp".into()),
            steps: vec![
                crate::optimizer::calibration::MiscalibrationStep::FailClosed {
                    metric: "ece_bp".into(),
                },
            ],
            ..crate::optimizer::calibration::CalibrationResponse::default()
        };
        let decision = router(predictor)
            .with_calibration(response, None)
            .select(
                &capable_state(),
                &[execute_policy(
                    "cheap",
                    "model-a",
                    CanonicalEffort::Low,
                    RestartMode::Continuation,
                )],
            )
            .expect("select");
        assert!(matches!(
            decision,
            RouterDecision::Infeasible {
                ref reason,
                ..
            } if reason == "calibration_fail_closed"
        ));
        assert!(!decision.may_publish());
        assert_eq!(
            decision.diagnostics().calibration_metric.as_deref(),
            Some("ece_bp")
        );
        assert_eq!(
            decision.diagnostics().calibration_step.as_deref(),
            Some("fail_closed")
        );
    }
}
