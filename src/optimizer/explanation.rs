//! Machine-readable decision explanations. Consumed by #167 and replay (#166).
//!
//! [`DecisionExplanation`] keeps the field set the resource-accounting tests
//! construct. Richer diagnostics live in [`DecisionDiagnostics`] and are also
//! flattened into the explanation envelope so a replay record stays complete.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::action::{AgentRole, CanonicalEffort, ModelAction};
use super::ids::{PolicyId, TimestampMillis};
use super::resources::{DispatchDecision, Quantity, ResourceSnapshot};
use super::switch_cost::SwitchCostEstimate;

/// Stable envelope stored on [`super::replay::ReplayRecord`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionExplanation {
    pub decided_at: TimestampMillis,
    pub selected: Option<PolicyId>,
    pub candidate_ids: Vec<PolicyId>,
    pub rejection_reasons: Vec<String>,
    pub resources: ResourceSnapshot,
}

impl DecisionExplanation {
    pub fn record_dispatch(&mut self, decision: &DispatchDecision) {
        if let Some(reason) = decision.rejection_reason() {
            self.rejection_reasons.push(reason.to_string());
        }
    }

    /// Flatten diagnostics into the replay envelope without adding fields.
    pub fn from_diagnostics(
        diagnostics: &DecisionDiagnostics,
        resources: ResourceSnapshot,
    ) -> Self {
        let mut rejection_reasons: Vec<String> = diagnostics
            .rejected_candidates
            .iter()
            .map(|rejected| format!("{}: {}", rejected.policy, rejected.reason))
            .collect();
        if let Ok(json) = serde_json::to_string(diagnostics) {
            rejection_reasons.insert(0, format!("diagnostics_json={json}"));
        }
        Self {
            decided_at: diagnostics.decided_at,
            selected: diagnostics.selected_policy.clone(),
            candidate_ids: diagnostics.candidate_ids.clone(),
            rejection_reasons,
            resources,
        }
    }

    pub fn diagnostics_json(&self) -> Option<&str> {
        self.rejection_reasons
            .iter()
            .find_map(|reason| reason.strip_prefix("diagnostics_json="))
    }
}

/// Production decision record. Diagnostic evidence, not a proof of optimality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionDiagnostics {
    pub decided_at: TimestampMillis,
    pub selected_policy: Option<PolicyId>,
    pub selected_action: Option<SelectedAction>,
    pub quality_lcb_bp: Option<u16>,
    pub predicted_p95_time_to_certification_micros: Option<i64>,
    pub predicted_consumption: BTreeMap<String, i64>,
    pub reserves_after_selection: BTreeMap<String, i64>,
    pub objective_value_micros: Option<i64>,
    pub rejected_candidates: Vec<RejectedCandidate>,
    pub candidate_ids: Vec<PolicyId>,
    pub candidate_predictions: Vec<CandidatePrediction>,
    pub continuation: Option<String>,
    pub escalation_comparison: Option<EscalationComparison>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taxonomy_version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taxonomy_cell: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taxonomy_confidence_bp: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommendation_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_observations: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub switch_cost_micros: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub switch_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub switch_observation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub switch_cost_applied_micros: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub switch_cost_evidence: Option<SwitchCostEstimate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub switch_hysteresis_margin_bp: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oscillation_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oscillation_alarm_threshold: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oscillation_alarm: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub difficulty_score_bp: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub difficulty_lower_bp: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub difficulty_upper_bp: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_overhead_micros: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overhead_degraded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calibration_step: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calibration_metric: Option<String>,
}

impl DecisionDiagnostics {
    pub fn new(decided_at: TimestampMillis, candidate_ids: Vec<PolicyId>) -> Self {
        Self {
            decided_at,
            selected_policy: None,
            selected_action: None,
            quality_lcb_bp: None,
            predicted_p95_time_to_certification_micros: None,
            predicted_consumption: BTreeMap::new(),
            reserves_after_selection: BTreeMap::new(),
            objective_value_micros: None,
            rejected_candidates: Vec::new(),
            candidate_ids,
            candidate_predictions: Vec::new(),
            continuation: None,
            escalation_comparison: None,
            taxonomy_version: None,
            taxonomy_cell: None,
            taxonomy_confidence_bp: None,
            recommendation_source: None,
            evidence_observations: None,
            switch_cost_micros: None,
            switch_class: None,
            switch_observation: None,
            switch_cost_applied_micros: None,
            switch_cost_evidence: None,
            switch_hysteresis_margin_bp: None,
            oscillation_count: None,
            oscillation_alarm_threshold: None,
            oscillation_alarm: None,
            stage_path: None,
            difficulty_score_bp: None,
            difficulty_lower_bp: None,
            difficulty_upper_bp: None,
            decision_overhead_micros: None,
            overhead_degraded: None,
            calibration_step: None,
            calibration_metric: None,
        }
    }

    pub fn reject(&mut self, policy: PolicyId, reason: impl Into<String>) {
        self.rejected_candidates.push(RejectedCandidate {
            policy,
            reason: reason.into(),
        });
    }

    pub fn record_prediction(&mut self, prediction: CandidatePrediction) {
        self.candidate_predictions.push(prediction);
    }

    pub fn fill_reserves(&mut self, snapshot: &ResourceSnapshot) {
        for (id, remaining, reserve, price) in snapshot.balances_reserves_and_prices() {
            self.reserves_after_selection
                .insert(format!("{id}:remaining"), remaining.as_i64());
            self.reserves_after_selection
                .insert(format!("{id}:frontier_reserve"), reserve.as_i64());
            self.reserves_after_selection
                .insert(format!("{id}:shadow_price"), price);
        }
    }

    pub fn record_consumption(&mut self, dimension: &str, expected: Quantity) {
        self.predicted_consumption
            .insert(dimension.to_string(), expected.as_i64());
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectedAction {
    pub backend: String,
    pub model: String,
    pub effort: String,
    pub role: String,
}

impl SelectedAction {
    pub fn from_model_action(action: &ModelAction) -> Self {
        Self {
            backend: action.backend_id.to_string(),
            model: action.runtime_model.runtime_slug.to_string(),
            effort: action.effort.as_label().to_string(),
            role: role_label(&action.role),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedCandidate {
    pub policy: PolicyId,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidatePrediction {
    pub policy: PolicyId,
    pub quality_lcb_bp: u16,
    pub certified_probability_bp: u16,
    pub expected_cost_micros: i64,
    pub expected_latency_micros: i64,
    pub tail_latency_p95_micros: i64,
    pub cvar95_latency_micros: i64,
    pub objective_value_micros: Option<i64>,
    pub feasible: bool,
}

/// Four-way comparison recorded on every effort-escalation decision (#168).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationComparison {
    #[serde(default)]
    pub continue_arm: Option<ComparedPolicy>,
    #[serde(default, alias = "same_model_higher_effort")]
    pub escalate_arm: Option<ComparedPolicy>,
    #[serde(default, alias = "different_model_same_effort")]
    pub switch_arm: Option<ComparedPolicy>,
    #[serde(default)]
    pub repair_arm: Option<ComparedPolicy>,
    pub selected: Option<PolicyId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComparedPolicy {
    pub policy: PolicyId,
    pub model: String,
    pub effort: String,
    #[serde(default)]
    pub base_objective_value_micros: i64,
    pub objective_value_micros: i64,
    pub quality_lcb_bp: u16,
    #[serde(default)]
    pub applied_switch_cost_micros: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub switch_evidence: Option<SwitchCostEstimate>,
}

pub(crate) fn role_label(role: &AgentRole) -> String {
    match role {
        AgentRole::Planner => "planner".to_string(),
        AgentRole::Supervisor => "supervisor".to_string(),
        AgentRole::ChildOrchestrator => "child_orchestrator".to_string(),
        AgentRole::Worker => "worker".to_string(),
        AgentRole::Repairer => "repairer".to_string(),
        AgentRole::Researcher => "researcher".to_string(),
        AgentRole::GateClassifier => "gate_classifier".to_string(),
        AgentRole::Auditor => "auditor".to_string(),
        AgentRole::Certifier => "certifier".to_string(),
        AgentRole::Extension(id) => format!("extension:{id}"),
    }
}

pub(crate) fn effort_rank(effort: &CanonicalEffort) -> u8 {
    match effort {
        CanonicalEffort::Minimal => 0,
        CanonicalEffort::Low => 1,
        CanonicalEffort::Medium => 2,
        CanonicalEffort::High => 3,
        CanonicalEffort::XHigh => 4,
        CanonicalEffort::Max => 5,
        CanonicalEffort::ProviderNative(_) => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::ids::{PolicyId, ResourceDimensionId};
    use crate::optimizer::resources::{
        ObservationKind, ResourceDimension, ResourceObservation, ResourceVector,
    };

    fn snapshot() -> ResourceSnapshot {
        let mut vector = ResourceVector::new();
        vector.insert(ResourceDimension {
            id: ResourceDimensionId::well_known(ResourceDimensionId::LOCAL_COMPUTE_SECONDS),
            remaining: Quantity::new(100),
            reset_at: None,
            frontier_reserve: Quantity::new(10),
            emergency_margin: Quantity::new(1),
            uncertainty: Quantity::ZERO,
            shadow_price: 2,
            observation: ResourceObservation {
                kind: ObservationKind::Measured,
                confidence_bp: 10_000,
            },
            chance_epsilon_bp: 1_000,
            target_usage_bp: 5_000,
            learning_rate: 1_000,
        });
        vector.snapshot(TimestampMillis::from_millis(7))
    }

    #[test]
    fn diagnostics_round_trip_through_explanation_envelope() {
        let policy = PolicyId::new("worker-low").expect("policy");
        let mut diagnostics =
            DecisionDiagnostics::new(TimestampMillis::from_millis(7), vec![policy.clone()]);
        diagnostics.selected_policy = Some(policy.clone());
        diagnostics.quality_lcb_bp = Some(9_900);
        diagnostics.objective_value_micros = Some(42);
        diagnostics.reject(
            PolicyId::new("frontier-xhigh").expect("id"),
            "feasible_but_dominated_on_time_and_resource_use",
        );
        diagnostics.fill_reserves(&snapshot());

        let explanation = DecisionExplanation::from_diagnostics(&diagnostics, snapshot());
        assert_eq!(explanation.selected.as_ref(), Some(&policy));
        let json = explanation.diagnostics_json().expect("json");
        let restored: DecisionDiagnostics = serde_json::from_str(json).expect("parse");
        assert_eq!(restored.quality_lcb_bp, Some(9_900));
        assert_eq!(restored.rejected_candidates.len(), 1);
        assert!(restored
            .reserves_after_selection
            .keys()
            .any(|key| key.contains("frontier_reserve")));
    }
}
