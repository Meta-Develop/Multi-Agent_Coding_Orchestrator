//! First slice of #830: a providerless coordination-depth decision core.
//!
//! Depth `d` means `d - 1` delegating coordinator levels above one level of
//! terminal Workers. Depth 1 is a single terminal Worker with no coordinator.
//! Depth 2 and deeper equal the supervisor plan `max_depth` (a root assignment
//! has depth 2, a nested child depth 3; `max_depth` 1 is not a supervisor
//! plan). Every coordinator carries one independent read-only auditor.
//!
//! Candidate quality and cost come from an uncalibrated prior
//! ([`DepthCostModel`]) that every record carries, so later calibration can
//! replace it. Selection is the #157 evaluation function: quality is a hard
//! floor, then minimum cost. Wiring the decision into planning and autopilot
//! is a later #830 slice.

use serde::{Deserialize, Serialize};

use super::action::CanonicalEffort;
use super::evaluation_fn::{EvaluatedPolicy, EvaluationFunction, EvaluationOutcome};
use super::ids::PolicyId;

/// Schema tag for serialized depth decision records.
pub const DEPTH_DECISION_SCHEMA: &str = "maco.depth_decision.v1";

/// Emergency backstop that mirrors `MAX_SUPERVISOR_DEPTH` in src/supervise.rs.
pub const ABSOLUTE_DEPTH_CAP: u8 = 32;

/// Operator inputs for one depth decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DepthDecisionInput {
    /// Disjoint executable work units from decomposition.
    pub work_units: u32,
    /// Tokens to execute the whole task at the leaves.
    pub estimated_work_tokens: u64,
    /// Fan-out bound per coordinator.
    pub max_child_assignments: u32,
    /// Operator ceiling the decision never exceeds.
    pub depth_ceiling: u8,
}

/// Uncalibrated prior for depth candidate quality and cost.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DepthCostModel {
    /// Tokens one terminal Worker can execute.
    pub worker_capacity_tokens: u64,
    /// Overhead tokens per terminal Worker.
    pub per_worker_overhead_tokens: u64,
    /// Overhead tokens per coordinator.
    pub per_coordinator_overhead_tokens: u64,
    /// Overhead tokens per read-only auditor.
    pub per_auditor_overhead_tokens: u64,
    /// Quality at depth 1, in basis points.
    pub base_quality_bp: u16,
    /// Quality lost per extra coordination level, in basis points.
    pub per_level_quality_loss_bp: u16,
}

impl DepthCostModel {
    /// The uncalibrated prior carried by every record until calibration lands.
    pub fn uncalibrated_prior() -> Self {
        Self {
            worker_capacity_tokens: 400_000,
            per_worker_overhead_tokens: 60_000,
            per_coordinator_overhead_tokens: 120_000,
            per_auditor_overhead_tokens: 80_000,
            base_quality_bp: 9_500,
            per_level_quality_loss_bp: 200,
        }
    }
}

/// One coordination-depth candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepthCandidate {
    /// The candidate depth `d`.
    pub depth: u8,
    /// `depth-{d}` policy identity.
    pub policy_id: PolicyId,
    /// Terminal Workers at this depth.
    pub workers: u64,
    /// Delegating coordinators at this depth.
    pub coordinators: u64,
    /// Read-only auditors, one per coordinator.
    pub auditors: u64,
    /// Tokens each terminal Worker must execute.
    pub per_worker_load_tokens: u64,
    /// Lower confidence bound on quality, in basis points.
    pub quality_lower_confidence_bp: u16,
    /// Total estimated cost in tokens.
    pub cost_tokens: u64,
}

/// The chosen depth, or a refusal when no depth satisfies the quality floor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DepthDecision {
    /// The selected coordination depth.
    Selected {
        /// The selected depth.
        depth: u8,
        /// Terminal Workers at the selected depth.
        workers: u64,
        /// Coordinators at the selected depth.
        coordinators: u64,
        /// Total cost in tokens at the selected depth.
        cost_tokens: u64,
    },
    /// No candidate depth satisfied the quality contract.
    Refused {
        /// Why the decision was refused.
        reason: String,
    },
}

/// A complete, deterministic depth decision record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepthDecisionRecord {
    /// Always [`DEPTH_DECISION_SCHEMA`].
    pub schema: String,
    /// The operator inputs the decision was made from.
    pub input: DepthDecisionInput,
    /// The uncalibrated prior used to build the candidates.
    pub model: DepthCostModel,
    /// The quality floor applied by the evaluation function.
    pub quality_threshold_bp: u16,
    /// One candidate per depth, in increasing depth order.
    pub candidates: Vec<DepthCandidate>,
    /// The #157 evaluation outcome over the candidates, unchanged.
    pub evaluation: EvaluationOutcome,
    /// The resulting depth decision.
    pub decision: DepthDecision,
    /// One human-readable reason per candidate, in depth order.
    pub reasons: Vec<String>,
}

/// Errors for invalid depth decision inputs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DepthDecisionError {
    /// No executable work units were given.
    #[error("depth decision needs at least one work unit")]
    ZeroWorkUnits,
    /// The fan-out bound was zero.
    #[error("max_child_assignments must be at least 1")]
    ZeroFanOut,
    /// The depth ceiling was zero.
    #[error("depth ceiling must be at least 1")]
    ZeroCeiling,
    /// The depth ceiling exceeded the absolute cap.
    #[error("depth ceiling {ceiling} exceeds the absolute cap 32")]
    CeilingAboveAbsoluteCap {
        /// The offending ceiling.
        ceiling: u8,
    },
    /// The worker capacity was zero.
    #[error("worker capacity must be at least 1 token")]
    ZeroWorkerCapacity,
    /// The base quality exceeded 10000 bp.
    #[error("base quality {observed_bp} bp exceeds 10000 bp")]
    InvalidBaseQuality {
        /// The offending base quality.
        observed_bp: u16,
    },
}

/// Decide the coordination depth for one task.
///
/// Builds one candidate per depth up to the ceiling, presents all of them to
/// the #157 evaluation function, and records the outcome unchanged.
pub fn decide_depth(
    input: &DepthDecisionInput,
    model: &DepthCostModel,
    evaluation: &EvaluationFunction,
) -> Result<DepthDecisionRecord, DepthDecisionError> {
    if input.work_units == 0 {
        return Err(DepthDecisionError::ZeroWorkUnits);
    }
    if input.max_child_assignments == 0 {
        return Err(DepthDecisionError::ZeroFanOut);
    }
    if input.depth_ceiling == 0 {
        return Err(DepthDecisionError::ZeroCeiling);
    }
    if input.depth_ceiling > ABSOLUTE_DEPTH_CAP {
        return Err(DepthDecisionError::CeilingAboveAbsoluteCap {
            ceiling: input.depth_ceiling,
        });
    }
    if model.worker_capacity_tokens == 0 {
        return Err(DepthDecisionError::ZeroWorkerCapacity);
    }
    if model.base_quality_bp > 10_000 {
        return Err(DepthDecisionError::InvalidBaseQuality {
            observed_bp: model.base_quality_bp,
        });
    }

    let fan_out = input.max_child_assignments as u64;
    let needed = 1_u64.max(
        input
            .estimated_work_tokens
            .div_ceil(model.worker_capacity_tokens),
    );

    let mut candidates = Vec::new();
    for depth in 1..=input.depth_ceiling {
        candidates.push(build_candidate(depth, input, model, fan_out, needed));
    }

    let evaluated: Vec<EvaluatedPolicy> = candidates
        .iter()
        .map(|candidate| EvaluatedPolicy {
            policy_id: candidate.policy_id.clone(),
            certified_quality: true,
            quality_lower_confidence_bp: candidate.quality_lower_confidence_bp,
            cost_to_certification_micros: i64::try_from(candidate.cost_tokens).unwrap_or(i64::MAX),
            resource_constraints_satisfied: true,
            effort: CanonicalEffort::ProviderNative("coordination-depth".to_string()),
        })
        .collect();

    let outcome = evaluation.evaluate(&evaluated);

    let decision = match &outcome {
        EvaluationOutcome::Selected { policy_id, .. } => {
            match candidates
                .iter()
                .find(|candidate| &candidate.policy_id == policy_id)
            {
                Some(candidate) => DepthDecision::Selected {
                    depth: candidate.depth,
                    workers: candidate.workers,
                    coordinators: candidate.coordinators,
                    cost_tokens: candidate.cost_tokens,
                },
                None => DepthDecision::Refused {
                    reason: format!(
                        "no candidate depth up to the ceiling {} satisfies the quality contract",
                        input.depth_ceiling
                    ),
                },
            }
        }
        EvaluationOutcome::Infeasible { .. } => DepthDecision::Refused {
            reason: format!(
                "no candidate depth up to the ceiling {} satisfies the quality contract",
                input.depth_ceiling
            ),
        },
    };

    let reasons = candidates
        .iter()
        .map(|candidate| reason_for(candidate, &outcome))
        .collect();

    Ok(DepthDecisionRecord {
        schema: DEPTH_DECISION_SCHEMA.to_string(),
        input: input.clone(),
        model: model.clone(),
        quality_threshold_bp: evaluation.quality_threshold_bp(),
        candidates,
        evaluation: outcome,
        decision,
        reasons,
    })
}

fn build_candidate(
    depth: u8,
    input: &DepthDecisionInput,
    model: &DepthCostModel,
    fan_out: u64,
    needed: u64,
) -> DepthCandidate {
    let leaf_capacity = fan_out.saturating_pow((depth - 1) as u32);
    let workers = needed
        .min(input.work_units as u64)
        .min(leaf_capacity)
        .max(1);
    let per_worker_load_tokens = input.estimated_work_tokens.div_ceil(workers);

    let mut n = workers;
    let mut coordinators = 0_u64;
    for _ in 0..(depth - 1) {
        n = n.div_ceil(fan_out);
        coordinators = coordinators.saturating_add(n);
    }
    let auditors = coordinators;

    let level_loss = (depth as u64 - 1).saturating_mul(model.per_level_quality_loss_bp as u64);
    let level_quality = (model.base_quality_bp as u64).saturating_sub(level_loss) as u16;
    let quality_lower_confidence_bp = if per_worker_load_tokens <= model.worker_capacity_tokens {
        level_quality
    } else {
        ((level_quality as u128 * model.worker_capacity_tokens as u128)
            / per_worker_load_tokens as u128) as u16
    };

    let cost_tokens = input
        .estimated_work_tokens
        .saturating_add(workers.saturating_mul(model.per_worker_overhead_tokens))
        .saturating_add(
            coordinators.saturating_mul(
                model
                    .per_coordinator_overhead_tokens
                    .saturating_add(model.per_auditor_overhead_tokens),
            ),
        );

    let policy_id =
        PolicyId::new(format!("depth-{depth}")).expect("depth policy id is always valid");

    DepthCandidate {
        depth,
        policy_id,
        workers,
        coordinators,
        auditors,
        per_worker_load_tokens,
        quality_lower_confidence_bp,
        cost_tokens,
    }
}

fn reason_for(candidate: &DepthCandidate, outcome: &EvaluationOutcome) -> String {
    let rejected = match outcome {
        EvaluationOutcome::Selected { rejected, .. } => rejected,
        EvaluationOutcome::Infeasible { rejected, .. } => rejected,
    };
    if let Some(rejection) = rejected
        .iter()
        .find(|rejection| rejection.policy_id == candidate.policy_id)
    {
        return format!(
            "depth {}: rejected ({:?})",
            candidate.depth, rejection.reason
        );
    }
    if let EvaluationOutcome::Selected { policy_id, .. } = outcome {
        if policy_id == &candidate.policy_id {
            return format!(
                "depth {}: selected (cost {} tokens)",
                candidate.depth, candidate.cost_tokens
            );
        }
    }
    format!(
        "depth {}: feasible, not selected (cost {} tokens)",
        candidate.depth, candidate.cost_tokens
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(
        work_units: u32,
        estimated_work_tokens: u64,
        max_child_assignments: u32,
        depth_ceiling: u8,
    ) -> DepthDecisionInput {
        DepthDecisionInput {
            work_units,
            estimated_work_tokens,
            max_child_assignments,
            depth_ceiling,
        }
    }

    #[test]
    fn small_task_selects_depth_one() {
        let record = decide_depth(
            &input(3, 100_000, 4, 4),
            &DepthCostModel::uncalibrated_prior(),
            &EvaluationFunction::shipped_default(),
        )
        .expect("decision succeeds");
        assert_eq!(
            record.decision,
            DepthDecision::Selected {
                depth: 1,
                workers: 1,
                coordinators: 0,
                cost_tokens: 160_000,
            }
        );
        assert_eq!(record.candidates.len(), 4);
        let costs: Vec<u64> = record
            .candidates
            .iter()
            .map(|candidate| candidate.cost_tokens)
            .collect();
        assert_eq!(costs, vec![160_000, 360_000, 560_000, 760_000]);
        let qualities: Vec<u16> = record
            .candidates
            .iter()
            .map(|candidate| candidate.quality_lower_confidence_bp)
            .collect();
        assert_eq!(qualities, vec![9_500, 9_300, 9_100, 8_900]);
    }

    #[test]
    fn medium_task_selects_depth_two() {
        let record = decide_depth(
            &input(4, 1_200_000, 4, 4),
            &DepthCostModel::uncalibrated_prior(),
            &EvaluationFunction::shipped_default(),
        )
        .expect("decision succeeds");
        assert_eq!(
            record.decision,
            DepthDecision::Selected {
                depth: 2,
                workers: 3,
                coordinators: 1,
                cost_tokens: 1_580_000,
            }
        );
        assert_eq!(record.candidates[0].workers, 1);
        assert_eq!(record.candidates[0].per_worker_load_tokens, 1_200_000);
        assert_eq!(record.candidates[0].quality_lower_confidence_bp, 3_166);
        assert_eq!(
            record.reasons,
            vec![
                "depth 1: rejected (QualityConfidenceBelowThreshold { observed_bp: 3166, threshold_bp: 8000 })".to_string(),
                "depth 2: selected (cost 1580000 tokens)".to_string(),
                "depth 3: feasible, not selected (cost 1780000 tokens)".to_string(),
                "depth 4: feasible, not selected (cost 1980000 tokens)".to_string(),
            ]
        );
    }

    #[test]
    fn large_task_selects_depth_three() {
        let record = decide_depth(
            &input(12, 4_000_000, 4, 4),
            &DepthCostModel::uncalibrated_prior(),
            &EvaluationFunction::shipped_default(),
        )
        .expect("decision succeeds");
        assert_eq!(
            record.decision,
            DepthDecision::Selected {
                depth: 3,
                workers: 10,
                coordinators: 4,
                cost_tokens: 5_400_000,
            }
        );
        let qualities: Vec<u16> = record
            .candidates
            .iter()
            .map(|candidate| candidate.quality_lower_confidence_bp)
            .collect();
        assert_eq!(qualities, vec![950, 3_720, 9_100, 8_900]);
        let coordinators: Vec<u64> = record
            .candidates
            .iter()
            .map(|candidate| candidate.coordinators)
            .collect();
        assert_eq!(coordinators, vec![0, 1, 4, 5]);
        assert!(record
            .candidates
            .iter()
            .all(|candidate| candidate.auditors == candidate.coordinators));
    }

    #[test]
    fn ceiling_below_required_depth_refuses() {
        let record = decide_depth(
            &input(12, 4_000_000, 4, 2),
            &DepthCostModel::uncalibrated_prior(),
            &EvaluationFunction::shipped_default(),
        )
        .expect("decision succeeds");
        assert_eq!(record.candidates.len(), 2);
        assert!(matches!(
            record.evaluation,
            EvaluationOutcome::Infeasible { .. }
        ));
        assert_eq!(
            record.decision,
            DepthDecision::Refused {
                reason: "no candidate depth up to the ceiling 2 satisfies the quality contract"
                    .to_string(),
            }
        );
        assert!(record
            .reasons
            .iter()
            .all(|reason| reason.starts_with("depth ") && reason.contains(": rejected (")));
    }

    #[test]
    fn too_few_work_units_refuses_every_depth() {
        let record = decide_depth(
            &input(2, 4_000_000, 4, 4),
            &DepthCostModel::uncalibrated_prior(),
            &EvaluationFunction::shipped_default(),
        )
        .expect("decision succeeds");
        for candidate in &record.candidates[1..] {
            assert_eq!(candidate.workers, 2);
            assert_eq!(candidate.per_worker_load_tokens, 2_000_000);
        }
        assert!(matches!(record.decision, DepthDecision::Refused { .. }));
    }

    #[test]
    fn invalid_inputs_are_refused() {
        let prior = DepthCostModel::uncalibrated_prior();
        let evaluation = EvaluationFunction::shipped_default();

        let err = decide_depth(&input(0, 100_000, 4, 4), &prior, &evaluation)
            .expect_err("zero work units");
        assert_eq!(err, DepthDecisionError::ZeroWorkUnits);

        let err =
            decide_depth(&input(3, 100_000, 0, 4), &prior, &evaluation).expect_err("zero fan-out");
        assert_eq!(err, DepthDecisionError::ZeroFanOut);

        let err =
            decide_depth(&input(3, 100_000, 4, 0), &prior, &evaluation).expect_err("zero ceiling");
        assert_eq!(err, DepthDecisionError::ZeroCeiling);

        let err = decide_depth(&input(3, 100_000, 4, 33), &prior, &evaluation)
            .expect_err("ceiling above cap");
        assert_eq!(
            err,
            DepthDecisionError::CeilingAboveAbsoluteCap { ceiling: 33 }
        );
        assert_eq!(
            DepthDecisionError::CeilingAboveAbsoluteCap { ceiling: 33 }.to_string(),
            "depth ceiling 33 exceeds the absolute cap 32"
        );

        let mut zero_capacity = prior.clone();
        zero_capacity.worker_capacity_tokens = 0;
        let err = decide_depth(&input(3, 100_000, 4, 4), &zero_capacity, &evaluation)
            .expect_err("zero worker capacity");
        assert_eq!(err, DepthDecisionError::ZeroWorkerCapacity);

        let mut bad_quality = prior.clone();
        bad_quality.base_quality_bp = 10_001;
        let err = decide_depth(&input(3, 100_000, 4, 4), &bad_quality, &evaluation)
            .expect_err("invalid base quality");
        assert_eq!(
            err,
            DepthDecisionError::InvalidBaseQuality {
                observed_bp: 10_001,
            }
        );
    }

    #[test]
    fn extreme_inputs_saturate_without_panic() {
        let record = decide_depth(
            &input(u32::MAX, u64::MAX, u32::MAX, 32),
            &DepthCostModel::uncalibrated_prior(),
            &EvaluationFunction::shipped_default(),
        )
        .expect("decision succeeds");
        assert_eq!(record.candidates.len(), 32);
        assert_eq!(record.candidates.last().expect("nonempty").depth, 32);
        assert!(matches!(record.decision, DepthDecision::Refused { .. }));
    }

    #[test]
    fn record_round_trips_through_json() {
        let record = decide_depth(
            &input(4, 1_200_000, 4, 4),
            &DepthCostModel::uncalibrated_prior(),
            &EvaluationFunction::shipped_default(),
        )
        .expect("decision succeeds");
        let value = serde_json::to_value(&record).expect("serializes");
        assert_eq!(value["schema"], "maco.depth_decision.v1");
        assert_eq!(value["decision"]["kind"], "selected");
        let round_tripped: DepthDecisionRecord =
            serde_json::from_value(value).expect("deserializes");
        assert_eq!(round_tripped, record);
    }
}
