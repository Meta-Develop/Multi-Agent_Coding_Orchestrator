//! #157 evaluation function: certified quality as a hard constraint.
//!
//! This is the first slice of umbrella #157. It lands the mathematical object
//!
//! ```text
//! min_π  CostToCertification(π)
//! s.t.   CertifiedQuality(π) = 1
//!        ProviderResourceConstraints(π) satisfied
//! ```
//!
//! Quality is never a weighted term. Preference weights, latency, and later
//! soft objectives compete only among candidates that already satisfy the
//! complete quality contract. When no candidate is feasible the function
//! returns [`EvaluationOutcome::Infeasible`]; uncertified artifacts must not
//! merge or publish.
//!
//! Phases 6–7 (#169 cold start / shadow / global search, #170 drift) are
//! intentionally out of scope here. Those modules already exist as later
//! owners and must not be edited by this slice.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use super::action::CanonicalEffort;
use super::ids::PolicyId;

/// Basis-point quality floor applied as a hard constraint (inclusive).
pub const DEFAULT_QUALITY_THRESHOLD_BP: u16 = 8_000;

/// The #157 evaluation function.
///
/// The type carries only the quality-confidence floor. It has no quality
/// weight, no scalarisation coefficient, and no API that can relax
/// certification. Cost-to-certification is the sole ranking key among
/// feasible candidates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationFunction {
    quality_threshold_bp: u16,
}

impl EvaluationFunction {
    pub fn new(quality_threshold_bp: u16) -> Self {
        Self {
            quality_threshold_bp,
        }
    }

    pub fn shipped_default() -> Self {
        Self::new(DEFAULT_QUALITY_THRESHOLD_BP)
    }

    pub fn quality_threshold_bp(&self) -> u16 {
        self.quality_threshold_bp
    }

    /// Evaluate complete execution policies. Quality and provider-resource
    /// constraints define the feasible set; only then is cost minimized.
    pub fn evaluate(&self, candidates: &[EvaluatedPolicy]) -> EvaluationOutcome {
        if self.quality_threshold_bp > 10_000 {
            return EvaluationOutcome::Infeasible {
                reason: "quality confidence threshold must be at most 10000 basis points".into(),
                rejected: Vec::new(),
            };
        }
        let mut seen = BTreeSet::new();
        let mut duplicates = BTreeSet::new();
        for candidate in candidates {
            if !seen.insert(&candidate.policy_id) {
                duplicates.insert(&candidate.policy_id);
            }
        }
        let mut rejected = Vec::new();
        let mut eligible: Vec<&EvaluatedPolicy> = Vec::new();

        for candidate in candidates {
            let reason = if duplicates.contains(&candidate.policy_id) {
                Some(RejectionReason::DuplicatePolicyIdentity)
            } else {
                self.rejection_reason(candidate)
            };
            if let Some(reason) = reason {
                rejected.push(PolicyRejection {
                    policy_id: candidate.policy_id.clone(),
                    reason,
                });
                continue;
            }
            eligible.push(candidate);
        }

        if eligible.is_empty() {
            return EvaluationOutcome::Infeasible {
                reason: "no candidate satisfies the quality contract".to_string(),
                rejected,
            };
        }

        eligible.sort_by_key(|candidate| {
            (
                candidate.cost_to_certification_micros,
                candidate.policy_id.as_str().to_string(),
            )
        });
        let winner = eligible[0];
        EvaluationOutcome::Selected {
            policy_id: winner.policy_id.clone(),
            cost_to_certification_micros: winner.cost_to_certification_micros,
            rejected,
        }
    }

    fn rejection_reason(&self, candidate: &EvaluatedPolicy) -> Option<RejectionReason> {
        if candidate.cost_to_certification_micros < 0 {
            return Some(RejectionReason::InvalidCost);
        }
        if candidate.quality_lower_confidence_bp > 10_000 {
            return Some(RejectionReason::InvalidQualityConfidence);
        }
        if !candidate.certified_quality {
            return Some(RejectionReason::Uncertified);
        }
        if candidate.quality_lower_confidence_bp < self.quality_threshold_bp {
            return Some(RejectionReason::QualityConfidenceBelowThreshold {
                observed_bp: candidate.quality_lower_confidence_bp,
                threshold_bp: self.quality_threshold_bp,
            });
        }
        if !candidate.resource_constraints_satisfied {
            return Some(RejectionReason::ProviderResourceConstraint);
        }
        None
    }
}

/// One complete execution policy presented to the evaluation function.
///
/// `certified_quality` is the binary contract conjunction
/// (`Q_cert = Π q_j = 1`). A cheaper uncertified candidate never competes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluatedPolicy {
    pub policy_id: PolicyId,
    pub certified_quality: bool,
    pub quality_lower_confidence_bp: u16,
    pub cost_to_certification_micros: i64,
    pub resource_constraints_satisfied: bool,
    /// Distinct `model@effort` actions carry independently measured cost.
    /// Higher effort is never assumed cheaper or better.
    pub effort: CanonicalEffort,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RejectionReason {
    InvalidCost,
    InvalidQualityConfidence,
    DuplicatePolicyIdentity,
    Uncertified,
    QualityConfidenceBelowThreshold { observed_bp: u16, threshold_bp: u16 },
    ProviderResourceConstraint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRejection {
    pub policy_id: PolicyId,
    pub reason: RejectionReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvaluationOutcome {
    Selected {
        policy_id: PolicyId,
        cost_to_certification_micros: i64,
        rejected: Vec<PolicyRejection>,
    },
    Infeasible {
        reason: String,
        rejected: Vec<PolicyRejection>,
    },
}

impl EvaluationOutcome {
    pub fn selected_policy(&self) -> Option<&PolicyId> {
        match self {
            Self::Selected { policy_id, .. } => Some(policy_id),
            Self::Infeasible { .. } => None,
        }
    }

    pub fn may_merge(&self) -> bool {
        matches!(self, Self::Selected { .. })
    }

    pub fn may_publish(&self) -> bool {
        self.may_merge()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(id: &str) -> PolicyId {
        PolicyId::new(id).expect("policy id")
    }

    fn certified(id: &str, cost: i64, effort: CanonicalEffort) -> EvaluatedPolicy {
        EvaluatedPolicy {
            policy_id: policy(id),
            certified_quality: true,
            quality_lower_confidence_bp: 9_000,
            cost_to_certification_micros: cost,
            resource_constraints_satisfied: true,
            effort,
        }
    }

    #[test]
    fn cheaper_uncertified_candidate_never_beats_certified_candidate() {
        let eval = EvaluationFunction::shipped_default();
        let outcome = eval.evaluate(&[
            EvaluatedPolicy {
                policy_id: policy("cheap-uncertified"),
                certified_quality: false,
                quality_lower_confidence_bp: 4_000,
                cost_to_certification_micros: 1,
                resource_constraints_satisfied: true,
                effort: CanonicalEffort::Low,
            },
            certified("certified-dear", 100_000, CanonicalEffort::High),
        ]);
        assert_eq!(
            outcome.selected_policy().map(PolicyId::as_str),
            Some("certified-dear")
        );
        assert!(outcome.may_merge());
        assert!(outcome.may_publish());
        match outcome {
            EvaluationOutcome::Selected { rejected, .. } => {
                assert_eq!(rejected.len(), 1);
                assert_eq!(rejected[0].policy_id.as_str(), "cheap-uncertified");
                assert_eq!(rejected[0].reason, RejectionReason::Uncertified);
            }
            EvaluationOutcome::Infeasible { .. } => panic!("certified candidate must win"),
        }
    }

    #[test]
    fn minimum_cost_to_certification_wins_among_certified_policies() {
        let eval = EvaluationFunction::shipped_default();
        let outcome = eval.evaluate(&[
            certified("dear", 50_000, CanonicalEffort::Max),
            certified("cheap", 8_000, CanonicalEffort::Medium),
            certified("mid", 12_000, CanonicalEffort::High),
        ]);
        assert_eq!(
            outcome,
            EvaluationOutcome::Selected {
                policy_id: policy("cheap"),
                cost_to_certification_micros: 8_000,
                rejected: Vec::new(),
            }
        );
    }

    #[test]
    fn quality_confidence_below_threshold_is_infeasible_even_when_cheaper() {
        let eval = EvaluationFunction::new(8_000);
        let outcome = eval.evaluate(&[EvaluatedPolicy {
            policy_id: policy("weak-lcb"),
            certified_quality: true,
            quality_lower_confidence_bp: 7_999,
            cost_to_certification_micros: 1,
            resource_constraints_satisfied: true,
            effort: CanonicalEffort::Low,
        }]);
        assert_eq!(
            outcome,
            EvaluationOutcome::Infeasible {
                reason: "no candidate satisfies the quality contract".to_string(),
                rejected: vec![PolicyRejection {
                    policy_id: policy("weak-lcb"),
                    reason: RejectionReason::QualityConfidenceBelowThreshold {
                        observed_bp: 7_999,
                        threshold_bp: 8_000,
                    },
                }],
            }
        );
        assert!(!outcome.may_merge());
        assert!(!outcome.may_publish());
    }

    #[test]
    fn no_satisfying_candidate_is_infeasible_and_cannot_merge_or_publish() {
        let eval = EvaluationFunction::shipped_default();
        let outcome = eval.evaluate(&[EvaluatedPolicy {
            policy_id: policy("only-uncertified"),
            certified_quality: false,
            quality_lower_confidence_bp: 10_000,
            cost_to_certification_micros: 1,
            resource_constraints_satisfied: true,
            effort: CanonicalEffort::Max,
        }]);
        assert!(matches!(outcome, EvaluationOutcome::Infeasible { .. }));
        assert!(!outcome.may_merge());
        assert!(!outcome.may_publish());
    }

    #[test]
    fn provider_resource_constraint_excludes_an_otherwise_certified_cheap_policy() {
        let eval = EvaluationFunction::shipped_default();
        let outcome = eval.evaluate(&[
            EvaluatedPolicy {
                policy_id: policy("cheap-but-over-quota"),
                certified_quality: true,
                quality_lower_confidence_bp: 9_500,
                cost_to_certification_micros: 100,
                resource_constraints_satisfied: false,
                effort: CanonicalEffort::Low,
            },
            certified("feasible-dear", 9_000, CanonicalEffort::Medium),
        ]);
        assert_eq!(
            outcome.selected_policy().map(PolicyId::as_str),
            Some("feasible-dear")
        );
        match outcome {
            EvaluationOutcome::Selected { rejected, .. } => {
                assert_eq!(
                    rejected[0].reason,
                    RejectionReason::ProviderResourceConstraint
                );
            }
            EvaluationOutcome::Infeasible { .. } => panic!("feasible certified policy must win"),
        }
    }

    #[test]
    fn lower_effort_wins_when_its_cost_to_certification_is_lower() {
        let eval = EvaluationFunction::shipped_default();
        let outcome = eval.evaluate(&[
            certified("same-model-max", 40_000, CanonicalEffort::Max),
            certified("same-model-medium", 9_000, CanonicalEffort::Medium),
        ]);
        assert_eq!(
            outcome.selected_policy().map(PolicyId::as_str),
            Some("same-model-medium")
        );
        match outcome {
            EvaluationOutcome::Selected {
                cost_to_certification_micros,
                ..
            } => assert_eq!(cost_to_certification_micros, 9_000),
            EvaluationOutcome::Infeasible { .. } => panic!("medium effort must remain feasible"),
        }
    }

    #[test]
    fn evaluation_function_has_no_quality_weight_that_can_buy_down_the_floor() {
        let eval = EvaluationFunction::shipped_default();
        let encoded = serde_json::to_value(&eval).expect("serialize evaluation function");
        let object = encoded.as_object().expect("object");
        assert_eq!(object.len(), 1);
        assert_eq!(object["quality_threshold_bp"], 8_000);
        assert!(!object.contains_key("quality_weight_bp"));
        assert!(!object.contains_key("quality_floor"));
        assert!(!object.contains_key("cost_weight_bp"));
    }

    #[test]
    fn readiness_regression_invalid_measurements_cannot_win() {
        for (cost, quality, reason) in [
            (-1, 9_000, RejectionReason::InvalidCost),
            (0, 10_001, RejectionReason::InvalidQualityConfidence),
        ] {
            let mut invalid = certified("invalid", cost, CanonicalEffort::Low);
            invalid.quality_lower_confidence_bp = quality;
            let outcome = EvaluationFunction::shipped_default()
                .evaluate(&[invalid, certified("valid", 100, CanonicalEffort::Medium)]);
            assert_eq!(
                outcome.selected_policy().map(PolicyId::as_str),
                Some("valid")
            );
            let EvaluationOutcome::Selected { rejected, .. } = outcome else {
                panic!("valid evidence must remain eligible");
            };
            assert_eq!(
                rejected,
                vec![PolicyRejection {
                    policy_id: policy("invalid"),
                    reason
                }]
            );
        }
        let mut impossible = certified("impossible", 0, CanonicalEffort::Low);
        impossible.quality_lower_confidence_bp = u16::MAX;
        assert!(!EvaluationFunction::new(10_001)
            .evaluate(&[impossible])
            .may_publish());
    }

    #[test]
    fn readiness_regression_duplicate_policy_evidence_is_ambiguous() {
        let outcome = EvaluationFunction::shipped_default().evaluate(&[
            certified("duplicate", 1, CanonicalEffort::Low),
            certified("duplicate", 1_000, CanonicalEffort::High),
            certified("unambiguous", 10, CanonicalEffort::Medium),
        ]);
        assert_eq!(
            outcome.selected_policy().map(PolicyId::as_str),
            Some("unambiguous")
        );
        let EvaluationOutcome::Selected { rejected, .. } = outcome else {
            panic!("unique evidence must remain eligible");
        };
        assert_eq!(rejected.len(), 2);
        assert!(rejected
            .iter()
            .all(|entry| entry.reason == RejectionReason::DuplicatePolicyIdentity));
    }

    #[test]
    fn readiness_regression_quality_boundaries_and_unknown_configuration() {
        let mut perfect = certified("perfect", 0, CanonicalEffort::Low);
        perfect.quality_lower_confidence_bp = 10_000;
        assert!(EvaluationFunction::new(10_000)
            .evaluate(&[perfect])
            .may_publish());
        assert!(serde_json::from_str::<EvaluationFunction>(
            r#"{"quality_threshold_bp":8000,"quality_weight":1}"#,
        )
        .is_err());
    }
}
