//! Shadow evaluation. Implemented by issue #169.
//!
//! Shadow policies never gain merge, publication, or certification authority.
//! Authority is absent by construction: [`ShadowAssignment`] only exposes
//! [`ShadowAuthority::ObserveOnly`], and promotion eligibility is a separate
//! safe-set concern (#169) that still requires a complete quality contract.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Mutex;

use super::error::OptimizerError;
use super::ids::{PolicyId, TimestampMillis};
use super::quality::QualityContract;
use super::safe_set::EvaluationFidelity;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShadowAuthority {
    ObserveOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowAssignment {
    pub policy_id: PolicyId,
    pub authority: ShadowAuthority,
}

pub trait ShadowEvaluator {
    fn assign(&self, policy_id: &PolicyId) -> Result<ShadowAssignment, OptimizerError>;
}

impl ShadowAssignment {
    pub fn has_publication_authority(&self) -> bool {
        false
    }

    pub fn has_merge_authority(&self) -> bool {
        false
    }

    pub fn has_certification_authority(&self) -> bool {
        false
    }

    /// Any attempt to escalate shadow authority fails closed.
    pub fn escalate(&self, _requested: ShadowAuthorityEscalation) -> Result<(), OptimizerError> {
        Err(OptimizerError::invalid(
            "shadow isolation: ObserveOnly assignments cannot obtain merge, publication, or certification authority",
        ))
    }
}

/// Requested authorities that shadow evaluation must refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShadowAuthorityEscalation {
    Merge,
    Publish,
    Certify,
}

/// Outcome of a shadow comparison against an accepted production run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowObservation {
    pub policy_id: PolicyId,
    pub observed_at: TimestampMillis,
    pub matched_accepted_outcome: bool,
    pub certification_contract_satisfied: bool,
    pub fidelity: EvaluationFidelity,
}

/// Persisted, replayable shadow ledger entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowLedgerEntry {
    pub assignment: ShadowAssignment,
    pub observation: ShadowObservation,
}

/// In-memory shadow evaluator. Assignments are always observe-only.
#[derive(Debug, Default)]
pub struct InMemoryShadowEvaluator {
    ledger: Mutex<Vec<ShadowLedgerEntry>>,
    active: Mutex<BTreeMap<String, ShadowAssignment>>,
}

impl InMemoryShadowEvaluator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_observation(
        &self,
        observation: ShadowObservation,
    ) -> Result<ShadowLedgerEntry, OptimizerError> {
        let assignment = self.assign(&observation.policy_id)?;
        if assignment.has_publication_authority()
            || assignment.has_merge_authority()
            || assignment.has_certification_authority()
        {
            return Err(OptimizerError::invalid(
                "shadow isolation violated: assignment carried production authority",
            ));
        }
        let entry = ShadowLedgerEntry {
            assignment,
            observation,
        };
        self.ledger
            .lock()
            .map_err(|_| OptimizerError::invalid("shadow ledger lock poisoned"))?
            .push(entry.clone());
        Ok(entry)
    }

    pub fn ledger_snapshot(&self) -> Result<Vec<ShadowLedgerEntry>, OptimizerError> {
        Ok(self
            .ledger
            .lock()
            .map_err(|_| OptimizerError::invalid("shadow ledger lock poisoned"))?
            .clone())
    }

    /// Shadow evidence may contribute to promotion eligibility only when the
    /// complete quality contract is already satisfied. This never grants
    /// merge/publish/certify authority to the shadow assignment itself.
    pub fn eligible_for_safe_set_consideration(
        &self,
        policy_id: &PolicyId,
        contract: &QualityContract,
    ) -> Result<bool, OptimizerError> {
        if !contract.has_machine_checkable_mandatory_validator() {
            return Ok(false);
        }
        let ledger = self.ledger_snapshot()?;
        Ok(ledger.iter().any(|entry| {
            &entry.observation.policy_id == policy_id
                && entry.observation.certification_contract_satisfied
                && entry.observation.fidelity.can_promote_to_safe_set()
        }))
    }
}

impl ShadowEvaluator for InMemoryShadowEvaluator {
    fn assign(&self, policy_id: &PolicyId) -> Result<ShadowAssignment, OptimizerError> {
        let assignment = ShadowAssignment {
            policy_id: policy_id.clone(),
            authority: ShadowAuthority::ObserveOnly,
        };
        self.active
            .lock()
            .map_err(|_| OptimizerError::invalid("shadow active lock poisoned"))?
            .insert(policy_id.to_string(), assignment.clone());
        Ok(assignment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::ids::{ContractId, ValidatorId};
    use crate::optimizer::quality::{ValidatorBinding, ValidatorKind};

    fn policy(id: &str) -> PolicyId {
        PolicyId::new(id).expect("policy")
    }

    #[test]
    fn shadow_assignment_never_gains_publication_merge_or_certification_authority() {
        let evaluator = InMemoryShadowEvaluator::new();
        let assignment = evaluator.assign(&policy("candidate-a")).expect("assign");
        assert_eq!(assignment.authority, ShadowAuthority::ObserveOnly);
        assert!(!assignment.has_publication_authority());
        assert!(!assignment.has_merge_authority());
        assert!(!assignment.has_certification_authority());
        for requested in [
            ShadowAuthorityEscalation::Merge,
            ShadowAuthorityEscalation::Publish,
            ShadowAuthorityEscalation::Certify,
        ] {
            let err = assignment.escalate(requested).expect_err("must refuse");
            assert!(
                err.to_string().contains("shadow isolation"),
                "unexpected error: {err}"
            );
        }
    }

    #[test]
    fn attempting_to_certify_from_shadow_ledger_is_impossible_by_construction() {
        let evaluator = InMemoryShadowEvaluator::new();
        let entry = evaluator
            .record_observation(ShadowObservation {
                policy_id: policy("shadow-b"),
                observed_at: TimestampMillis::from_millis(10),
                matched_accepted_outcome: true,
                certification_contract_satisfied: true,
                fidelity: EvaluationFidelity::F5ProductionShadow,
            })
            .expect("record");
        assert!(!entry.assignment.has_certification_authority());
        assert!(!entry.assignment.has_merge_authority());
        assert!(!entry.assignment.has_publication_authority());
    }

    #[test]
    fn safe_set_consideration_requires_complete_quality_contract() {
        let evaluator = InMemoryShadowEvaluator::new();
        let id = policy("shadow-c");
        evaluator
            .record_observation(ShadowObservation {
                policy_id: id.clone(),
                observed_at: TimestampMillis::from_millis(11),
                matched_accepted_outcome: true,
                certification_contract_satisfied: true,
                fidelity: EvaluationFidelity::F5ProductionShadow,
            })
            .expect("record");

        let empty = QualityContract::new(ContractId::new("empty").expect("id"));
        assert!(!evaluator
            .eligible_for_safe_set_consideration(&id, &empty)
            .expect("check"));

        let mut complete = QualityContract::new(ContractId::new("complete").expect("id"));
        complete.add_mandatory_validator(ValidatorBinding {
            validator_id: ValidatorId::new("unit").expect("id"),
            kind: ValidatorKind::DeterministicCommand {
                name: "cargo-test".to_string(),
            },
            required_for_production: true,
        });
        assert!(evaluator
            .eligible_for_safe_set_consideration(&id, &complete)
            .expect("check"));

        let low = policy("shadow-low-fid");
        evaluator
            .record_observation(ShadowObservation {
                policy_id: low.clone(),
                observed_at: TimestampMillis::from_millis(12),
                matched_accepted_outcome: true,
                certification_contract_satisfied: true,
                fidelity: EvaluationFidelity::F3HistoricalReplay,
            })
            .expect("record");
        assert!(!evaluator
            .eligible_for_safe_set_consideration(&low, &complete)
            .expect("check"));
    }
}
