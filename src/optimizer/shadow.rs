//! Shadow evaluation. Implemented by issue #169.
//!
//! Shadow policies never gain merge, publication, or certification authority.
//! Authority is absent by construction: [`ShadowAssignment`] only exposes
//! [`ShadowAuthority::ObserveOnly`], and promotion eligibility is a separate
//! safe-set concern (#169) that still requires a complete quality contract.
//!
//! This first slice lands the remaining type-level objects for cold start,
//! weak priors, and safe-set promotion verdicts. Global search, live
//! exploration budgets, and durable provenance stores remain later slices.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Mutex;

use super::error::OptimizerError;
use super::ids::{PolicyId, TimestampMillis};
use super::quality::QualityContract;
use super::safe_set::{EvaluationFidelity, PromotionThreshold, TaskClass};

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

/// Stages of the shipped known-safe baseline (issue #169 cold start).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ColdStartStage {
    FrontierPlanning,
    ValidatedExecution,
    IndependentAudit,
    CompleteCertification,
}

impl ColdStartStage {
    pub const SHIPPED: [Self; 4] = [
        Self::FrontierPlanning,
        Self::ValidatedExecution,
        Self::IndependentAudit,
        Self::CompleteCertification,
    ];
}

/// Configurable known-safe baseline that is always the production fallback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColdStartBaseline {
    policy_id: PolicyId,
    stages: [ColdStartStage; 4],
}

impl ColdStartBaseline {
    pub fn shipped(policy_id: PolicyId) -> Self {
        Self {
            policy_id,
            stages: ColdStartStage::SHIPPED,
        }
    }

    pub fn policy_id(&self) -> &PolicyId {
        &self.policy_id
    }

    pub fn stages(&self) -> &[ColdStartStage; 4] {
        &self.stages
    }

    pub fn always_available(&self) -> bool {
        true
    }
}

/// Production roster that cannot drop its cold-start baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColdStartRoster {
    baseline: ColdStartBaseline,
    extras: Vec<PolicyId>,
}

impl ColdStartRoster {
    pub fn new(baseline: ColdStartBaseline) -> Self {
        Self {
            baseline,
            extras: Vec::new(),
        }
    }

    pub fn baseline(&self) -> &ColdStartBaseline {
        &self.baseline
    }

    pub fn insert_candidate(&mut self, policy_id: PolicyId) {
        if policy_id != self.baseline.policy_id && !self.extras.contains(&policy_id) {
            self.extras.push(policy_id);
        }
    }

    pub fn try_remove(&mut self, policy_id: &PolicyId) -> Result<(), OptimizerError> {
        if policy_id == &self.baseline.policy_id {
            return Err(OptimizerError::invalid(
                "cold-start baseline cannot be removed",
            ));
        }
        self.extras.retain(|id| id != policy_id);
        Ok(())
    }

    pub fn contains(&self, policy_id: &PolicyId) -> bool {
        policy_id == &self.baseline.policy_id || self.extras.contains(policy_id)
    }

    /// Production selection always sees the baseline, even when extras are empty.
    pub fn production_ids(&self) -> Vec<PolicyId> {
        let mut ids = vec![self.baseline.policy_id.clone()];
        ids.extend(self.extras.iter().cloned());
        ids
    }
}

/// Benchmark / provider-tier information enters only as a weak prior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WeakPriorKind {
    Benchmark,
    ProviderTier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowWeakPrior {
    pub kind: WeakPriorKind,
    pub certified: bool,
}

/// Caps weak-prior influence so local observations can dominate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct WeakPriorBudget {
    accepted: u32,
}

impl WeakPriorBudget {
    pub const MAX_EQUIVALENT_TRIALS: u32 = 3;

    pub fn admit(&mut self, _prior: ShadowWeakPrior) -> bool {
        if self.accepted >= Self::MAX_EQUIVALENT_TRIALS {
            return false;
        }
        self.accepted = self.accepted.saturating_add(1);
        true
    }

    pub fn accepted_trials(&self) -> u32 {
        self.accepted
    }

    pub fn exhausted(&self) -> bool {
        self.accepted >= Self::MAX_EQUIVALENT_TRIALS
    }
}

/// Task-class scoped promotion case built from shadow evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowPromotionCase {
    pub policy_id: PolicyId,
    pub task_class: TaskClass,
    pub fidelity: EvaluationFidelity,
    pub lcb_bp: u16,
    pub threshold_bp: u16,
    pub contract_complete: bool,
    pub assignment: ShadowAssignment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShadowPromotionReject {
    IncompleteQualityContract,
    InsufficientFidelity,
    BelowLcb,
    ShadowIsolation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShadowPromotionVerdict {
    EligibleForSafeSetConsideration,
    Rejected { reason: ShadowPromotionReject },
}

impl ShadowPromotionCase {
    pub fn from_parts(
        assignment: ShadowAssignment,
        task_class: TaskClass,
        fidelity: EvaluationFidelity,
        lcb_bp: u16,
        threshold: PromotionThreshold,
        contract: &QualityContract,
    ) -> Self {
        Self {
            policy_id: assignment.policy_id.clone(),
            task_class,
            fidelity,
            lcb_bp,
            threshold_bp: threshold.lcb_bp,
            contract_complete: contract.has_machine_checkable_mandatory_validator(),
            assignment,
        }
    }

    pub fn verdict(&self) -> ShadowPromotionVerdict {
        if self.assignment.has_publication_authority()
            || self.assignment.has_merge_authority()
            || self.assignment.has_certification_authority()
        {
            return ShadowPromotionVerdict::Rejected {
                reason: ShadowPromotionReject::ShadowIsolation,
            };
        }
        if !self.contract_complete {
            return ShadowPromotionVerdict::Rejected {
                reason: ShadowPromotionReject::IncompleteQualityContract,
            };
        }
        if !self.fidelity.can_promote_to_safe_set() {
            return ShadowPromotionVerdict::Rejected {
                reason: ShadowPromotionReject::InsufficientFidelity,
            };
        }
        if self.lcb_bp < self.threshold_bp {
            return ShadowPromotionVerdict::Rejected {
                reason: ShadowPromotionReject::BelowLcb,
            };
        }
        ShadowPromotionVerdict::EligibleForSafeSetConsideration
    }

    /// Eligibility never grants merge, publication, or certification authority.
    pub fn grants_production_authority(&self) -> bool {
        false
    }
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

    /// Typed promotion case for one `(policy, task class)`. The verdict never
    /// mutates the shadow assignment's observe-only authority.
    pub fn promotion_case(
        &self,
        policy_id: &PolicyId,
        task_class: TaskClass,
        lcb_bp: u16,
        threshold: PromotionThreshold,
        contract: &QualityContract,
    ) -> Result<ShadowPromotionCase, OptimizerError> {
        let assignment = self.assign(policy_id)?;
        let ledger = self.ledger_snapshot()?;
        let fidelity = ledger
            .iter()
            .rev()
            .find(|entry| &entry.observation.policy_id == policy_id)
            .map(|entry| entry.observation.fidelity)
            .unwrap_or(EvaluationFidelity::F0StaticPrediction);
        Ok(ShadowPromotionCase::from_parts(
            assignment, task_class, fidelity, lcb_bp, threshold, contract,
        ))
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

    fn complete_contract() -> QualityContract {
        let mut contract = QualityContract::new(ContractId::new("complete").expect("id"));
        contract.add_mandatory_validator(ValidatorBinding {
            validator_id: ValidatorId::new("unit").expect("id"),
            kind: ValidatorKind::DeterministicCommand {
                name: "cargo-test".to_string(),
            },
            required_for_production: true,
        });
        contract
    }

    #[test]
    fn cold_start_baseline_cannot_be_removed_from_the_roster() {
        let baseline = ColdStartBaseline::shipped(policy("baseline-safe"));
        assert_eq!(baseline.stages(), &ColdStartStage::SHIPPED);
        assert!(baseline.always_available());
        let mut roster = ColdStartRoster::new(baseline);
        roster.insert_candidate(policy("shadow-candidate"));
        assert_eq!(
            roster.production_ids(),
            vec![policy("baseline-safe"), policy("shadow-candidate")]
        );
        roster
            .try_remove(&policy("shadow-candidate"))
            .expect("candidate may leave");
        let err = roster
            .try_remove(&policy("baseline-safe"))
            .expect_err("baseline stays");
        assert!(
            err.to_string().contains("cold-start baseline"),
            "unexpected error: {err}"
        );
        assert!(roster.contains(&policy("baseline-safe")));
        assert_eq!(roster.production_ids(), vec![policy("baseline-safe")]);
    }

    #[test]
    fn weak_priors_stop_after_three_equivalent_trials() {
        let mut budget = WeakPriorBudget::default();
        for kind in [
            WeakPriorKind::Benchmark,
            WeakPriorKind::ProviderTier,
            WeakPriorKind::Benchmark,
        ] {
            assert!(budget.admit(ShadowWeakPrior {
                kind,
                certified: true,
            }));
        }
        assert!(budget.exhausted());
        assert_eq!(
            budget.accepted_trials(),
            WeakPriorBudget::MAX_EQUIVALENT_TRIALS
        );
        assert!(!budget.admit(ShadowWeakPrior {
            kind: WeakPriorKind::ProviderTier,
            certified: false,
        }));
    }

    #[test]
    fn promotion_verdict_requires_lcb_fidelity_and_complete_contract() {
        let evaluator = InMemoryShadowEvaluator::new();
        let id = policy("promote-me");
        evaluator
            .record_observation(ShadowObservation {
                policy_id: id.clone(),
                observed_at: TimestampMillis::from_millis(20),
                matched_accepted_outcome: true,
                certification_contract_satisfied: true,
                fidelity: EvaluationFidelity::F5ProductionShadow,
            })
            .expect("record");
        let class = TaskClass::new("coding").expect("class");
        let threshold = PromotionThreshold { lcb_bp: 8_000 };
        let empty = QualityContract::new(ContractId::new("empty").expect("id"));
        let incomplete = evaluator
            .promotion_case(&id, class.clone(), 9_000, threshold, &empty)
            .expect("case");
        assert_eq!(
            incomplete.verdict(),
            ShadowPromotionVerdict::Rejected {
                reason: ShadowPromotionReject::IncompleteQualityContract,
            }
        );

        let complete = complete_contract();
        let low_fid = ShadowPromotionCase::from_parts(
            evaluator.assign(&id).expect("assign"),
            class.clone(),
            EvaluationFidelity::F2PartialTrajectory,
            9_000,
            threshold,
            &complete,
        );
        assert_eq!(
            low_fid.verdict(),
            ShadowPromotionVerdict::Rejected {
                reason: ShadowPromotionReject::InsufficientFidelity,
            }
        );

        let below = evaluator
            .promotion_case(&id, class.clone(), 7_999, threshold, &complete)
            .expect("below");
        assert_eq!(
            below.verdict(),
            ShadowPromotionVerdict::Rejected {
                reason: ShadowPromotionReject::BelowLcb,
            }
        );

        let eligible = evaluator
            .promotion_case(&id, class, 8_000, threshold, &complete)
            .expect("eligible");
        assert_eq!(
            eligible.verdict(),
            ShadowPromotionVerdict::EligibleForSafeSetConsideration
        );
        assert!(!eligible.grants_production_authority());
        assert!(!eligible.assignment.has_merge_authority());
        assert!(!eligible.assignment.has_publication_authority());
        assert!(!eligible.assignment.has_certification_authority());
        let err = eligible
            .assignment
            .escalate(ShadowAuthorityEscalation::Certify)
            .expect_err("still observe-only");
        assert!(
            err.to_string().contains("shadow isolation"),
            "unexpected error: {err}"
        );
    }
}
