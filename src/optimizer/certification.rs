//! Fail-closed certification against a [`QualityContract`].
//!
//! Quality is a hard constraint: a cheaper uncertified candidate is never
//! selected over a certified one, and missing, stale, misbound, or
//! unauthorized evidence fails closed. Later phases implement
//! [`QualityCertifier`] without editing the trait signature.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use super::error::OptimizerError;
use super::ids::{
    CandidateId, ContractId, EvidenceId, RequirementId, ReviewId, RuntimeSlug, TaskId,
    TimestampMillis, ValidatorId, VerifierProfileId,
};
use super::quality::{QualityContract, RequirementStatus, ReviewLens, ValidatorKind};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskBinding {
    pub task_id: TaskId,
    pub contract_id: ContractId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateBinding {
    pub candidate_id: CandidateId,
    pub produced_at: TimestampMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificationPlan {
    pub contract_id: ContractId,
    pub verifier_profile: VerifierProfileId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificationResult {
    pub certified: bool,
    pub requirement_coverage_complete: bool,
    pub mandatory_validators_passed: bool,
    pub performance_passed: bool,
    pub security_passed: bool,
    pub scope_integrity_passed: bool,
    pub audit_passed: bool,
    pub unresolved_findings: Vec<Finding>,
    pub evidence_bindings: Vec<EvidenceBinding>,
}

impl CertificationResult {
    pub fn rejected() -> Self {
        Self {
            certified: false,
            requirement_coverage_complete: false,
            mandatory_validators_passed: false,
            performance_passed: false,
            security_passed: false,
            scope_integrity_passed: false,
            audit_passed: false,
            unresolved_findings: Vec::new(),
            evidence_bindings: Vec::new(),
        }
    }

    /// Conjunction of the declared binary conditions.
    pub fn all_conditions_pass(&self) -> bool {
        self.requirement_coverage_complete
            && self.mandatory_validators_passed
            && self.performance_passed
            && self.security_passed
            && self.scope_integrity_passed
            && self.audit_passed
            && self.unresolved_findings.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub finding_id: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBinding {
    pub evidence_id: EvidenceId,
    pub candidate_id: CandidateId,
    pub produced_at: TimestampMillis,
    pub source: EvidenceSource,
    pub watermark: FreshnessWatermark,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceSource {
    DeterministicValidator { name: String },
    FormalTool { name: String },
    IndependentReviewer { slug: RuntimeSlug },
    ImplementingModel { slug: RuntimeSlug },
    Unauthorized { label: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreshnessWatermark {
    pub valid_until: TimestampMillis,
}

/// Object-safe certifier. Implementations arrive in later phases / #161 tests.
pub trait QualityCertifier {
    fn certify(
        &self,
        task: &TaskBinding,
        candidate: &CandidateBinding,
        contract: &QualityContract,
    ) -> Result<CertificationResult, OptimizerError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorOutcome {
    pub passed: bool,
    pub observable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewRecord {
    pub review_id: ReviewId,
    pub reviewer: RuntimeSlug,
    pub lens: ReviewLens,
    pub passed: bool,
    /// Persisted as a weak feature only. Zero certification authority.
    pub self_reported_confidence_bp: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateObservation {
    pub implementer: RuntimeSlug,
    pub requirement_status: BTreeMap<RequirementId, RequirementStatus>,
    pub validator_outcomes: BTreeMap<ValidatorId, ValidatorOutcome>,
    pub performance_passed: Option<bool>,
    pub security_passed: Option<bool>,
    pub scope_integrity_passed: Option<bool>,
    pub reviews: Vec<ReviewRecord>,
    pub evidence_bindings: Vec<EvidenceBinding>,
    /// Ignored by [`FailClosedCertifier`].
    pub self_reported_confidence_bp: Option<u16>,
}

/// Production certifier. Constructed with per-candidate observations so the
/// trait signature stays stable for later implementors.
#[derive(Debug, Clone)]
pub struct FailClosedCertifier {
    now: TimestampMillis,
    observations: BTreeMap<CandidateId, CandidateObservation>,
}

impl FailClosedCertifier {
    pub fn new(now: TimestampMillis) -> Self {
        Self {
            now,
            observations: BTreeMap::new(),
        }
    }

    pub fn insert_observation(
        &mut self,
        candidate_id: CandidateId,
        observation: CandidateObservation,
    ) {
        self.observations.insert(candidate_id, observation);
    }
}

impl QualityCertifier for FailClosedCertifier {
    fn certify(
        &self,
        task: &TaskBinding,
        candidate: &CandidateBinding,
        contract: &QualityContract,
    ) -> Result<CertificationResult, OptimizerError> {
        if task.contract_id != *contract.contract_id() {
            return Err(OptimizerError::invalid(
                "task is not bound to the supplied quality contract",
            ));
        }

        let mut result = CertificationResult::rejected();
        let Some(observation) = self.observations.get(&candidate.candidate_id) else {
            result.unresolved_findings.push(finding(
                "missing-observation",
                "candidate observation is missing; fail closed",
            ));
            return Ok(result);
        };

        result.evidence_bindings = observation.evidence_bindings.clone();
        if let Err(error) =
            validate_evidence_bindings(&observation.evidence_bindings, candidate, self.now)
        {
            result
                .unresolved_findings
                .push(finding("evidence", error.to_string()));
            return Ok(result);
        }

        result.requirement_coverage_complete =
            requirement_coverage_complete(contract, observation, &mut result.unresolved_findings);
        result.mandatory_validators_passed =
            mandatory_validators_passed(contract, observation, &mut result.unresolved_findings);
        result.performance_passed = observed_flag(
            observation.performance_passed,
            contract.performance_constraints().is_empty(),
            "performance",
            &mut result.unresolved_findings,
        );
        result.security_passed = observed_flag(
            observation.security_passed,
            contract.security_constraints().is_empty(),
            "security",
            &mut result.unresolved_findings,
        );
        result.scope_integrity_passed = observed_flag(
            observation.scope_integrity_passed,
            contract.prohibited_changes().is_empty(),
            "scope",
            &mut result.unresolved_findings,
        );
        result.audit_passed =
            independent_audit_passed(contract, observation, &mut result.unresolved_findings);

        let _ = observation.self_reported_confidence_bp;
        result.certified = result.all_conditions_pass();
        if !result.certified && result.unresolved_findings.is_empty() {
            result.unresolved_findings.push(finding(
                "uncertified",
                "declared contract conditions are not all satisfied",
            ));
        }
        Ok(result)
    }
}

fn finding(id: &str, message: impl Into<String>) -> Finding {
    Finding {
        finding_id: id.to_string(),
        message: message.into(),
    }
}

pub fn validate_evidence_bindings(
    bindings: &[EvidenceBinding],
    candidate: &CandidateBinding,
    now: TimestampMillis,
) -> Result<(), OptimizerError> {
    if bindings.is_empty() {
        return Err(OptimizerError::EvidenceRejected(
            "no evidence bindings were supplied".to_string(),
        ));
    }
    for binding in bindings {
        if binding.candidate_id != candidate.candidate_id {
            return Err(OptimizerError::EvidenceRejected(format!(
                "evidence {} is bound to a different candidate",
                binding.evidence_id
            )));
        }
        if now > binding.watermark.valid_until
            || binding.produced_at > binding.watermark.valid_until
        {
            return Err(OptimizerError::EvidenceRejected(format!(
                "evidence {} is stale",
                binding.evidence_id
            )));
        }
        match &binding.source {
            EvidenceSource::Unauthorized { label } => {
                return Err(OptimizerError::EvidenceRejected(format!(
                    "evidence {} comes from unauthorized source {label}",
                    binding.evidence_id
                )));
            }
            EvidenceSource::ImplementingModel { slug } => {
                return Err(OptimizerError::EvidenceRejected(format!(
                    "evidence {} is the implementing model {slug}; self-reports have zero authority",
                    binding.evidence_id
                )));
            }
            EvidenceSource::DeterministicValidator { .. }
            | EvidenceSource::FormalTool { .. }
            | EvidenceSource::IndependentReviewer { .. } => {}
        }
    }
    Ok(())
}

fn requirement_coverage_complete(
    contract: &QualityContract,
    observation: &CandidateObservation,
    findings: &mut Vec<Finding>,
) -> bool {
    if contract.requirements().is_empty() {
        findings.push(finding(
            "no-requirements",
            "quality contract declares no requirements; cannot certify",
        ));
        return false;
    }
    let mut complete = true;
    for requirement in contract.requirements() {
        if requirement.implementation_paths.is_empty() || requirement.validation_ids.is_empty() {
            findings.push(finding(
                requirement.requirement_id.as_str(),
                "requirement is missing implementation or validation bindings",
            ));
            complete = false;
            continue;
        }
        let status = observation
            .requirement_status
            .get(&requirement.requirement_id)
            .copied()
            .unwrap_or(RequirementStatus::Unbound);
        if status != RequirementStatus::Satisfied {
            findings.push(finding(
                requirement.requirement_id.as_str(),
                format!("requirement status is {status:?}, not satisfied"),
            ));
            complete = false;
        }
        for validator_id in &requirement.validation_ids {
            match observation.validator_outcomes.get(validator_id) {
                Some(outcome) if outcome.observable && outcome.passed => {}
                Some(outcome) if !outcome.observable => {
                    findings.push(finding(
                        validator_id.as_str(),
                        "requirement validator is unobservable",
                    ));
                    complete = false;
                }
                _ => {
                    findings.push(finding(
                        validator_id.as_str(),
                        "requirement validator is missing or failed",
                    ));
                    complete = false;
                }
            }
        }
    }
    complete
}

fn mandatory_validators_passed(
    contract: &QualityContract,
    observation: &CandidateObservation,
    findings: &mut Vec<Finding>,
) -> bool {
    if contract.mandatory_validators().is_empty() {
        findings.push(finding(
            "no-validators",
            "quality contract declares no mandatory validators; cannot certify",
        ));
        return false;
    }
    if !contract.llm_only_review_permitted()
        && !contract.has_machine_checkable_mandatory_validator()
    {
        findings.push(finding(
            "llm-only",
            "production certification requires a deterministic or formal validator",
        ));
        return false;
    }
    let mut passed = true;
    for binding in contract.mandatory_validators() {
        match observation.validator_outcomes.get(&binding.validator_id) {
            Some(outcome) if outcome.observable && outcome.passed => {}
            Some(outcome) if !outcome.observable => {
                findings.push(finding(
                    binding.validator_id.as_str(),
                    "mandatory validator is unobservable",
                ));
                passed = false;
            }
            Some(_) => {
                findings.push(finding(
                    binding.validator_id.as_str(),
                    "mandatory validator failed",
                ));
                passed = false;
            }
            None => {
                findings.push(finding(
                    binding.validator_id.as_str(),
                    "mandatory validator evidence is missing",
                ));
                passed = false;
            }
        }
        if binding.kind.is_formal()
            && !observation
                .validator_outcomes
                .contains_key(&binding.validator_id)
        {
            findings.push(finding(
                binding.validator_id.as_str(),
                "formal property has no bound formal tool; task cannot yet be certified",
            ));
            passed = false;
        }
    }
    passed
}

fn observed_flag(
    value: Option<bool>,
    vacuously_ok: bool,
    label: &str,
    findings: &mut Vec<Finding>,
) -> bool {
    match value {
        Some(true) => true,
        Some(false) => {
            findings.push(finding(label, format!("{label} constraint failed")));
            false
        }
        None if vacuously_ok => true,
        None => {
            findings.push(finding(
                label,
                format!("{label} evidence is unobservable; fail closed"),
            ));
            false
        }
    }
}

fn independent_audit_passed(
    contract: &QualityContract,
    observation: &CandidateObservation,
    findings: &mut Vec<Finding>,
) -> bool {
    if !contract.requires_llm_review() {
        return true;
    }
    let independent: Vec<&ReviewRecord> = observation
        .reviews
        .iter()
        .filter(|review| review.reviewer != observation.implementer)
        .collect();
    if independent.is_empty() {
        findings.push(finding(
            "audit",
            "implementing model is the sole reviewer; independent review required",
        ));
        return false;
    }
    let lenses: BTreeSet<&ReviewLens> = independent.iter().map(|review| &review.lens).collect();
    if independent.len() > 1 && lenses.len() < 2 {
        findings.push(finding(
            "audit",
            "independent reviewers share a single information lens",
        ));
        return false;
    }
    if independent.iter().any(|review| !review.passed) {
        findings.push(finding(
            "audit",
            "an independent review rejected the candidate",
        ));
        return false;
    }
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoredCandidate {
    pub candidate_id: CandidateId,
    pub cost_micros: i64,
    pub quality_lower_confidence_bp: u16,
    pub result: CertificationResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SelectionOutcome {
    Selected { candidate_id: CandidateId },
    Infeasible { reason: String },
}

impl SelectionOutcome {
    pub fn may_merge(&self) -> bool {
        matches!(self, Self::Selected { .. })
    }

    pub fn may_publish(&self) -> bool {
        self.may_merge()
    }
}

/// Quality cannot be traded for cost. Only certified candidates whose lower
/// confidence bound meets the threshold compete.
pub fn select_under_quality_constraint(
    candidates: &[ScoredCandidate],
    quality_threshold_bp: u16,
) -> SelectionOutcome {
    let mut eligible: Vec<&ScoredCandidate> = candidates
        .iter()
        .filter(|candidate| {
            candidate.result.certified
                && candidate.quality_lower_confidence_bp >= quality_threshold_bp
        })
        .collect();
    if eligible.is_empty() {
        return SelectionOutcome::Infeasible {
            reason: "no candidate satisfies the quality contract".to_string(),
        };
    }
    eligible.sort_by_key(|candidate| {
        (
            candidate.cost_micros,
            candidate.candidate_id.as_str().to_string(),
        )
    });
    SelectionOutcome::Selected {
        candidate_id: eligible[0].candidate_id.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::quality::{RequirementContract, ValidatorBinding};
    use std::path::PathBuf;

    fn now() -> TimestampMillis {
        TimestampMillis::from_millis(1_000)
    }

    fn watermark(until: u64) -> FreshnessWatermark {
        FreshnessWatermark {
            valid_until: TimestampMillis::from_millis(until),
        }
    }

    fn binding(candidate: &str, evidence: &str, until: u64) -> EvidenceBinding {
        EvidenceBinding {
            evidence_id: EvidenceId::new(evidence).expect("evidence"),
            candidate_id: CandidateId::new(candidate).expect("candidate"),
            produced_at: TimestampMillis::from_millis(500),
            source: EvidenceSource::DeterministicValidator {
                name: "cargo-test".to_string(),
            },
            watermark: watermark(until),
        }
    }

    fn production_contract() -> QualityContract {
        let mut contract = QualityContract::new(ContractId::new("c1").expect("contract"));
        contract.add_requirement(RequirementContract {
            requirement_id: RequirementId::new("REQ-004").expect("req"),
            implementation_paths: vec![PathBuf::from("src/optimizer/online_router.rs")],
            validation_ids: vec![ValidatorId::new("hidden-router-regression").expect("val")],
            status: RequirementStatus::Satisfied,
        });
        contract.add_mandatory_validator(ValidatorBinding {
            validator_id: ValidatorId::new("hidden-router-regression").expect("val"),
            kind: ValidatorKind::DeterministicCommand {
                name: "hidden-router-regression".to_string(),
            },
            required_for_production: true,
        });
        contract.add_performance_constraint(crate::optimizer::quality::PerformanceConstraint {
            name: "p95".to_string(),
            ceiling_micros: 1_000_000,
        });
        contract.add_security_constraint(crate::optimizer::quality::SecurityConstraint {
            name: "no-secrets".to_string(),
            required: true,
        });
        contract.add_prohibited_change(crate::optimizer::quality::ScopeConstraint {
            path_prefix: PathBuf::from("src/supervise.rs"),
        });
        contract
    }

    fn passing_observation(candidate: &str) -> CandidateObservation {
        let mut requirement_status = BTreeMap::new();
        requirement_status.insert(
            RequirementId::new("REQ-004").expect("req"),
            RequirementStatus::Satisfied,
        );
        let mut validator_outcomes = BTreeMap::new();
        validator_outcomes.insert(
            ValidatorId::new("hidden-router-regression").expect("val"),
            ValidatorOutcome {
                passed: true,
                observable: true,
            },
        );
        CandidateObservation {
            implementer: RuntimeSlug::new("worker-model").expect("slug"),
            requirement_status,
            validator_outcomes,
            performance_passed: Some(true),
            security_passed: Some(true),
            scope_integrity_passed: Some(true),
            reviews: Vec::new(),
            evidence_bindings: vec![binding(candidate, "ev-1", 2_000)],
            self_reported_confidence_bp: Some(10_000),
        }
    }

    fn task() -> TaskBinding {
        TaskBinding {
            task_id: TaskId::new("t1").expect("task"),
            contract_id: ContractId::new("c1").expect("contract"),
        }
    }

    fn candidate(id: &str) -> CandidateBinding {
        CandidateBinding {
            candidate_id: CandidateId::new(id).expect("candidate"),
            produced_at: TimestampMillis::from_millis(500),
        }
    }

    #[test]
    fn certified_candidate_beats_cheaper_uncertified_candidate() {
        let mut certified = CertificationResult::rejected();
        certified.certified = true;
        certified.requirement_coverage_complete = true;
        certified.mandatory_validators_passed = true;
        certified.performance_passed = true;
        certified.security_passed = true;
        certified.scope_integrity_passed = true;
        certified.audit_passed = true;

        let cheaper = ScoredCandidate {
            candidate_id: CandidateId::new("cheap").expect("id"),
            cost_micros: 1,
            quality_lower_confidence_bp: 4000,
            result: CertificationResult::rejected(),
        };
        let expensive = ScoredCandidate {
            candidate_id: CandidateId::new("certified").expect("id"),
            cost_micros: 100,
            quality_lower_confidence_bp: 9000,
            result: certified,
        };
        let outcome = select_under_quality_constraint(&[cheaper, expensive], 8000);
        assert_eq!(
            outcome,
            SelectionOutcome::Selected {
                candidate_id: CandidateId::new("certified").expect("id")
            }
        );
        assert!(outcome.may_merge());
    }

    #[test]
    fn no_satisfying_candidate_is_infeasible_and_cannot_merge() {
        let cheap = ScoredCandidate {
            candidate_id: CandidateId::new("cheap").expect("id"),
            cost_micros: 1,
            quality_lower_confidence_bp: 4000,
            result: CertificationResult::rejected(),
        };
        let outcome = select_under_quality_constraint(&[cheap], 8000);
        assert_eq!(
            outcome,
            SelectionOutcome::Infeasible {
                reason: "no candidate satisfies the quality contract".to_string()
            }
        );
        assert!(!outcome.may_merge());
        assert!(!outcome.may_publish());
    }

    #[test]
    fn evidence_from_another_candidate_fails_closed() {
        let foreign = binding("other", "ev-x", 2_000);
        let error = validate_evidence_bindings(&[foreign], &candidate("self"), now())
            .expect_err("foreign evidence");
        assert!(matches!(error, OptimizerError::EvidenceRejected(_)));
    }

    #[test]
    fn stale_evidence_fails_closed() {
        let stale = binding("self", "ev-old", 100);
        let error =
            validate_evidence_bindings(&[stale], &candidate("self"), now()).expect_err("stale");
        assert!(error.to_string().contains("stale"));
    }

    #[test]
    fn unauthorized_and_self_reported_evidence_fail_closed() {
        let mut unauthorized = binding("self", "ev-bad", 2_000);
        unauthorized.source = EvidenceSource::Unauthorized {
            label: "anonymous".to_string(),
        };
        assert!(validate_evidence_bindings(&[unauthorized], &candidate("self"), now()).is_err());

        let mut self_report = binding("self", "ev-self", 2_000);
        self_report.source = EvidenceSource::ImplementingModel {
            slug: RuntimeSlug::new("worker-model").expect("slug"),
        };
        assert!(validate_evidence_bindings(&[self_report], &candidate("self"), now()).is_err());
    }

    #[test]
    fn fail_closed_certifier_accepts_a_complete_contract() {
        let contract = production_contract();
        let mut certifier = FailClosedCertifier::new(now());
        certifier.insert_observation(
            CandidateId::new("ok").expect("id"),
            passing_observation("ok"),
        );
        let result = certifier
            .certify(&task(), &candidate("ok"), &contract)
            .expect("certify");
        assert!(result.certified);
        assert!(result.all_conditions_pass());
    }

    #[test]
    fn missing_requirement_evidence_is_a_hard_failure() {
        let contract = production_contract();
        let mut observation = passing_observation("gap");
        observation.requirement_status.clear();
        let mut certifier = FailClosedCertifier::new(now());
        certifier.insert_observation(CandidateId::new("gap").expect("id"), observation);
        let result = certifier
            .certify(&task(), &candidate("gap"), &contract)
            .expect("certify");
        assert!(!result.certified);
        assert!(!result.requirement_coverage_complete);
    }

    #[test]
    fn llm_only_review_is_insufficient_for_production() {
        let mut contract = QualityContract::new(ContractId::new("c1").expect("contract"));
        contract.add_requirement(RequirementContract {
            requirement_id: RequirementId::new("REQ-1").expect("req"),
            implementation_paths: vec![PathBuf::from("src/x.rs")],
            validation_ids: vec![ValidatorId::new("review").expect("val")],
            status: RequirementStatus::Satisfied,
        });
        contract.add_mandatory_validator(ValidatorBinding {
            validator_id: ValidatorId::new("review").expect("val"),
            kind: ValidatorKind::LlmReview {
                lens: ReviewLens::DiffOnly,
                reviewer: RuntimeSlug::new("reviewer").expect("slug"),
            },
            required_for_production: true,
        });
        let mut observation = passing_observation("llm");
        observation.validator_outcomes.insert(
            ValidatorId::new("review").expect("val"),
            ValidatorOutcome {
                passed: true,
                observable: true,
            },
        );
        observation.reviews.push(ReviewRecord {
            review_id: ReviewId::new("r1").expect("id"),
            reviewer: RuntimeSlug::new("reviewer").expect("slug"),
            lens: ReviewLens::DiffOnly,
            passed: true,
            self_reported_confidence_bp: Some(9900),
        });
        let mut certifier = FailClosedCertifier::new(now());
        certifier.insert_observation(CandidateId::new("llm").expect("id"), observation);
        let result = certifier
            .certify(&task(), &candidate("llm"), &contract)
            .expect("certify");
        assert!(!result.certified);
        assert!(!result.mandatory_validators_passed);
    }

    #[test]
    fn implementing_model_cannot_be_sole_certifier() {
        let mut contract = production_contract();
        contract.add_mandatory_validator(ValidatorBinding {
            validator_id: ValidatorId::new("review").expect("val"),
            kind: ValidatorKind::LlmReview {
                lens: ReviewLens::SpecificationVsResult,
                reviewer: RuntimeSlug::new("reviewer").expect("slug"),
            },
            required_for_production: true,
        });
        let mut observation = passing_observation("selfish");
        observation.reviews.push(ReviewRecord {
            review_id: ReviewId::new("r-self").expect("id"),
            reviewer: RuntimeSlug::new("worker-model").expect("slug"),
            lens: ReviewLens::SpecificationVsResult,
            passed: true,
            self_reported_confidence_bp: Some(10_000),
        });
        let mut certifier = FailClosedCertifier::new(now());
        certifier.insert_observation(CandidateId::new("selfish").expect("id"), observation);
        let result = certifier
            .certify(&task(), &candidate("selfish"), &contract)
            .expect("certify");
        assert!(!result.certified);
        assert!(!result.audit_passed);
    }

    #[test]
    fn self_reported_confidence_has_zero_certification_authority() {
        let contract = production_contract();
        let mut observation = passing_observation("confident");
        observation.self_reported_confidence_bp = Some(10_000);
        observation.performance_passed = None;
        let mut certifier = FailClosedCertifier::new(now());
        certifier.insert_observation(CandidateId::new("confident").expect("id"), observation);
        let result = certifier
            .certify(&task(), &candidate("confident"), &contract)
            .expect("certify");
        assert!(!result.certified);
        assert!(!result.performance_passed);
    }
}
