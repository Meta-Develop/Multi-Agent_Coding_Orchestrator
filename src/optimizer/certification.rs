//! Certification plan and certifier trait boundary.
//!
//! Fail-closed evaluation is issue #161. Later phases implement
//! [`QualityCertifier`] without editing this trait signature.

use serde::{Deserialize, Serialize};

use super::error::OptimizerError;
use super::ids::{
    CandidateId, ContractId, EvidenceId, FindingId, RuntimeSlug, TaskId, TimestampMillis,
    VerifierProfileId,
};
use super::quality::QualityContract;

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
    pub finding_id: FindingId,
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
