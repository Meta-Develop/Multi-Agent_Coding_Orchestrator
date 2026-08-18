//! Quality-contract data.
//!
//! Fail-closed certification behaviour is issue #161. This module defines the
//! contract shape and an append-only validator API so later search phases
//! cannot remove a mandatory gate.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use super::ids::{ContractId, RequirementId, RuntimeSlug, ValidatorId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualityContract {
    contract_id: ContractId,
    requirements: Vec<RequirementContract>,
    invariants: Vec<InvariantContract>,
    mandatory_validators: Vec<ValidatorBinding>,
    performance_constraints: Vec<PerformanceConstraint>,
    security_constraints: Vec<SecurityConstraint>,
    compatibility_constraints: Vec<CompatibilityConstraint>,
    prohibited_changes: Vec<ScopeConstraint>,
    llm_only_review_permitted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequirementContract {
    pub requirement_id: RequirementId,
    pub implementation_paths: Vec<PathBuf>,
    pub validation_ids: Vec<ValidatorId>,
    pub status: RequirementStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequirementStatus {
    Unbound,
    InProgress,
    Satisfied,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantContract {
    pub invariant_id: RequirementId,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorBinding {
    pub validator_id: ValidatorId,
    pub kind: ValidatorKind,
    pub required_for_production: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorKind {
    DeterministicCommand { name: String },
    FormalProof { tool: String },
    ModelChecking { tool: String },
    ExhaustiveExploration,
    PropertyBasedTest { suite: String },
    DifferentialTest { suite: String },
    MutationTest { suite: String },
    StaticAnalysis { tool: String },
    Fuzzing { harness: String },
    SecurityAnalysis { tool: String },
    PerformanceBenchmark { name: String },
    LlmReview { lens: String, reviewer: RuntimeSlug },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceConstraint {
    pub name: String,
    pub ceiling_micros: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityConstraint {
    pub name: String,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityConstraint {
    pub name: String,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeConstraint {
    pub path_prefix: PathBuf,
}

impl QualityContract {
    pub fn new(contract_id: ContractId) -> Self {
        Self {
            contract_id,
            requirements: Vec::new(),
            invariants: Vec::new(),
            mandatory_validators: Vec::new(),
            performance_constraints: Vec::new(),
            security_constraints: Vec::new(),
            compatibility_constraints: Vec::new(),
            prohibited_changes: Vec::new(),
            llm_only_review_permitted: false,
        }
    }

    pub fn contract_id(&self) -> &ContractId {
        &self.contract_id
    }

    pub fn requirements(&self) -> &[RequirementContract] {
        &self.requirements
    }

    pub fn invariants(&self) -> &[InvariantContract] {
        &self.invariants
    }

    pub fn mandatory_validators(&self) -> &[ValidatorBinding] {
        &self.mandatory_validators
    }

    pub fn performance_constraints(&self) -> &[PerformanceConstraint] {
        &self.performance_constraints
    }

    pub fn security_constraints(&self) -> &[SecurityConstraint] {
        &self.security_constraints
    }

    pub fn compatibility_constraints(&self) -> &[CompatibilityConstraint] {
        &self.compatibility_constraints
    }

    pub fn prohibited_changes(&self) -> &[ScopeConstraint] {
        &self.prohibited_changes
    }

    pub fn llm_only_review_permitted(&self) -> bool {
        self.llm_only_review_permitted
    }

    pub fn add_requirement(&mut self, requirement: RequirementContract) {
        self.requirements.push(requirement);
    }

    pub fn add_invariant(&mut self, invariant: InvariantContract) {
        self.invariants.push(invariant);
    }

    /// Mandatory validators are append-only from the optimizer's perspective.
    /// There is no remove or replace API.
    pub fn add_mandatory_validator(&mut self, validator: ValidatorBinding) {
        if self
            .mandatory_validators
            .iter()
            .any(|existing| existing.validator_id == validator.validator_id)
        {
            return;
        }
        self.mandatory_validators.push(validator);
    }

    pub fn add_performance_constraint(&mut self, constraint: PerformanceConstraint) {
        self.performance_constraints.push(constraint);
    }

    pub fn add_security_constraint(&mut self, constraint: SecurityConstraint) {
        self.security_constraints.push(constraint);
    }

    pub fn add_compatibility_constraint(&mut self, constraint: CompatibilityConstraint) {
        self.compatibility_constraints.push(constraint);
    }

    pub fn add_prohibited_change(&mut self, constraint: ScopeConstraint) {
        self.prohibited_changes.push(constraint);
    }

    pub fn permit_llm_only_review(&mut self, permitted: bool) {
        self.llm_only_review_permitted = permitted;
    }
}
