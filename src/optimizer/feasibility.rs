//! Chance-constrained feasibility. Implemented by issue #167.

use serde::{Deserialize, Serialize};

use super::error::OptimizerError;
use super::ids::PolicyId;
use super::policy::PolicyGraph;
use super::state::OptimizerState;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeasibilityResult {
    pub policy_id: PolicyId,
    pub feasible: bool,
    pub rejection_reasons: Vec<String>,
}

pub trait FeasibilityChecker {
    fn check(
        &self,
        state: &OptimizerState,
        policy: &PolicyGraph,
    ) -> Result<FeasibilityResult, OptimizerError>;
}
