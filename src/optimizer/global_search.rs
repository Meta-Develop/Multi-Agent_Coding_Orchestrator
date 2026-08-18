//! Offline / global candidate proposal. Implemented by issue #169.
//!
//! The trait signature is the plug-in boundary. Search must receive the
//! quality contract from the caller and cannot mutate it (see #161).

use serde::{Deserialize, Serialize};

use super::error::OptimizerError;
use super::ids::PolicyId;
use super::policy::PolicyGraph;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizationHistory {
    pub evaluated_policy_ids: Vec<PolicyId>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySearchSpace {
    pub seed_policy_ids: Vec<PolicyId>,
}

pub trait GlobalPolicyOptimizer {
    fn propose(
        &self,
        history: &OptimizationHistory,
        search_space: &PolicySearchSpace,
    ) -> Result<Vec<PolicyGraph>, OptimizerError>;
}
