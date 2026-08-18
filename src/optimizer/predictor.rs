//! Predictive outcome distributions. Implemented by issue #167.

use serde::{Deserialize, Serialize};

use super::error::OptimizerError;
use super::ids::PolicyId;
use super::policy::PolicyGraph;
use super::state::OptimizerState;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyOutcomeDistribution {
    pub policy_id: PolicyId,
    /// Millionths of a unit; deterministic stand-in for a real density.
    pub expected_cost_micros: i64,
    pub expected_latency_micros: i64,
    pub quality_lower_confidence_bp: u16,
    pub certified_probability_bp: u16,
}

pub trait PolicyPredictor {
    fn predict(
        &self,
        state: &OptimizerState,
        policy: &PolicyGraph,
    ) -> Result<PolicyOutcomeDistribution, OptimizerError>;
}
