//! Cost-to-certification objective. Implemented by issue #167.
//!
//! Quality is not a term in this objective. It is a hard constraint evaluated
//! by [`crate::optimizer::certification`].

use serde::{Deserialize, Serialize};

use super::error::OptimizerError;
use super::ids::PolicyId;
use super::predictor::PolicyOutcomeDistribution;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectiveValue {
    pub policy_id: PolicyId,
    pub risk_adjusted_cost_micros: i64,
    pub tail_latency_micros: i64,
}

pub trait ObjectiveEvaluator {
    fn evaluate(
        &self,
        distribution: &PolicyOutcomeDistribution,
    ) -> Result<ObjectiveValue, OptimizerError>;
}
