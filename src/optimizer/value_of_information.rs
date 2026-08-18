//! Value-of-information probes. Implemented by issue #168.

use serde::{Deserialize, Serialize};

use super::error::OptimizerError;
use super::ids::PolicyId;
use super::policy::PolicyGraph;
use super::state::OptimizerState;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoyDecision {
    pub probe_policy: Option<PolicyId>,
    pub expected_value_micros: i64,
}

pub trait ValueOfInformation {
    fn evaluate_probe(
        &self,
        state: &OptimizerState,
        candidates: &[PolicyGraph],
    ) -> Result<VoyDecision, OptimizerError>;
}
