//! Delayed hedging. Implemented by issue #168.

use serde::{Deserialize, Serialize};

use super::error::OptimizerError;
use super::ids::PolicyId;
use super::state::OptimizerState;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HedgePlan {
    pub delayed_policy: PolicyId,
    pub delay_seconds: u64,
}

pub trait HedgePlanner {
    fn plan(&self, state: &OptimizerState) -> Result<Option<HedgePlan>, OptimizerError>;
}
