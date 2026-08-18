//! Offline replay and certified-equal comparison. Implemented by issue #166.

use serde::{Deserialize, Serialize};

use super::error::OptimizerError;
use super::explanation::DecisionExplanation;
use super::ids::PolicyId;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayRecord {
    pub policy_id: PolicyId,
    pub explanation: DecisionExplanation,
}

pub trait ReplayStore {
    fn load(&self, policy_id: &PolicyId) -> Result<Option<ReplayRecord>, OptimizerError>;
}
