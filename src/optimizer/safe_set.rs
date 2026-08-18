//! Safe-set promotion. Implemented by issue #169.

use serde::{Deserialize, Serialize};

use super::error::OptimizerError;
use super::ids::PolicyId;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeSet {
    pub policy_ids: Vec<PolicyId>,
}

pub trait SafeSetStore {
    fn contains(&self, policy_id: &PolicyId) -> Result<bool, OptimizerError>;
    fn snapshot(&self) -> Result<SafeSet, OptimizerError>;
}
