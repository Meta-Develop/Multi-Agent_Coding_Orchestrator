//! Shadow evaluation. Implemented by issue #169.
//!
//! Shadow policies never gain merge, publication, or certification authority.

use serde::{Deserialize, Serialize};

use super::error::OptimizerError;
use super::ids::PolicyId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShadowAuthority {
    ObserveOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowAssignment {
    pub policy_id: PolicyId,
    pub authority: ShadowAuthority,
}

pub trait ShadowEvaluator {
    fn assign(&self, policy_id: &PolicyId) -> Result<ShadowAssignment, OptimizerError>;
}

impl ShadowAssignment {
    pub fn has_publication_authority(&self) -> bool {
        false
    }
}
