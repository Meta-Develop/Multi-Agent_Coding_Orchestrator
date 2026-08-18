//! Online policy selection. Implemented by issue #167.

use serde::{Deserialize, Serialize};

use super::error::OptimizerError;
use super::explanation::DecisionExplanation;
use super::ids::PolicyId;
use super::policy::PolicyGraph;
use super::state::OptimizerState;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouterDecision {
    Select {
        policy_id: PolicyId,
        explanation: DecisionExplanation,
    },
    Infeasible {
        reason: String,
        explanation: DecisionExplanation,
    },
}

pub trait OnlineRouter {
    fn select(
        &self,
        state: &OptimizerState,
        candidates: &[PolicyGraph],
    ) -> Result<RouterDecision, OptimizerError>;
}
