//! Machine-readable decision explanations. Consumed by #167 and replay (#166).

use serde::{Deserialize, Serialize};

use super::ids::{PolicyId, TimestampMillis};
use super::resources::ResourceSnapshot;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionExplanation {
    pub decided_at: TimestampMillis,
    pub selected: Option<PolicyId>,
    pub candidate_ids: Vec<PolicyId>,
    pub rejection_reasons: Vec<String>,
    pub resources: ResourceSnapshot,
}
