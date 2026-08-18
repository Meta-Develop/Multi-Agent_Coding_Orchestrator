//! Attributed invocation telemetry. Implemented by issue #159.

use serde::{Deserialize, Serialize};

use super::error::OptimizerError;
use super::ids::{CandidateId, PolicyId, TimestampMillis};
use super::resources::ResourceSnapshot;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationRecord {
    pub policy_id: PolicyId,
    pub candidate_id: CandidateId,
    pub started_at: TimestampMillis,
    pub finished_at: Option<TimestampMillis>,
    pub quota_snapshot: ResourceSnapshot,
}

pub trait TelemetrySink {
    fn record(&self, record: &InvocationRecord) -> Result<(), OptimizerError>;
}
