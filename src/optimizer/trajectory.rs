//! Running-trajectory history consumed by [`crate::optimizer::state::OptimizerState`].
//!
//! Issue #164 classifies progress and failure modes. This module only stores
//! the ordered evidence later classifiers read.

use serde::{Deserialize, Serialize};

use super::features::TrajectoryFeatures;
use super::ids::{PolicyId, PolicyNodeId, TimestampMillis};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrajectoryHistory {
    events: Vec<TrajectoryEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrajectoryEvent {
    pub at: TimestampMillis,
    pub policy_id: PolicyId,
    pub node_id: PolicyNodeId,
    pub observation: TrajectoryObservation,
    pub features: TrajectoryFeatures,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrajectoryObservation {
    Started,
    Progress,
    NoProgress,
    LocalizedFailure,
    StructuralFailure,
    QuotaPressure,
    TimeoutRisk,
    HumanEscalationRequired,
    Certified,
    FailedCertification,
}

impl TrajectoryHistory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, event: TrajectoryEvent) {
        self.events.push(event);
    }

    pub fn events(&self) -> &[TrajectoryEvent] {
        &self.events
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}
