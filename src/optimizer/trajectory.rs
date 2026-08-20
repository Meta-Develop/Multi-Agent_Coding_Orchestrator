//! Running-trajectory history consumed by [`crate::optimizer::state::OptimizerState`].
//!
//! This module stores the ordered evidence later classifiers read. Issue #164
//! classifies progress and failure modes from these events and their feature
//! bags; it does not rewrite the event vocabulary.

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

    pub fn last_event(&self) -> Option<&TrajectoryEvent> {
        self.events.last()
    }

    pub fn last_observation(&self) -> Option<&TrajectoryObservation> {
        self.events.last().map(|event| &event.observation)
    }

    pub fn latest_features(&self) -> Option<&TrajectoryFeatures> {
        self.events.last().map(|event| &event.features)
    }

    pub fn last_progress_at(&self) -> Option<TimestampMillis> {
        self.events
            .iter()
            .rev()
            .find(|event| {
                matches!(
                    event.observation,
                    TrajectoryObservation::Progress | TrajectoryObservation::Certified
                )
            })
            .map(|event| event.at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::ids::PolicyId;

    fn event(at: u64, observation: TrajectoryObservation) -> TrajectoryEvent {
        TrajectoryEvent {
            at: TimestampMillis::from_millis(at),
            policy_id: PolicyId::new("p").expect("policy"),
            node_id: PolicyNodeId::new("n").expect("node"),
            observation,
            features: TrajectoryFeatures::new(),
        }
    }

    #[test]
    fn latest_features_and_last_progress_read_ordered_evidence() {
        let mut history = TrajectoryHistory::new();
        history.push(event(1, TrajectoryObservation::Started));
        history.push(event(5, TrajectoryObservation::Progress));
        history.push(event(9, TrajectoryObservation::NoProgress));
        assert_eq!(
            history.last_progress_at().map(TimestampMillis::as_millis),
            Some(5)
        );
        assert!(matches!(
            history.last_observation(),
            Some(TrajectoryObservation::NoProgress)
        ));
        assert!(history.latest_features().is_some());
    }
}
