//! Optimizer decision state `s_t`.
//!
//! Feature extractors (#163), telemetry (#159), and resource accounting
//! (#162) fill these fields. The state shape stays stable so later phases
//! do not edit this module to plug in.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::features::{RepoFeatures, TaskFeatures};
use super::ids::{PolicyId, TimestampMillis};
use super::resources::ResourceVector;
use super::trajectory::TrajectoryHistory;

/// Time-to-reset and deadline horizon `τ_t`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionHorizon {
    pub now: TimestampMillis,
    pub deadline: Option<TimestampMillis>,
    pub next_reset: Option<TimestampMillis>,
}

/// Learned posteriors `Θ_t`. Entries are keyed by policy so #167/#170 can
/// write new summaries without changing this type.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LearnedPosteriors {
    entries: BTreeMap<PolicyId, PosteriorSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PosteriorSummary {
    pub observation_count: u32,
    pub last_updated: TimestampMillis,
}

impl LearnedPosteriors {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, policy_id: PolicyId, summary: PosteriorSummary) {
        self.entries.insert(policy_id, summary);
    }

    pub fn get(&self, policy_id: &PolicyId) -> Option<&PosteriorSummary> {
        self.entries.get(policy_id)
    }
}

/// `s_t = (task features, repo features, trajectory h_t, budget B_t, τ_t, Θ_t)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizerState {
    pub task_features: TaskFeatures,
    pub repo_features: RepoFeatures,
    pub trajectory: TrajectoryHistory,
    pub budget: ResourceVector,
    pub horizon: DecisionHorizon,
    pub posteriors: LearnedPosteriors,
}

impl OptimizerState {
    pub fn new(horizon: DecisionHorizon) -> Self {
        Self {
            task_features: TaskFeatures::new(),
            repo_features: RepoFeatures::new(),
            trajectory: TrajectoryHistory::new(),
            budget: ResourceVector::new(),
            horizon,
            posteriors: LearnedPosteriors::new(),
        }
    }
}
