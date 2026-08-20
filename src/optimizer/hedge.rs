//! Delayed hedging. Implemented by issue #168.
//!
//! Start the most resource-efficient feasible policy, wait a learned
//! task-class-specific delay, and launch a second policy only when progress
//! is below threshold. Cancel the redundant branch once one candidate
//! becomes certifiable.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::error::OptimizerError;
use super::ids::{PolicyId, TimestampMillis};
use super::predictor::{feature_bool, feature_keys, feature_text};
use super::state::OptimizerState;
use super::telemetry::{InvocationRecord, TelemetrySink};
use super::trajectory::TrajectoryObservation;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HedgePlan {
    pub delayed_policy: PolicyId,
    pub delay_seconds: u64,
    pub primary_policy: PolicyId,
    pub cancel_when_certifiable: bool,
    pub max_concurrent_hedges: u32,
    pub cancellation: Option<HedgeCancellation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HedgeCancellation {
    pub cancelled_policy: PolicyId,
    pub surviving_policy: PolicyId,
    pub reason: String,
    pub recorded_at: TimestampMillis,
}

pub trait HedgePlanner {
    fn plan(&self, state: &OptimizerState) -> Result<Option<HedgePlan>, OptimizerError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HedgeForecast {
    pub policy: PolicyId,
    pub delay_seconds: u64,
    pub latency_samples_micros: Vec<i64>,
    pub partial_cost_micros: i64,
}

#[derive(Debug, Clone)]
pub struct DelayedHedgePlanner {
    primary: PolicyId,
    hedge: PolicyId,
    delay_by_task_class: BTreeMap<String, u64>,
    default_delay_seconds: u64,
    forecasts: BTreeMap<PolicyId, HedgeForecast>,
    shadow_price: i64,
    max_concurrent_hedges: u32,
}

impl DelayedHedgePlanner {
    pub fn new(primary: PolicyId, hedge: PolicyId) -> Self {
        Self {
            primary,
            hedge,
            delay_by_task_class: BTreeMap::new(),
            default_delay_seconds: 30,
            forecasts: BTreeMap::new(),
            shadow_price: 1,
            max_concurrent_hedges: 1,
        }
    }

    pub fn set_delay_for_task_class(&mut self, task_class: impl Into<String>, delay_seconds: u64) {
        self.delay_by_task_class
            .insert(task_class.into(), delay_seconds);
    }

    pub fn insert_forecast(&mut self, forecast: HedgeForecast) {
        self.forecasts.insert(forecast.policy.clone(), forecast);
    }

    pub fn set_shadow_price(&mut self, price: i64) {
        self.shadow_price = price.max(0);
    }

    pub fn delay_for(&self, state: &OptimizerState) -> u64 {
        feature_text(&state.task_features, feature_keys::TASK_CLASS)
            .and_then(|class| self.delay_by_task_class.get(&class).copied())
            .unwrap_or(self.default_delay_seconds)
    }

    /// Hedge when `P(T_1 > h) × E[latency reduction] > shadow-priced partial cost`.
    pub fn hedge_justified(&self, state: &OptimizerState) -> bool {
        if !progress_below_threshold(state) {
            return false;
        }
        let delay = self.delay_for(state);
        let Some(primary) = self.forecasts.get(&self.primary) else {
            return false;
        };
        let Some(hedge) = self.forecasts.get(&self.hedge) else {
            return false;
        };
        if primary.latency_samples_micros.is_empty() {
            return false;
        }
        let horizon_micros = i64::try_from(delay.saturating_mul(1_000_000)).unwrap_or(i64::MAX);
        let misses = primary
            .latency_samples_micros
            .iter()
            .filter(|sample| **sample > horizon_micros)
            .count();
        let p_miss_bp =
            (misses as u64).saturating_mul(10_000) / primary.latency_samples_micros.len() as u64;
        let primary_mean = mean(&primary.latency_samples_micros);
        let hedge_mean = mean(&hedge.latency_samples_micros);
        let reduction = primary_mean.saturating_sub(hedge_mean).max(0);
        let expected_benefit = (i128::from(p_miss_bp) * i128::from(reduction)) / 10_000;
        let priced_cost =
            i128::from(hedge.partial_cost_micros) * i128::from(self.shadow_price.max(1));
        expected_benefit > priced_cost
    }

    pub fn cancel_if_certifiable(&self, state: &OptimizerState) -> Option<HedgeCancellation> {
        let certified = state.trajectory.events().iter().rev().find_map(|event| {
            matches!(event.observation, TrajectoryObservation::Certified)
                .then(|| event.policy_id.clone())
        })?;
        let cancelled = if certified == self.primary {
            self.hedge.clone()
        } else if certified == self.hedge {
            self.primary.clone()
        } else {
            return None;
        };
        Some(HedgeCancellation {
            cancelled_policy: cancelled,
            surviving_policy: certified,
            reason: "redundant_branch_cancelled_after_certification".to_string(),
            recorded_at: state.horizon.now,
        })
    }

    pub fn emit_cancellation(
        &self,
        sink: &dyn TelemetrySink,
        cancellation: &HedgeCancellation,
        state: &OptimizerState,
    ) -> Result<(), OptimizerError> {
        let mut record = InvocationRecord::new(
            cancellation.cancelled_policy.clone(),
            super::ids::CandidateId::new(format!("hedge-cancel-{}", cancellation.cancelled_policy))
                .map_err(|_| OptimizerError::invalid("cancellation candidate id"))?,
            cancellation.recorded_at,
            state.budget.snapshot(cancellation.recorded_at),
        );
        record.finished_at = Some(cancellation.recorded_at);
        sink.record(&record)
    }
}

impl HedgePlanner for DelayedHedgePlanner {
    fn plan(&self, state: &OptimizerState) -> Result<Option<HedgePlan>, OptimizerError> {
        if let Some(cancellation) = self.cancel_if_certifiable(state) {
            return Ok(Some(HedgePlan {
                delayed_policy: self.hedge.clone(),
                delay_seconds: self.delay_for(state),
                primary_policy: self.primary.clone(),
                cancel_when_certifiable: true,
                max_concurrent_hedges: self.max_concurrent_hedges,
                cancellation: Some(cancellation),
            }));
        }
        if !self.hedge_justified(state) {
            return Ok(None);
        }
        Ok(Some(HedgePlan {
            delayed_policy: self.hedge.clone(),
            delay_seconds: self.delay_for(state),
            primary_policy: self.primary.clone(),
            cancel_when_certifiable: true,
            max_concurrent_hedges: self.max_concurrent_hedges,
            cancellation: None,
        }))
    }
}

fn progress_below_threshold(state: &OptimizerState) -> bool {
    if feature_bool(&state.task_features, feature_keys::PROGRESS_BELOW_THRESHOLD) == Some(true) {
        return true;
    }
    state.trajectory.events().last().is_some_and(|event| {
        matches!(
            event.observation,
            TrajectoryObservation::NoProgress
                | TrajectoryObservation::TimeoutRisk
                | TrajectoryObservation::QuotaPressure
        )
    })
}

fn mean(samples: &[i64]) -> i64 {
    if samples.is_empty() {
        return 0;
    }
    let sum = samples
        .iter()
        .fold(0i128, |acc, sample| acc + i128::from(*sample));
    i64::try_from(sum / i128::from(samples.len() as i64)).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::super::state::DecisionHorizon;
    use super::super::trajectory::TrajectoryEvent;
    use super::*;
    use crate::optimizer::ids::{CandidateId, PolicyNodeId};
    use crate::optimizer::predictor::insert_text;
    use crate::optimizer::resources::ResourceVector;

    fn state_with(observation: TrajectoryObservation, policy: &str) -> OptimizerState {
        let mut state = OptimizerState::new(DecisionHorizon {
            now: TimestampMillis::from_millis(10),
            deadline: None,
            next_reset: None,
        });
        insert_text(&mut state.task_features, feature_keys::TASK_CLASS, "repair");
        state.trajectory.push(TrajectoryEvent {
            at: TimestampMillis::from_millis(9),
            policy_id: PolicyId::new(policy).expect("p"),
            node_id: PolicyNodeId::new("start").expect("n"),
            observation,
            features: Default::default(),
        });
        state
    }

    fn planner() -> DelayedHedgePlanner {
        let mut planner = DelayedHedgePlanner::new(
            PolicyId::new("efficient").expect("p"),
            PolicyId::new("hedge").expect("h"),
        );
        planner.set_delay_for_task_class("repair", 20);
        planner.insert_forecast(HedgeForecast {
            policy: PolicyId::new("efficient").expect("p"),
            delay_seconds: 20,
            latency_samples_micros: vec![
                5_000_000,
                60_000_000,
                90_000_000,
                120_000_000,
                180_000_000,
            ],
            partial_cost_micros: 10,
        });
        planner.insert_forecast(HedgeForecast {
            policy: PolicyId::new("hedge").expect("h"),
            delay_seconds: 20,
            latency_samples_micros: vec![8_000_000, 9_000_000, 10_000_000],
            partial_cost_micros: 10,
        });
        planner
    }

    #[test]
    fn no_hedge_when_progress_is_healthy() {
        let planner = planner();
        let state = state_with(TrajectoryObservation::Progress, "efficient");
        assert!(planner.plan(&state).expect("plan").is_none());
    }

    #[test]
    fn hedge_fires_when_progress_is_below_threshold_and_tail_is_expensive() {
        let planner = planner();
        let state = state_with(TrajectoryObservation::NoProgress, "efficient");
        let plan = planner.plan(&state).expect("plan").expect("hedge");
        assert_eq!(plan.delayed_policy.as_str(), "hedge");
        assert_eq!(plan.delay_seconds, 20);
        assert!(plan.cancellation.is_none());
        assert!(plan.cancel_when_certifiable);
    }

    struct RecordingSink {
        records: std::sync::Mutex<Vec<InvocationRecord>>,
    }

    impl TelemetrySink for RecordingSink {
        fn record(&self, record: &InvocationRecord) -> Result<(), OptimizerError> {
            self.records.lock().expect("lock").push(record.clone());
            Ok(())
        }
    }

    #[test]
    fn fired_hedge_cancels_redundant_branch_and_records_telemetry() {
        let planner = planner();
        let mut state = state_with(TrajectoryObservation::Certified, "efficient");
        state.budget = ResourceVector::new();
        let plan = planner.plan(&state).expect("plan").expect("cancel");
        let cancellation = plan.cancellation.expect("cancellation");
        assert_eq!(cancellation.cancelled_policy.as_str(), "hedge");
        assert_eq!(cancellation.surviving_policy.as_str(), "efficient");
        assert!(cancellation.reason.contains("cancelled"));

        let sink = RecordingSink {
            records: std::sync::Mutex::new(Vec::new()),
        };
        planner
            .emit_cancellation(&sink, &cancellation, &state)
            .expect("telemetry");
        let records = sink.records.lock().expect("lock");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].policy_id.as_str(), "hedge");
        let _ = CandidateId::new("hedge-cancel-hedge").expect("id");
    }
}
