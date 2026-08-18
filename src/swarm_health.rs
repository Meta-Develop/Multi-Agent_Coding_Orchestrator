use std::collections::VecDeque;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssignmentHealthOutcome {
    Accepted,
    Rejected,
    Failed,
    Retried,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmHealthSignal {
    AssignmentOutcome(AssignmentHealthOutcome),
    ClaimAcquisitionDenied,
    ClaimAcquisitionFailed,
    SemanticConflictBlocked { conflicts: usize },
    SemanticConflictWarned { conflicts: usize },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CircuitBreakerConfig {
    pub window_capacity: usize,
    pub assignment_failure_threshold: usize,
    pub retry_threshold: usize,
    pub claim_denial_threshold: usize,
    pub rejection_threshold: usize,
    pub semantic_conflict_threshold: usize,
    pub open_cooldown_signals: usize,
    pub half_open_successes: usize,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            window_capacity: 12,
            assignment_failure_threshold: 3,
            retry_threshold: 4,
            claim_denial_threshold: 3,
            rejection_threshold: 3,
            semantic_conflict_threshold: 4,
            open_cooldown_signals: 4,
            half_open_successes: 2,
        }
    }
}

impl CircuitBreakerConfig {
    fn validate(&self) -> Result<(), CircuitBreakerConfigError> {
        if self.window_capacity == 0 {
            return Err(CircuitBreakerConfigError::ZeroValue("window_capacity"));
        }
        for (name, value) in [
            (
                "assignment_failure_threshold",
                self.assignment_failure_threshold,
            ),
            ("retry_threshold", self.retry_threshold),
            ("claim_denial_threshold", self.claim_denial_threshold),
            ("rejection_threshold", self.rejection_threshold),
            (
                "semantic_conflict_threshold",
                self.semantic_conflict_threshold,
            ),
            ("open_cooldown_signals", self.open_cooldown_signals),
            ("half_open_successes", self.half_open_successes),
        ] {
            if value == 0 {
                return Err(CircuitBreakerConfigError::ZeroValue(name));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CircuitBreakerConfigError {
    #[error("circuit-breaker configuration field '{0}' must be greater than zero")]
    ZeroValue(&'static str),
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SwarmHealthSnapshot {
    pub window_len: usize,
    pub accepted_assignments: usize,
    pub repeated_rejections: usize,
    pub failed_assignments: usize,
    pub retries: usize,
    pub claim_denials: usize,
    pub claim_failures: usize,
    pub semantic_conflict_blocks: usize,
    pub semantic_conflict_warnings: usize,
    pub semantic_conflicts: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CircuitBreakerTripReason {
    SustainedAssignmentFailures {
        failures: usize,
        retries: usize,
        threshold: usize,
    },
    RepeatedClaimDenial {
        denials: usize,
        failures: usize,
        threshold: usize,
    },
    RepeatedRejectionLoop {
        rejections: usize,
        retries: usize,
        threshold: usize,
    },
    SustainedSemanticConflicts {
        blocked: usize,
        warned: usize,
        conflicts: usize,
        threshold: usize,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CircuitBreakerTrip {
    pub reason: CircuitBreakerTripReason,
    pub window: SwarmHealthSnapshot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CircuitBreakerState {
    Closed,
    Open {
        trip: CircuitBreakerTrip,
        cooldown_remaining: usize,
    },
    HalfOpen {
        previous_trip: CircuitBreakerTrip,
        successes_observed: usize,
        successes_required: usize,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CircuitBreakerTransition {
    Opened(CircuitBreakerTrip),
    EnteredHalfOpen,
    Closed,
}

#[derive(Clone, Debug)]
pub struct SwarmHealthCircuitBreaker {
    config: CircuitBreakerConfig,
    window: VecDeque<SwarmHealthSignal>,
    state: CircuitBreakerState,
}

impl Default for SwarmHealthCircuitBreaker {
    fn default() -> Self {
        Self {
            config: CircuitBreakerConfig::default(),
            window: VecDeque::new(),
            state: CircuitBreakerState::Closed,
        }
    }
}

impl SwarmHealthCircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Result<Self, CircuitBreakerConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            window: VecDeque::new(),
            state: CircuitBreakerState::Closed,
        })
    }

    pub fn state(&self) -> &CircuitBreakerState {
        &self.state
    }

    pub fn snapshot(&self) -> SwarmHealthSnapshot {
        let mut snapshot = SwarmHealthSnapshot {
            window_len: self.window.len(),
            ..SwarmHealthSnapshot::default()
        };
        for signal in &self.window {
            match signal {
                SwarmHealthSignal::AssignmentOutcome(AssignmentHealthOutcome::Accepted) => {
                    snapshot.accepted_assignments = snapshot.accepted_assignments.saturating_add(1);
                }
                SwarmHealthSignal::AssignmentOutcome(AssignmentHealthOutcome::Rejected) => {
                    snapshot.repeated_rejections = snapshot.repeated_rejections.saturating_add(1);
                }
                SwarmHealthSignal::AssignmentOutcome(AssignmentHealthOutcome::Failed) => {
                    snapshot.failed_assignments = snapshot.failed_assignments.saturating_add(1);
                }
                SwarmHealthSignal::AssignmentOutcome(AssignmentHealthOutcome::Retried) => {
                    snapshot.retries = snapshot.retries.saturating_add(1);
                }
                SwarmHealthSignal::ClaimAcquisitionDenied => {
                    snapshot.claim_denials = snapshot.claim_denials.saturating_add(1);
                }
                SwarmHealthSignal::ClaimAcquisitionFailed => {
                    snapshot.claim_failures = snapshot.claim_failures.saturating_add(1);
                }
                SwarmHealthSignal::SemanticConflictBlocked { conflicts } => {
                    snapshot.semantic_conflict_blocks =
                        snapshot.semantic_conflict_blocks.saturating_add(1);
                    snapshot.semantic_conflicts =
                        snapshot.semantic_conflicts.saturating_add(*conflicts);
                }
                SwarmHealthSignal::SemanticConflictWarned { conflicts } => {
                    snapshot.semantic_conflict_warnings =
                        snapshot.semantic_conflict_warnings.saturating_add(1);
                    snapshot.semantic_conflicts =
                        snapshot.semantic_conflicts.saturating_add(*conflicts);
                }
            }
        }
        snapshot
    }

    pub fn permits_admission(&self) -> bool {
        !matches!(self.state, CircuitBreakerState::Open { .. })
    }

    pub fn observe(&mut self, signal: SwarmHealthSignal) -> Option<CircuitBreakerTransition> {
        self.window.push_back(signal);
        while self.window.len() > self.config.window_capacity {
            self.window.pop_front();
        }

        match self.state.clone() {
            CircuitBreakerState::Closed => self.evaluate_closed_state(),
            CircuitBreakerState::Open {
                trip,
                cooldown_remaining,
            } => {
                if cooldown_remaining > 1 {
                    self.state = CircuitBreakerState::Open {
                        trip,
                        cooldown_remaining: cooldown_remaining.saturating_sub(1),
                    };
                    None
                } else {
                    self.state = CircuitBreakerState::HalfOpen {
                        previous_trip: trip,
                        successes_observed: 0,
                        successes_required: self.config.half_open_successes,
                    };
                    Some(CircuitBreakerTransition::EnteredHalfOpen)
                }
            }
            CircuitBreakerState::HalfOpen {
                previous_trip,
                successes_observed,
                successes_required,
            } => match signal {
                SwarmHealthSignal::AssignmentOutcome(AssignmentHealthOutcome::Accepted) => {
                    let observed = successes_observed.saturating_add(1);
                    if observed >= successes_required {
                        self.window.clear();
                        self.state = CircuitBreakerState::Closed;
                        Some(CircuitBreakerTransition::Closed)
                    } else {
                        self.state = CircuitBreakerState::HalfOpen {
                            previous_trip,
                            successes_observed: observed,
                            successes_required,
                        };
                        None
                    }
                }
                _ => {
                    let trip = CircuitBreakerTrip {
                        reason: previous_trip.reason,
                        window: self.snapshot(),
                    };
                    self.state = CircuitBreakerState::Open {
                        trip: trip.clone(),
                        cooldown_remaining: self.config.open_cooldown_signals,
                    };
                    Some(CircuitBreakerTransition::Opened(trip))
                }
            },
        }
    }

    fn evaluate_closed_state(&mut self) -> Option<CircuitBreakerTransition> {
        let snapshot = self.snapshot();
        let reason = if snapshot.repeated_rejections >= self.config.rejection_threshold {
            Some(CircuitBreakerTripReason::RepeatedRejectionLoop {
                rejections: snapshot.repeated_rejections,
                retries: snapshot.retries,
                threshold: self.config.rejection_threshold,
            })
        } else if snapshot.failed_assignments >= self.config.assignment_failure_threshold
            || snapshot.retries >= self.config.retry_threshold
        {
            Some(CircuitBreakerTripReason::SustainedAssignmentFailures {
                failures: snapshot.failed_assignments,
                retries: snapshot.retries,
                threshold: if snapshot.failed_assignments
                    >= self.config.assignment_failure_threshold
                {
                    self.config.assignment_failure_threshold
                } else {
                    self.config.retry_threshold
                },
            })
        } else if snapshot
            .claim_denials
            .saturating_add(snapshot.claim_failures)
            >= self.config.claim_denial_threshold
        {
            Some(CircuitBreakerTripReason::RepeatedClaimDenial {
                denials: snapshot.claim_denials,
                failures: snapshot.claim_failures,
                threshold: self.config.claim_denial_threshold,
            })
        } else if snapshot
            .semantic_conflict_blocks
            .saturating_add(snapshot.semantic_conflict_warnings)
            >= self.config.semantic_conflict_threshold
        {
            Some(CircuitBreakerTripReason::SustainedSemanticConflicts {
                blocked: snapshot.semantic_conflict_blocks,
                warned: snapshot.semantic_conflict_warnings,
                conflicts: snapshot.semantic_conflicts,
                threshold: self.config.semantic_conflict_threshold,
            })
        } else {
            None
        };
        reason.map(|reason| {
            let trip = CircuitBreakerTrip {
                reason,
                window: snapshot,
            };
            self.state = CircuitBreakerState::Open {
                trip: trip.clone(),
                cooldown_remaining: self.config.open_cooldown_signals,
            };
            CircuitBreakerTransition::Opened(trip)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn low_threshold_config() -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            window_capacity: 8,
            assignment_failure_threshold: 2,
            retry_threshold: 2,
            claim_denial_threshold: 2,
            rejection_threshold: 2,
            semantic_conflict_threshold: 2,
            open_cooldown_signals: 2,
            half_open_successes: 2,
        }
    }

    #[test]
    fn isolated_failure_and_single_retry_keep_default_breaker_closed() {
        let mut breaker = SwarmHealthCircuitBreaker::default();
        assert_eq!(
            breaker.observe(SwarmHealthSignal::AssignmentOutcome(
                AssignmentHealthOutcome::Failed
            )),
            None
        );
        assert_eq!(
            breaker.observe(SwarmHealthSignal::AssignmentOutcome(
                AssignmentHealthOutcome::Retried
            )),
            None
        );
        assert!(matches!(breaker.state(), CircuitBreakerState::Closed));
    }

    #[test]
    fn sustained_failures_open_with_structured_reason() {
        let mut breaker = SwarmHealthCircuitBreaker::new(low_threshold_config())
            .expect("valid breaker configuration");
        breaker.observe(SwarmHealthSignal::AssignmentOutcome(
            AssignmentHealthOutcome::Failed,
        ));
        let transition = breaker.observe(SwarmHealthSignal::AssignmentOutcome(
            AssignmentHealthOutcome::Failed,
        ));
        assert!(matches!(
            transition,
            Some(CircuitBreakerTransition::Opened(CircuitBreakerTrip {
                reason: CircuitBreakerTripReason::SustainedAssignmentFailures {
                    failures: 2,
                    retries: 0,
                    threshold: 2,
                },
                ..
            }))
        ));
    }

    #[test]
    fn repeated_claim_denials_and_rejections_open_with_specific_reasons() {
        let mut claim_breaker = SwarmHealthCircuitBreaker::new(low_threshold_config())
            .expect("valid breaker configuration");
        claim_breaker.observe(SwarmHealthSignal::ClaimAcquisitionDenied);
        let claim_transition = claim_breaker.observe(SwarmHealthSignal::ClaimAcquisitionFailed);
        assert!(matches!(
            claim_transition,
            Some(CircuitBreakerTransition::Opened(CircuitBreakerTrip {
                reason: CircuitBreakerTripReason::RepeatedClaimDenial {
                    denials: 1,
                    failures: 1,
                    threshold: 2,
                },
                ..
            }))
        ));

        let mut rejection_breaker = SwarmHealthCircuitBreaker::new(low_threshold_config())
            .expect("valid breaker configuration");
        rejection_breaker.observe(SwarmHealthSignal::AssignmentOutcome(
            AssignmentHealthOutcome::Rejected,
        ));
        let rejection_transition = rejection_breaker.observe(SwarmHealthSignal::AssignmentOutcome(
            AssignmentHealthOutcome::Rejected,
        ));
        assert!(matches!(
            rejection_transition,
            Some(CircuitBreakerTransition::Opened(CircuitBreakerTrip {
                reason: CircuitBreakerTripReason::RepeatedRejectionLoop {
                    rejections: 2,
                    retries: 0,
                    threshold: 2,
                },
                ..
            }))
        ));
    }

    #[test]
    fn cooldown_and_half_open_successes_prevent_immediate_reclose() {
        let mut breaker = SwarmHealthCircuitBreaker::new(low_threshold_config())
            .expect("valid breaker configuration");
        breaker.observe(SwarmHealthSignal::AssignmentOutcome(
            AssignmentHealthOutcome::Rejected,
        ));
        breaker.observe(SwarmHealthSignal::AssignmentOutcome(
            AssignmentHealthOutcome::Rejected,
        ));

        breaker.observe(SwarmHealthSignal::AssignmentOutcome(
            AssignmentHealthOutcome::Accepted,
        ));
        assert!(matches!(breaker.state(), CircuitBreakerState::Open { .. }));
        assert_eq!(
            breaker.observe(SwarmHealthSignal::AssignmentOutcome(
                AssignmentHealthOutcome::Accepted
            )),
            Some(CircuitBreakerTransition::EnteredHalfOpen)
        );
        breaker.observe(SwarmHealthSignal::AssignmentOutcome(
            AssignmentHealthOutcome::Accepted,
        ));
        assert!(matches!(
            breaker.state(),
            CircuitBreakerState::HalfOpen {
                successes_observed: 1,
                successes_required: 2,
                ..
            }
        ));
        assert_eq!(
            breaker.observe(SwarmHealthSignal::AssignmentOutcome(
                AssignmentHealthOutcome::Accepted
            )),
            Some(CircuitBreakerTransition::Closed)
        );
        assert!(matches!(breaker.state(), CircuitBreakerState::Closed));
    }
}
