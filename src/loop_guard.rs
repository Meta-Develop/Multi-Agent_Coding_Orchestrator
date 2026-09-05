//! Severity-scored loop guard for worker self-review and repair cycles.
//!
//! Issue #340 / closed #93. Hard round limits (`max_depth`, `max_child_retries`,
//! `max_gate_corrections`) and the swarm-health cascade breaker remain the
//! admission and budget backstops. This module scores consecutive review
//! findings by severity and returns a typed escalation (`continue` / `narrow` /
//! `refuse`) with durable evidence. It never converts a failed or missing
//! validation floor into loop-exit success.
//!
//! Supervisor wiring lives in `src/supervise/assignment_execution.rs` on the
//! historical #93 branch. This crate-root module is the mainline home so the
//! wave-2 scheduler / follow-up-queue / process-runner lanes keep exclusive
//! ownership of those files.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stored cycle history bound. Matches historical #93:
/// `MAX_GATE_CORRECTIONS_LIMIT` (4) + 1.
pub const MAX_LOOP_GUARD_CYCLES: usize = 5;
/// Maximum accepted failure-signature bytes. Fail closed above this.
pub const MAX_FAILURE_SIGNATURE_BYTES: usize = 1024;

/// Hard round limits already enforced by the supervisor plan. The guard
/// composes with these values and never raises them.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExistingRoundLimits {
    pub max_depth: u8,
    pub max_child_retries: u8,
    pub max_gate_corrections: u8,
}

impl ExistingRoundLimits {
    /// Plan-document defaults on this checkout (`max_depth = 2`, retries and
    /// gate corrections default to 0).
    pub const fn plan_defaults() -> Self {
        Self {
            max_depth: 2,
            max_child_retries: 0,
            max_gate_corrections: 0,
        }
    }

    /// Absolute supervisor caps (`MAX_SUPERVISOR_DEPTH = 32`,
    /// `MAX_CHILD_RETRIES_LIMIT = 2`, `MAX_GATE_CORRECTIONS_LIMIT = 4`).
    pub const fn supervisor_caps() -> Self {
        Self {
            max_depth: 32,
            max_child_retries: 2,
            max_gate_corrections: 4,
        }
    }

    pub const fn remaining_gate_corrections(self, used: u8) -> u8 {
        self.max_gate_corrections.saturating_sub(used)
    }

    pub const fn remaining_child_retries(self, used: u8) -> u8 {
        self.max_child_retries.saturating_sub(used)
    }
}

/// Read-only view of the issue #24 swarm-health cascade breaker. The guard
/// does not re-implement closed/open/half-open admission.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CascadeBreakerView {
    Closed,
    HalfOpen,
    Open,
}

/// Finding severity used for scoring. Independent of `supervise::FindingSeverity`
/// so this module does not take a dependency on the supervise tree; the handoff
/// maps `info`/`warning`/`error` 1:1.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoopFindingSeverity {
    Info,
    Warning,
    Error,
}

impl LoopFindingSeverity {
    /// Severity weight used instead of a flat cycle count. Info=1, Warning=2,
    /// Error=4. An empty cycle (no finding) scores 0 and is still low-severity.
    pub const fn score(self) -> u8 {
        match self {
            Self::Info => 1,
            Self::Warning => 2,
            Self::Error => 4,
        }
    }
}

/// Inclusive ceiling for "low-severity" cycles. Error is never low.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LowSeverityCeiling {
    Info,
    Warning,
}

/// Locked verification floor. A loop-guard exit cannot mark this passed.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationFloor {
    Passed,
    Missing,
    Failed,
}

impl ValidationFloor {
    pub const fn is_satisfied(self) -> bool {
        matches!(self, Self::Passed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoopGuardConfig {
    pub max_low_severity: LowSeverityCeiling,
    pub consecutive_low_severity_cycles: u8,
    pub consecutive_repeat_failures: u8,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum LoopGuardConfigError {
    #[error("loop-guard field '{0}' must be between 1 and {1}")]
    OutOfRange(&'static str, usize),
    #[error(
        "loop-guard consecutive_low_severity_cycles ({got}) must be at most max_gate_corrections + 1 ({max})"
    )]
    ThresholdExceedsCorrectionBound { got: u8, max: u8 },
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum LoopGuardError {
    #[error(transparent)]
    Config(#[from] LoopGuardConfigError),
    #[error("loop-guard cycle count overflowed")]
    CycleCountOverflow,
    #[error("loop-guard exceeded its bounded {0} cycle history")]
    CycleHistoryBound(usize),
    #[error("loop-guard failure signature exceeds {0} bytes")]
    SignatureTooLong(usize),
    #[error("loop-guard cycle ordinal exceeded its u8 bound")]
    CycleOrdinalOverflow,
}

impl LoopGuardConfig {
    pub fn warning_streak(
        consecutive_low_severity_cycles: u8,
    ) -> Result<Self, LoopGuardConfigError> {
        let config = Self {
            max_low_severity: LowSeverityCeiling::Warning,
            consecutive_low_severity_cycles,
            consecutive_repeat_failures: 2,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), LoopGuardConfigError> {
        for (name, value) in [
            (
                "consecutive_low_severity_cycles",
                self.consecutive_low_severity_cycles,
            ),
            (
                "consecutive_repeat_failures",
                self.consecutive_repeat_failures,
            ),
        ] {
            if !(1..=MAX_LOOP_GUARD_CYCLES as u8).contains(&value) {
                return Err(LoopGuardConfigError::OutOfRange(
                    name,
                    MAX_LOOP_GUARD_CYCLES,
                ));
            }
        }
        Ok(())
    }

    pub fn validate_against_limits(
        &self,
        limits: ExistingRoundLimits,
    ) -> Result<(), LoopGuardConfigError> {
        self.validate()?;
        let max = limits.max_gate_corrections.saturating_add(1);
        if self.consecutive_low_severity_cycles > max {
            return Err(LoopGuardConfigError::ThresholdExceedsCorrectionBound {
                got: self.consecutive_low_severity_cycles,
                max,
            });
        }
        Ok(())
    }
}

pub const fn severity_is_low(
    ceiling: LowSeverityCeiling,
    highest: Option<LoopFindingSeverity>,
) -> bool {
    match (ceiling, highest) {
        (_, None | Some(LoopFindingSeverity::Info)) => true,
        (LowSeverityCeiling::Warning, Some(LoopFindingSeverity::Warning)) => true,
        (_, Some(LoopFindingSeverity::Warning | LoopFindingSeverity::Error)) => false,
    }
}

/// One observed self-review / repair cycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoopCycleObservation {
    pub highest_severity: Option<LoopFindingSeverity>,
    pub failure_signature: Option<String>,
    pub validation_floor: ValidationFloor,
}

impl LoopCycleObservation {
    pub fn new(
        highest_severity: Option<LoopFindingSeverity>,
        failure_signature: Option<String>,
        validation_floor: ValidationFloor,
    ) -> Result<Self, LoopGuardError> {
        if let Some(signature) = failure_signature.as_ref() {
            if signature.len() > MAX_FAILURE_SIGNATURE_BYTES {
                return Err(LoopGuardError::SignatureTooLong(
                    MAX_FAILURE_SIGNATURE_BYTES,
                ));
            }
        }
        Ok(Self {
            highest_severity,
            failure_signature,
            validation_floor,
        })
    }
}

/// Inputs the guard composes with existing scheduler / plan bounds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoopGuardObserveRequest {
    pub observation: LoopCycleObservation,
    pub limits: ExistingRoundLimits,
    pub used_gate_corrections: u8,
    pub used_child_retries: u8,
    pub current_depth: u8,
    pub cascade_breaker: CascadeBreakerView,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoopGuardEscalation {
    Continue,
    Narrow,
    Refuse,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoundLimitKind {
    MaxDepth,
    MaxChildRetries,
    MaxGateCorrections,
}

/// Durable explanation of why the guard chose an escalation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LoopGuardReason {
    ProgressOrBudgetRemains,
    ConsecutiveLowSeverityNonProgress {
        consecutive: u8,
        threshold: u8,
        severity_score: u8,
    },
    RepeatedHighSeverityFailure {
        consecutive: u8,
        threshold: u8,
        signature: String,
        severity_score: u8,
    },
    RoundLimitExhausted {
        limit: RoundLimitKind,
        used: u8,
        bound: u8,
    },
    CascadeBreakerOpen,
    ValidationFloorUnsatisfied {
        floor: ValidationFloor,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoopGuardDecision {
    pub escalation: LoopGuardEscalation,
    pub reason: LoopGuardReason,
    pub retry_suppressed: bool,
    /// Always true. A loop-guard exit cannot disable fmt/check/clippy/test.
    pub validation_floor_required: bool,
}

impl LoopGuardDecision {
    fn continue_progress() -> Self {
        Self {
            escalation: LoopGuardEscalation::Continue,
            reason: LoopGuardReason::ProgressOrBudgetRemains,
            retry_suppressed: false,
            validation_floor_required: true,
        }
    }

    fn narrow(consecutive: u8, threshold: u8, severity_score: u8) -> Self {
        Self {
            escalation: LoopGuardEscalation::Narrow,
            reason: LoopGuardReason::ConsecutiveLowSeverityNonProgress {
                consecutive,
                threshold,
                severity_score,
            },
            retry_suppressed: true,
            validation_floor_required: true,
        }
    }

    fn refuse(reason: LoopGuardReason) -> Self {
        Self {
            escalation: LoopGuardEscalation::Refuse,
            reason,
            retry_suppressed: true,
            validation_floor_required: true,
        }
    }

    /// Success is allowed only after a low-severity Narrow stop whose
    /// validation floor passed. Refuse never succeeds. Continue is not a stop.
    /// A failed or missing floor can never be treated as loop-exit success.
    pub fn permits_success(&self, floor: ValidationFloor) -> bool {
        floor.is_satisfied() && matches!(self.escalation, LoopGuardEscalation::Narrow)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoopCycleRecord {
    pub cycle_ordinal: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub highest_severity: Option<LoopFindingSeverity>,
    pub severity_score: u8,
    pub low_severity: bool,
    pub consecutive_low_severity_cycles: u8,
    pub consecutive_repeat_failures: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_signature: Option<String>,
    pub validation_floor: ValidationFloor,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoopGuardEvidence {
    pub config: LoopGuardConfig,
    pub cycles: Vec<LoopCycleRecord>,
    pub decision: LoopGuardDecision,
    pub round_limits: ExistingRoundLimits,
    pub cascade_breaker: CascadeBreakerView,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoopGuardTracker {
    config: LoopGuardConfig,
    limits: ExistingRoundLimits,
    cycles: Vec<LoopCycleRecord>,
    last_decision: Option<LoopGuardDecision>,
    last_breaker: CascadeBreakerView,
    last_limits: ExistingRoundLimits,
}

impl LoopGuardTracker {
    pub fn new(
        config: LoopGuardConfig,
        limits: ExistingRoundLimits,
    ) -> Result<Self, LoopGuardConfigError> {
        config.validate_against_limits(limits)?;
        Ok(Self {
            config,
            limits,
            cycles: Vec::new(),
            last_decision: None,
            last_breaker: CascadeBreakerView::Closed,
            last_limits: limits,
        })
    }

    pub fn config(&self) -> LoopGuardConfig {
        self.config
    }

    pub fn cycles(&self) -> &[LoopCycleRecord] {
        &self.cycles
    }

    pub fn last_decision(&self) -> Option<&LoopGuardDecision> {
        self.last_decision.as_ref()
    }

    pub fn observe(
        &mut self,
        request: LoopGuardObserveRequest,
    ) -> Result<LoopGuardDecision, LoopGuardError> {
        request
            .observation
            .failure_signature
            .as_ref()
            .map_or(Ok(()), |signature| {
                if signature.len() > MAX_FAILURE_SIGNATURE_BYTES {
                    Err(LoopGuardError::SignatureTooLong(
                        MAX_FAILURE_SIGNATURE_BYTES,
                    ))
                } else {
                    Ok(())
                }
            })?;

        let next_len = self
            .cycles
            .len()
            .checked_add(1)
            .ok_or(LoopGuardError::CycleCountOverflow)?;
        if next_len > MAX_LOOP_GUARD_CYCLES {
            let used = u8::try_from(self.cycles.len()).unwrap_or(u8::MAX);
            let decision = LoopGuardDecision::refuse(LoopGuardReason::RoundLimitExhausted {
                limit: RoundLimitKind::MaxGateCorrections,
                used,
                bound: MAX_LOOP_GUARD_CYCLES as u8,
            });
            // Keep evidence of the bound without appending an extra cycle.
            // Returning Refuse rather than masking as success is required.
            self.last_decision = Some(decision.clone());
            self.last_breaker = request.cascade_breaker;
            self.last_limits = request.limits;
            return Err(LoopGuardError::CycleHistoryBound(MAX_LOOP_GUARD_CYCLES));
        }
        let cycle_ordinal =
            u8::try_from(next_len).map_err(|_| LoopGuardError::CycleOrdinalOverflow)?;

        let highest = request.observation.highest_severity;
        let severity_score = highest.map(LoopFindingSeverity::score).unwrap_or(0);
        let low_severity = severity_is_low(self.config.max_low_severity, highest);
        let previous_low = self
            .cycles
            .last()
            .map(|cycle| cycle.consecutive_low_severity_cycles)
            .unwrap_or(0);
        let consecutive_low_severity_cycles = if low_severity {
            previous_low
                .checked_add(1)
                .ok_or(LoopGuardError::CycleCountOverflow)?
        } else {
            0
        };

        let signature = request.observation.failure_signature.clone();
        let consecutive_repeat_failures =
            consecutive_repeat_count(self.cycles.last(), highest, signature.as_deref());

        let record = LoopCycleRecord {
            cycle_ordinal,
            highest_severity: highest,
            severity_score,
            low_severity,
            consecutive_low_severity_cycles,
            consecutive_repeat_failures,
            failure_signature: signature,
            validation_floor: request.observation.validation_floor,
        };
        self.cycles.push(record.clone());
        self.last_breaker = request.cascade_breaker;
        self.last_limits = request.limits;

        let decision = decide(self.config, request, &record);
        self.last_decision = Some(decision.clone());
        Ok(decision)
    }

    pub fn evidence(&self) -> LoopGuardEvidence {
        LoopGuardEvidence {
            config: self.config,
            cycles: self.cycles.clone(),
            decision: self
                .last_decision
                .clone()
                .unwrap_or_else(LoopGuardDecision::continue_progress),
            round_limits: self.last_limits,
            cascade_breaker: self.last_breaker,
        }
    }
}

fn consecutive_repeat_count(
    previous: Option<&LoopCycleRecord>,
    highest: Option<LoopFindingSeverity>,
    signature: Option<&str>,
) -> u8 {
    if highest != Some(LoopFindingSeverity::Error) {
        return 0;
    }
    let Some(signature) = signature else {
        return 0;
    };
    match previous {
        Some(previous)
            if previous.highest_severity == Some(LoopFindingSeverity::Error)
                && previous.failure_signature.as_deref() == Some(signature) =>
        {
            previous.consecutive_repeat_failures.saturating_add(1)
        }
        _ => 1,
    }
}

fn decide(
    config: LoopGuardConfig,
    request: LoopGuardObserveRequest,
    record: &LoopCycleRecord,
) -> LoopGuardDecision {
    let floor = record.validation_floor;
    let remaining_corrections = request
        .limits
        .remaining_gate_corrections(request.used_gate_corrections);
    let depth_exceeded = request.current_depth > request.limits.max_depth;
    let retries_exceeded = request.used_child_retries > request.limits.max_child_retries;
    let corrections_exhausted = remaining_corrections == 0;
    let repeat_threshold_reached = record.consecutive_repeat_failures
        >= config.consecutive_repeat_failures
        && record.consecutive_repeat_failures > 0;
    let low_threshold_reached =
        record.consecutive_low_severity_cycles >= config.consecutive_low_severity_cycles;

    // 1. Cascade breaker already owns admission. Do not reclassify that trip
    //    as a self-review loop.
    if request.cascade_breaker == CascadeBreakerView::Open {
        return LoopGuardDecision::refuse(LoopGuardReason::CascadeBreakerOpen);
    }

    // 2. Depth / retry caps that have already been *violated* (used > bound)
    //    are named as bound failures, not loops. Plan defaults set
    //    max_child_retries = 0; used == 0 is remaining budget of zero on a
    //    bound that was never entered, not a retry-cap trip. The existing
    //    retry machinery owns that counter.
    if depth_exceeded {
        return LoopGuardDecision::refuse(LoopGuardReason::RoundLimitExhausted {
            limit: RoundLimitKind::MaxDepth,
            used: request.current_depth,
            bound: request.limits.max_depth,
        });
    }
    if retries_exceeded {
        return LoopGuardDecision::refuse(LoopGuardReason::RoundLimitExhausted {
            limit: RoundLimitKind::MaxChildRetries,
            used: request.used_child_retries,
            bound: request.limits.max_child_retries,
        });
    }

    // 3. Correction budget is gone. Name the floor when it is unsatisfied;
    //    otherwise name the exhausted gate-correction bound. This must precede
    //    the scored loop exits so an exhausted budget is not reclassified as
    //    repeated high-severity or low-severity non-progress.
    if corrections_exhausted {
        if !floor.is_satisfied() {
            return LoopGuardDecision::refuse(LoopGuardReason::ValidationFloorUnsatisfied {
                floor,
            });
        }
        return LoopGuardDecision::refuse(LoopGuardReason::RoundLimitExhausted {
            limit: RoundLimitKind::MaxGateCorrections,
            used: request.used_gate_corrections,
            bound: request.limits.max_gate_corrections,
        });
    }

    // 4. Repeated identical high-severity failures: refuse, keep the real
    //    failure visible.
    if repeat_threshold_reached {
        return LoopGuardDecision::refuse(LoopGuardReason::RepeatedHighSeverityFailure {
            consecutive: record.consecutive_repeat_failures,
            threshold: config.consecutive_repeat_failures,
            signature: record.failure_signature.clone().unwrap_or_default(),
            severity_score: record.severity_score,
        });
    }

    // 5. Consecutive low-severity non-progress: narrow (stop critique) without
    //    spending remaining correction budget. The floor still binds.
    if low_threshold_reached {
        return LoopGuardDecision::narrow(
            record.consecutive_low_severity_cycles,
            config.consecutive_low_severity_cycles,
            record.severity_score,
        );
    }

    // 6. Remaining budget and no threshold: keep iterating. A failed floor
    //    here is a real repair attempt, not a loop classification.
    LoopGuardDecision::continue_progress()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps() -> ExistingRoundLimits {
        ExistingRoundLimits::supervisor_caps()
    }

    fn request(
        severity: Option<LoopFindingSeverity>,
        signature: Option<&str>,
        floor: ValidationFloor,
        used_corrections: u8,
        breaker: CascadeBreakerView,
    ) -> LoopGuardObserveRequest {
        LoopGuardObserveRequest {
            observation: LoopCycleObservation::new(severity, signature.map(str::to_owned), floor)
                .expect("observation"),
            limits: caps(),
            used_gate_corrections: used_corrections,
            used_child_retries: 0,
            current_depth: 2,
            cascade_breaker: breaker,
        }
    }

    fn tracker() -> LoopGuardTracker {
        LoopGuardTracker::new(LoopGuardConfig::warning_streak(2).expect("config"), caps())
            .expect("tracker")
    }

    fn exhausted_gate_limits() -> ExistingRoundLimits {
        ExistingRoundLimits {
            max_depth: 2,
            max_child_retries: 2,
            max_gate_corrections: 0,
        }
    }

    fn exhausted_gate_request(
        severity: Option<LoopFindingSeverity>,
        signature: Option<&str>,
        floor: ValidationFloor,
    ) -> LoopGuardObserveRequest {
        LoopGuardObserveRequest {
            observation: LoopCycleObservation::new(severity, signature.map(str::to_owned), floor)
                .expect("observation"),
            limits: exhausted_gate_limits(),
            used_gate_corrections: 0,
            used_child_retries: 0,
            current_depth: 2,
            cascade_breaker: CascadeBreakerView::Closed,
        }
    }

    fn exhausted_gate_reason(floor: ValidationFloor) -> LoopGuardReason {
        if floor.is_satisfied() {
            LoopGuardReason::RoundLimitExhausted {
                limit: RoundLimitKind::MaxGateCorrections,
                used: 0,
                bound: 0,
            }
        } else {
            LoopGuardReason::ValidationFloorUnsatisfied { floor }
        }
    }

    #[test]
    fn config_rejects_zero_and_oversize_thresholds() {
        let err = LoopGuardConfig {
            max_low_severity: LowSeverityCeiling::Warning,
            consecutive_low_severity_cycles: 0,
            consecutive_repeat_failures: 2,
        }
        .validate()
        .expect_err("zero threshold");
        assert!(matches!(err, LoopGuardConfigError::OutOfRange(_, _)));

        let err = LoopGuardConfig {
            max_low_severity: LowSeverityCeiling::Warning,
            consecutive_low_severity_cycles: (MAX_LOOP_GUARD_CYCLES as u8).saturating_add(1),
            consecutive_repeat_failures: 2,
        }
        .validate()
        .expect_err("oversize threshold");
        assert!(matches!(err, LoopGuardConfigError::OutOfRange(_, _)));
    }

    #[test]
    fn config_composes_with_max_gate_corrections_plus_one() {
        let config = LoopGuardConfig::warning_streak(2).expect("config");
        let limits = ExistingRoundLimits {
            max_depth: 2,
            max_child_retries: 0,
            max_gate_corrections: 0,
        };
        let err = config
            .validate_against_limits(limits)
            .expect_err("threshold 2 exceeds 0+1");
        assert_eq!(
            err,
            LoopGuardConfigError::ThresholdExceedsCorrectionBound { got: 2, max: 1 }
        );
        LoopGuardConfig::warning_streak(1)
            .expect("config")
            .validate_against_limits(limits)
            .expect("threshold 1 is at most 0+1");
    }

    #[test]
    fn unknown_json_fields_fail_closed() {
        let err = serde_json::from_str::<LoopGuardConfig>(
            r#"{"max_low_severity":"warning","consecutive_low_severity_cycles":2,"consecutive_repeat_failures":2,"unexpected":true}"#,
        );
        assert!(err.is_err());
        let err = serde_json::from_str::<LoopGuardEvidence>(
            r#"{"config":{"max_low_severity":"warning","consecutive_low_severity_cycles":2,"consecutive_repeat_failures":2},"cycles":[],"decision":{"escalation":"continue","reason":{"kind":"progress_or_budget_remains"},"retry_suppressed":false,"validation_floor_required":true},"round_limits":{"max_depth":2,"max_child_retries":0,"max_gate_corrections":0},"cascade_breaker":"closed","extra":1}"#,
        );
        assert!(err.is_err());
    }

    #[test]
    fn empty_and_info_are_low_warning_depends_on_ceiling_error_is_never_low() {
        assert!(severity_is_low(LowSeverityCeiling::Warning, None));
        assert!(severity_is_low(
            LowSeverityCeiling::Warning,
            Some(LoopFindingSeverity::Info)
        ));
        assert!(severity_is_low(
            LowSeverityCeiling::Warning,
            Some(LoopFindingSeverity::Warning)
        ));
        assert!(!severity_is_low(
            LowSeverityCeiling::Warning,
            Some(LoopFindingSeverity::Error)
        ));
        assert!(!severity_is_low(
            LowSeverityCeiling::Info,
            Some(LoopFindingSeverity::Warning)
        ));
        assert_eq!(LoopFindingSeverity::Info.score(), 1);
        assert_eq!(LoopFindingSeverity::Warning.score(), 2);
        assert_eq!(LoopFindingSeverity::Error.score(), 4);
    }

    #[test]
    fn high_severity_resets_low_streak_then_warning_reaches_narrow() {
        let mut tracker = tracker();
        let first = tracker
            .observe(request(
                None,
                None,
                ValidationFloor::Passed,
                0,
                CascadeBreakerView::Closed,
            ))
            .expect("empty cycle");
        assert_eq!(first.escalation, LoopGuardEscalation::Continue);

        let error = tracker
            .observe(request(
                Some(LoopFindingSeverity::Error),
                Some("impl-defect"),
                ValidationFloor::Passed,
                0,
                CascadeBreakerView::Closed,
            ))
            .expect("error cycle");
        assert_eq!(error.escalation, LoopGuardEscalation::Continue);

        let info = tracker
            .observe(request(
                Some(LoopFindingSeverity::Info),
                None,
                ValidationFloor::Passed,
                0,
                CascadeBreakerView::Closed,
            ))
            .expect("info cycle");
        assert_eq!(info.escalation, LoopGuardEscalation::Continue);

        let warning = tracker
            .observe(request(
                Some(LoopFindingSeverity::Warning),
                None,
                ValidationFloor::Passed,
                0,
                CascadeBreakerView::Closed,
            ))
            .expect("warning cycle");
        assert_eq!(warning.escalation, LoopGuardEscalation::Narrow);
        assert!(warning.retry_suppressed);
        assert!(warning.validation_floor_required);
        assert!(warning.permits_success(ValidationFloor::Passed));
        assert_eq!(
            tracker
                .cycles()
                .iter()
                .map(|cycle| cycle.consecutive_low_severity_cycles)
                .collect::<Vec<_>>(),
            vec![1, 0, 1, 2]
        );
        assert_eq!(
            tracker
                .cycles()
                .iter()
                .map(|cycle| cycle.severity_score)
                .collect::<Vec<_>>(),
            vec![0, 4, 1, 2]
        );
    }

    #[test]
    fn narrow_does_not_spend_correction_budget_and_cannot_bypass_failed_floor() {
        let mut tracker =
            LoopGuardTracker::new(LoopGuardConfig::warning_streak(1).expect("config"), caps())
                .expect("tracker");
        let decision = tracker
            .observe(request(
                Some(LoopFindingSeverity::Warning),
                None,
                ValidationFloor::Failed,
                0,
                CascadeBreakerView::Closed,
            ))
            .expect("narrow");
        assert_eq!(decision.escalation, LoopGuardEscalation::Narrow);
        assert!(decision.retry_suppressed);
        assert!(decision.validation_floor_required);
        assert!(
            !decision.permits_success(ValidationFloor::Failed),
            "a failed validation floor must not become loop-exit success"
        );
        assert!(
            !decision.permits_success(ValidationFloor::Missing),
            "a missing validation floor must not become loop-exit success"
        );
        let evidence = tracker.evidence();
        assert_eq!(evidence.cycles[0].validation_floor, ValidationFloor::Failed);
        assert_eq!(evidence.decision.escalation, LoopGuardEscalation::Narrow);
    }

    #[test]
    fn exhausted_budget_with_failed_floor_is_named_as_floor_not_as_loop() {
        let mut tracker = tracker();
        let decision = tracker
            .observe(LoopGuardObserveRequest {
                observation: LoopCycleObservation::new(
                    Some(LoopFindingSeverity::Error),
                    Some("fmt-failed".to_owned()),
                    ValidationFloor::Failed,
                )
                .expect("observation"),
                limits: ExistingRoundLimits {
                    max_depth: 2,
                    max_child_retries: 2,
                    max_gate_corrections: 0,
                },
                used_gate_corrections: 0,
                used_child_retries: 0,
                current_depth: 2,
                cascade_breaker: CascadeBreakerView::Closed,
            })
            .expect("refuse floor");
        assert_eq!(decision.escalation, LoopGuardEscalation::Refuse);
        assert_eq!(
            decision.reason,
            LoopGuardReason::ValidationFloorUnsatisfied {
                floor: ValidationFloor::Failed
            }
        );
        assert!(!decision.permits_success(ValidationFloor::Failed));
    }

    #[test]
    fn exhausted_budget_with_passed_floor_refuses_as_round_limit() {
        let mut tracker = tracker();
        let decision = tracker
            .observe(LoopGuardObserveRequest {
                observation: LoopCycleObservation::new(
                    Some(LoopFindingSeverity::Error),
                    Some("still-broken".to_owned()),
                    ValidationFloor::Passed,
                )
                .expect("observation"),
                limits: ExistingRoundLimits {
                    max_depth: 2,
                    max_child_retries: 2,
                    max_gate_corrections: 1,
                },
                used_gate_corrections: 1,
                used_child_retries: 0,
                current_depth: 2,
                cascade_breaker: CascadeBreakerView::Closed,
            })
            .expect("refuse bound");
        assert_eq!(decision.escalation, LoopGuardEscalation::Refuse);
        assert_eq!(
            decision.reason,
            LoopGuardReason::RoundLimitExhausted {
                limit: RoundLimitKind::MaxGateCorrections,
                used: 1,
                bound: 1
            }
        );
    }

    #[test]
    fn exhausted_budget_precedes_low_severity_threshold_for_each_floor() {
        for floor in [
            ValidationFloor::Passed,
            ValidationFloor::Failed,
            ValidationFloor::Missing,
        ] {
            let mut tracker =
                LoopGuardTracker::new(LoopGuardConfig::warning_streak(1).expect("config"), caps())
                    .expect("tracker");
            let decision = tracker
                .observe(exhausted_gate_request(
                    Some(LoopFindingSeverity::Warning),
                    None,
                    floor,
                ))
                .expect("exhausted low-threshold observe");
            assert_eq!(
                decision.escalation,
                LoopGuardEscalation::Refuse,
                "exhausted budget must refuse rather than narrow for {floor:?}"
            );
            assert_eq!(
                decision.reason,
                exhausted_gate_reason(floor),
                "exhausted budget must keep the floor/round-limit name for {floor:?}"
            );
            assert!(
                !matches!(
                    decision.reason,
                    LoopGuardReason::ConsecutiveLowSeverityNonProgress { .. }
                ),
                "exhausted correction budget must precede low-severity nonprogress for {floor:?}"
            );
            assert!(!decision.permits_success(floor));
        }
    }

    #[test]
    fn exhausted_budget_precedes_repeated_high_severity_for_each_floor() {
        for floor in [
            ValidationFloor::Passed,
            ValidationFloor::Failed,
            ValidationFloor::Missing,
        ] {
            let mut tracker = tracker();
            tracker
                .observe(exhausted_gate_request(
                    Some(LoopFindingSeverity::Error),
                    Some("same-bug"),
                    floor,
                ))
                .expect("first exhausted high-severity observe");
            let decision = tracker
                .observe(exhausted_gate_request(
                    Some(LoopFindingSeverity::Error),
                    Some("same-bug"),
                    floor,
                ))
                .expect("repeat exhausted high-severity observe");
            assert_eq!(
                tracker.cycles()[1].consecutive_repeat_failures,
                2,
                "repeat threshold must be reached for {floor:?}"
            );
            assert_eq!(
                decision.escalation,
                LoopGuardEscalation::Refuse,
                "exhausted budget must refuse rather than reclassify as a repeat loop for {floor:?}"
            );
            assert_eq!(
                decision.reason,
                exhausted_gate_reason(floor),
                "exhausted budget must keep the floor/round-limit name for {floor:?}"
            );
            assert!(
                !matches!(
                    decision.reason,
                    LoopGuardReason::RepeatedHighSeverityFailure { .. }
                ),
                "exhausted correction budget must precede repeated high-severity for {floor:?}"
            );
            assert!(!decision.permits_success(floor));
        }
    }

    #[test]
    fn repeated_identical_error_signature_refuses_without_masking_failure() {
        let mut tracker = tracker();
        let first = tracker
            .observe(request(
                Some(LoopFindingSeverity::Error),
                Some("same-bug"),
                ValidationFloor::Failed,
                0,
                CascadeBreakerView::Closed,
            ))
            .expect("first error");
        assert_eq!(first.escalation, LoopGuardEscalation::Continue);
        let second = tracker
            .observe(request(
                Some(LoopFindingSeverity::Error),
                Some("same-bug"),
                ValidationFloor::Failed,
                1,
                CascadeBreakerView::Closed,
            ))
            .expect("repeat error");
        assert_eq!(second.escalation, LoopGuardEscalation::Refuse);
        assert!(matches!(
            second.reason,
            LoopGuardReason::RepeatedHighSeverityFailure {
                consecutive: 2,
                threshold: 2,
                ..
            }
        ));
        assert!(!second.permits_success(ValidationFloor::Failed));
    }

    #[test]
    fn distinct_error_signatures_continue_until_bounds() {
        let mut tracker = tracker();
        let first = tracker
            .observe(request(
                Some(LoopFindingSeverity::Error),
                Some("bug-a"),
                ValidationFloor::Failed,
                0,
                CascadeBreakerView::Closed,
            ))
            .expect("bug a");
        let second = tracker
            .observe(request(
                Some(LoopFindingSeverity::Error),
                Some("bug-b"),
                ValidationFloor::Failed,
                1,
                CascadeBreakerView::Closed,
            ))
            .expect("bug b");
        assert_eq!(first.escalation, LoopGuardEscalation::Continue);
        assert_eq!(second.escalation, LoopGuardEscalation::Continue);
        assert_eq!(tracker.cycles()[1].consecutive_repeat_failures, 1);
    }

    #[test]
    fn open_cascade_breaker_refuses_without_reclassifying_as_loop() {
        let mut tracker = tracker();
        let decision = tracker
            .observe(request(
                Some(LoopFindingSeverity::Warning),
                None,
                ValidationFloor::Passed,
                0,
                CascadeBreakerView::Open,
            ))
            .expect("breaker open");
        assert_eq!(decision.escalation, LoopGuardEscalation::Refuse);
        assert_eq!(decision.reason, LoopGuardReason::CascadeBreakerOpen);
        assert!(
            !matches!(
                decision.reason,
                LoopGuardReason::ConsecutiveLowSeverityNonProgress { .. }
            ),
            "an already-open cascade breaker must not be renamed a review loop"
        );
    }

    #[test]
    fn depth_and_retry_caps_are_composed_not_extended() {
        let mut depth_tracker = tracker();
        let depth = depth_tracker
            .observe(LoopGuardObserveRequest {
                observation: LoopCycleObservation::new(
                    None,
                    None::<String>,
                    ValidationFloor::Passed,
                )
                .expect("observation"),
                limits: caps(),
                used_gate_corrections: 0,
                used_child_retries: 0,
                current_depth: 33,
                cascade_breaker: CascadeBreakerView::Closed,
            })
            .expect("depth");
        assert_eq!(
            depth.reason,
            LoopGuardReason::RoundLimitExhausted {
                limit: RoundLimitKind::MaxDepth,
                used: 33,
                bound: 32
            }
        );

        let mut retry_tracker = tracker();
        let retries = retry_tracker
            .observe(LoopGuardObserveRequest {
                observation: LoopCycleObservation::new(
                    Some(LoopFindingSeverity::Error),
                    Some("retry".to_owned()),
                    ValidationFloor::Passed,
                )
                .expect("observation"),
                limits: caps(),
                used_gate_corrections: 0,
                used_child_retries: 3,
                current_depth: 2,
                cascade_breaker: CascadeBreakerView::Closed,
            })
            .expect("retries");
        assert_eq!(
            retries.reason,
            LoopGuardReason::RoundLimitExhausted {
                limit: RoundLimitKind::MaxChildRetries,
                used: 3,
                bound: 2
            }
        );
    }

    #[test]
    fn failed_floor_with_remaining_budget_continues_as_real_repair() {
        let mut tracker = tracker();
        let decision = tracker
            .observe(request(
                Some(LoopFindingSeverity::Error),
                Some("needs-fix"),
                ValidationFloor::Failed,
                0,
                CascadeBreakerView::Closed,
            ))
            .expect("continue repair");
        assert_eq!(decision.escalation, LoopGuardEscalation::Continue);
        assert!(!decision.retry_suppressed);
        assert!(decision.validation_floor_required);
        assert!(!decision.permits_success(ValidationFloor::Failed));
    }

    #[test]
    fn cycle_history_bound_fails_closed_without_success() {
        let mut tracker = tracker();
        for _ in 0..MAX_LOOP_GUARD_CYCLES {
            tracker
                .observe(request(
                    Some(LoopFindingSeverity::Error),
                    Some(&format!("cycle-{}", tracker.cycles().len())),
                    ValidationFloor::Passed,
                    0,
                    CascadeBreakerView::Closed,
                ))
                .expect("within bound");
        }
        let err = tracker
            .observe(request(
                Some(LoopFindingSeverity::Error),
                Some("overflow"),
                ValidationFloor::Passed,
                0,
                CascadeBreakerView::Closed,
            ))
            .expect_err("history bound");
        assert_eq!(
            err,
            LoopGuardError::CycleHistoryBound(MAX_LOOP_GUARD_CYCLES)
        );
        assert_eq!(tracker.cycles().len(), MAX_LOOP_GUARD_CYCLES);
        let evidence = tracker.evidence();
        assert!(!evidence.decision.permits_success(ValidationFloor::Passed));
    }

    #[test]
    fn evidence_round_trips_and_keeps_validation_floor_required() {
        let mut tracker =
            LoopGuardTracker::new(LoopGuardConfig::warning_streak(1).expect("config"), caps())
                .expect("tracker");
        tracker
            .observe(request(
                Some(LoopFindingSeverity::Info),
                None,
                ValidationFloor::Passed,
                0,
                CascadeBreakerView::Closed,
            ))
            .expect("narrow");
        let evidence = tracker.evidence();
        assert!(evidence.decision.validation_floor_required);
        let json = serde_json::to_value(&evidence).expect("serialize");
        let decoded: LoopGuardEvidence = serde_json::from_value(json).expect("deserialize");
        assert_eq!(decoded, evidence);
        assert_eq!(decoded.decision.escalation, LoopGuardEscalation::Narrow);
    }

    #[test]
    fn oversized_signature_fails_closed() {
        let signature = "x".repeat(MAX_FAILURE_SIGNATURE_BYTES.saturating_add(1));
        let err = LoopCycleObservation::new(
            Some(LoopFindingSeverity::Error),
            Some(signature),
            ValidationFloor::Failed,
        )
        .expect_err("signature too long");
        assert_eq!(
            err,
            LoopGuardError::SignatureTooLong(MAX_FAILURE_SIGNATURE_BYTES)
        );
    }

    #[test]
    fn half_open_breaker_does_not_by_itself_refuse() {
        let mut tracker = tracker();
        let decision = tracker
            .observe(request(
                Some(LoopFindingSeverity::Error),
                Some("probe"),
                ValidationFloor::Passed,
                0,
                CascadeBreakerView::HalfOpen,
            ))
            .expect("half-open");
        assert_eq!(decision.escalation, LoopGuardEscalation::Continue);
    }

    #[test]
    fn zero_retry_default_is_not_a_retry_cap_violation() {
        let limits = ExistingRoundLimits::plan_defaults();
        let mut tracker =
            LoopGuardTracker::new(LoopGuardConfig::warning_streak(1).expect("config"), limits)
                .expect("tracker");
        let decision = tracker
            .observe(LoopGuardObserveRequest {
                observation: LoopCycleObservation::new(
                    Some(LoopFindingSeverity::Error),
                    Some("real-defect".to_owned()),
                    ValidationFloor::Failed,
                )
                .expect("observation"),
                limits,
                used_gate_corrections: 0,
                used_child_retries: 0,
                current_depth: 2,
                cascade_breaker: CascadeBreakerView::Closed,
            })
            .expect("observe");
        assert_eq!(decision.escalation, LoopGuardEscalation::Refuse);
        assert_eq!(
            decision.reason,
            LoopGuardReason::ValidationFloorUnsatisfied {
                floor: ValidationFloor::Failed
            },
            "a default max_child_retries of 0 with used=0 must not be renamed a retry loop"
        );
        assert!(!decision.permits_success(ValidationFloor::Failed));
        assert_eq!(limits.remaining_child_retries(0), 0);
        assert_eq!(tracker.evidence().round_limits, limits);
    }

    #[test]
    fn evidence_records_the_limits_supplied_on_the_last_observe() {
        let construction = ExistingRoundLimits::supervisor_caps();
        let observed = ExistingRoundLimits {
            max_depth: 4,
            max_child_retries: 1,
            max_gate_corrections: 3,
        };
        let mut tracker = LoopGuardTracker::new(
            LoopGuardConfig::warning_streak(2).expect("config"),
            construction,
        )
        .expect("tracker");
        tracker
            .observe(LoopGuardObserveRequest {
                observation: LoopCycleObservation::new(
                    Some(LoopFindingSeverity::Info),
                    None,
                    ValidationFloor::Passed,
                )
                .expect("observation"),
                limits: observed,
                used_gate_corrections: 0,
                used_child_retries: 0,
                current_depth: 2,
                cascade_breaker: CascadeBreakerView::Closed,
            })
            .expect("observe");
        assert_eq!(tracker.evidence().round_limits, observed);
        assert_ne!(tracker.evidence().round_limits, construction);
    }
}
