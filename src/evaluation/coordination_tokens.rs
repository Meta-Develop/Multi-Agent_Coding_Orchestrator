//! Own provider usage of coordinating agents.
//!
//! The supervisor row in `role_usage` is a [`RoleUsageObservation::SupervisorAggregate`]:
//! it repeats the sum of launched children. That sum already includes workers, reviewers,
//! and any child orchestrator. It is the right total-economics figure and the wrong
//! coordination figure. Adding it to `child_orchestrator` double-counts.

use crate::{
    llm::provider::Usage,
    supervise::{AgentRole, RoleUsageObservation, RoleUsageReport},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Supervisor row copies launched-child usage. It is not own coordination usage.
pub const SUPERVISOR_AGGREGATE_NOT_OWN_USAGE: &str = "supervisor_aggregate_not_own_usage: \
     supervisor usage rolls up launched children and is not the coordinating agent's own provider usage";

/// A missing supervisor row does not prove the supervising agent made no provider call.
pub const SUPERVISOR_USAGE_NOT_RETAINED: &str = "supervisor_usage_not_retained: \
     absence is not evidence that the supervising agent made no provider call";

/// Historical executed summaries predate this projection.
pub const COORDINATION_TOKENS_NOT_PROJECTED: &str = "coordination_tokens_not_projected: \
     historical summary did not project coordination tokens";

const CHILD_ORCHESTRATOR_NOT_PROCESS_OBSERVED: &str = "child_orchestrator_not_process_observed: \
     child orchestrator provider usage was not process-observed";
const SUPERVISOR_NOT_PROCESS_OBSERVED: &str = "supervisor_not_process_observed: \
     supervisor provider usage was not process-observed";
const SYNTHETIC_FAKE_NOT_LIVE: &str = "synthetic_fake_not_live_coordination: \
     synthetic role usage is not live coordinating-agent usage";
const COORDINATION_TOKEN_OVERFLOW: &str =
    "coordination_token_overflow: coordinating-agent token sum overflowed";
const COORDINATION_TOKENS_NO_REPETITIONS: &str = "coordination_tokens_no_repetitions: \
     no executed repetitions were retained";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoordinationTokenStatus {
    /// The role did not appear. Counts as zero own tokens.
    Absent,
    /// Process-observed own provider usage.
    Known,
    /// Present, but not usable as own provider usage.
    Unknown,
}

/// One coordinating role's own tokens. Unknown rows omit `usage` so a child rollup
/// cannot be added by mistake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinationRoleTokens {
    pub status: CoordinationTokenStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
}

impl CoordinationRoleTokens {
    fn absent() -> Self {
        Self {
            status: CoordinationTokenStatus::Absent,
            usage: None,
            unavailable_reason: None,
        }
    }

    fn known(usage: Usage) -> Self {
        Self {
            status: CoordinationTokenStatus::Known,
            usage: Some(usage),
            unavailable_reason: None,
        }
    }

    fn unknown(reason: impl Into<String>) -> Self {
        Self {
            status: CoordinationTokenStatus::Unknown,
            usage: None,
            unavailable_reason: Some(reason.into()),
        }
    }

    fn as_tokens(&self) -> Result<Usage, &str> {
        match self.status {
            CoordinationTokenStatus::Absent => Ok(Usage::default()),
            CoordinationTokenStatus::Known => self
                .usage
                .ok_or("process_observed_usage_missing: known coordination usage was empty"),
            CoordinationTokenStatus::Unknown => Err(self
                .unavailable_reason
                .as_deref()
                .unwrap_or("coordination_tokens_unknown")),
        }
    }
}

/// Own tokens for the supervising agent and any child orchestrator.
///
/// `total` is `Some` only when both components are known or absent. Worker,
/// researcher, gate-classifier, auditor, and review-lens usage are excluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinationTokenObservation {
    pub supervisor_own: CoordinationRoleTokens,
    pub child_orchestrator: CoordinationRoleTokens,
    pub total: Option<Usage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
}

/// Sum of per-repetition coordination totals for one executed profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinationTokenSummary {
    pub aggregate_total: Option<Usage>,
    pub repetitions_known: u32,
    pub repetitions_unknown: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
}

impl Default for CoordinationTokenSummary {
    fn default() -> Self {
        Self {
            aggregate_total: None,
            repetitions_known: 0,
            repetitions_unknown: 0,
            unavailable_reason: Some(COORDINATION_TOKENS_NOT_PROJECTED.to_string()),
        }
    }
}

/// Project coordinating-agent tokens from a supervisor-final `role_usage` map.
pub fn coordination_token_observation(
    role_usage: &BTreeMap<AgentRole, RoleUsageReport>,
) -> CoordinationTokenObservation {
    let supervisor_own = classify_role(
        AgentRole::Supervisor,
        role_usage.get(&AgentRole::Supervisor),
    );
    let child_orchestrator = classify_role(
        AgentRole::ChildOrchestrator,
        role_usage.get(&AgentRole::ChildOrchestrator),
    );
    let (total, unavailable_reason) =
        match (supervisor_own.as_tokens(), child_orchestrator.as_tokens()) {
            (Ok(left), Ok(right)) => match checked_add_usage(left, right) {
                Some(total) => (Some(total), None),
                None => (None, Some(COORDINATION_TOKEN_OVERFLOW.to_string())),
            },
            _ => (
                None,
                Some(join_reasons(&supervisor_own, &child_orchestrator)),
            ),
        };
    CoordinationTokenObservation {
        supervisor_own,
        child_orchestrator,
        total,
        unavailable_reason,
    }
}

/// Sum known repetition totals. Any unknown repetition makes the aggregate unknown.
pub fn summarize_coordination_observations(
    observations: &[CoordinationTokenObservation],
) -> CoordinationTokenSummary {
    if observations.is_empty() {
        return CoordinationTokenSummary {
            aggregate_total: None,
            repetitions_known: 0,
            repetitions_unknown: 0,
            unavailable_reason: Some(COORDINATION_TOKENS_NO_REPETITIONS.to_string()),
        };
    }
    let mut repetitions_known = 0u32;
    let mut repetitions_unknown = 0u32;
    let mut sum = Usage::default();
    let mut overflow = false;
    let mut unknown_reason = None;
    for observation in observations {
        match observation.total {
            Some(usage) => {
                repetitions_known = repetitions_known.saturating_add(1);
                if !overflow {
                    match checked_add_usage(sum, usage) {
                        Some(next) => sum = next,
                        None => overflow = true,
                    }
                }
            }
            None => {
                repetitions_unknown = repetitions_unknown.saturating_add(1);
                if unknown_reason.is_none() {
                    unknown_reason = observation.unavailable_reason.clone();
                }
            }
        }
    }
    if repetitions_unknown > 0 {
        let reason = if observations.len() == 1 {
            unknown_reason.unwrap_or_else(|| {
                "coordination_tokens_incomplete: the repetition lacks a known coordination total"
                    .to_string()
            })
        } else {
            format!(
                "coordination_tokens_incomplete: {repetitions_unknown} of {} repetitions lack a known coordination total",
                observations.len()
            )
        };
        return CoordinationTokenSummary {
            aggregate_total: None,
            repetitions_known,
            repetitions_unknown,
            unavailable_reason: Some(reason),
        };
    }
    if overflow {
        return CoordinationTokenSummary {
            aggregate_total: None,
            repetitions_known,
            repetitions_unknown,
            unavailable_reason: Some(COORDINATION_TOKEN_OVERFLOW.to_string()),
        };
    }
    CoordinationTokenSummary {
        aggregate_total: Some(sum),
        repetitions_known,
        repetitions_unknown,
        unavailable_reason: None,
    }
}

fn classify_role(role: AgentRole, report: Option<&RoleUsageReport>) -> CoordinationRoleTokens {
    let Some(report) = report else {
        return match role {
            AgentRole::ChildOrchestrator => CoordinationRoleTokens::absent(),
            _ => CoordinationRoleTokens::unknown(SUPERVISOR_USAGE_NOT_RETAINED),
        };
    };
    match report.observation {
        RoleUsageObservation::SupervisorAggregate => {
            CoordinationRoleTokens::unknown(SUPERVISOR_AGGREGATE_NOT_OWN_USAGE)
        }
        RoleUsageObservation::NotProcessObservable => CoordinationRoleTokens::unknown(match role {
            AgentRole::ChildOrchestrator => CHILD_ORCHESTRATOR_NOT_PROCESS_OBSERVED,
            _ => SUPERVISOR_NOT_PROCESS_OBSERVED,
        }),
        RoleUsageObservation::SyntheticFake => {
            CoordinationRoleTokens::unknown(SYNTHETIC_FAKE_NOT_LIVE)
        }
        RoleUsageObservation::ProcessObserved => match report.usage {
            None => CoordinationRoleTokens::unknown(format!(
                "process_observed_usage_missing: {} observation is process_observed but usage is absent",
                role_label(role)
            )),
            Some(usage) => match consistent_usage(usage) {
                Some(usage) => CoordinationRoleTokens::known(usage),
                None => CoordinationRoleTokens::unknown(format!(
                    "usage_total_inconsistent: {} total_tokens must equal input_tokens plus output_tokens",
                    role_label(role)
                )),
            },
        },
    }
}

fn role_label(role: AgentRole) -> &'static str {
    match role {
        AgentRole::Supervisor => "supervisor",
        AgentRole::ChildOrchestrator => "child_orchestrator",
        AgentRole::Worker => "worker",
        AgentRole::Researcher => "researcher",
        AgentRole::GateClassifier => "gate_classifier",
        AgentRole::Auditor => "auditor",
    }
}

fn consistent_usage(usage: Usage) -> Option<Usage> {
    let sum = usage.input_tokens.checked_add(usage.output_tokens)?;
    (sum == usage.total_tokens).then_some(usage)
}

fn checked_add_usage(left: Usage, right: Usage) -> Option<Usage> {
    let input_tokens = left.input_tokens.checked_add(right.input_tokens)?;
    let output_tokens = left.output_tokens.checked_add(right.output_tokens)?;
    let total_tokens = input_tokens.checked_add(output_tokens)?;
    Some(Usage {
        input_tokens,
        output_tokens,
        total_tokens,
    })
}

fn join_reasons(supervisor: &CoordinationRoleTokens, child: &CoordinationRoleTokens) -> String {
    match (
        supervisor.unavailable_reason.as_deref(),
        child.unavailable_reason.as_deref(),
    ) {
        (Some(left), Some(right)) if left != right => format!("{left}; {right}"),
        (Some(reason), _) | (_, Some(reason)) => reason.to_string(),
        (None, None) => "coordination_tokens_unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage(input: usize, output: usize) -> Usage {
        Usage {
            input_tokens: input,
            output_tokens: output,
            total_tokens: input + output,
        }
    }

    fn report(observation: RoleUsageObservation, usage: Option<Usage>) -> RoleUsageReport {
        RoleUsageReport {
            models: Vec::new(),
            usage,
            cost_usd: None,
            observation,
            unavailable_reason: None,
        }
    }

    fn map(entries: &[(AgentRole, RoleUsageReport)]) -> BTreeMap<AgentRole, RoleUsageReport> {
        entries.iter().cloned().collect()
    }

    #[test]
    fn supervisor_aggregate_is_not_coordination_usage_and_does_not_double_count() {
        let child = usage(7, 3);
        let worker = usage(80, 20);
        let aggregate = checked_add_usage(child, worker).expect("fixture sum");
        let observed = coordination_token_observation(&map(&[
            (
                AgentRole::Supervisor,
                report(RoleUsageObservation::SupervisorAggregate, Some(aggregate)),
            ),
            (
                AgentRole::ChildOrchestrator,
                report(RoleUsageObservation::ProcessObserved, Some(child)),
            ),
            (
                AgentRole::Worker,
                report(RoleUsageObservation::ProcessObserved, Some(worker)),
            ),
            (
                AgentRole::Auditor,
                report(RoleUsageObservation::ProcessObserved, Some(usage(5, 5))),
            ),
        ]));

        assert_eq!(
            observed.supervisor_own.status,
            CoordinationTokenStatus::Unknown
        );
        assert!(observed.supervisor_own.usage.is_none());
        assert_eq!(
            observed.child_orchestrator.status,
            CoordinationTokenStatus::Known
        );
        assert_eq!(observed.child_orchestrator.usage, Some(child));
        assert!(observed.total.is_none());
        assert_ne!(observed.total, Some(aggregate));
        assert_ne!(observed.total, Some(child));
        let reason = observed.unavailable_reason.expect("reason");
        assert!(reason.contains("supervisor_aggregate_not_own_usage"));
    }

    #[test]
    fn explicit_zero_supervisor_usage_excludes_workers_and_absent_child_orchestrator() {
        let observed = coordination_token_observation(&map(&[
            (
                AgentRole::Supervisor,
                report(
                    RoleUsageObservation::ProcessObserved,
                    Some(Usage::default()),
                ),
            ),
            (
                AgentRole::Worker,
                report(RoleUsageObservation::ProcessObserved, Some(usage(40, 10))),
            ),
        ]));

        assert_eq!(
            observed.supervisor_own.status,
            CoordinationTokenStatus::Known
        );
        assert_eq!(
            observed.child_orchestrator.status,
            CoordinationTokenStatus::Absent
        );
        assert_eq!(observed.total, Some(Usage::default()));
        assert!(observed.unavailable_reason.is_none());
    }

    #[test]
    fn known_supervisor_and_child_orchestrator_sum_excludes_other_roles() {
        let observed = coordination_token_observation(&map(&[
            (
                AgentRole::Supervisor,
                report(RoleUsageObservation::ProcessObserved, Some(usage(4, 6))),
            ),
            (
                AgentRole::ChildOrchestrator,
                report(RoleUsageObservation::ProcessObserved, Some(usage(1, 2))),
            ),
            (
                AgentRole::Worker,
                report(RoleUsageObservation::ProcessObserved, Some(usage(100, 50))),
            ),
        ]));

        assert_eq!(observed.total, Some(usage(5, 8)));
    }

    #[test]
    fn missing_supervisor_unobserved_child_and_inconsistent_usage_stay_unknown() {
        let missing = coordination_token_observation(&BTreeMap::new());
        assert!(missing.total.is_none());
        assert!(missing
            .unavailable_reason
            .unwrap()
            .contains("supervisor_usage_not_retained"));

        let unobserved_child = coordination_token_observation(&map(&[
            (
                AgentRole::Supervisor,
                report(RoleUsageObservation::ProcessObserved, Some(usage(1, 1))),
            ),
            (
                AgentRole::ChildOrchestrator,
                report(RoleUsageObservation::NotProcessObservable, None),
            ),
        ]));
        assert!(unobserved_child.total.is_none());
        assert!(unobserved_child
            .unavailable_reason
            .unwrap()
            .contains("child_orchestrator_not_process_observed"));

        let mut inconsistent = usage(3, 4);
        inconsistent.total_tokens = 99;
        let bad = coordination_token_observation(&map(&[(
            AgentRole::Supervisor,
            report(RoleUsageObservation::ProcessObserved, Some(inconsistent)),
        )]));
        assert!(bad.total.is_none());
        assert!(bad
            .unavailable_reason
            .unwrap()
            .contains("usage_total_inconsistent"));

        let fake = coordination_token_observation(&map(&[(
            AgentRole::Supervisor,
            report(RoleUsageObservation::SyntheticFake, Some(usage(1, 1))),
        )]));
        assert!(fake.total.is_none());
        assert!(fake
            .unavailable_reason
            .unwrap()
            .contains("synthetic_fake_not_live_coordination"));
    }

    #[test]
    fn summary_keeps_one_unknown_reason_and_sums_only_complete_repetitions() {
        let known = coordination_token_observation(&map(&[(
            AgentRole::Supervisor,
            report(RoleUsageObservation::ProcessObserved, Some(usage(2, 2))),
        )]));
        let unknown = coordination_token_observation(&BTreeMap::new());
        let mixed = summarize_coordination_observations(&[known.clone(), unknown]);
        assert!(mixed.aggregate_total.is_none());
        assert_eq!(mixed.repetitions_known, 1);
        assert_eq!(mixed.repetitions_unknown, 1);
        assert!(mixed
            .unavailable_reason
            .unwrap()
            .contains("coordination_tokens_incomplete: 1 of 2"));

        let single = summarize_coordination_observations(&[unknown_observation()]);
        assert!(single
            .unavailable_reason
            .unwrap()
            .contains("supervisor_usage_not_retained"));

        let both = summarize_coordination_observations(&[known.clone(), known]);
        assert_eq!(both.aggregate_total, Some(usage(4, 4)));
        assert_eq!(both.repetitions_known, 2);
        assert_eq!(both.repetitions_unknown, 0);
        assert!(both.unavailable_reason.is_none());
    }

    fn unknown_observation() -> CoordinationTokenObservation {
        coordination_token_observation(&BTreeMap::new())
    }

    #[test]
    fn historical_summary_default_is_distinct_from_a_computed_unknown() {
        let historical = CoordinationTokenSummary::default();
        assert!(historical.aggregate_total.is_none());
        assert_eq!(historical.repetitions_known, 0);
        assert_eq!(historical.repetitions_unknown, 0);
        assert!(historical
            .unavailable_reason
            .unwrap()
            .contains("coordination_tokens_not_projected"));
    }
}
