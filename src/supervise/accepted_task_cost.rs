//! Cost-per-accepted-task rollup over parent attempt cost evidence.
//!
//! Attempts with any missing attributable bucket — including `environment_cost_microunits:
//! None` on verified external launches — retain partial evidence but prevent numeric CPO.
//! Unknown terminal results remain explicit; neither cost nor acceptance is invented.
//!
//! The supervisor final-report path records this rollup on
//! `role_economics_profile.execution.accepted_task_cost`.

use super::outcome_history::{AttemptAttributableCosts, AttemptSelectionBinding};
use crate::selection::{AcceptedTaskCostLane, AcceptedTaskCostObservation, OutcomeResult};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::supervise) struct AttemptCostRecord {
    pub selection: Option<AttemptSelectionBinding>,
    pub result: Option<OutcomeResult>,
    pub costs: AttemptAttributableCosts,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedTaskCostRollup {
    pub incomplete_attempt_count: u32,
    /// Independent of cost completeness: unresolved terminal results prevent numeric CPO.
    #[serde(default, skip_serializing_if = "is_zero_count")]
    pub unknown_terminal_result_count: u32,
    pub complete_attempt_count: u32,
    pub complete_accepted_count: u32,
    /// Known subtotal over complete-cost rows; partial if costs or results remain unresolved.
    pub complete_total_cycle_cost_microunits: u64,
    /// Known buckets on incomplete-cost rows; evidence only, excluded from CPO.
    #[serde(default, skip_serializing_if = "is_zero_cost")]
    pub known_incomplete_cost_microunits: u64,
    pub cost_per_accepted_task_microunits: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedTaskCostCohort {
    pub lane: AcceptedTaskCostLane,
    pub costs: AcceptedTaskCostRollup,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedTaskCostCohorts {
    pub lanes: Vec<AcceptedTaskCostCohort>,
    /// Legacy, missing, or shape-unbound identity never supplies feedback.
    pub unattributed: AcceptedTaskCostRollup,
}

impl AcceptedTaskCostCohorts {
    pub(in crate::supervise) fn observations(&self) -> Vec<AcceptedTaskCostObservation> {
        self.lanes
            .iter()
            .filter_map(|cohort| {
                Some(AcceptedTaskCostObservation {
                    lane: cohort.lane.clone(),
                    cost_per_accepted_task_microunits: observed_cost_per_accepted_task_microunits(
                        Some(&cohort.costs),
                    )?,
                })
            })
            .collect()
    }
}

pub(in crate::supervise) fn rollup_selection_cost_cohorts(
    records: &[AttemptCostRecord],
) -> Result<AcceptedTaskCostCohorts> {
    let mut lanes: Vec<(AcceptedTaskCostLane, Vec<AttemptCostRecord>)> = Vec::new();
    let mut unattributed = Vec::new();
    for record in records {
        let lane = record.selection.as_ref().and_then(|selection| {
            Some(AcceptedTaskCostLane {
                role: selection.role,
                task: selection.task.clone(),
                assignment_shape_identity: selection.assignment_shape_identity.clone()?,
                candidate: selection.requested_candidate.clone(),
            })
        });
        let Some(lane) = lane else {
            unattributed.push(record.clone());
            continue;
        };
        if let Some((_, cohort)) = lanes.iter_mut().find(|(key, _)| *key == lane) {
            cohort.push(record.clone());
        } else {
            lanes.push((lane, vec![record.clone()]));
        }
    }
    Ok(AcceptedTaskCostCohorts {
        lanes: lanes
            .into_iter()
            .map(|(lane, records)| {
                Ok(AcceptedTaskCostCohort {
                    lane,
                    costs: rollup_cost_per_accepted_task(&records)?,
                })
            })
            .collect::<Result<_>>()?,
        unattributed: rollup_cost_per_accepted_task(&unattributed)?,
    })
}

pub(in crate::supervise) fn attempt_cost_record(
    selection: Option<AttemptSelectionBinding>,
    costs: AttemptAttributableCosts,
    result: Option<OutcomeResult>,
) -> AttemptCostRecord {
    AttemptCostRecord {
        selection,
        result,
        costs,
    }
}

fn is_zero_count(count: &u32) -> bool {
    *count == 0
}

fn is_zero_cost(cost: &u64) -> bool {
    *cost == 0
}

pub(in crate::supervise) fn rollup_cost_per_accepted_task(
    records: &[AttemptCostRecord],
) -> Result<AcceptedTaskCostRollup> {
    let mut incomplete_attempt_count = 0u32;
    let mut unknown_terminal_result_count = 0u32;
    let mut complete_attempt_count = 0u32;
    let mut complete_accepted_count = 0u32;
    let mut complete_total_cycle_cost_microunits = 0u64;
    let mut known_incomplete_cost_microunits = 0u64;

    for record in records {
        if record.result.is_none() {
            unknown_terminal_result_count = unknown_terminal_result_count
                .checked_add(1)
                .context("unknown terminal result count overflowed")?;
        }
        let Some(buckets) = record.costs.complete() else {
            incomplete_attempt_count = incomplete_attempt_count
                .checked_add(1)
                .context("incomplete attempt count overflowed")?;
            for cost in [
                record.costs.execution_cost_microunits,
                record.costs.review_cost_microunits,
                record.costs.rework_cost_microunits,
                record.costs.rereview_cost_microunits,
                record.costs.environment_cost_microunits,
            ]
            .into_iter()
            .flatten()
            {
                known_incomplete_cost_microunits = known_incomplete_cost_microunits
                    .checked_add(cost)
                    .context("known incomplete cost overflowed")?;
            }
            continue;
        };
        complete_attempt_count = complete_attempt_count
            .checked_add(1)
            .context("complete attempt count overflowed")?;
        let attempt_total = sum_five_bucket_cycle_cost(buckets)?;
        complete_total_cycle_cost_microunits = complete_total_cycle_cost_microunits
            .checked_add(attempt_total)
            .context("complete total cycle cost overflowed")?;
        if record.result == Some(OutcomeResult::Accepted) {
            complete_accepted_count = complete_accepted_count
                .checked_add(1)
                .context("complete accepted count overflowed")?;
        }
    }

    let cost_per_accepted_task_microunits = if incomplete_attempt_count != 0
        || unknown_terminal_result_count != 0
        || complete_accepted_count == 0
    {
        None
    } else {
        Some(
            complete_total_cycle_cost_microunits
                .checked_div(u64::from(complete_accepted_count))
                .context("accepted-task cost division overflowed")?,
        )
    };

    Ok(AcceptedTaskCostRollup {
        incomplete_attempt_count,
        unknown_terminal_result_count,
        complete_attempt_count,
        complete_accepted_count,
        complete_total_cycle_cost_microunits,
        known_incomplete_cost_microunits,
        cost_per_accepted_task_microunits,
    })
}

/// Numeric CPO only for a complete, resolved, internally consistent rollup.
///
/// Legacy/wire partial subtotals and absent observations stay `None`, never zero.
pub(in crate::supervise) fn observed_cost_per_accepted_task_microunits(
    rollup: Option<&AcceptedTaskCostRollup>,
) -> Option<u64> {
    let rollup = rollup?;
    if rollup.incomplete_attempt_count != 0
        || rollup.known_incomplete_cost_microunits != 0
        || rollup.unknown_terminal_result_count != 0
        || rollup.complete_accepted_count == 0
        || rollup.complete_accepted_count > rollup.complete_attempt_count
    {
        return None;
    }
    let expected = rollup
        .complete_total_cycle_cost_microunits
        .checked_div(u64::from(rollup.complete_accepted_count))?;
    rollup
        .cost_per_accepted_task_microunits
        .filter(|observed| *observed == expected)
}

fn sum_five_bucket_cycle_cost(buckets: [u64; 5]) -> Result<u64> {
    buckets.into_iter().try_fold(0u64, |total, bucket| {
        total
            .checked_add(bucket)
            .context("attempt cycle cost overflowed")
    })
}

#[cfg(test)]
mod tests {
    use super::super::SupervisorExecutionMetadata;
    use super::*;

    fn bound_attempt(model: &str, shape: &str, cost: u64) -> AttemptCostRecord {
        let mut record = fake_simulation_complete_accepted();
        record.costs.execution_cost_microunits = Some(cost);
        record.selection = Some(AttemptSelectionBinding {
            role: super::super::AgentRole::Worker,
            event_assignment_id: None,
            event_attempt: 0,
            normalized_input_sha256: "f".repeat(64),
            task: crate::selection::selection_test_base_input().task,
            assignment_shape_identity: Some(
                crate::selection::AssignmentShapeIdentity::v1(shape.repeat(64)).expect("shape"),
            ),
            requested_candidate: crate::selection::CandidateKey {
                runtime: "codex".to_string(),
                model: model.to_string(),
                effort: crate::selection::ReasoningEffort::High,
            },
        });
        record
    }

    #[test]
    fn feedback_isolated_by_candidate_and_task_shape() -> Result<()> {
        let accepted = bound_attempt("candidate-a", "a", 10);
        let mut rejected = accepted.clone();
        rejected.result = Some(OutcomeResult::Rejected);
        rejected.costs.rework_cost_microunits = Some(7);
        rejected.costs.rereview_cost_microunits = Some(3);
        let mut other_role = accepted.clone();
        other_role.selection.as_mut().unwrap().role = super::super::AgentRole::Researcher;
        let mut other_task = accepted.clone();
        other_task.selection.as_mut().unwrap().task.context = crate::selection::ContextSize::Long;
        let cohorts = rollup_selection_cost_cohorts(&[
            accepted,
            rejected,
            bound_attempt("candidate-b", "a", 500),
            bound_attempt("candidate-a", "b", 200),
            other_role,
            other_task,
        ])?;
        assert_eq!(cohorts.lanes.len(), 5);
        assert_eq!(cohorts.lanes[0].costs.complete_attempt_count, 2);
        assert_eq!(cohorts.lanes[0].costs.complete_accepted_count, 1);
        assert_eq!(
            cohorts.lanes[0].costs.complete_total_cycle_cost_microunits,
            34
        );
        assert_eq!(
            cohorts.observations()[0].cost_per_accepted_task_microunits,
            34
        );
        assert_eq!(
            cohorts.observations()[1].cost_per_accepted_task_microunits,
            502
        );
        assert_eq!(
            cohorts.observations()[2].cost_per_accepted_task_microunits,
            202
        );
        let wire = serde_json::to_value(&cohorts)?;
        assert_eq!(
            serde_json::from_value::<AcceptedTaskCostCohorts>(wire)?,
            cohorts
        );
        Ok(())
    }

    #[test]
    fn incomplete_and_unknown_cohorts_refuse_feedback_and_preserve_spend() -> Result<()> {
        let mut incomplete = bound_attempt("candidate-a", "a", 500);
        incomplete.costs.review_cost_microunits = Some(50);
        incomplete.costs.environment_cost_microunits = None;
        let mut unknown = bound_attempt("candidate-b", "a", 100);
        unknown.result = None;
        let cohorts = rollup_selection_cost_cohorts(&[
            bound_attempt("candidate-a", "a", 10),
            incomplete,
            bound_attempt("candidate-b", "a", 20),
            unknown,
            bound_attempt("candidate-c", "a", 200),
        ])?;
        let partial = &cohorts.lanes[0].costs;
        assert_eq!(partial.complete_total_cycle_cost_microunits, 12);
        assert_eq!(partial.known_incomplete_cost_microunits, 550);
        assert_eq!(partial.incomplete_attempt_count, 1);
        assert_eq!(partial.cost_per_accepted_task_microunits, None);
        let unresolved = &cohorts.lanes[1].costs;
        assert_eq!(unresolved.complete_total_cycle_cost_microunits, 124);
        assert_eq!(unresolved.unknown_terminal_result_count, 1);
        assert_eq!(unresolved.cost_per_accepted_task_microunits, None);
        let observations = cohorts.observations();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].lane.candidate.model, "candidate-c");
        assert_eq!(observations[0].cost_per_accepted_task_microunits, 202);
        Ok(())
    }

    #[test]
    fn unbound_and_legacy_identity_remains_unattributed() -> Result<()> {
        let mut unbound = bound_attempt("candidate-a", "a", 500);
        unbound
            .selection
            .as_mut()
            .unwrap()
            .assignment_shape_identity = None;
        let cohorts =
            rollup_selection_cost_cohorts(&[unbound, fake_simulation_complete_accepted()])?;
        assert!(cohorts.lanes.is_empty());
        assert!(cohorts.observations().is_empty());
        assert_eq!(cohorts.unattributed.complete_attempt_count, 2);
        assert_eq!(
            cohorts.unattributed.complete_total_cycle_cost_microunits,
            514
        );
        Ok(())
    }

    #[test]
    fn rejected_retry_spend_stays_in_its_candidate_lane() -> Result<()> {
        let mut rejected = bound_attempt("candidate-a", "a", 500);
        rejected.result = Some(OutcomeResult::Rejected);
        rejected.costs.rework_cost_microunits = Some(20);
        let cohorts =
            rollup_selection_cost_cohorts(&[rejected, bound_attempt("candidate-b", "a", 10)])?;
        assert_eq!(
            cohorts.lanes[0].costs.complete_total_cycle_cost_microunits,
            522
        );
        assert_eq!(cohorts.lanes[0].costs.complete_accepted_count, 0);
        assert_eq!(
            cohorts.lanes[0].costs.cost_per_accepted_task_microunits,
            None
        );
        assert_eq!(cohorts.observations().len(), 1);
        assert_eq!(
            cohorts.observations()[0].lane.candidate.model,
            "candidate-b"
        );
        assert_eq!(
            cohorts.observations()[0].cost_per_accepted_task_microunits,
            12
        );
        Ok(())
    }

    fn fake_simulation_complete_accepted() -> AttemptCostRecord {
        AttemptCostRecord {
            selection: None,
            result: Some(OutcomeResult::Accepted),
            costs: AttemptAttributableCosts {
                execution_cost_microunits: Some(10),
                review_cost_microunits: Some(2),
                rework_cost_microunits: Some(0),
                rereview_cost_microunits: Some(0),
                environment_cost_microunits: Some(0),
            },
        }
    }

    fn grok_verified_environment_unknown_accepted() -> AttemptCostRecord {
        AttemptCostRecord {
            selection: None,
            result: Some(OutcomeResult::Accepted),
            costs: AttemptAttributableCosts {
                execution_cost_microunits: Some(500),
                review_cost_microunits: Some(50),
                rework_cost_microunits: Some(0),
                rereview_cost_microunits: Some(0),
                environment_cost_microunits: None,
            },
        }
    }

    #[test]
    fn rollup_retains_partial_subtotal_without_numeric_cpo() -> Result<()> {
        let rollup = rollup_cost_per_accepted_task(&[
            fake_simulation_complete_accepted(),
            grok_verified_environment_unknown_accepted(),
        ])?;

        assert_eq!(rollup.incomplete_attempt_count, 1);
        assert_eq!(rollup.complete_attempt_count, 1);
        assert_eq!(rollup.complete_accepted_count, 1);
        assert_eq!(rollup.complete_total_cycle_cost_microunits, 12);
        assert_eq!(rollup.known_incomplete_cost_microunits, 550);
        assert_eq!(rollup.unknown_terminal_result_count, 0);
        assert_eq!(rollup.cost_per_accepted_task_microunits, None);
        assert_eq!(
            observed_cost_per_accepted_task_microunits(Some(&rollup)),
            None
        );
        Ok(())
    }

    #[test]
    fn incomplete_rows_do_not_coerce_environment_none_to_zero() -> Result<()> {
        let grok_only =
            rollup_cost_per_accepted_task(&[grok_verified_environment_unknown_accepted()])?;
        assert_eq!(grok_only.incomplete_attempt_count, 1);
        assert_eq!(grok_only.complete_attempt_count, 0);
        assert_eq!(grok_only.complete_accepted_count, 0);
        assert_eq!(grok_only.complete_total_cycle_cost_microunits, 0);
        assert_eq!(grok_only.cost_per_accepted_task_microunits, None);

        let fake_only = rollup_cost_per_accepted_task(&[fake_simulation_complete_accepted()])?;
        assert_eq!(fake_only.incomplete_attempt_count, 0);
        assert_eq!(fake_only.complete_total_cycle_cost_microunits, 12);
        Ok(())
    }

    #[test]
    fn unknown_terminal_result_is_retained_without_numeric_cpo() -> Result<()> {
        let costs = fake_simulation_complete_accepted().costs;
        let unknown = attempt_cost_record(None, costs.clone(), None);
        assert_eq!(unknown.result, None);
        assert_eq!(unknown.costs, costs);
        let rollup =
            rollup_cost_per_accepted_task(&[fake_simulation_complete_accepted(), unknown])?;
        assert_eq!(rollup.complete_attempt_count, 2);
        assert_eq!(rollup.incomplete_attempt_count, 0);
        assert_eq!(rollup.unknown_terminal_result_count, 1);
        assert_eq!(rollup.complete_accepted_count, 1);
        assert_eq!(rollup.complete_total_cycle_cost_microunits, 24);
        assert_eq!(rollup.cost_per_accepted_task_microunits, None);
        assert_eq!(
            observed_cost_per_accepted_task_microunits(Some(&rollup)),
            None
        );
        let accepted = attempt_cost_record(None, costs, Some(OutcomeResult::Accepted));
        assert_eq!(accepted.result, Some(OutcomeResult::Accepted));
        Ok(())
    }

    #[test]
    fn unknown_result_and_missing_cost_counts_are_independent() -> Result<()> {
        let mut unknown = grok_verified_environment_unknown_accepted();
        unknown.result = None;
        let rollup =
            rollup_cost_per_accepted_task(&[fake_simulation_complete_accepted(), unknown])?;
        assert_eq!(rollup.incomplete_attempt_count, 1);
        assert_eq!(rollup.unknown_terminal_result_count, 1);
        assert_eq!(rollup.complete_attempt_count, 1);
        assert_eq!(rollup.complete_total_cycle_cost_microunits, 12);
        assert_eq!(rollup.cost_per_accepted_task_microunits, None);
        Ok(())
    }

    #[test]
    fn complete_rejections_and_blocked_attempts_contribute_to_cpo() -> Result<()> {
        let accepted = fake_simulation_complete_accepted();
        let mut rejected = accepted.clone();
        rejected.result = Some(OutcomeResult::Rejected);
        let mut blocked = accepted.clone();
        blocked.result = Some(OutcomeResult::Blocked);
        let no_accepted = rollup_cost_per_accepted_task(&[rejected.clone(), blocked.clone()])?;
        assert_eq!(no_accepted.complete_total_cycle_cost_microunits, 24);
        assert_eq!(no_accepted.cost_per_accepted_task_microunits, None);
        let rollup = rollup_cost_per_accepted_task(&[accepted, rejected, blocked])?;
        assert_eq!(rollup.complete_attempt_count, 3);
        assert_eq!(rollup.complete_accepted_count, 1);
        assert_eq!(rollup.complete_total_cycle_cost_microunits, 36);
        assert_eq!(rollup.cost_per_accepted_task_microunits, Some(36));
        assert_eq!(
            observed_cost_per_accepted_task_microunits(Some(&rollup)),
            Some(36)
        );
        Ok(())
    }

    #[test]
    fn fully_complete_accepted_attempts_use_the_exact_ratio() -> Result<()> {
        let accepted = fake_simulation_complete_accepted();
        let mut rejected = accepted.clone();
        rejected.result = Some(OutcomeResult::Rejected);
        let rollup = rollup_cost_per_accepted_task(&[accepted.clone(), accepted, rejected])?;
        assert_eq!(rollup.complete_total_cycle_cost_microunits, 36);
        assert_eq!(rollup.complete_accepted_count, 2);
        assert_eq!(rollup.cost_per_accepted_task_microunits, Some(18));
        assert_eq!(
            observed_cost_per_accepted_task_microunits(Some(&rollup)),
            Some(18)
        );
        Ok(())
    }

    #[test]
    fn legacy_and_wire_partial_rollups_cannot_supply_observed_cpo() -> Result<()> {
        let legacy = serde_json::json!({
            "incomplete_attempt_count": 1,
            "complete_attempt_count": 1,
            "complete_accepted_count": 1,
            "complete_total_cycle_cost_microunits": 12,
            "cost_per_accepted_task_microunits": 12
        });
        let partial: AcceptedTaskCostRollup = serde_json::from_value(legacy.clone())?;
        assert_eq!(partial.unknown_terminal_result_count, 0);
        assert_eq!(partial.known_incomplete_cost_microunits, 0);
        assert_eq!(
            observed_cost_per_accepted_task_microunits(Some(&partial)),
            None
        );
        assert_eq!(serde_json::to_value(&partial)?, legacy);

        let complete = rollup_cost_per_accepted_task(&[fake_simulation_complete_accepted()])?;
        let mut unresolved = complete.clone();
        unresolved.unknown_terminal_result_count = 1;
        let wire: AcceptedTaskCostRollup =
            serde_json::from_value(serde_json::to_value(&unresolved)?)?;
        assert_eq!(wire.unknown_terminal_result_count, 1);
        assert_eq!(
            observed_cost_per_accepted_task_microunits(Some(&wire)),
            None
        );
        for (attempts, accepted, ratio) in [(0, 1, 12), (1, 2, 6), (1, 1, 999)] {
            let mut malformed = complete.clone();
            malformed.complete_attempt_count = attempts;
            malformed.complete_accepted_count = accepted;
            malformed.cost_per_accepted_task_microunits = Some(ratio);
            assert_eq!(
                observed_cost_per_accepted_task_microunits(Some(&malformed)),
                None
            );
        }
        let complete_wire = serde_json::to_value(&complete)?;
        assert!(complete_wire.get("unknown_terminal_result_count").is_none());
        let legacy_complete: AcceptedTaskCostRollup = serde_json::from_value(complete_wire)?;
        assert_eq!(
            observed_cost_per_accepted_task_microunits(Some(&legacy_complete)),
            Some(12)
        );
        let mut inconsistent = legacy_complete;
        inconsistent.known_incomplete_cost_microunits = 550;
        assert_eq!(
            observed_cost_per_accepted_task_microunits(Some(&inconsistent)),
            None
        );
        Ok(())
    }

    #[test]
    fn attributable_cost_overflow_still_refuses_the_rollup() {
        let mut overflowing_bucket = fake_simulation_complete_accepted();
        overflowing_bucket.costs.execution_cost_microunits = Some(u64::MAX);
        assert!(rollup_cost_per_accepted_task(&[overflowing_bucket]).is_err());
        let mut overflowing_total = fake_simulation_complete_accepted();
        overflowing_total.costs.execution_cost_microunits = Some(u64::MAX - 2);
        assert!(rollup_cost_per_accepted_task(&[
            overflowing_total,
            fake_simulation_complete_accepted(),
        ])
        .is_err());
        let mut incomplete = grok_verified_environment_unknown_accepted();
        incomplete.costs.execution_cost_microunits = Some(u64::MAX);
        assert!(rollup_cost_per_accepted_task(&[incomplete]).is_err());
    }

    #[test]
    fn legacy_execution_metadata_without_accepted_task_cost_still_deserializes() {
        let json = serde_json::json!({
            "assignment_count": 0,
            "started_assignment_count": 0,
            "completed_assignment_count": 0,
            "concurrency": {
                "configured_max_concurrent_children": 1,
                "policy_input_observation": "scheduler_observed",
                "achieved_max_concurrent_children": 0,
                "achieved_mean_concurrent_children": null,
                "achieved_mean_observation": "not_process_observable"
            },
            "role_bindings": {},
            "usage": {
                "total_usage": null,
                "total_cost_usd": null,
                "usage_complete": false,
                "observation": "not_process_observable"
            }
        });
        let metadata: SupervisorExecutionMetadata =
            serde_json::from_value(json).expect("legacy execution metadata deserializes");
        assert!(metadata.accepted_task_cost.is_none());
    }

    #[test]
    fn observed_cpo_for_selection_stays_none_until_complete() -> Result<()> {
        assert_eq!(observed_cost_per_accepted_task_microunits(None), None);
        let incomplete =
            rollup_cost_per_accepted_task(&[grok_verified_environment_unknown_accepted()])?;
        assert_eq!(
            observed_cost_per_accepted_task_microunits(Some(&incomplete)),
            None
        );
        let complete = rollup_cost_per_accepted_task(&[fake_simulation_complete_accepted()])?;
        assert_eq!(
            observed_cost_per_accepted_task_microunits(Some(&complete)),
            Some(12)
        );
        Ok(())
    }
}
