//! Cost-per-accepted-task rollup over parent attempt cost evidence.
//!
//! Attempts with any missing attributable bucket — including `environment_cost_microunits:
//! None` on verified external launches — retain partial evidence but prevent numeric CPO.
//! Unknown terminal results remain explicit; neither cost nor acceptance is invented.
//!
//! The supervisor final-report path records this rollup on
//! `role_economics_profile.execution.accepted_task_cost`.

use super::outcome_history::AttemptAttributableCosts;
use crate::selection::OutcomeResult;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::supervise) struct AttemptCostRecord {
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
    pub cost_per_accepted_task_microunits: Option<u64>,
}

pub(in crate::supervise) fn attempt_cost_record(
    costs: AttemptAttributableCosts,
    result: Option<OutcomeResult>,
) -> AttemptCostRecord {
    AttemptCostRecord { result, costs }
}

fn is_zero_count(count: &u32) -> bool {
    *count == 0
}

pub(in crate::supervise) fn rollup_cost_per_accepted_task(
    records: &[AttemptCostRecord],
) -> Result<AcceptedTaskCostRollup> {
    let mut incomplete_attempt_count = 0u32;
    let mut unknown_terminal_result_count = 0u32;
    let mut complete_attempt_count = 0u32;
    let mut complete_accepted_count = 0u32;
    let mut complete_total_cycle_cost_microunits = 0u64;

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

    fn fake_simulation_complete_accepted() -> AttemptCostRecord {
        AttemptCostRecord {
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
        let unknown = attempt_cost_record(costs.clone(), None);
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
        let accepted = attempt_cost_record(costs, Some(OutcomeResult::Accepted));
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
