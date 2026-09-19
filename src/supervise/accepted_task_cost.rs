//! Cost-per-accepted-task rollup over parent attempt cost evidence.
//!
//! Attempts with any missing attributable bucket — including `environment_cost_microunits:
//! None` on verified external launches — are incomplete and excluded from numeric rollup.
//! Unknown terminal results are omitted from the average; they are not invented.
//!
//! The supervisor final-report path records this rollup on
//! `role_economics_profile.execution.accepted_task_cost`.

use super::outcome_history::AttemptAttributableCosts;
use crate::selection::OutcomeResult;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::supervise) struct AttemptCostRecord {
    pub result: OutcomeResult,
    pub costs: AttemptAttributableCosts,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedTaskCostRollup {
    pub incomplete_attempt_count: u32,
    pub complete_attempt_count: u32,
    pub complete_accepted_count: u32,
    pub complete_total_cycle_cost_microunits: u64,
    pub cost_per_accepted_task_microunits: Option<u64>,
}

pub(in crate::supervise) fn attempt_cost_record(
    costs: AttemptAttributableCosts,
    result: Option<OutcomeResult>,
) -> Option<AttemptCostRecord> {
    Some(AttemptCostRecord {
        result: result?,
        costs,
    })
}

pub(in crate::supervise) fn rollup_cost_per_accepted_task(
    records: &[AttemptCostRecord],
) -> Result<AcceptedTaskCostRollup> {
    let mut incomplete_attempt_count = 0u32;
    let mut complete_attempt_count = 0u32;
    let mut complete_accepted_count = 0u32;
    let mut complete_total_cycle_cost_microunits = 0u64;

    for record in records {
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
        if record.result == OutcomeResult::Accepted {
            complete_accepted_count = complete_accepted_count
                .checked_add(1)
                .context("complete accepted count overflowed")?;
        }
    }

    let cost_per_accepted_task_microunits = if complete_accepted_count == 0 {
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
        complete_attempt_count,
        complete_accepted_count,
        complete_total_cycle_cost_microunits,
        cost_per_accepted_task_microunits,
    })
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
            result: OutcomeResult::Accepted,
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
            result: OutcomeResult::Accepted,
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
    fn rollup_ignores_incomplete_environment_bucket_and_counts_it() -> Result<()> {
        let rollup = rollup_cost_per_accepted_task(&[
            fake_simulation_complete_accepted(),
            grok_verified_environment_unknown_accepted(),
        ])?;

        assert_eq!(rollup.incomplete_attempt_count, 1);
        assert_eq!(rollup.complete_attempt_count, 1);
        assert_eq!(rollup.complete_accepted_count, 1);
        assert_eq!(rollup.complete_total_cycle_cost_microunits, 12);
        assert_eq!(rollup.cost_per_accepted_task_microunits, Some(12));
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
    fn unknown_terminal_result_is_omitted_not_invented() {
        let costs = AttemptAttributableCosts {
            execution_cost_microunits: Some(10),
            review_cost_microunits: Some(2),
            rework_cost_microunits: Some(0),
            rereview_cost_microunits: Some(0),
            environment_cost_microunits: Some(0),
        };
        assert_eq!(attempt_cost_record(costs.clone(), None), None);
        let accepted = attempt_cost_record(costs, Some(OutcomeResult::Accepted))
            .expect("known accepted result maps");
        assert_eq!(accepted.result, OutcomeResult::Accepted);
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
}
