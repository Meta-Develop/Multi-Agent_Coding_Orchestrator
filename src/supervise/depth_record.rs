//! Third slice of #830: every emitted supervisor plan carries a shadow depth
//! decision computed from the plan shape.
//!
//! Shadow means the decision is recorded for calibration but does not change
//! the plan shape, the schedule or execution; applying it is a later #830
//! slice. The work-token estimate is a per-work-unit prior, recorded in the
//! output.

use super::*;
use crate::optimizer::depth_decision::{
    decide_depth, DepthCostModel, DepthDecisionInput, DepthDecisionRecord, ABSOLUTE_DEPTH_CAP,
};
use crate::optimizer::EvaluationFunction;
use std::collections::HashSet;

/// Prior tokens of executable work assumed per work unit.
pub(super) const PLAN_DEPTH_TOKENS_PER_WORK_UNIT: u64 = 200_000;

/// Shadow coordination-depth decision recorded in every emitted supervisor plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanDepthDecision {
    /// Always `shadow`: the decision does not change the plan.
    pub mode: String,
    /// Always `plan_shape_prior`: the inputs come from the plan shape.
    pub input_source: String,
    /// The per-work-unit token prior used for the estimate.
    pub tokens_per_work_unit: u64,
    /// The coordination depth derived from the plan topology.
    pub plan_coordination_depth: u32,
    /// The full depth decision record.
    pub record: DepthDecisionRecord,
}

/// Compute the shadow depth decision for one supervisor plan.
///
/// Reads only its arguments: no clock, environment or file access.
pub(super) fn plan_depth_decision(
    plan: &SupervisorPlan,
    schedule: &[AssignmentScheduleEntry],
) -> Result<PlanDepthDecision> {
    let parent_ids: HashSet<&str> = schedule
        .iter()
        .filter_map(|entry| entry.parent_assignment_id.as_deref())
        .collect();
    let work_units_total: u64 = plan
        .assignments
        .iter()
        .filter(|assignment| assignment.phase == AssignmentPhase::Execution)
        .map(|assignment| {
            if !assignment.worker_assignments.is_empty() {
                assignment.worker_assignments.len() as u64
            } else if parent_ids.contains(assignment.id.as_str()) {
                0
            } else {
                1
            }
        })
        .sum();
    let work_units = u32::try_from(work_units_total.max(1)).unwrap_or(u32::MAX);
    let estimated_work_tokens = (work_units as u64).saturating_mul(PLAN_DEPTH_TOKENS_PER_WORK_UNIT);
    let max_child_assignments = u32::try_from(plan.max_child_assignments)
        .unwrap_or(u32::MAX)
        .max(1);
    let depth_ceiling = plan.max_depth.clamp(1, ABSOLUTE_DEPTH_CAP);
    let input = DepthDecisionInput {
        work_units,
        estimated_work_tokens,
        max_child_assignments,
        depth_ceiling,
    };
    let record = decide_depth(
        &input,
        &DepthCostModel::uncalibrated_prior(),
        &EvaluationFunction::shipped_default(),
    )
    .context("failed to decide coordination depth")?;
    Ok(PlanDepthDecision {
        mode: "shadow".to_string(),
        input_source: "plan_shape_prior".to_string(),
        tokens_per_work_unit: PLAN_DEPTH_TOKENS_PER_WORK_UNIT,
        plan_coordination_depth: coordination_topology_from_plan(plan, schedule)
            .derived_coordination_depth,
        record,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::depth_decision::DepthDecision;

    #[test]
    fn single_assignment_plan_records_depth_one() {
        let document = r#"{
            "version": 1,
            "task": "one unit",
            "max_depth": 2,
            "max_child_assignments": 4,
            "assignments": [
                {"id": "only", "phase": "execution", "assigned_paths": ["src/only.rs"]}
            ]
        }"#;
        let loaded = parse_supervisor_plan_with_consultant(document).expect("single plan");
        let decision = plan_depth_decision(&loaded.plan, &loaded.plan_metadata.assignment_schedule)
            .expect("depth decision");
        assert_eq!(
            decision.record.input,
            DepthDecisionInput {
                work_units: 1,
                estimated_work_tokens: 200_000,
                max_child_assignments: 4,
                depth_ceiling: 2,
            }
        );
        assert_eq!(
            decision.record.decision,
            DepthDecision::Selected {
                depth: 1,
                workers: 1,
                coordinators: 0,
                cost_tokens: 260_000,
            }
        );
        assert_eq!(decision.mode, "shadow");
        assert_eq!(decision.input_source, "plan_shape_prior");
        assert_eq!(decision.tokens_per_work_unit, 200_000);
        assert_eq!(
            decision.plan_coordination_depth,
            coordination_topology_from_plan(
                &loaded.plan,
                &loaded.plan_metadata.assignment_schedule
            )
            .derived_coordination_depth
        );
    }

    #[test]
    fn three_units_record_depth_two() {
        let document = r#"{
            "version": 1,
            "task": "three units",
            "max_depth": 3,
            "max_child_assignments": 4,
            "assignments": [
                {"id": "a", "phase": "execution", "assigned_paths": ["src/a.rs"]},
                {"id": "b", "phase": "execution", "assigned_paths": ["src/b.rs"]},
                {"id": "c", "phase": "execution", "assigned_paths": ["src/c.rs"]}
            ]
        }"#;
        let loaded = parse_supervisor_plan_with_consultant(document).expect("three-unit plan");
        let decision = plan_depth_decision(&loaded.plan, &loaded.plan_metadata.assignment_schedule)
            .expect("depth decision");
        assert_eq!(
            decision.record.input,
            DepthDecisionInput {
                work_units: 3,
                estimated_work_tokens: 600_000,
                max_child_assignments: 4,
                depth_ceiling: 3,
            }
        );
        assert_eq!(decision.record.candidates.len(), 3);
        assert_eq!(
            decision.record.decision,
            DepthDecision::Selected {
                depth: 2,
                workers: 2,
                coordinators: 1,
                cost_tokens: 920_000,
            }
        );
        assert!(decision
            .record
            .reasons
            .first()
            .is_some_and(|reason| reason.starts_with("depth 1: rejected (")));
    }

    #[test]
    fn nested_plan_counts_only_execution_work_units() {
        let document = r#"{
            "version": 1,
            "task": "three-layer topology",
            "max_depth": 4,
            "max_child_assignments": 3,
            "assignments": [{
                "id": "layer-0",
                "phase": "planning",
                "role": "child_orchestrator",
                "assigned_paths": ["README.md"],
                "worker_assignments": [],
                "child_assignments": [{
                    "id": "layer-1",
                    "phase": "execution",
                    "role": "child_orchestrator",
                    "assigned_paths": ["README.md"],
                    "worker_assignments": [],
                    "child_assignments": [{
                        "id": "layer-2",
                        "phase": "execution",
                        "role": "child_orchestrator",
                        "assigned_paths": ["src/lib.rs"],
                        "worker_assignments": []
                    }]
                }]
            }]
        }"#;
        let loaded = parse_supervisor_plan_with_consultant(document).expect("nested plan");
        let decision = plan_depth_decision(&loaded.plan, &loaded.plan_metadata.assignment_schedule)
            .expect("depth decision");
        assert_eq!(
            decision.record.input,
            DepthDecisionInput {
                work_units: 1,
                estimated_work_tokens: 200_000,
                max_child_assignments: 3,
                depth_ceiling: 4,
            }
        );
        assert_eq!(
            decision.record.decision,
            DepthDecision::Selected {
                depth: 1,
                workers: 1,
                coordinators: 0,
                cost_tokens: 260_000,
            }
        );
        assert_eq!(decision.plan_coordination_depth, 3);
    }

    #[test]
    fn worker_assignments_count_as_work_units() {
        let document = r#"{
            "version": 1,
            "task": "three workers",
            "max_depth": 2,
            "max_child_assignments": 4,
            "assignments": [{
                "id": "parent",
                "phase": "execution",
                "assigned_paths": ["src/a"],
                "worker_assignments": [
                    {"id": "worker-one", "assigned_paths": ["src/a/one.rs"]},
                    {"id": "worker-two", "assigned_paths": ["src/a/two.rs"]},
                    {"id": "worker-three", "assigned_paths": ["src/a/three.rs"]}
                ]
            }]
        }"#;
        let loaded = parse_supervisor_plan_with_consultant(document).expect("worker plan");
        let decision = plan_depth_decision(&loaded.plan, &loaded.plan_metadata.assignment_schedule)
            .expect("depth decision");
        assert_eq!(decision.record.input.work_units, 3);
        assert_eq!(decision.record.input.depth_ceiling, 2);
        assert_eq!(
            decision.record.decision,
            DepthDecision::Selected {
                depth: 2,
                workers: 2,
                coordinators: 1,
                cost_tokens: 920_000,
            }
        );
    }

    #[test]
    fn supervisor_plan_value_emits_the_depth_decision() {
        let document = r#"{
            "version": 1,
            "task": "three units",
            "max_depth": 3,
            "max_child_assignments": 4,
            "assignments": [
                {"id": "a", "phase": "execution", "assigned_paths": ["src/a.rs"]},
                {"id": "b", "phase": "execution", "assigned_paths": ["src/b.rs"]},
                {"id": "c", "phase": "execution", "assigned_paths": ["src/c.rs"]}
            ]
        }"#;
        let loaded = parse_supervisor_plan_with_consultant(document).expect("three-unit plan");
        let emitted = supervisor_plan_value(
            &loaded.plan,
            &loaded.consultant,
            &loaded.assignment_metadata,
            &loaded.plan_metadata,
        )
        .expect("emit plan");
        assert_eq!(emitted["depth_decision"]["mode"], "shadow");
        assert_eq!(
            emitted["depth_decision"]["record"]["schema"],
            "maco.depth_decision.v1"
        );
        assert_eq!(
            emitted["depth_decision"]["record"]["decision"]["kind"],
            "selected"
        );
        assert_eq!(emitted["depth_decision"]["record"]["decision"]["depth"], 2);
        assert!(emitted["coordination_topology"].is_object());
        let expected = serde_json::to_value(
            plan_depth_decision(&loaded.plan, &loaded.plan_metadata.assignment_schedule)
                .expect("depth decision"),
        )
        .expect("serialize depth decision");
        assert_eq!(emitted["depth_decision"], expected);
        let emitted_again = supervisor_plan_value(
            &loaded.plan,
            &loaded.consultant,
            &loaded.assignment_metadata,
            &loaded.plan_metadata,
        )
        .expect("emit plan again");
        assert_eq!(emitted, emitted_again);
    }
}
