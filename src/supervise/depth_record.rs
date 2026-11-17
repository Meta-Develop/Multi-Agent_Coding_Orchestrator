//! Third slice of #830: every emitted supervisor plan carries a coordination
//! depth decision computed from the plan shape.
//!
//! Two modes are recorded. `shadow` means the decision is recorded for
//! calibration only and does not change the plan shape, the schedule or
//! execution. `applied` means the decision was computed under the operator's
//! per-coordinator Worker bound, which goal/spec coordinated lowering applies
//! to the emitted plan. Other plan shapes record the same decision for
//! calibration. The work-token estimate is a per-work-unit prior, recorded in
//! the output.

use super::*;
use crate::optimizer::depth_decision::{
    decide_depth, DepthCostModel, DepthDecisionInput, DepthDecisionRecord, ABSOLUTE_DEPTH_CAP,
};
use crate::optimizer::EvaluationFunction;
use std::collections::HashSet;

/// Prior tokens of executable work assumed per work unit.
pub(super) const PLAN_DEPTH_TOKENS_PER_WORK_UNIT: u64 = 200_000;

/// Coordination-depth decision recorded in every emitted supervisor plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanDepthDecision {
    /// `shadow` when the decision is calibration-only, or `applied` when it
    /// was computed under the operator's per-coordinator Worker bound and
    /// goal/spec coordinated lowering applies it.
    pub mode: String,
    /// `plan_shape_prior` for the shadow prior, or
    /// `plan_shape_worker_capacity_prior` when one work unit fills one
    /// Worker's capacity under the operator's bound.
    pub input_source: String,
    /// The per-work-unit token prior used for the estimate.
    pub tokens_per_work_unit: u64,
    /// The coordination depth derived from the plan topology.
    pub plan_coordination_depth: u32,
    /// The full depth decision record.
    pub record: DepthDecisionRecord,
}

/// Compute the depth decision for one supervisor plan.
///
/// Reads only its arguments: no clock, environment or file access. With
/// `None` the decision is the shadow calibration record. With `Some(p)` the
/// decision was computed under the operator's per-coordinator Worker bound,
/// which goal/spec coordinated lowering applies.
pub(super) fn plan_depth_decision(
    plan: &SupervisorPlan,
    schedule: &[AssignmentScheduleEntry],
    max_workers_per_coordinator: Option<usize>,
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
    let (mode, input_source, tokens_per_work_unit, max_child_assignments) =
        match max_workers_per_coordinator {
            None => (
                "shadow",
                "plan_shape_prior",
                PLAN_DEPTH_TOKENS_PER_WORK_UNIT,
                u32::try_from(plan.max_child_assignments)
                    .unwrap_or(u32::MAX)
                    .max(1),
            ),
            // One workstream fills one Worker's capacity under the bound.
            Some(p) => (
                "applied",
                "plan_shape_worker_capacity_prior",
                DepthCostModel::uncalibrated_prior().worker_capacity_tokens,
                u32::try_from(p).unwrap_or(u32::MAX).max(1),
            ),
        };
    let estimated_work_tokens = (work_units as u64).saturating_mul(tokens_per_work_unit);
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
        mode: mode.to_string(),
        input_source: input_source.to_string(),
        tokens_per_work_unit,
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
        let decision = plan_depth_decision(
            &loaded.plan,
            &loaded.plan_metadata.assignment_schedule,
            None,
        )
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
        let decision = plan_depth_decision(
            &loaded.plan,
            &loaded.plan_metadata.assignment_schedule,
            None,
        )
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
        let decision = plan_depth_decision(
            &loaded.plan,
            &loaded.plan_metadata.assignment_schedule,
            None,
        )
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
        let decision = plan_depth_decision(
            &loaded.plan,
            &loaded.plan_metadata.assignment_schedule,
            None,
        )
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
    fn per_coordinator_bound_applies_worker_capacity_prior() {
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
        let decision = plan_depth_decision(
            &loaded.plan,
            &loaded.plan_metadata.assignment_schedule,
            Some(2),
        )
        .expect("depth decision");
        assert_eq!(
            decision.record.input,
            DepthDecisionInput {
                work_units: 3,
                estimated_work_tokens: 1_200_000,
                max_child_assignments: 2,
                depth_ceiling: 3,
            }
        );
        assert_eq!(decision.mode, "applied");
        assert_eq!(decision.input_source, "plan_shape_worker_capacity_prior");
        assert_eq!(decision.tokens_per_work_unit, 400_000);
        assert_eq!(
            decision.record.decision,
            DepthDecision::Selected {
                depth: 3,
                workers: 3,
                coordinators: 3,
                cost_tokens: 1_980_000,
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
            plan_depth_decision(
                &loaded.plan,
                &loaded.plan_metadata.assignment_schedule,
                None,
            )
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
