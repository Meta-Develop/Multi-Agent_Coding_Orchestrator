//! Assignment fitness retained across initial dispatch, retries and history projection.

use super::*;
use crate::selection::AssignmentShapeIdentity;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(in crate::supervise) struct AssignmentSelectionShapes {
    entries: BTreeMap<String, (AgentRole, Option<ValidatedAssignmentShape>)>,
    nested_worker_parents: BTreeSet<String>,
    schedule: Vec<AssignmentScheduleEntry>,
}

impl AssignmentSelectionShapes {
    pub(in crate::supervise) fn validate(
        plan: &SupervisorPlan,
        schedule: &[AssignmentScheduleEntry],
        frozen: Option<&crate::selection::routing_policy::FrozenRoutingPolicy>,
    ) -> Result<Self> {
        // Legacy plans retain their assessed fallback and never gain an exact
        // assignment identity. Unassessed legacy input remains Unknown.
        if plan
            .assignments
            .iter()
            .all(|assignment| assignment.assignment_shape.is_none())
        {
            return Ok(Self::default());
        }
        let mut entries = BTreeMap::new();
        let mut nested_worker_parents = BTreeSet::new();
        for (index, assignment) in plan.assignments.iter().enumerate() {
            let shape = assignment
                .assignment_shape
                .as_ref()
                .map(|declaration| {
                    declaration.validate(
                        plan,
                        index,
                        schedule,
                        frozen.context("assignment shape requires its frozen routing policy")?,
                    )
                })
                .transpose()?;
            if entries
                .insert(assignment.id.clone(), (assignment.role, shape))
                .is_some()
            {
                bail!("assignment shape repeats an assignment identity");
            }
            if assignment.role == AgentRole::ChildOrchestrator
                && assignment
                    .worker_assignments
                    .iter()
                    .any(|worker| worker.role == AgentRole::Worker)
            {
                nested_worker_parents.insert(assignment.id.clone());
            }
        }
        Ok(Self {
            entries,
            nested_worker_parents,
            schedule: schedule.to_vec(),
        })
    }

    fn projected_shape(
        &self,
        assignment_id: &str,
        role: AgentRole,
    ) -> Option<(TaskProfile, &AssignmentShapeIdentity)> {
        let (assignment_role, shape) = self.entries.get(assignment_id)?;
        let shape = shape.as_ref()?;
        let profile = if *assignment_role == role {
            shape.profile().clone()
        } else if role == AgentRole::Worker && self.nested_worker_parents.contains(assignment_id) {
            // Nested work keeps terminal authority and its intrinsic minimums.
            // The enclosing declaration binds all nested inputs and raises bounds.
            let mut profile = task_profile_for_role(role);
            profile.risk = profile.risk.max(shape.profile().risk);
            profile.boundedness = profile.boundedness.max(shape.profile().boundedness);
            profile.context = profile.context.max(shape.profile().context);
            profile.horizon = profile.horizon.max(shape.profile().horizon);
            profile
        } else {
            return None;
        };
        Some((profile, shape.identity()))
    }

    // Preflight must cover every reachable assignment of a role. It does not
    // stamp an exact identity onto a role-wide decision.
    pub(in crate::supervise) fn role_profile(
        &self,
        plan: &SupervisorPlan,
        role: AgentRole,
    ) -> Result<Option<TaskProfile>> {
        if matches!(
            role,
            AgentRole::Supervisor | AgentRole::GateClassifier | AgentRole::Auditor
        ) && self.entries.values().any(|(_, shape)| shape.is_some())
        {
            return Ok(Some(task_profile_for_role(role)));
        }
        let mut combined: Option<TaskProfile> = None;
        for assignment in &plan.assignments {
            let Some((profile, _)) = self.projected_shape(&assignment.id, role) else {
                continue;
            };
            if let Some(combined) = combined.as_mut() {
                if combined.authority_role != profile.authority_role {
                    combined.authority_role = AuthorityRole::UnknownJudgment;
                }
                combined.risk = combined.risk.max(profile.risk);
                combined.boundedness = combined.boundedness.max(profile.boundedness);
                combined.context = combined.context.max(profile.context);
                combined.horizon = combined.horizon.max(profile.horizon);
            } else {
                combined = Some(profile);
            }
        }
        Ok(combined)
    }

    pub(in crate::supervise) fn bind_input(
        &self,
        assignment_id: &str,
        role: AgentRole,
        input: &mut SelectionInput,
    ) -> Result<()> {
        input.assignment_shape_identity = None;
        if self.entries.is_empty() {
            return Ok(());
        }
        if let Some((profile, identity)) = self.projected_shape(assignment_id, role) {
            input.task = profile;
            input.assignment_shape_identity = Some(identity.clone());
            return Ok(());
        }
        if let Some((assignment_role, _)) = self.entries.get(assignment_id) {
            if *assignment_role == role {
                input.task = task_profile_with_assessment(role, None, None, None)?;
                return Ok(());
            }
        }
        // Other roles have no declaration for this target.
        // They must not inherit a different assignment's shape or learned rows.
        input.task = if matches!(
            role,
            AgentRole::Supervisor | AgentRole::GateClassifier | AgentRole::Auditor
        ) {
            task_profile_for_role(role)
        } else {
            task_profile_with_assessment(role, None, None, None)?
        };
        Ok(())
    }

    pub(in crate::supervise) fn validate_current_assignment(
        &self,
        plan: &SupervisorPlan,
        assignment: &OrchestratorAssignment,
        frozen: Option<&crate::selection::routing_policy::FrozenRoutingPolicy>,
    ) -> Result<()> {
        if self.entries.is_empty() {
            return Ok(());
        }
        let (role, shape) = self
            .entries
            .get(&assignment.id)
            .context("dispatch has an unknown assignment shape")?;
        let index = plan
            .assignments
            .iter()
            .position(|entry| entry.id == assignment.id)
            .context("dispatch assignment is absent from the current plan")?;
        if *role != assignment.role || plan.assignments[index] != *assignment {
            bail!("dispatch assignment differs from the current plan");
        }
        match (&assignment.assignment_shape, shape) {
            (Some(declaration), Some(expected)) => {
                let current = declaration.validate(
                    plan,
                    index,
                    &self.schedule,
                    frozen.context("dispatch assignment shape has no frozen policy")?,
                )?;
                if &current != expected {
                    bail!("dispatch assignment shape differs from selection state");
                }
            }
            (None, None) => {}
            _ => bail!("dispatch assignment shape declaration changed"),
        }
        Ok(())
    }

    pub(in crate::supervise) fn validate_event(
        &self,
        assignment_id: &str,
        event: &SupervisorSelectionEvent,
    ) -> Result<()> {
        if !self.entries.is_empty() && !self.entries.contains_key(assignment_id) {
            bail!("completed selection has an unknown assignment identity");
        }
        let input = &event.provenance.normalized_input;
        let expected = self.projected_shape(assignment_id, event.role);
        let Some(identity) = input.assignment_shape_identity.as_ref() else {
            if expected.is_some() {
                bail!("completed selection omitted its validated assignment shape");
            }
            return Ok(());
        };
        let (profile, expected_identity) =
            expected.context("completed selection has an undeclared assignment shape")?;
        if expected_identity != identity
            || profile != input.task
            || event.provenance.normalized_task != input.task
        {
            bail!("completed selection differs from its validated assignment shape");
        }
        Ok(())
    }
}
