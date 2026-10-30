//! Parent-validated assignment declarations. These describe fitness, never permissions.

use super::*;
use crate::selection::{
    AssignmentShapeIdentity, AuthorityRole, Boundedness, RiskLevel, TaskProfile,
};
use serde::{Deserialize, Deserializer, Serialize};

/// Declared effect ceiling, including effects beyond repository edits. Declaring
/// an effect does not authorize it; existing admission and publication gates apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssignmentEffects {
    ReadOnly,
    RepositoryWrite,
    ExternalSideEffects,
    Publication,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssignmentDelegation {
    Terminal,
    Delegating,
}

/// Optional versioned input from the parent. Deserialization alone does not
/// establish fitness: validate against the current normalized assignment first.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssignmentShapeDeclaration {
    version: u32,
    policy_sha256: String,
    assignment_input_sha256: String,
    profile: TaskProfile,
    effects: AssignmentEffects,
    delegation: AssignmentDelegation,
}

/// Constructible only by validating the declaration and its exact bound inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAssignmentShape {
    profile: TaskProfile,
    identity: AssignmentShapeIdentity,
}

impl ValidatedAssignmentShape {
    pub fn profile(&self) -> &TaskProfile {
        &self.profile
    }

    pub fn identity(&self) -> &AssignmentShapeIdentity {
        &self.identity
    }
}

impl AssignmentShapeDeclaration {
    /// Assess one normalized recursive assignment using only declared inputs and
    /// the frozen policy. Scores/context remain heuristics, not observations.
    pub fn assess(
        plan: &SupervisorPlan,
        index: usize,
        schedule: &[AssignmentScheduleEntry],
        frozen: &crate::selection::routing_policy::FrozenRoutingPolicy,
        effects: AssignmentEffects,
    ) -> Result<Self> {
        let (assignment_input_sha256, profile, delegation) =
            assignment_shape_inputs(plan, index, schedule, frozen, effects)?;
        Ok(Self {
            version: 1,
            policy_sha256: frozen.sha256.clone(),
            assignment_input_sha256,
            profile,
            effects,
            delegation,
        })
    }

    /// Reject replay drift and dimensions below policy-derived minimums. A
    /// parent may conservatively raise a dimension, including to Unknown.
    pub fn validate(
        &self,
        plan: &SupervisorPlan,
        index: usize,
        schedule: &[AssignmentScheduleEntry],
        frozen: &crate::selection::routing_policy::FrozenRoutingPolicy,
    ) -> Result<ValidatedAssignmentShape> {
        if self.version != 1 || self.policy_sha256 != frozen.sha256 {
            bail!("assignment shape version or frozen policy differs");
        }
        let (digest, minimum, delegation) =
            assignment_shape_inputs(plan, index, schedule, frozen, self.effects)?;
        if self.assignment_input_sha256 != digest || self.delegation != delegation {
            bail!("assignment shape task, scope, effects or delegation binding differs");
        }
        if self.profile.task_class != minimum.task_class
            || self.profile.authority_role != minimum.authority_role
            || self.profile.risk < minimum.risk
            || self.profile.boundedness < minimum.boundedness
            || self.profile.context < minimum.context
            || self.profile.horizon < minimum.horizon
        {
            bail!("assignment shape changes intrinsic authority or understates policy minimums");
        }
        let identity = AssignmentShapeIdentity::v1(crate::artifacts::state_auth::sha256_hex(
            &serde_json::to_vec(self)?,
        ))
        .map_err(anyhow::Error::msg)?;
        Ok(ValidatedAssignmentShape {
            profile: self.profile.clone(),
            identity,
        })
    }
}

pub(super) fn deserialize_shape<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<AssignmentShapeDeclaration>, D::Error>
where
    D: Deserializer<'de>,
{
    AssignmentShapeDeclaration::deserialize(deserializer).map(Some)
}

pub(super) fn validate_assignment_shapes(
    plan: &SupervisorPlan,
    metadata: &SupervisorPlanMetadata,
) -> Result<()> {
    for (index, assignment) in plan.assignments.iter().enumerate() {
        let Some(declaration) = &assignment.assignment_shape else {
            // Legacy omission is unproven; never synthesize a declaration from a role.
            continue;
        };
        declaration
            .validate(
                plan,
                index,
                &metadata.assignment_schedule,
                metadata
                    .resolved_routing_policy
                    .as_ref()
                    .context("assignment shape requires its frozen routing policy")?,
            )
            .with_context(|| format!("assignment '{}' has an invalid shape", assignment.id))?;
    }
    Ok(())
}

fn assignment_shape_inputs(
    plan: &SupervisorPlan,
    index: usize,
    schedule: &[AssignmentScheduleEntry],
    frozen: &crate::selection::routing_policy::FrozenRoutingPolicy,
    effects: AssignmentEffects,
) -> Result<(String, TaskProfile, AssignmentDelegation)> {
    let assignment = plan
        .assignments
        .get(index)
        .context("assignment shape index is outside the current plan")?;
    if schedule.len() != plan.assignments.len()
        || schedule
            .iter()
            .zip(&plan.assignments)
            .enumerate()
            .any(|(position, (entry, current))| {
                entry.assignment_id != current.id || entry.flattened_index != position
            })
    {
        bail!("assignment shape requires the complete normalized assignment schedule");
    }
    let children = schedule
        .iter()
        .filter(|entry| entry.parent_assignment_id.as_deref() == Some(assignment.id.as_str()))
        .collect::<Vec<_>>();
    if assignment.role != AgentRole::ChildOrchestrator
        && (!children.is_empty() || !assignment.worker_assignments.is_empty())
    {
        bail!("terminal assignment shape cannot hide delegated assignments");
    }
    let delegation = if assignment.role == AgentRole::ChildOrchestrator
        || assignment.effective_role_category() == RoleCategory::DelegatingCoordinator
    {
        AssignmentDelegation::Delegating
    } else {
        AssignmentDelegation::Terminal
    };
    let writable =
        assignment.phase == AssignmentPhase::Execution && assignment.role != AgentRole::Researcher;
    if writable && effects == AssignmentEffects::ReadOnly {
        bail!("assignment shape cannot understate repository write effects");
    }
    let mut bound_assignment = assignment.clone();
    bound_assignment.assignment_shape = None;
    bound_assignment.bind_role_category();
    // Serialize repository paths in the same portable form as estimator scope.
    // PathBuf retains the supplied '/' spelling until serialization on every host.
    canonicalize_shape_paths(&mut bound_assignment.assigned_paths)?;
    for worker in &mut bound_assignment.worker_assignments {
        canonicalize_shape_paths(&mut worker.assigned_paths)?;
        if let Some(path) = &mut worker.report_path {
            *path = canonical_shape_path(path)?;
        }
    }
    if let Some(declaration) = &mut bound_assignment.licensed_breakage {
        for dependent in &mut declaration.dependents {
            canonicalize_shape_paths(&mut dependent.paths)?;
        }
    }
    let mut bound_value = serde_json::to_value(&bound_assignment)?;
    // Routing choices are candidate identity, not assignment shape. Automatic
    // selection can replace these without changing the declared work.
    let fields = bound_value.as_object_mut().context("assignment object")?;
    fields.remove("runtime");
    fields.remove("selection_source");
    if let Some(workers) = fields
        .get_mut("worker_assignments")
        .and_then(Value::as_array_mut)
    {
        for worker in workers {
            let fields = worker.as_object_mut().context("worker object")?;
            // Manual designations affect authority even when the category itself
            // equals its derived value. Retain them in the assignment binding.
            let source = fields.get("selection_source").and_then(Value::as_str);
            if source != Some("operator_override") {
                fields.remove("selection_source");
            }
        }
    }
    let task = assignment.task.as_deref().unwrap_or(&plan.task);
    let bound_input = serde_json::to_vec(&json!({
        "task": task,
        "assignment": bound_value,
        "schedule": schedule[index],
        "children": children,
        "effects": effects,
        "delegation": delegation,
    }))?;
    let estimator = super::task_routing::effective_estimator(frozen)?;
    if bound_input.len() as u64 > estimator.max_declaration_bytes {
        bail!("assignment shape declaration exceeds the frozen policy input bound");
    }
    // Count all declared scopes, including nested terminal work, without claiming
    // that directory names measure context or that heuristic scores prove safety.
    let mut paths = bound_assignment.assigned_paths.clone();
    let mut modules = assignment.semantic_modules.clone();
    let mut symbols = assignment.semantic_symbols.clone();
    let mut text = task.to_string();
    if let Some(notes) = &assignment.notes {
        text.push('\n');
        text.push_str(notes);
    }
    for worker in &bound_assignment.worker_assignments {
        paths.extend(worker.assigned_paths.iter().cloned());
        modules.extend(worker.semantic_modules.iter().cloned());
        symbols.extend(worker.semantic_symbols.iter().cloned());
        if let Some(task) = &worker.task {
            text.push('\n');
            text.push_str(task);
        }
    }
    paths.sort();
    paths.dedup();
    modules.sort();
    modules.dedup();
    symbols.sort();
    symbols.dedup();
    let proposal = planning::TaskDecompositionProposal {
        fragments: vec![planning::TaskSpecFragment {
            id: assignment.id.clone(),
            // Include the complete bound declaration in the context estimate,
            // including environment and authority metadata outside task prose.
            text: String::from_utf8(bound_input.clone())?,
        }],
        assignments: vec![planning::TaskAssignmentProposal {
            id: assignment.id.clone(),
            task: text.clone(),
            fragment_ids: vec![assignment.id.clone()],
            assigned_paths: paths,
            semantic_symbols: symbols,
            semantic_modules: modules,
            decision_dependencies: assignment
                .decision_refs
                .iter()
                .map(|reference| reference.question_key().to_string())
                .collect(),
        }],
        coverage_gaps: Vec::new(),
        diagnostics: planning::TaskPathProposalDiagnostics::default(),
        disjointness: planning::TaskDisjointnessReport::default(),
    };
    let assessment = super::task_routing::assess_task_routing(&text, &proposal, frozen)?;
    let base = super::selection_bridge::task_profile_for_role(assignment.role);
    let mut profile = super::task_routing::project_task_profile_with_final_features(
        &base,
        &assessment,
        &assessment.features,
        frozen,
    )?;
    if assignment.category_is_operator_override() {
        profile.authority_role = AuthorityRole::UnknownJudgment;
    }
    if effects >= AssignmentEffects::ExternalSideEffects || assignment.licensed_breakage.is_some() {
        profile.risk = profile.risk.max(RiskLevel::High);
        profile.boundedness = profile.boundedness.max(Boundedness::CrossCutting);
    }
    if effects == AssignmentEffects::Publication {
        profile.risk = profile.risk.max(RiskLevel::Critical);
    }
    Ok((
        crate::artifacts::state_auth::sha256_hex(&bound_input),
        profile,
        delegation,
    ))
}

fn canonical_shape_path(path: &Path) -> Result<PathBuf> {
    super::task_routing::canonical_estimation_scope(path).map(PathBuf::from)
}

fn canonicalize_shape_paths(paths: &mut [PathBuf]) -> Result<()> {
    for path in paths {
        *path = canonical_shape_path(path)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "assignment_shape_tests.rs"]
mod tests;
