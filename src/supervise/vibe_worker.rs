//! Vibe admission contract for managed assignments.
//!
//! Vibe is admitted for exactly one shape: a direct execution-phase Worker with
//! the non-delegating terminal Worker category and no nested worker
//! assignments. Every other phase, role, category, or delegating shape is
//! refused here, before any launch is bound. The predicate is pure so the plan
//! validator, the launch binder, and the workspace binder all consult the same
//! rule, including when the effective runtime comes from the selector rather
//! than from `assignment.runtime`.

use anyhow::{bail, Result};

use super::{AssignmentPhase, OrchestratorAssignment, RoleCategory, SupervisorRuntime};

/// Refuse every Vibe assignment that is not a direct execution-phase
/// non-delegating terminal Worker.
///
/// Non-Vibe runtimes are a no-op: their admission stays with the runtime that
/// owns them. A `None` runtime is also a no-op, because the Codex default is
/// applied later by the caller.
pub(super) fn validate_assignment(
    assignment: &OrchestratorAssignment,
    runtime: SupervisorRuntime,
) -> Result<()> {
    if runtime != SupervisorRuntime::Vibe {
        return Ok(());
    }
    let direct_execution_worker = assignment.phase == AssignmentPhase::Execution
        && assignment.role == super::AgentRole::Worker
        && assignment.effective_role_category() == RoleCategory::NonDelegatingTerminalWorker
        && assignment.worker_assignments.is_empty();
    if !direct_execution_worker {
        bail!(
            "{}: Vibe is admitted only for a direct execution-phase, non-delegating terminal Worker \
             with no nested worker assignments; assignment '{}' is phase '{}', role '{}', category \
             '{}' with {} nested worker assignment(s)",
            crate::external_agent::WRITABLE_VIBE_TERMINAL_WORKER_REQUIRED,
            assignment.id,
            match assignment.phase {
                AssignmentPhase::Planning => "planning",
                AssignmentPhase::Execution => "execution",
            },
            assignment.role.as_str(),
            assignment.effective_role_category().as_str(),
            assignment.worker_assignments.len()
        );
    }
    Ok(())
}

/// Refuse a nested Vibe Worker launch inside a managed coordinator.
///
/// The managed coordinator path never admits Vibe, so the refusal is explicit
/// rather than a silent fallthrough into another runtime arm.
pub(super) fn refuse_nested_worker_launch() -> Result<()> {
    bail!("Vibe is not admitted for nested Worker assignments")
}
