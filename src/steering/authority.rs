use crate::{
    hierarchy_ledger::RoleCategory,
    steering::types::{
        AssignmentBinding, AssignmentKind, SteeringAction, SteeringActor, SteeringRefusal,
        SteeringRequest,
    },
    supervise::ModelCapabilityClass,
};

pub(crate) fn authorize(
    request: &SteeringRequest,
    target: &AssignmentBinding,
) -> Result<(), SteeringRefusal> {
    if target.run_id != request.run_id || target.assignment_id != request.assignment_id {
        return Err(SteeringRefusal::UnknownTarget);
    }
    if matches!(
        target.kind,
        AssignmentKind::MergeGate | AssignmentKind::ReviewGate
    ) {
        return Err(SteeringRefusal::MergeBypass);
    }

    match &request.actor {
        SteeringActor::Operator { .. } => authorize_action(&request.action, target),
        SteeringActor::ParentCoordinator {
            agent_id,
            role_category,
            model_capability,
        } => {
            if *role_category != RoleCategory::DelegatingCoordinator {
                return Err(SteeringRefusal::InsufficientAuthority);
            }
            if *model_capability == ModelCapabilityClass::WeakMechanical {
                return Err(SteeringRefusal::WeakModelCannotSteerCoordinator);
            }
            if coordinator_target_blocked_for_weak_actor(&request.actor, target) {
                return Err(SteeringRefusal::WeakModelCannotSteerCoordinator);
            }
            if let Some(parent) = &target.parent_agent_id {
                if parent != agent_id {
                    return Err(SteeringRefusal::InsufficientAuthority);
                }
            }
            authorize_action(&request.action, target)
        }
    }
}

fn authorize_action(
    action: &SteeringAction,
    target: &AssignmentBinding,
) -> Result<(), SteeringRefusal> {
    match action {
        SteeringAction::Resume if matches!(target.kind, AssignmentKind::MergeGate) => {
            Err(SteeringRefusal::MergeBypass)
        }
        _ => Ok(()),
    }
}

pub(crate) fn coordinator_target_blocked_for_weak_actor(
    actor: &SteeringActor,
    target: &AssignmentBinding,
) -> bool {
    target.role_category == RoleCategory::DelegatingCoordinator
        && actor
            .model_capability()
            .is_some_and(|capability| capability == ModelCapabilityClass::WeakMechanical)
}
