//! Fail-closed mutation-taxonomy classification for replayed effects.
//!
//! Replay never autonomously re-executes an effect. Listed reversible
//! operations still require an exact [`super::EffectRearmCapability`]. Unlisted
//! actions fail closed as irreversible, matching
//! [`crate::mutation_taxonomy::reversibility_for`].

use super::{EffectAction, EffectRequest};
use crate::mutation_taxonomy::{
    autonomous_decision_for, reversibility_for, AutonomousMutationDecision, MutationReversibility,
};

impl EffectRequest {
    /// Taxonomy reversibility of this exact action identifier.
    ///
    /// Unknown actions are irreversible.
    pub fn taxonomy_reversibility(&self) -> MutationReversibility {
        action_reversibility(&self.action)
    }

    /// Autonomous taxonomy decision for this exact action identifier.
    ///
    /// Replay still requires an explicit re-arm even when this returns
    /// [`AutonomousMutationDecision::Allow`].
    pub fn taxonomy_decision(&self) -> AutonomousMutationDecision {
        autonomous_decision_for(self.action.as_str())
    }
}

pub(super) fn action_reversibility(action: &EffectAction) -> MutationReversibility {
    reversibility_for(action.as_str())
}

#[cfg(test)]
mod tests {
    use crate::{
        execution_replay::{
            CapabilityId, EffectAction, EffectCategory, EffectDescriptor, EffectGuard, EffectId,
            EffectRearmCapability, EffectRequest, LineagePoint, ReplayError, RunId,
        },
        mutation_taxonomy::{AutonomousMutationDecision, MutationReversibility},
    };

    fn request(action: &str, category: EffectCategory) -> EffectRequest {
        EffectRequest::new(
            LineagePoint::new(RunId::new("root").expect("run id"), 1),
            EffectDescriptor::new(
                EffectId::new("effect").expect("effect id"),
                EffectAction::new(action).expect("action"),
                category,
            ),
        )
    }

    #[test]
    fn unlisted_actions_fail_closed_as_irreversible() {
        let request = request("git.commit", EffectCategory::GitMutation);
        assert_eq!(
            request.taxonomy_reversibility(),
            MutationReversibility::Irreversible
        );
        assert!(matches!(
            request.taxonomy_decision(),
            AutonomousMutationDecision::Refuse { .. }
        ));
    }

    #[test]
    fn listed_reversible_actions_still_require_explicit_rearm() {
        let request = request("worktree-create", EffectCategory::WorktreeCreation);
        assert_eq!(
            request.taxonomy_reversibility(),
            MutationReversibility::Reversible
        );
        assert_eq!(
            request.taxonomy_decision(),
            AutonomousMutationDecision::Allow
        );
        let mut guard = EffectGuard::new();
        assert!(matches!(
            guard.authorize(&request, None),
            Err(ReplayError::EffectDisarmed { .. })
        ));
        let permit = guard
            .authorize(
                &request,
                Some(
                    EffectRearmCapability::new(
                        CapabilityId::new("rearm-worktree").expect("capability"),
                        request.clone(),
                    )
                    .expect("capability"),
                ),
            )
            .expect("explicit rearm");
        assert_eq!(permit.request(), &request);
    }

    #[test]
    fn listed_irreversible_publication_still_requires_explicit_rearm() {
        let request = request("publication-push", EffectCategory::ForgeCall);
        assert_eq!(
            request.taxonomy_reversibility(),
            MutationReversibility::Irreversible
        );
        let mut guard = EffectGuard::new();
        assert!(matches!(
            guard.authorize(&request, None),
            Err(ReplayError::EffectDisarmed { .. })
        ));
    }
}
