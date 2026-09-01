//! Integration coverage for execution-run replay, time travel, and fork.

use multi_agent_coding_orchestrator::{
    execution_replay::{
        CapabilityId, EffectAction, EffectCategory, EffectDescriptor, EffectGuard, EffectId,
        EffectRearmCapability, EffectRequest, ExecutionReplayArchive, LineagePoint,
        NotReexecutedMaterial, ObservationId, ReplayBoundaryContract, ReplayError, ReplayEvent,
        ReplayEventKind, ReplayMode, ReplaySnapshot, ReplayedMaterial, RunId, RunLineage, StateKey,
        WorkId,
    },
    mutation_taxonomy::MutationReversibility,
};
use serde_json::json;
use std::collections::BTreeSet;

fn run_id(value: &str) -> RunId {
    RunId::new(value).expect("valid run id")
}

fn event(sequence: u64, event: ReplayEventKind) -> ReplayEvent {
    ReplayEvent::new(sequence, event)
}

fn recorded_run() -> RunLineage {
    let git = EffectDescriptor::new(
        EffectId::new("git-commit").expect("effect id"),
        EffectAction::new("git.commit").expect("action"),
        EffectCategory::GitMutation,
    );
    let worktree = EffectDescriptor::new(
        EffectId::new("worktree-create").expect("effect id"),
        EffectAction::new("worktree-create").expect("action"),
        EffectCategory::WorktreeCreation,
    );
    let provider = EffectDescriptor::new(
        EffectId::new("provider-call").expect("effect id"),
        EffectAction::new("provider.invoke").expect("action"),
        EffectCategory::ProviderCall,
    );
    RunLineage {
        version: 1,
        run_id: run_id("root"),
        parent: None,
        base_snapshot: ReplaySnapshot::empty(),
        events: vec![
            event(
                1,
                ReplayEventKind::StateSet {
                    key: StateKey::new("phase").expect("key"),
                    value: json!("planned"),
                },
            ),
            event(
                2,
                ReplayEventKind::WorkPlanned {
                    work_id: WorkId::new("compile").expect("work id"),
                },
            ),
            event(
                3,
                ReplayEventKind::WorkStarted {
                    work_id: WorkId::new("compile").expect("work id"),
                },
            ),
            event(
                4,
                ReplayEventKind::WorkCompleted {
                    work_id: WorkId::new("compile").expect("work id"),
                    outcome: json!({"status": 0}),
                },
            ),
            event(
                5,
                ReplayEventKind::ObservationRecorded {
                    observation_id: ObservationId::new("head").expect("observation"),
                    value: json!("abc"),
                },
            ),
            event(6, ReplayEventKind::ExternalEffectPlanned { effect: git }),
            event(
                7,
                ReplayEventKind::ExternalEffectStarted {
                    effect_id: EffectId::new("git-commit").expect("effect id"),
                },
            ),
            event(
                8,
                ReplayEventKind::ExternalEffectObserved {
                    effect_id: EffectId::new("git-commit").expect("effect id"),
                    observation: json!({"oid": "def"}),
                },
            ),
            event(
                9,
                ReplayEventKind::ExternalEffectCompleted {
                    effect_id: EffectId::new("git-commit").expect("effect id"),
                    outcome: json!({"commit": "def"}),
                },
            ),
            event(
                10,
                ReplayEventKind::ExternalEffectPlanned { effect: worktree },
            ),
            event(
                11,
                ReplayEventKind::ExternalEffectStarted {
                    effect_id: EffectId::new("worktree-create").expect("effect id"),
                },
            ),
            event(
                12,
                ReplayEventKind::ExternalEffectObserved {
                    effect_id: EffectId::new("worktree-create").expect("effect id"),
                    observation: json!({"path": "agent-a"}),
                },
            ),
            event(
                13,
                ReplayEventKind::ExternalEffectCompleted {
                    effect_id: EffectId::new("worktree-create").expect("effect id"),
                    outcome: json!({"created": true}),
                },
            ),
            event(
                14,
                ReplayEventKind::ExternalEffectPlanned { effect: provider },
            ),
            event(
                15,
                ReplayEventKind::ExternalEffectStarted {
                    effect_id: EffectId::new("provider-call").expect("effect id"),
                },
            ),
            event(
                16,
                ReplayEventKind::ExternalEffectObserved {
                    effect_id: EffectId::new("provider-call").expect("effect id"),
                    observation: json!({"tokens": 12}),
                },
            ),
            event(
                17,
                ReplayEventKind::ExternalEffectCompleted {
                    effect_id: EffectId::new("provider-call").expect("effect id"),
                    outcome: json!({"text": "recorded"}),
                },
            ),
            event(
                18,
                ReplayEventKind::StateSet {
                    key: StateKey::new("phase").expect("key"),
                    value: json!("done"),
                },
            ),
        ],
    }
}

#[test]
fn inspect_replay_and_fork_preserve_lineage_and_disarm_external_effects() {
    let archive = ExecutionReplayArchive::new(vec![recorded_run()]).expect("archive");
    let before = archive.to_json_bytes().expect("before");
    let terminal = LineagePoint::new(run_id("root"), 18);

    let inspection = archive.inspect_at(&terminal).expect("inspect");
    assert_eq!(
        inspection
            .snapshot
            .state
            .get(&StateKey::new("phase").expect("key")),
        Some(&json!("done"))
    );
    assert_eq!(
        archive.to_json_bytes().expect("inspect is read-only"),
        before
    );

    let replay = archive.replay_at(&terminal).expect("replay");
    assert_eq!(replay.contract, ReplayBoundaryContract::observation_only());
    assert_eq!(replay.contract.mode, ReplayMode::ObservationOnly);
    assert!(replay.contract.effects_disarmed);
    assert_eq!(
        replay.contract.replayed,
        BTreeSet::from([
            ReplayedMaterial::RecordedState,
            ReplayedMaterial::RecordedObservations,
            ReplayedMaterial::RecordedWorkOutcomes,
            ReplayedMaterial::RecordedExternalEffectEvidence,
        ])
    );
    assert_eq!(
        replay.contract.not_reexecuted,
        BTreeSet::from([
            NotReexecutedMaterial::Work,
            NotReexecutedMaterial::ExternalEffects,
        ])
    );
    assert_eq!(
        archive.replay_at(&terminal).expect("deterministic replay"),
        replay
    );

    let pending = archive
        .inspect_at(&LineagePoint::new(run_id("root"), 2))
        .expect_err("pending work is refused");
    assert_eq!(pending.code(), "replay_pending_execution");
    assert!(matches!(pending, ReplayError::PendingExecution { .. }));
    let uncertain = archive
        .replay_at(&LineagePoint::new(run_id("root"), 3))
        .expect_err("uncertain work is refused");
    assert_eq!(uncertain.code(), "replay_uncertain_execution");
    assert!(matches!(uncertain, ReplayError::UncertainExecution { .. }));

    let forked = archive
        .fork(&terminal, run_id("child"))
        .expect("independent child");
    assert_eq!(archive.to_json_bytes().expect("parent unchanged"), before);
    let child = forked
        .inspect_at(&LineagePoint::new(run_id("child"), 0))
        .expect("child base");
    assert_eq!(child.snapshot, inspection.snapshot);
    assert_eq!(
        forked.children_of(&run_id("root")).expect("children").len(),
        1
    );

    let mut guard = EffectGuard::new();
    for (effect, action, category) in [
        ("git-commit", "git.commit", EffectCategory::GitMutation),
        (
            "worktree-create",
            "worktree-create",
            EffectCategory::WorktreeCreation,
        ),
        (
            "provider-call",
            "provider.invoke",
            EffectCategory::ProviderCall,
        ),
    ] {
        let request = EffectRequest::new(
            LineagePoint::new(run_id("child"), 0),
            EffectDescriptor::new(
                EffectId::new(effect).expect("effect id"),
                EffectAction::new(action).expect("action"),
                category,
            ),
        );
        assert!(matches!(
            guard.authorize(&request, None),
            Err(ReplayError::EffectDisarmed { .. })
        ));
        if action == "worktree-create" {
            assert_eq!(
                request.taxonomy_reversibility(),
                MutationReversibility::Reversible
            );
        } else {
            assert_eq!(
                request.taxonomy_reversibility(),
                MutationReversibility::Irreversible
            );
        }
    }

    let rearm_request = EffectRequest::new(
        LineagePoint::new(run_id("child"), 0),
        EffectDescriptor::new(
            EffectId::new("git-commit").expect("effect id"),
            EffectAction::new("git.commit").expect("action"),
            EffectCategory::GitMutation,
        ),
    );
    let permit = guard
        .authorize(
            &rearm_request,
            Some(
                EffectRearmCapability::new(
                    CapabilityId::new("rearm-git").expect("capability"),
                    rearm_request.clone(),
                )
                .expect("capability"),
            ),
        )
        .expect("explicit one-shot rearm");
    assert_eq!(permit.request(), &rearm_request);
}
