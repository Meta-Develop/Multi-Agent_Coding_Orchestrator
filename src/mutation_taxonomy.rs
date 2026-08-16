//! Versioned mutation taxonomy and autonomous-admission decision boundary.
//!
//! Autopilot consults this module before source dispatch and every generated
//! follow-up dispatch. The taxonomy is conservative policy input, not a grant
//! of authority: every existing claim, containment, review, and effect gate
//! remains independently required.

/// Current reviewed registry version.
///
/// Version 2 incorporates the managed-worktree guard operations and corrects
/// release/effect gates against their production admission boundaries.
pub const MUTATION_TAXONOMY_VERSION: u32 = 2;

/// Gate identity returned for an unlisted, empty, or internally inconsistent row.
pub const TAXONOMY_REVIEW_REQUIRED_GATE_ID: &str = "taxonomy-review-required";

/// Whether MACO can restore the pre-operation state under the policy in
/// `docs/MUTATION_REVERSIBILITY.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationReversibility {
    Reversible,
    Irreversible,
}

impl MutationReversibility {
    /// Stable spelling used by the policy document.
    pub const fn policy_name(self) -> &'static str {
        match self {
            Self::Reversible => "Reversible",
            Self::Irreversible => "Irreversible",
        }
    }
}

/// Reviewed explicit gate required before an irreversible operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExplicitMutationGate {
    ExplicitInitCli,
    ExplicitMegafileTelemetrySeedCli,
    OfflineMigrationApplyAttestation,
    ExplicitWorktreeDestructiveCleanup,
    ForceWorktreeRemove,
    WorktreeDeleteBranch,
    ExactClaimReleaseAuthority,
    LiveOverrideActorReason,
    MergeApply,
    ExplicitMergeArbitrateCli,
    PrimaryPlanCliDoubleOptIn,
    ExplicitRealForgeDurableWalStart,
    ExplicitArtifactPruneApply,
    MachineGlobalOperationIdBearer,
    WorktreeGuardUninstallAuthority,
    InternalSealedPinnedExecCapability,
    ExactAgentProcessSelector,
    BoundedExternalScopeEventApi,
}

impl ExplicitMutationGate {
    /// Stable gate identifier used by policy documentation and audit surfaces.
    pub const fn id(self) -> &'static str {
        match self {
            Self::ExplicitInitCli => "explicit-init-cli",
            Self::ExplicitMegafileTelemetrySeedCli => "explicit-megafile-telemetry-seed-cli",
            Self::OfflineMigrationApplyAttestation => "offline-migration-apply-attestation",
            Self::ExplicitWorktreeDestructiveCleanup => "explicit-worktree-destructive-cleanup",
            Self::ForceWorktreeRemove => "force-worktree-remove",
            Self::WorktreeDeleteBranch => "worktree-delete-branch",
            Self::ExactClaimReleaseAuthority => "exact-claim-release-authority",
            Self::LiveOverrideActorReason => "live-override-actor-reason",
            Self::MergeApply => "merge-apply",
            Self::ExplicitMergeArbitrateCli => "explicit-merge-arbitrate-cli",
            Self::PrimaryPlanCliDoubleOptIn => "primary-plan-cli-double-opt-in",
            Self::ExplicitRealForgeDurableWalStart => "explicit-real-forge-durable-wal-start",
            Self::ExplicitArtifactPruneApply => "explicit-artifact-prune-apply",
            Self::MachineGlobalOperationIdBearer => "machine-global-operation-id-bearer",
            Self::WorktreeGuardUninstallAuthority => "worktree-guard-uninstall-authority",
            Self::InternalSealedPinnedExecCapability => "internal-sealed-pinned-exec-capability",
            Self::ExactAgentProcessSelector => "exact-agent-process-selector",
            Self::BoundedExternalScopeEventApi => "bounded-external-scope-event-api",
        }
    }
}

/// Typed inventory of reviewed MACO operation boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MutationOperation {
    RepositoryInitialize,
    MegafileTelemetrySeed,
    StateMigrationPreview,
    StateMigrationApply,
    WorktreeCreate,
    WorktreeGcPreview,
    WorktreeGarbageCollect,
    WorktreeTargetReclaim,
    WorktreeRemove,
    WorktreeBranchDelete,
    ClaimAcquire,
    ClaimRenew,
    ClaimRelease,
    ClaimOverrideRelease,
    MergePreview,
    MergeApply,
    MergeArbitrationProposal,
    SandboxWorktreeEdit,
    SandboxWorktreeCommit,
    PrimaryWorktreeMutation,
    PublicationPreview,
    PublicationPush,
    PullRequestCreate,
    IssueCreate,
    ArtifactPrunePreview,
    ArtifactPrune,
    MachineGlobalQuarantine,
    MachineGlobalRestore,
    MachineGlobalPurge,
    HookInstall,
    HookVerify,
    HookUninstall,
    PinnedExecutableExec,
    AgentProcessStop,
    ScopeEventAppend,
}

impl MutationOperation {
    /// Complete enum inventory, kept explicit so additions cannot evade tests.
    pub const ALL: [Self; 35] = [
        Self::RepositoryInitialize,
        Self::MegafileTelemetrySeed,
        Self::StateMigrationPreview,
        Self::StateMigrationApply,
        Self::WorktreeCreate,
        Self::WorktreeGcPreview,
        Self::WorktreeGarbageCollect,
        Self::WorktreeTargetReclaim,
        Self::WorktreeRemove,
        Self::WorktreeBranchDelete,
        Self::ClaimAcquire,
        Self::ClaimRenew,
        Self::ClaimRelease,
        Self::ClaimOverrideRelease,
        Self::MergePreview,
        Self::MergeApply,
        Self::MergeArbitrationProposal,
        Self::SandboxWorktreeEdit,
        Self::SandboxWorktreeCommit,
        Self::PrimaryWorktreeMutation,
        Self::PublicationPreview,
        Self::PublicationPush,
        Self::PullRequestCreate,
        Self::IssueCreate,
        Self::ArtifactPrunePreview,
        Self::ArtifactPrune,
        Self::MachineGlobalQuarantine,
        Self::MachineGlobalRestore,
        Self::MachineGlobalPurge,
        Self::HookInstall,
        Self::HookVerify,
        Self::HookUninstall,
        Self::PinnedExecutableExec,
        Self::AgentProcessStop,
        Self::ScopeEventAppend,
    ];

    /// Stable identifier used for lookup, policy rows, and gate evidence.
    pub const fn id(self) -> &'static str {
        match self {
            Self::RepositoryInitialize => "repository-initialize",
            Self::MegafileTelemetrySeed => "megafile-telemetry-seed",
            Self::StateMigrationPreview => "state-migration-preview",
            Self::StateMigrationApply => "state-migration-apply",
            Self::WorktreeCreate => "worktree-create",
            Self::WorktreeGcPreview => "worktree-gc-preview",
            Self::WorktreeGarbageCollect => "worktree-garbage-collect",
            Self::WorktreeTargetReclaim => "worktree-target-reclaim",
            Self::WorktreeRemove => "worktree-remove",
            Self::WorktreeBranchDelete => "worktree-branch-delete",
            Self::ClaimAcquire => "claim-acquire",
            Self::ClaimRenew => "claim-renew",
            Self::ClaimRelease => "claim-release",
            Self::ClaimOverrideRelease => "claim-override-release",
            Self::MergePreview => "merge-preview",
            Self::MergeApply => "merge-apply",
            Self::MergeArbitrationProposal => "merge-arbitration-proposal",
            Self::SandboxWorktreeEdit => "sandbox-worktree-edit",
            Self::SandboxWorktreeCommit => "sandbox-worktree-commit",
            Self::PrimaryWorktreeMutation => "primary-worktree-mutation",
            Self::PublicationPreview => "publication-preview",
            Self::PublicationPush => "publication-push",
            Self::PullRequestCreate => "pull-request-create",
            Self::IssueCreate => "issue-create",
            Self::ArtifactPrunePreview => "artifact-prune-preview",
            Self::ArtifactPrune => "artifact-prune",
            Self::MachineGlobalQuarantine => "machine-global-quarantine",
            Self::MachineGlobalRestore => "machine-global-restore",
            Self::MachineGlobalPurge => "machine-global-purge",
            Self::HookInstall => "hook-install",
            Self::HookVerify => "hook-verify",
            Self::HookUninstall => "hook-uninstall",
            Self::PinnedExecutableExec => "pinned-executable-exec",
            Self::AgentProcessStop => "agent-process-stop",
            Self::ScopeEventAppend => "scope-event-append",
        }
    }

    /// Parses an exact stable operation identifier.
    pub fn from_id(operation_id: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|operation| operation.id() == operation_id)
    }
}

/// One reviewed registry row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MutationClassification {
    pub operation: MutationOperation,
    pub reversibility: MutationReversibility,
    pub justification: &'static str,
    pub explicit_gate: Option<ExplicitMutationGate>,
}

/// Version and complete rows for one reviewed taxonomy generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MutationTaxonomyRegistry {
    pub version: u32,
    pub entries: &'static [MutationClassification],
}

const fn reversible(
    operation: MutationOperation,
    justification: &'static str,
) -> MutationClassification {
    MutationClassification {
        operation,
        reversibility: MutationReversibility::Reversible,
        justification,
        explicit_gate: None,
    }
}

const fn irreversible(
    operation: MutationOperation,
    justification: &'static str,
    explicit_gate: ExplicitMutationGate,
) -> MutationClassification {
    MutationClassification {
        operation,
        reversibility: MutationReversibility::Irreversible,
        justification,
        explicit_gate: Some(explicit_gate),
    }
}

const ENTRIES: &[MutationClassification] = &[
    irreversible(
        MutationOperation::RepositoryInitialize,
        "Establishes repository identity without retaining a MACO rollback bundle for prior filesystem and Git state.",
        ExplicitMutationGate::ExplicitInitCli,
    ),
    irreversible(
        MutationOperation::MegafileTelemetrySeed,
        "Persists coordination telemetry and no supported operation restores the exact prior authenticated telemetry state.",
        ExplicitMutationGate::ExplicitMegafileTelemetrySeedCli,
    ),
    reversible(
        MutationOperation::StateMigrationPreview,
        "Validates and reports migration work without changing durable state.",
    ),
    irreversible(
        MutationOperation::StateMigrationApply,
        "Rewrites authenticated durable state and does not retain a supported lossless rollback to the legacy representation.",
        ExplicitMutationGate::OfflineMigrationApplyAttestation,
    ),
    reversible(
        MutationOperation::WorktreeCreate,
        "Creates an isolated lane and branch that can be removed before work is added without losing pre-existing state.",
    ),
    reversible(
        MutationOperation::WorktreeGcPreview,
        "Only classifies and reports candidates; it does not remove lanes, targets, branches, or artifacts.",
    ),
    irreversible(
        MutationOperation::WorktreeGarbageCollect,
        "Removes lanes or leftover directories and may destroy work or forensic state even when guarded by cleanliness checks.",
        ExplicitMutationGate::ExplicitWorktreeDestructiveCleanup,
    ),
    irreversible(
        MutationOperation::WorktreeTargetReclaim,
        "Deletes build output; rebuilding is recomputation rather than restoration from retained state.",
        ExplicitMutationGate::ExplicitWorktreeDestructiveCleanup,
    ),
    irreversible(
        MutationOperation::WorktreeRemove,
        "Deletes a working directory and can discard uncommitted or untracked work even when an exact managed binding is selected.",
        ExplicitMutationGate::ForceWorktreeRemove,
    ),
    irreversible(
        MutationOperation::WorktreeBranchDelete,
        "Deletes a Git reference and MACO does not promise a retained, lossless ref restoration path.",
        ExplicitMutationGate::WorktreeDeleteBranch,
    ),
    reversible(
        MutationOperation::ClaimAcquire,
        "The bounded coordination record can be released without changing claimed user data.",
    ),
    reversible(
        MutationOperation::ClaimRenew,
        "Extends only the owner's bounded lease metadata and the claim remains releasable.",
    ),
    irreversible(
        MutationOperation::ClaimRelease,
        "Relinquishes exclusion immediately; another actor can acquire the paths, so the same ownership state cannot be recreated deterministically.",
        ExplicitMutationGate::ExactClaimReleaseAuthority,
    ),
    irreversible(
        MutationOperation::ClaimOverrideRelease,
        "Overrides another owner's live coordination state and may invalidate decisions made from the prior ownership record.",
        ExplicitMutationGate::LiveOverrideActorReason,
    ),
    reversible(
        MutationOperation::MergePreview,
        "Reads candidate and primary state to produce a report without applying the candidate.",
    ),
    irreversible(
        MutationOperation::MergeApply,
        "Mutates the primary worktree and index without a general retained-state rollback guarantee.",
        ExplicitMutationGate::MergeApply,
    ),
    irreversible(
        MutationOperation::MergeArbitrationProposal,
        "Launches an external arbiter and persists proposal evidence; costs and external execution cannot be undone.",
        ExplicitMutationGate::ExplicitMergeArbitrateCli,
    ),
    reversible(
        MutationOperation::SandboxWorktreeEdit,
        "The isolated clean lane retains its Git baseline, so tracked changes and newly created files can be discarded locally.",
    ),
    reversible(
        MutationOperation::SandboxWorktreeCommit,
        "The predecessor commit and objects remain local and retained, allowing the private branch to move back without primary or remote effects.",
    ),
    irreversible(
        MutationOperation::PrimaryWorktreeMutation,
        "Changes the user's active checkout without a universal snapshot-and-restore contract.",
        ExplicitMutationGate::PrimaryPlanCliDoubleOptIn,
    ),
    reversible(
        MutationOperation::PublicationPreview,
        "Builds a local report without pushing a ref or creating a forge object.",
    ),
    irreversible(
        MutationOperation::PublicationPush,
        "Creates a remote-visible ref; deleting or moving it later would be another external effect.",
        ExplicitMutationGate::ExplicitRealForgeDurableWalStart,
    ),
    irreversible(
        MutationOperation::PullRequestCreate,
        "Creates a remote review object and notifications that cannot be erased by a local rollback.",
        ExplicitMutationGate::ExplicitRealForgeDurableWalStart,
    ),
    irreversible(
        MutationOperation::IssueCreate,
        "Creates a remote-visible issue and may trigger notifications or automation.",
        ExplicitMutationGate::ExplicitRealForgeDurableWalStart,
    ),
    reversible(
        MutationOperation::ArtifactPrunePreview,
        "Reports retention candidates without deleting run artifacts or evidence.",
    ),
    irreversible(
        MutationOperation::ArtifactPrune,
        "Deletes run, audit, or acceptance evidence; retention policy does not make that evidence recoverable.",
        ExplicitMutationGate::ExplicitArtifactPruneApply,
    ),
    reversible(
        MutationOperation::MachineGlobalQuarantine,
        "Moves the complete declared target set into retained quarantine with a durable restore operation and no purge.",
    ),
    reversible(
        MutationOperation::MachineGlobalRestore,
        "Restores retained quarantined bytes to their original declared coordinates without deleting their contents.",
    ),
    irreversible(
        MutationOperation::MachineGlobalPurge,
        "Permanently deletes quarantined bytes and already requires the dedicated bearer capability.",
        ExplicitMutationGate::MachineGlobalOperationIdBearer,
    ),
    reversible(
        MutationOperation::HookInstall,
        "Adds only verified MACO-owned conditional hook state, leaves prior hook bytes untouched and chained, and uninstall removes that exact state to restore the prior effective hook configuration.",
    ),
    reversible(
        MutationOperation::HookVerify,
        "Reads and validates the exact guard ownership, configuration, hook bytes, and prior-hook binding without changing them.",
    ),
    irreversible(
        MutationOperation::HookUninstall,
        "Deletes the captured guard binding and owned hook state; exposing the unchanged prior hooks is safe, but it does not retain the complete pre-uninstall guard state for deterministic restoration.",
        ExplicitMutationGate::WorktreeGuardUninstallAuthority,
    ),
    irreversible(
        MutationOperation::PinnedExecutableExec,
        "Replaces the running process and may initiate effects that cannot be rolled back by the original process.",
        ExplicitMutationGate::InternalSealedPinnedExecCapability,
    ),
    irreversible(
        MutationOperation::AgentProcessStop,
        "Terminates a live process; restarting cannot restore its exact in-memory execution state.",
        ExplicitMutationGate::ExactAgentProcessSelector,
    ),
    irreversible(
        MutationOperation::ScopeEventAppend,
        "Emits durable observability history whose removal would destroy audit evidence and whose consumers cannot be rewound.",
        ExplicitMutationGate::BoundedExternalScopeEventApi,
    ),
];

const REGISTRY: MutationTaxonomyRegistry = MutationTaxonomyRegistry {
    version: MUTATION_TAXONOMY_VERSION,
    entries: ENTRIES,
};

/// Returns the complete reviewed, versioned registry.
pub const fn registry() -> &'static MutationTaxonomyRegistry {
    &REGISTRY
}

/// Looks up an exact reviewed operation ID.
pub fn classification_for(operation_id: &str) -> Option<&'static MutationClassification> {
    REGISTRY
        .entries
        .iter()
        .find(|entry| entry.operation.id() == operation_id)
}

/// Looks up an operation ID, failing closed for every unlisted value.
pub fn reversibility_for(operation_id: &str) -> MutationReversibility {
    classification_for(operation_id).map_or(MutationReversibility::Irreversible, |entry| {
        entry.reversibility
    })
}

/// Autonomous admission decision for one exact operation identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutonomousMutationDecision {
    Allow,
    RequireExplicitGate(ExplicitMutationGate),
    Refuse { gate_id: &'static str },
}

impl AutonomousMutationDecision {
    /// Gate identity for non-autonomous outcomes.
    pub const fn gate_id(self) -> Option<&'static str> {
        match self {
            Self::Allow => None,
            Self::RequireExplicitGate(gate) => Some(gate.id()),
            Self::Refuse { gate_id } => Some(gate_id),
        }
    }
}

/// Permits only a listed Reversible row with no explicit gate.
///
/// Listed Irreversible rows return their reviewed explicit gate. Unknown,
/// empty, or internally inconsistent rows refuse with
/// `taxonomy-review-required`.
pub fn autonomous_decision_for(operation_id: &str) -> AutonomousMutationDecision {
    match classification_for(operation_id) {
        Some(MutationClassification {
            reversibility: MutationReversibility::Reversible,
            explicit_gate: None,
            ..
        }) => AutonomousMutationDecision::Allow,
        Some(MutationClassification {
            reversibility: MutationReversibility::Irreversible,
            explicit_gate: Some(gate),
            ..
        }) => AutonomousMutationDecision::RequireExplicitGate(*gate),
        Some(_) | None => AutonomousMutationDecision::Refuse {
            gate_id: TAXONOMY_REVIEW_REQUIRED_GATE_ID,
        },
    }
}

/// Returns whether an identifier names a reviewed taxonomy refusal gate.
///
/// Consumers use this to recover the exact gate identity from a typed denial
/// without re-running a policy decision after the denied boundary.
pub(crate) fn is_reviewed_taxonomy_gate_id(gate_id: &str) -> bool {
    gate_id == TAXONOMY_REVIEW_REQUIRED_GATE_ID
        || REGISTRY.entries.iter().any(|entry| {
            entry
                .explicit_gate
                .is_some_and(|explicit_gate| explicit_gate.id() == gate_id)
        })
}

/// Exact workspace mutations admitted by a sandbox Supervisor child dispatch.
///
/// Claim release is intentionally absent: it is an irreversible operation
/// admitted separately after either a durable per-assignment completion
/// checkpoint or the durable aggregate final-report plan (or by an explicit
/// exact-target CLI request), never by this pre-dispatch decision.
pub const SUPERVISOR_CHILD_DISPATCH_MUTATIONS: [MutationOperation; 5] = [
    MutationOperation::WorktreeCreate,
    MutationOperation::HookInstall,
    MutationOperation::ClaimAcquire,
    MutationOperation::SandboxWorktreeEdit,
    MutationOperation::SandboxWorktreeCommit,
];

/// Applies the taxonomy to every workspace mutation performed by a sandbox
/// Supervisor child dispatch.
///
/// Both initial source admission and the central generated-follow-up boundary
/// call this function, so a taxonomy change cannot update only one dispatch
/// path accidentally.
pub(crate) fn autonomous_decision_for_supervisor_child_dispatch() -> AutonomousMutationDecision {
    #[cfg(test)]
    if let Some(decision) = AUTOPILOT_DISPATCH_DECISION_OVERRIDES.with(|overrides| {
        let mut overrides = overrides.borrow_mut();
        overrides.as_mut().map(|decisions| {
            decisions.pop_front().unwrap_or_else(|| {
                panic!("active Autopilot taxonomy override received an unexpected extra decision")
            })
        })
    }) {
        return decision;
    }

    for operation in SUPERVISOR_CHILD_DISPATCH_MUTATIONS {
        let decision = autonomous_decision_for(operation.id());
        if decision != AutonomousMutationDecision::Allow {
            return decision;
        }
    }
    AutonomousMutationDecision::Allow
}

#[cfg(test)]
thread_local! {
    static AUTOPILOT_DISPATCH_DECISION_OVERRIDES: std::cell::RefCell<Option<std::collections::VecDeque<AutonomousMutationDecision>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
static AUTOPILOT_DISPATCH_DECISION_OVERRIDE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub(crate) struct AutopilotDispatchDecisionOverrideGuard {
    _serialized: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl Drop for AutopilotDispatchDecisionOverrideGuard {
    fn drop(&mut self) {
        let remaining = AUTOPILOT_DISPATCH_DECISION_OVERRIDES.with(|overrides| {
            let mut overrides = overrides.borrow_mut();
            overrides.take().map_or(0, |decisions| decisions.len())
        });
        assert!(
            remaining == 0 || std::thread::panicking(),
            "{remaining} injected Autopilot taxonomy decisions were not consumed"
        );
    }
}

#[cfg(test)]
pub(crate) fn set_autopilot_dispatch_decisions_for_test(
    decisions: impl IntoIterator<Item = AutonomousMutationDecision>,
) -> AutopilotDispatchDecisionOverrideGuard {
    assert!(
        AUTOPILOT_DISPATCH_DECISION_OVERRIDES.with(|overrides| overrides.borrow().is_none()),
        "Autopilot taxonomy decision overrides are already active on this test thread"
    );
    let serialized = AUTOPILOT_DISPATCH_DECISION_OVERRIDE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    AUTOPILOT_DISPATCH_DECISION_OVERRIDES.with(|overrides| {
        let mut overrides = overrides.borrow_mut();
        debug_assert!(overrides.is_none());
        *overrides = Some(decisions.into_iter().collect());
    });
    AutopilotDispatchDecisionOverrideGuard {
        _serialized: serialized,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{
        autonomous_decision_for, autonomous_decision_for_supervisor_child_dispatch,
        classification_for, is_reviewed_taxonomy_gate_id, registry, reversibility_for,
        set_autopilot_dispatch_decisions_for_test, AutonomousMutationDecision, MutationOperation,
        MutationReversibility, MUTATION_TAXONOMY_VERSION, SUPERVISOR_CHILD_DISPATCH_MUTATIONS,
        TAXONOMY_REVIEW_REQUIRED_GATE_ID,
    };

    const POLICY: &str = include_str!("../docs/MUTATION_REVERSIBILITY.md");

    #[test]
    fn registry_version_is_explicit_and_current() {
        assert_eq!(registry().version, MUTATION_TAXONOMY_VERSION);
        assert_eq!(registry().version, 2);
    }

    #[test]
    fn registry_is_complete_for_the_operation_enum() {
        assert_eq!(registry().entries.len(), MutationOperation::ALL.len());
        let registered = registry()
            .entries
            .iter()
            .map(|entry| entry.operation)
            .collect::<HashSet<_>>();
        let declared = MutationOperation::ALL.into_iter().collect::<HashSet<_>>();
        assert_eq!(registered, declared);
    }

    #[test]
    fn registry_operation_ids_are_unique() {
        let mut ids = HashSet::new();
        for entry in registry().entries {
            assert!(
                ids.insert(entry.operation.id()),
                "duplicate operation id {}",
                entry.operation.id()
            );
        }
    }

    #[test]
    fn every_operation_id_roundtrips() {
        for operation in MutationOperation::ALL {
            assert_eq!(MutationOperation::from_id(operation.id()), Some(operation));
            assert_eq!(
                classification_for(operation.id()).map(|entry| entry.operation),
                Some(operation)
            );
        }
        assert_eq!(MutationOperation::from_id(""), None);
        assert_eq!(MutationOperation::from_id("unreviewed-operation"), None);
    }

    #[test]
    fn classification_counts_and_gate_invariants_are_exact() {
        let mut reversible_count = 0;
        let mut irreversible_count = 0;
        for entry in registry().entries {
            assert!(!entry.justification.trim().is_empty());
            match entry.reversibility {
                MutationReversibility::Reversible => {
                    reversible_count += 1;
                    assert_eq!(entry.explicit_gate, None, "{}", entry.operation.id());
                }
                MutationReversibility::Irreversible => {
                    irreversible_count += 1;
                    assert!(entry.explicit_gate.is_some(), "{}", entry.operation.id());
                }
            }
        }
        assert_eq!(reversible_count, 14);
        assert_eq!(irreversible_count, 21);
    }

    #[test]
    fn unknown_and_empty_ids_are_irreversible_and_refused() {
        for operation_id in ["", "future-operation-without-review"] {
            assert_eq!(
                reversibility_for(operation_id),
                MutationReversibility::Irreversible
            );
            assert_eq!(
                autonomous_decision_for(operation_id),
                AutonomousMutationDecision::Refuse {
                    gate_id: TAXONOMY_REVIEW_REQUIRED_GATE_ID
                }
            );
        }
    }

    #[test]
    fn autonomous_decision_has_no_default_allow_path() {
        for entry in registry().entries {
            match autonomous_decision_for(entry.operation.id()) {
                AutonomousMutationDecision::Allow => {
                    assert_eq!(entry.reversibility, MutationReversibility::Reversible);
                    assert_eq!(entry.explicit_gate, None);
                }
                AutonomousMutationDecision::RequireExplicitGate(gate) => {
                    assert_eq!(entry.reversibility, MutationReversibility::Irreversible);
                    assert_eq!(entry.explicit_gate, Some(gate));
                }
                AutonomousMutationDecision::Refuse { gate_id } => {
                    panic!(
                        "reviewed operation {} unexpectedly refused via {gate_id}",
                        entry.operation.id()
                    );
                }
            }
        }
        assert!(!matches!(
            autonomous_decision_for("unlisted"),
            AutonomousMutationDecision::Allow
        ));
    }

    #[test]
    fn taxonomy_gate_id_recognition_and_supervisor_dispatch_set_are_exact() {
        assert!(is_reviewed_taxonomy_gate_id(
            TAXONOMY_REVIEW_REQUIRED_GATE_ID
        ));
        for gate in registry()
            .entries
            .iter()
            .filter_map(|entry| entry.explicit_gate)
        {
            assert!(is_reviewed_taxonomy_gate_id(gate.id()), "{}", gate.id());
        }
        assert!(!is_reviewed_taxonomy_gate_id("unreviewed-gate"));
        assert_eq!(
            SUPERVISOR_CHILD_DISPATCH_MUTATIONS,
            [
                MutationOperation::WorktreeCreate,
                MutationOperation::HookInstall,
                MutationOperation::ClaimAcquire,
                MutationOperation::SandboxWorktreeEdit,
                MutationOperation::SandboxWorktreeCommit,
            ]
        );
        for operation in SUPERVISOR_CHILD_DISPATCH_MUTATIONS {
            assert_eq!(
                autonomous_decision_for(operation.id()),
                AutonomousMutationDecision::Allow,
                "{}",
                operation.id()
            );
        }
        assert_eq!(
            autonomous_decision_for_supervisor_child_dispatch(),
            AutonomousMutationDecision::Allow
        );
    }

    #[test]
    fn dispatch_override_is_serialized_scoped_and_thread_local() {
        let _guard =
            set_autopilot_dispatch_decisions_for_test([AutonomousMutationDecision::Refuse {
                gate_id: TAXONOMY_REVIEW_REQUIRED_GATE_ID,
            }]);
        let unrelated = std::thread::spawn(autonomous_decision_for_supervisor_child_dispatch)
            .join()
            .expect("join unrelated taxonomy decision thread");
        assert_eq!(unrelated, AutonomousMutationDecision::Allow);
        assert_eq!(
            autonomous_decision_for_supervisor_child_dispatch(),
            AutonomousMutationDecision::Refuse {
                gate_id: TAXONOMY_REVIEW_REQUIRED_GATE_ID,
            }
        );
    }

    #[test]
    #[should_panic(
        expected = "active Autopilot taxonomy override received an unexpected extra decision"
    )]
    fn active_dispatch_override_never_falls_through_after_exhaustion() {
        let _guard = set_autopilot_dispatch_decisions_for_test([AutonomousMutationDecision::Allow]);
        assert_eq!(
            autonomous_decision_for_supervisor_child_dispatch(),
            AutonomousMutationDecision::Allow
        );
        let _unexpected = autonomous_decision_for_supervisor_child_dispatch();
    }

    #[test]
    fn policy_document_has_exact_registry_parity() {
        for entry in registry().entries {
            let gate_id = entry.explicit_gate.map_or("none", |gate| gate.id());
            let expected = format!(
                "| `{}` | {} | {} | `{}` |",
                entry.operation.id(),
                entry.reversibility.policy_name(),
                entry.justification,
                gate_id
            );
            assert!(
                POLICY.lines().any(|line| line == expected),
                "policy table is missing or disagrees with registry entry {}",
                entry.operation.id()
            );
        }
        let documented_rows = POLICY
            .lines()
            .filter(|line| line.starts_with("| `") && line.ends_with(" |"))
            .count();
        assert_eq!(documented_rows, registry().entries.len());
    }
}
