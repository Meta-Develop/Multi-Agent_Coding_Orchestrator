//! Versioned mutation taxonomy and autonomous-admission decision boundary.
//!
//! Autopilot consults this module before source dispatch and every generated
//! follow-up dispatch. The taxonomy is conservative policy input, not a grant
//! of authority: every existing claim, containment, review, and effect gate
//! remains independently required.

use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

/// Current reviewed registry version.
///
/// Version 3 adds the durable semantic-intent acquire/release surface used by
/// current Supervisor dispatch while retaining the reviewed worktree-guard
/// operations that are installed by the independently owned hook integration.
/// Version 4 adds Supervisor Codex catalog preflight as an irreversible spawn
/// admitted only by an upstream one-shot grant bound to the final ProcessSpec.
/// Version 5 adds Inbox/PR-intake Codex catalog preflight as a distinct
/// irreversible spawn with its own explicit gate and sealed origin.
/// Version 6 adds assignment-child and parent-auditor process launch as a
/// distinct irreversible spawn admitted only by an upstream one-shot sibling
/// grant bound to the final ProcessSpec.
/// Version 7 adds Inbox independent-auditor process launch as a distinct
/// irreversible sibling spawn with its own explicit gate. Catalog grants and
/// parent-auditor grants cannot authorize that spawn.
/// Version 8 adds consult Codex/Claude process launch as a distinct
/// irreversible sibling spawn with its own explicit gate. Trusted program
/// spelling is kind-scoped: existing child/parent/Inbox kinds still require
/// `codex`; consult-Claude requires `claude` without broadening those kinds.
pub const MUTATION_TAXONOMY_VERSION: u32 = 8;

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
    ExactSemanticIntentReleaseAuthority,
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
    ExplicitSupervisorCatalogCodexPreflightGrant,
    ExplicitInboxPrIntakeCatalogCodexPreflightGrant,
    ExplicitAssignmentParentAuditorProcessLaunchGrant,
    ExplicitInboxIndependentAuditorProcessLaunchGrant,
    ExplicitConsultProcessLaunchGrant,
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
            Self::ExactSemanticIntentReleaseAuthority => "exact-semantic-intent-release-authority",
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
            Self::ExplicitSupervisorCatalogCodexPreflightGrant => {
                "explicit-supervisor-catalog-codex-preflight-grant"
            }
            Self::ExplicitInboxPrIntakeCatalogCodexPreflightGrant => {
                "explicit-inbox-pr-intake-catalog-codex-preflight-grant"
            }
            Self::ExplicitAssignmentParentAuditorProcessLaunchGrant => {
                "explicit-assignment-parent-auditor-process-launch-grant"
            }
            Self::ExplicitInboxIndependentAuditorProcessLaunchGrant => {
                "explicit-inbox-independent-auditor-process-launch-grant"
            }
            Self::ExplicitConsultProcessLaunchGrant => "explicit-consult-process-launch-grant",
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
    SemanticIntentAcquire,
    SemanticIntentRelease,
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
    SupervisorCatalogCodexPreflight,
    InboxPrIntakeCatalogCodexPreflight,
    AssignmentParentAuditorProcessLaunch,
    InboxIndependentAuditorProcessLaunch,
    ConsultProcessLaunch,
}

impl MutationOperation {
    /// Complete enum inventory, kept explicit so additions cannot evade tests.
    pub const ALL: [Self; 42] = [
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
        Self::SemanticIntentAcquire,
        Self::SemanticIntentRelease,
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
        Self::SupervisorCatalogCodexPreflight,
        Self::InboxPrIntakeCatalogCodexPreflight,
        Self::AssignmentParentAuditorProcessLaunch,
        Self::InboxIndependentAuditorProcessLaunch,
        Self::ConsultProcessLaunch,
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
            Self::SemanticIntentAcquire => "semantic-intent-acquire",
            Self::SemanticIntentRelease => "semantic-intent-release",
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
            Self::SupervisorCatalogCodexPreflight => "supervisor-catalog-codex-preflight",
            Self::InboxPrIntakeCatalogCodexPreflight => "inbox-pr-intake-catalog-codex-preflight",
            Self::AssignmentParentAuditorProcessLaunch => {
                "assignment-parent-auditor-process-launch"
            }
            Self::InboxIndependentAuditorProcessLaunch => {
                "inbox-independent-auditor-process-launch"
            }
            Self::ConsultProcessLaunch => "consult-process-launch",
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
    reversible(
        MutationOperation::SemanticIntentAcquire,
        "Adds a bounded planning intent that can be released without changing the repository content it describes.",
    ),
    irreversible(
        MutationOperation::SemanticIntentRelease,
        "Relinquishes semantic planning exclusion immediately, so the same conflict and ownership state cannot be recreated deterministically.",
        ExplicitMutationGate::ExactSemanticIntentReleaseAuthority,
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
        "Adds only verified MACO-owned conditional hook state, leaves prior hook bytes untouched and chained, and can remove that exact owned state.",
    ),
    reversible(
        MutationOperation::HookVerify,
        "Reads and validates the exact guard ownership, configuration, hook bytes, and prior-hook binding without changing them.",
    ),
    irreversible(
        MutationOperation::HookUninstall,
        "Deletes the captured guard binding and owned hook state without retaining the complete pre-uninstall state for deterministic restoration.",
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
    irreversible(
        MutationOperation::SupervisorCatalogCodexPreflight,
        "Spawns a trusted Codex catalog probe whose process, network, and captured output cannot be restored from retained MACO state.",
        ExplicitMutationGate::ExplicitSupervisorCatalogCodexPreflightGrant,
    ),
    irreversible(
        MutationOperation::InboxPrIntakeCatalogCodexPreflight,
        "Spawns a trusted Codex catalog probe for Inbox independent-audit or PR-intake whose process, network, and captured output cannot be restored from retained MACO state.",
        ExplicitMutationGate::ExplicitInboxPrIntakeCatalogCodexPreflightGrant,
    ),
    irreversible(
        MutationOperation::AssignmentParentAuditorProcessLaunch,
        "Spawns a trusted assignment-child or parent-auditor process whose process, network, and captured output cannot be restored from retained MACO state.",
        ExplicitMutationGate::ExplicitAssignmentParentAuditorProcessLaunchGrant,
    ),
    irreversible(
        MutationOperation::InboxIndependentAuditorProcessLaunch,
        "Spawns a trusted Inbox independent-auditor process whose process, network, and captured output cannot be restored from retained MACO state.",
        ExplicitMutationGate::ExplicitInboxIndependentAuditorProcessLaunchGrant,
    ),
    irreversible(
        MutationOperation::ConsultProcessLaunch,
        "Spawns a trusted consult Codex or Claude consultant process whose process, network, and captured output cannot be restored from retained MACO state.",
        ExplicitMutationGate::ExplicitConsultProcessLaunchGrant,
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
/// Release operations are intentionally absent: they are irreversible and
/// admitted separately by exact held tokens after the durable completion or
/// final-report cleanup plan is recorded.
pub const SUPERVISOR_CHILD_DISPATCH_MUTATIONS: [MutationOperation; 6] = [
    MutationOperation::WorktreeCreate,
    MutationOperation::HookInstall,
    MutationOperation::ClaimAcquire,
    MutationOperation::SemanticIntentAcquire,
    MutationOperation::SandboxWorktreeEdit,
    MutationOperation::SandboxWorktreeCommit,
];

/// Applies the taxonomy to every workspace mutation performed by a sandbox
/// Supervisor child dispatch.
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

/// Cwd policy sealed into a Codex catalog-preflight grant.
///
/// Production issuance can only name the resolved trusted program parent.
/// Exact paths exist solely so tests can inject the historical caller-repo
/// mismatch; they are not a production encoding of the resolver search base.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CatalogPreflightCwdPolicy {
    ResolvedTrustedProgramParent,
    #[cfg(test)]
    Exact(PathBuf),
}

/// Expected executable binding sealed into a Codex catalog-preflight grant.
///
/// Production issuance records only the trusted path spelling `codex`. The
/// authorized loader must refine that intent with an independently verified
/// canonical program (and its parent) before `ProcessSpec` construction.
/// Consume then exact-matches the final spec against that sealed canonical
/// binding. It does not rederive the expected parent from an arbitrary
/// supplied final program, and it does not require the canonical filename to
/// be `codex`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CatalogPreflightExpectedProgram {
    TrustedSpelling,
    IndependentlyVerifiedCanonical { program: PathBuf, parent: PathBuf },
}

/// Caller origin sealed into a catalog-preflight grant.
///
/// Consume exact-matches this origin. A Supervisor grant cannot bind Inbox or
/// PR-intake catalog, and Inbox/PR-intake grants cannot bind `for_supervisor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CatalogPreflightOrigin {
    Supervisor,
    Inbox,
    PrIntake,
}

/// One-shot grant that admits a Codex catalog preflight spawn against a fully
/// built `ProcessSpec`.
///
/// The issuer is the production catalog-preflight caller, not the catalog
/// builder. `run_id` may correlate; it is not the grant. A nonce is. Origin is
/// sealed at admit and exact-matched at consume. Inbox and PR-intake must not
/// call the Supervisor admit helper.
#[derive(Debug, Clone)]
#[must_use]
pub(crate) struct SupervisorCatalogCodexPreflightGrant {
    nonce: u64,
    /// Correlation only; `run_id` is not the grant. Inspected by tests.
    #[allow(dead_code)]
    run_id: String,
    /// Negative context: caller repo / resolver search base, never process cwd.
    #[allow(dead_code)]
    resolver_search_base: PathBuf,
    expected_program: CatalogPreflightExpectedProgram,
    cwd_policy: CatalogPreflightCwdPolicy,
    origin: CatalogPreflightOrigin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SupervisorCatalogCodexPreflightGrantError {
    UntrustedExpectedProgram,
    AlreadyConsumed,
    ProgramMismatch,
    CurrentDirMismatch,
    ArgvMismatch,
    OriginMismatch,
}

impl SupervisorCatalogCodexPreflightGrantError {
    pub(crate) const fn cause_id(self) -> &'static str {
        match self {
            Self::UntrustedExpectedProgram => "untrusted_catalog_preflight_program",
            Self::AlreadyConsumed => "catalog_preflight_grant_consumed",
            Self::ProgramMismatch | Self::CurrentDirMismatch | Self::ArgvMismatch => {
                "catalog_preflight_grant_mismatch"
            }
            Self::OriginMismatch => "catalog_preflight_grant_origin_mismatch",
        }
    }
}

impl fmt::Display for SupervisorCatalogCodexPreflightGrantError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.cause_id())
    }
}

impl std::error::Error for SupervisorCatalogCodexPreflightGrantError {}

static NEXT_SUPERVISOR_CATALOG_PREFLIGHT_NONCE: AtomicU64 = AtomicU64::new(1);
static CONSUMED_SUPERVISOR_CATALOG_PREFLIGHT_NONCES: LazyLock<Mutex<HashSet<u64>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

const TRUSTED_SUPERVISOR_CATALOG_CODEX_PROGRAM: &str = "codex";
const SUPERVISOR_CATALOG_CODEX_PREFLIGHT_ARGV: [&str; 2] = ["debug", "models"];

impl SupervisorCatalogCodexPreflightGrant {
    fn admit_from_catalog_intent(
        run_id: &str,
        resolver_search_base: &Path,
        expected_program: &Path,
        origin: CatalogPreflightOrigin,
    ) -> Result<Self, SupervisorCatalogCodexPreflightGrantError> {
        if expected_program != Path::new(TRUSTED_SUPERVISOR_CATALOG_CODEX_PROGRAM) {
            return Err(SupervisorCatalogCodexPreflightGrantError::UntrustedExpectedProgram);
        }
        Ok(Self {
            nonce: NEXT_SUPERVISOR_CATALOG_PREFLIGHT_NONCE.fetch_add(1, Ordering::Relaxed),
            run_id: run_id.to_string(),
            resolver_search_base: resolver_search_base.to_path_buf(),
            expected_program: CatalogPreflightExpectedProgram::TrustedSpelling,
            cwd_policy: CatalogPreflightCwdPolicy::ResolvedTrustedProgramParent,
            origin,
        })
    }

    /// Production Supervisor issuer. Encodes only `ResolvedTrustedProgramParent`.
    ///
    /// `resolver_search_base` is negative context (the caller repo / search
    /// base). It is never stored as process cwd.
    pub(crate) fn admit_from_supervisor_catalog_intent(
        run_id: &str,
        resolver_search_base: &Path,
        expected_program: &Path,
    ) -> Result<Self, SupervisorCatalogCodexPreflightGrantError> {
        Self::admit_from_catalog_intent(
            run_id,
            resolver_search_base,
            expected_program,
            CatalogPreflightOrigin::Supervisor,
        )
    }

    /// Production Inbox issuer. Distinct from the Supervisor admit helper.
    pub(crate) fn admit_from_inbox_catalog_intent(
        run_id: &str,
        resolver_search_base: &Path,
        expected_program: &Path,
    ) -> Result<Self, SupervisorCatalogCodexPreflightGrantError> {
        Self::admit_from_catalog_intent(
            run_id,
            resolver_search_base,
            expected_program,
            CatalogPreflightOrigin::Inbox,
        )
    }

    /// Production PR-intake issuer. Distinct from the Supervisor admit helper.
    pub(crate) fn admit_from_pr_intake_catalog_intent(
        run_id: &str,
        resolver_search_base: &Path,
        expected_program: &Path,
    ) -> Result<Self, SupervisorCatalogCodexPreflightGrantError> {
        Self::admit_from_catalog_intent(
            run_id,
            resolver_search_base,
            expected_program,
            CatalogPreflightOrigin::PrIntake,
        )
    }

    /// Test-only issuer that can encode `Exact(current_dir)` so negative tests
    /// can inject the historical caller-repo cwd mismatch.
    #[cfg(test)]
    pub(crate) fn admit_exact_cwd_for_test(
        run_id: &str,
        resolver_search_base: &Path,
        expected_program: &Path,
        current_dir: &Path,
    ) -> Result<Self, SupervisorCatalogCodexPreflightGrantError> {
        Self::admit_exact_cwd_with_origin_for_test(
            run_id,
            resolver_search_base,
            expected_program,
            current_dir,
            CatalogPreflightOrigin::Supervisor,
        )
    }

    #[cfg(test)]
    pub(crate) fn admit_exact_cwd_with_origin_for_test(
        run_id: &str,
        resolver_search_base: &Path,
        expected_program: &Path,
        current_dir: &Path,
        origin: CatalogPreflightOrigin,
    ) -> Result<Self, SupervisorCatalogCodexPreflightGrantError> {
        if expected_program != Path::new(TRUSTED_SUPERVISOR_CATALOG_CODEX_PROGRAM) {
            return Err(SupervisorCatalogCodexPreflightGrantError::UntrustedExpectedProgram);
        }
        Ok(Self {
            nonce: NEXT_SUPERVISOR_CATALOG_PREFLIGHT_NONCE.fetch_add(1, Ordering::Relaxed),
            run_id: run_id.to_string(),
            resolver_search_base: resolver_search_base.to_path_buf(),
            expected_program: CatalogPreflightExpectedProgram::TrustedSpelling,
            cwd_policy: CatalogPreflightCwdPolicy::Exact(current_dir.to_path_buf()),
            origin,
        })
    }

    /// Refine admitted trusted spelling `codex` with an independently verified
    /// canonical program before `ProcessSpec` construction.
    ///
    /// `independently_verified_canonical_program` is the result of trusted
    /// resolution plus identity validation. This seals that canonical path and
    /// its parent. It refuses to treat the admit spelling `codex` as if it
    /// were already a canonical binding, and it does not require the canonical
    /// filename to be `codex`.
    pub(crate) fn seal_independently_verified_canonical_binding(
        self,
        independently_verified_canonical_program: &Path,
    ) -> Result<Self, SupervisorCatalogCodexPreflightGrantError> {
        if !matches!(
            self.expected_program,
            CatalogPreflightExpectedProgram::TrustedSpelling
        ) {
            return Err(SupervisorCatalogCodexPreflightGrantError::ProgramMismatch);
        }
        if independently_verified_canonical_program
            == Path::new(TRUSTED_SUPERVISOR_CATALOG_CODEX_PROGRAM)
        {
            return Err(SupervisorCatalogCodexPreflightGrantError::ProgramMismatch);
        }
        let Some(parent) = independently_verified_canonical_program.parent() else {
            return Err(SupervisorCatalogCodexPreflightGrantError::CurrentDirMismatch);
        };
        if parent.as_os_str().is_empty() {
            return Err(SupervisorCatalogCodexPreflightGrantError::CurrentDirMismatch);
        }
        Ok(Self {
            expected_program: CatalogPreflightExpectedProgram::IndependentlyVerifiedCanonical {
                program: independently_verified_canonical_program.to_path_buf(),
                parent: parent.to_path_buf(),
            },
            ..self
        })
    }

    pub(crate) fn independently_verified_canonical_program(&self) -> Option<&Path> {
        match &self.expected_program {
            CatalogPreflightExpectedProgram::IndependentlyVerifiedCanonical { program, .. } => {
                Some(program)
            }
            CatalogPreflightExpectedProgram::TrustedSpelling => None,
        }
    }

    pub(crate) fn independently_verified_canonical_parent(&self) -> Option<&Path> {
        match &self.expected_program {
            CatalogPreflightExpectedProgram::IndependentlyVerifiedCanonical { parent, .. } => {
                Some(parent)
            }
            CatalogPreflightExpectedProgram::TrustedSpelling => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn run_id(&self) -> &str {
        &self.run_id
    }

    #[cfg(test)]
    pub(crate) fn resolver_search_base(&self) -> &Path {
        &self.resolver_search_base
    }

    pub(crate) fn origin(&self) -> CatalogPreflightOrigin {
        self.origin
    }

    /// Consume this one-shot grant against the final process binding.
    ///
    /// Exact-matches `program` to the independently sealed canonical expected
    /// program and `current_dir` to the independently sealed expected parent
    /// (or a test-only `Exact` cwd), and exact-matches `expected_origin` to the
    /// origin sealed at admit. Does not accept a basename-only `codex`
    /// match and does not rederive the expected parent from the supplied
    /// final program. Returns the sealed expected parent so bind can compare
    /// confinement independently of `spec.current_dir`.
    pub(crate) fn consume_for_process_binding<A: AsRef<OsStr>>(
        self,
        program: &Path,
        current_dir: &Path,
        argv: &[A],
        expected_origin: CatalogPreflightOrigin,
    ) -> Result<PathBuf, SupervisorCatalogCodexPreflightGrantError> {
        let mut consumed = CONSUMED_SUPERVISOR_CATALOG_PREFLIGHT_NONCES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !consumed.insert(self.nonce) {
            return Err(SupervisorCatalogCodexPreflightGrantError::AlreadyConsumed);
        }
        drop(consumed);

        if self.origin != expected_origin {
            return Err(SupervisorCatalogCodexPreflightGrantError::OriginMismatch);
        }

        let CatalogPreflightExpectedProgram::IndependentlyVerifiedCanonical {
            program: expected_program,
            parent: expected_parent,
        } = &self.expected_program
        else {
            return Err(SupervisorCatalogCodexPreflightGrantError::ProgramMismatch);
        };
        if program != expected_program {
            return Err(SupervisorCatalogCodexPreflightGrantError::ProgramMismatch);
        }
        if argv.len() != SUPERVISOR_CATALOG_CODEX_PREFLIGHT_ARGV.len()
            || argv
                .iter()
                .zip(SUPERVISOR_CATALOG_CODEX_PREFLIGHT_ARGV.iter())
                .any(|(actual, expected)| actual.as_ref() != OsStr::new(expected))
        {
            return Err(SupervisorCatalogCodexPreflightGrantError::ArgvMismatch);
        }
        let cwd_matches = match &self.cwd_policy {
            CatalogPreflightCwdPolicy::ResolvedTrustedProgramParent => {
                current_dir == expected_parent
            }
            #[cfg(test)]
            CatalogPreflightCwdPolicy::Exact(expected_cwd) => current_dir == expected_cwd,
        };
        if !cwd_matches {
            return Err(SupervisorCatalogCodexPreflightGrantError::CurrentDirMismatch);
        }
        Ok(expected_parent.clone())
    }
}

/// Launch kind sealed into an assignment-child / parent-auditor /
/// Inbox-independent-auditor / consult process grant.
///
/// Distinct from `CatalogPreflightOrigin`. Catalog grants cannot bind these
/// worker, auditor, or consult argv surfaces. Inbox independent-auditor is a
/// sibling kind, not a parent-auditor alias. Consult Codex and consult Claude
/// are sibling kinds with kind-scoped trusted program spellings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AssignmentProcessLaunchKind {
    AssignmentChild,
    ParentAuditor,
    InboxIndependentAuditor,
    ConsultCodex,
    ConsultClaude,
}

impl AssignmentProcessLaunchKind {
    /// Trusted basename spelling admitted for this kind.
    ///
    /// Child, parent-auditor, Inbox independent-auditor, and consult-Codex
    /// remain `codex`. Consult-Claude is `claude` only for that kind.
    pub(crate) const fn trusted_program_spelling(self) -> &'static str {
        match self {
            Self::AssignmentChild
            | Self::ParentAuditor
            | Self::InboxIndependentAuditor
            | Self::ConsultCodex => TRUSTED_ASSIGNMENT_PROCESS_CODEX_PROGRAM,
            Self::ConsultClaude => TRUSTED_CONSULT_CLAUDE_PROGRAM,
        }
    }
}

/// Expected executable binding sealed into an assignment process-launch grant.
///
/// Production issuance records only the kind's trusted path spelling (`codex`
/// for child/parent/Inbox/consult-Codex, `claude` for consult-Claude). The
/// runtime must refine that intent with an independently verified canonical
/// program (and its parent) plus the final argv and output staging path before
/// `ProcessSpec` construction.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AssignmentProcessExpectedProgram {
    TrustedSpelling,
    IndependentlyVerifiedCanonical { program: PathBuf, parent: PathBuf },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AssignmentProcessSealedDelivery {
    argv: Vec<OsString>,
    output_staging: PathBuf,
    cwd: PathBuf,
}

/// One-shot grant that admits an assignment-child, parent-auditor, Inbox
/// independent-auditor, or consult spawn against a fully built `ProcessSpec`.
///
/// The issuer is the trusted caller (`admit_assignment_child_process_intent` /
/// `admit_parent_auditor_process_intent` /
/// `admit_inbox_independent_auditor_process_intent` /
/// `admit_consult_codex_process_intent` /
/// `admit_consult_claude_process_intent`), not the external-agent sink. The
/// sink must not mint this grant from `run_id` plus the caller repository.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub(crate) struct AssignmentProcessLaunchGrant {
    nonce: u64,
    run_id: String,
    subject: String,
    attempt: usize,
    kind: AssignmentProcessLaunchKind,
    expected_program: AssignmentProcessExpectedProgram,
    model: Option<String>,
    duty: String,
    sealed_delivery: Option<AssignmentProcessSealedDelivery>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AssignmentProcessLaunchGrantError {
    UntrustedExpectedProgram,
    MissingGrant,
    AlreadyConsumed,
    ProgramMismatch,
    CurrentDirMismatch,
    ArgvMismatch,
    OutputStagingMismatch,
    KindMismatch,
    IdentityMismatch,
}

impl AssignmentProcessLaunchGrantError {
    pub(crate) const fn cause_id(self) -> &'static str {
        match self {
            Self::UntrustedExpectedProgram => "untrusted_assignment_process_launch_program",
            Self::MissingGrant => "assignment_process_launch_grant_missing",
            Self::AlreadyConsumed => "assignment_process_launch_grant_consumed",
            Self::ProgramMismatch
            | Self::CurrentDirMismatch
            | Self::ArgvMismatch
            | Self::OutputStagingMismatch => "assignment_process_launch_grant_mismatch",
            Self::KindMismatch => "assignment_process_launch_grant_kind_mismatch",
            Self::IdentityMismatch => "assignment_process_launch_grant_identity_mismatch",
        }
    }
}

impl fmt::Display for AssignmentProcessLaunchGrantError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.cause_id())
    }
}

impl std::error::Error for AssignmentProcessLaunchGrantError {}

static NEXT_ASSIGNMENT_PROCESS_LAUNCH_NONCE: AtomicU64 = AtomicU64::new(1);
static CONSUMED_ASSIGNMENT_PROCESS_LAUNCH_NONCES: LazyLock<Mutex<HashSet<u64>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

const TRUSTED_ASSIGNMENT_PROCESS_CODEX_PROGRAM: &str = "codex";
const TRUSTED_CONSULT_CLAUDE_PROGRAM: &str = "claude";
pub(crate) const ASSIGNMENT_CHILD_PROCESS_DUTY: &str = "assignment-child";
pub(crate) const PARENT_AUDITOR_PROCESS_DUTY: &str = "parent-auditor";
pub(crate) const INBOX_INDEPENDENT_AUDITOR_PROCESS_DUTY: &str = "inbox-independent-auditor";
pub(crate) const CONSULTANT_PROCESS_DUTY: &str = "consultant";

impl AssignmentProcessLaunchGrant {
    fn admit(
        run_id: &str,
        subject: &str,
        attempt: usize,
        kind: AssignmentProcessLaunchKind,
        expected_program: &Path,
        model: Option<&str>,
        duty: &str,
    ) -> Result<Self, AssignmentProcessLaunchGrantError> {
        if expected_program != Path::new(kind.trusted_program_spelling()) {
            return Err(AssignmentProcessLaunchGrantError::UntrustedExpectedProgram);
        }
        Ok(Self {
            nonce: NEXT_ASSIGNMENT_PROCESS_LAUNCH_NONCE.fetch_add(1, Ordering::Relaxed),
            run_id: run_id.to_string(),
            subject: subject.to_string(),
            attempt,
            kind,
            expected_program: AssignmentProcessExpectedProgram::TrustedSpelling,
            model: model.map(str::to_string),
            duty: duty.to_string(),
            sealed_delivery: None,
        })
    }

    pub(crate) fn kind(&self) -> AssignmentProcessLaunchKind {
        self.kind
    }

    pub(crate) fn attempt(&self) -> usize {
        self.attempt
    }

    pub(crate) fn duty(&self) -> &str {
        &self.duty
    }

    pub(crate) fn run_id(&self) -> &str {
        &self.run_id
    }

    pub(crate) fn subject(&self) -> &str {
        &self.subject
    }

    pub(crate) fn model(&self) -> Option<&str> {
        self.model.as_deref()
    }

    #[cfg(test)]
    pub(crate) fn independently_verified_canonical_program(&self) -> Option<&Path> {
        match &self.expected_program {
            AssignmentProcessExpectedProgram::IndependentlyVerifiedCanonical {
                program, ..
            } => Some(program),
            AssignmentProcessExpectedProgram::TrustedSpelling => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn independently_verified_canonical_parent(&self) -> Option<&Path> {
        match &self.expected_program {
            AssignmentProcessExpectedProgram::IndependentlyVerifiedCanonical { parent, .. } => {
                Some(parent)
            }
            AssignmentProcessExpectedProgram::TrustedSpelling => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_independently_verified_canonical_parent_for_test(
        mut self,
        parent: PathBuf,
    ) -> Self {
        if let AssignmentProcessExpectedProgram::IndependentlyVerifiedCanonical {
            parent: expected_parent,
            ..
        } = &mut self.expected_program
        {
            *expected_parent = parent;
        }
        self
    }

    #[cfg(test)]
    pub(crate) fn seal_independently_verified_canonical_program_for_test(
        self,
        independently_verified_canonical_program: &Path,
    ) -> Result<Self, AssignmentProcessLaunchGrantError> {
        if !matches!(
            self.expected_program,
            AssignmentProcessExpectedProgram::TrustedSpelling
        ) {
            return Err(AssignmentProcessLaunchGrantError::ProgramMismatch);
        }
        if independently_verified_canonical_program
            == Path::new(self.kind.trusted_program_spelling())
        {
            return Err(AssignmentProcessLaunchGrantError::ProgramMismatch);
        }
        let Some(parent) = independently_verified_canonical_program.parent() else {
            return Err(AssignmentProcessLaunchGrantError::CurrentDirMismatch);
        };
        if parent.as_os_str().is_empty() {
            return Err(AssignmentProcessLaunchGrantError::CurrentDirMismatch);
        }
        Ok(Self {
            expected_program: AssignmentProcessExpectedProgram::IndependentlyVerifiedCanonical {
                program: independently_verified_canonical_program.to_path_buf(),
                parent: parent.to_path_buf(),
            },
            ..self
        })
    }

    /// Refine admitted trusted spelling with an independently verified
    /// canonical program, final argv, output staging path, and ProcessSpec cwd.
    ///
    /// Already-sealed program bindings are retained so a later substituted
    /// program cannot overwrite the independently verified canonical. Delivery
    /// fields are sealed once.
    pub(crate) fn seal_independently_verified_canonical_binding<A: AsRef<OsStr>>(
        self,
        independently_verified_canonical_program: &Path,
        argv: impl IntoIterator<Item = A>,
        output_staging: &Path,
        cwd: &Path,
    ) -> Result<Self, AssignmentProcessLaunchGrantError> {
        let expected_program = match &self.expected_program {
            AssignmentProcessExpectedProgram::TrustedSpelling => {
                if independently_verified_canonical_program
                    == Path::new(self.kind.trusted_program_spelling())
                {
                    return Err(AssignmentProcessLaunchGrantError::ProgramMismatch);
                }
                let Some(parent) = independently_verified_canonical_program.parent() else {
                    return Err(AssignmentProcessLaunchGrantError::CurrentDirMismatch);
                };
                if parent.as_os_str().is_empty() {
                    return Err(AssignmentProcessLaunchGrantError::CurrentDirMismatch);
                }
                AssignmentProcessExpectedProgram::IndependentlyVerifiedCanonical {
                    program: independently_verified_canonical_program.to_path_buf(),
                    parent: parent.to_path_buf(),
                }
            }
            AssignmentProcessExpectedProgram::IndependentlyVerifiedCanonical {
                program, ..
            } => {
                if independently_verified_canonical_program != program {
                    return Err(AssignmentProcessLaunchGrantError::ProgramMismatch);
                }
                self.expected_program.clone()
            }
        };
        if let Some(delivery) = self.sealed_delivery.clone() {
            // Delivery is sealed once. Retain it so consume exact-matches the
            // independently verified staging/argv/cwd against the final spec.
            return Ok(Self {
                expected_program,
                sealed_delivery: Some(delivery),
                ..self
            });
        }
        if cwd.as_os_str().is_empty() || output_staging.as_os_str().is_empty() {
            return Err(AssignmentProcessLaunchGrantError::CurrentDirMismatch);
        }
        Ok(Self {
            expected_program,
            sealed_delivery: Some(AssignmentProcessSealedDelivery {
                argv: argv
                    .into_iter()
                    .map(|argument| argument.as_ref().to_os_string())
                    .collect(),
                output_staging: output_staging.to_path_buf(),
                cwd: cwd.to_path_buf(),
            }),
            ..self
        })
    }

    /// Consume this one-shot grant against the final process binding.
    ///
    /// Exact-matches sealed canonical program, ProcessSpec cwd, argv, output
    /// staging, launch kind, run_id, subject, attempt, model, and duty. Does
    /// not accept a basename-only `codex` match and does not rederive the
    /// expected program from the supplied final program.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn consume_for_process_binding<A: AsRef<OsStr>>(
        self,
        program: &Path,
        current_dir: &Path,
        argv: &[A],
        output_staging: &Path,
        run_id: &str,
        subject: &str,
        attempt: usize,
        kind: AssignmentProcessLaunchKind,
        model: Option<&str>,
        duty: &str,
    ) -> Result<(), AssignmentProcessLaunchGrantError> {
        let mut consumed = CONSUMED_ASSIGNMENT_PROCESS_LAUNCH_NONCES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !consumed.insert(self.nonce) {
            return Err(AssignmentProcessLaunchGrantError::AlreadyConsumed);
        }
        drop(consumed);

        if self.kind != kind {
            return Err(AssignmentProcessLaunchGrantError::KindMismatch);
        }
        if self.run_id != run_id
            || self.subject != subject
            || self.attempt != attempt
            || self.model.as_deref() != model
            || self.duty != duty
        {
            return Err(AssignmentProcessLaunchGrantError::IdentityMismatch);
        }

        let AssignmentProcessExpectedProgram::IndependentlyVerifiedCanonical {
            program: expected_program,
            parent: expected_parent,
        } = &self.expected_program
        else {
            return Err(AssignmentProcessLaunchGrantError::ProgramMismatch);
        };
        let Some(delivery) = &self.sealed_delivery else {
            return Err(AssignmentProcessLaunchGrantError::ProgramMismatch);
        };
        if program != expected_program {
            return Err(AssignmentProcessLaunchGrantError::ProgramMismatch);
        }
        // Parent is a component of the independently verified canonical program
        // path. ProcessSpec cwd is sealed delivery.cwd, not this parent field.
        if program.parent() != Some(expected_parent.as_path()) {
            return Err(AssignmentProcessLaunchGrantError::ProgramMismatch);
        }
        if current_dir != delivery.cwd.as_path() {
            return Err(AssignmentProcessLaunchGrantError::CurrentDirMismatch);
        }
        if output_staging != delivery.output_staging.as_path() {
            return Err(AssignmentProcessLaunchGrantError::OutputStagingMismatch);
        }
        if argv.len() != delivery.argv.len()
            || argv
                .iter()
                .zip(delivery.argv.iter())
                .any(|(actual, expected)| actual.as_ref() != expected.as_os_str())
        {
            return Err(AssignmentProcessLaunchGrantError::ArgvMismatch);
        }
        Ok(())
    }
}

/// Trusted assignment-child issuer. Encodes run identity, subject, attempt,
/// kind, trusted program spelling `codex`, model, and duty. Does not mint a
/// grant from `run_id` plus a repository path.
pub(crate) fn admit_assignment_child_process_intent(
    run_id: &str,
    subject: &str,
    attempt: usize,
    expected_program: &Path,
    model: Option<&str>,
    duty: &str,
) -> Result<AssignmentProcessLaunchGrant, AssignmentProcessLaunchGrantError> {
    AssignmentProcessLaunchGrant::admit(
        run_id,
        subject,
        attempt,
        AssignmentProcessLaunchKind::AssignmentChild,
        expected_program,
        model,
        duty,
    )
}

/// Trusted parent-auditor issuer. Distinct kind from assignment-child; shares
/// the assignment process-launch nonce ledger, not the catalog ledger.
pub(crate) fn admit_parent_auditor_process_intent(
    run_id: &str,
    subject: &str,
    attempt: usize,
    expected_program: &Path,
    model: Option<&str>,
    duty: &str,
) -> Result<AssignmentProcessLaunchGrant, AssignmentProcessLaunchGrantError> {
    AssignmentProcessLaunchGrant::admit(
        run_id,
        subject,
        attempt,
        AssignmentProcessLaunchKind::ParentAuditor,
        expected_program,
        model,
        duty,
    )
}

/// Trusted Inbox independent-auditor issuer. Distinct kind from assignment
/// child and parent-auditor; shares the process-launch nonce ledger, not the
/// catalog ledger. Does not mint a grant from `run_id` plus a repository path.
pub(crate) fn admit_inbox_independent_auditor_process_intent(
    run_id: &str,
    subject: &str,
    attempt: usize,
    expected_program: &Path,
    model: Option<&str>,
    duty: &str,
) -> Result<AssignmentProcessLaunchGrant, AssignmentProcessLaunchGrantError> {
    AssignmentProcessLaunchGrant::admit(
        run_id,
        subject,
        attempt,
        AssignmentProcessLaunchKind::InboxIndependentAuditor,
        expected_program,
        model,
        duty,
    )
}

/// Trusted consult-Codex issuer. Distinct kind from assignment child, parent
/// auditor, Inbox independent-auditor, and consult-Claude. Shares the
/// process-launch nonce ledger, not the catalog ledger. Trusted spelling is
/// `codex`. Does not mint a grant from `run_id` plus a repository path.
pub(crate) fn admit_consult_codex_process_intent(
    run_id: &str,
    subject: &str,
    attempt: usize,
    expected_program: &Path,
    model: Option<&str>,
    duty: &str,
) -> Result<AssignmentProcessLaunchGrant, AssignmentProcessLaunchGrantError> {
    AssignmentProcessLaunchGrant::admit(
        run_id,
        subject,
        attempt,
        AssignmentProcessLaunchKind::ConsultCodex,
        expected_program,
        model,
        duty,
    )
}

/// Trusted consult-Claude issuer. Distinct kind; trusted spelling is `claude`
/// for this kind only and does not broaden child/parent/Inbox `codex` rules.
/// Shares the process-launch nonce ledger, not the catalog ledger. Does not
/// mint a grant from `run_id` plus a repository path.
pub(crate) fn admit_consult_claude_process_intent(
    run_id: &str,
    subject: &str,
    attempt: usize,
    expected_program: &Path,
    model: Option<&str>,
    duty: &str,
) -> Result<AssignmentProcessLaunchGrant, AssignmentProcessLaunchGrantError> {
    AssignmentProcessLaunchGrant::admit(
        run_id,
        subject,
        attempt,
        AssignmentProcessLaunchKind::ConsultClaude,
        expected_program,
        model,
        duty,
    )
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

    use super::*;

    const POLICY: &str = include_str!("../docs/MUTATION_REVERSIBILITY.md");

    #[test]
    fn registry_is_current_complete_and_unique() {
        assert_eq!(registry().version, MUTATION_TAXONOMY_VERSION);
        assert_eq!(registry().version, 8);
        assert_eq!(registry().entries.len(), MutationOperation::ALL.len());

        let registered = registry()
            .entries
            .iter()
            .map(|entry| entry.operation)
            .collect::<HashSet<_>>();
        let declared = MutationOperation::ALL.into_iter().collect::<HashSet<_>>();
        assert_eq!(registered, declared);

        let mut ids = HashSet::new();
        for operation in MutationOperation::ALL {
            assert!(ids.insert(operation.id()), "duplicate {}", operation.id());
            assert_eq!(MutationOperation::from_id(operation.id()), Some(operation));
        }
    }

    #[test]
    fn unlisted_and_inconsistent_operations_fail_closed() {
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
        for entry in registry().entries {
            match entry.reversibility {
                MutationReversibility::Reversible => {
                    assert_eq!(entry.explicit_gate, None, "{}", entry.operation.id());
                    assert_eq!(
                        autonomous_decision_for(entry.operation.id()),
                        AutonomousMutationDecision::Allow
                    );
                }
                MutationReversibility::Irreversible => {
                    let gate = entry
                        .explicit_gate
                        .unwrap_or_else(|| panic!("{} has no gate", entry.operation.id()));
                    assert_eq!(
                        autonomous_decision_for(entry.operation.id()),
                        AutonomousMutationDecision::RequireExplicitGate(gate)
                    );
                }
            }
        }
    }

    #[test]
    fn classification_counts_and_dispatch_set_are_exact() {
        let reversible = registry()
            .entries
            .iter()
            .filter(|entry| entry.reversibility == MutationReversibility::Reversible)
            .count();
        assert_eq!(reversible, 15);
        assert_eq!(registry().entries.len() - reversible, 27);
        assert_eq!(
            SUPERVISOR_CHILD_DISPATCH_MUTATIONS,
            [
                MutationOperation::WorktreeCreate,
                MutationOperation::HookInstall,
                MutationOperation::ClaimAcquire,
                MutationOperation::SemanticIntentAcquire,
                MutationOperation::SandboxWorktreeEdit,
                MutationOperation::SandboxWorktreeCommit,
            ]
        );
        assert_eq!(
            autonomous_decision_for_supervisor_child_dispatch(),
            AutonomousMutationDecision::Allow
        );
    }

    #[test]
    fn every_registry_row_has_exact_documentation_parity() {
        for entry in registry().entries {
            let gate_id = entry.explicit_gate.map_or("none", ExplicitMutationGate::id);
            let expected = format!(
                "| `{}` | {} | {} | `{}` |",
                entry.operation.id(),
                entry.reversibility.policy_name(),
                entry.justification,
                gate_id
            );
            assert!(
                POLICY.lines().any(|line| line == expected),
                "policy table is missing or disagrees with {}",
                entry.operation.id()
            );
        }
        assert_eq!(
            POLICY
                .lines()
                .filter(|line| line.starts_with("| `") && line.ends_with(" |"))
                .count(),
            registry().entries.len()
        );
    }

    #[test]
    fn dispatch_override_is_scoped_thread_local_and_never_falls_through() {
        let _guard =
            set_autopilot_dispatch_decisions_for_test([AutonomousMutationDecision::Refuse {
                gate_id: TAXONOMY_REVIEW_REQUIRED_GATE_ID,
            }]);
        let unrelated = std::thread::spawn(autonomous_decision_for_supervisor_child_dispatch)
            .join()
            .expect("join unrelated decision thread");
        assert_eq!(unrelated, AutonomousMutationDecision::Allow);
        assert_eq!(
            autonomous_decision_for_supervisor_child_dispatch(),
            AutonomousMutationDecision::Refuse {
                gate_id: TAXONOMY_REVIEW_REQUIRED_GATE_ID
            }
        );
    }

    #[test]
    fn production_catalog_preflight_grant_consumes_once_against_program_parent() {
        use crate::process_runner::{ProcessCommand, ProcessSpec};

        let program = Path::new("/usr/bin/codex");
        let program_parent = Path::new("/usr/bin");
        let resolver_search_base = Path::new("/repos/caller-worktree");
        assert_ne!(program_parent, resolver_search_base);

        let spec = ProcessSpec::direct(
            "catalog preflight binding",
            program,
            ["debug", "models"],
            program_parent,
            64,
        );
        let ProcessCommand::Direct {
            program: spec_program,
            args: spec_argv,
        } = &spec.command
        else {
            panic!("direct catalog spec must remain a direct command");
        };
        assert_eq!(spec.current_dir.as_path(), program_parent);

        let grant = SupervisorCatalogCodexPreflightGrant::admit_from_supervisor_catalog_intent(
            "run-catalog-preflight-1",
            resolver_search_base,
            Path::new("codex"),
        )
        .expect("trusted codex spelling must admit")
        .seal_independently_verified_canonical_binding(program)
        .expect("independently verified canonical must seal");
        assert_eq!(grant.run_id(), "run-catalog-preflight-1");
        assert_eq!(grant.resolver_search_base(), resolver_search_base);
        assert_eq!(
            grant.independently_verified_canonical_program(),
            Some(program)
        );
        assert_eq!(
            grant.independently_verified_canonical_parent(),
            Some(program_parent)
        );

        let sealed_parent = grant
            .clone()
            .consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                CatalogPreflightOrigin::Supervisor,
            )
            .expect("program-parent binding must consume once");
        assert_eq!(sealed_parent.as_path(), program_parent);
        let reused = grant.consume_for_process_binding(
            spec_program,
            &spec.current_dir,
            spec_argv,
            CatalogPreflightOrigin::Supervisor,
        );
        assert_eq!(
            reused,
            Err(SupervisorCatalogCodexPreflightGrantError::AlreadyConsumed)
        );
    }

    #[test]
    fn production_catalog_preflight_grant_rejects_resolver_search_base_cwd() {
        use crate::process_runner::{ProcessCommand, ProcessSpec};

        let program = Path::new("/usr/bin/codex");
        let program_parent = Path::new("/usr/bin");
        let resolver_search_base = Path::new("/repos/caller-worktree");
        let spec = ProcessSpec::direct(
            "catalog preflight residual cwd",
            program,
            ["debug", "models"],
            resolver_search_base,
            64,
        );
        let ProcessCommand::Direct {
            program: spec_program,
            args: spec_argv,
        } = &spec.command
        else {
            panic!("direct catalog spec must remain a direct command");
        };
        assert_eq!(spec.current_dir.as_path(), resolver_search_base);
        assert_ne!(spec.current_dir.as_path(), program_parent);

        let grant = SupervisorCatalogCodexPreflightGrant::admit_from_supervisor_catalog_intent(
            "run-catalog-preflight-repo-cwd",
            resolver_search_base,
            Path::new("codex"),
        )
        .expect("trusted codex spelling must admit")
        .seal_independently_verified_canonical_binding(program)
        .expect("independently verified canonical must seal");
        assert_eq!(
            grant.consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                CatalogPreflightOrigin::Supervisor,
            ),
            Err(SupervisorCatalogCodexPreflightGrantError::CurrentDirMismatch)
        );
    }

    #[test]
    fn exact_repo_grant_rejects_program_parent_spec() {
        use crate::process_runner::{ProcessCommand, ProcessSpec};

        let program = Path::new("/usr/bin/codex");
        let program_parent = Path::new("/usr/bin");
        let repo = Path::new("/repos/caller-worktree");
        let spec = ProcessSpec::direct(
            "catalog preflight program parent spec",
            program,
            ["debug", "models"],
            program_parent,
            64,
        );
        let ProcessCommand::Direct {
            program: spec_program,
            args: spec_argv,
        } = &spec.command
        else {
            panic!("direct catalog spec must remain a direct command");
        };

        let grant = SupervisorCatalogCodexPreflightGrant::admit_exact_cwd_for_test(
            "run-catalog-preflight-exact-repo",
            repo,
            Path::new("codex"),
            repo,
        )
        .expect("test exact-cwd constructor must admit trusted program spelling")
        .seal_independently_verified_canonical_binding(program)
        .expect("independently verified canonical must seal");
        assert_eq!(
            grant.consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                CatalogPreflightOrigin::Supervisor,
            ),
            Err(SupervisorCatalogCodexPreflightGrantError::CurrentDirMismatch)
        );
    }

    #[test]
    fn catalog_preflight_grant_rejects_wrong_argv() {
        use crate::process_runner::{ProcessCommand, ProcessSpec};

        let program = Path::new("/usr/bin/codex");
        let program_parent = Path::new("/usr/bin");
        let spec = ProcessSpec::direct(
            "catalog preflight wrong argv",
            program,
            ["debug", "model"],
            program_parent,
            64,
        );
        let ProcessCommand::Direct {
            program: spec_program,
            args: spec_argv,
        } = &spec.command
        else {
            panic!("direct catalog spec must remain a direct command");
        };

        let grant = SupervisorCatalogCodexPreflightGrant::admit_from_supervisor_catalog_intent(
            "run-catalog-preflight-argv",
            Path::new("/repos/caller-worktree"),
            Path::new("codex"),
        )
        .expect("trusted codex spelling must admit")
        .seal_independently_verified_canonical_binding(program)
        .expect("independently verified canonical must seal");
        assert_eq!(
            grant.consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                CatalogPreflightOrigin::Supervisor,
            ),
            Err(SupervisorCatalogCodexPreflightGrantError::ArgvMismatch)
        );
    }

    #[test]
    fn production_catalog_preflight_grant_consumes_sealed_canonical_with_non_codex_filename() {
        use crate::process_runner::{ProcessCommand, ProcessSpec};

        let independently_verified_canonical = Path::new("/opt/codex-lib/codex.js");
        let sealed_parent = Path::new("/opt/codex-lib");
        let resolver_search_base = Path::new("/repos/caller-worktree");
        assert_ne!(
            independently_verified_canonical.file_name(),
            Some(OsStr::new("codex"))
        );
        assert_eq!(
            independently_verified_canonical.parent(),
            Some(sealed_parent)
        );
        assert_ne!(sealed_parent, resolver_search_base);

        let spec = ProcessSpec::direct(
            "catalog preflight non-codex canonical filename",
            independently_verified_canonical,
            ["debug", "models"],
            sealed_parent,
            64,
        );
        let ProcessCommand::Direct {
            program: spec_program,
            args: spec_argv,
        } = &spec.command
        else {
            panic!("direct catalog spec must remain a direct command");
        };
        assert_eq!(spec_program, independently_verified_canonical);
        assert_eq!(spec.current_dir.as_path(), sealed_parent);

        let grant = SupervisorCatalogCodexPreflightGrant::admit_from_supervisor_catalog_intent(
            "run-catalog-preflight-codex-js",
            resolver_search_base,
            Path::new("codex"),
        )
        .expect("trusted codex spelling must admit")
        .seal_independently_verified_canonical_binding(independently_verified_canonical)
        .expect("canonical target whose filename is not codex must seal");
        let consumed_parent = grant
            .consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                CatalogPreflightOrigin::Supervisor,
            )
            .expect("sealed non-codex canonical filename must consume when spec matches");
        assert_eq!(consumed_parent.as_path(), sealed_parent);
    }

    #[test]
    fn production_catalog_preflight_grant_rejects_same_basename_wrong_final_program() {
        use crate::process_runner::{ProcessCommand, ProcessSpec};

        let independently_verified_canonical = Path::new("/usr/bin/codex");
        let independently_verified_parent = Path::new("/usr/bin");
        let wrong_program = Path::new("/tmp/codex");
        let wrong_cwd = Path::new("/tmp");
        assert_eq!(
            wrong_program.file_name(),
            independently_verified_canonical.file_name()
        );
        assert_eq!(wrong_program.file_name(), Some(OsStr::new("codex")));
        assert_ne!(wrong_program, independently_verified_canonical);
        assert_ne!(wrong_cwd, independently_verified_parent);

        let spec = ProcessSpec::direct(
            "catalog preflight same-basename wrong program",
            wrong_program,
            ["debug", "models"],
            wrong_cwd,
            64,
        );
        let ProcessCommand::Direct {
            program: spec_program,
            args: spec_argv,
        } = &spec.command
        else {
            panic!("direct catalog spec must remain a direct command");
        };
        assert_eq!(spec_program, wrong_program);
        assert_eq!(spec.current_dir.as_path(), wrong_cwd);

        let grant = SupervisorCatalogCodexPreflightGrant::admit_from_supervisor_catalog_intent(
            "run-catalog-preflight-tmp-codex",
            Path::new("/repos/caller-worktree"),
            Path::new("codex"),
        )
        .expect("trusted codex spelling must admit")
        .seal_independently_verified_canonical_binding(independently_verified_canonical)
        .expect("independently verified canonical must seal");
        assert_eq!(
            grant.consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                CatalogPreflightOrigin::Supervisor,
            ),
            Err(SupervisorCatalogCodexPreflightGrantError::ProgramMismatch)
        );
    }

    #[test]
    fn production_catalog_preflight_issuer_refuses_untrusted_program_spelling() {
        let error = SupervisorCatalogCodexPreflightGrant::admit_from_supervisor_catalog_intent(
            "run-catalog-preflight-untrusted",
            Path::new("/repos/caller-worktree"),
            Path::new("/tmp/untrusted-custom-codex"),
        )
        .expect_err("production issuer must refuse non-codex spelling");
        assert_eq!(
            error,
            SupervisorCatalogCodexPreflightGrantError::UntrustedExpectedProgram
        );
    }

    #[test]
    fn supervisor_catalog_codex_preflight_is_irreversible_and_not_child_dispatch() {
        assert!(!SUPERVISOR_CHILD_DISPATCH_MUTATIONS
            .contains(&MutationOperation::SupervisorCatalogCodexPreflight));
        assert_eq!(
            autonomous_decision_for(MutationOperation::SupervisorCatalogCodexPreflight.id()),
            AutonomousMutationDecision::RequireExplicitGate(
                ExplicitMutationGate::ExplicitSupervisorCatalogCodexPreflightGrant
            )
        );
        assert_ne!(
            ExplicitMutationGate::ExplicitSupervisorCatalogCodexPreflightGrant,
            ExplicitMutationGate::InternalSealedPinnedExecCapability
        );
    }

    #[test]
    fn inbox_pr_intake_catalog_codex_preflight_is_irreversible_distinct_gate_and_not_child_dispatch(
    ) {
        assert!(!SUPERVISOR_CHILD_DISPATCH_MUTATIONS
            .contains(&MutationOperation::InboxPrIntakeCatalogCodexPreflight));
        assert_eq!(
            autonomous_decision_for(MutationOperation::InboxPrIntakeCatalogCodexPreflight.id()),
            AutonomousMutationDecision::RequireExplicitGate(
                ExplicitMutationGate::ExplicitInboxPrIntakeCatalogCodexPreflightGrant
            )
        );
        assert_ne!(
            ExplicitMutationGate::ExplicitInboxPrIntakeCatalogCodexPreflightGrant,
            ExplicitMutationGate::ExplicitSupervisorCatalogCodexPreflightGrant
        );
        assert_ne!(
            ExplicitMutationGate::ExplicitInboxPrIntakeCatalogCodexPreflightGrant,
            ExplicitMutationGate::InternalSealedPinnedExecCapability
        );
    }

    #[test]
    fn supervisor_grant_cannot_consume_as_inbox_origin() {
        use crate::process_runner::{ProcessCommand, ProcessSpec};

        let program = Path::new("/usr/bin/codex");
        let program_parent = Path::new("/usr/bin");
        let spec = ProcessSpec::direct(
            "catalog preflight cross-origin supervisor as inbox",
            program,
            ["debug", "models"],
            program_parent,
            64,
        );
        let ProcessCommand::Direct {
            program: spec_program,
            args: spec_argv,
        } = &spec.command
        else {
            panic!("direct catalog spec must remain a direct command");
        };

        let grant = SupervisorCatalogCodexPreflightGrant::admit_from_supervisor_catalog_intent(
            "run-catalog-preflight-supervisor-as-inbox",
            Path::new("/repos/caller-worktree"),
            Path::new("codex"),
        )
        .expect("trusted codex spelling must admit")
        .seal_independently_verified_canonical_binding(program)
        .expect("independently verified canonical must seal");
        assert_eq!(grant.origin(), CatalogPreflightOrigin::Supervisor);
        assert_eq!(
            grant.consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                CatalogPreflightOrigin::Inbox,
            ),
            Err(SupervisorCatalogCodexPreflightGrantError::OriginMismatch)
        );
    }

    #[test]
    fn inbox_grant_cannot_consume_as_supervisor_origin() {
        use crate::process_runner::{ProcessCommand, ProcessSpec};

        let program = Path::new("/usr/bin/codex");
        let program_parent = Path::new("/usr/bin");
        let spec = ProcessSpec::direct(
            "catalog preflight cross-origin inbox as supervisor",
            program,
            ["debug", "models"],
            program_parent,
            64,
        );
        let ProcessCommand::Direct {
            program: spec_program,
            args: spec_argv,
        } = &spec.command
        else {
            panic!("direct catalog spec must remain a direct command");
        };

        let grant = SupervisorCatalogCodexPreflightGrant::admit_from_inbox_catalog_intent(
            "run-catalog-preflight-inbox-as-supervisor",
            Path::new("/repos/caller-worktree"),
            Path::new("codex"),
        )
        .expect("trusted codex spelling must admit")
        .seal_independently_verified_canonical_binding(program)
        .expect("independently verified canonical must seal");
        assert_eq!(grant.origin(), CatalogPreflightOrigin::Inbox);
        assert_eq!(
            grant.consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                CatalogPreflightOrigin::Supervisor,
            ),
            Err(SupervisorCatalogCodexPreflightGrantError::OriginMismatch)
        );
    }

    #[test]
    fn inbox_catalog_preflight_grant_consumes_sealed_canonical_with_non_codex_filename() {
        use crate::process_runner::{ProcessCommand, ProcessSpec};

        let independently_verified_canonical = Path::new("/opt/codex-lib/codex.js");
        let sealed_parent = Path::new("/opt/codex-lib");
        let resolver_search_base = Path::new("/repos/caller-worktree");
        assert_ne!(
            independently_verified_canonical.file_name(),
            Some(OsStr::new("codex"))
        );

        let spec = ProcessSpec::direct(
            "inbox catalog preflight non-codex canonical filename",
            independently_verified_canonical,
            ["debug", "models"],
            sealed_parent,
            64,
        );
        let ProcessCommand::Direct {
            program: spec_program,
            args: spec_argv,
        } = &spec.command
        else {
            panic!("direct catalog spec must remain a direct command");
        };

        let grant = SupervisorCatalogCodexPreflightGrant::admit_from_inbox_catalog_intent(
            "run-inbox-catalog-preflight-codex-js",
            resolver_search_base,
            Path::new("codex"),
        )
        .expect("trusted codex spelling must admit")
        .seal_independently_verified_canonical_binding(independently_verified_canonical)
        .expect("canonical target whose filename is not codex must seal");
        let consumed_parent = grant
            .consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                CatalogPreflightOrigin::Inbox,
            )
            .expect("sealed non-codex canonical filename must consume with Inbox origin");
        assert_eq!(consumed_parent.as_path(), sealed_parent);
    }

    #[test]
    fn inbox_catalog_preflight_grant_rejects_same_basename_wrong_final_program() {
        use crate::process_runner::{ProcessCommand, ProcessSpec};

        let independently_verified_canonical = Path::new("/usr/bin/codex");
        let wrong_program = Path::new("/tmp/codex");
        let wrong_cwd = Path::new("/tmp");
        assert_eq!(
            wrong_program.file_name(),
            independently_verified_canonical.file_name()
        );
        assert_ne!(wrong_program, independently_verified_canonical);

        let spec = ProcessSpec::direct(
            "inbox catalog preflight same-basename wrong program",
            wrong_program,
            ["debug", "models"],
            wrong_cwd,
            64,
        );
        let ProcessCommand::Direct {
            program: spec_program,
            args: spec_argv,
        } = &spec.command
        else {
            panic!("direct catalog spec must remain a direct command");
        };

        let grant = SupervisorCatalogCodexPreflightGrant::admit_from_inbox_catalog_intent(
            "run-inbox-catalog-preflight-tmp-codex",
            Path::new("/repos/caller-worktree"),
            Path::new("codex"),
        )
        .expect("trusted codex spelling must admit")
        .seal_independently_verified_canonical_binding(independently_verified_canonical)
        .expect("independently verified canonical must seal");
        assert_eq!(
            grant.consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                CatalogPreflightOrigin::Inbox,
            ),
            Err(SupervisorCatalogCodexPreflightGrantError::ProgramMismatch)
        );
    }

    #[test]
    fn inbox_catalog_preflight_grant_rejects_resolver_search_base_cwd() {
        use crate::process_runner::{ProcessCommand, ProcessSpec};

        let program = Path::new("/usr/bin/codex");
        let program_parent = Path::new("/usr/bin");
        let resolver_search_base = Path::new("/repos/caller-worktree");
        let spec = ProcessSpec::direct(
            "inbox catalog preflight residual cwd",
            program,
            ["debug", "models"],
            resolver_search_base,
            64,
        );
        let ProcessCommand::Direct {
            program: spec_program,
            args: spec_argv,
        } = &spec.command
        else {
            panic!("direct catalog spec must remain a direct command");
        };
        assert_ne!(spec.current_dir.as_path(), program_parent);

        let grant = SupervisorCatalogCodexPreflightGrant::admit_from_inbox_catalog_intent(
            "run-inbox-catalog-preflight-repo-cwd",
            resolver_search_base,
            Path::new("codex"),
        )
        .expect("trusted codex spelling must admit")
        .seal_independently_verified_canonical_binding(program)
        .expect("independently verified canonical must seal");
        assert_eq!(
            grant.consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                CatalogPreflightOrigin::Inbox,
            ),
            Err(SupervisorCatalogCodexPreflightGrantError::CurrentDirMismatch)
        );
    }

    #[test]
    fn inbox_catalog_preflight_grant_rejects_wrong_argv_and_replay() {
        use crate::process_runner::{ProcessCommand, ProcessSpec};

        let program = Path::new("/usr/bin/codex");
        let program_parent = Path::new("/usr/bin");
        let wrong_argv_spec = ProcessSpec::direct(
            "inbox catalog preflight wrong argv",
            program,
            ["debug", "model"],
            program_parent,
            64,
        );
        let ProcessCommand::Direct {
            program: spec_program,
            args: spec_argv,
        } = &wrong_argv_spec.command
        else {
            panic!("direct catalog spec must remain a direct command");
        };

        let grant = SupervisorCatalogCodexPreflightGrant::admit_from_inbox_catalog_intent(
            "run-inbox-catalog-preflight-argv",
            Path::new("/repos/caller-worktree"),
            Path::new("codex"),
        )
        .expect("trusted codex spelling must admit")
        .seal_independently_verified_canonical_binding(program)
        .expect("independently verified canonical must seal");
        assert_eq!(
            grant.consume_for_process_binding(
                spec_program,
                &wrong_argv_spec.current_dir,
                spec_argv,
                CatalogPreflightOrigin::Inbox,
            ),
            Err(SupervisorCatalogCodexPreflightGrantError::ArgvMismatch)
        );

        let matching_spec = ProcessSpec::direct(
            "inbox catalog preflight replay",
            program,
            ["debug", "models"],
            program_parent,
            64,
        );
        let ProcessCommand::Direct {
            program: matching_program,
            args: matching_argv,
        } = &matching_spec.command
        else {
            panic!("direct catalog spec must remain a direct command");
        };
        let grant = SupervisorCatalogCodexPreflightGrant::admit_from_inbox_catalog_intent(
            "run-inbox-catalog-preflight-replay",
            Path::new("/repos/caller-worktree"),
            Path::new("codex"),
        )
        .expect("trusted codex spelling must admit")
        .seal_independently_verified_canonical_binding(program)
        .expect("independently verified canonical must seal");
        grant
            .clone()
            .consume_for_process_binding(
                matching_program,
                &matching_spec.current_dir,
                matching_argv,
                CatalogPreflightOrigin::Inbox,
            )
            .expect("matching Inbox origin grant must consume once");
        assert_eq!(
            grant.consume_for_process_binding(
                matching_program,
                &matching_spec.current_dir,
                matching_argv,
                CatalogPreflightOrigin::Inbox,
            ),
            Err(SupervisorCatalogCodexPreflightGrantError::AlreadyConsumed)
        );
    }

    #[test]
    fn inbox_and_pr_intake_issuers_refuse_untrusted_program_spelling() {
        let inbox_error = SupervisorCatalogCodexPreflightGrant::admit_from_inbox_catalog_intent(
            "run-inbox-catalog-preflight-untrusted",
            Path::new("/repos/caller-worktree"),
            Path::new("/tmp/untrusted-custom-codex"),
        )
        .expect_err("Inbox issuer must refuse non-codex spelling");
        assert_eq!(
            inbox_error,
            SupervisorCatalogCodexPreflightGrantError::UntrustedExpectedProgram
        );

        let pr_intake_error =
            SupervisorCatalogCodexPreflightGrant::admit_from_pr_intake_catalog_intent(
                "run-pr-intake-catalog-preflight-untrusted",
                Path::new("/repos/caller-worktree"),
                Path::new("/tmp/untrusted-custom-codex"),
            )
            .expect_err("PR-intake issuer must refuse non-codex spelling");
        assert_eq!(
            pr_intake_error,
            SupervisorCatalogCodexPreflightGrantError::UntrustedExpectedProgram
        );
    }

    struct AssignmentProcessGrantFixture<'a> {
        run_id: &'a str,
        subject: &'a str,
        attempt: usize,
        model: Option<&'a str>,
        duty: &'a str,
        program: &'a Path,
        argv: &'a [&'a str],
        output_staging: &'a Path,
        cwd: &'a Path,
    }

    impl AssignmentProcessGrantFixture<'_> {
        fn admit_child(self) -> AssignmentProcessLaunchGrant {
            admit_assignment_child_process_intent(
                self.run_id,
                self.subject,
                self.attempt,
                Path::new("codex"),
                self.model,
                self.duty,
            )
            .expect("trusted codex spelling must admit")
            .seal_independently_verified_canonical_binding(
                self.program,
                self.argv.iter().copied(),
                self.output_staging,
                self.cwd,
            )
            .expect("independently verified canonical must seal")
        }

        fn admit_auditor(self) -> AssignmentProcessLaunchGrant {
            admit_parent_auditor_process_intent(
                self.run_id,
                self.subject,
                self.attempt,
                Path::new("codex"),
                self.model,
                self.duty,
            )
            .expect("trusted codex spelling must admit")
            .seal_independently_verified_canonical_binding(
                self.program,
                self.argv.iter().copied(),
                self.output_staging,
                self.cwd,
            )
            .expect("independently verified canonical must seal")
        }

        fn admit_inbox(self) -> AssignmentProcessLaunchGrant {
            admit_inbox_independent_auditor_process_intent(
                self.run_id,
                self.subject,
                self.attempt,
                Path::new("codex"),
                self.model,
                self.duty,
            )
            .expect("trusted codex spelling must admit")
            .seal_independently_verified_canonical_binding(
                self.program,
                self.argv.iter().copied(),
                self.output_staging,
                self.cwd,
            )
            .expect("independently verified canonical must seal")
        }

        fn admit_consult_codex(self) -> AssignmentProcessLaunchGrant {
            admit_consult_codex_process_intent(
                self.run_id,
                self.subject,
                self.attempt,
                Path::new("codex"),
                self.model,
                self.duty,
            )
            .expect("trusted consult-Codex spelling must admit")
            .seal_independently_verified_canonical_binding(
                self.program,
                self.argv.iter().copied(),
                self.output_staging,
                self.cwd,
            )
            .expect("independently verified canonical must seal")
        }

        fn admit_consult_claude(self) -> AssignmentProcessLaunchGrant {
            admit_consult_claude_process_intent(
                self.run_id,
                self.subject,
                self.attempt,
                Path::new("claude"),
                self.model,
                self.duty,
            )
            .expect("trusted consult-Claude spelling must admit")
            .seal_independently_verified_canonical_binding(
                self.program,
                self.argv.iter().copied(),
                self.output_staging,
                self.cwd,
            )
            .expect("independently verified canonical must seal")
        }
    }

    #[test]
    fn assignment_parent_auditor_process_launch_is_irreversible_and_not_child_dispatch() {
        assert!(!SUPERVISOR_CHILD_DISPATCH_MUTATIONS
            .contains(&MutationOperation::AssignmentParentAuditorProcessLaunch));
        assert_eq!(
            autonomous_decision_for(MutationOperation::AssignmentParentAuditorProcessLaunch.id()),
            AutonomousMutationDecision::RequireExplicitGate(
                ExplicitMutationGate::ExplicitAssignmentParentAuditorProcessLaunchGrant
            )
        );
        assert_ne!(
            ExplicitMutationGate::ExplicitAssignmentParentAuditorProcessLaunchGrant,
            ExplicitMutationGate::InternalSealedPinnedExecCapability
        );
        assert_ne!(
            ExplicitMutationGate::ExplicitAssignmentParentAuditorProcessLaunchGrant,
            ExplicitMutationGate::ExplicitSupervisorCatalogCodexPreflightGrant
        );
        assert_ne!(
            ExplicitMutationGate::ExplicitAssignmentParentAuditorProcessLaunchGrant,
            ExplicitMutationGate::ExplicitInboxPrIntakeCatalogCodexPreflightGrant
        );
        assert_ne!(
            MutationOperation::AssignmentParentAuditorProcessLaunch,
            MutationOperation::SupervisorCatalogCodexPreflight
        );
        assert_ne!(
            MutationOperation::AssignmentParentAuditorProcessLaunch,
            MutationOperation::InboxPrIntakeCatalogCodexPreflight
        );
        assert_ne!(
            MutationOperation::AssignmentParentAuditorProcessLaunch,
            MutationOperation::InboxIndependentAuditorProcessLaunch
        );
        assert_ne!(
            ExplicitMutationGate::ExplicitAssignmentParentAuditorProcessLaunchGrant,
            ExplicitMutationGate::ExplicitInboxIndependentAuditorProcessLaunchGrant
        );
    }

    #[test]
    fn inbox_independent_auditor_process_launch_is_irreversible_distinct_gate_and_not_child_dispatch(
    ) {
        assert!(!SUPERVISOR_CHILD_DISPATCH_MUTATIONS
            .contains(&MutationOperation::InboxIndependentAuditorProcessLaunch));
        assert_eq!(
            autonomous_decision_for(MutationOperation::InboxIndependentAuditorProcessLaunch.id()),
            AutonomousMutationDecision::RequireExplicitGate(
                ExplicitMutationGate::ExplicitInboxIndependentAuditorProcessLaunchGrant
            )
        );
        assert_ne!(
            ExplicitMutationGate::ExplicitInboxIndependentAuditorProcessLaunchGrant,
            ExplicitMutationGate::InternalSealedPinnedExecCapability
        );
        assert_ne!(
            ExplicitMutationGate::ExplicitInboxIndependentAuditorProcessLaunchGrant,
            ExplicitMutationGate::ExplicitSupervisorCatalogCodexPreflightGrant
        );
        assert_ne!(
            ExplicitMutationGate::ExplicitInboxIndependentAuditorProcessLaunchGrant,
            ExplicitMutationGate::ExplicitInboxPrIntakeCatalogCodexPreflightGrant
        );
        assert_ne!(
            ExplicitMutationGate::ExplicitInboxIndependentAuditorProcessLaunchGrant,
            ExplicitMutationGate::ExplicitAssignmentParentAuditorProcessLaunchGrant
        );
        assert_ne!(
            MutationOperation::InboxIndependentAuditorProcessLaunch,
            MutationOperation::SupervisorCatalogCodexPreflight
        );
        assert_ne!(
            MutationOperation::InboxIndependentAuditorProcessLaunch,
            MutationOperation::InboxPrIntakeCatalogCodexPreflight
        );
        assert_ne!(
            MutationOperation::InboxIndependentAuditorProcessLaunch,
            MutationOperation::AssignmentParentAuditorProcessLaunch
        );
        assert_ne!(
            AssignmentProcessLaunchKind::InboxIndependentAuditor,
            AssignmentProcessLaunchKind::ParentAuditor
        );
        assert_ne!(
            AssignmentProcessLaunchKind::InboxIndependentAuditor,
            AssignmentProcessLaunchKind::AssignmentChild
        );
    }

    #[test]
    fn inbox_independent_auditor_process_grant_consumes_once_against_final_spec_identity() {
        use crate::process_runner::{ProcessCommand, ProcessSpec};

        let program = Path::new("/usr/bin/codex");
        let cwd = Path::new("/repos/inbox-audit");
        let staging = Path::new("/run/maco/output/auditor-output.json");
        let argv = ["exec", "--sandbox", "read-only"];
        let spec = ProcessSpec::direct("inbox independent auditor binding", program, argv, cwd, 64);
        let ProcessCommand::Direct {
            program: spec_program,
            args: spec_argv,
        } = &spec.command
        else {
            panic!("direct inbox auditor spec must remain a direct command");
        };

        let grant = AssignmentProcessGrantFixture {
            run_id: "run-inbox-audit-1",
            subject: "run-inbox-audit-1-item-1-auditor",
            attempt: 1,
            model: Some("gpt-5.6-sol"),
            duty: INBOX_INDEPENDENT_AUDITOR_PROCESS_DUTY,
            program,
            argv: &argv,
            output_staging: staging,
            cwd,
        }
        .admit_inbox();
        assert_eq!(grant.run_id(), "run-inbox-audit-1");
        assert_eq!(grant.subject(), "run-inbox-audit-1-item-1-auditor");
        assert_eq!(grant.attempt(), 1);
        assert_eq!(
            grant.kind(),
            AssignmentProcessLaunchKind::InboxIndependentAuditor
        );
        assert_eq!(grant.duty(), INBOX_INDEPENDENT_AUDITOR_PROCESS_DUTY);
        assert_eq!(
            grant.independently_verified_canonical_program(),
            Some(program)
        );
        grant
            .clone()
            .consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                staging,
                "run-inbox-audit-1",
                "run-inbox-audit-1-item-1-auditor",
                1,
                AssignmentProcessLaunchKind::InboxIndependentAuditor,
                Some("gpt-5.6-sol"),
                INBOX_INDEPENDENT_AUDITOR_PROCESS_DUTY,
            )
            .expect("matching Inbox independent-auditor grant must consume once");
        assert_eq!(
            grant.consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                staging,
                "run-inbox-audit-1",
                "run-inbox-audit-1-item-1-auditor",
                1,
                AssignmentProcessLaunchKind::InboxIndependentAuditor,
                Some("gpt-5.6-sol"),
                INBOX_INDEPENDENT_AUDITOR_PROCESS_DUTY,
            ),
            Err(AssignmentProcessLaunchGrantError::AlreadyConsumed)
        );
    }

    #[test]
    fn inbox_independent_auditor_process_grant_rejects_parent_auditor_kind_and_catalog_argv() {
        use crate::process_runner::{ProcessCommand, ProcessSpec};

        let program = Path::new("/usr/bin/codex");
        let cwd = Path::new("/repos/inbox-audit");
        let staging = Path::new("/run/maco/output/auditor-output.json");
        let argv = ["exec"];
        let spec = ProcessSpec::direct("inbox kind mismatch", program, argv, cwd, 64);
        let ProcessCommand::Direct {
            program: spec_program,
            args: spec_argv,
        } = &spec.command
        else {
            panic!("direct inbox auditor spec must remain a direct command");
        };
        let inbox_grant = AssignmentProcessGrantFixture {
            run_id: "run-inbox-kind",
            subject: "run-inbox-kind-item-1-auditor",
            attempt: 1,
            model: Some("gpt-5.6-sol"),
            duty: INBOX_INDEPENDENT_AUDITOR_PROCESS_DUTY,
            program,
            argv: &argv,
            output_staging: staging,
            cwd,
        }
        .admit_inbox();
        assert_eq!(
            inbox_grant.consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                staging,
                "run-inbox-kind",
                "run-inbox-kind-item-1-auditor",
                1,
                AssignmentProcessLaunchKind::ParentAuditor,
                Some("gpt-5.6-sol"),
                INBOX_INDEPENDENT_AUDITOR_PROCESS_DUTY,
            ),
            Err(AssignmentProcessLaunchGrantError::KindMismatch)
        );

        let catalog_argv = ["debug", "models"];
        let catalog_spec = ProcessSpec::direct(
            "catalog argv cannot bind inbox auditor",
            program,
            catalog_argv,
            cwd,
            64,
        );
        let ProcessCommand::Direct {
            program: catalog_program,
            args: catalog_args,
        } = &catalog_spec.command
        else {
            panic!("direct catalog spec must remain a direct command");
        };
        let catalog_shaped = AssignmentProcessGrantFixture {
            run_id: "run-inbox-catalog-argv",
            subject: "run-inbox-catalog-argv-item-1-auditor",
            attempt: 1,
            model: Some("gpt-5.6-sol"),
            duty: INBOX_INDEPENDENT_AUDITOR_PROCESS_DUTY,
            program,
            argv: &argv,
            output_staging: staging,
            cwd,
        }
        .admit_inbox();
        assert_eq!(
            catalog_shaped.consume_for_process_binding(
                catalog_program,
                &catalog_spec.current_dir,
                catalog_args,
                staging,
                "run-inbox-catalog-argv",
                "run-inbox-catalog-argv-item-1-auditor",
                1,
                AssignmentProcessLaunchKind::InboxIndependentAuditor,
                Some("gpt-5.6-sol"),
                INBOX_INDEPENDENT_AUDITOR_PROCESS_DUTY,
            ),
            Err(AssignmentProcessLaunchGrantError::ArgvMismatch)
        );
    }

    #[test]
    fn consult_process_launch_is_irreversible_distinct_gate_and_not_child_dispatch() {
        assert!(
            !SUPERVISOR_CHILD_DISPATCH_MUTATIONS.contains(&MutationOperation::ConsultProcessLaunch)
        );
        assert_eq!(
            autonomous_decision_for(MutationOperation::ConsultProcessLaunch.id()),
            AutonomousMutationDecision::RequireExplicitGate(
                ExplicitMutationGate::ExplicitConsultProcessLaunchGrant
            )
        );
        assert_ne!(
            ExplicitMutationGate::ExplicitConsultProcessLaunchGrant,
            ExplicitMutationGate::InternalSealedPinnedExecCapability
        );
        assert_ne!(
            ExplicitMutationGate::ExplicitConsultProcessLaunchGrant,
            ExplicitMutationGate::ExplicitSupervisorCatalogCodexPreflightGrant
        );
        assert_ne!(
            ExplicitMutationGate::ExplicitConsultProcessLaunchGrant,
            ExplicitMutationGate::ExplicitInboxPrIntakeCatalogCodexPreflightGrant
        );
        assert_ne!(
            ExplicitMutationGate::ExplicitConsultProcessLaunchGrant,
            ExplicitMutationGate::ExplicitAssignmentParentAuditorProcessLaunchGrant
        );
        assert_ne!(
            ExplicitMutationGate::ExplicitConsultProcessLaunchGrant,
            ExplicitMutationGate::ExplicitInboxIndependentAuditorProcessLaunchGrant
        );
        assert_ne!(
            MutationOperation::ConsultProcessLaunch,
            MutationOperation::SupervisorCatalogCodexPreflight
        );
        assert_ne!(
            MutationOperation::ConsultProcessLaunch,
            MutationOperation::InboxPrIntakeCatalogCodexPreflight
        );
        assert_ne!(
            MutationOperation::ConsultProcessLaunch,
            MutationOperation::AssignmentParentAuditorProcessLaunch
        );
        assert_ne!(
            MutationOperation::ConsultProcessLaunch,
            MutationOperation::InboxIndependentAuditorProcessLaunch
        );
        assert_ne!(
            AssignmentProcessLaunchKind::ConsultCodex,
            AssignmentProcessLaunchKind::ConsultClaude
        );
        assert_ne!(
            AssignmentProcessLaunchKind::ConsultCodex,
            AssignmentProcessLaunchKind::AssignmentChild
        );
        assert_ne!(
            AssignmentProcessLaunchKind::ConsultCodex,
            AssignmentProcessLaunchKind::ParentAuditor
        );
        assert_ne!(
            AssignmentProcessLaunchKind::ConsultCodex,
            AssignmentProcessLaunchKind::InboxIndependentAuditor
        );
        assert_ne!(
            AssignmentProcessLaunchKind::ConsultClaude,
            AssignmentProcessLaunchKind::InboxIndependentAuditor
        );
        assert_eq!(
            AssignmentProcessLaunchKind::ConsultCodex.trusted_program_spelling(),
            "codex"
        );
        assert_eq!(
            AssignmentProcessLaunchKind::ConsultClaude.trusted_program_spelling(),
            "claude"
        );
        assert_eq!(
            AssignmentProcessLaunchKind::AssignmentChild.trusted_program_spelling(),
            "codex"
        );
        assert_eq!(
            AssignmentProcessLaunchKind::ParentAuditor.trusted_program_spelling(),
            "codex"
        );
        assert_eq!(
            AssignmentProcessLaunchKind::InboxIndependentAuditor.trusted_program_spelling(),
            "codex"
        );
    }

    #[test]
    fn consult_process_grant_consumes_once_against_final_spec_identity() {
        use crate::process_runner::{ProcessCommand, ProcessSpec};

        let program = Path::new("/usr/bin/codex");
        let cwd = Path::new("/repos/consult");
        let staging = Path::new("/run/maco/output/consultant-report.json");
        let argv = ["exec", "--sandbox", "read-only"];
        let spec = ProcessSpec::direct("consult Codex binding", program, argv, cwd, 64);
        let ProcessCommand::Direct {
            program: spec_program,
            args: spec_argv,
        } = &spec.command
        else {
            panic!("direct consult spec must remain a direct command");
        };

        let grant = AssignmentProcessGrantFixture {
            run_id: "run-consult-1",
            subject: "run-consult-1",
            attempt: 1,
            model: None,
            duty: CONSULTANT_PROCESS_DUTY,
            program,
            argv: &argv,
            output_staging: staging,
            cwd,
        }
        .admit_consult_codex();
        assert_eq!(grant.run_id(), "run-consult-1");
        assert_eq!(grant.subject(), "run-consult-1");
        assert_eq!(grant.attempt(), 1);
        assert_eq!(grant.kind(), AssignmentProcessLaunchKind::ConsultCodex);
        assert_eq!(grant.duty(), CONSULTANT_PROCESS_DUTY);
        assert_eq!(
            grant.independently_verified_canonical_program(),
            Some(program)
        );
        grant
            .clone()
            .consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                staging,
                "run-consult-1",
                "run-consult-1",
                1,
                AssignmentProcessLaunchKind::ConsultCodex,
                None,
                CONSULTANT_PROCESS_DUTY,
            )
            .expect("matching consult-Codex grant must consume once");
        assert_eq!(
            grant.consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                staging,
                "run-consult-1",
                "run-consult-1",
                1,
                AssignmentProcessLaunchKind::ConsultCodex,
                None,
                CONSULTANT_PROCESS_DUTY,
            ),
            Err(AssignmentProcessLaunchGrantError::AlreadyConsumed)
        );

        let claude_program = Path::new("/usr/bin/claude");
        let claude_argv = ["-p", "--output-format", "json"];
        let claude_spec = ProcessSpec::direct(
            "consult Claude binding",
            claude_program,
            claude_argv,
            cwd,
            64,
        );
        let ProcessCommand::Direct {
            program: claude_spec_program,
            args: claude_spec_argv,
        } = &claude_spec.command
        else {
            panic!("direct consult Claude spec must remain a direct command");
        };
        let claude_grant = AssignmentProcessGrantFixture {
            run_id: "run-consult-claude-1",
            subject: "run-consult-claude-1",
            attempt: 1,
            model: None,
            duty: CONSULTANT_PROCESS_DUTY,
            program: claude_program,
            argv: &claude_argv,
            output_staging: staging,
            cwd,
        }
        .admit_consult_claude();
        assert_eq!(
            claude_grant.kind(),
            AssignmentProcessLaunchKind::ConsultClaude
        );
        claude_grant
            .clone()
            .consume_for_process_binding(
                claude_spec_program,
                &claude_spec.current_dir,
                claude_spec_argv,
                staging,
                "run-consult-claude-1",
                "run-consult-claude-1",
                1,
                AssignmentProcessLaunchKind::ConsultClaude,
                None,
                CONSULTANT_PROCESS_DUTY,
            )
            .expect("matching consult-Claude grant must consume once");
        assert_eq!(
            claude_grant.consume_for_process_binding(
                claude_spec_program,
                &claude_spec.current_dir,
                claude_spec_argv,
                staging,
                "run-consult-claude-1",
                "run-consult-claude-1",
                1,
                AssignmentProcessLaunchKind::ConsultClaude,
                None,
                CONSULTANT_PROCESS_DUTY,
            ),
            Err(AssignmentProcessLaunchGrantError::AlreadyConsumed)
        );
    }

    #[test]
    fn consult_process_grant_rejects_wrong_kind_identity_runtime_spelling_and_catalog_argv() {
        use crate::process_runner::{ProcessCommand, ProcessSpec};

        let program = Path::new("/usr/bin/codex");
        let cwd = Path::new("/repos/consult");
        let staging = Path::new("/run/maco/output/consultant-report.json");
        let argv = ["exec"];
        let spec = ProcessSpec::direct("consult kind mismatch", program, argv, cwd, 64);
        let ProcessCommand::Direct {
            program: spec_program,
            args: spec_argv,
        } = &spec.command
        else {
            panic!("direct consult spec must remain a direct command");
        };
        let consult_grant = AssignmentProcessGrantFixture {
            run_id: "run-consult-kind",
            subject: "run-consult-kind",
            attempt: 1,
            model: None,
            duty: CONSULTANT_PROCESS_DUTY,
            program,
            argv: &argv,
            output_staging: staging,
            cwd,
        }
        .admit_consult_codex();
        assert_eq!(
            consult_grant.consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                staging,
                "run-consult-kind",
                "run-consult-kind",
                1,
                AssignmentProcessLaunchKind::InboxIndependentAuditor,
                None,
                CONSULTANT_PROCESS_DUTY,
            ),
            Err(AssignmentProcessLaunchGrantError::KindMismatch)
        );
        assert_eq!(
            AssignmentProcessGrantFixture {
                run_id: "run-consult-kind",
                subject: "run-consult-kind",
                attempt: 1,
                model: None,
                duty: CONSULTANT_PROCESS_DUTY,
                program,
                argv: &argv,
                output_staging: staging,
                cwd,
            }
            .admit_consult_codex()
            .consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                staging,
                "run-consult-kind",
                "run-consult-kind",
                1,
                AssignmentProcessLaunchKind::ConsultClaude,
                None,
                CONSULTANT_PROCESS_DUTY,
            ),
            Err(AssignmentProcessLaunchGrantError::KindMismatch)
        );
        assert_eq!(
            AssignmentProcessGrantFixture {
                run_id: "run-consult-id",
                subject: "run-consult-id",
                attempt: 1,
                model: None,
                duty: CONSULTANT_PROCESS_DUTY,
                program,
                argv: &argv,
                output_staging: staging,
                cwd,
            }
            .admit_consult_codex()
            .consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                staging,
                "run-other-consult",
                "run-consult-id",
                1,
                AssignmentProcessLaunchKind::ConsultCodex,
                None,
                CONSULTANT_PROCESS_DUTY,
            ),
            Err(AssignmentProcessLaunchGrantError::IdentityMismatch)
        );
        assert_eq!(
            AssignmentProcessGrantFixture {
                run_id: "run-consult-duty",
                subject: "run-consult-duty",
                attempt: 1,
                model: None,
                duty: CONSULTANT_PROCESS_DUTY,
                program,
                argv: &argv,
                output_staging: staging,
                cwd,
            }
            .admit_consult_codex()
            .consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                staging,
                "run-consult-duty",
                "run-consult-duty",
                1,
                AssignmentProcessLaunchKind::ConsultCodex,
                None,
                INBOX_INDEPENDENT_AUDITOR_PROCESS_DUTY,
            ),
            Err(AssignmentProcessLaunchGrantError::IdentityMismatch)
        );
        assert_eq!(
            AssignmentProcessGrantFixture {
                run_id: "run-consult-model",
                subject: "run-consult-model",
                attempt: 1,
                model: None,
                duty: CONSULTANT_PROCESS_DUTY,
                program,
                argv: &argv,
                output_staging: staging,
                cwd,
            }
            .admit_consult_codex()
            .consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                staging,
                "run-consult-model",
                "run-consult-model",
                1,
                AssignmentProcessLaunchKind::ConsultCodex,
                Some("gpt-5.6-sol"),
                CONSULTANT_PROCESS_DUTY,
            ),
            Err(AssignmentProcessLaunchGrantError::IdentityMismatch)
        );

        let catalog_argv = ["debug", "models"];
        let catalog_spec = ProcessSpec::direct(
            "catalog argv cannot bind consult",
            program,
            catalog_argv,
            cwd,
            64,
        );
        let ProcessCommand::Direct {
            program: catalog_program,
            args: catalog_args,
        } = &catalog_spec.command
        else {
            panic!("direct catalog spec must remain a direct command");
        };
        assert_eq!(
            AssignmentProcessGrantFixture {
                run_id: "run-consult-catalog-argv",
                subject: "run-consult-catalog-argv",
                attempt: 1,
                model: None,
                duty: CONSULTANT_PROCESS_DUTY,
                program,
                argv: &argv,
                output_staging: staging,
                cwd,
            }
            .admit_consult_codex()
            .consume_for_process_binding(
                catalog_program,
                &catalog_spec.current_dir,
                catalog_args,
                staging,
                "run-consult-catalog-argv",
                "run-consult-catalog-argv",
                1,
                AssignmentProcessLaunchKind::ConsultCodex,
                None,
                CONSULTANT_PROCESS_DUTY,
            ),
            Err(AssignmentProcessLaunchGrantError::ArgvMismatch)
        );

        assert_eq!(
            admit_consult_codex_process_intent(
                "run-consult-codex-untrusted",
                "run-consult-codex-untrusted",
                1,
                Path::new("claude"),
                None,
                CONSULTANT_PROCESS_DUTY,
            )
            .expect_err("consult-Codex issuer must refuse non-codex spelling"),
            AssignmentProcessLaunchGrantError::UntrustedExpectedProgram
        );
        assert_eq!(
            admit_consult_claude_process_intent(
                "run-consult-claude-untrusted",
                "run-consult-claude-untrusted",
                1,
                Path::new("codex"),
                None,
                CONSULTANT_PROCESS_DUTY,
            )
            .expect_err("consult-Claude issuer must refuse non-claude spelling"),
            AssignmentProcessLaunchGrantError::UntrustedExpectedProgram
        );
        assert_eq!(
            admit_assignment_child_process_intent(
                "run-child-claude-spelling",
                "assignment-a",
                1,
                Path::new("claude"),
                None,
                "worker-duty",
            )
            .expect_err("child issuer must not broaden trusted spelling to claude"),
            AssignmentProcessLaunchGrantError::UntrustedExpectedProgram
        );
        assert_eq!(
            admit_inbox_independent_auditor_process_intent(
                "run-inbox-claude-spelling",
                "run-inbox-claude-spelling-item-1-auditor",
                1,
                Path::new("claude"),
                None,
                INBOX_INDEPENDENT_AUDITOR_PROCESS_DUTY,
            )
            .expect_err("Inbox issuer must not broaden trusted spelling to claude"),
            AssignmentProcessLaunchGrantError::UntrustedExpectedProgram
        );
    }

    #[test]
    fn assignment_process_grant_consumes_once_against_final_spec_identity() {
        use crate::process_runner::{ProcessCommand, ProcessSpec};

        let program = Path::new("/usr/bin/codex");
        let cwd = Path::new("/worktrees/assignment-child");
        let staging = Path::new("/run/maco/output/last-message.raw");
        let argv = ["exec", "--sandbox", "workspace-write"];
        let spec = ProcessSpec::direct("assignment child binding", program, argv, cwd, 64);
        let ProcessCommand::Direct {
            program: spec_program,
            args: spec_argv,
        } = &spec.command
        else {
            panic!("direct assignment spec must remain a direct command");
        };

        let grant = AssignmentProcessGrantFixture {
            run_id: "run-assignment-1",
            subject: "assignment-a",
            attempt: 1,
            model: Some("gpt-5.4"),
            duty: "worker-duty",
            program,
            argv: &argv,
            output_staging: staging,
            cwd,
        }
        .admit_child();
        assert_eq!(grant.run_id(), "run-assignment-1");
        assert_eq!(grant.subject(), "assignment-a");
        assert_eq!(grant.attempt(), 1);
        assert_eq!(grant.kind(), AssignmentProcessLaunchKind::AssignmentChild);
        assert_eq!(
            grant.independently_verified_canonical_program(),
            Some(program)
        );
        grant
            .clone()
            .consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                staging,
                "run-assignment-1",
                "assignment-a",
                1,
                AssignmentProcessLaunchKind::AssignmentChild,
                Some("gpt-5.4"),
                "worker-duty",
            )
            .expect("matching assignment-child grant must consume once");
        assert_eq!(
            grant.consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                staging,
                "run-assignment-1",
                "assignment-a",
                1,
                AssignmentProcessLaunchKind::AssignmentChild,
                Some("gpt-5.4"),
                "worker-duty",
            ),
            Err(AssignmentProcessLaunchGrantError::AlreadyConsumed)
        );
    }

    #[test]
    fn assignment_process_grant_rejects_wrong_kind_and_identity() {
        use crate::process_runner::{ProcessCommand, ProcessSpec};

        let program = Path::new("/usr/bin/codex");
        let cwd = Path::new("/worktrees/assignment-child");
        let staging = Path::new("/run/maco/output/last-message.raw");
        let argv = ["exec"];
        let spec = ProcessSpec::direct("assignment identity", program, argv, cwd, 64);
        let ProcessCommand::Direct {
            program: spec_program,
            args: spec_argv,
        } = &spec.command
        else {
            panic!("direct assignment spec must remain a direct command");
        };
        let bind =
            |run_id: &str, subject: &str, attempt: usize, model: Option<&str>, duty: &str| {
                AssignmentProcessGrantFixture {
                    run_id,
                    subject,
                    attempt,
                    model,
                    duty,
                    program,
                    argv: &argv,
                    output_staging: staging,
                    cwd,
                }
                .admit_child()
            };
        assert_eq!(
            bind(
                "run-assignment-kind",
                "assignment-a",
                2,
                Some("gpt-5.4"),
                "worker-duty"
            )
            .consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                staging,
                "run-assignment-kind",
                "assignment-a",
                2,
                AssignmentProcessLaunchKind::ParentAuditor,
                Some("gpt-5.4"),
                "worker-duty",
            ),
            Err(AssignmentProcessLaunchGrantError::KindMismatch)
        );
        assert_eq!(
            bind(
                "run-assignment-kind",
                "assignment-a",
                2,
                Some("gpt-5.4"),
                "worker-duty"
            )
            .consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                staging,
                "run-other",
                "assignment-a",
                2,
                AssignmentProcessLaunchKind::AssignmentChild,
                Some("gpt-5.4"),
                "worker-duty",
            ),
            Err(AssignmentProcessLaunchGrantError::IdentityMismatch)
        );
        assert_eq!(
            bind(
                "run-assignment-kind",
                "assignment-a",
                2,
                Some("gpt-5.4"),
                "worker-duty"
            )
            .consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                staging,
                "run-assignment-kind",
                "assignment-b",
                2,
                AssignmentProcessLaunchKind::AssignmentChild,
                Some("gpt-5.4"),
                "worker-duty",
            ),
            Err(AssignmentProcessLaunchGrantError::IdentityMismatch)
        );
        assert_eq!(
            bind(
                "run-assignment-kind",
                "assignment-a",
                2,
                Some("gpt-5.4"),
                "worker-duty"
            )
            .consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                staging,
                "run-assignment-kind",
                "assignment-a",
                9,
                AssignmentProcessLaunchKind::AssignmentChild,
                Some("gpt-5.4"),
                "worker-duty",
            ),
            Err(AssignmentProcessLaunchGrantError::IdentityMismatch)
        );
        assert_eq!(
            bind(
                "run-assignment-kind",
                "assignment-a",
                2,
                Some("gpt-5.4"),
                "worker-duty"
            )
            .consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                staging,
                "run-assignment-kind",
                "assignment-a",
                2,
                AssignmentProcessLaunchKind::AssignmentChild,
                Some("other-model"),
                "worker-duty",
            ),
            Err(AssignmentProcessLaunchGrantError::IdentityMismatch)
        );
    }

    #[test]
    fn catalog_preflight_grant_cannot_consume_as_assignment_process_worker() {
        use crate::process_runner::{ProcessCommand, ProcessSpec};

        let program = Path::new("/usr/bin/codex");
        let worker_argv = ["exec", "--sandbox", "workspace-write"];
        let spec = ProcessSpec::direct(
            "catalog grant cannot bind worker argv",
            program,
            worker_argv,
            Path::new("/worktrees/assignment-child"),
            64,
        );
        let ProcessCommand::Direct {
            program: spec_program,
            args: spec_argv,
        } = &spec.command
        else {
            panic!("direct spec must remain a direct command");
        };
        let grant = SupervisorCatalogCodexPreflightGrant::admit_from_supervisor_catalog_intent(
            "run-catalog-as-worker",
            Path::new("/repos/caller-worktree"),
            Path::new("codex"),
        )
        .expect("trusted codex spelling must admit")
        .seal_independently_verified_canonical_binding(program)
        .expect("independently verified canonical must seal");
        assert_eq!(
            grant.consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                CatalogPreflightOrigin::Supervisor,
            ),
            Err(SupervisorCatalogCodexPreflightGrantError::ArgvMismatch)
        );
    }

    #[test]
    fn assignment_process_grant_rejects_same_basename_tmp_codex_and_untrusted_spelling() {
        use crate::process_runner::{ProcessCommand, ProcessSpec};

        let independently_verified_canonical = Path::new("/usr/bin/codex");
        let wrong_program = Path::new("/tmp/codex");
        let cwd = Path::new("/worktrees/assignment-child");
        let staging = Path::new("/run/maco/output/last-message.raw");
        let argv = ["exec"];
        assert_eq!(
            wrong_program.file_name(),
            independently_verified_canonical.file_name()
        );
        assert_ne!(wrong_program, independently_verified_canonical);
        let spec = ProcessSpec::direct(
            "assignment process same-basename wrong program",
            wrong_program,
            argv,
            cwd,
            64,
        );
        let ProcessCommand::Direct {
            program: spec_program,
            args: spec_argv,
        } = &spec.command
        else {
            panic!("direct assignment spec must remain a direct command");
        };
        let grant = AssignmentProcessGrantFixture {
            run_id: "run-assignment-tmp-codex",
            subject: "assignment-a",
            attempt: 1,
            model: None,
            duty: "worker-duty",
            program: independently_verified_canonical,
            argv: &argv,
            output_staging: staging,
            cwd,
        }
        .admit_child();
        assert_eq!(
            grant.consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                staging,
                "run-assignment-tmp-codex",
                "assignment-a",
                1,
                AssignmentProcessLaunchKind::AssignmentChild,
                None,
                "worker-duty",
            ),
            Err(AssignmentProcessLaunchGrantError::ProgramMismatch)
        );
        assert_eq!(
            admit_assignment_child_process_intent(
                "run-assignment-untrusted",
                "assignment-a",
                1,
                Path::new("/tmp/untrusted-custom-codex"),
                None,
                "worker-duty",
            )
            .expect_err("production issuer must refuse non-codex spelling"),
            AssignmentProcessLaunchGrantError::UntrustedExpectedProgram
        );
        assert_eq!(
            admit_parent_auditor_process_intent(
                "run-auditor-untrusted",
                "auditor-a",
                1,
                Path::new("/tmp/untrusted-custom-codex"),
                None,
                "auditor-duty",
            )
            .expect_err("parent-auditor issuer must refuse non-codex spelling"),
            AssignmentProcessLaunchGrantError::UntrustedExpectedProgram
        );
    }

    #[test]
    fn assignment_process_grant_consumes_sealed_canonical_with_non_codex_filename() {
        use crate::process_runner::{ProcessCommand, ProcessSpec};

        let independently_verified_canonical = Path::new("/opt/codex-lib/codex.js");
        let sealed_parent = Path::new("/opt/codex-lib");
        let cwd = Path::new("/worktrees/assignment-child");
        let staging = Path::new("/run/maco/output/last-message.raw");
        let argv = ["exec", "--json"];
        assert_ne!(
            independently_verified_canonical.file_name(),
            Some(OsStr::new("codex"))
        );
        assert_eq!(
            independently_verified_canonical.parent(),
            Some(sealed_parent)
        );
        let spec = ProcessSpec::direct(
            "assignment process non-codex canonical filename",
            independently_verified_canonical,
            argv,
            cwd,
            64,
        );
        let ProcessCommand::Direct {
            program: spec_program,
            args: spec_argv,
        } = &spec.command
        else {
            panic!("direct assignment spec must remain a direct command");
        };
        let grant = AssignmentProcessGrantFixture {
            run_id: "run-auditor-codex-js",
            subject: "auditor-a",
            attempt: 3,
            model: Some("o4-mini"),
            duty: "parent-auditor-duty",
            program: independently_verified_canonical,
            argv: &argv,
            output_staging: staging,
            cwd,
        }
        .admit_auditor();
        assert_eq!(
            grant.independently_verified_canonical_parent(),
            Some(sealed_parent)
        );
        grant
            .consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                staging,
                "run-auditor-codex-js",
                "auditor-a",
                3,
                AssignmentProcessLaunchKind::ParentAuditor,
                Some("o4-mini"),
                "parent-auditor-duty",
            )
            .expect("sealed non-codex canonical filename must consume when spec matches");
    }

    #[test]
    fn assignment_process_grant_rejects_staging_and_canonical_parent_mismatch() {
        use crate::process_runner::{ProcessCommand, ProcessSpec};

        let program = Path::new("/usr/bin/codex");
        let cwd = Path::new("/worktrees/assignment-child");
        let staging = Path::new("/run/maco/output/last-message.raw");
        let argv = ["exec"];
        let spec = ProcessSpec::direct("assignment staging parent", program, argv, cwd, 64);
        let ProcessCommand::Direct {
            program: spec_program,
            args: spec_argv,
        } = &spec.command
        else {
            panic!("direct assignment spec must remain a direct command");
        };
        let grant = AssignmentProcessGrantFixture {
            run_id: "run-assignment-staging",
            subject: "assignment-a",
            attempt: 1,
            model: None,
            duty: "worker-duty",
            program,
            argv: &argv,
            output_staging: staging,
            cwd,
        }
        .admit_child();
        assert_eq!(
            grant.consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                Path::new("/run/maco/output/other-staging.raw"),
                "run-assignment-staging",
                "assignment-a",
                1,
                AssignmentProcessLaunchKind::AssignmentChild,
                None,
                "worker-duty",
            ),
            Err(AssignmentProcessLaunchGrantError::OutputStagingMismatch)
        );

        let grant = AssignmentProcessGrantFixture {
            run_id: "run-assignment-parent",
            subject: "assignment-a",
            attempt: 1,
            model: None,
            duty: "worker-duty",
            program,
            argv: &argv,
            output_staging: staging,
            cwd,
        }
        .admit_child()
        .with_independently_verified_canonical_parent_for_test(PathBuf::from("/tmp"));
        assert_eq!(
            grant.independently_verified_canonical_parent(),
            Some(Path::new("/tmp"))
        );
        assert_eq!(
            grant.consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                staging,
                "run-assignment-parent",
                "assignment-a",
                1,
                AssignmentProcessLaunchKind::AssignmentChild,
                None,
                "worker-duty",
            ),
            Err(AssignmentProcessLaunchGrantError::ProgramMismatch)
        );
    }
}
