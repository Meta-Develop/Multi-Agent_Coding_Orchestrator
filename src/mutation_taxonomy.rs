//! Versioned mutation taxonomy and autonomous-admission decision boundary.
//!
//! Every Supervisor entrypoint and generated-follow-up queue lifecycle uses
//! this conservative policy before its first production mutation. Admission
//! returns a single-use authority bound to one canonical effective manifest;
//! every existing claim, containment, review, and effect gate remains
//! independently required.

use crate::artifacts::state_auth::sha256_hex;
use serde::Serialize;

/// Current reviewed registry version.
///
/// Version 4 adds the exact Supervisor and generated-follow-up lifecycle
/// boundaries consumed by effective-mutation manifests.
pub const MUTATION_TAXONOMY_VERSION: u32 = 4;

/// Current canonical effective Supervisor manifest version.
pub const EFFECTIVE_SUPERVISOR_MUTATION_MANIFEST_VERSION: u32 = 1;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
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
    BoundSupervisorRunLifecycleAuthority,
    VerifiedSupervisorProcessLifecycleAuthority,
    VerifiedSupervisorPrimaryObjectImportAuthority,
    BoundSupervisorFieldGuideMutationAuthority,
    BoundGeneratedFollowUpQueueLifecycleAuthority,
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
            Self::BoundSupervisorRunLifecycleAuthority => {
                "bound-supervisor-run-lifecycle-authority"
            }
            Self::VerifiedSupervisorProcessLifecycleAuthority => {
                "verified-supervisor-process-lifecycle-authority"
            }
            Self::VerifiedSupervisorPrimaryObjectImportAuthority => {
                "verified-supervisor-primary-object-import-authority"
            }
            Self::BoundSupervisorFieldGuideMutationAuthority => {
                "bound-supervisor-field-guide-mutation-authority"
            }
            Self::BoundGeneratedFollowUpQueueLifecycleAuthority => {
                "bound-generated-follow-up-queue-lifecycle-authority"
            }
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
    SupervisorRunArtifactReserve,
    SupervisorRunArtifactWriteAppend,
    SupervisorRunArtifactAuthenticatedFinalize,
    SupervisorScratchEvidenceCleanup,
    SupervisorRefusalEvidenceWrite,
    SupervisorCheckpointJournalLifecycle,
    SupervisorOrchestrationJournalLifecycle,
    SupervisorCoordinationStoreBootstrap,
    SupervisorClaimAcquisitionTelemetry,
    SupervisorMandatoryControlProvision,
    SupervisorPrimaryObjectDatabaseImport,
    SupervisorProcessRegister,
    SupervisorProcessSpawn,
    SupervisorProcessOutputStage,
    SupervisorProcessOutputWrite,
    SupervisorProcessOutputCleanup,
    SupervisorProcessTerminate,
    SupervisorFieldGuideMutation,
    GeneratedFollowUpQueueReserve,
    GeneratedFollowUpQueueWriteAppend,
    GeneratedFollowUpQueueAuthenticatedCommit,
    GeneratedFollowUpQueueClaim,
    GeneratedFollowUpQueueRelease,
    GeneratedFollowUpRefusalEvidenceWrite,
    GeneratedSupervisorPlanStage,
}

impl MutationOperation {
    /// Complete enum inventory, kept explicit so additions cannot evade tests.
    pub const ALL: [Self; 62] = [
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
        Self::SupervisorRunArtifactReserve,
        Self::SupervisorRunArtifactWriteAppend,
        Self::SupervisorRunArtifactAuthenticatedFinalize,
        Self::SupervisorScratchEvidenceCleanup,
        Self::SupervisorRefusalEvidenceWrite,
        Self::SupervisorCheckpointJournalLifecycle,
        Self::SupervisorOrchestrationJournalLifecycle,
        Self::SupervisorCoordinationStoreBootstrap,
        Self::SupervisorClaimAcquisitionTelemetry,
        Self::SupervisorMandatoryControlProvision,
        Self::SupervisorPrimaryObjectDatabaseImport,
        Self::SupervisorProcessRegister,
        Self::SupervisorProcessSpawn,
        Self::SupervisorProcessOutputStage,
        Self::SupervisorProcessOutputWrite,
        Self::SupervisorProcessOutputCleanup,
        Self::SupervisorProcessTerminate,
        Self::SupervisorFieldGuideMutation,
        Self::GeneratedFollowUpQueueReserve,
        Self::GeneratedFollowUpQueueWriteAppend,
        Self::GeneratedFollowUpQueueAuthenticatedCommit,
        Self::GeneratedFollowUpQueueClaim,
        Self::GeneratedFollowUpQueueRelease,
        Self::GeneratedFollowUpRefusalEvidenceWrite,
        Self::GeneratedSupervisorPlanStage,
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
            Self::SupervisorRunArtifactReserve => "supervisor-run-artifact-reserve",
            Self::SupervisorRunArtifactWriteAppend => "supervisor-run-artifact-write-append",
            Self::SupervisorRunArtifactAuthenticatedFinalize => {
                "supervisor-run-artifact-authenticated-finalize"
            }
            Self::SupervisorScratchEvidenceCleanup => "supervisor-scratch-evidence-cleanup",
            Self::SupervisorRefusalEvidenceWrite => "supervisor-refusal-evidence-write",
            Self::SupervisorCheckpointJournalLifecycle => "supervisor-checkpoint-journal-lifecycle",
            Self::SupervisorOrchestrationJournalLifecycle => {
                "supervisor-orchestration-journal-lifecycle"
            }
            Self::SupervisorCoordinationStoreBootstrap => "supervisor-coordination-store-bootstrap",
            Self::SupervisorClaimAcquisitionTelemetry => "supervisor-claim-acquisition-telemetry",
            Self::SupervisorMandatoryControlProvision => "supervisor-mandatory-control-provision",
            Self::SupervisorPrimaryObjectDatabaseImport => {
                "supervisor-primary-object-database-import"
            }
            Self::SupervisorProcessRegister => "supervisor-process-register",
            Self::SupervisorProcessSpawn => "supervisor-process-spawn",
            Self::SupervisorProcessOutputStage => "supervisor-process-output-stage",
            Self::SupervisorProcessOutputWrite => "supervisor-process-output-write",
            Self::SupervisorProcessOutputCleanup => "supervisor-process-output-cleanup",
            Self::SupervisorProcessTerminate => "supervisor-process-terminate",
            Self::SupervisorFieldGuideMutation => "supervisor-field-guide-mutation",
            Self::GeneratedFollowUpQueueReserve => "generated-follow-up-queue-reserve",
            Self::GeneratedFollowUpQueueWriteAppend => "generated-follow-up-queue-write-append",
            Self::GeneratedFollowUpQueueAuthenticatedCommit => {
                "generated-follow-up-queue-authenticated-commit"
            }
            Self::GeneratedFollowUpQueueClaim => "generated-follow-up-queue-claim",
            Self::GeneratedFollowUpQueueRelease => "generated-follow-up-queue-release",
            Self::GeneratedFollowUpRefusalEvidenceWrite => {
                "generated-follow-up-refusal-evidence-write"
            }
            Self::GeneratedSupervisorPlanStage => "generated-supervisor-plan-stage",
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
    reversible(
        MutationOperation::SupervisorRunArtifactReserve,
        "Reserves a new isolated run-artifact container before it contains accepted work or evidence.",
    ),
    irreversible(
        MutationOperation::SupervisorRunArtifactWriteAppend,
        "Writes durable run evidence whose exact prior artifact state has no supported lossless restoration path.",
        ExplicitMutationGate::BoundSupervisorRunLifecycleAuthority,
    ),
    irreversible(
        MutationOperation::SupervisorRunArtifactAuthenticatedFinalize,
        "Commits authenticated terminal run evidence and intentionally makes the finalized artifact immutable.",
        ExplicitMutationGate::BoundSupervisorRunLifecycleAuthority,
    ),
    irreversible(
        MutationOperation::SupervisorScratchEvidenceCleanup,
        "Deletes or consumes private scratch evidence after import, and recomputation is not restoration from retained state.",
        ExplicitMutationGate::BoundSupervisorRunLifecycleAuthority,
    ),
    irreversible(
        MutationOperation::SupervisorRefusalEvidenceWrite,
        "Persists refusal evidence in the bound run lifecycle and no supported operation restores the exact prior audit history.",
        ExplicitMutationGate::BoundSupervisorRunLifecycleAuthority,
    ),
    irreversible(
        MutationOperation::SupervisorCheckpointJournalLifecycle,
        "Creates and advances authenticated checkpoint history used for recovery and dispatch ordering.",
        ExplicitMutationGate::BoundSupervisorRunLifecycleAuthority,
    ),
    irreversible(
        MutationOperation::SupervisorOrchestrationJournalLifecycle,
        "Creates and appends authenticated orchestration history whose removal would destroy audit evidence.",
        ExplicitMutationGate::BoundSupervisorRunLifecycleAuthority,
    ),
    irreversible(
        MutationOperation::SupervisorCoordinationStoreBootstrap,
        "May initialize repository-bound authenticated coordination state without a supported rollback to the absent namespace.",
        ExplicitMutationGate::BoundSupervisorRunLifecycleAuthority,
    ),
    irreversible(
        MutationOperation::SupervisorClaimAcquisitionTelemetry,
        "Appends authenticated claim-frequency telemetry after claim acquisition and does not rewind consumers to the prior history.",
        ExplicitMutationGate::BoundSupervisorRunLifecycleAuthority,
    ),
    reversible(
        MutationOperation::SupervisorMandatoryControlProvision,
        "Creates bounded control directories only inside a disposable managed child lane and retains the lane baseline.",
    ),
    irreversible(
        MutationOperation::SupervisorPrimaryObjectDatabaseImport,
        "Imports verified child commit objects into the primary object database without a supported exact object-pruning rollback.",
        ExplicitMutationGate::VerifiedSupervisorPrimaryObjectImportAuthority,
    ),
    irreversible(
        MutationOperation::SupervisorProcessRegister,
        "Persists current-run process identity and best-effort guard cleanup cannot guarantee restoration if unregister fails.",
        ExplicitMutationGate::BoundSupervisorRunLifecycleAuthority,
    ),
    irreversible(
        MutationOperation::SupervisorProcessSpawn,
        "Starts an external child or auditor whose execution time and possible effects cannot be undone.",
        ExplicitMutationGate::VerifiedSupervisorProcessLifecycleAuthority,
    ),
    reversible(
        MutationOperation::SupervisorProcessOutputStage,
        "Creates an exclusive private output-staging container under the reviewed runtime root before output is accepted.",
    ),
    irreversible(
        MutationOperation::SupervisorProcessOutputWrite,
        "Writes child or auditor output and execution evidence that cannot be rolled back without discarding run evidence.",
        ExplicitMutationGate::VerifiedSupervisorProcessLifecycleAuthority,
    ),
    irreversible(
        MutationOperation::SupervisorProcessOutputCleanup,
        "Removes private process-output staging or setup residue and does not retain a byte-for-byte restore operation for every path.",
        ExplicitMutationGate::VerifiedSupervisorProcessLifecycleAuthority,
    ),
    irreversible(
        MutationOperation::SupervisorProcessTerminate,
        "Terminates a bound child process on cancellation, timeout, or failed containment and cannot restore its exact execution state.",
        ExplicitMutationGate::VerifiedSupervisorProcessLifecycleAuthority,
    ),
    irreversible(
        MutationOperation::SupervisorFieldGuideMutation,
        "Appends or deterministically curates authenticated field-guide state used by later runs.",
        ExplicitMutationGate::BoundSupervisorFieldGuideMutationAuthority,
    ),
    reversible(
        MutationOperation::GeneratedFollowUpQueueReserve,
        "Reserves a new source-bound queue container before generated tasks are committed.",
    ),
    irreversible(
        MutationOperation::GeneratedFollowUpQueueWriteAppend,
        "Writes authenticated generated-follow-up lifecycle records whose exact prior audit state is not restored.",
        ExplicitMutationGate::BoundGeneratedFollowUpQueueLifecycleAuthority,
    ),
    irreversible(
        MutationOperation::GeneratedFollowUpQueueAuthenticatedCommit,
        "Commits the source-bound generated task batch and terminal observations into authenticated queue history.",
        ExplicitMutationGate::BoundGeneratedFollowUpQueueLifecycleAuthority,
    ),
    reversible(
        MutationOperation::GeneratedFollowUpQueueClaim,
        "Claims one exact queued item inside the bounded queue and can release it before dispatch.",
    ),
    irreversible(
        MutationOperation::GeneratedFollowUpQueueRelease,
        "Releases or terminalizes a queued item and cannot deterministically recreate the same intervening queue ownership state.",
        ExplicitMutationGate::BoundGeneratedFollowUpQueueLifecycleAuthority,
    ),
    irreversible(
        MutationOperation::GeneratedFollowUpRefusalEvidenceWrite,
        "Persists a generated-item refusal in authenticated queue history without a supported audit rewind.",
        ExplicitMutationGate::BoundGeneratedFollowUpQueueLifecycleAuthority,
    ),
    reversible(
        MutationOperation::GeneratedSupervisorPlanStage,
        "Creates a private temporary exact-plan staging file that is retained only for the bounded subordinate call.",
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

/// Dispatch identity bound into one exact effective Supervisor mutation set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum EffectiveSupervisorDispatchIdentity {
    Root,
    GeneratedFollowUpSubordinate {
        parent_run_id: String,
    },
    EvidenceOnlyReaudit {
        source_run_id: String,
        assignment_id: String,
    },
    GeneratedFollowUpQueue {
        source_run_id: String,
        task_count: usize,
    },
}

impl EffectiveSupervisorDispatchIdentity {
    fn canonical_id(&self) -> String {
        match self {
            Self::Root => "root".to_string(),
            Self::GeneratedFollowUpSubordinate { parent_run_id } => {
                format!("generated-follow-up-subordinate:{parent_run_id}")
            }
            Self::EvidenceOnlyReaudit {
                source_run_id,
                assignment_id,
            } => format!("evidence-only-reaudit:{source_run_id}:{assignment_id}"),
            Self::GeneratedFollowUpQueue {
                source_run_id,
                task_count,
            } => format!("generated-follow-up-queue:{source_run_id}:{task_count}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EffectiveSupervisorExecutionRuntime {
    Verified,
    NonpublishableSimulation,
}

impl EffectiveSupervisorExecutionRuntime {
    const fn canonical_id(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::NonpublishableSimulation => "nonpublishable-simulation",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EffectiveSupervisorWorktreeMode {
    BoundCreateOrReuse,
    ExistingOnly,
    PrimaryWorktree,
    NonpublishableSimulation,
    NotApplicable,
    #[cfg(test)]
    TestOnly,
    #[cfg(test)]
    VerifiedTestOnly,
}

impl EffectiveSupervisorWorktreeMode {
    const fn canonical_id(self) -> &'static str {
        match self {
            Self::BoundCreateOrReuse => "bound-create-or-reuse",
            Self::ExistingOnly => "existing-only",
            Self::PrimaryWorktree => "primary-worktree",
            Self::NonpublishableSimulation => "nonpublishable-simulation",
            Self::NotApplicable => "not-applicable",
            #[cfg(test)]
            Self::TestOnly => "test-only",
            #[cfg(test)]
            Self::VerifiedTestOnly => "verified-test-only",
        }
    }
}

/// One operation ID in an exact effective manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct EffectiveSupervisorMutationOperation {
    operation_id: String,
}

impl EffectiveSupervisorMutationOperation {
    fn registered(operation: MutationOperation) -> Self {
        Self {
            operation_id: operation.id().to_string(),
        }
    }

    pub(crate) fn operation_id(&self) -> &str {
        &self.operation_id
    }
}

/// Construction input for one canonical effective Supervisor mutation manifest.
pub(crate) struct EffectiveSupervisorMutationManifestInput {
    pub(crate) run_id: String,
    pub(crate) parent_node: Option<String>,
    pub(crate) normalized_plan_sha256: String,
    pub(crate) dispatch_identity: EffectiveSupervisorDispatchIdentity,
    pub(crate) execution_runtime: EffectiveSupervisorExecutionRuntime,
    pub(crate) worktree_mode: EffectiveSupervisorWorktreeMode,
    pub(crate) operations: Vec<MutationOperation>,
    /// Gates demonstrated by the production control-flow inputs that selected
    /// this exact mutation surface. The registry independently determines
    /// which gates are required; construction never manufactures them from
    /// the operation rows themselves.
    pub(crate) demonstrated_gates: Vec<ExplicitMutationGate>,
}

/// Exact post-override Supervisor mutation set admitted for one dispatch.
///
/// The serialized form is audit evidence only. It does not carry authority;
/// only the non-serializable grant produced by consuming the common
/// authorizer's single-use authority can admit the matching scheduler call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct EffectiveSupervisorMutationManifest {
    version: u32,
    run_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_node: Option<String>,
    normalized_plan_sha256: String,
    dispatch_identity: EffectiveSupervisorDispatchIdentity,
    execution_runtime: EffectiveSupervisorExecutionRuntime,
    worktree_mode: EffectiveSupervisorWorktreeMode,
    operations: Vec<EffectiveSupervisorMutationOperation>,
    demonstrated_gates: Vec<ExplicitMutationGate>,
    canonical_manifest_sha256: String,
}

impl EffectiveSupervisorMutationManifest {
    pub(crate) fn new(input: EffectiveSupervisorMutationManifestInput) -> Self {
        let mut operations = input
            .operations
            .into_iter()
            .map(EffectiveSupervisorMutationOperation::registered)
            .collect::<Vec<_>>();
        operations.sort_by(|left, right| left.operation_id.cmp(&right.operation_id));
        operations.dedup_by(|left, right| left.operation_id == right.operation_id);
        let mut demonstrated_gates = input.demonstrated_gates;
        demonstrated_gates.sort_by_key(|gate| gate.id());
        demonstrated_gates.dedup();
        let mut manifest = Self {
            version: EFFECTIVE_SUPERVISOR_MUTATION_MANIFEST_VERSION,
            run_id: input.run_id,
            parent_node: input.parent_node,
            normalized_plan_sha256: input.normalized_plan_sha256,
            dispatch_identity: input.dispatch_identity,
            execution_runtime: input.execution_runtime,
            worktree_mode: input.worktree_mode,
            operations,
            demonstrated_gates,
            canonical_manifest_sha256: String::new(),
        };
        manifest.refresh_digest();
        manifest
    }

    pub(crate) fn canonical_manifest_sha256(&self) -> &str {
        &self.canonical_manifest_sha256
    }

    pub(crate) fn operations(&self) -> &[EffectiveSupervisorMutationOperation] {
        &self.operations
    }

    fn refresh_digest(&mut self) {
        self.canonical_manifest_sha256 = sha256_hex(&self.canonical_bytes());
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        push_canonical_manifest_field(&mut bytes, "domain", "maco-effective-supervisor-mutations");
        push_canonical_manifest_field(&mut bytes, "version", &self.version.to_string());
        push_canonical_manifest_field(&mut bytes, "run_id", &self.run_id);
        push_canonical_manifest_field(
            &mut bytes,
            "parent_node",
            self.parent_node.as_deref().unwrap_or(""),
        );
        push_canonical_manifest_field(
            &mut bytes,
            "normalized_plan_sha256",
            &self.normalized_plan_sha256,
        );
        push_canonical_manifest_field(
            &mut bytes,
            "dispatch_identity",
            &self.dispatch_identity.canonical_id(),
        );
        push_canonical_manifest_field(
            &mut bytes,
            "execution_runtime",
            self.execution_runtime.canonical_id(),
        );
        push_canonical_manifest_field(
            &mut bytes,
            "worktree_mode",
            self.worktree_mode.canonical_id(),
        );
        for operation in &self.operations {
            push_canonical_manifest_field(&mut bytes, "operation", &operation.operation_id);
        }
        for gate in &self.demonstrated_gates {
            push_canonical_manifest_field(&mut bytes, "demonstrated_gate", gate.id());
        }
        bytes
    }

    fn validate_shape(&self) -> Result<(), EffectiveSupervisorMutationAdmissionError> {
        if self.version != EFFECTIVE_SUPERVISOR_MUTATION_MANIFEST_VERSION {
            return Err(EffectiveSupervisorMutationAdmissionError::InvalidManifest {
                reason: "unsupported effective Supervisor mutation manifest version".to_string(),
            });
        }
        if self.run_id.is_empty()
            || self.normalized_plan_sha256.len() != 64
            || !self
                .normalized_plan_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || self.operations.is_empty()
        {
            return Err(EffectiveSupervisorMutationAdmissionError::InvalidManifest {
                reason: "effective Supervisor mutation manifest identity is incomplete".to_string(),
            });
        }
        if self
            .operations
            .windows(2)
            .any(|pair| pair[0].operation_id >= pair[1].operation_id)
            || self
                .operations
                .iter()
                .any(|operation| operation.operation_id.is_empty())
            || self
                .demonstrated_gates
                .windows(2)
                .any(|pair| pair[0].id() >= pair[1].id())
        {
            return Err(EffectiveSupervisorMutationAdmissionError::InvalidManifest {
                reason:
                    "effective Supervisor mutation manifest entries are not canonical and unique"
                        .to_string(),
            });
        }
        if sha256_hex(&self.canonical_bytes()) != self.canonical_manifest_sha256 {
            return Err(EffectiveSupervisorMutationAdmissionError::InvalidManifest {
                reason: "effective Supervisor mutation manifest digest is invalid".to_string(),
            });
        }
        match &self.dispatch_identity {
            EffectiveSupervisorDispatchIdentity::Root => {}
            EffectiveSupervisorDispatchIdentity::GeneratedFollowUpSubordinate { parent_run_id }
                if !parent_run_id.is_empty()
                    && self.parent_node.as_deref() == Some(parent_run_id.as_str()) => {}
            EffectiveSupervisorDispatchIdentity::EvidenceOnlyReaudit {
                source_run_id,
                assignment_id,
            } if !source_run_id.is_empty() && !assignment_id.is_empty() => {}
            EffectiveSupervisorDispatchIdentity::GeneratedFollowUpQueue {
                source_run_id,
                task_count,
            } if source_run_id == &self.run_id && self.parent_node.is_none() && *task_count > 0 => {
            }
            _ => {
                return Err(EffectiveSupervisorMutationAdmissionError::InvalidManifest {
                    reason:
                        "effective Supervisor mutation manifest dispatch identity is inconsistent"
                            .to_string(),
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn append_unknown_operation_for_test(&mut self, operation_id: &str) {
        self.operations.push(EffectiveSupervisorMutationOperation {
            operation_id: operation_id.to_string(),
        });
        self.operations
            .sort_by(|left, right| left.operation_id.cmp(&right.operation_id));
        self.operations
            .dedup_by(|left, right| left.operation_id == right.operation_id);
        self.refresh_digest();
    }

    #[cfg(test)]
    pub(crate) fn remove_demonstrated_gate_for_test(&mut self, gate: ExplicitMutationGate) {
        self.demonstrated_gates
            .retain(|candidate| *candidate != gate);
        self.refresh_digest();
    }
}

fn push_canonical_manifest_field(bytes: &mut Vec<u8>, name: &str, value: &str) {
    bytes.extend_from_slice(name.len().to_string().as_bytes());
    bytes.push(b':');
    bytes.extend_from_slice(name.as_bytes());
    bytes.push(b'=');
    bytes.extend_from_slice(value.len().to_string().as_bytes());
    bytes.push(b':');
    bytes.extend_from_slice(value.as_bytes());
    bytes.push(b'\n');
}

/// Typed failure from the common effective-manifest authorizer or consumer.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum EffectiveSupervisorMutationAdmissionError {
    #[error("effective Supervisor mutation manifest is invalid: {reason}")]
    InvalidManifest { reason: String },
    #[error("effective Supervisor mutation operation '{operation_id}' is unlisted and requires taxonomy review")]
    UnknownOperation { operation_id: String },
    #[error("effective Supervisor mutation operation '{operation_id}' requires missing explicit gate '{gate_id}'")]
    MissingExplicitGate {
        operation_id: String,
        gate_id: &'static str,
    },
    #[error("effective Supervisor mutation manifest includes unrelated explicit gate '{gate_id}'")]
    UnrelatedExplicitGate { gate_id: &'static str },
    #[error("effective Supervisor mutation authority is bound to a different canonical manifest")]
    ManifestBindingMismatch,
}

impl EffectiveSupervisorMutationAdmissionError {
    pub(crate) const fn gate_id(&self) -> &'static str {
        match self {
            Self::MissingExplicitGate { gate_id, .. } | Self::UnrelatedExplicitGate { gate_id } => {
                gate_id
            }
            Self::InvalidManifest { .. }
            | Self::UnknownOperation { .. }
            | Self::ManifestBindingMismatch => TAXONOMY_REVIEW_REQUIRED_GATE_ID,
        }
    }
}

/// Non-serializable, non-cloneable, single-use authority for one manifest.
pub(crate) struct EffectiveSupervisorMutationAuthority {
    canonical_manifest_sha256: String,
}

impl EffectiveSupervisorMutationAuthority {
    /// Consumes the authorizer result into a non-serializable grant bound to
    /// the exact canonical manifest. Persisted manifest bytes never confer it.
    pub(crate) fn consume(
        self,
        expected: &EffectiveSupervisorMutationManifest,
    ) -> Result<EffectiveSupervisorMutationGrant, EffectiveSupervisorMutationAdmissionError> {
        expected.validate_shape()?;
        if self.canonical_manifest_sha256 != expected.canonical_manifest_sha256 {
            return Err(EffectiveSupervisorMutationAdmissionError::ManifestBindingMismatch);
        }
        Ok(EffectiveSupervisorMutationGrant {
            canonical_manifest_sha256: self.canonical_manifest_sha256,
        })
    }
}

/// Non-serializable, non-cloneable proof that the one-shot authorizer was
/// consumed for an exact canonical manifest. The common scheduler consumes
/// this grant again before preparation can mutate durable state.
pub(crate) struct EffectiveSupervisorMutationGrant {
    canonical_manifest_sha256: String,
}

impl EffectiveSupervisorMutationGrant {
    pub(crate) fn consume(
        self,
        expected: &EffectiveSupervisorMutationManifest,
    ) -> Result<(), EffectiveSupervisorMutationAdmissionError> {
        expected.validate_shape()?;
        if self.canonical_manifest_sha256 != expected.canonical_manifest_sha256 {
            return Err(EffectiveSupervisorMutationAdmissionError::ManifestBindingMismatch);
        }
        Ok(())
    }
}

/// Applies the reviewed registry and exact gate evidence to one canonical
/// manifest, returning authority only when every operation is admitted.
pub(crate) fn authorize_effective_supervisor_mutation_manifest(
    manifest: &EffectiveSupervisorMutationManifest,
) -> Result<EffectiveSupervisorMutationAuthority, EffectiveSupervisorMutationAdmissionError> {
    manifest.validate_shape()?;
    let mut required_gates = std::collections::BTreeSet::new();
    for operation in manifest.operations() {
        match autonomous_decision_for(operation.operation_id()) {
            AutonomousMutationDecision::Allow => {}
            AutonomousMutationDecision::RequireExplicitGate(gate) => {
                required_gates.insert(gate);
                if !manifest.demonstrated_gates.contains(&gate) {
                    return Err(
                        EffectiveSupervisorMutationAdmissionError::MissingExplicitGate {
                            operation_id: operation.operation_id().to_string(),
                            gate_id: gate.id(),
                        },
                    );
                }
            }
            AutonomousMutationDecision::Refuse { .. } => {
                return Err(
                    EffectiveSupervisorMutationAdmissionError::UnknownOperation {
                        operation_id: operation.operation_id().to_string(),
                    },
                );
            }
        }
    }
    if let Some(unrelated) = manifest
        .demonstrated_gates
        .iter()
        .find(|gate| !required_gates.contains(gate))
    {
        return Err(
            EffectiveSupervisorMutationAdmissionError::UnrelatedExplicitGate {
                gate_id: unrelated.id(),
            },
        );
    }
    Ok(EffectiveSupervisorMutationAuthority {
        canonical_manifest_sha256: manifest.canonical_manifest_sha256.clone(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    const POLICY: &str = include_str!("../docs/MUTATION_REVERSIBILITY.md");

    #[test]
    fn registry_is_current_complete_and_unique() {
        assert_eq!(registry().version, MUTATION_TAXONOMY_VERSION);
        assert_eq!(registry().version, 4);
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
    fn classification_counts_are_exact() {
        let reversible = registry()
            .entries
            .iter()
            .filter(|entry| entry.reversibility == MutationReversibility::Reversible)
            .count();
        assert_eq!(reversible, 21);
        assert_eq!(registry().entries.len() - reversible, 41);
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

    fn effective_manifest(run_id: &str) -> EffectiveSupervisorMutationManifest {
        EffectiveSupervisorMutationManifest::new(EffectiveSupervisorMutationManifestInput {
            run_id: run_id.to_string(),
            parent_node: None,
            normalized_plan_sha256: sha256_hex(run_id.as_bytes()),
            dispatch_identity: EffectiveSupervisorDispatchIdentity::Root,
            execution_runtime: EffectiveSupervisorExecutionRuntime::Verified,
            worktree_mode: EffectiveSupervisorWorktreeMode::BoundCreateOrReuse,
            operations: vec![
                MutationOperation::SupervisorRunArtifactReserve,
                MutationOperation::SupervisorRunArtifactWriteAppend,
            ],
            demonstrated_gates: vec![ExplicitMutationGate::BoundSupervisorRunLifecycleAuthority],
        })
    }

    #[test]
    fn effective_manifest_unknown_and_missing_gate_fail_closed() {
        let mut unknown = effective_manifest("unknown-manifest");
        unknown.append_unknown_operation_for_test("actual-unlisted-supervisor-effect");
        let unknown_error = authorize_effective_supervisor_mutation_manifest(&unknown)
            .err()
            .expect("unknown operation must be refused");
        assert_eq!(
            unknown_error,
            EffectiveSupervisorMutationAdmissionError::UnknownOperation {
                operation_id: "actual-unlisted-supervisor-effect".to_string()
            }
        );
        assert_eq!(unknown_error.gate_id(), TAXONOMY_REVIEW_REQUIRED_GATE_ID);

        let mut missing_gate = effective_manifest("missing-gate-manifest");
        missing_gate.remove_demonstrated_gate_for_test(
            ExplicitMutationGate::BoundSupervisorRunLifecycleAuthority,
        );
        let missing_error = authorize_effective_supervisor_mutation_manifest(&missing_gate)
            .err()
            .expect("irreversible operation without its gate must be refused");
        assert!(matches!(
            missing_error,
            EffectiveSupervisorMutationAdmissionError::MissingExplicitGate {
                gate_id: "bound-supervisor-run-lifecycle-authority",
                ..
            }
        ));
    }

    #[test]
    fn effective_authority_is_digest_bound_and_consumed_by_value() {
        let manifest_a = effective_manifest("manifest-a");
        let manifest_b = effective_manifest("manifest-b");
        assert_ne!(
            manifest_a.canonical_manifest_sha256(),
            manifest_b.canonical_manifest_sha256()
        );
        let authority = authorize_effective_supervisor_mutation_manifest(&manifest_a)
            .expect("authorize manifest A");
        assert!(matches!(
            authority.consume(&manifest_b),
            Err(EffectiveSupervisorMutationAdmissionError::ManifestBindingMismatch)
        ));

        let authority = authorize_effective_supervisor_mutation_manifest(&manifest_a)
            .expect("reauthorize manifest A for its one valid consumption");
        let grant = authority
            .consume(&manifest_a)
            .expect("consume exact manifest authority");
        grant
            .consume(&manifest_a)
            .expect("consume exact manifest grant");
    }
}
