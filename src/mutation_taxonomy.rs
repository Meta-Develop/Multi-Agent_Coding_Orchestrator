//! Versioned mutation taxonomy and autonomous-admission decision boundary.
//!
//! Every Supervisor entrypoint and generated-follow-up queue lifecycle uses
//! this conservative policy before its first production mutation. Admission
//! returns a single-use authority bound to one canonical effective manifest;
//! every existing claim, containment, review, and effect gate remains
//! independently required.

use crate::artifacts::state_auth::sha256_hex;
use serde::{Deserialize, Serialize};

/// Current reviewed registry version.
///
/// Version 5 seals the exact Supervisor lifecycle operation sets, introduces
/// distinct preflight/resume/outer-Autopilot authorities, and binds every
/// single-use permit to the complete canonical effective identity.
pub const MUTATION_TAXONOMY_VERSION: u32 = 5;

/// Current canonical effective Supervisor manifest version.
pub const EFFECTIVE_SUPERVISOR_MUTATION_MANIFEST_VERSION: u32 = 2;

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
    SupervisorMessagingJournalLifecycle,
    SupervisorCoordinationStoreBootstrap,
    SupervisorBudgetLedgerBootstrapRecovery,
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
    pub const ALL: [Self; 64] = [
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
        Self::SupervisorMessagingJournalLifecycle,
        Self::SupervisorCoordinationStoreBootstrap,
        Self::SupervisorBudgetLedgerBootstrapRecovery,
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
            Self::SupervisorMessagingJournalLifecycle => "supervisor-messaging-journal-lifecycle",
            Self::SupervisorCoordinationStoreBootstrap => "supervisor-coordination-store-bootstrap",
            Self::SupervisorBudgetLedgerBootstrapRecovery => {
                "supervisor-budget-ledger-bootstrap-recovery"
            }
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
        MutationOperation::SupervisorMessagingJournalLifecycle,
        "Creates or recovers authenticated Supervisor messaging history whose exact prior journal state cannot be restored.",
        ExplicitMutationGate::BoundSupervisorRunLifecycleAuthority,
    ),
    irreversible(
        MutationOperation::SupervisorCoordinationStoreBootstrap,
        "May initialize repository-bound authenticated coordination state without a supported rollback to the absent namespace.",
        ExplicitMutationGate::BoundSupervisorRunLifecycleAuthority,
    ),
    irreversible(
        MutationOperation::SupervisorBudgetLedgerBootstrapRecovery,
        "May initialize or recover authenticated rolling budget state before final Supervisor plan resolution.",
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
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
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
    fn append_canonical(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Root => push_canonical_manifest_field(bytes, "dispatch_kind", "root"),
            Self::GeneratedFollowUpSubordinate { parent_run_id } => {
                push_canonical_manifest_field(
                    bytes,
                    "dispatch_kind",
                    "generated-follow-up-subordinate",
                );
                push_canonical_manifest_field(bytes, "dispatch_parent_run_id", parent_run_id);
            }
            Self::EvidenceOnlyReaudit {
                source_run_id,
                assignment_id,
            } => {
                push_canonical_manifest_field(bytes, "dispatch_kind", "evidence-only-reaudit");
                push_canonical_manifest_field(bytes, "dispatch_source_run_id", source_run_id);
                push_canonical_manifest_field(bytes, "dispatch_assignment_id", assignment_id);
            }
            Self::GeneratedFollowUpQueue {
                source_run_id,
                task_count,
            } => {
                push_canonical_manifest_field(bytes, "dispatch_kind", "generated-follow-up-queue");
                push_canonical_manifest_field(bytes, "dispatch_source_run_id", source_run_id);
                push_canonical_manifest_field(
                    bytes,
                    "dispatch_task_count",
                    &task_count.to_string(),
                );
            }
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum EffectiveSupervisorMutationLifecycle {
    SupervisorRun {
        semantic_coordination: bool,
        external_process_runtime: bool,
        machine_global_retention_bound: bool,
        field_guide_mutation: bool,
        primary_object_import: bool,
    },
    CatalogPreflight {
        launches_process: bool,
    },
    ResumeRecovery {
        semantic_release: bool,
    },
    AutopilotOuter,
    GeneratedFollowUpQueue,
}

impl EffectiveSupervisorMutationLifecycle {
    const fn id(&self) -> &'static str {
        match self {
            Self::SupervisorRun { .. } => "supervisor-run",
            Self::CatalogPreflight { .. } => "catalog-preflight",
            Self::ResumeRecovery { .. } => "resume-recovery",
            Self::AutopilotOuter => "autopilot-outer",
            Self::GeneratedFollowUpQueue => "generated-follow-up-queue",
        }
    }

    fn fixed_operations(
        &self,
        worktree_mode: EffectiveSupervisorWorktreeMode,
    ) -> Vec<MutationOperation> {
        let mut operations = match self {
            Self::SupervisorRun {
                semantic_coordination,
                external_process_runtime,
                machine_global_retention_bound,
                field_guide_mutation,
                primary_object_import,
            } => {
                let mut operations = vec![
                    MutationOperation::SupervisorRunArtifactReserve,
                    MutationOperation::SupervisorRunArtifactWriteAppend,
                    MutationOperation::SupervisorRunArtifactAuthenticatedFinalize,
                    MutationOperation::SupervisorScratchEvidenceCleanup,
                    MutationOperation::SupervisorRefusalEvidenceWrite,
                    MutationOperation::SupervisorCheckpointJournalLifecycle,
                    MutationOperation::SupervisorOrchestrationJournalLifecycle,
                    MutationOperation::SupervisorMessagingJournalLifecycle,
                    MutationOperation::SupervisorCoordinationStoreBootstrap,
                    MutationOperation::ClaimAcquire,
                    MutationOperation::SupervisorClaimAcquisitionTelemetry,
                    MutationOperation::ClaimRelease,
                    MutationOperation::SupervisorProcessRegister,
                ];
                if *semantic_coordination {
                    operations.extend([
                        MutationOperation::SemanticIntentAcquire,
                        MutationOperation::SemanticIntentRelease,
                    ]);
                }
                match worktree_mode {
                    EffectiveSupervisorWorktreeMode::BoundCreateOrReuse
                    | EffectiveSupervisorWorktreeMode::NonpublishableSimulation => operations
                        .extend([
                            MutationOperation::WorktreeCreate,
                            MutationOperation::SupervisorMandatoryControlProvision,
                        ]),
                    EffectiveSupervisorWorktreeMode::ExistingOnly => {
                        operations.push(MutationOperation::SupervisorMandatoryControlProvision)
                    }
                    EffectiveSupervisorWorktreeMode::PrimaryWorktree => {
                        operations.push(MutationOperation::PrimaryWorktreeMutation)
                    }
                    EffectiveSupervisorWorktreeMode::NotApplicable => {}
                    #[cfg(test)]
                    EffectiveSupervisorWorktreeMode::TestOnly
                    | EffectiveSupervisorWorktreeMode::VerifiedTestOnly => operations.extend([
                        MutationOperation::WorktreeCreate,
                        MutationOperation::SupervisorMandatoryControlProvision,
                    ]),
                }
                if *external_process_runtime {
                    operations.extend([
                        MutationOperation::SupervisorProcessSpawn,
                        MutationOperation::SupervisorProcessOutputStage,
                        MutationOperation::SupervisorProcessOutputWrite,
                        MutationOperation::SupervisorProcessTerminate,
                    ]);
                    operations.push(if *machine_global_retention_bound {
                        MutationOperation::MachineGlobalQuarantine
                    } else {
                        MutationOperation::SupervisorProcessOutputCleanup
                    });
                    if *field_guide_mutation {
                        operations.push(MutationOperation::SupervisorFieldGuideMutation);
                    }
                    if *primary_object_import {
                        operations.extend([
                            MutationOperation::SandboxWorktreeEdit,
                            MutationOperation::SandboxWorktreeCommit,
                            MutationOperation::SupervisorPrimaryObjectDatabaseImport,
                        ]);
                    }
                }
                operations
            }
            Self::CatalogPreflight { launches_process } => {
                let mut operations =
                    vec![MutationOperation::SupervisorBudgetLedgerBootstrapRecovery];
                if *launches_process {
                    operations.extend([
                        MutationOperation::SupervisorProcessSpawn,
                        MutationOperation::SupervisorProcessTerminate,
                    ]);
                }
                operations
            }
            Self::ResumeRecovery { semantic_release } => {
                let mut operations = vec![
                    MutationOperation::SupervisorRunArtifactWriteAppend,
                    MutationOperation::SupervisorRunArtifactAuthenticatedFinalize,
                    MutationOperation::SupervisorCheckpointJournalLifecycle,
                    MutationOperation::SupervisorOrchestrationJournalLifecycle,
                    MutationOperation::SupervisorMessagingJournalLifecycle,
                    MutationOperation::SupervisorCoordinationStoreBootstrap,
                    MutationOperation::ClaimRelease,
                ];
                if *semantic_release {
                    operations.push(MutationOperation::SemanticIntentRelease);
                }
                operations
            }
            Self::AutopilotOuter => vec![
                MutationOperation::SupervisorRunArtifactReserve,
                MutationOperation::SupervisorRunArtifactWriteAppend,
                MutationOperation::SupervisorRunArtifactAuthenticatedFinalize,
                MutationOperation::SupervisorRefusalEvidenceWrite,
                MutationOperation::SupervisorProcessRegister,
            ],
            Self::GeneratedFollowUpQueue => vec![
                MutationOperation::GeneratedFollowUpQueueReserve,
                MutationOperation::GeneratedFollowUpQueueWriteAppend,
                MutationOperation::GeneratedFollowUpQueueAuthenticatedCommit,
                MutationOperation::GeneratedFollowUpQueueClaim,
                MutationOperation::GeneratedFollowUpQueueRelease,
                MutationOperation::GeneratedFollowUpRefusalEvidenceWrite,
                MutationOperation::GeneratedSupervisorPlanStage,
            ],
        };
        operations.sort_by_key(|operation| operation.id());
        operations.dedup();
        operations
    }

    fn supplies_gate(
        &self,
        gate: ExplicitMutationGate,
        worktree_mode: EffectiveSupervisorWorktreeMode,
    ) -> bool {
        match self {
            Self::SupervisorRun {
                semantic_coordination,
                external_process_runtime,
                machine_global_retention_bound: _,
                field_guide_mutation,
                primary_object_import,
            } => match gate {
                ExplicitMutationGate::BoundSupervisorRunLifecycleAuthority
                | ExplicitMutationGate::ExactClaimReleaseAuthority => true,
                ExplicitMutationGate::ExactSemanticIntentReleaseAuthority => *semantic_coordination,
                ExplicitMutationGate::PrimaryPlanCliDoubleOptIn => {
                    worktree_mode == EffectiveSupervisorWorktreeMode::PrimaryWorktree
                }
                ExplicitMutationGate::VerifiedSupervisorProcessLifecycleAuthority => {
                    *external_process_runtime
                }
                ExplicitMutationGate::BoundSupervisorFieldGuideMutationAuthority => {
                    *field_guide_mutation
                }
                ExplicitMutationGate::VerifiedSupervisorPrimaryObjectImportAuthority => {
                    *primary_object_import
                }
                _ => false,
            },
            Self::CatalogPreflight { launches_process } => {
                gate == ExplicitMutationGate::BoundSupervisorRunLifecycleAuthority
                    || (*launches_process
                        && gate
                            == ExplicitMutationGate::VerifiedSupervisorProcessLifecycleAuthority)
            }
            Self::ResumeRecovery { semantic_release } => match gate {
                ExplicitMutationGate::BoundSupervisorRunLifecycleAuthority
                | ExplicitMutationGate::ExactClaimReleaseAuthority => true,
                ExplicitMutationGate::ExactSemanticIntentReleaseAuthority => *semantic_release,
                _ => false,
            },
            Self::AutopilotOuter => {
                gate == ExplicitMutationGate::BoundSupervisorRunLifecycleAuthority
            }
            Self::GeneratedFollowUpQueue => {
                gate == ExplicitMutationGate::BoundGeneratedFollowUpQueueLifecycleAuthority
            }
        }
    }
}

/// Exact identity shared by the sealed lifecycle constructors below.
pub(crate) struct EffectiveSupervisorMutationIdentityInput {
    pub(crate) run_id: String,
    pub(crate) parent_node: Option<String>,
    pub(crate) normalized_plan_sha256: String,
    pub(crate) dispatch_identity: EffectiveSupervisorDispatchIdentity,
    pub(crate) execution_runtime: EffectiveSupervisorExecutionRuntime,
    pub(crate) worktree_mode: EffectiveSupervisorWorktreeMode,
    pub(crate) runtime_adapter: Option<String>,
    pub(crate) repository_identity: String,
    pub(crate) artifact_family: String,
    pub(crate) delivery_identity: String,
    pub(crate) machine_global_retention_sha256: Option<String>,
    pub(crate) queue_item_sha256: Option<String>,
    pub(crate) task_batch_sha256: Option<String>,
    pub(crate) primary_baseline_sha256: Option<String>,
    pub(crate) outer_entrypoint: Option<String>,
    pub(crate) outer_run_id: Option<String>,
}

pub(crate) struct EffectiveSupervisorRunManifestInput {
    pub(crate) identity: EffectiveSupervisorMutationIdentityInput,
    pub(crate) semantic_coordination: bool,
    pub(crate) external_process_runtime: bool,
    pub(crate) machine_global_retention_bound: bool,
    pub(crate) field_guide_mutation: bool,
    pub(crate) primary_object_import: bool,
}

pub(crate) struct EffectiveCatalogPreflightManifestInput {
    pub(crate) identity: EffectiveSupervisorMutationIdentityInput,
    pub(crate) launches_process: bool,
}

pub(crate) struct EffectiveResumeRecoveryManifestInput {
    pub(crate) identity: EffectiveSupervisorMutationIdentityInput,
    pub(crate) semantic_release: bool,
}

pub(crate) struct EffectiveGeneratedFollowUpQueueManifestInput {
    pub(crate) identity: EffectiveSupervisorMutationIdentityInput,
}

pub(crate) struct EffectiveAutopilotOuterManifestInput {
    pub(crate) identity: EffectiveSupervisorMutationIdentityInput,
}

/// Authorizable exact effective mutation set. This object is deliberately not
/// Clone or Deserialize; authorization consumes it globally.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EffectiveSupervisorMutationManifest {
    version: u32,
    lifecycle: EffectiveSupervisorMutationLifecycle,
    run_id: String,
    parent_node: Option<String>,
    normalized_plan_sha256: String,
    dispatch_identity: EffectiveSupervisorDispatchIdentity,
    execution_runtime: EffectiveSupervisorExecutionRuntime,
    worktree_mode: EffectiveSupervisorWorktreeMode,
    runtime_adapter: Option<String>,
    repository_identity: String,
    artifact_family: String,
    delivery_identity: String,
    machine_global_retention_sha256: Option<String>,
    queue_item_sha256: Option<String>,
    task_batch_sha256: Option<String>,
    primary_baseline_sha256: Option<String>,
    outer_entrypoint: Option<String>,
    outer_run_id: Option<String>,
    operation_ids: Vec<String>,
    canonical_manifest_sha256: String,
}

/// Serializable audit evidence emitted only after the authorizable manifest
/// has been irreversibly consumed. It is not accepted by the authorizer.
#[derive(Debug, Serialize)]
#[serde(transparent)]
pub(crate) struct EffectiveSupervisorMutationAuditEvidence {
    manifest: EffectiveSupervisorMutationManifest,
}

impl EffectiveSupervisorMutationAuditEvidence {
    pub(crate) fn canonical_manifest_sha256(&self) -> &str {
        self.manifest.canonical_manifest_sha256()
    }
}

macro_rules! lifecycle_permit {
    ($name:ident) => {
        pub(crate) struct $name {
            canonical_manifest_sha256: String,
        }

        impl $name {
            pub(crate) fn consume(
                self,
                expected_manifest_sha256: &str,
            ) -> Result<(), EffectiveSupervisorMutationAdmissionError> {
                if self.canonical_manifest_sha256 != expected_manifest_sha256 {
                    return Err(EffectiveSupervisorMutationAdmissionError::ManifestBindingMismatch);
                }
                Ok(())
            }

            #[cfg(test)]
            #[allow(dead_code)]
            pub(crate) fn invalid_for_test() -> Self {
                Self {
                    canonical_manifest_sha256: sha256_hex(b"invalid-test-permit"),
                }
            }
        }
    };
}

lifecycle_permit!(SupervisorRunMutationPermit);
lifecycle_permit!(CatalogPreflightMutationPermit);
lifecycle_permit!(SupervisorResolutionPreflightPermit);
lifecycle_permit!(ResumeRecoveryMutationPermit);
lifecycle_permit!(AutopilotOuterMutationPermit);
lifecycle_permit!(GeneratedFollowUpQueueMutationPermit);

/// One consumed authorizer result. The lifecycle-specific conversion consumes
/// this wrapper and yields non-serializable sink authority plus inert evidence.
pub(crate) struct AuthorizedEffectiveSupervisorMutation {
    manifest: EffectiveSupervisorMutationManifest,
}

macro_rules! into_lifecycle_permit {
    ($method:ident, $pattern:pat, $permit:ident) => {
        pub(crate) fn $method(
            self,
        ) -> Result<
            (EffectiveSupervisorMutationAuditEvidence, $permit),
            EffectiveSupervisorMutationAdmissionError,
        > {
            if !matches!(self.manifest.lifecycle, $pattern) {
                return Err(EffectiveSupervisorMutationAdmissionError::WrongLifecycle);
            }
            let canonical_manifest_sha256 = self.manifest.canonical_manifest_sha256.clone();
            Ok((
                EffectiveSupervisorMutationAuditEvidence {
                    manifest: self.manifest,
                },
                $permit {
                    canonical_manifest_sha256,
                },
            ))
        }
    };
}

impl AuthorizedEffectiveSupervisorMutation {
    into_lifecycle_permit!(
        into_supervisor_run,
        EffectiveSupervisorMutationLifecycle::SupervisorRun { .. },
        SupervisorRunMutationPermit
    );
    into_lifecycle_permit!(
        into_resume_recovery,
        EffectiveSupervisorMutationLifecycle::ResumeRecovery { .. },
        ResumeRecoveryMutationPermit
    );
    into_lifecycle_permit!(
        into_autopilot_outer,
        EffectiveSupervisorMutationLifecycle::AutopilotOuter,
        AutopilotOuterMutationPermit
    );
    into_lifecycle_permit!(
        into_generated_follow_up_queue,
        EffectiveSupervisorMutationLifecycle::GeneratedFollowUpQueue,
        GeneratedFollowUpQueueMutationPermit
    );

    pub(crate) fn into_catalog_preflight(
        self,
    ) -> Result<
        (
            EffectiveSupervisorMutationAuditEvidence,
            CatalogPreflightMutationPermit,
            SupervisorResolutionPreflightPermit,
        ),
        EffectiveSupervisorMutationAdmissionError,
    > {
        if !matches!(
            self.manifest.lifecycle,
            EffectiveSupervisorMutationLifecycle::CatalogPreflight { .. }
        ) {
            return Err(EffectiveSupervisorMutationAdmissionError::WrongLifecycle);
        }
        let canonical_manifest_sha256 = self.manifest.canonical_manifest_sha256.clone();
        Ok((
            EffectiveSupervisorMutationAuditEvidence {
                manifest: self.manifest,
            },
            CatalogPreflightMutationPermit {
                canonical_manifest_sha256: canonical_manifest_sha256.clone(),
            },
            SupervisorResolutionPreflightPermit {
                canonical_manifest_sha256,
            },
        ))
    }
}

/// Exact post-override Supervisor mutation set admitted for one dispatch.
///
/// The serialized form is audit evidence only. It does not carry authority;
impl EffectiveSupervisorMutationManifest {
    fn new(
        input: EffectiveSupervisorMutationIdentityInput,
        lifecycle: EffectiveSupervisorMutationLifecycle,
    ) -> Self {
        let operation_ids = lifecycle
            .fixed_operations(input.worktree_mode)
            .into_iter()
            .map(|operation| operation.id().to_string())
            .collect();
        let mut manifest = Self {
            version: EFFECTIVE_SUPERVISOR_MUTATION_MANIFEST_VERSION,
            lifecycle,
            run_id: input.run_id,
            parent_node: input.parent_node,
            normalized_plan_sha256: input.normalized_plan_sha256,
            dispatch_identity: input.dispatch_identity,
            execution_runtime: input.execution_runtime,
            worktree_mode: input.worktree_mode,
            runtime_adapter: input.runtime_adapter,
            repository_identity: input.repository_identity,
            artifact_family: input.artifact_family,
            delivery_identity: input.delivery_identity,
            machine_global_retention_sha256: input.machine_global_retention_sha256,
            queue_item_sha256: input.queue_item_sha256,
            task_batch_sha256: input.task_batch_sha256,
            primary_baseline_sha256: input.primary_baseline_sha256,
            outer_entrypoint: input.outer_entrypoint,
            outer_run_id: input.outer_run_id,
            operation_ids,
            canonical_manifest_sha256: String::new(),
        };
        manifest.refresh_digest();
        manifest
    }

    pub(crate) fn supervisor_run(input: EffectiveSupervisorRunManifestInput) -> Self {
        Self::new(
            input.identity,
            EffectiveSupervisorMutationLifecycle::SupervisorRun {
                semantic_coordination: input.semantic_coordination,
                external_process_runtime: input.external_process_runtime,
                machine_global_retention_bound: input.machine_global_retention_bound,
                field_guide_mutation: input.field_guide_mutation,
                primary_object_import: input.primary_object_import,
            },
        )
    }

    pub(crate) fn catalog_preflight(input: EffectiveCatalogPreflightManifestInput) -> Self {
        Self::new(
            input.identity,
            EffectiveSupervisorMutationLifecycle::CatalogPreflight {
                launches_process: input.launches_process,
            },
        )
    }

    pub(crate) fn resume_recovery(input: EffectiveResumeRecoveryManifestInput) -> Self {
        Self::new(
            input.identity,
            EffectiveSupervisorMutationLifecycle::ResumeRecovery {
                semantic_release: input.semantic_release,
            },
        )
    }

    pub(crate) fn autopilot_outer(input: EffectiveAutopilotOuterManifestInput) -> Self {
        Self::new(
            input.identity,
            EffectiveSupervisorMutationLifecycle::AutopilotOuter,
        )
    }

    pub(crate) fn generated_follow_up_queue(
        input: EffectiveGeneratedFollowUpQueueManifestInput,
    ) -> Self {
        Self::new(
            input.identity,
            EffectiveSupervisorMutationLifecycle::GeneratedFollowUpQueue,
        )
    }

    pub(crate) fn canonical_manifest_sha256(&self) -> &str {
        &self.canonical_manifest_sha256
    }

    #[cfg(test)]
    pub(crate) fn operation_ids(&self) -> &[String] {
        &self.operation_ids
    }

    fn refresh_digest(&mut self) {
        self.canonical_manifest_sha256 = sha256_hex(&self.canonical_bytes());
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        push_canonical_manifest_field(&mut bytes, "domain", "maco-effective-supervisor-mutations");
        push_canonical_manifest_field(&mut bytes, "version", &self.version.to_string());
        push_canonical_manifest_field(&mut bytes, "lifecycle", self.lifecycle.id());
        push_canonical_manifest_field(&mut bytes, "run_id", &self.run_id);
        push_canonical_optional_manifest_field(
            &mut bytes,
            "parent_node",
            self.parent_node.as_deref(),
        );
        push_canonical_manifest_field(
            &mut bytes,
            "normalized_plan_sha256",
            &self.normalized_plan_sha256,
        );
        self.dispatch_identity.append_canonical(&mut bytes);
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
        push_canonical_optional_manifest_field(
            &mut bytes,
            "runtime_adapter",
            self.runtime_adapter.as_deref(),
        );
        push_canonical_manifest_field(&mut bytes, "repository_identity", &self.repository_identity);
        push_canonical_manifest_field(&mut bytes, "artifact_family", &self.artifact_family);
        push_canonical_manifest_field(&mut bytes, "delivery_identity", &self.delivery_identity);
        push_canonical_optional_manifest_field(
            &mut bytes,
            "machine_global_retention_sha256",
            self.machine_global_retention_sha256.as_deref(),
        );
        push_canonical_optional_manifest_field(
            &mut bytes,
            "queue_item_sha256",
            self.queue_item_sha256.as_deref(),
        );
        push_canonical_optional_manifest_field(
            &mut bytes,
            "task_batch_sha256",
            self.task_batch_sha256.as_deref(),
        );
        push_canonical_optional_manifest_field(
            &mut bytes,
            "primary_baseline_sha256",
            self.primary_baseline_sha256.as_deref(),
        );
        push_canonical_optional_manifest_field(
            &mut bytes,
            "outer_entrypoint",
            self.outer_entrypoint.as_deref(),
        );
        push_canonical_optional_manifest_field(
            &mut bytes,
            "outer_run_id",
            self.outer_run_id.as_deref(),
        );
        for operation_id in &self.operation_ids {
            push_canonical_manifest_field(&mut bytes, "operation", operation_id);
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
            || !is_canonical_sha256(&self.normalized_plan_sha256)
            || !is_canonical_sha256(&self.repository_identity)
            || self.artifact_family.is_empty()
            || self.delivery_identity.is_empty()
            || self.parent_node.as_ref().is_some_and(String::is_empty)
            || self.runtime_adapter.as_ref().is_some_and(String::is_empty)
            || self
                .machine_global_retention_sha256
                .as_ref()
                .is_some_and(|digest| !is_canonical_sha256(digest))
            || self
                .queue_item_sha256
                .as_ref()
                .is_some_and(|digest| !is_canonical_sha256(digest))
            || self
                .task_batch_sha256
                .as_ref()
                .is_some_and(|digest| !is_canonical_sha256(digest))
            || self
                .primary_baseline_sha256
                .as_ref()
                .is_some_and(|digest| !is_canonical_sha256(digest))
            || self.outer_entrypoint.as_ref().is_some_and(String::is_empty)
            || self.outer_run_id.as_ref().is_some_and(String::is_empty)
            || (self.operation_ids.is_empty()
                && !matches!(
                    self.lifecycle,
                    EffectiveSupervisorMutationLifecycle::CatalogPreflight {
                        launches_process: false
                    }
                ))
        {
            return Err(EffectiveSupervisorMutationAdmissionError::InvalidManifest {
                reason: "effective Supervisor mutation manifest identity is incomplete".to_string(),
            });
        }
        if self.operation_ids.windows(2).any(|pair| pair[0] >= pair[1])
            || self.operation_ids.iter().any(String::is_empty)
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
        let expected_operation_ids = self
            .lifecycle
            .fixed_operations(self.worktree_mode)
            .into_iter()
            .map(|operation| operation.id().to_string())
            .collect::<Vec<_>>();
        if self.operation_ids != expected_operation_ids {
            return Err(EffectiveSupervisorMutationAdmissionError::InvalidManifest {
                reason: "effective mutation operation set is not the fixed lifecycle set"
                    .to_string(),
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
        match &self.lifecycle {
            EffectiveSupervisorMutationLifecycle::SupervisorRun {
                machine_global_retention_bound,
                primary_object_import,
                ..
            } => {
                if self.artifact_family != "supervise"
                    || self.runtime_adapter.is_none()
                    || self.primary_baseline_sha256.is_none()
                    || *machine_global_retention_bound
                        != self.machine_global_retention_sha256.is_some()
                    || (*primary_object_import
                        && self.worktree_mode
                            != EffectiveSupervisorWorktreeMode::BoundCreateOrReuse
                        && !cfg!(test))
                {
                    return Err(EffectiveSupervisorMutationAdmissionError::InvalidManifest {
                        reason: "effective Supervisor run identity is incomplete".to_string(),
                    });
                }
            }
            EffectiveSupervisorMutationLifecycle::CatalogPreflight { launches_process } => {
                if self.artifact_family != "supervise-preflight"
                    || self.runtime_adapter.is_none()
                    || (*launches_process
                        && self.execution_runtime != EffectiveSupervisorExecutionRuntime::Verified)
                {
                    return Err(EffectiveSupervisorMutationAdmissionError::InvalidManifest {
                        reason: "catalog preflight identity is incomplete".to_string(),
                    });
                }
            }
            EffectiveSupervisorMutationLifecycle::ResumeRecovery { .. } => {
                if self.artifact_family != "supervise"
                    || self.primary_baseline_sha256.is_none()
                    || self.runtime_adapter.is_none()
                {
                    return Err(EffectiveSupervisorMutationAdmissionError::InvalidManifest {
                        reason: "resume recovery identity is incomplete".to_string(),
                    });
                }
            }
            EffectiveSupervisorMutationLifecycle::AutopilotOuter => {
                if self.artifact_family != "autopilot"
                    || self.runtime_adapter.is_none()
                    || self.primary_baseline_sha256.is_none()
                    || self.machine_global_retention_sha256.is_none()
                    || self.outer_entrypoint.as_deref() != Some("autopilot_run")
                    || self.outer_run_id.as_deref() != Some(self.run_id.as_str())
                {
                    return Err(EffectiveSupervisorMutationAdmissionError::InvalidManifest {
                        reason: "outer Autopilot identity is incomplete".to_string(),
                    });
                }
            }
            EffectiveSupervisorMutationLifecycle::GeneratedFollowUpQueue => {
                if self.artifact_family != "generated-follow-up-queue"
                    || self.runtime_adapter.is_some()
                    || self.machine_global_retention_sha256.is_none()
                    || self.queue_item_sha256.is_none()
                    || self.task_batch_sha256.is_none()
                    || self.primary_baseline_sha256.is_none()
                    || self.outer_entrypoint.is_none()
                    || self.outer_run_id.is_none()
                {
                    return Err(EffectiveSupervisorMutationAdmissionError::InvalidManifest {
                        reason: "generated follow-up queue identity is incomplete".to_string(),
                    });
                }
            }
        }
        Ok(())
    }
}

fn is_canonical_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

fn push_canonical_optional_manifest_field(bytes: &mut Vec<u8>, name: &str, value: Option<&str>) {
    match value {
        Some(value) => {
            push_canonical_manifest_field(bytes, &format!("{name}_presence"), "some");
            push_canonical_manifest_field(bytes, name, value);
        }
        None => push_canonical_manifest_field(bytes, &format!("{name}_presence"), "none"),
    }
}

/// Typed failure from the common effective-manifest authorizer or consumer.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum EffectiveSupervisorMutationAdmissionError {
    #[error("effective Supervisor mutation manifest is invalid: {reason}")]
    InvalidManifest { reason: String },
    #[error("effective Supervisor mutation operation '{operation_id}' is unlisted and requires taxonomy review")]
    UnknownOperation { operation_id: String },
    #[error("effective Supervisor mutation lifecycle did not produce capability '{gate_id}'")]
    MissingCapability { gate_id: &'static str },
    #[error("effective Supervisor mutation authorization was consumed as the wrong lifecycle")]
    WrongLifecycle,
    #[error("effective Supervisor mutation authority is bound to a different canonical manifest")]
    ManifestBindingMismatch,
}

impl EffectiveSupervisorMutationAdmissionError {
    pub(crate) const fn gate_id(&self) -> &'static str {
        match self {
            Self::MissingCapability { gate_id } => gate_id,
            Self::InvalidManifest { .. }
            | Self::UnknownOperation { .. }
            | Self::WrongLifecycle
            | Self::ManifestBindingMismatch => TAXONOMY_REVIEW_REQUIRED_GATE_ID,
        }
    }
}

/// Applies the reviewed registry to a taxonomy-owned fixed lifecycle set.
/// The manifest is consumed, so the same authorizable object cannot be issued
/// twice and serialized audit evidence cannot be passed back here.
pub(crate) fn authorize_effective_supervisor_mutation_manifest(
    manifest: EffectiveSupervisorMutationManifest,
) -> Result<AuthorizedEffectiveSupervisorMutation, EffectiveSupervisorMutationAdmissionError> {
    manifest.validate_shape()?;
    for operation_id in &manifest.operation_ids {
        match autonomous_decision_for(operation_id) {
            AutonomousMutationDecision::Allow => {}
            AutonomousMutationDecision::RequireExplicitGate(gate) => {
                if !manifest
                    .lifecycle
                    .supplies_gate(gate, manifest.worktree_mode)
                {
                    return Err(
                        EffectiveSupervisorMutationAdmissionError::MissingCapability {
                            gate_id: gate.id(),
                        },
                    );
                }
            }
            AutonomousMutationDecision::Refuse { .. } => {
                return Err(
                    EffectiveSupervisorMutationAdmissionError::UnknownOperation {
                        operation_id: operation_id.to_string(),
                    },
                );
            }
        }
    }
    Ok(AuthorizedEffectiveSupervisorMutation { manifest })
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    const POLICY: &str = include_str!("../docs/MUTATION_REVERSIBILITY.md");

    #[test]
    fn registry_is_current_complete_and_unique() {
        assert_eq!(registry().version, MUTATION_TAXONOMY_VERSION);
        assert_eq!(registry().version, 5);
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
        assert_eq!(registry().entries.len() - reversible, 43);
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

    fn effective_identity(
        run_id: &str,
        parent_node: Option<String>,
    ) -> EffectiveSupervisorMutationIdentityInput {
        EffectiveSupervisorMutationIdentityInput {
            run_id: run_id.to_string(),
            parent_node,
            normalized_plan_sha256: sha256_hex(run_id.as_bytes()),
            dispatch_identity: EffectiveSupervisorDispatchIdentity::Root,
            execution_runtime: EffectiveSupervisorExecutionRuntime::Verified,
            worktree_mode: EffectiveSupervisorWorktreeMode::ExistingOnly,
            runtime_adapter: Some("fake".to_string()),
            repository_identity: sha256_hex(b"repository-fixture"),
            artifact_family: "supervise".to_string(),
            delivery_identity: "plan-file-fixture".to_string(),
            machine_global_retention_sha256: None,
            queue_item_sha256: None,
            task_batch_sha256: None,
            primary_baseline_sha256: Some(sha256_hex(b"primary-fixture")),
            outer_entrypoint: None,
            outer_run_id: None,
        }
    }

    fn effective_manifest(run_id: &str) -> EffectiveSupervisorMutationManifest {
        EffectiveSupervisorMutationManifest::supervisor_run(EffectiveSupervisorRunManifestInput {
            identity: effective_identity(run_id, None),
            semantic_coordination: true,
            external_process_runtime: false,
            machine_global_retention_bound: false,
            field_guide_mutation: false,
            primary_object_import: false,
        })
    }

    #[test]
    fn sealed_lifecycles_emit_only_complete_registered_operation_sets() {
        let mut catalog_identity = effective_identity("catalog-fixture", None);
        catalog_identity.artifact_family = "supervise-preflight".to_string();
        catalog_identity.runtime_adapter = Some("codex".to_string());
        catalog_identity.primary_baseline_sha256 = None;
        let mut outer_identity = effective_identity("outer-fixture", None);
        outer_identity.artifact_family = "autopilot".to_string();
        outer_identity.execution_runtime =
            EffectiveSupervisorExecutionRuntime::NonpublishableSimulation;
        outer_identity.machine_global_retention_sha256 = Some(sha256_hex(b"retention"));
        outer_identity.outer_entrypoint = Some("autopilot_run".to_string());
        outer_identity.outer_run_id = Some("outer-fixture".to_string());
        let mut queue_identity = effective_identity("queue-fixture", None);
        queue_identity.dispatch_identity =
            EffectiveSupervisorDispatchIdentity::GeneratedFollowUpQueue {
                source_run_id: "queue-fixture".to_string(),
                task_count: 1,
            };
        queue_identity.artifact_family = "generated-follow-up-queue".to_string();
        queue_identity.worktree_mode = EffectiveSupervisorWorktreeMode::NotApplicable;
        queue_identity.runtime_adapter = None;
        queue_identity.machine_global_retention_sha256 = Some(sha256_hex(b"retention"));
        queue_identity.queue_item_sha256 = Some(sha256_hex(b"item-set"));
        queue_identity.task_batch_sha256 = Some(sha256_hex(b"task-batch"));
        queue_identity.outer_entrypoint = Some("supervise_run".to_string());
        queue_identity.outer_run_id = Some("queue-fixture".to_string());
        let manifests = vec![
            effective_manifest("supervisor-fixture"),
            EffectiveSupervisorMutationManifest::catalog_preflight(
                EffectiveCatalogPreflightManifestInput {
                    identity: catalog_identity,
                    launches_process: true,
                },
            ),
            EffectiveSupervisorMutationManifest::resume_recovery(
                EffectiveResumeRecoveryManifestInput {
                    identity: effective_identity("resume-fixture", None),
                    semantic_release: true,
                },
            ),
            EffectiveSupervisorMutationManifest::autopilot_outer(
                EffectiveAutopilotOuterManifestInput {
                    identity: outer_identity,
                },
            ),
            EffectiveSupervisorMutationManifest::generated_follow_up_queue(
                EffectiveGeneratedFollowUpQueueManifestInput {
                    identity: queue_identity,
                },
            ),
        ];
        for manifest in manifests {
            assert_eq!(
                manifest.operation_ids,
                manifest
                    .lifecycle
                    .fixed_operations(manifest.worktree_mode)
                    .into_iter()
                    .map(|operation| operation.id().to_string())
                    .collect::<Vec<_>>()
            );
            for operation_id in &manifest.operation_ids {
                assert!(classification_for(operation_id).is_some());
            }
            authorize_effective_supervisor_mutation_manifest(manifest)
                .expect("sealed complete lifecycle must authorize");
        }
    }

    #[test]
    fn effective_authority_is_digest_bound_and_consumed_by_value() {
        let manifest_a = effective_manifest("manifest-a");
        let manifest_b = effective_manifest("manifest-b");
        assert_ne!(
            manifest_a.canonical_manifest_sha256(),
            manifest_b.canonical_manifest_sha256()
        );
        let manifest_a_sha256 = manifest_a.canonical_manifest_sha256().to_string();
        let authority = authorize_effective_supervisor_mutation_manifest(manifest_a)
            .expect("authorize manifest A");
        let (evidence_a, permit_a) = authority
            .into_supervisor_run()
            .expect("convert exact Supervisor lifecycle");
        assert_eq!(evidence_a.canonical_manifest_sha256(), manifest_a_sha256);
        let authority_b = authorize_effective_supervisor_mutation_manifest(manifest_b)
            .expect("authorize manifest B");
        let (evidence_b, _permit_b) = authority_b
            .into_supervisor_run()
            .expect("convert second Supervisor lifecycle");
        assert!(matches!(
            permit_a.consume(evidence_b.canonical_manifest_sha256()),
            Err(EffectiveSupervisorMutationAdmissionError::ManifestBindingMismatch)
        ));
        serde_json::to_vec(&evidence_a).expect("consumed evidence remains serializable for audit");
    }

    #[test]
    fn canonical_optional_identity_distinguishes_absence_from_present_empty() {
        let absent = effective_manifest("optional-identity");
        let present_empty = EffectiveSupervisorMutationManifest::supervisor_run(
            EffectiveSupervisorRunManifestInput {
                identity: effective_identity("optional-identity", Some(String::new())),
                semantic_coordination: true,
                external_process_runtime: false,
                machine_global_retention_bound: false,
                field_guide_mutation: false,
                primary_object_import: false,
            },
        );
        assert_ne!(
            absent.canonical_manifest_sha256(),
            present_empty.canonical_manifest_sha256()
        );
    }

    #[test]
    fn lifecycle_authority_cannot_be_consumed_as_another_lifecycle() {
        let mut identity = effective_identity("wrong-lifecycle", None);
        identity.artifact_family = "supervise-preflight".to_string();
        identity.primary_baseline_sha256 = None;
        let authorization = authorize_effective_supervisor_mutation_manifest(
            EffectiveSupervisorMutationManifest::catalog_preflight(
                EffectiveCatalogPreflightManifestInput {
                    identity,
                    launches_process: false,
                },
            ),
        )
        .expect("authorize catalog preflight");
        assert!(matches!(
            authorization.into_supervisor_run(),
            Err(EffectiveSupervisorMutationAdmissionError::WrongLifecycle)
        ));
    }
}
