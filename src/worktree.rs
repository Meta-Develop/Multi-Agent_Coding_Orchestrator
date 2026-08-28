#[cfg(test)]
use crate::safe_state::scavenge_private_random_directories;
use crate::{
    artifacts::{
        prune_artifacts_with_policy, repository_authenticator_key_only,
        state_auth::{random_identifier, AuthenticationDomain, RepositoryAuthBinding},
        ArtifactRetentionFamily, ArtifactRetentionPolicy, RunArtifactPruneReport,
    },
    authenticated_snapshot::{AuthenticatedSnapshot, AuthenticatedSnapshotStore, SnapshotSpec},
    gate_denial::GateDenial,
    machine_global::{
        DestructiveTargetInput, GateOutcome, MachineGlobalRetentionBinding, MachineGlobalStore,
        RetentionOperationId,
    },
    process_runner::{
        run_process, ContainmentPolicy, EnvironmentMode, ProcessOutput, ProcessRunError,
        ProcessSpec, SideEffectConfinementProfile, StdinMode, StrictOfflineWorkspaceProfile,
    },
    safe_state::{
        identity_for_path, quarantine_direct_child_directory, remove_direct_child_tree,
        remove_quarantined_direct_child_tree, replace_reserved_directory_from,
        scavenge_private_random_directories_until, stable_checksum, AtomicStateWriter,
        BoundedRegularReader, BoundedTreeEntryKind, BoundedTreeWalkAction, BoundedTreeWalkLimits,
        BoundedTreeWalker, DirectoryBindingGuard, ExistingExclusiveLock, FileIdentity,
        KernelStateLock, PrivateDirectoryScavengeLimits, RegularFileBindingGuard, SafeRoot,
        TreeLinkPolicy,
    },
    state_journal::JournalSpec,
    state_migration::{
        finalize_legacy_retirement, prepare_legacy_retirement, LegacyAdoption,
        LEGACY_RETIREMENT_DOMAIN,
    },
    sync_store::{LockedClaimsSnapshot, SyncStore},
};
use anyhow::{bail, Context, Result};
use git2::{
    Branch, BranchType, ErrorCode, ObjectType, Oid, Repository, RepositoryInitOptions, Status,
    StatusOptions, Transaction, WorktreeAddOptions, WorktreeLockStatus, WorktreePruneOptions,
};
use serde::{Deserialize, Serialize, Serializer};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};

#[cfg(unix)]
use std::{fs::OpenOptions, io::Write, os::unix::fs::PermissionsExt};

#[cfg(target_os = "linux")]
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

const DEFAULT_BRANCH_PREFIX: &str = "maco";
const WORKTREE_GUARD_ASSET: &[u8] = include_bytes!("../assets/maco-worktree-guard.sh");
const WORKTREE_GUARD_STATE_DIRECTORY: &str = ".maco-worktree-guard";
const WORKTREE_GUARD_MARKER: &str = "maco-worktree-guard-v3";
const WORKTREE_GUARD_PREVIOUS_SUFFIX: &str = ".maco-worktree-guard-previous";
const WORKTREE_GUARD_STAGED_SUFFIX: &str = ".maco-worktree-guard-installing";
const WORKTREE_GUARD_PRE_PUSH_TARGET: &str = "pre-push.human-authorship-previous";
const HUMAN_AUTHORSHIP_PRE_PUSH_DISPATCHER_V5: &[u8] = br#"#!/usr/bin/env bash
# human-authorship-guard dispatcher v5
set -euo pipefail
self="$(cd "$(dirname "$0")" && pwd -P)/$(basename "$0")"
previous="$self.human-authorship-previous"
input="$(mktemp)"
trap 'rm -f "$input"' EXIT
cat > "$input"
if [[ -x "$previous" ]]; then
  "$previous" "$@" < "$input"
fi

resolve_guard() {
  local name="$1"
  local repo_root
  local primary
  local common_dir
  local fallback

  repo_root="$(git rev-parse --show-toplevel)"
  primary="$repo_root/.agents/scripts/$name"
  if [[ -x "$primary" ]]; then
    printf '%s\n' "$primary"
    return 0
  fi

  if ! common_dir="$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null)"; then
    printf 'human-authorship-guard dispatcher: cannot resolve Git common directory for %s\n' \
      "$name" >&2
    return 1
  fi
  fallback="$(dirname "$common_dir")/.agents/scripts/$name"
  if [[ -x "$fallback" ]]; then
    printf '%s\n' "$fallback"
    return 0
  fi

  printf 'human-authorship-guard dispatcher: missing executable guard %s; checked %s and %s\n' \
    "$name" "$primary" "$fallback" >&2
  return 1
}

authorship_guard="$(resolve_guard check-human-authorship)"
"$authorship_guard" approved-current
"$authorship_guard" pre-push-approved "${1:-}" < "$input"
private_guard="$(resolve_guard check-private-agent-paths)"
"$private_guard" pre-push "${1:-}" < "$input"
github_actor_guard="$(resolve_guard check-approved-github-actor)"
"$github_actor_guard"
"#;
const MAX_WORKTREE_GUARD_FILE_BYTES: u64 = 256 * 1024;
const MANAGED_WORKTREE_REGISTRY_VERSION: u32 = 2;
const MAX_WORKTREE_METADATA_BYTES: u64 = 64 * 1024;
const MAX_AGENT_ID_BYTES: usize = 64;
const MAX_BRANCH_NAME_BYTES: usize = 255;
const MAX_MANAGED_REGISTRY_BYTES: u64 = 4 * 1024 * 1024;
const MAX_MANAGED_RECORDS: usize = 4096;
const MAX_MANAGED_OPERATIONS: usize = 4096;
const MAX_WORKTREE_STATUS_ENTRIES: usize = 100_000;
const MAX_WORKTREE_STATUS_OUTPUT_BYTES: usize = 2 * 1024 * 1024;
const MAX_WORKTREE_INDEX_BYTES: u64 = 16 * 1024 * 1024;
const MAX_WORKTREE_HEAD_BYTES: u64 = 64 * 1024;
const MAX_WORKTREE_GIT_TEXT_FILE_BYTES: u64 = 1024 * 1024;
const MAX_WORKTREE_GIT_TEXT_TOTAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_WORKTREE_GIT_TEXT_FILES: usize = 4096;
const MAX_PERSISTED_PATH_BYTES: usize = 16 * 1024;
const MAX_WORKSPACE_SWEEP_GROUPS: usize = 4096;
const MAX_WORKSPACE_SWEEP_LANES_PER_GROUP: usize = 4096;
const MAX_WORKSPACE_SWEEP_CHILDREN: usize = 4096;
const MAX_WORKSPACE_SWEEP_GROUP_NAME_BYTES: usize = 255;
const MAX_GC_ALLOWED_UNTRACKED_PATHS: usize = 128;
const MAX_GC_ALLOWED_UNTRACKED_PATH_BYTES: usize = 16 * 1024;
const MAX_GC_ALLOWED_UNTRACKED_TOTAL_BYTES: usize = 64 * 1024;
const WORKTREE_STATUS_RUNTIME_SEED: &str = "git-status";
const WORKTREE_STATUS_RUNTIME_LOCK: &str = "bounded-status.lock";
const WORKTREE_STATUS_SCAVENGE_LIMITS: PrivateDirectoryScavengeLimits =
    PrivateDirectoryScavengeLimits {
        max_root_entries: 65,
        max_directories: 64,
        max_tree_entries: 65_536,
        max_total_bytes: 64 * 1024 * 1024,
        max_duration: Duration::from_secs(10),
    };
const WORKTREE_STATUS_LOCK_TIMEOUT: Duration = Duration::from_secs(60);
#[cfg(not(test))]
const WORKTREE_STATUS_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
// Full library suites share the finite systemd containment slots with other
// process-runner tests. Preserve the production cap while allowing that
// bounded slot wait to complete inside the larger test-only status budget.
#[cfg(test)]
const WORKTREE_STATUS_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const WORKTREE_GC_STATUS_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_WORKTREE_GC_SIZE_ENTRIES: usize = 500_000;
const MAX_WORKTREE_GC_SIZE_TOTAL_PATH_BYTES: usize = 256 * 1024 * 1024;
const WORKTREE_GC_SIZE_TIMEOUT: Duration = Duration::from_secs(60);
#[cfg(target_os = "linux")]
const MAX_WORKTREE_GC_PROC_ENTRIES: usize = 262_144;
#[cfg(target_os = "linux")]
const MAX_WORKTREE_GC_PROC_ENVIRON_BYTES: u64 = 1024 * 1024;
#[cfg(target_os = "linux")]
const MAX_WORKTREE_GC_PROC_CMDLINE_BYTES: u64 = 1024 * 1024;
#[cfg(target_os = "linux")]
const MAX_WORKTREE_GC_PROC_CMDLINE_ARGS: usize = 4096;
#[cfg(target_os = "linux")]
const MAX_WORKTREE_GC_PROC_FDS: usize = 4096;
#[cfg(target_os = "linux")]
const MAX_WORKTREE_GC_IDENTITY_ANCESTORS: usize = 128;
#[cfg(target_os = "linux")]
const WORKTREE_GC_PROC_SCAN_TIMEOUT: Duration = Duration::from_secs(10);
// The total budget starts after the in-process status serializer is acquired.
// Queueing behind another caller in this process is not subprocess or private
// runtime work, so it must not spend the bounded Git execution budget. Once a
// caller is admitted, the deadline covers the global runtime lock, startup
// scavenging, repository/index capture, private Git setup, Git commands, and
// resumable cleanup. Individual Git commands remain bounded by this same
// absolute deadline and the per-command cap.
#[cfg(test)]
const WORKTREE_STATUS_TIMEOUT: Duration = Duration::from_secs(60);
const REMOVAL_LOCK_REASON: &str = "MACO removal quarantine; child process must be stopped";
const MANAGED_LOGICAL_ID: &str = "managed-worktrees";

pub const O2_LAUNCH_WORKTREE_MAX_COUNT: usize = 10;
pub const O2_LAUNCH_ARTIFACT_KEEP_COUNT: usize = 10;
pub const O2_LAUNCH_UNFINALIZED_GRACE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

static BOUNDED_STATUS_PROCESS_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> =
    std::sync::OnceLock::new();

pub(crate) enum ManagedSnapshotSpec {}

impl JournalSpec for ManagedSnapshotSpec {
    const FORMAT_VERSION: u32 = 1;
    const NAMESPACE: &'static str = "authenticated_managed_worktrees";
    const ROOT_NAME: &'static str = "authenticated-managed-worktrees-v1";
    const ROOT_LOCK_NAME: &'static str = ".authenticated-managed-worktrees.lock";
    const INSTANCE_LOCK_NAME: &'static str = ".managed-snapshot.lock";
    const HEAD_FILE_NAME: &'static str = ".head.json";
    const RECORD_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0authenticated-managed-record\0v1\0");
    const HEAD_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0authenticated-managed-head\0v1\0");
    const MAX_RECORDS: usize = 4_096;
    const MAX_RECORD_BYTES: u64 = MAX_MANAGED_REGISTRY_BYTES;
    const MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
    const MAX_PHASE_BYTES: usize = 32;
    const MAX_SUBJECT_BYTES: usize = 64;
    const MAX_INSTANCE_ID_BYTES: usize = 128;
}

impl SnapshotSpec for ManagedSnapshotSpec {
    const SNAPSHOT_FORMAT_VERSION: u32 = 1;
    const LOCATOR_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0authenticated-managed-locator\0v1\0");
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RepositoryInfo {
    pub path: PathBuf,
    pub git_dir: PathBuf,
    pub head: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WorktreeRecord {
    pub name: String,
    pub path: PathBuf,
    pub branch: String,
}

/// Observable state for the explicit primary-worktree branch guard.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WorktreeGuardReport {
    pub status: WorktreeGuardStatus,
    pub worktree_path: PathBuf,
    pub hooks_path: PathBuf,
    pub pre_push_target: PathBuf,
    pub mode: &'static str,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorktreeGuardStatus {
    Installed,
    AlreadyInstalled,
    Verified,
    Removed,
    AlreadyAbsent,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PendingWorktreeOperation {
    pub name: String,
    pub kind: String,
    pub phase: String,
    pub path: PathBuf,
    pub force: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WorktreeRetentionPolicy {
    pub max_age: Option<Duration>,
    pub max_count: Option<usize>,
    /// Maximum apparent bytes retained across value-density survivors.
    ///
    /// Ranking is GreedyDual-Size / Landlord: rebuild cost per retained byte,
    /// with recency as the tie-breaker when cost is unknown or equal. This
    /// field remains a hard size bound on top of that ranking.
    pub max_total_bytes: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct WorktreeGcOptions {
    pub worktree_root: Option<PathBuf>,
    pub dry_run: bool,
    pub remove_targets: bool,
    pub targets_only: bool,
    pub retention: WorktreeRetentionPolicy,
    pub allowed_untracked_paths: Vec<PathBuf>,
    pub exclude_agent_id: Option<String>,
    /// Restrict authenticated candidates to these exact canonical agent IDs.
    /// A configured selector also disables pathname-only orphan pruning.
    pub candidate_agent_ids: Option<BTreeSet<String>>,
    /// Require full-lane candidates to be reachable from this exact local
    /// trunk reference. `None` preserves the pre-lifecycle manual GC policy.
    pub merged_into_reference: Option<String>,
    /// Exact authenticated candidates whose retry successor makes them
    /// lifecycle-complete even when their branch is not merged into HEAD.
    pub superseded_by_agent_id: BTreeMap<String, String>,
    pub machine_global_retention: Option<MachineGlobalRetentionBinding>,
}

#[derive(Debug, Clone, Default)]
pub struct WorktreeLifecycleOptions {
    pub apply: bool,
    pub auto_reap_merged: bool,
    pub retry_successor_agent_id: Option<String>,
    pub startup_reconcile: bool,
    pub destructive_reconciliation: bool,
    pub candidate_agent_ids: Option<BTreeSet<String>>,
    pub merged_into_reference: Option<String>,
    pub worktree_root: Option<PathBuf>,
    pub remove_targets: bool,
    pub worktree_retention: WorktreeRetentionPolicy,
    pub allowed_untracked_paths: Vec<PathBuf>,
    pub artifact_retention: Option<ArtifactRetentionPolicy>,
    pub machine_global_retention: Option<MachineGlobalRetentionBinding>,
}

impl WorktreeLifecycleOptions {
    pub fn o2_launch_defaults() -> Self {
        Self {
            artifact_retention: Some(o2_launch_artifact_retention_defaults()),
            ..Self::default()
        }
    }
}

pub fn o2_launch_worktree_retention_defaults() -> WorktreeRetentionPolicy {
    WorktreeRetentionPolicy {
        max_age: None,
        max_count: Some(O2_LAUNCH_WORKTREE_MAX_COUNT),
        max_total_bytes: None,
    }
}

pub fn o2_launch_artifact_retention_defaults() -> ArtifactRetentionPolicy {
    ArtifactRetentionPolicy {
        max_count: O2_LAUNCH_ARTIFACT_KEEP_COUNT,
        max_age: None,
        max_total_bytes: None,
        unfinalized_grace: Some(O2_LAUNCH_UNFINALIZED_GRACE),
        reclaim_unverifiable: false,
        external_writers_stopped: false,
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RetrySupersessionStatus {
    Disabled,
    NotRetryLane,
    PredecessorNotFound,
    Selected,
    Ambiguous,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RetrySupersessionReport {
    pub successor_agent_id: Option<String>,
    pub predecessor_agent_id: Option<String>,
    pub status: RetrySupersessionStatus,
    pub authenticated_matches: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorktreeReconciliationState {
    Consistent,
    PendingOperation,
    RegisteredMissingPath,
    PresentDeregistered,
    AuthenticatedMissingBoth,
    Ambiguous,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorktreeReconciliationAction {
    None,
    ReportOnly,
    ForgotAuthenticatedRecord,
    PrunedRegistrationAndForgotRecord,
    QuarantinedDirectory,
    QuarantinedDirectoryAndForgotRecord,
    Protected,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WorktreeReconciliationEntry {
    pub name: String,
    pub branch: Option<String>,
    pub path: PathBuf,
    pub state: WorktreeReconciliationState,
    pub action: WorktreeReconciliationAction,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WorktreeReconciliationReport {
    pub enabled: bool,
    pub apply: bool,
    pub destructive_reconciliation: bool,
    pub forgotten_record_count: usize,
    pub pruned_registration_count: usize,
    pub quarantined_directory_count: usize,
    pub entries: Vec<WorktreeReconciliationEntry>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WorktreeLifecycleReport {
    pub enabled: bool,
    pub apply: bool,
    pub dry_run: bool,
    pub auto_reap_merged: bool,
    pub retry: RetrySupersessionReport,
    pub reconciliation: WorktreeReconciliationReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worktree_gc: Option<WorktreeGcReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_prune: Option<RunArtifactPruneReport<ArtifactRetentionFamily>>,
    pub artifact_reclaim_unverifiable: Option<bool>,
    pub artifact_external_writers_stopped: Option<bool>,
    pub apparent_checked_bytes: u64,
    pub projected_reclaimable_bytes: u64,
    pub actual_reclaimed_bytes: u64,
    pub repository_prune: WorktreeRepositoryPruneReport,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorktreeRepositoryPruneStatus {
    Disabled,
    DryRun,
    NotNeeded,
    Completed,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WorktreeRepositoryPruneReport {
    pub status: WorktreeRepositoryPruneStatus,
    pub stale_registration_count: usize,
    pub pruned_registration_count: usize,
    pub protected_registration_count: usize,
}

#[derive(Debug, Clone)]
pub struct WorktreeSweepOptions {
    pub workspace: PathBuf,
    pub apply: bool,
    pub remove_targets: bool,
    pub targets_only: bool,
    pub retention: WorktreeRetentionPolicy,
    pub allowed_untracked_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WorktreeSweepReport {
    pub workspace: PathBuf,
    pub apply: bool,
    pub dry_run: bool,
    pub remove_targets: bool,
    pub targets_only: bool,
    pub max_age_seconds: Option<u64>,
    pub max_count: Option<usize>,
    pub max_total_bytes: Option<u64>,
    #[serde(serialize_with = "serialize_worktree_report_paths")]
    pub allowed_untracked_paths: Vec<PathBuf>,
    pub discovery_status: WorktreeSweepDiscoveryStatus,
    pub worktree_root_discovered_count: usize,
    pub repository_discovered_count: usize,
    pub repository_inspected_count: usize,
    pub repository_pre_gc_skipped_count: usize,
    pub repository_gc_failed_count: usize,
    pub repository_failure_count: usize,
    pub considered_count: usize,
    pub removed_count: usize,
    pub protected_count: usize,
    pub retained_count: usize,
    pub target_removed_count: usize,
    pub orphan_removed_count: usize,
    pub apparent_considered_bytes: u64,
    pub estimated_reclaimable_bytes: u64,
    pub estimated_reclaimed_bytes: u64,
    pub repositories: Vec<WorktreeSweepRepositoryReport>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WorktreeSweepRepositoryReport {
    pub group: String,
    pub root_kind: WorktreeSweepRootKind,
    pub worktree_root: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<PathBuf>,
    pub status: WorktreeSweepRepositoryStatus,
    pub gc_attempted: bool,
    pub effects_may_have_occurred: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<WorktreeSweepFailure>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gc_report: Option<WorktreeGcReport>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorktreeSweepDiscoveryStatus {
    NoRootsDiscovered,
    RootsDiscovered,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorktreeSweepRootKind {
    WorkspaceManaged,
    RepositoryLocal,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorktreeSweepRepositoryStatus {
    Inspected,
    Skipped,
    Failed,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WorktreeSweepFailure {
    pub kind: WorktreeSweepFailureKind,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorktreeSweepFailureKind {
    RepositoryOpen,
    RepositoryAssociation,
    AmbiguousRepository,
    GarbageCollection,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WorktreeGcReport {
    pub dry_run: bool,
    pub remove_targets: bool,
    pub targets_only: bool,
    pub max_age_seconds: Option<u64>,
    pub max_count: Option<usize>,
    pub max_total_bytes: Option<u64>,
    #[serde(serialize_with = "serialize_worktree_report_paths")]
    pub allowed_untracked_paths: Vec<PathBuf>,
    pub considered_count: usize,
    pub removed_count: usize,
    pub protected_count: usize,
    pub retained_count: usize,
    pub target_removed_count: usize,
    pub orphan_removed_count: usize,
    pub apparent_considered_bytes: u64,
    pub estimated_reclaimable_bytes: u64,
    pub estimated_reclaimed_bytes: u64,
    pub entries: Vec<WorktreeGcEntry>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WorktreeGcEntry {
    pub name: String,
    pub branch: Option<String>,
    pub path: PathBuf,
    pub status: WorktreeGcStatus,
    pub reason: WorktreeGcReason,
    pub target_path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_liveness: Option<WorktreeTargetLivenessEvidence>,
    pub apparent_worktree_bytes: Option<u64>,
    pub apparent_target_bytes: Option<u64>,
    #[serde(
        default,
        serialize_with = "serialize_worktree_report_paths",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub untracked_paths: Vec<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gate_denial: Option<GateDenial>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_operation_id: Option<RetentionOperationId>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorktreeGcStatus {
    Removed,
    WouldRemove,
    Retained,
    Protected,
    OrphanPruned,
    OrphanQuarantined,
    OrphanWouldPrune,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorktreeGcReason {
    FinishedBranch,
    SupersededLane,
    UnmergedBranch,
    RetentionKeep,
    ExcludedCurrentWorktree,
    Dirty,
    UntrackedOnly,
    ActiveLease,
    ActiveClaim,
    TargetRemoved,
    TargetWouldRemove,
    LiveTarget,
    TargetLivenessUnknown,
    TargetIdentityChanged,
    SizeMeasurementFailed,
    NoTarget,
    UnregisteredOrphan,
    MachineGlobalGate,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WorktreeTargetLivenessEvidence {
    pub pid: Option<u32>,
    pub source: WorktreeTargetLivenessSource,
    pub cause: WorktreeTargetLivenessCause,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorktreeTargetLivenessSource {
    CargoTargetDir,
    DefaultCargoTarget,
    ProcessEnvironment,
    ProcessCommandLine,
    ProcessCwd,
    ProcessExecutable,
    ProcessFileDescriptor,
    ProcScan,
    MountNamespace,
    Platform,
    TargetIdentity,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorktreeTargetLivenessCause {
    PathOverlap,
    CargoLikeProcessInLane,
    ReadFailed,
    InvalidValue,
    LimitExceeded,
    TimedOut,
    Unsupported,
    NamespaceUnresolved,
    IdentityChanged,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct WorktreeReportPathWire {
    platform: String,
    encoding: String,
    data: String,
}

fn serialize_worktree_report_paths<S>(
    paths: &[PathBuf],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    paths
        .iter()
        .map(|path| worktree_report_path_wire(path))
        .collect::<Vec<_>>()
        .serialize(serializer)
}

fn worktree_report_path_wire(path: &Path) -> WorktreeReportPathWire {
    #[cfg(unix)]
    {
        let mut data = String::with_capacity(path.as_os_str().as_bytes().len().saturating_mul(2));
        for byte in path.as_os_str().as_bytes() {
            use std::fmt::Write as _;
            let _ = write!(&mut data, "{byte:02x}");
        }
        return WorktreeReportPathWire {
            platform: std::env::consts::OS.to_string(),
            encoding: "unix-bytes-hex-v1".to_string(),
            data,
        };
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::ffi::OsStrExt;
        let mut data = String::new();
        for unit in path.as_os_str().encode_wide() {
            use std::fmt::Write as _;
            let _ = write!(&mut data, "{unit:04x}");
        }
        return WorktreeReportPathWire {
            platform: std::env::consts::OS.to_string(),
            encoding: "windows-wide-hex-v1".to_string(),
            data,
        };
    }

    #[allow(unreachable_code)]
    WorktreeReportPathWire {
        platform: std::env::consts::OS.to_string(),
        encoding: "utf8-lossy-v1".to_string(),
        data: path.to_string_lossy().into_owned(),
    }
}

fn worktree_report_path_from_wire(wire: &WorktreeReportPathWire) -> Result<PathBuf> {
    if wire.platform != std::env::consts::OS {
        bail!("managed GC path snapshot was recorded for a different platform");
    }

    #[cfg(unix)]
    let path = {
        if wire.encoding != "unix-bytes-hex-v1" || !wire.data.len().is_multiple_of(2) {
            bail!("managed GC path snapshot has an invalid Unix encoding");
        }
        let mut bytes = Vec::with_capacity(wire.data.len() / 2);
        for pair in wire.data.as_bytes().chunks_exact(2) {
            let high =
                hex_nibble(pair[0]).context("managed GC path snapshot is not hexadecimal")?;
            let low = hex_nibble(pair[1]).context("managed GC path snapshot is not hexadecimal")?;
            bytes.push((high << 4) | low);
        }
        PathBuf::from(OsString::from_vec(bytes))
    };

    #[cfg(target_os = "windows")]
    let path = {
        use std::os::windows::ffi::OsStringExt;

        if wire.encoding != "windows-wide-hex-v1" || wire.data.len() % 4 != 0 {
            bail!("managed GC path snapshot has an invalid Windows encoding");
        }
        let mut units = Vec::with_capacity(wire.data.len() / 4);
        for group in wire.data.as_bytes().chunks_exact(4) {
            let mut unit = 0u16;
            for byte in group {
                unit = unit
                    .checked_mul(16)
                    .and_then(|value| hex_nibble(*byte).map(|nibble| value | u16::from(nibble)))
                    .context("managed GC path snapshot is not hexadecimal")?;
            }
            units.push(unit);
        }
        PathBuf::from(OsString::from_wide(&units))
    };

    #[cfg(not(any(unix, target_os = "windows")))]
    let path = {
        if wire.encoding != "utf8-lossy-v1" {
            bail!("managed GC path snapshot has an invalid fallback encoding");
        }
        PathBuf::from(&wire.data)
    };

    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
        || worktree_path_native_bytes(&path) > MAX_GC_ALLOWED_UNTRACKED_PATH_BYTES
        || worktree_report_path_wire(&path) != *wire
    {
        bail!("managed GC path snapshot is non-canonical or out of bounds");
    }
    Ok(path)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

pub(crate) fn worktree_report_path_text(path: &Path) -> String {
    if let Some(text) = path.to_str() {
        let mut escaped = String::new();
        for character in text.chars() {
            match character {
                '\\' => escaped.push_str("\\\\"),
                ',' => escaped.push_str("\\x2C"),
                '\n' => escaped.push_str("\\n"),
                '\r' => escaped.push_str("\\r"),
                '\t' => escaped.push_str("\\t"),
                character if character.is_control() => {
                    use std::fmt::Write as _;
                    let _ = write!(&mut escaped, "\\u{{{:X}}}", u32::from(character));
                }
                character => escaped.push(character),
            }
        }
        return escaped;
    }

    #[cfg(unix)]
    {
        let mut escaped = String::new();
        for byte in path.as_os_str().as_bytes() {
            match *byte {
                b'\\' => escaped.push_str("\\\\"),
                b',' => escaped.push_str("\\x2C"),
                b'\n' => escaped.push_str("\\n"),
                b'\r' => escaped.push_str("\\r"),
                b'\t' => escaped.push_str("\\t"),
                0x20..=0x7e => escaped.push(char::from(*byte)),
                _ => {
                    use std::fmt::Write as _;
                    let _ = write!(&mut escaped, "\\x{byte:02X}");
                }
            }
        }
        return escaped;
    }

    #[allow(unreachable_code)]
    "<unrepresentable-path>".to_string()
}

#[derive(Debug, Clone)]
pub struct WorktreeManager {
    repo_path: PathBuf,
}

/// Opaque evidence that a specific primary repository was bound and observed
/// clean through the bounded status boundary.
///
/// The capability is intentionally constructed only by [`WorktreeManager`].
/// Each effectful create revalidates both the manager/repository association
/// and current cleanliness; holding this value is not a permanent assertion
/// that the worktree remained clean.
#[derive(Debug)]
pub(crate) struct RepositoryCleanlinessCapability {
    repository: ManagedRepositoryBinding,
}

#[derive(Debug, Clone, Copy)]
enum CreationCleanliness<'a> {
    Bound(&'a RepositoryCleanlinessCapability),
    NonpublishableSimulation,
    #[cfg(test)]
    TestOnly,
}

/// A cooperative shared read lease for one verified managed worktree.
///
/// Immutable readers and collectors may hold this value concurrently. A
/// mutating MACO lifecycle must use [`ManagedWorktreeWriteLease`] instead.
/// Both write and removal leases exclude this lease. These kernel leases
/// coordinate MACO participants; they are not an OS sandbox against an
/// unrelated, uncooperative process running as the same user.
#[must_use = "the read lease must be held for the complete immutable access lifetime"]
#[derive(Debug)]
pub struct ManagedWorktreeReadLease {
    record: WorktreeRecord,
    _lock: KernelStateLock,
    _process_lease: ManagedProcessLease,
}

impl ManagedWorktreeReadLease {
    pub fn record(&self) -> &WorktreeRecord {
        &self.record
    }

    pub fn path(&self) -> &Path {
        &self.record.path
    }
}

/// Compatibility name for the original shared execution lease.
///
/// This remains a shared read lease. New mutation call sites must acquire
/// [`ManagedWorktreeWriteLease`] rather than relying on this alias.
pub type ManagedWorktreeExecutionLease = ManagedWorktreeReadLease;

/// A cooperative exclusive write lease for one verified managed worktree.
///
/// MACO parents must hold this value for the complete lifetime of every child
/// or local operation that can mutate the worktree. It excludes shared readers,
/// other writers, and managed removal before a removal intent is persisted.
#[must_use = "the write lease must be held for the complete mutation lifetime"]
#[derive(Debug)]
pub struct ManagedWorktreeWriteLease {
    record: WorktreeRecord,
    repository: ManagedRepositoryBinding,
    _lock: KernelStateLock,
    _process_lease: ManagedProcessLease,
}

impl ManagedWorktreeWriteLease {
    pub fn record(&self) -> &WorktreeRecord {
        &self.record
    }

    pub fn path(&self) -> &Path {
        &self.record.path
    }
}

/// Removal owns a distinct capability so a write lease cannot be mistaken for
/// durable removal intent during crash recovery.
#[derive(Debug)]
struct ManagedWorktreeRemovalLease {
    name: String,
    incarnation_generation: u64,
    incarnation_nonce: String,
    _lock: KernelStateLock,
    _process_lease: ManagedProcessLease,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagedProcessLeaseKind {
    Shared,
    Exclusive,
}

#[derive(Debug, Default)]
struct ManagedProcessLeaseState {
    shared: usize,
    exclusive: usize,
}

#[derive(Debug)]
struct ManagedProcessLease {
    key: OsString,
    kind: ManagedProcessLeaseKind,
}

static MANAGED_PROCESS_LEASES: std::sync::OnceLock<
    std::sync::Mutex<BTreeMap<OsString, ManagedProcessLeaseState>>,
> = std::sync::OnceLock::new();

impl ManagedProcessLease {
    fn acquire_shared(lease_name: &OsStr, path: &Path) -> Result<Self> {
        let mut table = lock_managed_process_leases();
        let key = lease_name.to_os_string();
        let state = table.entry(key.clone()).or_default();
        if state.exclusive > 0 {
            bail!("kernel state lock is already held: {}", path.display());
        }
        state.shared = state
            .shared
            .checked_add(1)
            .context("managed process lease shared count overflowed")?;
        Ok(Self {
            key,
            kind: ManagedProcessLeaseKind::Shared,
        })
    }

    fn acquire_exclusive(lease_name: &OsStr, path: &Path) -> Result<Self> {
        let mut table = lock_managed_process_leases();
        let key = lease_name.to_os_string();
        let state = table.entry(key.clone()).or_default();
        if state.shared > 0 || state.exclusive > 0 {
            bail!("kernel state lock is already held: {}", path.display());
        }
        state.exclusive = 1;
        Ok(Self {
            key,
            kind: ManagedProcessLeaseKind::Exclusive,
        })
    }

    fn is_active(lease_name: &OsStr) -> bool {
        let table = lock_managed_process_leases();
        table
            .get(lease_name)
            .is_some_and(|state| state.shared > 0 || state.exclusive > 0)
    }
}

impl Drop for ManagedProcessLease {
    fn drop(&mut self) {
        let mut table = lock_managed_process_leases();
        let Some(state) = table.get_mut(&self.key) else {
            return;
        };
        match self.kind {
            ManagedProcessLeaseKind::Shared => {
                state.shared = state.shared.saturating_sub(1);
            }
            ManagedProcessLeaseKind::Exclusive => {
                state.exclusive = state.exclusive.saturating_sub(1);
            }
        }
        if state.shared == 0 && state.exclusive == 0 {
            table.remove(&self.key);
        }
    }
}

fn managed_process_leases(
) -> &'static std::sync::Mutex<BTreeMap<OsString, ManagedProcessLeaseState>> {
    MANAGED_PROCESS_LEASES.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

fn lock_managed_process_leases(
) -> std::sync::MutexGuard<'static, BTreeMap<OsString, ManagedProcessLeaseState>> {
    match managed_process_leases().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[derive(Debug, Clone)]
pub struct WorktreeCreateOptions {
    pub agent_id: String,
    pub branch: Option<String>,
    pub base: Option<String>,
    pub worktree_root: Option<PathBuf>,
}

/// Inputs for creating a structurally neutral arbitration worktree.
///
/// The arbiter identity is checked against both normalized source identities,
/// and the exact base OID is bound to a fresh MACO-owned default branch. The
/// caller cannot supply or reuse a branch.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct NeutralWorktreeCreateOptions {
    pub arbiter_agent_id: String,
    pub source_agent_ids: [String; 2],
    pub base_oid: Oid,
    pub worktree_root: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy)]
enum WorktreeCreationPolicy {
    Standard,
    NeutralFresh { exact_base_oid: Oid },
}

impl WorktreeCreationPolicy {
    fn is_neutral_fresh(self) -> bool {
        matches!(self, Self::NeutralFresh { .. })
    }

    fn exact_base_oid(self) -> Option<Oid> {
        match self {
            Self::Standard => None,
            Self::NeutralFresh { exact_base_oid } => Some(exact_base_oid),
        }
    }
}

struct ValidatedNeutralWorktreeCreate {
    options: WorktreeCreateOptions,
    exact_base_oid: Oid,
}

impl NeutralWorktreeCreateOptions {
    fn validate(self) -> Result<ValidatedNeutralWorktreeCreate> {
        let arbiter_agent_id = normalize_agent_id(&self.arbiter_agent_id)
            .context("neutral arbiter agent id is invalid")?;
        let [first_source, second_source] = self.source_agent_ids;
        let first_source =
            normalize_agent_id(&first_source).context("first source agent id is invalid")?;
        let second_source =
            normalize_agent_id(&second_source).context("second source agent id is invalid")?;
        if arbiter_agent_id == first_source || arbiter_agent_id == second_source {
            bail!("neutral arbiter agent id must differ from both normalized source agent ids");
        }

        Ok(ValidatedNeutralWorktreeCreate {
            options: WorktreeCreateOptions {
                agent_id: arbiter_agent_id,
                branch: None,
                base: Some(self.base_oid.to_string()),
                worktree_root: self.worktree_root,
            },
            exact_base_oid: self.base_oid,
        })
    }
}

/// Holds the durable path-claim serialization lock across neutral creation.
///
/// This gives the "no inherited claim" check one real linearization boundary:
/// no claim writer can add or release an arbiter claim between the signed
/// snapshot check and the completed managed-worktree creation.
#[derive(Debug)]
struct NeutralClaimBoundary {
    snapshot: LockedClaimsSnapshot,
}

impl NeutralClaimBoundary {
    fn acquire(repo: &Repository, arbiter_agent_id: &str) -> Result<Self> {
        let repo_path = repo.workdir().unwrap_or_else(|| repo.path());
        let store = SyncStore::open(repo_path)
            .context("failed to authenticate durable claims for neutral worktree creation")?;
        let snapshot = store
            .lock_authenticated_snapshot()
            .context("failed to lock authenticated claims for neutral worktree creation")?;
        let result = (|| -> Result<()> {
            if snapshot
                .claims()
                .iter()
                .any(|claim| claim.agent_id == arbiter_agent_id)
            {
                bail!(
                    "neutral arbiter '{arbiter_agent_id}' has an active durable path claim; refusing inherited claim authority"
                );
            }
            Ok(())
        })();
        finish_with_neutral_claim_lock_verification(result, snapshot.verify())?;
        Ok(Self { snapshot })
    }

    fn verify(&self) -> Result<()> {
        self.snapshot.verify()
    }
}

fn finish_with_neutral_claim_lock_verification<T>(
    result: Result<T>,
    verification: Result<()>,
) -> Result<T> {
    match (result, verification) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(lock_error)) => Err(lock_error),
        (Err(error), Err(lock_error)) => Err(error.context(format!(
            "operation also lost its durable claims lock-path binding: {lock_error:#}"
        ))),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagedRepositoryBinding {
    #[serde(with = "persisted_path")]
    common_dir: PathBuf,
    common_dir_identity: FileIdentity,
    #[serde(with = "persisted_path")]
    repository_workdir: PathBuf,
    repository_workdir_identity: FileIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagedWorktreeBinding {
    name: String,
    #[serde(with = "persisted_path")]
    root: PathBuf,
    root_identity: FileIdentity,
    #[serde(with = "persisted_path")]
    path: PathBuf,
    path_identity: FileIdentity,
    #[serde(with = "persisted_path")]
    metadata_dir: PathBuf,
    metadata_dir_identity: FileIdentity,
    worktree_git_file_identity: FileIdentity,
    metadata_gitdir_file_identity: FileIdentity,
    metadata_head_file_identity: FileIdentity,
    branch: String,
    branch_created_by_maco: bool,
    base_oid: String,
    created_branch_oid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    created_at_unix_nanos: Option<i64>,
    #[serde(default, skip_serializing_if = "is_false")]
    creation_lock_pending: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagedWorktreeRegistry {
    version: u32,
    checksum: String,
    repository: ManagedRepositoryBinding,
    records: BTreeMap<String, ManagedWorktreeBinding>,
    operations: BTreeMap<String, ManagedWorktreeOperation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagedIncarnation {
    generation: u64,
    nonce: String,
    active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedManagedState {
    version: u32,
    snapshot_revision: u64,
    repository: RepositoryAuthBinding,
    registry: ManagedWorktreeRegistry,
    incarnations: BTreeMap<String, ManagedIncarnation>,
    #[serde(default)]
    retired_leases: BTreeMap<String, FileIdentity>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ManagedWorktreeOperationKind {
    Create,
    Remove,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ManagedWorktreeOperationPhase {
    CreateIntent,
    CreatePrepared,
    CreateStaged,
    CreateObserved,
    RemovePrepared,
    WorktreeQuarantined,
    MetadataQuarantined,
    WorktreeDeleted,
    MetadataDeleted,
    BranchDeleted,
}

fn managed_operation_kind_label(kind: ManagedWorktreeOperationKind) -> &'static str {
    match kind {
        ManagedWorktreeOperationKind::Create => "create",
        ManagedWorktreeOperationKind::Remove => "remove",
    }
}

fn managed_operation_phase_label(phase: ManagedWorktreeOperationPhase) -> &'static str {
    match phase {
        ManagedWorktreeOperationPhase::CreateIntent => "create_intent",
        ManagedWorktreeOperationPhase::CreatePrepared => "create_prepared",
        ManagedWorktreeOperationPhase::CreateStaged => "create_staged",
        ManagedWorktreeOperationPhase::CreateObserved => "create_observed",
        ManagedWorktreeOperationPhase::RemovePrepared => "remove_prepared",
        ManagedWorktreeOperationPhase::WorktreeQuarantined => "worktree_quarantined",
        ManagedWorktreeOperationPhase::MetadataQuarantined => "metadata_quarantined",
        ManagedWorktreeOperationPhase::WorktreeDeleted => "worktree_deleted",
        ManagedWorktreeOperationPhase::MetadataDeleted => "metadata_deleted",
        ManagedWorktreeOperationPhase::BranchDeleted => "branch_deleted",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ManagedBranchOwnership {
    Unknown,
    Preexisting,
    CreatedByMaco,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "origin", rename_all = "snake_case", deny_unknown_fields)]
enum ManagedRemovalSafety {
    Explicit,
    GarbageCollection {
        dirtiness: ManagedGcDirtinessSnapshot,
        target: ManagedGcTargetSnapshot,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "classification", rename_all = "snake_case", deny_unknown_fields)]
enum ManagedGcDirtinessSnapshot {
    Clean,
    UntrackedOnly { paths: Vec<WorktreeReportPathWire> },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum ManagedGcTargetSnapshot {
    Absent,
    Present { identity: FileIdentity },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagedWorktreeOperation {
    kind: ManagedWorktreeOperationKind,
    phase: ManagedWorktreeOperationPhase,
    name: String,
    #[serde(with = "persisted_path")]
    root: PathBuf,
    root_identity: FileIdentity,
    #[serde(with = "persisted_path")]
    path: PathBuf,
    prepared_path_identity: Option<FileIdentity>,
    #[serde(default, with = "persisted_optional_path")]
    staging_root: Option<PathBuf>,
    staging_root_identity: Option<FileIdentity>,
    #[serde(default, with = "persisted_optional_path")]
    staging_path: Option<PathBuf>,
    staged_path_identity: Option<FileIdentity>,
    staged_metadata: Option<StagedWorktreeMetadata>,
    branch: String,
    base_oid: String,
    branch_preexisting_oid: Option<String>,
    branch_ownership: ManagedBranchOwnership,
    owned_branch_oid: Option<String>,
    binding: Option<ManagedWorktreeBinding>,
    delete_branch: bool,
    force: bool,
    expected_branch_oid: Option<String>,
    /// Legacy f3 GC digest retained only for authenticated format compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gc_dirtiness_checksum: Option<String>,
    /// Authenticated removal origin and, for GC, the exact reviewed state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    removal_safety: Option<ManagedRemovalSafety>,
    #[serde(
        default,
        with = "persisted_optional_path",
        skip_serializing_if = "Option::is_none"
    )]
    worktree_quarantine_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    worktree_quarantine_identity: Option<FileIdentity>,
    #[serde(
        default,
        with = "persisted_optional_path",
        skip_serializing_if = "Option::is_none"
    )]
    metadata_quarantine_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    metadata_quarantine_identity: Option<FileIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StagedWorktreeMetadata {
    #[serde(with = "persisted_path")]
    metadata_dir: PathBuf,
    metadata_dir_identity: FileIdentity,
    worktree_git_file_identity: FileIdentity,
    metadata_gitdir_file_identity: FileIdentity,
    metadata_head_file_identity: FileIdentity,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedPathWire {
    platform: String,
    encoding: String,
    data: String,
}

fn encode_persisted_path(path: &Path) -> std::result::Result<PersistedPathWire, String> {
    validate_persisted_path(path)?;

    #[cfg(unix)]
    {
        let bytes = path.as_os_str().as_bytes();
        if bytes.len() > MAX_PERSISTED_PATH_BYTES {
            return Err(format!(
                "persisted path exceeds its {MAX_PERSISTED_PATH_BYTES}-byte limit"
            ));
        }
        let mut data = String::with_capacity(bytes.len().saturating_mul(2));
        for byte in bytes {
            use std::fmt::Write as _;
            write!(&mut data, "{byte:02x}")
                .map_err(|_| "failed to encode persisted path".to_string())?;
        }
        Ok(PersistedPathWire {
            platform: std::env::consts::OS.to_string(),
            encoding: "unix-bytes-hex-v1".to_string(),
            data,
        })
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err("lossless persisted worktree paths are unsupported on this platform".to_string())
    }
}

fn decode_persisted_path(wire: PersistedPathWire) -> std::result::Result<PathBuf, String> {
    #[cfg(unix)]
    {
        if wire.platform != std::env::consts::OS {
            return Err(format!(
                "persisted path platform '{}' does not match '{}'",
                wire.platform,
                std::env::consts::OS
            ));
        }
        if wire.encoding != "unix-bytes-hex-v1" {
            return Err(format!(
                "unsupported persisted path encoding '{}'",
                wire.encoding
            ));
        }
        if wire.data.is_empty()
            || !wire.data.len().is_multiple_of(2)
            || wire.data.len() > MAX_PERSISTED_PATH_BYTES.saturating_mul(2)
            || !wire
                .data
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(
                "persisted path hex is empty, malformed, noncanonical, or oversized".to_string(),
            );
        }
        let mut bytes = Vec::with_capacity(wire.data.len() / 2);
        for pair in wire.data.as_bytes().chunks_exact(2) {
            let digit = |byte| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                _ => None,
            };
            let high = digit(pair[0]).ok_or_else(|| "invalid high hex digit".to_string())?;
            let low = digit(pair[1]).ok_or_else(|| "invalid low hex digit".to_string())?;
            bytes.push((high << 4) | low);
        }
        if bytes.contains(&0) {
            return Err("persisted path contains a NUL byte".to_string());
        }
        let path = PathBuf::from(std::ffi::OsString::from_vec(bytes));
        validate_persisted_path(&path)?;
        Ok(path)
    }
    #[cfg(not(unix))]
    {
        let _ = wire;
        Err("lossless persisted worktree paths are unsupported on this platform".to_string())
    }
}

fn validate_persisted_path(path: &Path) -> std::result::Result<(), String> {
    if !path.is_absolute() {
        return Err("persisted path must be absolute".to_string());
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            std::path::Component::RootDir => {
                normalized.push(Path::new(std::path::MAIN_SEPARATOR_STR))
            }
            std::path::Component::Normal(segment) => normalized.push(segment),
            std::path::Component::CurDir | std::path::Component::ParentDir => {
                return Err("persisted path is not lexically canonical".to_string())
            }
        }
    }
    if normalized.as_os_str() != path.as_os_str() {
        return Err("persisted path is not in canonical component form".to_string());
    }
    Ok(())
}

mod persisted_path {
    use super::*;
    use serde::{de::Error as _, ser::Error as _, Deserializer, Serializer};

    pub fn serialize<S>(path: &Path, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        encode_persisted_path(path)
            .map_err(S::Error::custom)?
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<PathBuf, D::Error>
    where
        D: Deserializer<'de>,
    {
        decode_persisted_path(PersistedPathWire::deserialize(deserializer)?)
            .map_err(D::Error::custom)
    }
}

mod persisted_optional_path {
    use super::*;
    use serde::{de::Error as _, ser::Error as _, Deserializer, Serializer};

    pub fn serialize<S>(
        path: &Option<PathBuf>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        path.as_deref()
            .map(encode_persisted_path)
            .transpose()
            .map_err(S::Error::custom)?
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Option<PathBuf>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<PersistedPathWire>::deserialize(deserializer)?
            .map(decode_persisted_path)
            .transpose()
            .map_err(D::Error::custom)
    }
}

struct ManagedWorktreeRegistryStore {
    repo_path: PathBuf,
    state_root: SafeRoot,
    repository: ManagedRepositoryBinding,
}

#[derive(Debug)]
struct ManagedWorktreeRegistryLock {
    lock: KernelStateLock,
    root_identity: FileIdentity,
    lock_identity: FileIdentity,
}

#[cfg(unix)]
#[derive(Debug)]
struct PrimaryWorktreeGuardLayout {
    worktree_path: PathBuf,
    git_dir: PathBuf,
    common_dir: PathBuf,
    hooks_dir: PathBuf,
    state_dir: PathBuf,
    pre_commit: PathBuf,
    pre_merge_commit: PathBuf,
    pre_push: PathBuf,
}

#[cfg(unix)]
#[derive(Debug)]
struct InstalledPrePushGuard {
    target: PathBuf,
    previous: PathBuf,
}

/// Installs the advisory branch guard in the primary repository's default
/// shared hooks directory. The operation never sets `core.hooksPath`.
#[cfg(unix)]
pub fn install_primary_worktree_guard(repo_path: impl AsRef<Path>) -> Result<WorktreeGuardReport> {
    let layout = primary_worktree_guard_layout(repo_path.as_ref())?;
    match fs::symlink_metadata(&layout.state_dir) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                bail!(
                    "MACO worktree guard state path is not an owned directory: {}",
                    layout.state_dir.display()
                );
            }
            let mut report = verify_primary_worktree_guard_layout(&layout)?;
            report.status = WorktreeGuardStatus::AlreadyInstalled;
            return Ok(report);
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("failed to inspect worktree guard state"),
    }

    let pre_push_target = select_pre_push_guard_target(&layout)?;
    preflight_guard_target(&layout.pre_commit)?;
    preflight_guard_target(&layout.pre_merge_commit)?;
    preflight_guard_target(&pre_push_target)?;

    fs::create_dir(&layout.state_dir).with_context(|| {
        format!(
            "failed to create worktree guard state directory {}",
            layout.state_dir.display()
        )
    })?;
    fs::set_permissions(&layout.state_dir, fs::Permissions::from_mode(0o700))
        .context("failed to protect worktree guard state directory")?;

    let installation = (|| -> Result<WorktreeGuardReport> {
        write_guard_state(&layout, &pre_push_target)?;
        install_guard_target(&layout.pre_commit)?;
        if let Err(error) = install_guard_target(&layout.pre_merge_commit) {
            rollback_installed_guard_target(&layout.pre_commit)?;
            return Err(error);
        }
        if let Err(error) = install_guard_target(&pre_push_target) {
            rollback_installed_guard_target(&layout.pre_merge_commit)?;
            rollback_installed_guard_target(&layout.pre_commit)?;
            return Err(error);
        }
        let mut report = verify_primary_worktree_guard_layout(&layout)?;
        report.status = WorktreeGuardStatus::Installed;
        Ok(report)
    })();

    if installation.is_err() {
        let _ = rollback_installed_guard_target(&pre_push_target);
        let _ = rollback_installed_guard_target(&layout.pre_merge_commit);
        let _ = rollback_installed_guard_target(&layout.pre_commit);
        let _ = remove_guard_state(&layout);
    }
    installation
}

#[cfg(not(unix))]
pub fn install_primary_worktree_guard(_repo_path: impl AsRef<Path>) -> Result<WorktreeGuardReport> {
    bail!("the POSIX MACO worktree guard is unsupported on this platform")
}

/// Verifies the exact installed hook payload and its primary-repository
/// binding without changing repository state.
#[cfg(unix)]
pub fn verify_primary_worktree_guard(repo_path: impl AsRef<Path>) -> Result<WorktreeGuardReport> {
    let layout = primary_worktree_guard_layout(repo_path.as_ref())?;
    verify_primary_worktree_guard_layout(&layout)
}

#[cfg(not(unix))]
pub fn verify_primary_worktree_guard(_repo_path: impl AsRef<Path>) -> Result<WorktreeGuardReport> {
    bail!("the POSIX MACO worktree guard is unsupported on this platform")
}

/// Removes only an exactly verified guard and restores hooks that were
/// preserved by its installation.
#[cfg(unix)]
pub fn uninstall_primary_worktree_guard(
    repo_path: impl AsRef<Path>,
) -> Result<WorktreeGuardReport> {
    let layout = primary_worktree_guard_layout(repo_path.as_ref())?;
    match fs::symlink_metadata(&layout.state_dir) {
        Err(error) if error.kind() == ErrorKind::NotFound => {
            require_no_orphaned_guard_payload(&layout)?;
            return Ok(worktree_guard_report(
                &layout,
                layout.pre_push.clone(),
                WorktreeGuardStatus::AlreadyAbsent,
            ));
        }
        Err(error) => return Err(error).context("failed to inspect worktree guard state"),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            bail!(
                "MACO worktree guard state path is not an owned directory: {}",
                layout.state_dir.display()
            )
        }
        Ok(_) => {}
    }

    let verified = verify_primary_worktree_guard_layout(&layout)?;
    let pre_push = resolve_installed_pre_push_guard(&layout)?;
    uninstall_guard_target_with_previous(&pre_push.target, &pre_push.previous)?;
    uninstall_guard_target(&layout.pre_merge_commit)?;
    uninstall_guard_target(&layout.pre_commit)?;
    remove_guard_state(&layout)?;
    Ok(worktree_guard_report(
        &layout,
        verified.pre_push_target,
        WorktreeGuardStatus::Removed,
    ))
}

#[cfg(not(unix))]
pub fn uninstall_primary_worktree_guard(
    _repo_path: impl AsRef<Path>,
) -> Result<WorktreeGuardReport> {
    bail!("the POSIX MACO worktree guard is unsupported on this platform")
}

#[cfg(unix)]
fn primary_worktree_guard_layout(repo_path: &Path) -> Result<PrimaryWorktreeGuardLayout> {
    let repository = crate::git_repository::open(repo_path).with_context(|| {
        format!(
            "failed to open primary repository for worktree guard: {}",
            repo_path.display()
        )
    })?;
    let worktree_path = fs::canonicalize(
        repository
            .workdir()
            .context("worktree guard requires a non-bare repository")?,
    )
    .context("failed to resolve primary worktree path")?;
    let git_dir =
        fs::canonicalize(repository.path()).context("failed to resolve primary Git directory")?;
    let common_dir = fs::canonicalize(repository.commondir())
        .context("failed to resolve Git common directory")?;
    if git_dir != common_dir {
        bail!(
            "worktree guard installation must be managed from the primary worktree; {} is linked",
            worktree_path.display()
        );
    }
    match repository.config()?.get_entry("core.hooksPath") {
        Ok(_) => {
            bail!(
                "worktree guard requires the default shared Git hooks directory; remove core.hooksPath before installing"
            )
        }
        Err(error) if error.code() == ErrorCode::NotFound => {}
        Err(error) => return Err(error).context("failed to inspect the effective core.hooksPath"),
    }
    let hooks_dir = common_dir.join("hooks");
    require_plain_directory(&hooks_dir, "default Git hooks directory")?;
    Ok(PrimaryWorktreeGuardLayout {
        worktree_path,
        git_dir,
        common_dir,
        state_dir: hooks_dir.join(WORKTREE_GUARD_STATE_DIRECTORY),
        pre_commit: hooks_dir.join("pre-commit"),
        pre_merge_commit: hooks_dir.join("pre-merge-commit"),
        pre_push: hooks_dir.join("pre-push"),
        hooks_dir,
    })
}

#[cfg(unix)]
fn select_pre_push_guard_target(layout: &PrimaryWorktreeGuardLayout) -> Result<PathBuf> {
    let bytes = read_guard_regular_file(&layout.pre_push)?.with_context(|| {
        format!(
            "human-authorship dispatcher v5 must be installed before the MACO worktree guard: {}",
            layout.pre_push.display()
        )
    })?;
    require_exact_human_authorship_dispatcher_v5(&layout.pre_push, &bytes)?;
    Ok(layout.hooks_dir.join(WORKTREE_GUARD_PRE_PUSH_TARGET))
}

#[cfg(unix)]
fn require_exact_human_authorship_dispatcher_v5(path: &Path, bytes: &[u8]) -> Result<()> {
    if bytes != HUMAN_AUTHORSHIP_PRE_PUSH_DISPATCHER_V5 {
        bail!(
            "human-authorship dispatcher v5 is missing or modified: {}",
            path.display()
        );
    }
    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to inspect human-authorship dispatcher {}",
            path.display()
        )
    })?;
    if metadata.permissions().mode() & 0o111 == 0 {
        bail!(
            "human-authorship dispatcher v5 is not executable: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn preflight_guard_target(target: &Path) -> Result<()> {
    let backup = guard_previous_path(target)?;
    if fs::symlink_metadata(&backup).is_ok() {
        bail!(
            "worktree guard backup collision; refusing to replace {}",
            backup.display()
        );
    }
    let staged = guard_staged_path(target)?;
    if fs::symlink_metadata(&staged).is_ok() {
        bail!(
            "worktree guard staged-file collision; refusing to replace {}",
            staged.display()
        );
    }
    if let Some(bytes) = read_guard_regular_file(target)? {
        if bytes == WORKTREE_GUARD_ASSET {
            bail!(
                "worktree guard hook exists without owned state; refusing to adopt {}",
                target.display()
            );
        }
    }
    Ok(())
}

#[cfg(unix)]
fn install_guard_target(target: &Path) -> Result<()> {
    let backup = guard_previous_path(target)?;
    let staged = guard_staged_path(target)?;
    let had_previous = read_guard_regular_file(target)?.is_some();
    publish_guard_file(&staged, WORKTREE_GUARD_ASSET, 0o755)?;

    if had_previous {
        if let Err(error) = fs::hard_link(target, &backup) {
            let _ = fs::remove_file(&staged);
            return Err(error).with_context(|| {
                format!(
                    "failed to preserve existing hook {} as {}",
                    target.display(),
                    backup.display()
                )
            });
        }
    }
    if let Err(error) = fs::rename(&staged, target) {
        if had_previous {
            let _ = fs::remove_file(&backup);
        }
        let _ = fs::remove_file(&staged);
        return Err(error).with_context(|| {
            format!(
                "failed to atomically install guard hook {}",
                target.display()
            )
        });
    }
    sync_guard_parent_directory(target)
}

#[cfg(unix)]
fn uninstall_guard_target(target: &Path) -> Result<()> {
    let backup = guard_previous_path(target)?;
    uninstall_guard_target_with_previous(target, &backup)
}

#[cfg(unix)]
fn uninstall_guard_target_with_previous(target: &Path, previous: &Path) -> Result<()> {
    require_exact_guard_hook(target)?;
    if fs::symlink_metadata(previous).is_ok() {
        fs::rename(previous, target).with_context(|| {
            format!(
                "failed to atomically restore preserved hook {} to {}",
                previous.display(),
                target.display()
            )
        })?;
    } else {
        fs::remove_file(target)
            .with_context(|| format!("failed to remove guard hook {}", target.display()))?;
    }
    sync_guard_parent_directory(target)
}

#[cfg(unix)]
fn rollback_installed_guard_target(target: &Path) -> Result<()> {
    match read_guard_regular_file(target)? {
        Some(bytes) if bytes == WORKTREE_GUARD_ASSET => uninstall_guard_target(target),
        Some(_) => bail!(
            "worktree guard rollback refused a changed hook: {}",
            target.display()
        ),
        None => Ok(()),
    }
}

#[cfg(unix)]
fn write_guard_state(layout: &PrimaryWorktreeGuardLayout, pre_push_target: &Path) -> Result<()> {
    let target_name = pre_push_target
        .file_name()
        .and_then(OsStr::to_str)
        .context("worktree guard pre-push target is not UTF-8")?;
    if target_name != WORKTREE_GUARD_PRE_PUSH_TARGET {
        bail!("worktree guard requires the canonical v5 pre-push chain");
    }
    for (name, value) in [
        ("marker", WORKTREE_GUARD_MARKER.to_string()),
        ("git-dir", guard_path_text(&layout.git_dir)?),
        ("common-dir", guard_path_text(&layout.common_dir)?),
        ("pre-push-target", target_name.to_string()),
        (
            "pre-commit-previous",
            guard_hook_state_value(&layout.pre_commit)?,
        ),
        (
            "pre-merge-commit-previous",
            guard_hook_state_value(&layout.pre_merge_commit)?,
        ),
        (
            "pre-push-previous",
            guard_hook_state_value(pre_push_target)?,
        ),
    ] {
        let mut bytes = value.into_bytes();
        bytes.push(b'\n');
        publish_guard_file(&layout.state_dir.join(name), &bytes, 0o600)?;
    }
    Ok(())
}

#[cfg(unix)]
fn verify_primary_worktree_guard_layout(
    layout: &PrimaryWorktreeGuardLayout,
) -> Result<WorktreeGuardReport> {
    let marker = read_guard_state_line(layout, "marker")?;
    if marker != WORKTREE_GUARD_MARKER {
        bail!("MACO worktree guard ownership marker is missing or changed");
    }
    if read_guard_state_line(layout, "git-dir")? != guard_path_text(&layout.git_dir)?
        || read_guard_state_line(layout, "common-dir")? != guard_path_text(&layout.common_dir)?
    {
        bail!("MACO worktree guard repository binding changed");
    }
    let pre_push = resolve_installed_pre_push_guard(layout)?;
    require_exact_guard_hook(&layout.pre_commit)?;
    require_exact_guard_hook(&layout.pre_merge_commit)?;
    require_exact_guard_hook(&pre_push.target)?;
    require_guard_previous_binding(layout, "pre-commit-previous", &layout.pre_commit)?;
    require_guard_previous_binding(
        layout,
        "pre-merge-commit-previous",
        &layout.pre_merge_commit,
    )?;
    require_guard_previous_binding(layout, "pre-push-previous", &pre_push.target)?;
    Ok(worktree_guard_report(
        layout,
        pre_push.target,
        WorktreeGuardStatus::Verified,
    ))
}

#[cfg(unix)]
fn resolve_installed_pre_push_guard(
    layout: &PrimaryWorktreeGuardLayout,
) -> Result<InstalledPrePushGuard> {
    let target_name = read_guard_state_line(layout, "pre-push-target")?;
    if target_name != WORKTREE_GUARD_PRE_PUSH_TARGET {
        bail!("worktree guard pre-push composition state is invalid");
    }
    let active = read_guard_regular_file(&layout.pre_push)?
        .context("human-authorship dispatcher v5 is missing")?;
    require_exact_human_authorship_dispatcher_v5(&layout.pre_push, &active)?;
    let target = layout.hooks_dir.join(WORKTREE_GUARD_PRE_PUSH_TARGET);
    Ok(InstalledPrePushGuard {
        previous: guard_previous_path(&target)?,
        target,
    })
}

#[cfg(unix)]
fn require_exact_guard_hook(path: &Path) -> Result<()> {
    let bytes = read_guard_regular_file(path)?
        .with_context(|| format!("worktree guard hook is missing: {}", path.display()))?;
    if bytes != WORKTREE_GUARD_ASSET {
        bail!("worktree guard hook changed: {}", path.display());
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect worktree guard hook {}", path.display()))?;
    if metadata.permissions().mode() & 0o111 == 0 {
        bail!("worktree guard hook is not executable: {}", path.display());
    }
    Ok(())
}

#[cfg(unix)]
fn require_guard_previous_binding(
    layout: &PrimaryWorktreeGuardLayout,
    state_name: &str,
    target: &Path,
) -> Result<()> {
    let expected = read_guard_state_line(layout, state_name)?;
    let backup = guard_previous_path(target)?;
    let actual = guard_hook_state_value(&backup)?;
    if actual != expected {
        bail!(
            "worktree guard preserved-hook binding changed: {}",
            backup.display()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn require_no_orphaned_guard_payload(layout: &PrimaryWorktreeGuardLayout) -> Result<()> {
    for target in [
        layout.pre_commit.clone(),
        layout.pre_merge_commit.clone(),
        layout.pre_push.clone(),
        layout.hooks_dir.join(WORKTREE_GUARD_PRE_PUSH_TARGET),
    ] {
        if read_guard_regular_file(&target)?.as_deref() == Some(WORKTREE_GUARD_ASSET) {
            bail!(
                "worktree guard payload exists without owned state; refusing uninstall: {}",
                target.display()
            );
        }
        for residue in [guard_previous_path(&target)?, guard_staged_path(&target)?] {
            if fs::symlink_metadata(&residue).is_ok() {
                bail!(
                    "worktree guard preserved or staged hook exists without owned state; refusing uninstall: {}",
                    residue.display()
                );
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn guard_previous_path(target: &Path) -> Result<PathBuf> {
    let name = target
        .file_name()
        .context("worktree guard target has no filename")?;
    let mut previous = name.to_os_string();
    previous.push(WORKTREE_GUARD_PREVIOUS_SUFFIX);
    Ok(target.with_file_name(previous))
}

#[cfg(unix)]
fn guard_staged_path(target: &Path) -> Result<PathBuf> {
    let name = target
        .file_name()
        .context("worktree guard target has no filename")?;
    let mut staged = name.to_os_string();
    staged.push(WORKTREE_GUARD_STAGED_SUFFIX);
    Ok(target.with_file_name(staged))
}

#[cfg(unix)]
fn guard_hook_state_value(path: &Path) -> Result<String> {
    let Some(bytes) = read_guard_regular_file(path)? else {
        return Ok("absent".to_string());
    };
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect preserved hook {}", path.display()))?;
    let object_id = Oid::hash_object(ObjectType::Blob, &bytes)
        .context("failed to bind preserved hook bytes")?;
    Ok(format!(
        "present:{}:{:o}",
        object_id,
        metadata.permissions().mode() & 0o7777
    ))
}

#[cfg(unix)]
fn sync_guard_parent_directory(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .context("worktree guard target has no parent directory")?;
    fs::File::open(parent)
        .with_context(|| format!("failed to open hooks directory {}", parent.display()))?
        .sync_all()
        .with_context(|| format!("failed to sync hooks directory {}", parent.display()))
}

#[cfg(unix)]
fn read_guard_regular_file(path: &Path) -> Result<Option<Vec<u8>>> {
    let before = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect guard file {}", path.display()))
        }
    };
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.nlink() != 1
        || before.len() > MAX_WORKTREE_GUARD_FILE_BYTES
    {
        bail!(
            "guard file is not a bounded single-link regular file: {}",
            path.display()
        );
    }
    let bytes =
        fs::read(path).with_context(|| format!("failed to read guard file {}", path.display()))?;
    let after = fs::symlink_metadata(path)
        .with_context(|| format!("failed to re-inspect guard file {}", path.display()))?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.permissions().mode() != after.permissions().mode()
        || u64::try_from(bytes.len()).map_or(true, |len| len > MAX_WORKTREE_GUARD_FILE_BYTES)
    {
        bail!("guard file changed while being read: {}", path.display());
    }
    Ok(Some(bytes))
}

#[cfg(unix)]
fn publish_guard_file(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("failed to create guard file {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write guard file {}", path.display()))?;
    file.set_permissions(fs::Permissions::from_mode(mode))
        .with_context(|| format!("failed to set guard file mode {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync guard file {}", path.display()))
}

#[cfg(unix)]
fn read_guard_state_line(layout: &PrimaryWorktreeGuardLayout, name: &str) -> Result<String> {
    let bytes = read_guard_regular_file(&layout.state_dir.join(name))?
        .with_context(|| format!("worktree guard state is missing: {name}"))?;
    let value = bytes
        .strip_suffix(b"\n")
        .context("worktree guard state is not newline terminated")?;
    if value.is_empty() || value.contains(&b'\n') || value.contains(&b'\r') {
        bail!("worktree guard state is not one non-empty line: {name}");
    }
    String::from_utf8(value.to_vec()).context("worktree guard state is not UTF-8")
}

#[cfg(unix)]
fn guard_path_text(path: &Path) -> Result<String> {
    let text = path
        .to_str()
        .context("worktree guard requires UTF-8 repository paths")?;
    if text.is_empty() || text.contains(['\n', '\r']) {
        bail!("worktree guard repository path contains an invalid line break");
    }
    Ok(text.to_string())
}

#[cfg(unix)]
fn remove_guard_state(layout: &PrimaryWorktreeGuardLayout) -> Result<()> {
    for name in [
        "marker",
        "git-dir",
        "common-dir",
        "pre-push-target",
        "pre-commit-previous",
        "pre-merge-commit-previous",
        "pre-push-previous",
    ] {
        match fs::remove_file(layout.state_dir.join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to remove worktree guard state {name}"))
            }
        }
    }
    fs::remove_dir(&layout.state_dir).context("failed to remove worktree guard state directory")
}

#[cfg(unix)]
fn worktree_guard_report(
    layout: &PrimaryWorktreeGuardLayout,
    pre_push_target: PathBuf,
    status: WorktreeGuardStatus,
) -> WorktreeGuardReport {
    WorktreeGuardReport {
        status,
        worktree_path: layout.worktree_path.clone(),
        hooks_path: layout.hooks_dir.clone(),
        pre_push_target,
        mode: "primary",
    }
}

impl WorktreeManager {
    pub fn new(repo_path: impl Into<PathBuf>) -> Self {
        Self {
            repo_path: repo_path.into(),
        }
    }

    pub fn init_repository(path: impl AsRef<Path>, initial_branch: &str) -> Result<RepositoryInfo> {
        let path = path.as_ref();
        fs::create_dir_all(path)
            .with_context(|| format!("failed to create repository directory {}", path.display()))?;

        let repo = if path.join(".git").exists() {
            crate::git_repository::open(path)
                .with_context(|| format!("failed to open repository {}", path.display()))?
        } else {
            let mut options = RepositoryInitOptions::new();
            options.initial_head(initial_branch);
            Repository::init_opts(path, &options)
                .with_context(|| format!("failed to initialize repository {}", path.display()))?
        };

        repository_info(&repo)
    }

    pub fn create(&self, options: WorktreeCreateOptions) -> Result<WorktreeRecord> {
        self.create_with_retention(options, WorktreeRetentionPolicy::default())
    }

    pub fn create_with_retention(
        &self,
        options: WorktreeCreateOptions,
        retention: WorktreeRetentionPolicy,
    ) -> Result<WorktreeRecord> {
        let cleanliness = self.acquire_repository_cleanliness().with_context(|| {
            "managed worktree creation requires a clean repository; `maco worktree create` derives the cleanliness capability automatically when the target repository is already clean"
        })?;
        self.create_with_repository_cleanliness_and_retention(options, retention, &cleanliness)
    }

    /// Captures repository-bound cleanliness evidence for effectful managed
    /// worktree creation. Callers must keep the opaque value and supply it to
    /// the explicit capability-bearing create entrypoint.
    #[allow(dead_code)]
    pub(crate) fn acquire_repository_cleanliness(&self) -> Result<RepositoryCleanlinessCapability> {
        RepositoryCleanlinessCapability::capture(self)
    }

    #[allow(dead_code)]
    pub(crate) fn create_with_repository_cleanliness(
        &self,
        options: WorktreeCreateOptions,
        cleanliness: &RepositoryCleanlinessCapability,
    ) -> Result<WorktreeRecord> {
        self.create_with_repository_cleanliness_and_retention(
            options,
            WorktreeRetentionPolicy::default(),
            cleanliness,
        )
    }

    #[allow(dead_code)]
    pub(crate) fn create_with_repository_cleanliness_and_retention(
        &self,
        options: WorktreeCreateOptions,
        retention: WorktreeRetentionPolicy,
        cleanliness: &RepositoryCleanlinessCapability,
    ) -> Result<WorktreeRecord> {
        cleanliness.require_clean_for_manager(self)?;
        let exclude_agent_id = Some(normalize_agent_id(&options.agent_id)?);
        let worktree_root = options.worktree_root.clone();
        let record = self.create_disabled_legacy(
            options,
            CreationCleanliness::Bound(cleanliness),
            WorktreeCreationPolicy::Standard,
        )?;
        cleanliness.require_clean_for_manager(self)?;
        if worktree_retention_is_configured(retention) {
            let max_total_bytes = retention
                .max_total_bytes
                .map(|max_total_bytes| -> Result<u64> {
                    let current = gc_worktree_size_estimate(&record.path)?;
                    Ok(max_total_bytes.saturating_sub(current.worktree_bytes))
                })
                .transpose()?;
            let retention = WorktreeRetentionPolicy {
                max_age: retention.max_age,
                max_count: retention
                    .max_count
                    .map(|max_count| max_count.saturating_sub(1)),
                max_total_bytes,
            };
            self.gc(WorktreeGcOptions {
                worktree_root,
                dry_run: false,
                remove_targets: true,
                targets_only: false,
                retention,
                allowed_untracked_paths: Vec::new(),
                exclude_agent_id,
                candidate_agent_ids: None,
                merged_into_reference: None,
                superseded_by_agent_id: BTreeMap::new(),
                machine_global_retention: None,
            })?;
            cleanliness.require_clean_for_manager(self)?;
        }
        Ok(record)
    }

    /// Creates a fresh arbitration worktree while structurally enforcing that
    /// its normalized identity is not either colliding source, it inherits no
    /// active durable path claim, and its default branch is newly created at
    /// the requested exact base OID.
    #[allow(dead_code)]
    pub(crate) fn create_neutral_with_repository_cleanliness(
        &self,
        options: NeutralWorktreeCreateOptions,
        cleanliness: &RepositoryCleanlinessCapability,
    ) -> Result<WorktreeRecord> {
        let validated = options.validate()?;
        cleanliness.require_clean_for_manager(self)?;
        let repo = self.open_repository()?;
        let claim_boundary = NeutralClaimBoundary::acquire(&repo, &validated.options.agent_id)?;
        let result = (|| -> Result<WorktreeRecord> {
            let record = self.create_disabled_legacy(
                validated.options,
                CreationCleanliness::Bound(cleanliness),
                WorktreeCreationPolicy::NeutralFresh {
                    exact_base_oid: validated.exact_base_oid,
                },
            )?;
            cleanliness.require_clean_for_manager(self)?;
            Ok(record)
        })();
        finish_with_neutral_claim_lock_verification(result, claim_boundary.verify())
    }

    /// Creates a managed child for an explicitly nonpublishable simulation.
    ///
    /// This reuses the internal durable worktree machinery without claiming a
    /// verified repository-cleanliness capability. Callers must bind it to a
    /// runtime that cannot launch an external process or publish acceptance.
    pub(crate) fn create_for_nonpublishable_simulation(
        &self,
        options: WorktreeCreateOptions,
    ) -> Result<WorktreeRecord> {
        self.create_disabled_legacy(
            options,
            CreationCleanliness::NonpublishableSimulation,
            WorktreeCreationPolicy::Standard,
        )
    }

    /// Unit-test-only capability seam for exercising the internal durable
    /// worktree machinery. This method is absent from production libraries
    /// and integration-test binaries.
    #[cfg(test)]
    pub(crate) fn create_for_test(&self, options: WorktreeCreateOptions) -> Result<WorktreeRecord> {
        self.create_for_test_with_retention(options, WorktreeRetentionPolicy::default())
    }

    #[cfg(test)]
    pub(crate) fn create_for_test_with_retention(
        &self,
        options: WorktreeCreateOptions,
        retention: WorktreeRetentionPolicy,
    ) -> Result<WorktreeRecord> {
        let exclude_agent_id = Some(normalize_agent_id(&options.agent_id)?);
        let worktree_root = options.worktree_root.clone();
        let record = self.create_disabled_legacy(
            options,
            CreationCleanliness::TestOnly,
            WorktreeCreationPolicy::Standard,
        )?;
        if worktree_retention_is_configured(retention) {
            let max_total_bytes = retention
                .max_total_bytes
                .map(|max_total_bytes| -> Result<u64> {
                    let current = gc_worktree_size_estimate(&record.path)?;
                    Ok(max_total_bytes.saturating_sub(current.worktree_bytes))
                })
                .transpose()?;
            let retention = WorktreeRetentionPolicy {
                max_age: retention.max_age,
                max_count: retention
                    .max_count
                    .map(|max_count| max_count.saturating_sub(1)),
                max_total_bytes,
            };
            self.gc(WorktreeGcOptions {
                worktree_root,
                dry_run: false,
                remove_targets: true,
                targets_only: false,
                retention,
                allowed_untracked_paths: Vec::new(),
                exclude_agent_id,
                candidate_agent_ids: None,
                merged_into_reference: None,
                superseded_by_agent_id: BTreeMap::new(),
                machine_global_retention: None,
            })?;
        }
        Ok(record)
    }

    #[cfg(test)]
    fn create_neutral_for_test(
        &self,
        options: NeutralWorktreeCreateOptions,
    ) -> Result<WorktreeRecord> {
        let validated = options.validate()?;
        let repo = self.open_repository()?;
        let claim_boundary = NeutralClaimBoundary::acquire(&repo, &validated.options.agent_id)?;
        let result = self.create_disabled_legacy(
            validated.options,
            CreationCleanliness::TestOnly,
            WorktreeCreationPolicy::NeutralFresh {
                exact_base_oid: validated.exact_base_oid,
            },
        );
        finish_with_neutral_claim_lock_verification(result, claim_boundary.verify())
    }

    #[allow(dead_code)]
    fn create_disabled_legacy(
        &self,
        options: WorktreeCreateOptions,
        cleanliness: CreationCleanliness<'_>,
        creation_policy: WorktreeCreationPolicy,
    ) -> Result<WorktreeRecord> {
        let repo = self.open_repository()?;
        let registry_store = ManagedWorktreeRegistryStore::open(&repo)?;
        cleanliness.require_clean_for_repository(&registry_store.repository)?;
        let registry_lock = registry_store.lock()?;
        let mut registry = registry_store.load(&registry_lock)?;
        let neutral_identity = match creation_policy {
            WorktreeCreationPolicy::Standard => None,
            WorktreeCreationPolicy::NeutralFresh { .. } => {
                if options.branch.is_some() {
                    bail!("neutral worktree creation does not accept a caller-supplied branch");
                }
                let name = normalize_agent_id(&options.agent_id)?;
                let branch_name = default_branch_name(&name);
                validate_branch_name(&branch_name)?;
                if registry.records.contains_key(&name) || registry.operations.contains_key(&name) {
                    bail!(
                        "neutral arbiter identity '{name}' already has managed worktree state; refusing reuse"
                    );
                }
                Some((name, branch_name))
            }
        };
        recover_pending_operations_with_creation_cleanliness(
            &repo,
            &registry_store,
            &registry_lock,
            &mut registry,
            cleanliness,
        )?;
        let (name, branch_name) = match neutral_identity {
            Some(identity) => identity,
            None => {
                let name = normalize_agent_id(&options.agent_id)?;
                let branch_name = options.branch.unwrap_or_else(|| default_branch_name(&name));
                validate_branch_name(&branch_name)?;
                (name, branch_name)
            }
        };
        if registry.records.contains_key(&name) {
            bail!("managed worktree '{name}' already has a registry binding");
        }
        if registry.records.len() >= MAX_MANAGED_RECORDS {
            bail!("managed worktree registry has no remaining record capacity");
        }
        if registry.operations.len() >= MAX_MANAGED_OPERATIONS {
            bail!("managed worktree registry has no remaining operation capacity");
        }
        let commit = resolve_base_commit(&repo, options.base.as_deref())?;
        if let Some(exact_base_oid) = creation_policy.exact_base_oid() {
            if commit.id() != exact_base_oid {
                bail!(
                    "neutral worktree base did not resolve to the requested exact commit {exact_base_oid}"
                );
            }
            if local_branch_oid(&repo, &branch_name)?.is_some() {
                bail!(
                    "neutral worktree requires a fresh MACO-owned default branch; '{branch_name}' already exists"
                );
            }
        }
        let requested_root = options
            .worktree_root
            .unwrap_or_else(|| default_worktree_root(&repo));
        let requested_root = if requested_root.is_absolute() {
            requested_root
        } else {
            repo.workdir()
                .context("worktree creation requires a non-bare repository")?
                .join(requested_root)
        };
        let root = SafeRoot::open_or_create_managed(&requested_root)?;
        crate::lane_build::ensure_lane_build_configuration(root.path())?;
        let worktree_path = root.direct_child(&name)?;

        if find_worktree(&repo, &name)?.is_some() {
            bail!("worktree '{name}' is already registered");
        }
        root.ensure_direct_child_absent(&name)?;

        let branch_preexisting_oid =
            local_branch_oid(&repo, &branch_name)?.map(|oid| oid.to_string());
        if creation_policy.is_neutral_fresh() && branch_preexisting_oid.is_some() {
            bail!(
                "neutral worktree requires a fresh MACO-owned default branch; '{branch_name}' appeared before creation"
            );
        }
        let branch_ownership = if branch_preexisting_oid.is_some() {
            ManagedBranchOwnership::Preexisting
        } else {
            ManagedBranchOwnership::Unknown
        };
        let staging_name = root.random_direct_child_name("maco-stage")?;
        let staging_root_path = root.direct_child(&staging_name)?;
        let staging_path = staging_root_path.join(&name);
        registry.operations.insert(
            name.clone(),
            ManagedWorktreeOperation {
                kind: ManagedWorktreeOperationKind::Create,
                phase: ManagedWorktreeOperationPhase::CreateIntent,
                name: name.clone(),
                root: root.path().to_path_buf(),
                root_identity: root.identity().clone(),
                path: worktree_path.clone(),
                prepared_path_identity: None,
                staging_root: Some(staging_root_path.clone()),
                staging_root_identity: None,
                staging_path: Some(staging_path.clone()),
                staged_path_identity: None,
                staged_metadata: None,
                branch: branch_name.clone(),
                base_oid: commit.id().to_string(),
                branch_preexisting_oid,
                branch_ownership,
                owned_branch_oid: None,
                binding: None,
                delete_branch: false,
                force: cfg!(test),
                expected_branch_oid: None,
                gc_dirtiness_checksum: None,
                removal_safety: None,
                worktree_quarantine_path: None,
                worktree_quarantine_identity: None,
                metadata_quarantine_path: None,
                metadata_quarantine_identity: None,
            },
        );
        registry_store.save(&registry_lock, &mut registry)?;

        let reserved = match root.reserve_direct_child_directory(&name) {
            Ok(reserved) => reserved,
            Err(error) => {
                recover_pending_operations_with_creation_cleanliness(
                    &repo,
                    &registry_store,
                    &registry_lock,
                    &mut registry,
                    cleanliness,
                )?;
                return Err(error);
            }
        };
        let staging_reserved = match root.reserve_direct_child_directory(&staging_name) {
            Ok(reserved) => reserved,
            Err(error) => {
                record_pre_worktree_bypass(
                    &name,
                    "delete_empty_pre_worktree_reservation_setup_rollback",
                    reserved.path(),
                );
                remove_direct_child_tree(
                    &root,
                    &name,
                    Some(reserved.identity()),
                    TreeLinkPolicy::UnlinkLinks,
                )?;
                recover_pending_operations_with_creation_cleanliness(
                    &repo,
                    &registry_store,
                    &registry_lock,
                    &mut registry,
                    cleanliness,
                )?;
                return Err(error);
            }
        };
        let staging_root = SafeRoot::open_existing(staging_reserved.path())?;
        if staging_root.path() != staging_root_path {
            bail!("reserved staging root path changed before create preparation");
        }
        staging_root.ensure_direct_child_absent(&name)?;
        let prepared_save = (|| -> Result<()> {
            let operation = registry
                .operations
                .get_mut(&name)
                .context("create intent disappeared before reservation was persisted")?;
            operation.phase = ManagedWorktreeOperationPhase::CreatePrepared;
            operation.prepared_path_identity = Some(reserved.identity().clone());
            operation.staging_root = Some(staging_root.path().to_path_buf());
            operation.staging_root_identity = Some(staging_root.identity().clone());
            operation.staging_path = Some(staging_path.clone());
            registry_store.save(&registry_lock, &mut registry)
        })();
        if let Err(error) = prepared_save {
            record_pre_worktree_bypass(
                &name,
                "delete_empty_pre_worktree_staging_setup_rollback",
                staging_reserved.path(),
            );
            remove_direct_child_tree(
                &root,
                staging_reserved
                    .path()
                    .file_name()
                    .context("staging reservation has no final name")?,
                Some(staging_reserved.identity()),
                TreeLinkPolicy::UnlinkLinks,
            )?;
            record_pre_worktree_bypass(
                &name,
                "delete_empty_pre_worktree_reservation_setup_rollback",
                reserved.path(),
            );
            let cleanup = remove_direct_child_tree(
                &root,
                &name,
                Some(reserved.identity()),
                TreeLinkPolicy::UnlinkLinks,
            );
            cleanup.context("failed to clean reserved directory after registry save failure")?;
            return Err(error);
        }

        let create_result =
            (|| -> Result<()> {
                reserved.verify(&root)?;
                let (branch, created_by_maco) =
                    ensure_branch_for_creation(&repo, &branch_name, &commit, creation_policy)?;
                let branch_oid = branch.get().target().with_context(|| {
                    format!("local branch '{branch_name}' has no direct target")
                })?;
                let preexisting_oid = registry
                    .operations
                    .get(&name)
                    .and_then(|operation| operation.branch_preexisting_oid.as_deref())
                    .map(Oid::from_str)
                    .transpose()
                    .context("create operation has malformed pre-existing branch OID")?;
                match (created_by_maco, preexisting_oid) {
                    (true, None) if branch_oid == commit.id() => {}
                    (true, None) => {
                        bail!("newly created branch changed before ownership was persisted")
                    }
                    (true, Some(_)) => {
                        bail!("a pre-existing branch disappeared during worktree creation")
                    }
                    (false, Some(expected)) if branch_oid == expected => {}
                    (false, Some(_)) => {
                        bail!("pre-existing branch changed before worktree creation")
                    }
                    (false, None) => {
                        bail!("branch appeared concurrently before worktree creation")
                    }
                }
                let operation = registry.operations.get_mut(&name).context(
                    "create operation disappeared before branch ownership was persisted",
                )?;
                operation.branch_ownership = if created_by_maco {
                    ManagedBranchOwnership::CreatedByMaco
                } else {
                    ManagedBranchOwnership::Preexisting
                };
                operation.owned_branch_oid = created_by_maco.then(|| branch_oid.to_string());
                registry_store.save(&registry_lock, &mut registry)?;
                let _branch_guard = lock_branch_reference(&repo, &branch_name)?;
                verify_local_branch_oid(&repo, &branch_name, branch_oid)?;
                let reference = branch.into_reference();
                let mut add_options = WorktreeAddOptions::new();
                add_options.reference(Some(&reference)).lock(true);
                repo.worktree(&name, &staging_path, Some(&add_options))
                    .with_context(|| {
                        format!(
                            "failed to create worktree '{name}' at {}",
                            staging_path.display()
                        )
                    })?;
                ensure_creation_worktree_locked(&repo, &name)?;
                reserved.verify(&root)?;
                staging_reserved.verify(&root)?;
                let staged = staging_root.bind_existing_managed_direct_child_directory(&name)?;
                verify_worktree_clean_at(&staging_path, &branch_name, branch_oid, cleanliness)?;
                let staged_metadata = capture_staged_worktree_metadata(
                    &registry_store.repository,
                    &name,
                    &branch_name,
                    &staging_path,
                )?;
                let operation = registry
                    .operations
                    .get_mut(&name)
                    .context("create operation disappeared before staged identity was persisted")?;
                operation.phase = ManagedWorktreeOperationPhase::CreateStaged;
                operation.staged_path_identity = Some(staged.identity().clone());
                operation.staged_metadata = Some(staged_metadata);
                registry_store.save(&registry_lock, &mut registry)?;
                Ok(())
            })();
        let recovery_result = recover_pending_operations_with_creation_cleanliness(
            &repo,
            &registry_store,
            &registry_lock,
            &mut registry,
            cleanliness,
        );
        if let Err(create_error) = create_result {
            recovery_result.with_context(|| {
                format!(
                    "worktree creation failed and its durable create operation could not be recovered: {create_error:#}"
                )
            })?;
            return Err(create_error);
        }
        recovery_result?;
        let binding = registry.records.get(&name).with_context(|| {
            format!("managed worktree '{name}' was not finalized after create recovery")
        })?;

        let record = WorktreeRecord {
            name,
            path: binding.path.clone(),
            branch: branch_name,
        };
        cleanliness.require_clean_for_repository(&registry_store.repository)?;
        Ok(record)
    }

    /// Removes a managed worktree after taking its cooperative exclusive
    /// execution lease. Active MACO child lifecycles holding a shared lease are
    /// refused before the remove intent is persisted. The lease cannot stop an
    /// unrelated, uncooperative same-user process; callers retain that OS trust
    /// boundary.
    pub fn remove(
        &self,
        agent_id: &str,
        force: bool,
        delete_branch: bool,
    ) -> Result<WorktreeRecord> {
        if !force {
            bail!(
                "non-force managed worktree removal is unsupported without a capability-bound repository cleanliness input"
            );
        }
        let repo = self.open_repository()?;
        let name = normalize_agent_id(agent_id)?;
        let registry_store = ManagedWorktreeRegistryStore::open(&repo)?;
        let registry_lock = registry_store.lock()?;
        let mut registry = registry_store.load(&registry_lock)?;
        if let Some(operation) = registry.operations.get_mut(&name) {
            operation.force = true;
            if operation.kind == ManagedWorktreeOperationKind::Remove {
                operation.delete_branch = delete_branch;
                operation.gc_dirtiness_checksum = None;
                operation.removal_safety = Some(ManagedRemovalSafety::Explicit);
            }
            registry_store.save(&registry_lock, &mut registry)?;
        }
        let pending_remove_binding = registry.operations.get(&name).and_then(|operation| {
            (operation.kind == ManagedWorktreeOperationKind::Remove)
                .then(|| operation.binding.clone())
                .flatten()
        });
        recover_pending_operations(&repo, &registry_store, &registry_lock, &mut registry)?;
        if let Some(binding) = pending_remove_binding {
            if !registry.records.contains_key(&name) && !registry.operations.contains_key(&name) {
                return Ok(WorktreeRecord {
                    name,
                    path: binding.path,
                    branch: binding.branch,
                });
            }
        }
        let binding = registry.records.get(&name).cloned().with_context(|| {
            format!(
                "worktree '{name}' has no create-time managed binding; refusing filesystem or branch deletion even with --force"
            )
        })?;
        let verified = verify_managed_worktree_binding(
            &repo,
            &registry_store.repository,
            &binding,
            delete_branch,
        )?;
        let _removal_lease = registry_store
            .try_acquire_worktree_removal_lease(&registry_lock, &name)
            .with_context(|| {
                format!(
                    "managed worktree '{name}' has an active cooperative execution lease; stop its MACO child before removal"
                )
            })?;

        if registry.operations.len() >= MAX_MANAGED_OPERATIONS {
            bail!("managed worktree registry has no remaining operation capacity");
        }
        let worktree_quarantine_path = deterministic_remove_quarantine_path(
            &binding.root,
            "worktree",
            &binding.name,
            &binding.path_identity,
        );
        let metadata_root = registry_store.repository.common_dir.join("worktrees");
        let metadata_quarantine_path = deterministic_remove_quarantine_path(
            &metadata_root,
            "metadata",
            &binding.name,
            &binding.metadata_dir_identity,
        );
        registry.operations.insert(
            name.clone(),
            ManagedWorktreeOperation {
                kind: ManagedWorktreeOperationKind::Remove,
                phase: ManagedWorktreeOperationPhase::RemovePrepared,
                name: name.clone(),
                root: binding.root.clone(),
                root_identity: binding.root_identity.clone(),
                path: binding.path.clone(),
                prepared_path_identity: Some(binding.path_identity.clone()),
                staging_root: None,
                staging_root_identity: None,
                staging_path: None,
                staged_path_identity: None,
                staged_metadata: None,
                branch: binding.branch.clone(),
                base_oid: binding.base_oid.clone(),
                branch_preexisting_oid: None,
                branch_ownership: if binding.branch_created_by_maco {
                    ManagedBranchOwnership::CreatedByMaco
                } else {
                    ManagedBranchOwnership::Preexisting
                },
                owned_branch_oid: binding
                    .branch_created_by_maco
                    .then(|| binding.created_branch_oid.clone()),
                binding: Some(binding.clone()),
                delete_branch,
                force,
                expected_branch_oid: Some(verified.branch_oid.to_string()),
                gc_dirtiness_checksum: None,
                removal_safety: Some(ManagedRemovalSafety::Explicit),
                worktree_quarantine_path: Some(worktree_quarantine_path),
                worktree_quarantine_identity: None,
                metadata_quarantine_path: Some(metadata_quarantine_path),
                metadata_quarantine_identity: None,
            },
        );
        registry_store.save(&registry_lock, &mut registry)?;
        recover_pending_operations_with_held_removal_lease(
            &repo,
            &registry_store,
            &registry_lock,
            &mut registry,
            Some(&_removal_lease),
        )?;

        Ok(WorktreeRecord {
            name,
            path: binding.path,
            branch: binding.branch,
        })
    }

    pub fn list(&self) -> Result<Vec<WorktreeRecord>> {
        self.list_managed_verified()
    }

    /// Returns only worktrees with a durable MACO binding that still matches
    /// their repository, filesystem identities, Git metadata, and backlinks.
    /// Git-registered legacy worktrees are intentionally not adopted here.
    pub fn list_managed_verified(&self) -> Result<Vec<WorktreeRecord>> {
        let repo = self.open_repository()?;
        let registry_store = ManagedWorktreeRegistryStore::open(&repo)?;
        let registry_lock = registry_store.lock()?;
        let registry = registry_store.load(&registry_lock)?;
        let mut records = Vec::with_capacity(registry.records.len());
        for binding in registry.records.values() {
            if registry.operations.contains_key(&binding.name) {
                continue;
            }
            records.push(verified_worktree_record(
                &repo,
                &registry_store.repository,
                binding,
            )?);
        }
        records.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(records)
    }

    /// Lists authenticated durable operations without attempting recovery or
    /// making a pathname-based cleanliness decision.
    pub fn pending_operations(&self) -> Result<Vec<PendingWorktreeOperation>> {
        let repo = self.open_repository()?;
        let Some(registry_store) = ManagedWorktreeRegistryStore::open_existing(&repo)? else {
            return Ok(Vec::new());
        };
        let Some(registry) = registry_store.load_existing_read_only()? else {
            return Ok(Vec::new());
        };
        let mut operations = registry
            .operations
            .values()
            .map(|operation| PendingWorktreeOperation {
                name: operation.name.clone(),
                kind: managed_operation_kind_label(operation.kind).to_string(),
                phase: managed_operation_phase_label(operation.phase).to_string(),
                path: operation.path.clone(),
                force: operation.force,
            })
            .collect::<Vec<_>>();
        operations.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(operations)
    }

    pub fn gc(&self, options: WorktreeGcOptions) -> Result<WorktreeGcReport> {
        self.gc_with_target_liveness(options, worktree_target_liveness)
    }

    /// Runs explicitly enabled lifecycle automation. The default options are
    /// read/write inert: no registry, worktree, Git metadata, or artifact
    /// store is opened until at least one lifecycle feature is enabled.
    pub fn lifecycle(&self, options: WorktreeLifecycleOptions) -> Result<WorktreeLifecycleReport> {
        let enabled = options.auto_reap_merged
            || options.retry_successor_agent_id.is_some()
            || options.startup_reconcile
            || options.artifact_retention.is_some();
        let mut report = WorktreeLifecycleReport {
            enabled,
            apply: options.apply,
            dry_run: !options.apply,
            auto_reap_merged: options.auto_reap_merged,
            retry: RetrySupersessionReport {
                successor_agent_id: options.retry_successor_agent_id.clone(),
                predecessor_agent_id: None,
                status: RetrySupersessionStatus::Disabled,
                authenticated_matches: Vec::new(),
                detail: None,
            },
            reconciliation: WorktreeReconciliationReport {
                enabled: options.startup_reconcile,
                apply: options.apply,
                destructive_reconciliation: options.destructive_reconciliation,
                forgotten_record_count: 0,
                pruned_registration_count: 0,
                quarantined_directory_count: 0,
                entries: Vec::new(),
            },
            worktree_gc: None,
            artifact_prune: None,
            artifact_reclaim_unverifiable: options
                .artifact_retention
                .as_ref()
                .map(|policy| policy.reclaim_unverifiable),
            artifact_external_writers_stopped: options
                .artifact_retention
                .as_ref()
                .map(|policy| policy.external_writers_stopped),
            apparent_checked_bytes: 0,
            projected_reclaimable_bytes: 0,
            actual_reclaimed_bytes: 0,
            repository_prune: WorktreeRepositoryPruneReport {
                status: WorktreeRepositoryPruneStatus::Disabled,
                stale_registration_count: 0,
                pruned_registration_count: 0,
                protected_registration_count: 0,
            },
        };
        if !enabled {
            return Ok(report);
        }
        if options.auto_reap_merged && options.merged_into_reference.is_none() {
            bail!("merged-lane lifecycle automation requires an explicit local trunk reference");
        }

        let repo = self.open_repository()?;
        if options.startup_reconcile {
            report.reconciliation = reconcile_managed_worktree_lifecycle(
                &repo,
                options.worktree_root.clone(),
                options.apply,
                options.destructive_reconciliation,
                options.machine_global_retention.as_ref(),
            )?;
        }

        let mut superseded_by_agent_id = BTreeMap::new();
        if let Some(successor) = options.retry_successor_agent_id.as_deref() {
            report.retry = resolve_retry_supersession(&repo, successor)?;
            if report.retry.status == RetrySupersessionStatus::Selected {
                let predecessor = report
                    .retry
                    .predecessor_agent_id
                    .clone()
                    .context("selected retry predecessor is missing from its report")?;
                superseded_by_agent_id.insert(predecessor, successor.to_string());
            }
        }

        let gc_enabled = options.auto_reap_merged || !superseded_by_agent_id.is_empty();
        if gc_enabled {
            let candidate_agent_ids = if options.auto_reap_merged {
                let mut selectors = options.candidate_agent_ids.clone();
                if !superseded_by_agent_id.is_empty() {
                    selectors
                        .get_or_insert_with(BTreeSet::new)
                        .extend(superseded_by_agent_id.keys().cloned());
                }
                selectors
            } else {
                Some(superseded_by_agent_id.keys().cloned().collect())
            };
            let gc = self.gc(WorktreeGcOptions {
                worktree_root: options.worktree_root,
                dry_run: !options.apply,
                remove_targets: options.remove_targets,
                targets_only: false,
                retention: options.worktree_retention,
                allowed_untracked_paths: options.allowed_untracked_paths,
                exclude_agent_id: None,
                candidate_agent_ids,
                merged_into_reference: options.merged_into_reference,
                superseded_by_agent_id,
                machine_global_retention: options.machine_global_retention,
            })?;
            report.apparent_checked_bytes = report
                .apparent_checked_bytes
                .checked_add(gc.apparent_considered_bytes)
                .context("lifecycle apparent checked bytes overflowed")?;
            report.projected_reclaimable_bytes = report
                .projected_reclaimable_bytes
                .checked_add(gc.estimated_reclaimable_bytes)
                .context("lifecycle projected reclaimable bytes overflowed")?;
            report.actual_reclaimed_bytes = report
                .actual_reclaimed_bytes
                .checked_add(gc.estimated_reclaimed_bytes)
                .context("lifecycle actual reclaimed bytes overflowed")?;
            if gc.removed_count > 0 {
                let selected_names = gc
                    .entries
                    .iter()
                    .filter(|entry| {
                        matches!(
                            entry.status,
                            WorktreeGcStatus::WouldRemove | WorktreeGcStatus::Removed
                        )
                    })
                    .map(|entry| entry.name.clone())
                    .collect::<BTreeSet<_>>();
                report.repository_prune = prune_stale_worktree_registrations(
                    &repo,
                    &selected_names,
                    options.apply,
                )
                .with_context(
                    || {
                        format!(
                            "{} managed worktree removal(s) completed, but post-removal Git worktree prune failed; effects occurred and the lifecycle pass must not be blindly retried",
                            gc.removed_count
                        )
                    },
                )?;
            } else {
                report.repository_prune.status = if options.apply {
                    WorktreeRepositoryPruneStatus::NotNeeded
                } else {
                    WorktreeRepositoryPruneStatus::DryRun
                };
            }
            report.worktree_gc = Some(gc);
        }

        if let Some(policy) = options.artifact_retention {
            let artifacts = prune_artifacts_with_policy(
                &self.repo_path,
                ArtifactRetentionFamily::O2Autopilot,
                &policy,
                !options.apply,
            )
            .with_context(|| {
                if report
                    .worktree_gc
                    .as_ref()
                    .is_some_and(|gc| gc.estimated_reclaimed_bytes > 0)
                {
                    "worktree reclamation completed before artifact pruning failed; effects occurred and the lifecycle pass must not be blindly retried"
                } else {
                    "lifecycle artifact pruning failed before any reported worktree reclamation"
                }
            })?;
            report.apparent_checked_bytes = report
                .apparent_checked_bytes
                .checked_add(artifacts.scanned_bytes)
                .context("lifecycle apparent checked bytes overflowed")?;
            report.projected_reclaimable_bytes = report
                .projected_reclaimable_bytes
                .checked_add(artifacts.would_reclaim_bytes)
                .context("lifecycle projected reclaimable bytes overflowed")?;
            report.actual_reclaimed_bytes = report
                .actual_reclaimed_bytes
                .checked_add(artifacts.reclaimed_bytes)
                .context("lifecycle actual reclaimed bytes overflowed")?;
            report.artifact_prune = Some(artifacts);
        }
        Ok(report)
    }

    fn gc_with_target_liveness<F>(
        &self,
        options: WorktreeGcOptions,
        target_liveness: F,
    ) -> Result<WorktreeGcReport>
    where
        F: Fn(&WorktreeGcTarget) -> WorktreeTargetLiveness,
    {
        validate_worktree_gc_mode(
            options.targets_only,
            options.remove_targets,
            options.retention,
            &options.allowed_untracked_paths,
            options.machine_global_retention.is_some(),
        )?;
        let repo = self.open_repository()?;
        let merge_target = options
            .merged_into_reference
            .as_deref()
            .map(|reference| resolve_lifecycle_trunk_tip(&repo, reference))
            .transpose()?;
        let restrict_to_requested_root = options.worktree_root.is_some();
        let worktree_root = resolve_worktree_root(&repo, options.worktree_root.clone())?;
        if !options.dry_run {
            crate::lane_build::ensure_lane_build_configuration(&worktree_root)?;
        }
        let allowed_untracked_paths =
            normalize_gc_allowed_untracked_paths(&options.allowed_untracked_paths)?;
        let active_claims = active_claim_agent_ids(&repo)?;
        let exclude_agent_id = options
            .exclude_agent_id
            .as_deref()
            .map(normalize_agent_id)
            .transpose()?;
        let candidate_agent_ids = options
            .candidate_agent_ids
            .as_ref()
            .map(|ids| normalize_gc_agent_id_set(ids, "candidate"))
            .transpose()?;
        let superseded_by_agent_id =
            normalize_gc_supersession_map(&options.superseded_by_agent_id)?;
        if let Some(candidate_agent_ids) = &candidate_agent_ids {
            if !superseded_by_agent_id
                .keys()
                .all(|predecessor| candidate_agent_ids.contains(predecessor))
            {
                bail!("superseded worktree selectors must be included in candidate selectors");
            }
        }
        let mut report = WorktreeGcReport {
            dry_run: options.dry_run,
            remove_targets: options.remove_targets,
            targets_only: options.targets_only,
            max_age_seconds: options.retention.max_age.map(|age| age.as_secs()),
            max_count: options.retention.max_count,
            max_total_bytes: options.retention.max_total_bytes,
            allowed_untracked_paths: allowed_untracked_paths.iter().cloned().collect(),
            considered_count: 0,
            removed_count: 0,
            protected_count: 0,
            retained_count: 0,
            target_removed_count: 0,
            orphan_removed_count: 0,
            apparent_considered_bytes: 0,
            estimated_reclaimable_bytes: 0,
            estimated_reclaimed_bytes: 0,
            entries: Vec::new(),
        };

        let mut registered_names = BTreeSet::new();
        let registry_store = ManagedWorktreeRegistryStore::open(&repo)?;
        let registry_lock = registry_store.lock()?;
        let mut registry = registry_store.load(&registry_lock)?;
        recover_pending_operations(&repo, &registry_store, &registry_lock, &mut registry)?;
        validate_retry_supersession_authorities(
            &repo,
            &registry_store.repository,
            &registry,
            &superseded_by_agent_id,
        )?;
        for name in registry.records.keys() {
            registered_names.insert(name.clone());
        }

        let mut candidates = Vec::new();
        let bindings = registry.records.values().cloned().collect::<Vec<_>>();
        for binding in bindings {
            if registry.operations.contains_key(&binding.name) {
                continue;
            }
            if candidate_agent_ids
                .as_ref()
                .is_some_and(|ids| !ids.contains(&binding.name))
            {
                continue;
            }
            if restrict_to_requested_root && binding.root != worktree_root {
                continue;
            }
            report.considered_count = report
                .considered_count
                .checked_add(1)
                .context("worktree GC considered count overflowed")?;
            if exclude_agent_id.as_deref() == Some(binding.name.as_str()) {
                report.retained_count = report
                    .retained_count
                    .checked_add(1)
                    .context("worktree GC retained count overflowed")?;
                report.entries.push(WorktreeGcEntry {
                    name: binding.name,
                    branch: Some(binding.branch),
                    path: binding.path,
                    status: WorktreeGcStatus::Retained,
                    reason: WorktreeGcReason::ExcludedCurrentWorktree,
                    target_path: None,
                    target_liveness: None,
                    apparent_worktree_bytes: None,
                    apparent_target_bytes: None,
                    untracked_paths: Vec::new(),
                    gate_denial: None,
                    retention_operation_id: None,
                });
                continue;
            }
            if active_claims.contains(&binding.name) {
                report.protected_count = report
                    .protected_count
                    .checked_add(1)
                    .context("worktree GC protected count overflowed")?;
                report.entries.push(WorktreeGcEntry {
                    name: binding.name,
                    branch: Some(binding.branch),
                    path: binding.path,
                    status: WorktreeGcStatus::Protected,
                    reason: WorktreeGcReason::ActiveClaim,
                    target_path: None,
                    target_liveness: None,
                    apparent_worktree_bytes: None,
                    apparent_target_bytes: None,
                    untracked_paths: Vec::new(),
                    gate_denial: None,
                    retention_operation_id: None,
                });
                continue;
            }
            let verified = verify_managed_worktree_binding(
                &repo,
                &registry_store.repository,
                &binding,
                false,
            )?;
            let branch_merged = match merge_target.as_ref() {
                Some((_, trunk_oid)) => {
                    verified.branch_oid == *trunk_oid
                        || repo
                            .graph_descendant_of(*trunk_oid, verified.branch_oid)
                            .context("failed to inspect managed branch ancestry from trunk")?
                }
                None => true,
            };
            let removal_lease = if options.dry_run {
                if registry_store
                    .worktree_has_active_execution_lease(&registry_lock, &binding.name)?
                {
                    report.protected_count = report
                        .protected_count
                        .checked_add(1)
                        .context("worktree GC protected count overflowed")?;
                    report.entries.push(WorktreeGcEntry {
                        name: binding.name,
                        branch: Some(binding.branch),
                        path: verified.path,
                        status: WorktreeGcStatus::Protected,
                        reason: WorktreeGcReason::ActiveLease,
                        target_path: None,
                        target_liveness: None,
                        apparent_worktree_bytes: None,
                        apparent_target_bytes: None,
                        untracked_paths: Vec::new(),
                        gate_denial: None,
                        retention_operation_id: None,
                    });
                    continue;
                }
                None
            } else {
                match registry_store
                    .try_acquire_worktree_removal_lease(&registry_lock, &binding.name)
                {
                    Ok(lease) => Some(lease),
                    Err(error) if is_active_lease_error(&error) => {
                        report.protected_count = report
                            .protected_count
                            .checked_add(1)
                            .context("worktree GC protected count overflowed")?;
                        report.entries.push(WorktreeGcEntry {
                            name: binding.name,
                            branch: Some(binding.branch),
                            path: verified.path,
                            status: WorktreeGcStatus::Protected,
                            reason: WorktreeGcReason::ActiveLease,
                            target_path: None,
                            target_liveness: None,
                            apparent_worktree_bytes: None,
                            apparent_target_bytes: None,
                            untracked_paths: Vec::new(),
                            gate_denial: None,
                            retention_operation_id: None,
                        });
                        continue;
                    }
                    Err(error) => {
                        return Err(error).context("failed to inspect managed worktree lease")
                    }
                }
            };
            let size = match gc_worktree_size_estimate(&verified.path) {
                Ok(size) => size,
                Err(_) => {
                    report.protected_count = report
                        .protected_count
                        .checked_add(1)
                        .context("worktree GC protected count overflowed")?;
                    report.entries.push(WorktreeGcEntry {
                        name: binding.name,
                        branch: Some(binding.branch),
                        path: verified.path,
                        status: WorktreeGcStatus::Protected,
                        reason: WorktreeGcReason::SizeMeasurementFailed,
                        target_path: None,
                        target_liveness: None,
                        apparent_worktree_bytes: None,
                        apparent_target_bytes: None,
                        untracked_paths: Vec::new(),
                        gate_denial: None,
                        retention_operation_id: None,
                    });
                    continue;
                }
            };
            report.apparent_considered_bytes = report
                .apparent_considered_bytes
                .checked_add(size.worktree_bytes)
                .context("worktree GC apparent considered bytes overflowed")?;
            let untracked_paths = match gc_worktree_dirtiness(&verified.path)? {
                WorktreeGcDirtiness::Clean => Vec::new(),
                WorktreeGcDirtiness::TrackedDirty => {
                    report.protected_count = report
                        .protected_count
                        .checked_add(1)
                        .context("worktree GC protected count overflowed")?;
                    report.entries.push(WorktreeGcEntry {
                        name: binding.name,
                        branch: Some(binding.branch),
                        path: verified.path,
                        status: WorktreeGcStatus::Protected,
                        reason: WorktreeGcReason::Dirty,
                        target_path: None,
                        target_liveness: None,
                        apparent_worktree_bytes: Some(size.worktree_bytes),
                        apparent_target_bytes: size.target_bytes,
                        untracked_paths: Vec::new(),
                        gate_denial: None,
                        retention_operation_id: None,
                    });
                    continue;
                }
                WorktreeGcDirtiness::UntrackedOnly(paths) => {
                    if !options.targets_only
                        && !paths
                            .iter()
                            .all(|path| allowed_untracked_paths.contains(path))
                    {
                        report.protected_count = report
                            .protected_count
                            .checked_add(1)
                            .context("worktree GC protected count overflowed")?;
                        report.entries.push(WorktreeGcEntry {
                            name: binding.name,
                            branch: Some(binding.branch),
                            path: verified.path,
                            status: WorktreeGcStatus::Protected,
                            reason: WorktreeGcReason::UntrackedOnly,
                            target_path: None,
                            target_liveness: None,
                            apparent_worktree_bytes: Some(size.worktree_bytes),
                            apparent_target_bytes: size.target_bytes,
                            untracked_paths: paths,
                            gate_denial: None,
                            retention_operation_id: None,
                        });
                        continue;
                    }
                    paths
                }
            };
            let superseded = superseded_by_agent_id.contains_key(&binding.name);
            candidates.push(WorktreeGcCandidate {
                binding,
                branch_oid: verified.branch_oid,
                branch_merged,
                superseded,
                merged_into_reference: merge_target
                    .as_ref()
                    .map(|(reference, _)| reference.clone()),
                removal_lease,
                untracked_paths,
                apparent_worktree_bytes: size.worktree_bytes,
                apparent_target_bytes: size.target_bytes,
                rebuild_cost_ms: load_lane_rebuild_cost(&verified.path),
            });
        }

        let now = unix_now_nanos()?;
        candidates.sort_by(|left, right| {
            cmp_retention_keep_order(
                &RetentionKeepKey {
                    rebuild_cost_ms: left.rebuild_cost_ms,
                    apparent_bytes: left.apparent_worktree_bytes,
                    created_at_unix_nanos: gc_created_at(&left.binding),
                    name: &left.binding.name,
                },
                &RetentionKeepKey {
                    rebuild_cost_ms: right.rebuild_cost_ms,
                    apparent_bytes: right.apparent_worktree_bytes,
                    created_at_unix_nanos: gc_created_at(&right.binding),
                    name: &right.binding.name,
                },
            )
        });
        // Retention is committed only on remove / retain / dry-run exits.
        // Protection continues deliberately drop `decision.committed_state` so
        // a live, dirty, or identity-changed lane cannot evict an older
        // finished candidate. `max_count` / `max_total_bytes` therefore
        // under-count on-disk usage (conservative: never unsafe removal).
        let mut retention_state = WorktreeGcRetentionState::default();
        for mut candidate in candidates {
            let decision = worktree_gc_retention_decision(
                &candidate,
                now,
                options.targets_only,
                options.retention,
                retention_state,
            )?;
            let preflight_target = gc_target_if_present(&candidate.binding.path)?;
            let target_cleanup = options.remove_targets && preflight_target.is_some();
            if decision.should_remove || target_cleanup {
                if let Some((reason, evidence)) = preflight_target
                    .as_ref()
                    .and_then(|target| gc_target_liveness_protection(target, &target_liveness))
                {
                    add_gc_candidate_protection(
                        &mut report,
                        &candidate,
                        reason,
                        preflight_target.as_ref().map(|target| target.path.clone()),
                        Some(evidence),
                        candidate.untracked_paths.clone(),
                    )?;
                    continue;
                }
                match worktree_gc_dirtiness_disposition(
                    gc_worktree_dirtiness(&candidate.binding.path)?,
                    options.targets_only,
                    &allowed_untracked_paths,
                ) {
                    WorktreeGcDirtinessDisposition::Eligible(paths) => {
                        candidate.untracked_paths = paths;
                    }
                    WorktreeGcDirtinessDisposition::Protected {
                        reason,
                        untracked_paths,
                    } => {
                        add_gc_candidate_protection(
                            &mut report,
                            &candidate,
                            reason,
                            preflight_target.as_ref().map(|target| target.path.clone()),
                            None,
                            untracked_paths,
                        )?;
                        continue;
                    }
                }
                if preflight_target
                    .as_ref()
                    .is_some_and(|target| !worktree_gc_target_identity_is_current(target))
                {
                    add_gc_candidate_protection(
                        &mut report,
                        &candidate,
                        WorktreeGcReason::TargetIdentityChanged,
                        preflight_target.as_ref().map(|target| target.path.clone()),
                        Some(target_identity_changed_evidence()),
                        candidate.untracked_paths.clone(),
                    )?;
                    continue;
                }
            }

            if decision.should_remove {
                let completion_reason = worktree_gc_completion_reason(&candidate);
                if options.dry_run {
                    report.estimated_reclaimable_bytes = report
                        .estimated_reclaimable_bytes
                        .checked_add(candidate.apparent_worktree_bytes)
                        .context("worktree GC estimated reclaimable bytes overflowed")?;
                    report.removed_count = report
                        .removed_count
                        .checked_add(1)
                        .context("worktree GC removed count overflowed")?;
                    report.entries.push(WorktreeGcEntry {
                        name: candidate.binding.name,
                        branch: Some(candidate.binding.branch),
                        path: candidate.binding.path,
                        status: WorktreeGcStatus::WouldRemove,
                        reason: completion_reason,
                        target_path: preflight_target.as_ref().map(|target| target.path.clone()),
                        target_liveness: None,
                        apparent_worktree_bytes: Some(candidate.apparent_worktree_bytes),
                        apparent_target_bytes: candidate.apparent_target_bytes,
                        untracked_paths: candidate.untracked_paths,
                        gate_denial: None,
                        retention_operation_id: None,
                    });
                    retention_state = decision.committed_state;
                    continue;
                }

                let boundary_target = gc_target_at_apply_boundary(
                    &candidate.binding.path,
                    preflight_target.as_ref(),
                )?;
                if !worktree_gc_target_bindings_match(
                    preflight_target.as_ref(),
                    boundary_target.as_ref(),
                ) {
                    add_gc_candidate_protection(
                        &mut report,
                        &candidate,
                        WorktreeGcReason::TargetIdentityChanged,
                        boundary_target
                            .as_ref()
                            .or(preflight_target.as_ref())
                            .map(|target| target.path.clone()),
                        Some(target_identity_changed_evidence()),
                        candidate.untracked_paths.clone(),
                    )?;
                    continue;
                }
                if let Some((reason, evidence)) = boundary_target
                    .as_ref()
                    .and_then(|target| gc_target_liveness_protection(target, &target_liveness))
                {
                    add_gc_candidate_protection(
                        &mut report,
                        &candidate,
                        reason,
                        boundary_target.as_ref().map(|target| target.path.clone()),
                        Some(evidence),
                        candidate.untracked_paths.clone(),
                    )?;
                    continue;
                }
                if !candidate.superseded
                    && !worktree_gc_candidate_remains_merged(&repo, &candidate)?
                {
                    add_gc_candidate_protection(
                        &mut report,
                        &candidate,
                        WorktreeGcReason::UnmergedBranch,
                        boundary_target.as_ref().map(|target| target.path.clone()),
                        None,
                        candidate.untracked_paths.clone(),
                    )?;
                    continue;
                }
                let removal = remove_gc_candidate(
                    &repo,
                    &registry_store,
                    &registry_lock,
                    &mut registry,
                    &candidate,
                    boundary_target.as_ref(),
                    WorktreeGcRemovalChecks {
                        allowed_untracked_paths: &allowed_untracked_paths,
                        target_liveness: &target_liveness,
                    },
                )?;
                let removed_untracked_paths = match removal {
                    WorktreeGcRemovalOutcome::Removed { untracked_paths } => untracked_paths,
                    WorktreeGcRemovalOutcome::TargetIdentityChanged => {
                        add_gc_candidate_protection(
                            &mut report,
                            &candidate,
                            WorktreeGcReason::TargetIdentityChanged,
                            boundary_target.as_ref().map(|target| target.path.clone()),
                            Some(target_identity_changed_evidence()),
                            candidate.untracked_paths.clone(),
                        )?;
                        continue;
                    }
                    WorktreeGcRemovalOutcome::DirtinessChanged {
                        reason,
                        untracked_paths,
                    } => {
                        add_gc_candidate_protection(
                            &mut report,
                            &candidate,
                            reason,
                            boundary_target.as_ref().map(|target| target.path.clone()),
                            None,
                            untracked_paths,
                        )?;
                        continue;
                    }
                };
                registered_names.remove(&candidate.binding.name);
                report.removed_count = report
                    .removed_count
                    .checked_add(1)
                    .context("worktree GC removed count overflowed")?;
                report.estimated_reclaimable_bytes = report
                    .estimated_reclaimable_bytes
                    .checked_add(candidate.apparent_worktree_bytes)
                    .context("worktree GC estimated reclaimable bytes overflowed")?;
                report.estimated_reclaimed_bytes = report
                    .estimated_reclaimed_bytes
                    .checked_add(candidate.apparent_worktree_bytes)
                    .context("worktree GC estimated reclaimed bytes overflowed")?;
                report.entries.push(WorktreeGcEntry {
                    name: candidate.binding.name,
                    branch: Some(candidate.binding.branch),
                    path: candidate.binding.path,
                    status: WorktreeGcStatus::Removed,
                    reason: completion_reason,
                    target_path: boundary_target.as_ref().map(|target| target.path.clone()),
                    target_liveness: None,
                    apparent_worktree_bytes: Some(candidate.apparent_worktree_bytes),
                    apparent_target_bytes: candidate.apparent_target_bytes,
                    untracked_paths: removed_untracked_paths,
                    gate_denial: None,
                    retention_operation_id: None,
                });
                retention_state = decision.committed_state;
                continue;
            }

            if options.remove_targets {
                if let Some(preflight_target) = preflight_target {
                    let Some(target_bytes) = candidate.apparent_target_bytes else {
                        add_gc_candidate_protection(
                            &mut report,
                            &candidate,
                            WorktreeGcReason::SizeMeasurementFailed,
                            Some(preflight_target.path.clone()),
                            None,
                            candidate.untracked_paths.clone(),
                        )?;
                        continue;
                    };
                    let (reason, target) = if options.dry_run {
                        (WorktreeGcReason::TargetWouldRemove, preflight_target)
                    } else {
                        let boundary_target = gc_target_at_apply_boundary(
                            &candidate.binding.path,
                            Some(&preflight_target),
                        )?;
                        if !worktree_gc_target_bindings_match(
                            Some(&preflight_target),
                            boundary_target.as_ref(),
                        ) {
                            add_gc_candidate_protection(
                                &mut report,
                                &candidate,
                                WorktreeGcReason::TargetIdentityChanged,
                                boundary_target
                                    .as_ref()
                                    .or(Some(&preflight_target))
                                    .map(|target| target.path.clone()),
                                Some(target_identity_changed_evidence()),
                                candidate.untracked_paths.clone(),
                            )?;
                            continue;
                        }
                        let Some(boundary_target) = boundary_target else {
                            add_gc_candidate_protection(
                                &mut report,
                                &candidate,
                                WorktreeGcReason::TargetIdentityChanged,
                                Some(preflight_target.path.clone()),
                                Some(target_identity_changed_evidence()),
                                candidate.untracked_paths.clone(),
                            )?;
                            continue;
                        };
                        if let Some((reason, evidence)) =
                            gc_target_liveness_protection(&boundary_target, &target_liveness)
                        {
                            add_gc_candidate_protection(
                                &mut report,
                                &candidate,
                                reason,
                                Some(boundary_target.path.clone()),
                                Some(evidence),
                                candidate.untracked_paths.clone(),
                            )?;
                            continue;
                        }
                        match worktree_gc_dirtiness_disposition(
                            gc_worktree_dirtiness(&candidate.binding.path)?,
                            options.targets_only,
                            &allowed_untracked_paths,
                        ) {
                            WorktreeGcDirtinessDisposition::Eligible(paths) => {
                                candidate.untracked_paths = paths;
                            }
                            WorktreeGcDirtinessDisposition::Protected {
                                reason,
                                untracked_paths,
                            } => {
                                add_gc_candidate_protection(
                                    &mut report,
                                    &candidate,
                                    reason,
                                    Some(boundary_target.path.clone()),
                                    None,
                                    untracked_paths,
                                )?;
                                continue;
                            }
                        }
                        if !worktree_gc_target_identity_is_current(&boundary_target)
                            || matches!(
                                remove_worktree_target_dir(
                                    &candidate.binding.path,
                                    &boundary_target,
                                )?,
                                WorktreeTargetRemovalOutcome::IdentityChanged
                            )
                        {
                            add_gc_candidate_protection(
                                &mut report,
                                &candidate,
                                WorktreeGcReason::TargetIdentityChanged,
                                Some(boundary_target.path.clone()),
                                Some(target_identity_changed_evidence()),
                                candidate.untracked_paths.clone(),
                            )?;
                            continue;
                        }
                        report.target_removed_count = report
                            .target_removed_count
                            .checked_add(1)
                            .context("worktree GC target count overflowed")?;
                        report.estimated_reclaimed_bytes = report
                            .estimated_reclaimed_bytes
                            .checked_add(target_bytes)
                            .context("worktree GC estimated reclaimed bytes overflowed")?;
                        (WorktreeGcReason::TargetRemoved, boundary_target)
                    };
                    report.estimated_reclaimable_bytes = report
                        .estimated_reclaimable_bytes
                        .checked_add(target_bytes)
                        .context("worktree GC estimated reclaimable bytes overflowed")?;
                    report.retained_count = report
                        .retained_count
                        .checked_add(1)
                        .context("worktree GC retained count overflowed")?;
                    report.entries.push(WorktreeGcEntry {
                        name: candidate.binding.name,
                        branch: Some(candidate.binding.branch),
                        path: candidate.binding.path,
                        status: WorktreeGcStatus::Retained,
                        reason,
                        target_path: Some(target.path),
                        target_liveness: None,
                        apparent_worktree_bytes: Some(candidate.apparent_worktree_bytes),
                        apparent_target_bytes: Some(target_bytes),
                        untracked_paths: candidate.untracked_paths,
                        gate_denial: None,
                        retention_operation_id: None,
                    });
                    retention_state = decision.committed_state;
                    continue;
                }
            }
            report.retained_count = report
                .retained_count
                .checked_add(1)
                .context("worktree GC retained count overflowed")?;
            report.entries.push(WorktreeGcEntry {
                name: candidate.binding.name,
                branch: Some(candidate.binding.branch),
                path: candidate.binding.path,
                status: WorktreeGcStatus::Retained,
                reason: if !candidate.branch_merged
                    && !candidate.superseded
                    && !options.targets_only
                {
                    WorktreeGcReason::UnmergedBranch
                } else if options.remove_targets {
                    WorktreeGcReason::NoTarget
                } else {
                    WorktreeGcReason::RetentionKeep
                },
                target_path: None,
                target_liveness: None,
                apparent_worktree_bytes: Some(candidate.apparent_worktree_bytes),
                apparent_target_bytes: None,
                untracked_paths: candidate.untracked_paths,
                gate_denial: None,
                retention_operation_id: None,
            });
            retention_state = decision.committed_state;
        }

        if !options.targets_only && candidate_agent_ids.is_none() {
            prune_unregistered_worktree_directories(
                &repo,
                &worktree_root,
                &registered_names,
                options.dry_run,
                options.machine_global_retention.as_ref(),
                &mut report,
            )?;
        }
        Ok(report)
    }

    /// Resolves one execution-facing worktree through the durable MACO
    /// registry. An unbound Git worktree is rejected instead of being adopted
    /// implicitly.
    pub fn get_managed_verified(&self, agent_id: &str) -> Result<WorktreeRecord> {
        let name = normalize_agent_id(agent_id)?;
        let repo = self.open_repository()?;
        let registry_store = ManagedWorktreeRegistryStore::open(&repo)?;
        let registry_lock = registry_store.lock()?;
        let mut registry = registry_store.load(&registry_lock)?;
        recover_pending_operations(&repo, &registry_store, &registry_lock, &mut registry)?;
        let binding = registry.records.get(&name).with_context(|| {
            format!("worktree '{name}' has no verified MACO binding; explicit adoption is required")
        })?;
        verified_worktree_record(&repo, &registry_store.repository, binding)
    }

    /// Acquires a shared cooperative lease for immutable access to a managed
    /// worktree. The returned record was verified while registry recovery,
    /// binding verification, and lease acquisition were serialized against
    /// managed removal.
    pub fn acquire_read_execution_lease(&self, agent_id: &str) -> Result<ManagedWorktreeReadLease> {
        let name = normalize_agent_id(agent_id)?;
        let repo = self.open_repository()?;
        let registry_store = ManagedWorktreeRegistryStore::open(&repo)?;
        let registry_lock = registry_store.lock()?;
        let mut registry = registry_store.load(&registry_lock)?;
        recover_pending_operations(&repo, &registry_store, &registry_lock, &mut registry)?;
        let binding = registry.records.get(&name).with_context(|| {
            format!("worktree '{name}' has no verified MACO binding; explicit adoption is required")
        })?;
        let record = verified_worktree_record(&repo, &registry_store.repository, binding)?;
        let (lock, process_lease) = finish_with_registry_lock_verification(
            registry_store
                .try_acquire_shared_worktree_read_lock(&registry_lock, &name)
                .with_context(|| {
                    format!("failed to acquire shared read lease for managed worktree '{name}'")
                }),
            registry_store.verify_lock(&registry_lock),
        )?;
        Ok(ManagedWorktreeReadLease {
            record,
            _lock: lock,
            _process_lease: process_lease,
        })
    }

    /// Compatibility wrapper for the original shared execution lease API.
    ///
    /// The returned lease is shared and is suitable only for immutable access.
    /// Mutation call sites must use [`Self::acquire_write_execution_lease`].
    pub fn acquire_execution_lease(&self, agent_id: &str) -> Result<ManagedWorktreeExecutionLease> {
        self.acquire_read_execution_lease(agent_id)
    }

    /// Acquires an exclusive cooperative lease for a mutating lifecycle on one
    /// verified managed worktree. Pending removal is recovered or rejected
    /// before lookup, and the exclusive lock is acquired while the durable
    /// registry lock remains held. Consequently readers, writers, and removal
    /// cannot cross the verified-record handoff.
    pub fn acquire_write_execution_lease(
        &self,
        agent_id: &str,
    ) -> Result<ManagedWorktreeWriteLease> {
        let name = normalize_agent_id(agent_id)?;
        let repo = self.open_repository()?;
        let registry_store = ManagedWorktreeRegistryStore::open(&repo)?;
        let registry_lock = registry_store.lock()?;
        let mut registry = registry_store.load(&registry_lock)?;
        recover_pending_operations(&repo, &registry_store, &registry_lock, &mut registry)?;
        let binding = registry.records.get(&name).with_context(|| {
            format!("worktree '{name}' has no verified MACO binding; explicit adoption is required")
        })?;
        let record = verified_worktree_record(&repo, &registry_store.repository, binding)?;
        let (lock, process_lease) = finish_with_registry_lock_verification(
            registry_store
                .try_acquire_exclusive_worktree_write_lock(&registry_lock, &name)
                .with_context(|| {
                    format!("failed to acquire exclusive write lease for managed worktree '{name}'")
                }),
            registry_store.verify_lock(&registry_lock),
        )?;
        Ok(ManagedWorktreeWriteLease {
            record,
            repository: registry_store.repository.clone(),
            _lock: lock,
            _process_lease: process_lease,
        })
    }

    /// Verifies that a borrowed write lease grants authority for this manager's
    /// repository and the requested managed agent binding.
    ///
    /// The lease records the create-time repository identity captured while
    /// the registry lock was held. Re-reading the durable binding here avoids
    /// treating a matching path alone as proof that a lease from another
    /// repository authorizes this operation.
    pub(crate) fn verify_write_execution_lease(
        &self,
        agent_id: &str,
        lease: &ManagedWorktreeWriteLease,
    ) -> Result<()> {
        let name = normalize_agent_id(agent_id)?;
        if lease.record.name != name {
            bail!(
                "managed worktree write lease belongs to agent '{}' rather than '{name}'",
                lease.record.name
            );
        }

        let repo = self.open_repository()?;
        let registry_store = ManagedWorktreeRegistryStore::open(&repo)?;
        if lease.repository != registry_store.repository {
            bail!("managed worktree write lease belongs to a different managed repository");
        }

        let registry_lock = registry_store.lock()?;
        let mut registry = registry_store.load(&registry_lock)?;
        recover_pending_operations(&repo, &registry_store, &registry_lock, &mut registry)?;
        let binding = registry.records.get(&name).with_context(|| {
            format!("worktree '{name}' has no verified MACO binding; explicit adoption is required")
        })?;
        let record = verified_worktree_record(&repo, &registry_store.repository, binding)?;
        if record != lease.record {
            bail!(
                "managed worktree write lease no longer matches the verified binding for '{name}'"
            );
        }
        registry_store.verify_lock(&registry_lock)
    }

    fn open_repository(&self) -> Result<Repository> {
        crate::git_repository::open(&self.repo_path)
            .with_context(|| format!("failed to open repository {}", self.repo_path.display()))
    }
}

pub fn sweep_workspace_worktrees(options: WorktreeSweepOptions) -> Result<WorktreeSweepReport> {
    validate_worktree_gc_mode(
        options.targets_only,
        options.remove_targets,
        options.retention,
        &options.allowed_untracked_paths,
        false,
    )?;
    let allowed_untracked_paths =
        normalize_gc_allowed_untracked_paths(&options.allowed_untracked_paths)?;
    let workspace = fs::canonicalize(&options.workspace).with_context(|| {
        format!(
            "failed to resolve workspace {}",
            options.workspace.display()
        )
    })?;
    require_plain_directory(&workspace, "workspace")?;
    let mut roots = discover_workspace_managed_sweep_roots(&workspace)?;
    roots.extend(discover_repository_local_sweep_roots(&workspace)?);
    roots.sort_by(|left, right| {
        left.group
            .cmp(&right.group)
            .then_with(|| left.worktree_root.cmp(&right.worktree_root))
    });
    let discovery_status = if roots.is_empty() {
        WorktreeSweepDiscoveryStatus::NoRootsDiscovered
    } else {
        WorktreeSweepDiscoveryStatus::RootsDiscovered
    };

    let dry_run = !options.apply;
    let mut report = WorktreeSweepReport {
        workspace: workspace.clone(),
        apply: options.apply,
        dry_run,
        remove_targets: options.remove_targets,
        targets_only: options.targets_only,
        max_age_seconds: options.retention.max_age.map(|age| age.as_secs()),
        max_count: options.retention.max_count,
        max_total_bytes: options.retention.max_total_bytes,
        allowed_untracked_paths: allowed_untracked_paths.iter().cloned().collect(),
        discovery_status,
        worktree_root_discovered_count: roots.len(),
        repository_discovered_count: roots.len(),
        repository_inspected_count: 0,
        repository_pre_gc_skipped_count: 0,
        repository_gc_failed_count: 0,
        repository_failure_count: 0,
        considered_count: 0,
        removed_count: 0,
        protected_count: 0,
        retained_count: 0,
        target_removed_count: 0,
        orphan_removed_count: 0,
        apparent_considered_bytes: 0,
        estimated_reclaimable_bytes: 0,
        estimated_reclaimed_bytes: 0,
        repositories: Vec::with_capacity(roots.len()),
    };

    for root in roots {
        let WorktreeSweepRootCandidate {
            group,
            root_kind,
            worktree_root: group_root,
            plain_directory,
            repository_hint,
        } = root;
        if !plain_directory {
            add_sweep_pre_gc_failure(
                &mut report,
                group,
                root_kind,
                group_root.clone(),
                WorktreeSweepFailure {
                    kind: WorktreeSweepFailureKind::RepositoryAssociation,
                    message: format!(
                        "workspace worktree group is not a plain directory: {}",
                        group_root.display()
                    ),
                },
            )?;
            continue;
        }
        let repository = match resolve_sweep_repository(
            &workspace,
            &group_root,
            &group,
            root_kind,
            repository_hint.as_deref(),
        ) {
            Ok(repository) => repository,
            Err(failure) => {
                add_sweep_pre_gc_failure(&mut report, group, root_kind, group_root, failure)?;
                continue;
            }
        };
        let gc_result = WorktreeManager::new(&repository).gc(WorktreeGcOptions {
            worktree_root: Some(group_root.clone()),
            dry_run,
            remove_targets: options.remove_targets,
            targets_only: options.targets_only,
            retention: options.retention,
            allowed_untracked_paths: allowed_untracked_paths.iter().cloned().collect(),
            exclude_agent_id: None,
            candidate_agent_ids: None,
            merged_into_reference: None,
            superseded_by_agent_id: BTreeMap::new(),
            machine_global_retention: None,
        });
        match gc_result {
            Ok(mut gc_report) => {
                if dry_run && root_kind == WorktreeSweepRootKind::RepositoryLocal {
                    let excluded_names = gc_report
                        .entries
                        .iter()
                        .map(|entry| entry.name.clone())
                        .collect::<BTreeSet<_>>();
                    match preview_registered_repository_local_worktrees(
                        &repository,
                        &group_root,
                        &options,
                        &excluded_names,
                    ) {
                        Ok(preview) => merge_worktree_gc_preview(&mut gc_report, preview)?,
                        Err(error) => {
                            add_sweep_gc_counts(&mut report, &gc_report)?;
                            report.repository_gc_failed_count = report
                                .repository_gc_failed_count
                                .checked_add(1)
                                .context("workspace sweep GC failure count overflowed")?;
                            report.repository_failure_count = report
                                .repository_failure_count
                                .checked_add(1)
                                .context("workspace sweep repository failure count overflowed")?;
                            report.repositories.push(WorktreeSweepRepositoryReport {
                                group,
                                root_kind,
                                worktree_root: group_root,
                                repository: Some(repository),
                                status: WorktreeSweepRepositoryStatus::Failed,
                                gc_attempted: true,
                                effects_may_have_occurred: false,
                                failure: Some(WorktreeSweepFailure {
                                    kind: WorktreeSweepFailureKind::GarbageCollection,
                                    message: format!(
                                        "repository-local registered-worktree preview failed: {error:#}"
                                    ),
                                }),
                                gc_report: Some(gc_report),
                            });
                            continue;
                        }
                    }
                }
                add_sweep_gc_counts(&mut report, &gc_report)?;
                report.repository_inspected_count = report
                    .repository_inspected_count
                    .checked_add(1)
                    .context("workspace sweep inspected repository count overflowed")?;
                report.repositories.push(WorktreeSweepRepositoryReport {
                    group,
                    root_kind,
                    worktree_root: group_root,
                    repository: Some(repository),
                    status: WorktreeSweepRepositoryStatus::Inspected,
                    gc_attempted: true,
                    effects_may_have_occurred: false,
                    failure: None,
                    gc_report: Some(gc_report),
                });
            }
            Err(error) => {
                let preview_result =
                    if dry_run && root_kind == WorktreeSweepRootKind::RepositoryLocal {
                        Some(preview_registered_repository_local_worktrees(
                            &repository,
                            &group_root,
                            &options,
                            &BTreeSet::new(),
                        ))
                    } else {
                        None
                    };
                let preview = preview_result
                    .as_ref()
                    .and_then(|result| result.as_ref().ok());
                if let Some(preview) = preview {
                    add_sweep_gc_counts(&mut report, preview)?;
                }
                report.repository_gc_failed_count = report
                    .repository_gc_failed_count
                    .checked_add(1)
                    .context("workspace sweep GC failure count overflowed")?;
                report.repository_failure_count = report
                    .repository_failure_count
                    .checked_add(1)
                    .context("workspace sweep repository failure count overflowed")?;
                report.repositories.push(WorktreeSweepRepositoryReport {
                    group,
                    root_kind,
                    worktree_root: group_root,
                    repository: Some(repository),
                    status: WorktreeSweepRepositoryStatus::Failed,
                    gc_attempted: true,
                    effects_may_have_occurred: !dry_run,
                    failure: Some(WorktreeSweepFailure {
                        kind: WorktreeSweepFailureKind::GarbageCollection,
                        message: match preview_result.as_ref() {
                            Some(Err(preview_error)) => format!(
                                "{error:#}; repository-local registered-worktree preview also failed: {preview_error:#}"
                            ),
                            _ => format!("{error:#}"),
                        },
                    }),
                    gc_report: preview.cloned(),
                });
            }
        }
    }

    Ok(report)
}

fn parse_retry_predecessor(successor: &str) -> std::result::Result<Option<String>, String> {
    let Some((stem, suffix)) = successor.rsplit_once('-') else {
        return Ok(None);
    };
    if stem.is_empty() {
        return Err("retry successor has an empty predecessor stem".to_string());
    }
    if suffix == "round2" {
        return Ok(Some(stem.to_string()));
    }
    if let Some(generation) = suffix.strip_prefix('r') {
        if generation.is_empty() || !generation.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("retry suffix is malformed".to_string());
        }
        if generation.len() > 1 && generation.starts_with('0') {
            return Err("retry generation is noncanonical".to_string());
        }
        let generation = generation
            .parse::<u32>()
            .map_err(|_| "retry generation is outside the supported range".to_string())?;
        if generation < 2 {
            return Err("retry generation must be at least 2".to_string());
        }
        return Ok(Some(if generation == 2 {
            stem.to_string()
        } else {
            format!("{stem}-r{}", generation - 1)
        }));
    }
    if suffix.starts_with("round") {
        return Err("only the canonical '-round2' long retry suffix is supported".to_string());
    }
    Ok(None)
}

fn resolve_retry_supersession(
    repo: &Repository,
    successor: &str,
) -> Result<RetrySupersessionReport> {
    let successor = normalize_agent_id(successor).context("retry successor agent id is invalid")?;
    let predecessor = match parse_retry_predecessor(&successor) {
        Ok(Some(predecessor)) => predecessor,
        Ok(None) => {
            return Ok(RetrySupersessionReport {
                successor_agent_id: Some(successor),
                predecessor_agent_id: None,
                status: RetrySupersessionStatus::NotRetryLane,
                authenticated_matches: Vec::new(),
                detail: Some("agent id has no canonical retry suffix".to_string()),
            })
        }
        Err(detail) => {
            return Ok(RetrySupersessionReport {
                successor_agent_id: Some(successor),
                predecessor_agent_id: None,
                status: RetrySupersessionStatus::Ambiguous,
                authenticated_matches: Vec::new(),
                detail: Some(detail),
            })
        }
    };
    let Some(store) = ManagedWorktreeRegistryStore::open_existing(repo)? else {
        return Ok(RetrySupersessionReport {
            successor_agent_id: Some(successor),
            predecessor_agent_id: Some(predecessor),
            status: RetrySupersessionStatus::PredecessorNotFound,
            authenticated_matches: Vec::new(),
            detail: Some("authenticated managed worktree state is absent".to_string()),
        });
    };
    let Some(registry) = store.load_existing_read_only()? else {
        return Ok(RetrySupersessionReport {
            successor_agent_id: Some(successor),
            predecessor_agent_id: Some(predecessor),
            status: RetrySupersessionStatus::PredecessorNotFound,
            authenticated_matches: Vec::new(),
            detail: Some("authenticated managed worktree registry is absent".to_string()),
        });
    };
    let Some(successor_binding) = registry.records.get(&successor) else {
        return Ok(RetrySupersessionReport {
            successor_agent_id: Some(successor),
            predecessor_agent_id: Some(predecessor),
            status: RetrySupersessionStatus::Ambiguous,
            authenticated_matches: Vec::new(),
            detail: Some("retry successor lacks an exact authenticated lane identity".to_string()),
        });
    };
    if registry.operations.contains_key(&successor_binding.name) {
        return Ok(RetrySupersessionReport {
            successor_agent_id: Some(successor),
            predecessor_agent_id: Some(predecessor),
            status: RetrySupersessionStatus::Ambiguous,
            authenticated_matches: Vec::new(),
            detail: Some("retry successor has a pending authenticated operation".to_string()),
        });
    }
    if let Err(error) =
        verify_managed_worktree_binding(repo, &store.repository, successor_binding, false)
    {
        return Ok(RetrySupersessionReport {
            successor_agent_id: Some(successor),
            predecessor_agent_id: Some(predecessor),
            status: RetrySupersessionStatus::Ambiguous,
            authenticated_matches: Vec::new(),
            detail: Some(format!(
                "retry successor binding is not live and verified: {error:#}"
            )),
        });
    }
    let mut matches = registry
        .records
        .values()
        .filter(|binding| {
            binding.root == successor_binding.root
                && (binding.name == predecessor
                    || binding.branch == predecessor
                    || binding.branch.rsplit('/').next() == Some(predecessor.as_str()))
        })
        .map(|binding| binding.name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    matches.sort();
    let (status, selected, detail) = match matches.as_slice() {
        [] => (
            RetrySupersessionStatus::PredecessorNotFound,
            None,
            Some("no exact authenticated predecessor identity matched".to_string()),
        ),
        [only] if only == &predecessor => {
            let predecessor_binding = registry
                .records
                .get(only)
                .context("authenticated retry predecessor disappeared during classification")?;
            if let Err(error) = verify_managed_worktree_binding(
                repo,
                &store.repository,
                predecessor_binding,
                false,
            ) {
                return Ok(RetrySupersessionReport {
                    successor_agent_id: Some(successor),
                    predecessor_agent_id: Some(predecessor),
                    status: RetrySupersessionStatus::Ambiguous,
                    authenticated_matches: matches,
                    detail: Some(format!(
                        "retry predecessor binding is not live and verified: {error:#}"
                    )),
                });
            }
            let successor_branch_predecessor = parse_retry_predecessor(&successor_binding.branch)
                .ok()
                .flatten();
            if successor_branch_predecessor.as_deref() == Some(predecessor_binding.branch.as_str())
                || successor_branch_predecessor
                    .as_deref()
                    .and_then(|branch| branch.rsplit('/').next())
                    == predecessor_binding.branch.rsplit('/').next()
            {
                (
                    RetrySupersessionStatus::Selected,
                    Some(only.clone()),
                    None,
                )
            } else {
                (
                    RetrySupersessionStatus::Ambiguous,
                    None,
                    Some(
                        "retry successor and predecessor do not share one canonical branch family"
                            .to_string(),
                    ),
                )
            }
        }
        [only] => (
            RetrySupersessionStatus::Ambiguous,
            None,
            Some(format!(
                "branch-derived predecessor matched authenticated lane '{only}', not exact agent id '{predecessor}'"
            )),
        ),
        _ => (
            RetrySupersessionStatus::Ambiguous,
            None,
            Some("multiple authenticated predecessor identities matched".to_string()),
        ),
    };
    Ok(RetrySupersessionReport {
        successor_agent_id: Some(successor),
        predecessor_agent_id: selected.or(Some(predecessor)),
        status,
        authenticated_matches: matches,
        detail,
    })
}

include!("worktree/part2.rs");
include!("worktree/part3.rs");
include!("worktree/part4.rs");

#[cfg(test)]
mod tests;
