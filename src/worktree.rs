#[cfg(test)]
use crate::safe_state::scavenge_private_random_directories;
use crate::{
    artifacts::{
        prune_artifacts_with_policy, repository_authenticator_key_only,
        state_auth::{random_identifier, AuthenticationDomain, RepositoryAuthBinding},
        ArtifactRetentionFamily, ArtifactRetentionPolicy, RunArtifactPruneReport,
    },
    authenticated_snapshot::{
        AuthenticatedSnapshot, AuthenticatedSnapshotStore, ExistingAuthenticatedSnapshot,
        SnapshotSpec,
    },
    gate_denial::GateDenial,
    machine_global::{
        DestructiveTargetInput, GateOutcome, MachineGlobalRetentionBinding, MachineGlobalStore,
        RetentionOperationId,
    },
    process_runner::{
        run_process, ContainmentPolicy, EnvironmentMode, ProcessOutput, ProcessSpec,
        SideEffectConfinementProfile, StdinMode, StrictOfflineWorkspaceProfile,
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
        finalize_legacy_retirement, prepare_legacy_retirement,
        verify_existing_active_legacy_retirement, LegacyAdoption, LEGACY_RETIREMENT_DOMAIN,
    },
    sync_store::{LockedClaimsSnapshot, SyncStore},
};
use anyhow::{bail, Context, Result};
#[cfg(unix)]
use git2::ConfigLevel;
use git2::{
    Branch, BranchType, ErrorCode, ObjectType, Oid, Repository, RepositoryInitOptions, Status,
    StatusOptions, Transaction, WorktreeAddOptions, WorktreeLockStatus, WorktreePruneOptions,
};
use serde::{Deserialize, Serialize, Serializer};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{CString, OsStr, OsString},
    fs::{self, File},
    io::ErrorKind,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

#[cfg(unix)]
use std::io::{Read, Seek, SeekFrom};
const DEFAULT_BRANCH_PREFIX: &str = "maco";
#[cfg(unix)]
const WORKTREE_GUARD_ASSET: &[u8] = include_bytes!("../assets/maco-worktree-guard.sh");
#[cfg(unix)]
const WORKTREE_GUARD_DIRECTORY: &str = "maco-worktree-guard";
#[cfg(unix)]
const WORKTREE_GUARD_MARKER: &str = "maco-worktree-guard-v1\n";
#[cfg(unix)]
const HUMAN_AUTHORSHIP_GUARD_V3_MARKER: &[u8] = b"# human-authorship-guard dispatcher v3";
#[cfg(unix)]
const HUMAN_AUTHORSHIP_GUARD_V3_TRAILER: &[u8] =
    b"\n# Chained human-authorship dispatcher compatibility.\n# human-authorship-guard dispatcher v3\n";
#[cfg(unix)]
const HUMAN_AUTHORSHIP_COMMIT_MSG_V3: &[u8] = br##"#!/usr/bin/env bash
# human-authorship-guard dispatcher v3
set -euo pipefail
self="$(cd "$(dirname "$0")" && pwd -P)/$(basename "$0")"
previous="$self.human-authorship-previous"
if [[ -x "$previous" ]]; then
  "$previous" "$@"
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

guard="$(resolve_guard check-human-authorship)"
"$guard" identity 'pending author identity' "$(git var GIT_AUTHOR_IDENT)"
"$guard" identity 'pending committer identity' "$(git var GIT_COMMITTER_IDENT)"
exec "$guard" message "$1"
"##;
#[cfg(unix)]
const HUMAN_AUTHORSHIP_PRE_PUSH_V3: &[u8] = br##"#!/usr/bin/env bash
# human-authorship-guard dispatcher v3
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
"$authorship_guard" pre-push "${1:-}" < "$input"
private_guard="$(resolve_guard check-private-agent-paths)"
"$private_guard" pre-push "${1:-}" < "$input"
"##;
#[cfg(unix)]
const PRIOR_HOOK_MARKER_SCAN_LIMIT: u64 = 1024 * 1024;
#[cfg(unix)]
const WORKTREE_GUARD_HOOK_NAMES: &[&str] = &[
    "applypatch-msg",
    "pre-applypatch",
    "post-applypatch",
    "pre-commit",
    "pre-merge-commit",
    "prepare-commit-msg",
    "commit-msg",
    "post-commit",
    "pre-rebase",
    "post-checkout",
    "post-merge",
    "pre-push",
    "pre-receive",
    "update",
    "proc-receive",
    "post-receive",
    "post-update",
    "reference-transaction",
    "push-to-checkout",
    "pre-auto-gc",
    "post-rewrite",
    "sendemail-validate",
    "fsmonitor-watchman",
    "p4-changelist",
    "p4-prepare-changelist",
    "p4-post-changelist",
    "p4-pre-submit",
    "post-index-change",
];
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

/// Observable state returned by the explicit primary-worktree guard command.
///
/// The guard is intentionally advisory. It protects interactive Git use by a
/// human or rogue worker; it is not a security boundary. Trusted MACO Git
/// operations continue to set `core.hooksPath=/dev/null`, so repository hooks
/// cannot influence orchestration and this guard cannot constrain it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WorktreeGuardReport {
    pub status: WorktreeGuardStatus,
    pub worktree_path: PathBuf,
    pub hooks_path: PathBuf,
    pub mode: String,
    pub expected_branch: Option<String>,
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
    /// Maximum apparent bytes retained across newest age/count survivors.
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

#[derive(Debug, Clone)]
pub(crate) struct ExistingWorktreeBindingRequest<'a> {
    pub agent_id: String,
    pub lease: &'a ManagedWorktreeWriteLease,
    pub expected_record: WorktreeRecord,
    pub expected_head_oid: Oid,
    pub expected_ref_oid: Oid,
}

#[derive(Debug, Clone)]
pub(crate) struct ExistingWorktreeHeadExpectation {
    pub agent_id: String,
    pub head_oid: Oid,
    pub ref_oid: Oid,
}

#[derive(Debug, Error)]
pub(crate) enum ExistingWorktreeRevalidationError {
    #[error("existing authenticated managed-worktree state is unavailable or invalid")]
    StateUnavailable {
        #[source]
        source: anyhow::Error,
    },
    #[error("existing managed-worktree registry lock is busy")]
    RegistryBusy,
    #[error("existing managed-worktree registry lock is missing")]
    RegistryLockMissing,
    #[error("managed-worktree revalidation request count exceeds the {limit} entry bound")]
    RequestLimit { limit: usize },
    #[error("managed-worktree registry has pending {kind} operation '{name}' in phase '{phase}'")]
    PendingOperation {
        name: String,
        kind: String,
        phase: String,
    },
    #[error("write lease for agent '{agent_id}' belongs to a different repository or record")]
    LeaseAuthorityMismatch { agent_id: String },
    #[error("write lease for agent '{agent_id}' is not the current exclusive incarnation")]
    LeaseIncarnationMismatch { agent_id: String },
    #[error("managed worktree binding for agent '{agent_id}' is unavailable or invalid")]
    BindingInvalid {
        agent_id: String,
        #[source]
        source: anyhow::Error,
    },
    #[error("managed worktree record mismatch for agent '{agent_id}'")]
    RecordMismatch { agent_id: String },
    #[error("managed worktree HEAD is detached for agent '{agent_id}'")]
    DetachedHead { agent_id: String },
    #[error("managed worktree branch mismatch for agent '{agent_id}': expected '{expected}', found '{actual}'")]
    WrongBranch {
        agent_id: String,
        expected: String,
        actual: String,
    },
    #[error("managed worktree HEAD OID mismatch for agent '{agent_id}': expected {expected}, found {actual}")]
    HeadOidMismatch {
        agent_id: String,
        expected: Oid,
        actual: Oid,
    },
    #[error("managed worktree ref OID mismatch for agent '{agent_id}': expected {expected}, found {actual}")]
    RefOidMismatch {
        agent_id: String,
        expected: Oid,
        actual: Oid,
    },
    #[error("authenticated managed-worktree state changed while its guard was held")]
    StateChanged,
    #[error("managed-worktree end expectation set does not match its guarded batch")]
    ExpectationMismatch,
}

#[must_use = "the managed-worktree guard must be retained for the protected operation"]
#[derive(Debug)]
pub(crate) struct ExistingManagedWorktreeGuard<'a> {
    store: ManagedWorktreeRegistryStore,
    lock: ManagedWorktreeRegistryLock,
    authenticated: AuthenticatedManagedState,
    requests: Vec<ExistingWorktreeBindingRequest<'a>>,
}

impl ExistingManagedWorktreeGuard<'_> {
    pub(crate) fn verify(&self) -> std::result::Result<(), ExistingWorktreeRevalidationError> {
        let expectations = self
            .requests
            .iter()
            .map(|request| ExistingWorktreeHeadExpectation {
                agent_id: request.agent_id.clone(),
                head_oid: request.expected_head_oid,
                ref_oid: request.expected_ref_oid,
            })
            .collect::<Vec<_>>();
        self.verify_with_heads(&expectations)
    }

    pub(crate) fn verify_with_heads(
        &self,
        expectations: &[ExistingWorktreeHeadExpectation],
    ) -> std::result::Result<(), ExistingWorktreeRevalidationError> {
        if expectations.len() != self.requests.len() {
            return Err(ExistingWorktreeRevalidationError::ExpectationMismatch);
        }
        let by_agent = expectations
            .iter()
            .map(|expectation| (expectation.agent_id.as_str(), expectation))
            .collect::<BTreeMap<_, _>>();
        if by_agent.len() != expectations.len() {
            return Err(ExistingWorktreeRevalidationError::ExpectationMismatch);
        }
        let authenticated = self
            .store
            .load_existing_authenticated_state(&self.lock)
            .map_err(|source| ExistingWorktreeRevalidationError::StateUnavailable { source })?;
        if authenticated != self.authenticated {
            return Err(ExistingWorktreeRevalidationError::StateChanged);
        }
        reject_pending_managed_operation(&authenticated.registry)?;
        for request in &self.requests {
            let expectation = by_agent
                .get(request.agent_id.as_str())
                .ok_or(ExistingWorktreeRevalidationError::ExpectationMismatch)?;
            verify_existing_worktree_request(
                &self.store,
                &self.lock,
                &authenticated,
                request,
                expectation.head_oid,
                expectation.ref_oid,
            )?;
        }
        Ok(())
    }

    /// Revalidates one member of a retained batch at its original HEAD.
    ///
    /// Parallel worker commands may advance their own branches after their
    /// literal pre-spawn check. A later sibling must still authenticate the
    /// retained registry state, but must not reject merely because that
    /// already-started sibling advanced its branch. The full batch is rebound
    /// to all resulting HEADs after every child has joined.
    pub(crate) fn verify_agent(
        &self,
        agent_id: &str,
    ) -> std::result::Result<(), ExistingWorktreeRevalidationError> {
        let mut matching = self
            .requests
            .iter()
            .filter(|request| request.agent_id == agent_id);
        let request = matching
            .next()
            .ok_or(ExistingWorktreeRevalidationError::ExpectationMismatch)?;
        if matching.next().is_some() {
            return Err(ExistingWorktreeRevalidationError::ExpectationMismatch);
        }
        let authenticated = self
            .store
            .load_existing_authenticated_state(&self.lock)
            .map_err(|source| ExistingWorktreeRevalidationError::StateUnavailable { source })?;
        if authenticated != self.authenticated {
            return Err(ExistingWorktreeRevalidationError::StateChanged);
        }
        reject_pending_managed_operation(&authenticated.registry)?;
        verify_existing_worktree_request(
            &self.store,
            &self.lock,
            &authenticated,
            request,
            request.expected_head_oid,
            request.expected_ref_oid,
        )
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

#[derive(Debug)]
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
        _options: WorktreeCreateOptions,
        _retention: WorktreeRetentionPolicy,
    ) -> Result<WorktreeRecord> {
        bail!(
            "managed worktree creation is unsupported without a capability-bound repository cleanliness input"
        );
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
            });
        }

        let now = unix_now_nanos()?;
        candidates.sort_by(|left, right| {
            gc_created_at(&right.binding)
                .cmp(&gc_created_at(&left.binding))
                .then_with(|| left.binding.name.cmp(&right.binding.name))
        });
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

    /// Revalidates a bounded batch of already-held exclusive write leases using
    /// only existing authenticated state. The returned guard retains the one
    /// global managed registry lock, so cooperative lifecycle operations cannot
    /// change an incarnation, record, or pending-operation set until the
    /// caller's mutation/collection boundary is complete.
    pub(crate) fn revalidate_existing_write_leases<'a>(
        &self,
        requests: Vec<ExistingWorktreeBindingRequest<'a>>,
    ) -> std::result::Result<ExistingManagedWorktreeGuard<'a>, ExistingWorktreeRevalidationError>
    {
        if requests.is_empty() || requests.len() > MAX_MANAGED_RECORDS {
            return Err(ExistingWorktreeRevalidationError::RequestLimit {
                limit: MAX_MANAGED_RECORDS,
            });
        }
        let repo = self
            .open_repository()
            .map_err(|source| ExistingWorktreeRevalidationError::StateUnavailable { source })?;
        let store = ManagedWorktreeRegistryStore::open_existing(&repo)
            .map_err(|source| ExistingWorktreeRevalidationError::StateUnavailable { source })?
            .ok_or_else(|| ExistingWorktreeRevalidationError::StateUnavailable {
                source: anyhow::anyhow!("authenticated managed-worktree state is absent"),
            })?;
        let lock = store.lock_existing_for_revalidation()?;
        let authenticated = store
            .load_existing_authenticated_state(&lock)
            .map_err(|source| ExistingWorktreeRevalidationError::StateUnavailable { source })?;
        reject_pending_managed_operation(&authenticated.registry)?;
        for request in &requests {
            verify_existing_worktree_request(
                &store,
                &lock,
                &authenticated,
                request,
                request.expected_head_oid,
                request.expected_ref_oid,
            )?;
        }
        Ok(ExistingManagedWorktreeGuard {
            store,
            lock,
            authenticated,
            requests,
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum WorktreeGuardMode {
    Primary,
    #[cfg(unix)]
    Managed {
        expected_branch: String,
    },
}

#[cfg(unix)]
impl WorktreeGuardMode {
    fn label(&self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Managed { .. } => "managed",
        }
    }

    fn expected_branch(&self) -> Option<&str> {
        match self {
            Self::Primary => None,
            Self::Managed { expected_branch } => Some(expected_branch),
        }
    }
}

#[cfg(unix)]
#[derive(Debug)]
struct WorktreeGuardLayout {
    worktree_path: PathBuf,
    git_dir: PathBuf,
    bound_git_dir: PathBuf,
    common_dir: PathBuf,
    root: PathBuf,
    hooks: PathBuf,
    bound_hooks: PathBuf,
    config: PathBuf,
    include_level: WorktreeGuardIncludeLevel,
    include_config: PathBuf,
    include_config_created: bool,
    include_key: String,
    config_text: String,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorktreeGuardIncludeLevel {
    Local,
    Worktree,
}

#[cfg(unix)]
impl WorktreeGuardIncludeLevel {
    fn label(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Worktree => "worktree",
        }
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct EffectivePriorHookPaths {
    worktree_hooks: PathBuf,
    git_dir_hooks: PathBuf,
    human_v3_commit_msg: bool,
    human_v3_pre_push: bool,
}

/// Installs the advisory guard into the selected primary checkout.
///
/// Primary installation is never implicit: only the explicit CLI surface
/// calls this function. Managed lanes use the separate internal creation and
/// supervisor bootstrap paths below. The guard composes with repository hooks
/// by dispatching every standard hook name to its previously effective hooks
/// directory after its own pre-commit/pre-merge/pre-push check succeeds.
pub fn install_primary_worktree_guard(repo_path: impl AsRef<Path>) -> Result<WorktreeGuardReport> {
    install_worktree_guard(repo_path.as_ref(), WorktreeGuardMode::Primary)
}

/// Verifies the explicit primary-worktree guard installation without changing
/// repository or hook state.
pub fn verify_primary_worktree_guard(repo_path: impl AsRef<Path>) -> Result<WorktreeGuardReport> {
    let repo = crate::git_repository::open(repo_path.as_ref())
        .with_context(|| format!("failed to open repository {}", repo_path.as_ref().display()))?;
    verify_worktree_guard(&repo, &WorktreeGuardMode::Primary)
}

/// Removes only MACO-owned primary guard state and restores the previously
/// effective hook resolution by deleting the exact conditional include.
pub fn uninstall_primary_worktree_guard(
    repo_path: impl AsRef<Path>,
) -> Result<WorktreeGuardReport> {
    uninstall_worktree_guard(repo_path.as_ref(), WorktreeGuardMode::Primary)
}

/// Reinstalls the guard for a registered managed lane during supervisor
/// bootstrap. This upgrades older lanes idempotently without ever opting the
/// primary checkout into the guard.
#[cfg(unix)]
pub(crate) fn ensure_registered_managed_worktree_guard(
    worktree_path: &Path,
) -> Result<WorktreeGuardReport> {
    let selected = fs::canonicalize(worktree_path).with_context(|| {
        format!(
            "failed to resolve managed worktree {} for guard installation",
            worktree_path.display()
        )
    })?;
    let linked_repository = crate::git_repository::open(&selected).with_context(|| {
        format!(
            "failed to open managed worktree {} for guard installation",
            selected.display()
        )
    })?;
    let linked_workdir = linked_repository
        .workdir()
        .context("managed worktree guard bootstrap requires a non-bare repository")?;
    let linked_workdir = fs::canonicalize(linked_workdir)
        .context("failed to resolve managed worktree repository root")?;
    if linked_workdir != selected {
        bail!("managed worktree guard bootstrap path is not the linked repository root");
    }
    let linked_git_dir = fs::canonicalize(linked_repository.path())
        .context("failed to resolve managed worktree Git directory")?;
    let common_dir = fs::canonicalize(linked_repository.commondir())
        .context("failed to resolve managed worktree Git common directory")?;
    if linked_git_dir == common_dir {
        bail!("managed worktree guard bootstrap requires a linked worktree");
    }
    let primary_candidate = common_dir
        .parent()
        .context("managed worktree Git common directory has no primary worktree parent")?;
    let primary_workdir = fs::canonicalize(primary_candidate)
        .context("failed to resolve primary worktree for managed guard bootstrap")?;
    drop(linked_repository);

    // The authenticated registry is deliberately primary-worktree scoped.
    // Opening a manager on the linked lane would hit the mutation boundary in
    // `managed_repository_binding` before its registered identity can be
    // checked. Re-enter through the canonical primary workdir, then require an
    // exact verified record for the selected linked lane.
    let manager = WorktreeManager::new(&primary_workdir);
    let record = manager
        .list_managed_verified()?
        .into_iter()
        .find_map(|record| {
            fs::canonicalize(&record.path)
                .ok()
                .filter(|path| path == &selected)
                .map(|_| record)
        })
        .with_context(|| {
            format!(
                "managed worktree {} has no verified registry identity for guard installation",
                selected.display()
            )
        })?;
    install_worktree_guard(
        &selected,
        WorktreeGuardMode::Managed {
            expected_branch: record.branch,
        },
    )
}

#[cfg(unix)]
fn install_managed_worktree_guard(
    worktree_path: &Path,
    expected_branch: &str,
) -> Result<WorktreeGuardReport> {
    validate_branch_name(expected_branch)?;
    install_worktree_guard(
        worktree_path,
        WorktreeGuardMode::Managed {
            expected_branch: expected_branch.to_string(),
        },
    )
}

#[cfg(not(unix))]
fn install_managed_worktree_guard(_worktree_path: &Path, _expected_branch: &str) -> Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn install_worktree_guard(
    _worktree_path: &Path,
    _mode: WorktreeGuardMode,
) -> Result<WorktreeGuardReport> {
    bail!("the POSIX MACO worktree guard is unsupported on this platform")
}

#[cfg(unix)]
fn install_worktree_guard(
    worktree_path: &Path,
    mode: WorktreeGuardMode,
) -> Result<WorktreeGuardReport> {
    let repo = crate::git_repository::open(worktree_path).with_context(|| {
        format!(
            "failed to open worktree {} for guard installation",
            worktree_path.display()
        )
    })?;
    repair_owned_guard_layout_prefixes(&repo)?;
    let layout = worktree_guard_layout(&repo)?;
    require_guard_mode_matches_worktree(&layout, &mode)?;
    let include_values = guard_include_values(&layout)?;
    let (root_present, root_owned) = match fs::symlink_metadata(&layout.root) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                bail!(
                    "MACO worktree guard path is not an owned directory: {}",
                    layout.root.display()
                );
            }
            if !path_entry_exists(&layout.root.join("marker"))? {
                if !include_values.is_empty()
                    || metadata.uid() != unsafe { libc::geteuid() }
                    || metadata.permissions().mode() & 0o7777 != 0o700
                    || fs::read_dir(&layout.root)
                        .context("failed to enumerate markerless guard root")?
                        .next()
                        .is_some()
                {
                    bail!(
                        "MACO worktree guard directory exists without an ownership marker; refusing collision: {}",
                        layout.root.display()
                    );
                }
                // Atomic marker publication uses an unnamed file. A crash can
                // therefore leave only this empty private directory; retrying
                // may safely finish publication without adopting any bytes.
                (true, false)
            } else {
                // The exact marker is the ownership boundary. Never repair or
                // stamp a pre-existing markerless nonempty directory, even if
                // it contains only expected names. Interrupted installs are
                // resumable only after this marker was published completely.
                require_guard_marker(&layout)?;
                validate_guard_tree_entries(&layout, true)?;
                (true, true)
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => (false, false),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect MACO worktree guard path {}",
                    layout.root.display()
                )
            })
        }
    };
    let already_installed = root_owned && verify_worktree_guard(&repo, &mode).is_ok();

    if !root_present {
        if !include_values.is_empty() {
            bail!(
                "worktree guard include key already exists without MACO-owned state: {}",
                layout.include_key
            );
        }
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(&layout.root)
            .with_context(|| format!("failed to create guard root {}", layout.root.display()))?;
    }
    let root = open_guard_directory(&layout.root, "guard root")?;
    if !root_owned {
        create_guard_marker(&root)?;
    }
    verify_guard_directory_binding(&layout.root, &root, "guard root")?;

    validate_guard_tree_entries(&layout, true)?;
    let previous_hooks =
        existing_or_effective_prior_hook_paths(&repo, &layout, &include_values, &root)?;
    ensure_guard_state(&layout, &mode, &previous_hooks, &root)?;

    let hooks = write_guard_dispatchers(&layout, &root, &previous_hooks)?;
    write_guard_config(&layout, &root)?;
    verify_guard_directory_binding(&layout.root, &root, "guard root")?;
    verify_guard_directory_binding(&layout.hooks, &hooks, "guard hooks")?;
    root.sync_all()
        .context("failed to sync complete guard state before include activation")?;
    ensure_guard_include(&layout)?;
    // Config activation is the final mutation. Refuse success if either owned
    // directory pathname was exchanged while the include was being updated.
    verify_guard_directory_binding(&layout.root, &root, "guard root")?;
    verify_guard_directory_binding(&layout.hooks, &hooks, "guard hooks")?;
    let mut report = verify_worktree_guard(&repo, &mode)?;
    report.status = if already_installed {
        WorktreeGuardStatus::AlreadyInstalled
    } else {
        WorktreeGuardStatus::Installed
    };
    Ok(report)
}

#[cfg(not(unix))]
fn uninstall_worktree_guard(
    _worktree_path: &Path,
    _mode: WorktreeGuardMode,
) -> Result<WorktreeGuardReport> {
    bail!("the POSIX MACO worktree guard is unsupported on this platform")
}

#[cfg(unix)]
fn uninstall_worktree_guard(
    worktree_path: &Path,
    mode: WorktreeGuardMode,
) -> Result<WorktreeGuardReport> {
    let repo = crate::git_repository::open(worktree_path).with_context(|| {
        format!(
            "failed to open worktree {} for guard removal",
            worktree_path.display()
        )
    })?;
    let layout = worktree_guard_layout(&repo)?;
    uninstall_worktree_guard_with_layout(layout, mode)
}

#[cfg(unix)]
fn uninstall_bound_managed_worktree_guard(
    repo: &Repository,
    binding: &ManagedWorktreeBinding,
    metadata_dir: &Path,
) -> Result<WorktreeGuardReport> {
    if identity_for_path(metadata_dir)? != binding.metadata_dir_identity {
        bail!("bound managed Git directory changed before guard removal");
    }
    let git_dir = fs::canonicalize(metadata_dir)
        .context("failed to resolve bound managed Git directory for guard removal")?;
    let common_dir = fs::canonicalize(repo.commondir())
        .context("failed to resolve common Git directory for guard removal")?;
    let layout = worktree_guard_layout_from_bound_parts(
        repo,
        binding.path.clone(),
        git_dir,
        binding.metadata_dir.clone(),
        common_dir,
    )?;
    uninstall_worktree_guard_with_layout(
        layout,
        WorktreeGuardMode::Managed {
            expected_branch: binding.branch.clone(),
        },
    )
}

#[cfg(unix)]
fn uninstall_worktree_guard_with_layout(
    layout: WorktreeGuardLayout,
    mode: WorktreeGuardMode,
) -> Result<WorktreeGuardReport> {
    require_guard_mode_matches_worktree(&layout, &mode)?;
    match fs::symlink_metadata(&layout.root) {
        Err(error) if error.kind() == ErrorKind::NotFound => {
            if !guard_include_values(&layout)?.is_empty() {
                bail!(
                    "worktree guard include remains without MACO-owned state: {}",
                    layout.include_key
                );
            }
            return Ok(worktree_guard_report(
                &layout,
                &mode,
                WorktreeGuardStatus::AlreadyAbsent,
            ));
        }
        Ok(metadata) if !metadata.file_type().is_symlink() && metadata.is_dir() => {}
        Ok(_) => bail!(
            "MACO worktree guard path is not an owned directory: {}",
            layout.root.display()
        ),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect guard root {}", layout.root.display()))
        }
    }
    if path_entry_exists(&layout.root.join("marker"))? {
        require_guard_marker(&layout)?;
        recover_pending_guard_config_transaction(&layout)?;
    }
    let include_values = guard_include_values(&layout)?;
    if path_entry_exists(&layout.root.join("marker"))? {
        require_guard_marker(&layout)?;
    } else if include_values.is_empty()
        && fs::read_dir(&layout.root)
            .context("failed to enumerate interrupted guard removal")?
            .next()
            .is_none()
    {
        fs::remove_dir(&layout.root).context("failed to remove empty guard root")?;
        return Ok(worktree_guard_report(
            &layout,
            &mode,
            WorktreeGuardStatus::Removed,
        ));
    } else {
        bail!("MACO worktree guard ownership marker is missing or changed");
    }
    let root = open_guard_directory(&layout.root, "guard root")?;
    let hooks = match open_guard_directory_at(&root, "hooks", "guard hooks directory") {
        Ok(hooks) => Some(hooks),
        Err(error)
            if include_values.is_empty()
                && error
                    .root_cause()
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == ErrorKind::NotFound) =>
        {
            None
        }
        Err(error) => return Err(error),
    };
    verify_guard_directory_binding(&layout.root, &root, "guard root")?;
    if let Some(hooks) = &hooks {
        verify_guard_directory_binding(&layout.hooks, hooks, "guard hooks")?;
    }
    match include_values.as_slice() {
        [value] if value == &layout.config_text => {
            verify_owned_worktree_guard(&layout, &mode)?;
            migrate_post_install_human_authorship_v3(&layout, &root)?;
            remove_guard_include(&layout)?;
            verify_guard_directory_binding(&layout.root, &root, "guard root")?;
            if let Some(hooks) = &hooks {
                verify_guard_directory_binding(&layout.hooks, hooks, "guard hooks")?;
            }
        }
        [] => {
            // The include is removed before known owned files. This is the
            // only accepted partial-uninstall shape and makes retries safe.
            validate_guard_tree_entries(&layout, true)?;
        }
        _ => bail!("refusing to remove changed or duplicated guard conditional include"),
    }
    remove_guard_owned_tree(&layout, &root, hooks.as_ref())?;
    Ok(worktree_guard_report(
        &layout,
        &mode,
        WorktreeGuardStatus::Removed,
    ))
}

#[cfg(unix)]
fn migrate_post_install_human_authorship_v3(
    layout: &WorktreeGuardLayout,
    root: &File,
) -> Result<()> {
    let previous_hooks = read_guard_path_line(&layout.root.join("previous-hooks-path"))?;
    for hook_name in ["commit-msg", "pre-push"] {
        let wrapper = human_authorship_v3_wrapper(hook_name)
            .context("missing human-authorship wrapper definition")?;
        let guard_hook = layout.hooks.join(hook_name);
        if fs::read(&guard_hook)
            .with_context(|| format!("failed to read guard hook {hook_name}"))?
            != wrapper
        {
            continue;
        }
        migrate_one_human_authorship_v3(root, &previous_hooks, hook_name, wrapper)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn migrate_one_human_authorship_v3(
    root: &File,
    previous_hooks: &Path,
    hook_name: &str,
    wrapper: &[u8],
) -> Result<()> {
    let previous = open_or_create_prior_hooks_directory(previous_hooks)?;
    verify_guard_directory_binding(previous_hooks, &previous, "prior hooks directory")?;
    let backup_name = format!("{hook_name}.human-authorship-previous");
    let phase_name = format!("human-v3-migration-{hook_name}");
    let original_name = format!("human-v3-original-{hook_name}");

    let phase_exists = guard_file_exists_at(root, &phase_name)?;
    let original_exists = guard_file_exists_at(root, &original_name)?;
    if !phase_exists {
        if guard_file_exists_at(&previous, &backup_name)? {
            bail!("human-authorship migration backup collision: {backup_name}");
        }
        if guard_file_exists_at(&previous, hook_name)? {
            let original =
                read_guard_regular_file_at(&previous, hook_name, PRIOR_HOOK_MARKER_SCAN_LIMIT)?;
            if original == wrapper {
                bail!("ambiguous pre-existing human-authorship wrapper at prior hook path");
            }
            let mode = guard_regular_mode_at(&previous, hook_name)?;
            if original_exists {
                if read_guard_regular_file_at(root, &original_name, PRIOR_HOOK_MARKER_SCAN_LIMIT)?
                    != original
                {
                    bail!("human-authorship migration journal does not match prior hook");
                }
            } else {
                publish_exact_guard_file_at(root, &original_name, &original, 0o600)?;
            }
            ensure_guard_line_at(root, &phase_name, &format!("present:{mode}"))?;
        } else {
            if original_exists {
                bail!("orphaned human-authorship original-hook journal");
            }
            ensure_guard_line_at(root, &phase_name, "absent")?;
        }
    }

    let phase = String::from_utf8(read_guard_line_at(root, &phase_name)?)
        .context("human-authorship migration phase is not UTF-8")?;
    match phase.as_str() {
        "absent" => {
            if guard_file_exists_at(root, &original_name)?
                || guard_file_exists_at(&previous, &backup_name)?
            {
                bail!("absent human-authorship migration has unexpected backup state");
            }
            if !guard_file_exists_at(&previous, hook_name)? {
                publish_exact_guard_file_at(&previous, hook_name, wrapper, 0o755)?;
            }
        }
        value if value.starts_with("present:") => {
            let expected_mode = value["present:".len()..]
                .parse::<u32>()
                .context("invalid human-authorship original hook mode")?;
            let original =
                read_guard_regular_file_at(root, &original_name, PRIOR_HOOK_MARKER_SCAN_LIMIT)?;
            let target_exists = guard_file_exists_at(&previous, hook_name)?;
            let backup_exists = guard_file_exists_at(&previous, &backup_name)?;
            match (target_exists, backup_exists) {
                (true, false) => {
                    if read_guard_regular_file_at(
                        &previous,
                        hook_name,
                        PRIOR_HOOK_MARKER_SCAN_LIMIT,
                    )? != original
                        || guard_regular_mode_at(&previous, hook_name)? != expected_mode
                    {
                        bail!("prior hook changed before human-authorship migration");
                    }
                    rename_guard_entry_noreplace_at(&previous, hook_name, &backup_name)?;
                    previous
                        .sync_all()
                        .context("failed to sync preserved prior hook")?;
                }
                (false, true) => {}
                (true, true)
                    if read_guard_regular_file_at(
                        &previous,
                        hook_name,
                        PRIOR_HOOK_MARKER_SCAN_LIMIT,
                    )? == wrapper => {}
                _ => bail!("ambiguous human-authorship migration target/backup state"),
            }
            if read_guard_regular_file_at(&previous, &backup_name, PRIOR_HOOK_MARKER_SCAN_LIMIT)?
                != original
                || guard_regular_mode_at(&previous, &backup_name)? != expected_mode
            {
                bail!("preserved prior hook changed during human-authorship migration");
            }
            if !guard_file_exists_at(&previous, hook_name)? {
                publish_exact_guard_file_at(&previous, hook_name, wrapper, 0o755)?;
            }
        }
        _ => bail!("invalid human-authorship migration phase"),
    }
    if read_guard_regular_file_at(&previous, hook_name, PRIOR_HOOK_MARKER_SCAN_LIMIT)? != wrapper
        || guard_regular_mode_at(&previous, hook_name)? & 0o111 == 0
    {
        bail!("human-authorship wrapper migration did not persist exactly");
    }
    verify_guard_directory_binding(previous_hooks, &previous, "prior hooks directory")?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_or_create_prior_hooks_directory(path: &Path) -> Result<File> {
    match open_guard_directory(path, "prior hooks directory") {
        Ok(directory) => return Ok(directory),
        Err(error)
            if error
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .is_none_or(|error| error.kind() != ErrorKind::NotFound) =>
        {
            return Err(error)
        }
        Err(_) => {}
    }
    let parent_path = path
        .parent()
        .context("prior hooks directory has no parent")?;
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .context("prior hooks directory name is not UTF-8")?;
    let parent = open_guard_directory(parent_path, "prior hooks parent")?;
    let name_c = guard_component(name)?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name_c.as_ptr(), 0o700) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to create descriptor-relative prior hooks directory");
    }
    parent
        .sync_all()
        .context("failed to sync prior hooks parent")?;
    let directory = open_guard_directory_at(&parent, name, "prior hooks directory")?;
    verify_guard_directory_binding(path, &directory, "prior hooks directory")?;
    Ok(directory)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn migrate_one_human_authorship_v3(
    _root: &File,
    _previous_hooks: &Path,
    _hook_name: &str,
    _wrapper: &[u8],
) -> Result<()> {
    bail!("safe human-authorship wrapper migration requires Linux renameat2")
}

#[cfg(not(unix))]
fn verify_worktree_guard(
    _repo: &Repository,
    _mode: &WorktreeGuardMode,
) -> Result<WorktreeGuardReport> {
    bail!("the POSIX MACO worktree guard is unsupported on this platform")
}

#[cfg(unix)]
fn verify_worktree_guard(
    repo: &Repository,
    mode: &WorktreeGuardMode,
) -> Result<WorktreeGuardReport> {
    let layout = worktree_guard_layout(repo)?;
    require_guard_mode_matches_worktree(&layout, mode)?;
    verify_owned_worktree_guard(&layout, mode)?;
    verify_no_pending_guard_config_transaction(&layout)?;
    let include_values = guard_include_values(&layout)?;
    if include_values != [layout.config_text.clone()] {
        bail!("guard conditional include is missing, duplicated, or changed");
    }
    let reopened = crate::git_repository::open(&layout.worktree_path)
        .context("failed to reopen worktree while verifying guard")?;
    let effective_hooks = reopened
        .config()
        .context("failed to load effective guard configuration")?
        .get_path("core.hooksPath")
        .context("installed guard is not the effective core.hooksPath")?;
    if effective_hooks != layout.bound_hooks {
        bail!("installed guard is not the effective core.hooksPath");
    }
    Ok(worktree_guard_report(
        &layout,
        mode,
        WorktreeGuardStatus::Verified,
    ))
}

#[cfg(unix)]
fn verify_no_pending_guard_config_transaction(layout: &WorktreeGuardLayout) -> Result<()> {
    let root = open_guard_directory(&layout.root, "guard root")?;
    for name in [
        "include-config-transaction",
        "include-config-before",
        "include-config-after",
        "include-config-exchanged",
    ] {
        if guard_file_exists_at(&root, name)? {
            bail!("guard config transaction journal remains pending: {name}");
        }
    }
    let parent_path = layout
        .include_config
        .parent()
        .context("guard include configuration has no parent")?;
    let file_name = layout
        .include_config
        .file_name()
        .and_then(OsStr::to_str)
        .context("guard include configuration name is not UTF-8")?;
    let parent = open_guard_directory(parent_path, "guard include configuration parent")?;
    for name in [
        format!("{file_name}.lock"),
        format!("{file_name}.maco-worktree-guard-rollback"),
    ] {
        if guard_file_exists_at(&parent, &name)? {
            bail!("guard config transaction filesystem state remains pending: {name}");
        }
    }
    verify_guard_directory_binding(&layout.root, &root, "guard root")?;
    verify_guard_directory_binding(parent_path, &parent, "guard include configuration parent")
}

#[cfg(unix)]
fn verify_owned_worktree_guard(
    layout: &WorktreeGuardLayout,
    mode: &WorktreeGuardMode,
) -> Result<()> {
    require_guard_marker(layout)?;
    require_guard_state(layout, mode)?;
    validate_guard_tree_entries(layout, false)?;
    require_regular_guard_file(&layout.config)?;
    if fs::read(&layout.config).context("failed to read MACO worktree guard config")?
        != expected_guard_config_bytes(&layout.bound_hooks)?
    {
        bail!("guard config content changed");
    }
    let config =
        git2::Config::open(&layout.config).context("failed to open MACO worktree guard config")?;
    let configured_hooks = config
        .get_path("core.hooksPath")
        .context("guard config has no core.hooksPath")?;
    if configured_hooks != layout.bound_hooks {
        bail!("guard config points to an unexpected hooks directory");
    }
    let previous_hooks = EffectivePriorHookPaths {
        worktree_hooks: read_guard_path_line(&layout.root.join("previous-hooks-path"))?,
        git_dir_hooks: read_guard_path_line(&layout.root.join("previous-git-dir-hooks-path"))?,
        human_v3_commit_msg: read_guard_text_line(
            &layout.root.join("human-v3-chained-commit-msg"),
        )? == "true",
        human_v3_pre_push: read_guard_text_line(&layout.root.join("human-v3-chained-pre-push"))?
            == "true",
    };
    for hook_name in WORKTREE_GUARD_HOOK_NAMES {
        let expected = expected_guard_dispatcher_bytes(&previous_hooks, hook_name)?;
        verify_guard_dispatcher_path(layout, hook_name, &expected)?;
    }
    Ok(())
}

#[cfg(unix)]
fn human_authorship_v3_wrapper(hook_name: &str) -> Option<&'static [u8]> {
    match hook_name {
        "commit-msg" => Some(HUMAN_AUTHORSHIP_COMMIT_MSG_V3),
        "pre-push" => Some(HUMAN_AUTHORSHIP_PRE_PUSH_V3),
        _ => None,
    }
}

#[cfg(unix)]
fn human_authorship_backup_name(hook_name: &str) -> Option<String> {
    human_authorship_v3_wrapper(hook_name).map(|_| format!("{hook_name}.human-authorship-previous"))
}

#[cfg(unix)]
fn verify_guard_dispatcher_path(
    layout: &WorktreeGuardLayout,
    hook_name: &str,
    expected_maco: &[u8],
) -> Result<()> {
    let hook = layout.hooks.join(hook_name);
    require_regular_guard_file(&hook)?;
    let observed =
        fs::read(&hook).with_context(|| format!("failed to read guard hook {}", hook.display()))?;
    if fs::metadata(&hook)?.permissions().mode() & 0o111 == 0 {
        bail!("guard hook is not executable: {}", hook.display());
    }
    let backup = human_authorship_backup_name(hook_name).map(|name| layout.hooks.join(name));
    if observed == expected_maco {
        if let Some(backup) = &backup {
            if path_entry_exists(backup)? {
                bail!("ambiguous human-authorship backup exists beside MACO dispatcher");
            }
        }
        return Ok(());
    }
    let wrapper = human_authorship_v3_wrapper(hook_name).context("guard hook content changed")?;
    if observed != wrapper {
        bail!("guard hook content changed: {}", hook.display());
    }
    let backup = backup.context("human-authorship wrapper has no backup name")?;
    require_regular_guard_file(&backup)?;
    if fs::read(&backup).context("failed to read human-authorship MACO backup")? != expected_maco
        || fs::metadata(&backup)?.permissions().mode() & 0o111 == 0
    {
        bail!("human-authorship wrapper does not preserve the exact MACO dispatcher");
    }
    Ok(())
}

#[cfg(unix)]
fn worktree_guard_layout(repo: &Repository) -> Result<WorktreeGuardLayout> {
    let worktree_path = repo
        .workdir()
        .context("worktree guard requires a non-bare repository")?;
    let worktree_path = fs::canonicalize(worktree_path)
        .context("failed to resolve worktree path for guard installation")?;
    let git_dir = fs::canonicalize(repo.path())
        .context("failed to resolve Git directory for guard installation")?;
    let common_dir = fs::canonicalize(repo.commondir())
        .context("failed to resolve Git common directory for guard installation")?;
    worktree_guard_layout_from_parts(repo, worktree_path, git_dir, common_dir)
}

#[cfg(unix)]
fn repair_owned_guard_layout_prefixes(repo: &Repository) -> Result<()> {
    let git_dir = fs::canonicalize(repo.path())
        .context("failed to resolve Git directory for guard state recovery")?;
    let common_dir = fs::canonicalize(repo.commondir())
        .context("failed to resolve common Git directory for guard state recovery")?;
    let root_path = git_dir.join(WORKTREE_GUARD_DIRECTORY);
    if !path_entry_exists(&root_path.join("marker"))? {
        return Ok(());
    }
    let root = open_guard_directory(&root_path, "guard root")?;
    if read_guard_regular_file_at(&root, "marker", WORKTREE_GUARD_MARKER.len() as u64)?
        != WORKTREE_GUARD_MARKER.as_bytes()
    {
        bail!("MACO worktree guard ownership marker is missing or changed");
    }
    verify_guard_directory_binding(&root_path, &root, "guard root")?;
    let current_level = guard_include_level(repo)?;
    let selected_level = if guard_file_exists_at(&root, "include-level")? {
        match repair_guard_choice_at(
            &root,
            "include-level",
            &["local", "worktree"],
            current_level.label(),
        )?
        .as_str()
        {
            "local" => WorktreeGuardIncludeLevel::Local,
            "worktree" => WorktreeGuardIncludeLevel::Worktree,
            _ => bail!("repaired guard include level is invalid"),
        }
    } else {
        current_level
    };
    if guard_file_exists_at(&root, "include-config-created")? {
        let include_config = match selected_level {
            WorktreeGuardIncludeLevel::Local => common_dir.join("config"),
            WorktreeGuardIncludeLevel::Worktree => git_dir.join("config.worktree"),
        };
        let expected = if path_entry_exists(&include_config)? {
            "false"
        } else {
            "true"
        };
        repair_guard_choice_at(
            &root,
            "include-config-created",
            &["true", "false"],
            expected,
        )?;
    }
    root.sync_all()
        .context("failed to sync repaired guard layout state")
}

#[cfg(unix)]
fn repair_guard_choice_at(
    root: &File,
    name: &str,
    choices: &[&str],
    fallback: &str,
) -> Result<String> {
    let observed = read_guard_regular_file_at(root, name, 64)?;
    for choice in choices {
        let mut exact = choice.as_bytes().to_vec();
        exact.push(b'\n');
        if observed == exact {
            return Ok((*choice).to_string());
        }
    }
    let candidates = choices
        .iter()
        .filter(|choice| {
            let mut exact = choice.as_bytes().to_vec();
            exact.push(b'\n');
            exact.starts_with(&observed)
        })
        .copied()
        .collect::<Vec<_>>();
    let selected = match candidates.as_slice() {
        [selected] => *selected,
        candidates if candidates.contains(&fallback) => fallback,
        _ => bail!("guard layout state is changed rather than an interrupted prefix: {name}"),
    };
    let mut expected = selected.as_bytes().to_vec();
    expected.push(b'\n');
    ensure_guard_file_bytes_at(root, name, &expected)?;
    Ok(selected.to_string())
}

#[cfg(unix)]
fn worktree_guard_layout_from_parts(
    repo: &Repository,
    worktree_path: PathBuf,
    git_dir: PathBuf,
    common_dir: PathBuf,
) -> Result<WorktreeGuardLayout> {
    worktree_guard_layout_from_bound_parts(
        repo,
        worktree_path,
        git_dir.clone(),
        git_dir,
        common_dir,
    )
}

#[cfg(unix)]
fn worktree_guard_layout_from_bound_parts(
    repo: &Repository,
    worktree_path: PathBuf,
    git_dir: PathBuf,
    bound_git_dir: PathBuf,
    common_dir: PathBuf,
) -> Result<WorktreeGuardLayout> {
    let root = git_dir.join(WORKTREE_GUARD_DIRECTORY);
    let hooks = root.join("hooks");
    let bound_root = bound_git_dir.join(WORKTREE_GUARD_DIRECTORY);
    let bound_hooks = bound_root.join("hooks");
    let config = root.join("config");
    let bound_config = bound_root.join("config");
    let current_include_level = guard_include_level(repo)?;
    let include_level = match fs::symlink_metadata(root.join("include-level")) {
        Ok(metadata) if !metadata.file_type().is_symlink() && metadata.is_file() => {
            match read_guard_text_line(&root.join("include-level"))?.as_str() {
                "local" => WorktreeGuardIncludeLevel::Local,
                "worktree" => WorktreeGuardIncludeLevel::Worktree,
                _ => bail!("worktree guard include level is invalid"),
            }
        }
        Ok(_) => bail!("worktree guard include-level state is not a regular file"),
        Err(error) if error.kind() == ErrorKind::NotFound => current_include_level,
        Err(error) => return Err(error).context("failed to inspect guard include-level state"),
    };
    let include_config = match include_level {
        WorktreeGuardIncludeLevel::Local => common_dir.join("config"),
        WorktreeGuardIncludeLevel::Worktree => git_dir.join("config.worktree"),
    };
    let observed_include_config_created = match fs::symlink_metadata(&include_config) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                bail!(
                    "guard include configuration is not a regular file: {}",
                    include_config.display()
                );
            }
            false
        }
        Err(error) if error.kind() == ErrorKind::NotFound => true,
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect guard include configuration {}",
                    include_config.display()
                )
            })
        }
    };
    let include_config_created = match fs::symlink_metadata(root.join("include-config-created")) {
        Ok(metadata) if !metadata.file_type().is_symlink() && metadata.is_file() => {
            match read_guard_text_line(&root.join("include-config-created"))?.as_str() {
                "true" => true,
                "false" => false,
                _ => bail!("worktree guard include-config-created state is invalid"),
            }
        }
        Ok(_) => bail!("worktree guard include-config-created state is not a regular file"),
        Err(error) if error.kind() == ErrorKind::NotFound => observed_include_config_created,
        Err(error) => {
            return Err(error).context("failed to inspect guard include-config-created state")
        }
    };
    let bound_include_config = match include_level {
        WorktreeGuardIncludeLevel::Local => common_dir.join("config"),
        WorktreeGuardIncludeLevel::Worktree => bound_git_dir.join("config.worktree"),
    };
    let bound_include_base = bound_include_config
        .parent()
        .context("bound guard include configuration has no parent")?;
    let relative_config = bound_config
        .strip_prefix(bound_include_base)
        .context("guard config is not beneath its selected Git configuration level")?;
    let config_text = guard_config_path_text(relative_config, "relative guard config")?.to_string();
    let include_condition = guard_include_condition(&bound_git_dir, &common_dir)?;
    let include_key = format!("includeIf.gitdir:{include_condition}.path");
    Ok(WorktreeGuardLayout {
        worktree_path,
        git_dir,
        bound_git_dir,
        common_dir,
        root,
        hooks,
        bound_hooks,
        config,
        include_level,
        include_config,
        include_config_created,
        include_key,
        config_text,
    })
}

#[cfg(unix)]
fn guard_include_level(repo: &Repository) -> Result<WorktreeGuardIncludeLevel> {
    let config = repo
        .config()
        .context("failed to load repository configuration for guard include selection")?;
    let local = config
        .open_level(ConfigLevel::Local)
        .context("failed to open local repository configuration")?;
    match local.get_bool("extensions.worktreeConfig") {
        Ok(true) => Ok(WorktreeGuardIncludeLevel::Worktree),
        Ok(false) => Ok(WorktreeGuardIncludeLevel::Local),
        Err(error) if error.code() == ErrorCode::NotFound => Ok(WorktreeGuardIncludeLevel::Local),
        Err(error) => Err(error).context("failed to inspect extensions.worktreeConfig"),
    }
}

#[cfg(unix)]
fn guard_include_condition(git_dir: &Path, common_dir: &Path) -> Result<String> {
    if let Some(text) = git_dir.to_str() {
        if !text.contains(['\n', '\r']) {
            return Ok(text.to_string());
        }
    }
    let suffix = if git_dir == common_dir {
        git_dir
            .file_name()
            .context("non-UTF-8 primary Git directory has no final component")?
            .to_str()
            .context("non-UTF-8 primary Git directory has no UTF-8 final component")?
            .to_string()
    } else {
        git_dir
            .strip_prefix(common_dir)
            .context("linked Git directory is not beneath its common directory")?
            .to_str()
            .context("linked Git metadata suffix is not valid UTF-8")?
            .to_string()
    };
    if suffix.contains(['\n', '\r']) {
        bail!("Git-directory include suffix contains an unsupported line break");
    }
    Ok(format!("**/{suffix}"))
}

#[cfg(unix)]
fn guard_config_path_text<'a>(path: &'a Path, label: &str) -> Result<&'a str> {
    let text = path
        .to_str()
        .with_context(|| format!("{label} is not valid UTF-8: {}", path.display()))?;
    if text.contains(['\n', '\r']) {
        bail!("{label} contains an unsupported line break");
    }
    Ok(text)
}

#[cfg(unix)]
fn require_guard_mode_matches_worktree(
    layout: &WorktreeGuardLayout,
    mode: &WorktreeGuardMode,
) -> Result<()> {
    let is_primary = layout.bound_git_dir == layout.common_dir;
    match (mode, is_primary) {
        (WorktreeGuardMode::Primary, true) | (WorktreeGuardMode::Managed { .. }, false) => Ok(()),
        (WorktreeGuardMode::Primary, false) => {
            bail!("primary guard command requires the repository's primary worktree")
        }
        (WorktreeGuardMode::Managed { .. }, true) => {
            bail!("managed guard installation refuses the primary worktree")
        }
    }
}

#[cfg(unix)]
fn effective_hook_paths_before_guard(
    repo: &Repository,
    layout: &WorktreeGuardLayout,
) -> Result<EffectivePriorHookPaths> {
    let configured = match repo
        .config()
        .context("failed to load repository hook configuration")?
        .get_path("core.hooksPath")
    {
        Ok(path) => Some(path),
        Err(error) if error.code() == ErrorCode::NotFound => None,
        Err(error) => return Err(error).context("failed to read existing core.hooksPath"),
    };
    let paths = match configured {
        Some(configured) if configured.is_absolute() => EffectivePriorHookPaths {
            worktree_hooks: configured.clone(),
            git_dir_hooks: configured,
            human_v3_commit_msg: false,
            human_v3_pre_push: false,
        },
        Some(configured) => EffectivePriorHookPaths {
            worktree_hooks: layout.worktree_path.join(&configured),
            git_dir_hooks: layout.bound_git_dir.join(configured),
            human_v3_commit_msg: false,
            human_v3_pre_push: false,
        },
        None => {
            let default_hooks = layout.common_dir.join("hooks");
            EffectivePriorHookPaths {
                worktree_hooks: default_hooks.clone(),
                git_dir_hooks: default_hooks,
                human_v3_commit_msg: false,
                human_v3_pre_push: false,
            }
        }
    };
    for resolved in [&paths.worktree_hooks, &paths.git_dir_hooks] {
        if resolved.as_os_str().as_bytes().contains(&b'\n')
            || resolved.as_os_str().as_bytes().contains(&b'\r')
        {
            bail!("existing hooks path contains an unsupported line break");
        }
        if resolved == &layout.bound_hooks {
            bail!("existing hooks path already points at unowned MACO guard state");
        }
    }
    Ok(EffectivePriorHookPaths {
        human_v3_commit_msg: prior_hook_contains_human_authorship_v3_marker(
            &paths.worktree_hooks.join("commit-msg"),
        )?,
        human_v3_pre_push: prior_hook_contains_human_authorship_v3_marker(
            &paths.worktree_hooks.join("pre-push"),
        )?,
        ..paths
    })
}

#[cfg(unix)]
fn ensure_guard_state(
    layout: &WorktreeGuardLayout,
    mode: &WorktreeGuardMode,
    previous_hooks: &EffectivePriorHookPaths,
    root: &File,
) -> Result<()> {
    if read_guard_regular_file_at(root, "marker", WORKTREE_GUARD_MARKER.len() as u64)?
        != WORKTREE_GUARD_MARKER.as_bytes()
    {
        bail!("MACO worktree guard ownership marker is missing or changed");
    }
    ensure_guard_line_at(root, "mode", mode.label())?;
    ensure_guard_line_at(
        root,
        "expected-branch",
        mode.expected_branch().unwrap_or_default(),
    )?;
    ensure_guard_path_line_at(root, "git-dir", &layout.bound_git_dir)?;
    ensure_guard_path_line_at(root, "previous-hooks-path", &previous_hooks.worktree_hooks)?;
    ensure_guard_path_line_at(
        root,
        "previous-git-dir-hooks-path",
        &previous_hooks.git_dir_hooks,
    )?;
    ensure_guard_line_at(
        root,
        "human-v3-chained-commit-msg",
        if previous_hooks.human_v3_commit_msg {
            "true"
        } else {
            "false"
        },
    )?;
    ensure_guard_line_at(
        root,
        "human-v3-chained-pre-push",
        if previous_hooks.human_v3_pre_push {
            "true"
        } else {
            "false"
        },
    )?;
    ensure_guard_path_line_at(root, "common-dir", &layout.common_dir)?;
    ensure_guard_line_at(root, "include-level", layout.include_level.label())?;
    ensure_guard_line_at(
        root,
        "include-config-created",
        if layout.include_config_created {
            "true"
        } else {
            "false"
        },
    )
}

#[cfg(target_os = "linux")]
fn create_guard_marker(root: &File) -> Result<()> {
    let dot = CString::new(".").context("invalid guard root name")?;
    let marker = CString::new("marker").context("invalid guard marker name")?;
    let temporary = unsafe {
        libc::openat(
            root.as_raw_fd(),
            dot.as_ptr(),
            libc::O_WRONLY | libc::O_TMPFILE | libc::O_CLOEXEC,
            0o600,
        )
    };
    if temporary < 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to create unnamed guard ownership marker");
    }
    let mut temporary = unsafe { File::from_raw_fd(temporary) };
    std::io::Write::write_all(&mut temporary, WORKTREE_GUARD_MARKER.as_bytes())
        .context("failed to write unnamed guard ownership marker")?;
    temporary
        .sync_all()
        .context("failed to sync guard ownership marker")?;
    let empty = CString::new("").context("invalid empty marker publication path")?;
    if unsafe {
        libc::linkat(
            temporary.as_raw_fd(),
            empty.as_ptr(),
            root.as_raw_fd(),
            marker.as_ptr(),
            libc::AT_EMPTY_PATH,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error())
            .context("failed atomic no-replace guard marker publication");
    }
    root.sync_all()
        .context("failed to sync guard root after marker publication")
}

#[cfg(all(unix, not(target_os = "linux")))]
fn create_guard_marker(_root: &File) -> Result<()> {
    bail!("atomic guard ownership marker publication requires Linux O_TMPFILE/linkat")
}

#[cfg(unix)]
fn ensure_guard_line_at(directory: &File, name: &str, value: &str) -> Result<()> {
    if value.contains(['\n', '\r']) {
        bail!("guard state value contains an unsupported line break");
    }
    let mut bytes = value.as_bytes().to_vec();
    bytes.push(b'\n');
    ensure_guard_file_bytes_at(directory, name, &bytes).map(|_| ())
}

#[cfg(unix)]
fn ensure_guard_path_line_at(directory: &File, name: &str, value: &Path) -> Result<()> {
    let value = value.as_os_str().as_bytes();
    if value.contains(&b'\n') || value.contains(&b'\r') {
        bail!("guard state path contains an unsupported line break");
    }
    let mut bytes = value.to_vec();
    bytes.push(b'\n');
    ensure_guard_file_bytes_at(directory, name, &bytes).map(|_| ())
}

#[cfg(unix)]
fn ensure_guard_file_bytes_at(directory: &File, name: &str, expected: &[u8]) -> Result<File> {
    let name_c = guard_component(name)?;
    let created = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name_c.as_ptr(),
            libc::O_RDWR
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK,
            0o600,
        )
    };
    if created >= 0 {
        let mut file = unsafe { File::from_raw_fd(created) };
        std::io::Write::write_all(&mut file, expected)
            .with_context(|| format!("failed to write guard state {name}"))?;
        file.sync_all()
            .with_context(|| format!("failed to sync guard state {name}"))?;
        return Ok(file);
    }
    let create_error = std::io::Error::last_os_error();
    if create_error.kind() != ErrorKind::AlreadyExists {
        return Err(create_error).with_context(|| format!("failed to create guard state {name}"));
    }
    let opened = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name_c.as_ptr(),
            libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if opened < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to open existing guard state {name}"));
    }
    let mut file = unsafe { File::from_raw_fd(opened) };
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect existing guard state {name}"))?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.uid() != unsafe { libc::geteuid() }
    {
        bail!("guard state is not a private single-link regular file: {name}");
    }
    let mut observed = Vec::new();
    (&file)
        .take(
            u64::try_from(expected.len())
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut observed)
        .with_context(|| format!("failed to read guard state {name}"))?;
    if observed == expected {
        return Ok(file);
    }
    if !expected.starts_with(&observed) {
        bail!("refusing to overwrite changed guard state {name}");
    }
    // A strict prefix is repairable only inside an exact marker-owned root.
    // The marker itself is never sent through this repair path.
    file.seek(SeekFrom::Start(0))
        .with_context(|| format!("failed to seek interrupted guard state {name}"))?;
    file.set_len(0)
        .with_context(|| format!("failed to reset interrupted guard state {name}"))?;
    std::io::Write::write_all(&mut file, expected)
        .with_context(|| format!("failed to repair interrupted guard state {name}"))?;
    file.sync_all()
        .with_context(|| format!("failed to sync repaired guard state {name}"))?;
    Ok(file)
}

#[cfg(unix)]
fn existing_or_effective_prior_hook_paths(
    repo: &Repository,
    layout: &WorktreeGuardLayout,
    include_values: &[String],
    root: &File,
) -> Result<EffectivePriorHookPaths> {
    let worktree_exists = guard_file_exists_at(root, "previous-hooks-path")?;
    let git_dir_exists = guard_file_exists_at(root, "previous-git-dir-hooks-path")?;
    match (worktree_exists, git_dir_exists) {
        (true, true) => {
            let worktree_hooks = read_guard_path_line_at(root, "previous-hooks-path")?;
            let commit_state = guard_file_exists_at(root, "human-v3-chained-commit-msg")?;
            let push_state = guard_file_exists_at(root, "human-v3-chained-pre-push")?;
            let (human_v3_commit_msg, human_v3_pre_push) = match (commit_state, push_state) {
                (true, true) => (
                    read_guard_bool_at(root, "human-v3-chained-commit-msg")?,
                    read_guard_bool_at(root, "human-v3-chained-pre-push")?,
                ),
                (false, false) if include_values.is_empty() => (
                    prior_hook_contains_human_authorship_v3_marker(
                        &worktree_hooks.join("commit-msg"),
                    )?,
                    prior_hook_contains_human_authorship_v3_marker(
                        &worktree_hooks.join("pre-push"),
                    )?,
                ),
                _ => bail!("guard human-authorship composition state is incomplete"),
            };
            Ok(EffectivePriorHookPaths {
                worktree_hooks,
                git_dir_hooks: read_guard_path_line_at(root, "previous-git-dir-hooks-path")?,
                human_v3_commit_msg,
                human_v3_pre_push,
            })
        }
        (false, false) if include_values.is_empty() => {
            effective_hook_paths_before_guard(repo, layout)
        }
        (false, false) => {
            bail!("active guard include has no persisted prior hook-path state")
        }
        _ => bail!("guard prior hook-path state is incomplete"),
    }
}

#[cfg(unix)]
fn read_guard_bool_at(directory: &File, name: &str) -> Result<bool> {
    match read_guard_line_at(directory, name)?.as_slice() {
        b"true" => Ok(true),
        b"false" => Ok(false),
        _ => bail!("guard boolean state is invalid: {name}"),
    }
}

#[cfg(unix)]
fn guard_component(name: &str) -> Result<CString> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        bail!("invalid guard-tree component: {name}");
    }
    CString::new(name.as_bytes()).context("guard-tree component contains NUL")
}

#[cfg(unix)]
fn open_guard_directory(path: &Path, label: &str) -> Result<File> {
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    options
        .open(path)
        .with_context(|| format!("failed to open {label} without following links"))
}

#[cfg(unix)]
fn open_guard_directory_at(directory: &File, name: &str, label: &str) -> Result<File> {
    let name = guard_component(name)?;
    let opened = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK,
        )
    };
    if opened < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to open {label} descriptor-relative"));
    }
    Ok(unsafe { File::from_raw_fd(opened) })
}

#[cfg(unix)]
fn verify_guard_directory_binding(path: &Path, held: &File, label: &str) -> Result<()> {
    let held = held
        .metadata()
        .with_context(|| format!("failed to inspect held {label}"))?;
    let named =
        fs::symlink_metadata(path).with_context(|| format!("failed to rebind named {label}"))?;
    if !held.is_dir()
        || !named.is_dir()
        || named.file_type().is_symlink()
        || held.dev() != named.dev()
        || held.ino() != named.ino()
    {
        bail!("{label} pathname identity changed during mutation");
    }
    Ok(())
}

#[cfg(unix)]
fn guard_file_exists_at(directory: &File, name: &str) -> Result<bool> {
    let name = guard_component(name)?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == ErrorKind::NotFound {
        Ok(false)
    } else {
        Err(error).with_context(|| format!("failed to inspect guard state {name:?}"))
    }
}

#[cfg(unix)]
fn read_guard_path_line_at(directory: &File, name: &str) -> Result<PathBuf> {
    Ok(PathBuf::from(OsString::from_vec(read_guard_line_at(
        directory, name,
    )?)))
}

#[cfg(unix)]
fn read_guard_line_at(directory: &File, name: &str) -> Result<Vec<u8>> {
    let mut bytes = read_guard_regular_file_at(directory, name, MAX_WORKTREE_GIT_TEXT_FILE_BYTES)?;
    if bytes.last() != Some(&b'\n') {
        bail!("guard state is not a single newline-terminated value: {name}");
    }
    bytes.pop();
    if bytes.contains(&b'\n') || bytes.contains(&b'\r') {
        bail!("guard state contains multiple lines: {name}");
    }
    Ok(bytes)
}

#[cfg(unix)]
fn read_guard_regular_file_at(directory: &File, name: &str, max_bytes: u64) -> Result<Vec<u8>> {
    let name_c = guard_component(name)?;
    let opened = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name_c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if opened < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to open guard state {name}"));
    }
    let mut file = unsafe { File::from_raw_fd(opened) };
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect guard state {name}"))?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > max_bytes {
        bail!("guard state is not a single-link regular file: {name}");
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read guard state {name}"))?;
    if u64::try_from(bytes.len()).map_or(true, |len| len > max_bytes) {
        bail!("guard state exceeds its bounded read limit: {name}");
    }
    Ok(bytes)
}

#[cfg(unix)]
fn guard_regular_mode_at(directory: &File, name: &str) -> Result<u32> {
    let name = guard_component(name)?;
    let opened = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if opened < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to open guard regular file");
    }
    let file = unsafe { File::from_raw_fd(opened) };
    let metadata = file
        .metadata()
        .context("failed to inspect guard regular file")?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        bail!("guard entry is not a single-link regular file");
    }
    Ok(metadata.permissions().mode())
}

#[cfg(unix)]
type GuardRegularSnapshot = (Vec<u8>, u32, (u64, u64));

#[cfg(unix)]
fn read_guard_regular_snapshot_at(
    directory: &File,
    name: &str,
    max_bytes: u64,
) -> Result<GuardRegularSnapshot> {
    let name = guard_component(name)?;
    let opened = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if opened < 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to open guard regular-file snapshot");
    }
    let mut file = unsafe { File::from_raw_fd(opened) };
    let metadata = file
        .metadata()
        .context("failed to inspect guard regular-file snapshot")?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > max_bytes {
        bail!("guard regular-file snapshot has unsafe type, links, or size");
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .context("failed to read guard regular-file snapshot")?;
    if u64::try_from(bytes.len()).map_or(true, |len| len > max_bytes) {
        bail!("guard regular-file snapshot exceeded its limit");
    }
    let after = file
        .metadata()
        .context("failed to re-inspect guard regular-file snapshot")?;
    if !same_prior_hook_metadata(&metadata, &after) {
        bail!("guard regular-file snapshot changed while being read");
    }
    Ok((
        bytes,
        metadata.permissions().mode(),
        (metadata.dev(), metadata.ino()),
    ))
}

#[cfg(target_os = "linux")]
fn publish_exact_guard_file_at(
    directory: &File,
    name: &str,
    bytes: &[u8],
    mode: u32,
) -> Result<()> {
    let temporary = create_unnamed_guard_file_at(directory, bytes, mode)?;
    link_unnamed_guard_file_at(&temporary, directory, name)
}

#[cfg(target_os = "linux")]
fn create_unnamed_guard_file_at(directory: &File, bytes: &[u8], mode: u32) -> Result<File> {
    let dot = CString::new(".").context("invalid guard publication directory")?;
    let temporary = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            dot.as_ptr(),
            libc::O_WRONLY | libc::O_TMPFILE | libc::O_CLOEXEC,
            mode,
        )
    };
    if temporary < 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to create unnamed guard publication file");
    }
    let mut temporary = unsafe { File::from_raw_fd(temporary) };
    std::io::Write::write_all(&mut temporary, bytes)
        .context("failed to write unnamed guard publication file")?;
    if unsafe { libc::fchmod(temporary.as_raw_fd(), mode as libc::mode_t) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to set guard publication mode");
    }
    temporary
        .sync_all()
        .context("failed to sync unnamed guard publication file")?;
    Ok(temporary)
}

#[cfg(target_os = "linux")]
fn link_unnamed_guard_file_at(temporary: &File, directory: &File, name: &str) -> Result<()> {
    let name = guard_component(name)?;
    let empty = CString::new("").context("invalid empty guard publication path")?;
    if unsafe {
        libc::linkat(
            temporary.as_raw_fd(),
            empty.as_ptr(),
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::AT_EMPTY_PATH,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error())
            .context("failed atomic no-replace guard file publication");
    }
    directory
        .sync_all()
        .context("failed to sync guard publication directory")
}

#[cfg(all(unix, not(target_os = "linux")))]
fn publish_exact_guard_file_at(
    _directory: &File,
    _name: &str,
    _bytes: &[u8],
    _mode: u32,
) -> Result<()> {
    bail!("atomic guard file publication requires Linux O_TMPFILE/linkat")
}

#[cfg(target_os = "linux")]
fn rename_guard_entry_noreplace_at(directory: &File, source: &str, target: &str) -> Result<()> {
    let source = guard_component(source)?;
    let target = guard_component(target)?;
    if unsafe {
        libc::renameat2(
            directory.as_raw_fd(),
            source.as_ptr(),
            directory.as_raw_fd(),
            target.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error())
            .context("atomic no-replace guard entry rename failed");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn rename_guard_entry_exchange_at(directory: &File, source: &str, target: &str) -> Result<()> {
    let source = guard_component(source)?;
    let target = guard_component(target)?;
    if unsafe {
        libc::renameat2(
            directory.as_raw_fd(),
            source.as_ptr(),
            directory.as_raw_fd(),
            target.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error()).context("atomic guard entry exchange failed");
    }
    Ok(())
}

#[cfg(unix)]
fn write_guard_dispatchers(
    layout: &WorktreeGuardLayout,
    root: &File,
    previous_hooks: &EffectivePriorHookPaths,
) -> Result<File> {
    if !guard_file_exists_at(root, "hooks")? {
        let hooks = guard_component("hooks")?;
        if unsafe { libc::mkdirat(root.as_raw_fd(), hooks.as_ptr(), 0o700) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to create descriptor-relative guard hooks directory");
        }
    }
    let hooks = open_guard_directory_at(root, "hooks", "guard hooks directory")?;

    // Preflight every existing dispatcher before creating anything so one
    // changed hook cannot leave a partial reinstall behind.
    for hook_name in WORKTREE_GUARD_HOOK_NAMES {
        let expected = expected_guard_dispatcher_bytes(previous_hooks, hook_name)?;
        guard_dispatcher_matches_expected_at(&hooks, hook_name, &expected)?;
    }

    for hook_name in WORKTREE_GUARD_HOOK_NAMES {
        let expected = expected_guard_dispatcher_bytes(previous_hooks, hook_name)?;
        if guard_dispatcher_matches_expected_at(&hooks, hook_name, &expected)? {
            continue;
        }
        let hook = ensure_guard_file_bytes_at(&hooks, hook_name, &expected)?;
        if unsafe { libc::fchmod(hook.as_raw_fd(), 0o700) } != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("failed to make guard hook executable: {hook_name}"));
        }
    }
    hooks
        .sync_all()
        .context("failed to sync guard hooks directory")?;
    verify_guard_directory_binding(&layout.hooks, &hooks, "guard hooks")?;
    Ok(hooks)
}

#[cfg(unix)]
fn guard_dispatcher_matches_expected_at(
    hooks: &File,
    hook_name: &str,
    expected: &[u8],
) -> Result<bool> {
    if !guard_file_exists_at(hooks, hook_name)? {
        return Ok(false);
    }
    let bytes = read_guard_regular_file_at(hooks, hook_name, PRIOR_HOOK_MARKER_SCAN_LIMIT)?;
    let backup = human_authorship_backup_name(hook_name);
    if bytes == expected || expected.starts_with(&bytes) {
        if let Some(backup) = backup {
            if guard_file_exists_at(hooks, &backup)? {
                bail!("ambiguous human-authorship backup exists beside MACO dispatcher");
            }
        }
        return Ok(bytes == expected);
    }
    if human_authorship_v3_wrapper(hook_name) == Some(bytes.as_slice()) {
        let backup = backup.context("human-authorship wrapper has no MACO backup name")?;
        if read_guard_regular_file_at(hooks, &backup, PRIOR_HOOK_MARKER_SCAN_LIMIT)? != expected {
            bail!("human-authorship wrapper does not preserve the exact MACO dispatcher");
        }
        return Ok(true);
    }
    bail!("refusing to overwrite changed or non-MACO guard hook {hook_name}")
}

#[cfg(unix)]
fn expected_guard_dispatcher_bytes(
    previous_hooks: &EffectivePriorHookPaths,
    hook_name: &str,
) -> Result<Vec<u8>> {
    let mut expected = WORKTREE_GUARD_ASSET.to_vec();
    let chained_human_v3 = match hook_name {
        "commit-msg" => previous_hooks.human_v3_commit_msg,
        "pre-push" => previous_hooks.human_v3_pre_push,
        _ => false,
    };
    if chained_human_v3 {
        expected.extend_from_slice(HUMAN_AUTHORSHIP_GUARD_V3_TRAILER);
    }
    Ok(expected)
}

#[cfg(unix)]
fn prior_hook_contains_human_authorship_v3_marker(hook: &Path) -> Result<bool> {
    let initial = match fs::symlink_metadata(hook) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Ok(false)
        }
        Ok(metadata) => metadata,
        Err(error) if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {
            return Ok(false)
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect prior hook {}", hook.display()))
        }
    };
    if initial.len() > PRIOR_HOOK_MARKER_SCAN_LIMIT {
        bail!(
            "prior hook exceeds the {}-byte compatibility scan limit: {}",
            PRIOR_HOOK_MARKER_SCAN_LIMIT,
            hook.display()
        );
    }

    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let file = options.open(hook).with_context(|| {
        format!(
            "failed to open prior hook without following links: {}",
            hook.display()
        )
    })?;
    let opened = file
        .metadata()
        .with_context(|| format!("failed to inspect opened prior hook {}", hook.display()))?;
    if !opened.is_file()
        || opened.len() > PRIOR_HOOK_MARKER_SCAN_LIMIT
        || !same_prior_hook_metadata(&initial, &opened)
    {
        bail!(
            "prior hook changed during compatibility scan: {}",
            hook.display()
        );
    }
    let mut bytes = Vec::new();
    (&file)
        .take(PRIOR_HOOK_MARKER_SCAN_LIMIT + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read prior hook {}", hook.display()))?;
    if u64::try_from(bytes.len()).map_or(true, |len| len > PRIOR_HOOK_MARKER_SCAN_LIMIT) {
        bail!(
            "prior hook exceeds the {}-byte compatibility scan limit: {}",
            PRIOR_HOOK_MARKER_SCAN_LIMIT,
            hook.display()
        );
    }
    let after_read = fs::symlink_metadata(hook)
        .with_context(|| format!("failed to re-inspect prior hook {}", hook.display()))?;
    let opened_after_read = file
        .metadata()
        .with_context(|| format!("failed to re-inspect opened prior hook {}", hook.display()))?;
    if !same_prior_hook_metadata(&opened, &opened_after_read)
        || !same_prior_hook_metadata(&opened, &after_read)
    {
        bail!(
            "prior hook changed during compatibility scan: {}",
            hook.display()
        );
    }
    Ok(bytes
        .windows(HUMAN_AUTHORSHIP_GUARD_V3_MARKER.len())
        .any(|window| window == HUMAN_AUTHORSHIP_GUARD_V3_MARKER))
}

#[cfg(unix)]
fn same_prior_hook_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(unix)]
fn write_guard_config(layout: &WorktreeGuardLayout, root: &File) -> Result<()> {
    let expected = expected_guard_config_bytes(&layout.bound_hooks)?;
    ensure_guard_file_bytes_at(root, "config", &expected).map(|_| ())
}

#[cfg(unix)]
fn expected_guard_config_bytes(hooks: &Path) -> Result<Vec<u8>> {
    let path = hooks.as_os_str().as_bytes();
    if path.contains(&b'\n') || path.contains(&b'\r') {
        bail!("guard hooks path contains an unsupported line break");
    }
    let mut bytes = b"[core]\n\thooksPath = \"".to_vec();
    for byte in path {
        match byte {
            b'\\' => bytes.extend_from_slice(b"\\\\"),
            b'\"' => bytes.extend_from_slice(b"\\\""),
            b'\t' => bytes.extend_from_slice(b"\\t"),
            0x08 => bytes.extend_from_slice(b"\\b"),
            _ => bytes.push(*byte),
        }
    }
    bytes.extend_from_slice(b"\"\n");
    Ok(bytes)
}

#[cfg(unix)]
fn guard_include_values(layout: &WorktreeGuardLayout) -> Result<Vec<String>> {
    let config = match git2::Config::open(&layout.include_config) {
        Ok(config) => config,
        Err(error) if error.code() == ErrorCode::NotFound && layout.include_config_created => {
            return Ok(Vec::new())
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to open guard include configuration {}",
                    layout.include_config.display()
                )
            })
        }
    };
    let mut entries = match config.multivar(&layout.include_key, None) {
        Ok(entries) => entries,
        Err(error) if error.code() == ErrorCode::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).context("failed to inspect guard conditional include"),
    };
    let mut values = Vec::new();
    while let Some(entry) = entries.next() {
        let entry = entry.context("failed to read guard conditional include")?;
        values.push(
            entry
                .value()
                .context("guard conditional include is not valid UTF-8")?
                .to_string(),
        );
    }
    Ok(values)
}

#[cfg(unix)]
fn ensure_guard_include(layout: &WorktreeGuardLayout) -> Result<()> {
    recover_pending_guard_config_transaction(layout)?;
    match guard_include_values(layout)?.as_slice() {
        [] => {
            mutate_guard_include_fragment(layout, true)?;
        }
        [value] if value == &layout.config_text => return Ok(()),
        _ => bail!("guard conditional include is duplicated or owned by another value"),
    }
    if guard_include_values(layout)? != [layout.config_text.clone()] {
        bail!("guard conditional include did not persist exactly once");
    }
    Ok(())
}

#[cfg(unix)]
fn remove_guard_include(layout: &WorktreeGuardLayout) -> Result<()> {
    recover_pending_guard_config_transaction(layout)?;
    if guard_include_values(layout)? != [layout.config_text.clone()] {
        bail!("refusing to remove changed or duplicated guard conditional include");
    }
    mutate_guard_include_fragment(layout, false)?;
    if !guard_include_values(layout)?.is_empty() {
        bail!("guard conditional include remains after removal");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn recover_pending_guard_config_transaction(layout: &WorktreeGuardLayout) -> Result<()> {
    let parent_path = layout
        .include_config
        .parent()
        .context("guard include configuration has no parent")?;
    let file_name = layout
        .include_config
        .file_name()
        .and_then(OsStr::to_str)
        .context("guard include configuration name is not UTF-8")?;
    let parent = open_guard_directory(parent_path, "guard include configuration parent")?;
    let root = open_guard_directory(&layout.root, "guard root")?;
    recover_guard_config_transaction(layout, &root, &parent, file_name).map(|_| ())
}

#[cfg(all(unix, not(target_os = "linux")))]
fn recover_pending_guard_config_transaction(_layout: &WorktreeGuardLayout) -> Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn mutate_guard_include_fragment(layout: &WorktreeGuardLayout, add: bool) -> Result<()> {
    let parent_path = layout
        .include_config
        .parent()
        .context("guard include configuration has no parent")?;
    let file_name = layout
        .include_config
        .file_name()
        .and_then(OsStr::to_str)
        .context("guard include configuration name is not UTF-8")?;
    let parent = open_guard_directory(parent_path, "guard include configuration parent")?;
    verify_guard_directory_binding(parent_path, &parent, "guard include configuration parent")?;
    let root = open_guard_directory(&layout.root, "guard root")?;
    verify_guard_directory_binding(&layout.root, &root, "guard root")?;
    let fragment = expected_guard_include_fragment(layout)?;
    if let Some(recovered_add) =
        recover_guard_config_transaction(layout, &root, &parent, file_name)?
    {
        if recovered_add == add {
            return Ok(());
        }
    }
    let exists = guard_file_exists_at(&parent, file_name)?;
    if !exists && (!add || !layout.include_config_created) {
        bail!("guard include configuration disappeared before mutation");
    }
    let (before, before_mode, before_identity) = if exists {
        let (bytes, mode, identity) =
            read_guard_regular_snapshot_at(&parent, file_name, MAX_MANAGED_REGISTRY_BYTES)?;
        (bytes, mode, Some(identity))
    } else {
        (Vec::new(), 0o600, None)
    };
    let mut after = before.clone();
    if add {
        if before
            .windows(fragment.len())
            .any(|window| window == fragment)
        {
            bail!("exact guard include fragment already exists without matching config state");
        }
        after.extend_from_slice(&fragment);
    } else {
        let positions = before
            .windows(fragment.len())
            .enumerate()
            .filter_map(|(index, window)| (window == fragment).then_some(index))
            .collect::<Vec<_>>();
        if positions.len() != 1 {
            bail!("guard include fragment is missing, duplicated, or reformatted");
        }
        let start = positions[0];
        after.drain(start..start + fragment.len());
    }
    let lock_name = format!("{file_name}.lock");
    let rollback_name = format!("{file_name}.maco-worktree-guard-rollback");
    if guard_file_exists_at(&parent, &lock_name)? {
        bail!("Git configuration lock already exists; refusing guard config mutation");
    }
    if guard_file_exists_at(&parent, &rollback_name)? {
        bail!(
            "guard configuration rollback entry already exists without a recoverable transaction"
        );
    }
    cleanup_incomplete_guard_config_journal(&root)?;
    let staged = create_unnamed_guard_file_at(&parent, &after, before_mode & 0o7777)?;
    let staged_metadata = staged
        .metadata()
        .context("failed to inspect staged guard configuration")?;
    let rollback = create_unnamed_guard_file_at(&parent, &before, before_mode & 0o7777)?;
    let rollback_metadata = rollback
        .metadata()
        .context("failed to inspect rollback guard configuration")?;
    publish_exact_guard_file_at(&root, "include-config-before", &before, 0o600)?;
    publish_exact_guard_file_at(&root, "include-config-after", &after, 0o600)?;
    let manifest = GuardConfigTransaction {
        add,
        before_present: before_identity.is_some(),
        delete_after: !add && layout.include_config_created && after.is_empty(),
        before_identity: before_identity.unwrap_or((0, 0)),
        before_mode,
        staged_identity: (staged_metadata.dev(), staged_metadata.ino()),
        staged_mode: staged_metadata.permissions().mode(),
        rollback_identity: (rollback_metadata.dev(), rollback_metadata.ino()),
        rollback_mode: rollback_metadata.permissions().mode(),
    };
    publish_exact_guard_file_at(
        &root,
        "include-config-transaction",
        &manifest.encode(),
        0o600,
    )?;
    root.sync_all()
        .context("failed to sync prepared guard config transaction")?;
    if let Err(error) = link_unnamed_guard_file_at(&rollback, &parent, &rollback_name) {
        unlink_guard_entry_if_matching_identity_at(
            &parent,
            &rollback_name,
            manifest.rollback_identity,
        )?;
        parent
            .sync_all()
            .context("failed to sync failed rollback publication cleanup")?;
        cleanup_guard_config_journal(&root)?;
        return Err(error).context("failed to publish exact guard config rollback");
    }
    if let Err(error) = link_unnamed_guard_file_at(&staged, &parent, &lock_name) {
        unlink_guard_entry_if_matching_identity_at(&parent, &lock_name, manifest.staged_identity)?;
        unlink_guard_entry_if_identity_at(
            &parent,
            &rollback_name,
            manifest.rollback_identity,
            false,
        )?;
        parent
            .sync_all()
            .context("failed to sync failed config-lock acquisition cleanup")?;
        cleanup_guard_config_journal(&root)?;
        return Err(error).context("failed to acquire exact Git configuration lock");
    }
    parent
        .sync_all()
        .context("failed to sync published Git configuration lock")?;
    complete_guard_config_transaction(layout, &root, &parent, file_name, &manifest)
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct GuardConfigTransaction {
    add: bool,
    before_present: bool,
    delete_after: bool,
    before_identity: (u64, u64),
    before_mode: u32,
    staged_identity: (u64, u64),
    staged_mode: u32,
    rollback_identity: (u64, u64),
    rollback_mode: u32,
}

#[cfg(target_os = "linux")]
impl GuardConfigTransaction {
    fn encode(&self) -> Vec<u8> {
        format!(
            "v2|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}\n",
            u8::from(self.add),
            u8::from(self.before_present),
            u8::from(self.delete_after),
            self.before_identity.0,
            self.before_identity.1,
            self.before_mode,
            self.staged_identity.0,
            self.staged_identity.1,
            self.staged_mode,
            self.rollback_identity.0,
            self.rollback_identity.1,
            self.rollback_mode,
        )
        .into_bytes()
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let text =
            std::str::from_utf8(bytes).context("guard config transaction manifest is not UTF-8")?;
        let text = text
            .strip_suffix('\n')
            .context("guard config transaction manifest is not newline terminated")?;
        let fields = text.split('|').collect::<Vec<_>>();
        if fields.len() != 13 || fields[0] != "v2" {
            bail!("guard config transaction manifest has an unknown shape");
        }
        let parse_bool = |value: &str| -> Result<bool> {
            match value {
                "0" => Ok(false),
                "1" => Ok(true),
                _ => bail!("guard config transaction boolean is invalid"),
            }
        };
        Ok(Self {
            add: parse_bool(fields[1])?,
            before_present: parse_bool(fields[2])?,
            delete_after: parse_bool(fields[3])?,
            before_identity: (
                fields[4]
                    .parse()
                    .context("invalid config preimage device")?,
                fields[5].parse().context("invalid config preimage inode")?,
            ),
            before_mode: fields[6].parse().context("invalid config preimage mode")?,
            staged_identity: (
                fields[7].parse().context("invalid staged config device")?,
                fields[8].parse().context("invalid staged config inode")?,
            ),
            staged_mode: fields[9].parse().context("invalid staged config mode")?,
            rollback_identity: (
                fields[10]
                    .parse()
                    .context("invalid rollback config device")?,
                fields[11]
                    .parse()
                    .context("invalid rollback config inode")?,
            ),
            rollback_mode: fields[12].parse().context("invalid rollback config mode")?,
        })
    }
}

#[cfg(target_os = "linux")]
fn recover_guard_config_transaction(
    layout: &WorktreeGuardLayout,
    root: &File,
    parent: &File,
    file_name: &str,
) -> Result<Option<bool>> {
    let lock_name = format!("{file_name}.lock");
    let rollback_name = format!("{file_name}.maco-worktree-guard-rollback");
    if !guard_file_exists_at(root, "include-config-transaction")? {
        if guard_file_exists_at(parent, &lock_name)?
            || guard_file_exists_at(parent, &rollback_name)?
        {
            bail!("guard config lock or rollback exists without a recoverable transaction");
        }
        cleanup_incomplete_guard_config_journal(root)?;
        return Ok(None);
    }
    let manifest = GuardConfigTransaction::decode(&read_guard_regular_file_at(
        root,
        "include-config-transaction",
        1024,
    )?)?;
    if !guard_file_exists_at(parent, &lock_name)?
        && !guard_file_exists_at(root, "include-config-exchanged")?
    {
        let target = optional_guard_snapshot_at(parent, file_name, MAX_MANAGED_REGISTRY_BYTES)?;
        let after =
            read_guard_regular_file_at(root, "include-config-after", MAX_MANAGED_REGISTRY_BYTES)?;
        let target_is_staged = snapshot_matches(
            target.as_ref(),
            &after,
            manifest.staged_mode,
            manifest.staged_identity,
        );
        // Exchange of an existing target always retains the deterministic
        // lock. With no lock/phase, that publication never occurred. For an
        // absent target, no-replace rename consumes the lock, so only the
        // exact staged inode proves a committed publication.
        let publication_never_started = manifest.before_present || !target_is_staged;
        if publication_never_started {
            if guard_file_exists_at(parent, &rollback_name)? {
                unlink_guard_entry_if_identity_at(
                    parent,
                    &rollback_name,
                    manifest.rollback_identity,
                    false,
                )?;
                parent
                    .sync_all()
                    .context("failed to sync abandoned guard config rollback")?;
            }
            cleanup_guard_config_journal(root)?;
            return Ok(None);
        }
    }
    complete_guard_config_transaction(layout, root, parent, file_name, &manifest)?;
    Ok(Some(manifest.add))
}

#[cfg(target_os = "linux")]
fn complete_guard_config_transaction(
    layout: &WorktreeGuardLayout,
    root: &File,
    parent: &File,
    file_name: &str,
    manifest: &GuardConfigTransaction,
) -> Result<()> {
    let before =
        read_guard_regular_file_at(root, "include-config-before", MAX_MANAGED_REGISTRY_BYTES)?;
    let after =
        read_guard_regular_file_at(root, "include-config-after", MAX_MANAGED_REGISTRY_BYTES)?;
    let lock_name = format!("{file_name}.lock");
    let rollback_name = format!("{file_name}.maco-worktree-guard-rollback");
    let target = optional_guard_snapshot_at(parent, file_name, MAX_MANAGED_REGISTRY_BYTES)?;
    let target_identity = guard_entry_identity_at(parent, file_name)?;
    let lock = optional_guard_snapshot_at(parent, &lock_name, MAX_MANAGED_REGISTRY_BYTES)?;
    let lock_identity = guard_entry_identity_at(parent, &lock_name)?;
    let rollback = optional_guard_snapshot_at(parent, &rollback_name, MAX_MANAGED_REGISTRY_BYTES)?;
    let rollback_identity = guard_entry_identity_at(parent, &rollback_name)?;
    let target_is_before = manifest.before_present
        && snapshot_matches(
            target.as_ref(),
            &before,
            manifest.before_mode,
            manifest.before_identity,
        );
    let target_is_staged = snapshot_matches(
        target.as_ref(),
        &after,
        manifest.staged_mode,
        manifest.staged_identity,
    );
    let target_is_rollback = snapshot_matches(
        target.as_ref(),
        &before,
        manifest.rollback_mode,
        manifest.rollback_identity,
    );
    let lock_is_staged = snapshot_matches(
        lock.as_ref(),
        &after,
        manifest.staged_mode,
        manifest.staged_identity,
    );
    let lock_is_before = manifest.before_present
        && snapshot_matches(
            lock.as_ref(),
            &before,
            manifest.before_mode,
            manifest.before_identity,
        );
    let rollback_is_before = snapshot_matches(
        rollback.as_ref(),
        &before,
        manifest.rollback_mode,
        manifest.rollback_identity,
    );
    let rollback_is_staged = snapshot_matches(
        rollback.as_ref(),
        &after,
        manifest.staged_mode,
        manifest.staged_identity,
    );

    if lock_is_staged
        && ((manifest.before_present && target_is_before)
            || (!manifest.before_present && target.is_none()))
    {
        if !rollback_is_before {
            bail!("guard config rollback changed before exchange; preserving transaction");
        }
        if manifest.before_present {
            rename_guard_entry_exchange_at(parent, &lock_name, file_name)?;
        } else {
            rename_guard_entry_noreplace_at(parent, &lock_name, file_name)?;
        }
        parent
            .sync_all()
            .context("failed to sync guard config exchange")?;
        return complete_guard_config_transaction(layout, root, parent, file_name, manifest);
    }

    if target_is_staged && manifest.before_present && lock_identity.is_some() && !lock_is_before {
        // Never exchange an unproven lock into the live configuration. Swap
        // only MACO's journaled rollback inode with the exact staged target.
        if !rollback_is_before {
            bail!("guard config mismatch has no exact owned rollback; preserving transaction");
        }
        if guard_entry_identity_at(parent, file_name)? != Some(manifest.staged_identity) {
            bail!("staged guard config target changed before rollback exchange; preserving transaction");
        }
        rename_guard_entry_exchange_at(parent, &rollback_name, file_name)?;
        let restored_target =
            optional_guard_snapshot_at(parent, file_name, MAX_MANAGED_REGISTRY_BYTES)?;
        let retired_staged =
            optional_guard_snapshot_at(parent, &rollback_name, MAX_MANAGED_REGISTRY_BYTES)?;
        let retired_identity = guard_entry_identity_at(parent, &rollback_name)?;
        if guard_entry_identity_at(parent, file_name)? == Some(manifest.rollback_identity)
            && retired_identity.is_some()
            && retired_identity != Some(manifest.staged_identity)
        {
            // The target name raced after its last exact check. Put that
            // unproven entry back at the live name and retain our rollback.
            rename_guard_entry_exchange_at(parent, &rollback_name, file_name)?;
            if guard_entry_identity_at(parent, file_name)? != retired_identity
                || guard_entry_identity_at(parent, &rollback_name)?
                    != Some(manifest.rollback_identity)
            {
                bail!("raced guard config rollback could not restore the displaced target; preserving journal");
            }
            parent
                .sync_all()
                .context("failed to sync restoration of raced config target")?;
            bail!("guard include configuration raced the rollback exchange; concurrent target restored");
        }
        if !snapshot_matches(
            restored_target.as_ref(),
            &before,
            manifest.rollback_mode,
            manifest.rollback_identity,
        ) || !snapshot_matches(
            retired_staged.as_ref(),
            &after,
            manifest.staged_mode,
            manifest.staged_identity,
        ) {
            bail!("guard config mismatch rollback could not be proven; preserving journal");
        }
        unlink_guard_entry_if_identity_at(parent, &rollback_name, manifest.staged_identity, false)?;
        parent
            .sync_all()
            .context("failed to sync config rollback")?;
        cleanup_guard_config_journal(root)?;
        bail!("guard include configuration changed before exchange; exact preimage restored without touching the foreign lock");
    }

    if manifest.before_present && target_is_rollback && rollback_is_staged {
        // Recovery after the owned rollback exchange completed but before its
        // staged inode and journal were removed. Any lock is unproven and is
        // deliberately left untouched.
        unlink_guard_entry_if_identity_at(parent, &rollback_name, manifest.staged_identity, false)?;
        parent
            .sync_all()
            .context("failed to sync recovered config rollback")?;
        cleanup_guard_config_journal(root)?;
        bail!("recovered exact guard config preimage without touching the current lock");
    }

    if manifest.before_present && target_is_rollback && rollback_identity.is_none() {
        // The exact, uniquely journaled rollback inode is already live and its
        // retired staged name is gone. This cannot be a pre-exchange target:
        // the rollback inode originated as an unnamed O_TMPFILE. Preserve any
        // current lock, durably recognize the completed rollback, and report
        // the original mutation as failed rather than promoting it to success.
        parent
            .sync_all()
            .context("failed to sync completed guard config rollback recovery")?;
        cleanup_guard_config_journal(root)?;
        bail!("recovered completed guard config rollback without touching the current lock");
    }

    if manifest.before_present && lock_is_before && !target_is_staged {
        let current = match (target.as_ref(), target_identity) {
            (Some(snapshot), Some(_)) => Some(snapshot.0.as_slice()),
            (None, None) => None,
            _ => {
                bail!("concurrent guard config target has an unsafe type; preserving transaction")
            }
        };
        let fragment = expected_guard_include_fragment(layout)?;
        let fragment_count = current.map_or(0, |bytes| {
            bytes
                .windows(fragment.len())
                .filter(|window| *window == fragment.as_slice())
                .count()
        });
        if fragment_count > 1 {
            bail!("concurrent guard config target has duplicate owned fragments; preserving transaction");
        }
        if !rollback_is_before {
            bail!("concurrent guard config recovery has no exact owned rollback; preserving transaction");
        }
        unlink_guard_entry_if_identity_at(parent, &lock_name, manifest.before_identity, false)?;
        unlink_guard_entry_if_identity_at(
            parent,
            &rollback_name,
            manifest.rollback_identity,
            false,
        )?;
        parent
            .sync_all()
            .context("failed to sync concurrent guard config recovery")?;
        cleanup_guard_config_journal(root)?;
        let desired_count = if manifest.add { 1 } else { 0 };
        if fragment_count == desired_count {
            return Ok(());
        }
        return mutate_guard_include_fragment(layout, manifest.add);
    }

    let exchanged_marker = guard_file_exists_at(root, "include-config-exchanged")?;
    if manifest.delete_after && target.is_none() && lock_is_staged && exchanged_marker {
        unlink_guard_entry_if_identity_at(parent, &lock_name, manifest.staged_identity, false)?;
        if rollback_identity.is_some() {
            unlink_guard_entry_if_identity_at(
                parent,
                &rollback_name,
                manifest.rollback_identity,
                false,
            )?;
        }
        parent
            .sync_all()
            .context("failed to sync recovered guard-created config removal")?;
        cleanup_guard_config_journal(root)?;
        return Ok(());
    }
    let committed = target_is_staged
        && ((!manifest.before_present && lock.is_none())
            || (manifest.before_present
                && (lock_is_before || (lock.is_none() && exchanged_marker))));
    let removed_after_commit =
        manifest.delete_after && target.is_none() && lock.is_none() && exchanged_marker;
    if !committed && !removed_after_commit {
        if lock_is_staged && !target_is_before && !target_is_staged {
            // Exchange never happened; return only our staged lock to MACO.
            unlink_guard_entry_if_identity_at(parent, &lock_name, manifest.staged_identity, false)?;
            if rollback_identity.is_some() {
                unlink_guard_entry_if_identity_at(
                    parent,
                    &rollback_name,
                    manifest.rollback_identity,
                    false,
                )?;
            }
            parent
                .sync_all()
                .context("failed to sync abandoned guard config publication")?;
            cleanup_guard_config_journal(root)?;
        }
        bail!("ambiguous guard config transaction state; preserving journaled entries");
    }

    if !exchanged_marker {
        publish_exact_guard_file_at(root, "include-config-exchanged", b"exchanged\n", 0o600)?;
        root.sync_all()
            .context("failed to sync exchanged config phase")?;
    }
    if lock_is_before {
        unlink_guard_entry_if_identity_at(parent, &lock_name, manifest.before_identity, false)?;
    }
    if manifest.delete_after && !removed_after_commit {
        rename_guard_entry_noreplace_at(parent, file_name, &lock_name)?;
        if guard_entry_identity_at(parent, &lock_name)? != Some(manifest.staged_identity) {
            if guard_entry_identity_at(parent, file_name)?.is_none() {
                rename_guard_entry_noreplace_at(parent, &lock_name, file_name)
                    .context("failed to restore raced config removal")?;
            }
            bail!("guard-created config changed during final removal");
        }
        unlink_guard_entry_if_identity_at(parent, &lock_name, manifest.staged_identity, false)?;
    }
    if rollback_identity.is_some() {
        unlink_guard_entry_if_identity_at(
            parent,
            &rollback_name,
            manifest.rollback_identity,
            false,
        )?;
    }
    parent
        .sync_all()
        .context("failed to sync completed guard config transaction")?;
    cleanup_guard_config_journal(root)?;
    verify_guard_directory_binding(&layout.root, root, "guard root")?;
    verify_guard_directory_binding(
        layout
            .include_config
            .parent()
            .context("guard include configuration has no parent")?,
        parent,
        "guard include configuration parent",
    )
}

#[cfg(target_os = "linux")]
fn snapshot_matches(
    snapshot: Option<&GuardRegularSnapshot>,
    bytes: &[u8],
    mode: u32,
    identity: (u64, u64),
) -> bool {
    snapshot
        .is_some_and(|snapshot| snapshot.0 == bytes && snapshot.1 == mode && snapshot.2 == identity)
}

#[cfg(target_os = "linux")]
fn optional_guard_snapshot_at(
    directory: &File,
    name: &str,
    max_bytes: u64,
) -> Result<Option<GuardRegularSnapshot>> {
    if guard_entry_identity_at(directory, name)?.is_none() {
        return Ok(None);
    }
    match read_guard_regular_snapshot_at(directory, name, max_bytes) {
        Ok(snapshot) => Ok(Some(snapshot)),
        // Preserve an unexpected entry for the transaction state machine to
        // classify by no-follow identity; never follow or delete it here.
        Err(_) => Ok(None),
    }
}

#[cfg(target_os = "linux")]
fn guard_entry_identity_at(directory: &File, name: &str) -> Result<Option<(u64, u64)>> {
    let name = guard_component(name)?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        let stat = unsafe { stat.assume_init() };
        return Ok(Some((stat.st_dev, stat.st_ino)));
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == ErrorKind::NotFound {
        Ok(None)
    } else {
        Err(error).context("failed to inspect guard transaction entry identity")
    }
}

#[cfg(target_os = "linux")]
fn unlink_guard_entry_if_identity_at(
    directory: &File,
    name: &str,
    expected_identity: (u64, u64),
    allow_missing: bool,
) -> Result<()> {
    match guard_entry_identity_at(directory, name)? {
        Some(identity) if identity == expected_identity => {
            unlink_guard_entry_at(directory, name, 0, false)
        }
        None if allow_missing => Ok(()),
        None => bail!("owned guard transaction entry disappeared before removal"),
        Some(_) => bail!("guard transaction entry identity changed; preserving it"),
    }
}

#[cfg(target_os = "linux")]
fn unlink_guard_entry_if_matching_identity_at(
    directory: &File,
    name: &str,
    expected_identity: (u64, u64),
) -> Result<bool> {
    if guard_entry_identity_at(directory, name)? != Some(expected_identity) {
        return Ok(false);
    }
    unlink_guard_entry_at(directory, name, 0, false)?;
    Ok(true)
}

#[cfg(target_os = "linux")]
fn cleanup_incomplete_guard_config_journal(root: &File) -> Result<()> {
    for name in [
        "include-config-before",
        "include-config-after",
        "include-config-exchanged",
    ] {
        unlink_guard_entry_at(root, name, 0, true)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn cleanup_guard_config_journal(root: &File) -> Result<()> {
    unlink_guard_entry_at(root, "include-config-transaction", 0, true)?;
    cleanup_incomplete_guard_config_journal(root)?;
    root.sync_all()
        .context("failed to sync guard config journal cleanup")
}

#[cfg(all(unix, not(target_os = "linux")))]
fn mutate_guard_include_fragment(_layout: &WorktreeGuardLayout, _add: bool) -> Result<()> {
    bail!("descriptor-safe guard include mutation requires Linux renameat2")
}

#[cfg(unix)]
fn expected_guard_include_fragment(layout: &WorktreeGuardLayout) -> Result<Vec<u8>> {
    let condition = guard_include_condition(&layout.bound_git_dir, &layout.common_dir)?;
    let mut fragment = b"\n[includeIf \"gitdir:".to_vec();
    append_git_config_quoted(&mut fragment, condition.as_bytes())?;
    fragment.extend_from_slice(b"\"]\n\tpath = \"");
    append_git_config_quoted(&mut fragment, layout.config_text.as_bytes())?;
    fragment.extend_from_slice(b"\"\n");
    Ok(fragment)
}

#[cfg(unix)]
fn append_git_config_quoted(output: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    for byte in value {
        match byte {
            b'\\' => output.extend_from_slice(b"\\\\"),
            b'\"' => output.extend_from_slice(b"\\\""),
            b'\n' | b'\r' | 0 => bail!("guard Git config value contains an unsupported byte"),
            b'\t' => output.extend_from_slice(b"\\t"),
            b'\x08' => output.extend_from_slice(b"\\b"),
            _ => output.push(*byte),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn require_guard_marker(layout: &WorktreeGuardLayout) -> Result<()> {
    let marker = layout.root.join("marker");
    require_regular_guard_file(&marker)?;
    if fs::read(&marker).context("failed to read guard ownership marker")?
        != WORKTREE_GUARD_MARKER.as_bytes()
    {
        bail!("MACO worktree guard ownership marker is missing or changed");
    }
    Ok(())
}

#[cfg(unix)]
fn require_guard_state(layout: &WorktreeGuardLayout, mode: &WorktreeGuardMode) -> Result<()> {
    let observed_mode = read_guard_text_line(&layout.root.join("mode"))?;
    if observed_mode != mode.label() {
        bail!("worktree guard mode does not match the requested installation");
    }
    let observed_branch = read_guard_text_line(&layout.root.join("expected-branch"))?;
    if observed_branch != mode.expected_branch().unwrap_or_default() {
        bail!("worktree guard expected branch does not match managed identity");
    }
    let observed_git_dir = read_guard_path_line(&layout.root.join("git-dir"))?;
    if observed_git_dir != layout.bound_git_dir {
        bail!("worktree guard Git-directory binding changed");
    }
    let observed_common = read_guard_path_line(&layout.root.join("common-dir"))?;
    if observed_common != layout.common_dir {
        bail!("worktree guard common-directory binding changed");
    }
    let previous_hooks = read_guard_path_line(&layout.root.join("previous-hooks-path"))?;
    if previous_hooks == layout.bound_hooks {
        bail!("worktree guard previous hook path loops back to itself");
    }
    let previous_git_dir_hooks =
        read_guard_path_line(&layout.root.join("previous-git-dir-hooks-path"))?;
    if previous_git_dir_hooks == layout.bound_hooks {
        bail!("worktree guard previous Git-directory hook path loops back to itself");
    }
    for state in ["human-v3-chained-commit-msg", "human-v3-chained-pre-push"] {
        if !matches!(
            read_guard_text_line(&layout.root.join(state))?.as_str(),
            "true" | "false"
        ) {
            bail!("worktree guard human-authorship composition state is invalid");
        }
    }
    let observed_include_level = read_guard_text_line(&layout.root.join("include-level"))?;
    if observed_include_level != layout.include_level.label() {
        bail!("worktree guard include level changed");
    }
    let observed_include_config_created =
        read_guard_text_line(&layout.root.join("include-config-created"))?;
    let expected_include_config_created = if layout.include_config_created {
        "true"
    } else {
        "false"
    };
    if observed_include_config_created != expected_include_config_created {
        bail!("worktree guard include configuration ownership changed");
    }
    Ok(())
}

#[cfg(unix)]
fn read_guard_text_line(path: &Path) -> Result<String> {
    let bytes = read_guard_line_bytes(path)?;
    String::from_utf8(bytes).context("guard state is not valid UTF-8")
}

#[cfg(unix)]
fn read_guard_path_line(path: &Path) -> Result<PathBuf> {
    Ok(PathBuf::from(OsString::from_vec(read_guard_line_bytes(
        path,
    )?)))
}

#[cfg(unix)]
fn read_guard_line_bytes(path: &Path) -> Result<Vec<u8>> {
    require_regular_guard_file(path)?;
    let mut bytes =
        fs::read(path).with_context(|| format!("failed to read guard state {}", path.display()))?;
    if bytes.last() != Some(&b'\n') {
        bail!("guard state is not a single newline-terminated value");
    }
    bytes.pop();
    if bytes.contains(&b'\n') || bytes.contains(&b'\r') {
        bail!("guard state contains multiple lines");
    }
    Ok(bytes)
}

#[cfg(unix)]
fn require_regular_guard_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect guard file {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "guard file is not a non-symlink regular file: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn validate_guard_tree_entries(layout: &WorktreeGuardLayout, allow_missing: bool) -> Result<()> {
    let required_root = BTreeSet::from([
        OsString::from("marker"),
        OsString::from("mode"),
        OsString::from("expected-branch"),
        OsString::from("git-dir"),
        OsString::from("previous-hooks-path"),
        OsString::from("previous-git-dir-hooks-path"),
        OsString::from("human-v3-chained-commit-msg"),
        OsString::from("human-v3-chained-pre-push"),
        OsString::from("common-dir"),
        OsString::from("include-level"),
        OsString::from("include-config-created"),
        OsString::from("config"),
        OsString::from("hooks"),
    ]);
    let mut permitted_root = required_root.clone();
    permitted_root.insert(OsString::from("human-v3-migration-commit-msg"));
    permitted_root.insert(OsString::from("human-v3-original-commit-msg"));
    permitted_root.insert(OsString::from("human-v3-migration-pre-push"));
    permitted_root.insert(OsString::from("human-v3-original-pre-push"));
    permitted_root.insert(OsString::from("include-config-transaction"));
    permitted_root.insert(OsString::from("include-config-before"));
    permitted_root.insert(OsString::from("include-config-after"));
    permitted_root.insert(OsString::from("include-config-exchanged"));
    let observed_root = fs::read_dir(&layout.root)
        .context("failed to enumerate guard root")?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<BTreeSet<_>>>()?;
    if (!allow_missing && !required_root.is_subset(&observed_root))
        || !observed_root.is_subset(&permitted_root)
    {
        bail!("guard root contains unexpected entries; refusing recursive removal");
    }
    let expected_hooks = WORKTREE_GUARD_HOOK_NAMES
        .iter()
        .map(OsString::from)
        .collect::<BTreeSet<_>>();
    let mut permitted_hooks = expected_hooks.clone();
    permitted_hooks.insert(OsString::from("commit-msg.human-authorship-previous"));
    permitted_hooks.insert(OsString::from("pre-push.human-authorship-previous"));
    match fs::read_dir(&layout.hooks) {
        Ok(entries) => {
            let observed_hooks = entries
                .map(|entry| entry.map(|entry| entry.file_name()))
                .collect::<std::io::Result<BTreeSet<_>>>()?;
            if (!allow_missing && !expected_hooks.is_subset(&observed_hooks))
                || !observed_hooks.is_subset(&permitted_hooks)
            {
                bail!("guard hooks directory contains unexpected entries; refusing removal");
            }
        }
        Err(error) if allow_missing && error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("failed to enumerate guard hooks"),
    }
    Ok(())
}

#[cfg(unix)]
fn remove_guard_owned_tree(
    layout: &WorktreeGuardLayout,
    root: &File,
    hooks: Option<&File>,
) -> Result<()> {
    if let Some(hooks) = hooks {
        for hook_name in WORKTREE_GUARD_HOOK_NAMES {
            unlink_guard_entry_at(hooks, hook_name, 0, true)
                .with_context(|| format!("failed to remove MACO guard hook {hook_name}"))?;
        }
        for backup in [
            "commit-msg.human-authorship-previous",
            "pre-push.human-authorship-previous",
        ] {
            unlink_guard_entry_at(hooks, backup, 0, true)
                .with_context(|| format!("failed to remove migrated MACO guard hook {backup}"))?;
        }
        verify_guard_directory_binding(&layout.hooks, hooks, "guard hooks")?;
        unlink_guard_entry_at(root, "hooks", libc::AT_REMOVEDIR, true)
            .context("failed to remove guard hooks directory")?;
    }
    for state_name in [
        "mode",
        "expected-branch",
        "git-dir",
        "previous-hooks-path",
        "previous-git-dir-hooks-path",
        "human-v3-chained-commit-msg",
        "human-v3-chained-pre-push",
        "common-dir",
        "include-level",
        "include-config-created",
        "human-v3-migration-commit-msg",
        "human-v3-original-commit-msg",
        "human-v3-migration-pre-push",
        "human-v3-original-pre-push",
        "include-config-transaction",
        "include-config-before",
        "include-config-after",
        "include-config-exchanged",
        "config",
    ] {
        unlink_guard_entry_at(root, state_name, 0, true)
            .with_context(|| format!("failed to remove MACO guard state {state_name}"))?;
    }
    unlink_guard_entry_at(root, "marker", 0, true)
        .context("failed to remove MACO guard ownership marker")?;
    root.sync_all()
        .context("failed to sync emptied guard root")?;
    verify_guard_directory_binding(&layout.root, root, "guard root")?;
    let git_dir = open_guard_directory(&layout.git_dir, "worktree Git directory")?;
    unlink_guard_entry_at(
        &git_dir,
        WORKTREE_GUARD_DIRECTORY,
        libc::AT_REMOVEDIR,
        false,
    )
    .context("failed to remove MACO guard root")?;
    git_dir
        .sync_all()
        .context("failed to sync worktree Git directory after guard removal")
}

#[cfg(unix)]
fn unlink_guard_entry_at(
    directory: &File,
    name: &str,
    flags: libc::c_int,
    allow_missing: bool,
) -> Result<()> {
    let name = guard_component(name)?;
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), flags) } == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if allow_missing && error.kind() == ErrorKind::NotFound {
        Ok(())
    } else {
        Err(error).context("descriptor-relative guard entry removal failed")
    }
}

#[cfg(unix)]
fn worktree_guard_report(
    layout: &WorktreeGuardLayout,
    mode: &WorktreeGuardMode,
    status: WorktreeGuardStatus,
) -> WorktreeGuardReport {
    WorktreeGuardReport {
        status,
        worktree_path: layout.worktree_path.clone(),
        hooks_path: layout.bound_hooks.clone(),
        mode: mode.label().to_string(),
        expected_branch: mode.expected_branch().map(ToOwned::to_owned),
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

fn validate_retry_supersession_authorities(
    repo: &Repository,
    repository: &ManagedRepositoryBinding,
    registry: &ManagedWorktreeRegistry,
    superseded_by: &BTreeMap<String, String>,
) -> Result<()> {
    for (predecessor, successor) in superseded_by {
        if parse_retry_predecessor(successor)
            .map_err(anyhow::Error::msg)?
            .as_deref()
            != Some(predecessor.as_str())
        {
            bail!(
                "retry supersession authority '{predecessor}' -> '{successor}' is not a canonical adjacent generation"
            );
        }
        if registry.operations.contains_key(predecessor)
            || registry.operations.contains_key(successor)
        {
            bail!("retry supersession authority changed to a pending lifecycle operation");
        }
        let predecessor_binding = registry
            .records
            .get(predecessor)
            .with_context(|| format!("retry predecessor '{predecessor}' disappeared before GC"))?;
        let successor_binding = registry
            .records
            .get(successor)
            .with_context(|| format!("retry successor '{successor}' disappeared before GC"))?;
        verify_managed_worktree_binding(repo, repository, predecessor_binding, false)
            .context("retry predecessor binding changed before GC")?;
        verify_managed_worktree_binding(repo, repository, successor_binding, false)
            .context("retry successor binding changed before GC")?;
        if predecessor_binding.root != successor_binding.root {
            bail!("retry generations no longer share one authenticated worktree root");
        }
        let successor_branch_predecessor = parse_retry_predecessor(&successor_binding.branch)
            .ok()
            .flatten();
        if successor_branch_predecessor.as_deref() != Some(predecessor_binding.branch.as_str())
            && successor_branch_predecessor
                .as_deref()
                .and_then(|branch| branch.rsplit('/').next())
                != predecessor_binding.branch.rsplit('/').next()
        {
            bail!("retry generations no longer share one canonical branch family");
        }
    }
    Ok(())
}

fn reconcile_managed_worktree_lifecycle(
    repo: &Repository,
    requested_root: Option<PathBuf>,
    apply: bool,
    destructive_reconciliation: bool,
    machine_global_retention: Option<&MachineGlobalRetentionBinding>,
) -> Result<WorktreeReconciliationReport> {
    let mut report = WorktreeReconciliationReport {
        enabled: true,
        apply,
        destructive_reconciliation,
        forgotten_record_count: 0,
        pruned_registration_count: 0,
        quarantined_directory_count: 0,
        entries: Vec::new(),
    };
    let active_claims = active_claim_agent_ids(repo)?;
    let managed_store = ManagedWorktreeRegistryStore::open_existing(repo)?;
    let snapshot = match managed_store.as_ref() {
        Some(store) => store.load_existing_read_only()?,
        None => None,
    };
    let mut resolutions = Vec::new();
    let mut authenticated_names = BTreeSet::new();
    let mut roots = BTreeSet::from([resolve_worktree_root(repo, requested_root)?]);

    if let (Some(store), Some(snapshot)) = (managed_store.as_ref(), snapshot.as_ref()) {
        for binding in snapshot.records.values() {
            authenticated_names.insert(binding.name.clone());
            roots.insert(binding.root.clone());
            let mut entry =
                classify_worktree_reconciliation(repo, &store.repository, snapshot, binding);
            let state = entry.state;
            let claimed = active_claims.contains(&binding.name);
            if claimed && state != WorktreeReconciliationState::Consistent {
                entry.action = WorktreeReconciliationAction::Protected;
                entry
                    .detail
                    .push_str("; an active durable claim protects this lane");
            } else if matches!(
                state,
                WorktreeReconciliationState::AuthenticatedMissingBoth
                    | WorktreeReconciliationState::RegisteredMissingPath
                    | WorktreeReconciliationState::PresentDeregistered
            ) {
                if apply && destructive_reconciliation {
                    resolutions.push(WorktreeReconciliationResolution::Authenticated {
                        entry_index: report.entries.len(),
                        state,
                        binding: Box::new(binding.clone()),
                    });
                } else {
                    entry.action = WorktreeReconciliationAction::ReportOnly;
                    entry.detail.push_str(
                        "; resolution requires both apply and destructive reconciliation",
                    );
                }
            }
            report.entries.push(entry);
        }
        for operation in snapshot.operations.values() {
            if snapshot.records.contains_key(&operation.name) {
                continue;
            }
            report.entries.push(WorktreeReconciliationEntry {
                name: operation.name.clone(),
                branch: Some(operation.branch.clone()),
                path: operation.path.clone(),
                state: WorktreeReconciliationState::PendingOperation,
                action: WorktreeReconciliationAction::Protected,
                detail: format!(
                    "authenticated {} operation remains in phase {}; startup reconciliation reports it without bypassing recovery",
                    managed_operation_kind_label(operation.kind),
                    managed_operation_phase_label(operation.phase),
                ),
            });
        }
    }

    let mut unregistered_name_paths = BTreeMap::<String, Vec<(usize, FileIdentity)>>::new();
    for root_path in roots {
        if !path_entry_exists(&root_path)? {
            continue;
        }
        let root = SafeRoot::open_existing(&root_path)?;
        let git_registered = git_registered_worktree_names_for_reconciliation(repo, root.path())?;
        for child_name in root.direct_child_names_bounded(MAX_MANAGED_RECORDS)? {
            if child_name.to_string_lossy().starts_with(".maco-") {
                continue;
            }
            let Some(name) = child_name.to_str() else {
                bail!("managed worktree root contains a non-UTF-8 child name");
            };
            if normalize_agent_id(name)? != name || authenticated_names.contains(name) {
                continue;
            }
            let path = root.direct_child(&child_name)?;
            let identity = identity_for_path(&path)?;
            let registered = git_registered.contains(name);
            let claimed = active_claims.contains(name);
            let entry_index = report.entries.len();
            report.entries.push(WorktreeReconciliationEntry {
                name: name.to_string(),
                branch: None,
                path: path.clone(),
                state: if registered {
                    WorktreeReconciliationState::Ambiguous
                } else {
                    WorktreeReconciliationState::PresentDeregistered
                },
                action: if claimed || registered {
                    WorktreeReconciliationAction::Protected
                } else {
                    WorktreeReconciliationAction::ReportOnly
                },
                detail: if claimed {
                    "unregistered on-disk lane is protected by an active durable claim".to_string()
                } else if registered {
                    "Git-registered lane lacks authenticated MACO ownership; startup reconciliation will not adopt or remove it".to_string()
                } else if apply && destructive_reconciliation {
                    "unregistered on-disk lane is eligible only for machine-global quarantine".to_string()
                } else {
                    "unregistered on-disk lane detected; quarantine requires apply plus destructive reconciliation and a reviewed machine-global binding".to_string()
                },
            });
            if !claimed && !registered && apply && destructive_reconciliation {
                unregistered_name_paths
                    .entry(name.to_string())
                    .or_default()
                    .push((entry_index, identity));
            }
        }
    }
    for (name, candidates) in unregistered_name_paths {
        if candidates.len() != 1 {
            for (entry_index, _) in candidates {
                mark_reconciliation_index_protected(
                    &mut report.entries,
                    entry_index,
                    "same unregistered lane name appears under multiple managed roots",
                );
            }
            continue;
        }
        let (entry_index, identity) = candidates
            .into_iter()
            .next()
            .context("one reconciliation candidate disappeared")?;
        let path = report.entries[entry_index].path.clone();
        resolutions.push(WorktreeReconciliationResolution::UnregisteredDirectory {
            entry_index,
            name,
            path,
            identity,
        });
    }

    if apply && destructive_reconciliation {
        apply_worktree_reconciliation_resolutions(
            repo,
            managed_store.as_ref(),
            &active_claims,
            machine_global_retention,
            resolutions,
            &mut report,
        )?;
    }
    report.entries.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.path.cmp(&right.path))
    });
    Ok(report)
}

enum WorktreeReconciliationResolution {
    Authenticated {
        entry_index: usize,
        state: WorktreeReconciliationState,
        binding: Box<ManagedWorktreeBinding>,
    },
    UnregisteredDirectory {
        entry_index: usize,
        name: String,
        path: PathBuf,
        identity: FileIdentity,
    },
}

struct WorktreeReconciliationQuarantine {
    entry_index: usize,
    name: String,
    path: PathBuf,
    identity: FileIdentity,
    authenticated_binding: Option<ManagedWorktreeBinding>,
}

fn apply_worktree_reconciliation_resolutions(
    repo: &Repository,
    managed_store: Option<&ManagedWorktreeRegistryStore>,
    observed_claims: &BTreeSet<String>,
    machine_global_retention: Option<&MachineGlobalRetentionBinding>,
    resolutions: Vec<WorktreeReconciliationResolution>,
    report: &mut WorktreeReconciliationReport,
) -> Result<()> {
    let current_claims = active_claim_agent_ids(repo)?;
    let mut authenticated = Vec::new();
    let mut quarantine = Vec::new();
    for resolution in resolutions {
        match resolution {
            WorktreeReconciliationResolution::Authenticated {
                entry_index,
                state,
                binding,
            } => authenticated.push((entry_index, state, *binding)),
            WorktreeReconciliationResolution::UnregisteredDirectory {
                entry_index,
                name,
                path,
                identity,
            } => quarantine.push(WorktreeReconciliationQuarantine {
                entry_index,
                name,
                path,
                identity,
                authenticated_binding: None,
            }),
        }
    }

    let mut managed_state = None;
    if !authenticated.is_empty() {
        let store = managed_store
            .context("authenticated reconciliation candidates lost their managed registry store")?;
        let lock = store.lock_existing()?;
        let current = store.load(&lock)?;
        managed_state = Some((store, lock, current));
    }

    if let Some((store, lock, current)) = managed_state.as_mut() {
        for (entry_index, state, expected) in authenticated {
            if observed_claims.contains(&expected.name) || current_claims.contains(&expected.name) {
                mark_reconciliation_index_protected(
                    &mut report.entries,
                    entry_index,
                    "an active durable claim appeared before destructive reconciliation",
                );
                continue;
            }
            let Some(observed) = current.records.get(&expected.name) else {
                mark_reconciliation_index_protected(
                    &mut report.entries,
                    entry_index,
                    "authenticated record disappeared before destructive reconciliation",
                );
                continue;
            };
            if observed != &expected
                || current.operations.contains_key(&expected.name)
                || store.worktree_has_active_execution_lease(lock, &expected.name)?
            {
                mark_reconciliation_index_protected(
                    &mut report.entries,
                    entry_index,
                    "authenticated identity, operation state, or execution lease changed before apply",
                );
                continue;
            }
            match state {
                WorktreeReconciliationState::AuthenticatedMissingBoth => {
                    if path_entry_exists(&expected.path)?
                        || path_entry_exists(&expected.metadata_dir)?
                        || repo.find_worktree(&expected.name).is_ok()
                    {
                        mark_reconciliation_index_protected(
                            &mut report.entries,
                            entry_index,
                            "missing-both state changed before apply",
                        );
                        continue;
                    }
                    current.records.remove(&expected.name);
                    let entry = &mut report.entries[entry_index];
                    entry.action = WorktreeReconciliationAction::ForgotAuthenticatedRecord;
                    entry.detail = "forgot exact authenticated missing-both record; branch and claims were preserved".to_string();
                    report.forgotten_record_count = report
                        .forgotten_record_count
                        .checked_add(1)
                        .context("forgotten reconciliation record count overflowed")?;
                }
                WorktreeReconciliationState::RegisteredMissingPath => {
                    if path_entry_exists(&expected.path)?
                        || identity_for_path(&expected.metadata_dir).ok().as_ref()
                            != Some(&expected.metadata_dir_identity)
                        || BoundedRegularReader::identity(expected.metadata_dir.join("gitdir"))
                            .ok()
                            .as_ref()
                            != Some(&expected.metadata_gitdir_file_identity)
                        || BoundedRegularReader::identity(expected.metadata_dir.join("HEAD"))
                            .ok()
                            .as_ref()
                            != Some(&expected.metadata_head_file_identity)
                    {
                        mark_reconciliation_index_protected(
                            &mut report.entries,
                            entry_index,
                            "registered-missing-path metadata identity changed before apply",
                        );
                        continue;
                    }
                    let worktree = match repo.find_worktree(&expected.name) {
                        Ok(worktree) => worktree,
                        Err(_) => {
                            mark_reconciliation_index_protected(
                                &mut report.entries,
                                entry_index,
                                "Git registration disappeared before exact prune",
                            );
                            continue;
                        }
                    };
                    if worktree.path() != expected.path {
                        mark_reconciliation_index_protected(
                            &mut report.entries,
                            entry_index,
                            "Git registration no longer names the authenticated path",
                        );
                        continue;
                    }
                    let mut options = WorktreePruneOptions::new();
                    if !worktree
                        .is_prunable(Some(&mut options))
                        .context("failed to classify exact stale worktree registration")?
                    {
                        mark_reconciliation_index_protected(
                            &mut report.entries,
                            entry_index,
                            "Git refused to classify the missing-path registration as prunable",
                        );
                        continue;
                    }
                    let mut options = WorktreePruneOptions::new();
                    worktree
                        .prune(Some(&mut options))
                        .context("failed to prune exact authenticated stale registration")?;
                    current.records.remove(&expected.name);
                    let entry = &mut report.entries[entry_index];
                    entry.action = WorktreeReconciliationAction::PrunedRegistrationAndForgotRecord;
                    entry.detail = "pruned the exact authenticated stale Git registration and forgot its record; branch and claims were preserved".to_string();
                    report.pruned_registration_count = report
                        .pruned_registration_count
                        .checked_add(1)
                        .context("reconciliation pruned registration count overflowed")?;
                    report.forgotten_record_count = report
                        .forgotten_record_count
                        .checked_add(1)
                        .context("forgotten reconciliation record count overflowed")?;
                }
                WorktreeReconciliationState::PresentDeregistered => {
                    if identity_for_path(&expected.path).ok().as_ref()
                        != Some(&expected.path_identity)
                        || path_entry_exists(&expected.metadata_dir)?
                        || repo.find_worktree(&expected.name).is_ok()
                    {
                        mark_reconciliation_index_protected(
                            &mut report.entries,
                            entry_index,
                            "present-deregistered identity or registration state changed before quarantine",
                        );
                        continue;
                    }
                    quarantine.push(WorktreeReconciliationQuarantine {
                        entry_index,
                        name: expected.name.clone(),
                        path: expected.path.clone(),
                        identity: expected.path_identity.clone(),
                        authenticated_binding: Some(expected),
                    });
                }
                _ => mark_reconciliation_index_protected(
                    &mut report.entries,
                    entry_index,
                    "reconciliation resolution no longer has a destructive action",
                ),
            }
        }
        store.save(lock, current)?;
    }

    if quarantine.is_empty() {
        return Ok(());
    }
    let Some(binding) = machine_global_retention else {
        for candidate in quarantine {
            mark_reconciliation_index_protected(
                &mut report.entries,
                candidate.entry_index,
                "destructive reconciliation of an on-disk directory requires an explicit machine-global config/root binding",
            );
        }
        return Ok(());
    };
    for candidate in &quarantine {
        if current_claims.contains(&candidate.name)
            || identity_for_path(&candidate.path).ok().as_ref() != Some(&candidate.identity)
        {
            mark_reconciliation_index_protected(
                &mut report.entries,
                candidate.entry_index,
                "claim or directory identity changed before machine-global quarantine",
            );
        }
    }
    quarantine.retain(|candidate| {
        report.entries[candidate.entry_index].action != WorktreeReconciliationAction::Protected
    });
    if quarantine.is_empty() {
        return Ok(());
    }
    let machine_store = MachineGlobalStore::open_config(&binding.config)
        .context("failed to open machine-global binding for startup reconciliation")?;
    let targets = quarantine
        .iter()
        .map(|candidate| {
            machine_store
                .coordinate_for_existing_directory(&binding.root_id, &candidate.path)
                .map(DestructiveTargetInput::Declared)
        })
        .collect::<Result<Vec<_>>>()
        .context("startup reconciliation target is outside the reviewed machine-global root")?;
    match machine_store.quarantine(&binding.owner, &binding.correction_correlation_id, targets)? {
        GateOutcome::Denied(denial) => {
            for candidate in quarantine {
                mark_reconciliation_index_protected(
                    &mut report.entries,
                    candidate.entry_index,
                    &format!("machine-global quarantine was denied: {denial:?}"),
                );
            }
        }
        GateOutcome::Allowed(operation) => {
            if quarantine
                .iter()
                .any(|candidate| candidate.authenticated_binding.is_some())
            {
                let (store, lock, current) = managed_state
                    .as_mut()
                    .context("authenticated quarantines lost their locked managed registry")?;
                for candidate in &quarantine {
                    if let Some(expected) = candidate.authenticated_binding.as_ref() {
                        if current.records.get(&expected.name) != Some(expected) {
                            bail!(
                                "authenticated reconciliation record changed after its directory was quarantined; manual recovery is required"
                            );
                        }
                        current.records.remove(&expected.name);
                        report.forgotten_record_count = report
                            .forgotten_record_count
                            .checked_add(1)
                            .context("forgotten reconciliation record count overflowed")?;
                    }
                }
                store.save(lock, current)?;
            }
            for candidate in quarantine {
                let entry = &mut report.entries[candidate.entry_index];
                entry.action = if candidate.authenticated_binding.is_some() {
                    WorktreeReconciliationAction::QuarantinedDirectoryAndForgotRecord
                } else {
                    WorktreeReconciliationAction::QuarantinedDirectory
                };
                entry.detail = format!(
                    "moved exact crash-orphan directory into recoverable machine-global quarantine operation {}",
                    operation.id.get()
                );
                report.quarantined_directory_count = report
                    .quarantined_directory_count
                    .checked_add(1)
                    .context("reconciliation quarantined directory count overflowed")?;
            }
        }
    }
    Ok(())
}

fn classify_worktree_reconciliation(
    repo: &Repository,
    repository: &ManagedRepositoryBinding,
    registry: &ManagedWorktreeRegistry,
    binding: &ManagedWorktreeBinding,
) -> WorktreeReconciliationEntry {
    let base = |state, action, detail: String| WorktreeReconciliationEntry {
        name: binding.name.clone(),
        branch: Some(binding.branch.clone()),
        path: binding.path.clone(),
        state,
        action,
        detail,
    };
    if registry.operations.contains_key(&binding.name) {
        return base(
            WorktreeReconciliationState::PendingOperation,
            WorktreeReconciliationAction::Protected,
            "authenticated lifecycle operation is pending; startup reconciliation does not bypass operation recovery".to_string(),
        );
    }
    let path = fs::symlink_metadata(&binding.path);
    let metadata = fs::symlink_metadata(&binding.metadata_dir);
    let registered = repo.find_worktree(&binding.name).is_ok();
    match (path, metadata, registered) {
        (Err(path_error), Err(metadata_error), false)
            if path_error.kind() == ErrorKind::NotFound
                && metadata_error.kind() == ErrorKind::NotFound =>
        {
            base(
                WorktreeReconciliationState::AuthenticatedMissingBoth,
                WorktreeReconciliationAction::ReportOnly,
                "authenticated record remains but its worktree and Git registration metadata are absent".to_string(),
            )
        }
        (Err(path_error), Ok(_), true) if path_error.kind() == ErrorKind::NotFound => base(
            WorktreeReconciliationState::RegisteredMissingPath,
            WorktreeReconciliationAction::Protected,
            "Git registration remains but the authenticated worktree path is missing".to_string(),
        ),
        (Ok(path_metadata), Err(metadata_error), false)
            if path_metadata.is_dir()
                && !path_metadata.file_type().is_symlink()
                && metadata_error.kind() == ErrorKind::NotFound =>
        {
            base(
                WorktreeReconciliationState::PresentDeregistered,
                WorktreeReconciliationAction::Protected,
                "authenticated path is present but deregistered; dirtiness and metadata cleanup are not inferred"
                    .to_string(),
            )
        }
        (Ok(_), Ok(_), true) => match verify_managed_worktree_binding(
            repo,
            repository,
            binding,
            false,
        ) {
            Ok(_) => base(
                WorktreeReconciliationState::Consistent,
                WorktreeReconciliationAction::None,
                "authenticated path and Git registration are consistent".to_string(),
            ),
            Err(error) => base(
                WorktreeReconciliationState::Ambiguous,
                WorktreeReconciliationAction::Protected,
                format!("authenticated binding could not be verified: {error:#}"),
            ),
        },
        (path, metadata, registered) => base(
            WorktreeReconciliationState::Ambiguous,
            WorktreeReconciliationAction::Protected,
            format!(
                "path/metadata/registration state is not safely reconcilable (path={}, metadata={}, registered={registered})",
                path.is_ok(),
                metadata.is_ok(),
            ),
        ),
    }
}

fn mark_reconciliation_index_protected(
    entries: &mut [WorktreeReconciliationEntry],
    entry_index: usize,
    detail: &str,
) {
    if let Some(entry) = entries.get_mut(entry_index) {
        entry.state = WorktreeReconciliationState::Ambiguous;
        entry.action = WorktreeReconciliationAction::Protected;
        entry.detail = detail.to_string();
    }
}

fn prune_stale_worktree_registrations(
    repo: &Repository,
    allowed_names: &BTreeSet<String>,
    apply: bool,
) -> Result<WorktreeRepositoryPruneReport> {
    let names = repo
        .worktrees()
        .context("failed to enumerate stale Git worktree registrations")?;
    if names.len() > MAX_MANAGED_RECORDS {
        bail!("Git worktree prune exceeds its bounded registration limit");
    }
    let mut report = WorktreeRepositoryPruneReport {
        status: if apply {
            WorktreeRepositoryPruneStatus::Completed
        } else {
            WorktreeRepositoryPruneStatus::DryRun
        },
        stale_registration_count: 0,
        pruned_registration_count: 0,
        protected_registration_count: 0,
    };
    for index in 0..names.len() {
        let Some(name) = names
            .get(index)
            .context("failed to read Git worktree registration during prune")?
        else {
            continue;
        };
        let worktree = repo
            .find_worktree(name)
            .with_context(|| format!("failed to inspect Git worktree '{name}' during prune"))?;
        let mut options = WorktreePruneOptions::new();
        if !worktree
            .is_prunable(Some(&mut options))
            .with_context(|| format!("failed to classify Git worktree '{name}' for prune"))?
        {
            continue;
        }
        report.stale_registration_count = report
            .stale_registration_count
            .checked_add(1)
            .context("stale Git worktree count overflowed")?;
        if !allowed_names.contains(name) {
            report.protected_registration_count = report
                .protected_registration_count
                .checked_add(1)
                .context("protected stale Git worktree count overflowed")?;
            continue;
        }
        if !apply {
            continue;
        }
        let mut options = WorktreePruneOptions::new();
        worktree
            .prune(Some(&mut options))
            .with_context(|| format!("failed to prune stale Git worktree '{name}'"))?;
        report.pruned_registration_count = report
            .pruned_registration_count
            .checked_add(1)
            .context("pruned Git worktree count overflowed")?;
    }
    Ok(report)
}

fn validate_worktree_gc_mode(
    targets_only: bool,
    remove_targets: bool,
    retention: WorktreeRetentionPolicy,
    allowed_untracked_paths: &[PathBuf],
    has_machine_global_retention: bool,
) -> Result<()> {
    if !targets_only {
        return Ok(());
    }
    if !remove_targets {
        bail!("target-only GC conflicts with keeping target directories");
    }
    if worktree_retention_is_configured(retention) {
        bail!("target-only GC does not accept worktree retention filters");
    }
    if !allowed_untracked_paths.is_empty() {
        bail!("target-only GC does not accept full-lane untracked-path allowances");
    }
    if has_machine_global_retention {
        bail!("target-only GC does not accept machine-global orphan cleanup bindings");
    }
    Ok(())
}

#[derive(Debug)]
struct WorktreeSweepRootCandidate {
    group: String,
    root_kind: WorktreeSweepRootKind,
    worktree_root: PathBuf,
    plain_directory: bool,
    repository_hint: Option<PathBuf>,
}

fn discover_workspace_managed_sweep_roots(
    workspace: &Path,
) -> Result<Vec<WorktreeSweepRootCandidate>> {
    let metadata_root = workspace.join(".maco");
    let worktrees_root = metadata_root.join("worktrees");
    let group_entries = match fs::symlink_metadata(&metadata_root) {
        Ok(_) => {
            require_plain_directory(&metadata_root, "workspace metadata root")?;
            match fs::symlink_metadata(&worktrees_root) {
                Ok(_) => bounded_workspace_sweep_group_entries(
                    &worktrees_root,
                    MAX_WORKSPACE_SWEEP_GROUPS,
                    "workspace worktree root",
                )?,
                Err(error) if error.kind() == ErrorKind::NotFound => Vec::new(),
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "failed to inspect workspace worktree root {}",
                            worktrees_root.display()
                        )
                    })
                }
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Vec::new(),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect workspace metadata root {}",
                    metadata_root.display()
                )
            })
        }
    };
    let mut roots = Vec::new();
    for group_entry in group_entries {
        let group = group_entry
            .name
            .to_str()
            .context("workspace worktree group name is not valid UTF-8")?;
        if group.is_empty() || group.len() > MAX_WORKSPACE_SWEEP_GROUP_NAME_BYTES {
            bail!("workspace worktree group name is invalid or out of bounds");
        }
        roots.push(WorktreeSweepRootCandidate {
            group: group.to_string(),
            root_kind: WorktreeSweepRootKind::WorkspaceManaged,
            worktree_root: worktrees_root.join(group),
            plain_directory: group_entry.plain_directory,
            repository_hint: None,
        });
    }
    Ok(roots)
}

fn discover_repository_local_sweep_roots(
    workspace: &Path,
) -> Result<Vec<WorktreeSweepRootCandidate>> {
    let mut roots = Vec::new();
    if path_entry_exists(&workspace.join(".git"))? {
        add_repository_local_sweep_root(workspace, &mut roots)?;
    }

    for child in
        bounded_workspace_sweep_group_entries(workspace, MAX_WORKSPACE_SWEEP_CHILDREN, "workspace")?
    {
        if !child.plain_directory || matches!(child.name.to_str(), Some(".maco" | ".worktrees")) {
            continue;
        }
        let repository = workspace.join(&child.name);
        if path_entry_exists(&repository.join(".git"))? {
            add_repository_local_sweep_root(&repository, &mut roots)?;
        }
    }
    Ok(roots)
}

fn add_repository_local_sweep_root(
    repository: &Path,
    roots: &mut Vec<WorktreeSweepRootCandidate>,
) -> Result<()> {
    let worktree_root = repository.join(".worktrees");
    let metadata = match fs::symlink_metadata(&worktree_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect repository-local worktree root {}",
                    worktree_root.display()
                )
            })
        }
    };
    let group = repository
        .file_name()
        .and_then(OsStr::to_str)
        .context("repository-local worktree repository name is not valid UTF-8")?;
    if group.is_empty() || group.len() > MAX_WORKSPACE_SWEEP_GROUP_NAME_BYTES {
        bail!("repository-local worktree repository name is invalid or out of bounds");
    }
    roots.push(WorktreeSweepRootCandidate {
        group: group.to_string(),
        root_kind: WorktreeSweepRootKind::RepositoryLocal,
        worktree_root,
        plain_directory: metadata.is_dir() && !metadata.file_type().is_symlink(),
        repository_hint: Some(repository.to_path_buf()),
    });
    Ok(())
}

fn add_sweep_pre_gc_failure(
    report: &mut WorktreeSweepReport,
    group: String,
    root_kind: WorktreeSweepRootKind,
    worktree_root: PathBuf,
    failure: WorktreeSweepFailure,
) -> Result<()> {
    report.repository_pre_gc_skipped_count = report
        .repository_pre_gc_skipped_count
        .checked_add(1)
        .context("workspace sweep skipped repository count overflowed")?;
    report.repository_failure_count = report
        .repository_failure_count
        .checked_add(1)
        .context("workspace sweep repository failure count overflowed")?;
    report.repositories.push(WorktreeSweepRepositoryReport {
        group,
        root_kind,
        worktree_root,
        repository: None,
        status: WorktreeSweepRepositoryStatus::Skipped,
        gc_attempted: false,
        effects_may_have_occurred: false,
        failure: Some(failure),
        gc_report: None,
    });
    Ok(())
}

fn add_sweep_gc_counts(sweep: &mut WorktreeSweepReport, gc: &WorktreeGcReport) -> Result<()> {
    sweep.considered_count = sweep
        .considered_count
        .checked_add(gc.considered_count)
        .context("workspace sweep considered count overflowed")?;
    sweep.removed_count = sweep
        .removed_count
        .checked_add(gc.removed_count)
        .context("workspace sweep removed count overflowed")?;
    sweep.protected_count = sweep
        .protected_count
        .checked_add(gc.protected_count)
        .context("workspace sweep protected count overflowed")?;
    sweep.retained_count = sweep
        .retained_count
        .checked_add(gc.retained_count)
        .context("workspace sweep retained count overflowed")?;
    sweep.target_removed_count = sweep
        .target_removed_count
        .checked_add(gc.target_removed_count)
        .context("workspace sweep target count overflowed")?;
    sweep.orphan_removed_count = sweep
        .orphan_removed_count
        .checked_add(gc.orphan_removed_count)
        .context("workspace sweep orphan count overflowed")?;
    sweep.apparent_considered_bytes = sweep
        .apparent_considered_bytes
        .checked_add(gc.apparent_considered_bytes)
        .context("workspace sweep apparent considered bytes overflowed")?;
    sweep.estimated_reclaimable_bytes = sweep
        .estimated_reclaimable_bytes
        .checked_add(gc.estimated_reclaimable_bytes)
        .context("workspace sweep estimated reclaimable bytes overflowed")?;
    sweep.estimated_reclaimed_bytes = sweep
        .estimated_reclaimed_bytes
        .checked_add(gc.estimated_reclaimed_bytes)
        .context("workspace sweep estimated reclaimed bytes overflowed")?;
    Ok(())
}

fn merge_worktree_gc_preview(
    report: &mut WorktreeGcReport,
    mut preview: WorktreeGcReport,
) -> Result<()> {
    report.considered_count = report
        .considered_count
        .checked_add(preview.considered_count)
        .context("worktree GC considered count overflowed")?;
    report.removed_count = report
        .removed_count
        .checked_add(preview.removed_count)
        .context("worktree GC removed count overflowed")?;
    report.protected_count = report
        .protected_count
        .checked_add(preview.protected_count)
        .context("worktree GC protected count overflowed")?;
    report.retained_count = report
        .retained_count
        .checked_add(preview.retained_count)
        .context("worktree GC retained count overflowed")?;
    report.target_removed_count = report
        .target_removed_count
        .checked_add(preview.target_removed_count)
        .context("worktree GC target count overflowed")?;
    report.orphan_removed_count = report
        .orphan_removed_count
        .checked_add(preview.orphan_removed_count)
        .context("worktree GC orphan count overflowed")?;
    report.apparent_considered_bytes = report
        .apparent_considered_bytes
        .checked_add(preview.apparent_considered_bytes)
        .context("worktree GC apparent considered bytes overflowed")?;
    report.estimated_reclaimable_bytes = report
        .estimated_reclaimable_bytes
        .checked_add(preview.estimated_reclaimable_bytes)
        .context("worktree GC estimated reclaimable bytes overflowed")?;
    report.estimated_reclaimed_bytes = report
        .estimated_reclaimed_bytes
        .checked_add(preview.estimated_reclaimed_bytes)
        .context("worktree GC estimated reclaimed bytes overflowed")?;
    report.entries.append(&mut preview.entries);
    report.entries.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.name.cmp(&right.name))
    });
    Ok(())
}

struct RegisteredWorktreePreviewCandidate {
    name: String,
    branch: Option<String>,
    branch_merged: bool,
    path: PathBuf,
    created_at_unix_nanos: i64,
    untracked_paths: Vec<PathBuf>,
    size: WorktreeGcSizeEstimate,
}

/// Classifies Git-registered repository-local lanes that predate the
/// authenticated MACO registry. This path is deliberately preview-only: it
/// makes legacy disk usage visible without granting destructive authority from
/// pathnames alone. Apply mode continues to require an authenticated binding.
fn preview_registered_repository_local_worktrees(
    repository: &Path,
    worktree_root: &Path,
    options: &WorktreeSweepOptions,
    excluded_names: &BTreeSet<String>,
) -> Result<WorktreeGcReport> {
    let allowed_untracked_paths =
        normalize_gc_allowed_untracked_paths(&options.allowed_untracked_paths)?;
    let repo = crate::git_repository::open(repository)
        .with_context(|| format!("failed to open repository {}", repository.display()))?;
    let worktree_root = fs::canonicalize(worktree_root).with_context(|| {
        format!(
            "failed to resolve repository-local worktree root {}",
            worktree_root.display()
        )
    })?;
    require_plain_directory(&worktree_root, "repository-local worktree root")?;
    let primary_head = repo
        .head()
        .context("repository-local preview requires a committed primary HEAD")?
        .peel_to_commit()
        .context("repository-local primary HEAD is not a commit")?
        .id();
    let now = unix_now_nanos()?;
    let mut report = WorktreeGcReport {
        dry_run: true,
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
    let names = repo
        .worktrees()
        .context("failed to list Git worktrees for repository-local preview")?;
    if names.len() > MAX_WORKSPACE_SWEEP_LANES_PER_GROUP {
        bail!(
            "repository-local preview exceeds its {}-worktree limit",
            MAX_WORKSPACE_SWEEP_LANES_PER_GROUP
        );
    }
    let mut candidates = Vec::new();
    for index in 0..names.len() {
        let Some(name) = names
            .get(index)
            .context("failed to read Git worktree name for repository-local preview")?
        else {
            continue;
        };
        if excluded_names.contains(name) || normalize_agent_id(name).ok().as_deref() != Some(name) {
            continue;
        }
        let worktree = match repo.find_worktree(name) {
            Ok(worktree) => worktree,
            Err(_) => continue,
        };
        if worktree.validate().is_err() {
            continue;
        }
        let path = match fs::canonicalize(worktree.path()) {
            Ok(path) => path,
            Err(_) => continue,
        };
        if path.parent() != Some(worktree_root.as_path()) {
            continue;
        }
        let lane_repo = match crate::git_repository::open(&path) {
            Ok(repo) => repo,
            Err(_) => continue,
        };
        let head = match lane_repo.head().and_then(|head| head.peel_to_commit()) {
            Ok(head) => head,
            Err(_) => continue,
        };
        let branch_oid = head.id();
        let branch = lane_repo
            .head()
            .ok()
            .and_then(|head| head.name().ok().map(str::to_owned))
            .and_then(|name| name.strip_prefix("refs/heads/").map(str::to_owned));
        let branch_merged = branch_oid == primary_head
            || repo
                .graph_descendant_of(primary_head, branch_oid)
                .context("failed to inspect repository-local branch ancestry")?;
        report.considered_count = report
            .considered_count
            .checked_add(1)
            .context("worktree GC considered count overflowed")?;
        let size = match gc_worktree_size_estimate(&path) {
            Ok(size) => size,
            Err(_) => {
                report.protected_count = report
                    .protected_count
                    .checked_add(1)
                    .context("worktree GC protected count overflowed")?;
                report.entries.push(WorktreeGcEntry {
                    name: name.to_string(),
                    branch,
                    path,
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
        let untracked_paths = match preview_registered_worktree_dirtiness(&path)? {
            WorktreeGcDirtiness::Clean => Vec::new(),
            WorktreeGcDirtiness::TrackedDirty => {
                report.protected_count = report
                    .protected_count
                    .checked_add(1)
                    .context("worktree GC protected count overflowed")?;
                report.entries.push(WorktreeGcEntry {
                    name: name.to_string(),
                    branch,
                    path,
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
            WorktreeGcDirtiness::UntrackedOnly(paths)
                if options.targets_only
                    || paths
                        .iter()
                        .all(|path| allowed_untracked_paths.contains(path)) =>
            {
                paths
            }
            WorktreeGcDirtiness::UntrackedOnly(paths) => {
                report.protected_count = report
                    .protected_count
                    .checked_add(1)
                    .context("worktree GC protected count overflowed")?;
                report.entries.push(WorktreeGcEntry {
                    name: name.to_string(),
                    branch,
                    path,
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
        };
        let created_at_unix_nanos = fs::metadata(&path)
            .and_then(|metadata| metadata.modified())
            .ok()
            .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
            .and_then(|duration| i64::try_from(duration.as_nanos()).ok())
            .unwrap_or(0);
        candidates.push(RegisteredWorktreePreviewCandidate {
            name: name.to_string(),
            branch,
            branch_merged,
            path,
            created_at_unix_nanos,
            untracked_paths,
            size,
        });
    }

    candidates.sort_by(|left, right| {
        right
            .created_at_unix_nanos
            .cmp(&left.created_at_unix_nanos)
            .then_with(|| left.name.cmp(&right.name))
    });
    let mut retention_state = WorktreeGcRetentionState::default();
    for candidate in candidates {
        let target = gc_target_if_present(&candidate.path)?;
        let should_remove = if options.targets_only || !candidate.branch_merged {
            false
        } else {
            let count_expired = options
                .retention
                .max_count
                .is_some_and(|max_count| retention_state.eligible_count >= max_count);
            let age_expired = options.retention.max_age.is_some_and(|max_age| {
                now.checked_sub(candidate.created_at_unix_nanos)
                    .and_then(|age| u128::try_from(age.max(0)).ok())
                    .is_some_and(|age| age >= max_age.as_nanos())
            });
            let mut size_expired = false;
            if !count_expired && !age_expired {
                if let Some(max_total_bytes) = options.retention.max_total_bytes {
                    if retention_state.size_budget_exhausted {
                        size_expired = true;
                    } else {
                        let retained = retention_state
                            .retained_apparent_bytes
                            .checked_add(candidate.size.worktree_bytes)
                            .context("worktree GC retained apparent byte count overflowed")?;
                        if retained <= max_total_bytes {
                            retention_state.retained_apparent_bytes = retained;
                        } else {
                            retention_state.size_budget_exhausted = true;
                            size_expired = true;
                        }
                    }
                }
            }
            retention_state.eligible_count = retention_state
                .eligible_count
                .checked_add(1)
                .context("worktree GC eligible count overflowed")?;
            !worktree_retention_is_configured(options.retention)
                || count_expired
                || age_expired
                || size_expired
        };
        let target_cleanup = options.remove_targets && target.is_some();
        if should_remove || target_cleanup {
            if let Some((reason, evidence)) = target
                .as_ref()
                .and_then(|target| gc_target_liveness_protection(target, &worktree_target_liveness))
            {
                report.protected_count = report
                    .protected_count
                    .checked_add(1)
                    .context("worktree GC protected count overflowed")?;
                report.entries.push(WorktreeGcEntry {
                    name: candidate.name,
                    branch: candidate.branch,
                    path: candidate.path,
                    status: WorktreeGcStatus::Protected,
                    reason,
                    target_path: target.map(|target| target.path),
                    target_liveness: Some(evidence),
                    apparent_worktree_bytes: Some(candidate.size.worktree_bytes),
                    apparent_target_bytes: candidate.size.target_bytes,
                    untracked_paths: candidate.untracked_paths,
                    gate_denial: None,
                    retention_operation_id: None,
                });
                continue;
            }
        }
        if should_remove {
            report.removed_count = report
                .removed_count
                .checked_add(1)
                .context("worktree GC removed count overflowed")?;
            report.estimated_reclaimable_bytes = report
                .estimated_reclaimable_bytes
                .checked_add(candidate.size.worktree_bytes)
                .context("worktree GC estimated reclaimable bytes overflowed")?;
            report.entries.push(WorktreeGcEntry {
                name: candidate.name,
                branch: candidate.branch,
                path: candidate.path,
                status: WorktreeGcStatus::WouldRemove,
                reason: WorktreeGcReason::FinishedBranch,
                target_path: target.map(|target| target.path),
                target_liveness: None,
                apparent_worktree_bytes: Some(candidate.size.worktree_bytes),
                apparent_target_bytes: candidate.size.target_bytes,
                untracked_paths: candidate.untracked_paths,
                gate_denial: None,
                retention_operation_id: None,
            });
            continue;
        }
        report.retained_count = report
            .retained_count
            .checked_add(1)
            .context("worktree GC retained count overflowed")?;
        let (reason, target_path) = match (target, candidate.size.target_bytes) {
            (Some(target), Some(target_bytes)) if options.remove_targets => {
                report.estimated_reclaimable_bytes = report
                    .estimated_reclaimable_bytes
                    .checked_add(target_bytes)
                    .context("worktree GC estimated reclaimable bytes overflowed")?;
                (WorktreeGcReason::TargetWouldRemove, Some(target.path))
            }
            _ if !candidate.branch_merged && !options.targets_only => {
                (WorktreeGcReason::UnmergedBranch, None)
            }
            _ if options.remove_targets => (WorktreeGcReason::NoTarget, None),
            _ => (WorktreeGcReason::RetentionKeep, None),
        };
        report.entries.push(WorktreeGcEntry {
            name: candidate.name,
            branch: candidate.branch,
            path: candidate.path,
            status: WorktreeGcStatus::Retained,
            reason,
            target_path,
            target_liveness: None,
            apparent_worktree_bytes: Some(candidate.size.worktree_bytes),
            apparent_target_bytes: candidate.size.target_bytes,
            untracked_paths: candidate.untracked_paths,
            gate_denial: None,
            retention_operation_id: None,
        });
    }
    Ok(report)
}

fn resolve_sweep_repository(
    workspace: &Path,
    group_root: &Path,
    group: &str,
    root_kind: WorktreeSweepRootKind,
    repository_hint: Option<&Path>,
) -> std::result::Result<PathBuf, WorktreeSweepFailure> {
    // A repository-local root is discovered from an exact primary repository
    // path. Validate that authority directly instead of letting a stale linked
    // worktree registration prevent every healthy sibling from being swept.
    if root_kind == WorktreeSweepRootKind::RepositoryLocal {
        return resolve_sweep_repository_from_workspace(
            workspace,
            group_root,
            group,
            root_kind,
            repository_hint,
        );
    }
    let lane_names = bounded_plain_direct_child_names(
        group_root,
        MAX_WORKSPACE_SWEEP_LANES_PER_GROUP,
        "workspace worktree group",
    )
    .map_err(|error| sweep_failure(WorktreeSweepFailureKind::RepositoryAssociation, error))?;
    let mut lane_associations = BTreeMap::new();
    for lane_name in lane_names {
        if lane_name.to_string_lossy().starts_with(".maco-") {
            continue;
        }
        let lane_path = group_root.join(&lane_name);
        let git_marker = lane_path.join(".git");
        match fs::symlink_metadata(&git_marker) {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(sweep_failure(
                    WorktreeSweepFailureKind::RepositoryOpen,
                    anyhow::Error::new(error).context(format!(
                        "failed to inspect lane Git metadata {}",
                        git_marker.display()
                    )),
                ))
            }
        }
        let lane_repo = crate::git_repository::open(&lane_path).map_err(|error| {
            sweep_failure(
                WorktreeSweepFailureKind::RepositoryOpen,
                anyhow::Error::new(error).context(format!(
                    "failed to open lane repository {}",
                    lane_path.display()
                )),
            )
        })?;
        let (common_dir, primary) = validate_lane_sweep_association(
            workspace, group_root, &lane_path, &lane_repo, root_kind,
        )?;
        lane_associations.insert(common_dir, primary);
        if lane_associations.len() > 1 {
            return Err(WorktreeSweepFailure {
                kind: WorktreeSweepFailureKind::AmbiguousRepository,
                message: format!(
                    "workspace worktree group '{}' is associated with multiple primary repositories",
                    group
                ),
            });
        }
    }
    if let Some(primary) = lane_associations.into_values().next() {
        let workspace_primary = resolve_sweep_repository_from_workspace(
            workspace,
            group_root,
            group,
            root_kind,
            repository_hint,
        )?;
        if workspace_primary != primary {
            return Err(WorktreeSweepFailure {
                kind: WorktreeSweepFailureKind::RepositoryAssociation,
                message: format!(
                    "workspace worktree group '{}' resolves to different lane and workspace repositories",
                    group
                ),
            });
        }
        return Ok(primary);
    }

    resolve_sweep_repository_from_workspace(
        workspace,
        group_root,
        group,
        root_kind,
        repository_hint,
    )
}

fn resolve_sweep_repository_from_workspace(
    workspace: &Path,
    group_root: &Path,
    group: &str,
    root_kind: WorktreeSweepRootKind,
    repository_hint: Option<&Path>,
) -> std::result::Result<PathBuf, WorktreeSweepFailure> {
    if root_kind == WorktreeSweepRootKind::RepositoryLocal {
        let candidate_path = repository_hint.ok_or_else(|| WorktreeSweepFailure {
            kind: WorktreeSweepFailureKind::RepositoryAssociation,
            message: "repository-local worktree root lacks a primary repository hint".to_string(),
        })?;
        let primary = crate::git_repository::open(candidate_path).map_err(|error| {
            sweep_failure(
                WorktreeSweepFailureKind::RepositoryOpen,
                anyhow::Error::new(error).context(format!(
                    "failed to open primary repository {}",
                    candidate_path.display()
                )),
            )
        })?;
        return validate_primary_sweep_association(
            workspace,
            group_root,
            candidate_path,
            &primary,
            None,
            root_kind,
        )
        .map(|(_, path)| path);
    }

    let child_names =
        bounded_plain_direct_child_names(workspace, MAX_WORKSPACE_SWEEP_CHILDREN, "workspace")
            .map_err(|error| {
                sweep_failure(WorktreeSweepFailureKind::RepositoryAssociation, error)
            })?;
    let mut candidates = Vec::new();
    for child_name in child_names {
        if child_name == OsStr::new(".maco") {
            continue;
        }
        let candidate_group = match child_name.to_str() {
            Some(name) => sanitize_path_segment(name),
            None => "repository".to_string(),
        };
        if candidate_group != group {
            continue;
        }
        let candidate_path = workspace.join(&child_name);
        match fs::symlink_metadata(candidate_path.join(".git")) {
            Ok(_) => candidates.push(candidate_path),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(sweep_failure(
                    WorktreeSweepFailureKind::RepositoryOpen,
                    anyhow::Error::new(error)
                        .context("failed to inspect primary repository Git metadata"),
                ))
            }
        }
    }
    if candidates.len() > 1 {
        return Err(WorktreeSweepFailure {
            kind: WorktreeSweepFailureKind::AmbiguousRepository,
            message: format!(
                "workspace worktree group '{}' matches multiple primary repository paths",
                group
            ),
        });
    }
    let Some(candidate_path) = candidates.pop() else {
        return Err(WorktreeSweepFailure {
            kind: WorktreeSweepFailureKind::RepositoryAssociation,
            message: format!(
                "workspace worktree group '{}' has no resolvable primary repository",
                group
            ),
        });
    };
    let primary = crate::git_repository::open(&candidate_path).map_err(|error| {
        sweep_failure(
            WorktreeSweepFailureKind::RepositoryOpen,
            anyhow::Error::new(error).context(format!(
                "failed to open primary repository {}",
                candidate_path.display()
            )),
        )
    })?;
    validate_primary_sweep_association(
        workspace,
        group_root,
        &candidate_path,
        &primary,
        None,
        root_kind,
    )
    .map(|(_, path)| path)
}

fn validate_lane_sweep_association(
    workspace: &Path,
    group_root: &Path,
    lane_path: &Path,
    lane: &Repository,
    root_kind: WorktreeSweepRootKind,
) -> std::result::Result<(PathBuf, PathBuf), WorktreeSweepFailure> {
    let lane_workdir = lane.workdir().ok_or_else(|| WorktreeSweepFailure {
        kind: WorktreeSweepFailureKind::RepositoryAssociation,
        message: format!("lane repository {} is bare", lane_path.display()),
    })?;
    let canonical_lane = fs::canonicalize(lane_path).map_err(|error| {
        sweep_failure(
            WorktreeSweepFailureKind::RepositoryAssociation,
            anyhow::Error::new(error).context("failed to resolve lane path"),
        )
    })?;
    let canonical_workdir = fs::canonicalize(lane_workdir).map_err(|error| {
        sweep_failure(
            WorktreeSweepFailureKind::RepositoryAssociation,
            anyhow::Error::new(error).context("failed to resolve lane workdir"),
        )
    })?;
    if canonical_workdir != canonical_lane {
        return Err(WorktreeSweepFailure {
            kind: WorktreeSweepFailureKind::RepositoryAssociation,
            message: format!(
                "lane repository workdir does not match its exact group child {}",
                lane_path.display()
            ),
        });
    }
    let common_dir = fs::canonicalize(lane.commondir()).map_err(|error| {
        sweep_failure(
            WorktreeSweepFailureKind::RepositoryAssociation,
            anyhow::Error::new(error).context("failed to resolve lane repository common directory"),
        )
    })?;
    let primary_path = common_dir
        .parent()
        .ok_or_else(|| WorktreeSweepFailure {
            kind: WorktreeSweepFailureKind::RepositoryAssociation,
            message: "lane repository common directory has no primary parent".to_string(),
        })?
        .to_path_buf();
    let primary = crate::git_repository::open(&primary_path).map_err(|error| {
        sweep_failure(
            WorktreeSweepFailureKind::RepositoryOpen,
            anyhow::Error::new(error).context(format!(
                "failed to open primary repository {}",
                primary_path.display()
            )),
        )
    })?;
    validate_primary_sweep_association(
        workspace,
        group_root,
        &primary_path,
        &primary,
        Some(&common_dir),
        root_kind,
    )
}

fn validate_primary_sweep_association(
    workspace: &Path,
    group_root: &Path,
    primary_path: &Path,
    primary: &Repository,
    expected_common_dir: Option<&Path>,
    root_kind: WorktreeSweepRootKind,
) -> std::result::Result<(PathBuf, PathBuf), WorktreeSweepFailure> {
    let primary_workdir = primary.workdir().ok_or_else(|| WorktreeSweepFailure {
        kind: WorktreeSweepFailureKind::RepositoryAssociation,
        message: format!("primary repository {} is bare", primary_path.display()),
    })?;
    let canonical_primary = fs::canonicalize(primary_path).map_err(|error| {
        sweep_failure(
            WorktreeSweepFailureKind::RepositoryAssociation,
            anyhow::Error::new(error).context("failed to resolve primary repository path"),
        )
    })?;
    let canonical_workdir = fs::canonicalize(primary_workdir).map_err(|error| {
        sweep_failure(
            WorktreeSweepFailureKind::RepositoryAssociation,
            anyhow::Error::new(error).context("failed to resolve primary repository workdir"),
        )
    })?;
    let canonical_common = fs::canonicalize(primary.commondir()).map_err(|error| {
        sweep_failure(
            WorktreeSweepFailureKind::RepositoryAssociation,
            anyhow::Error::new(error)
                .context("failed to resolve primary repository common directory"),
        )
    })?;
    let embedded_git = canonical_primary.join(".git");
    let embedded_git_metadata = fs::symlink_metadata(&embedded_git).map_err(|error| {
        sweep_failure(
            WorktreeSweepFailureKind::RepositoryAssociation,
            anyhow::Error::new(error).context("failed to inspect primary repository .git"),
        )
    })?;
    if !embedded_git_metadata.is_dir() || embedded_git_metadata.file_type().is_symlink() {
        return Err(WorktreeSweepFailure {
            kind: WorktreeSweepFailureKind::RepositoryAssociation,
            message: "resolved primary repository does not have a plain embedded .git directory"
                .to_string(),
        });
    }
    let canonical_embedded_git = fs::canonicalize(&embedded_git).map_err(|error| {
        sweep_failure(
            WorktreeSweepFailureKind::RepositoryAssociation,
            anyhow::Error::new(error).context("failed to resolve primary repository .git"),
        )
    })?;
    if canonical_primary != canonical_workdir
        || canonical_common != canonical_embedded_git
        || canonical_common.parent() != Some(canonical_primary.as_path())
        || primary.path() != primary.commondir()
    {
        return Err(WorktreeSweepFailure {
            kind: WorktreeSweepFailureKind::RepositoryAssociation,
            message: "resolved repository is not an embedded-Git primary worktree".to_string(),
        });
    }
    if expected_common_dir.is_some_and(|expected| expected != canonical_common) {
        return Err(WorktreeSweepFailure {
            kind: WorktreeSweepFailureKind::RepositoryAssociation,
            message: "lane and primary repository common directories do not match".to_string(),
        });
    }
    let primary_is_in_scope = match root_kind {
        WorktreeSweepRootKind::WorkspaceManaged => canonical_primary.parent() == Some(workspace),
        WorktreeSweepRootKind::RepositoryLocal => {
            canonical_primary == workspace || canonical_primary.parent() == Some(workspace)
        }
    };
    if !primary_is_in_scope {
        return Err(WorktreeSweepFailure {
            kind: WorktreeSweepFailureKind::RepositoryAssociation,
            message: "primary repository is neither the workspace nor a direct workspace child"
                .to_string(),
        });
    }
    let canonical_group_root = fs::canonicalize(group_root).map_err(|error| {
        sweep_failure(
            WorktreeSweepFailureKind::RepositoryAssociation,
            anyhow::Error::new(error).context("failed to resolve workspace worktree group"),
        )
    })?;
    let expected_group_root = match root_kind {
        WorktreeSweepRootKind::WorkspaceManaged => default_worktree_root(primary),
        WorktreeSweepRootKind::RepositoryLocal => canonical_primary.join(".worktrees"),
    };
    let canonical_expected_root = fs::canonicalize(&expected_group_root).map_err(|error| {
        sweep_failure(
            WorktreeSweepFailureKind::RepositoryAssociation,
            anyhow::Error::new(error)
                .context("failed to resolve primary repository default worktree root"),
        )
    })?;
    if canonical_group_root != canonical_expected_root {
        return Err(WorktreeSweepFailure {
            kind: WorktreeSweepFailureKind::RepositoryAssociation,
            message: "primary repository is not associated with the exact worktree group"
                .to_string(),
        });
    }
    Ok((canonical_common, canonical_primary))
}

fn sweep_failure(kind: WorktreeSweepFailureKind, error: anyhow::Error) -> WorktreeSweepFailure {
    WorktreeSweepFailure {
        kind,
        message: format!("{error:#}"),
    }
}

fn require_plain_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("{label} is not a plain directory: {}", path.display());
    }
    Ok(())
}

struct WorkspaceSweepGroupEntry {
    name: OsString,
    plain_directory: bool,
}

fn bounded_workspace_sweep_group_entries(
    root: &Path,
    limit: usize,
    label: &str,
) -> Result<Vec<WorkspaceSweepGroupEntry>> {
    require_plain_directory(root, label)?;
    let mut entries = Vec::new();
    for entry in
        fs::read_dir(root).with_context(|| format!("failed to read {label} {}", root.display()))?
    {
        if entries.len() >= limit {
            bail!("{label} exceeds the {limit} entry limit");
        }
        let entry = entry.with_context(|| format!("failed to read an entry in {label}"))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("failed to inspect an entry in {label}"))?;
        entries.push(WorkspaceSweepGroupEntry {
            name: entry.file_name(),
            plain_directory: file_type.is_dir() && !file_type.is_symlink(),
        });
    }
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(entries)
}

fn bounded_plain_direct_child_names(
    root: &Path,
    limit: usize,
    label: &str,
) -> Result<Vec<OsString>> {
    require_plain_directory(root, label)?;
    let mut names = Vec::new();
    let mut observed_entries = 0usize;
    for entry in
        fs::read_dir(root).with_context(|| format!("failed to read {label} {}", root.display()))?
    {
        observed_entries = observed_entries
            .checked_add(1)
            .context("workspace sweep direct entry count overflowed")?;
        if observed_entries > limit {
            bail!("{label} exceeds the {limit} entry limit");
        }
        let entry = entry.with_context(|| format!("failed to read an entry in {label}"))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("failed to inspect an entry in {label}"))?;
        if file_type.is_dir() && !file_type.is_symlink() {
            names.push(entry.file_name());
        }
    }
    names.sort();
    Ok(names)
}

struct WorktreeGcCandidate {
    binding: ManagedWorktreeBinding,
    branch_oid: Oid,
    branch_merged: bool,
    superseded: bool,
    merged_into_reference: Option<String>,
    removal_lease: Option<ManagedWorktreeRemovalLease>,
    untracked_paths: Vec<PathBuf>,
    apparent_worktree_bytes: u64,
    apparent_target_bytes: Option<u64>,
}

#[derive(Clone, Copy, Default)]
struct WorktreeGcRetentionState {
    eligible_count: usize,
    retained_apparent_bytes: u64,
    size_budget_exhausted: bool,
}

struct WorktreeGcRetentionDecision {
    should_remove: bool,
    committed_state: WorktreeGcRetentionState,
}

enum WorktreeGcDirtinessDisposition {
    Eligible(Vec<PathBuf>),
    Protected {
        reason: WorktreeGcReason,
        untracked_paths: Vec<PathBuf>,
    },
}

enum WorktreeGcRemovalOutcome {
    Removed {
        untracked_paths: Vec<PathBuf>,
    },
    TargetIdentityChanged,
    DirtinessChanged {
        reason: WorktreeGcReason,
        untracked_paths: Vec<PathBuf>,
    },
}

struct WorktreeGcRemovalChecks<'a> {
    allowed_untracked_paths: &'a BTreeSet<PathBuf>,
    target_liveness: &'a dyn Fn(&WorktreeGcTarget) -> WorktreeTargetLiveness,
}

fn remove_gc_candidate(
    repo: &Repository,
    registry_store: &ManagedWorktreeRegistryStore,
    registry_lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
    candidate: &WorktreeGcCandidate,
    target: Option<&WorktreeGcTarget>,
    checks: WorktreeGcRemovalChecks<'_>,
) -> Result<WorktreeGcRemovalOutcome> {
    if registry.operations.len() >= MAX_MANAGED_OPERATIONS {
        bail!("managed worktree registry has no remaining operation capacity");
    }
    let removal_lease = candidate
        .removal_lease
        .as_ref()
        .context("worktree GC removal candidate lacks removal authority")?;
    let binding = &candidate.binding;
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
    if target.is_some_and(|target| !worktree_gc_target_identity_is_current(target)) {
        return Ok(WorktreeGcRemovalOutcome::TargetIdentityChanged);
    }
    let final_dirtiness = gc_worktree_dirtiness(&binding.path)?;
    match &final_dirtiness {
        WorktreeGcDirtiness::TrackedDirty => {
            return Ok(WorktreeGcRemovalOutcome::DirtinessChanged {
                reason: WorktreeGcReason::Dirty,
                untracked_paths: Vec::new(),
            })
        }
        WorktreeGcDirtiness::UntrackedOnly(paths)
            if !paths
                .iter()
                .all(|path| checks.allowed_untracked_paths.contains(path)) =>
        {
            return Ok(WorktreeGcRemovalOutcome::DirtinessChanged {
                reason: WorktreeGcReason::UntrackedOnly,
                untracked_paths: paths.clone(),
            })
        }
        WorktreeGcDirtiness::Clean | WorktreeGcDirtiness::UntrackedOnly(_) => {}
    }
    let final_untracked_paths = match &final_dirtiness {
        WorktreeGcDirtiness::UntrackedOnly(paths) => paths.clone(),
        WorktreeGcDirtiness::Clean | WorktreeGcDirtiness::TrackedDirty => Vec::new(),
    };
    let dirtiness = managed_gc_dirtiness_snapshot(&final_dirtiness)?;
    let target_snapshot = match target {
        Some(target) => ManagedGcTargetSnapshot::Present {
            identity: target.identity.clone(),
        },
        None => ManagedGcTargetSnapshot::Absent,
    };
    let operation = ManagedWorktreeOperation {
        kind: ManagedWorktreeOperationKind::Remove,
        phase: ManagedWorktreeOperationPhase::RemovePrepared,
        name: binding.name.clone(),
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
        delete_branch: false,
        force: true,
        expected_branch_oid: Some(candidate.branch_oid.to_string()),
        gc_dirtiness_checksum: None,
        removal_safety: Some(ManagedRemovalSafety::GarbageCollection {
            dirtiness,
            target: target_snapshot,
        }),
        worktree_quarantine_path: Some(worktree_quarantine_path),
        worktree_quarantine_identity: None,
        metadata_quarantine_path: Some(metadata_quarantine_path),
        metadata_quarantine_identity: None,
    };
    registry
        .operations
        .insert(binding.name.clone(), operation.clone());
    registry_store.save(registry_lock, registry)?;
    recover_remove_operation_with_lease_using_target_liveness(
        repo,
        registry_store,
        registry_lock,
        registry,
        operation,
        Some(removal_lease),
        checks.target_liveness,
    )?;
    Ok(WorktreeGcRemovalOutcome::Removed {
        untracked_paths: final_untracked_paths,
    })
}

fn resolve_worktree_root(repo: &Repository, requested_root: Option<PathBuf>) -> Result<PathBuf> {
    let root = requested_root.unwrap_or_else(|| default_worktree_root(repo));
    let root = if root.is_absolute() {
        root
    } else {
        repo.workdir()
            .context("worktree GC requires a non-bare repository")?
            .join(root)
    };
    match fs::symlink_metadata(&root) {
        Ok(_) => SafeRoot::open_existing(&root)
            .map(|root| root.path().to_path_buf())
            .with_context(|| format!("failed to bind worktree root {}", root.display())),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(root),
        Err(error) => Err(error)
            .with_context(|| format!("failed to inspect worktree root {}", root.display())),
    }
}

fn active_claim_agent_ids(repo: &Repository) -> Result<BTreeSet<String>> {
    let state_root = repo.commondir().join("maco").join("state");
    if !path_entry_exists(&state_root.join(ClaimsStatePresence::Authenticated.root_name()))?
        && !path_entry_exists(&state_root.join(ClaimsStatePresence::Legacy.file_name()))?
    {
        return Ok(BTreeSet::new());
    }
    let repo_path = repo.workdir().unwrap_or_else(|| repo.path());
    let claims = SyncStore::open(repo_path)?.snapshot()?;
    Ok(claims
        .into_iter()
        .map(|claim| claim.agent_id)
        .collect::<BTreeSet<_>>())
}

enum ClaimsStatePresence {
    Authenticated,
    Legacy,
}

impl ClaimsStatePresence {
    fn root_name(&self) -> &'static str {
        match self {
            Self::Authenticated => "authenticated-claims-state-v1",
            Self::Legacy => "claims.json",
        }
    }

    fn file_name(&self) -> &'static str {
        self.root_name()
    }
}

fn is_active_lease_error(error: &anyhow::Error) -> bool {
    let message = error.to_string();
    message.contains("already held")
        || message.contains("active cooperative execution lease")
        || message.contains("state lock")
}

enum WorktreeGcDirtiness {
    Clean,
    TrackedDirty,
    UntrackedOnly(Vec<PathBuf>),
}

fn gc_worktree_dirtiness(path: &Path) -> Result<WorktreeGcDirtiness> {
    let status = bounded_repository_gc_status_paths(
        path,
        MAX_WORKTREE_STATUS_ENTRIES,
        MAX_WORKTREE_STATUS_OUTPUT_BYTES,
        WORKTREE_GC_STATUS_TIMEOUT,
    )?;
    gc_dirtiness_from_status(status)
}

fn gc_dirtiness_from_status(status: BoundedStatusPathRecords) -> Result<WorktreeGcDirtiness> {
    if status.is_empty() {
        return Ok(WorktreeGcDirtiness::Clean);
    }
    if status.iter().any(|(_, status)| *status != [b'?', b'?']) {
        return Ok(WorktreeGcDirtiness::TrackedDirty);
    }
    Ok(WorktreeGcDirtiness::UntrackedOnly(
        status.into_iter().map(|(path, _)| path).collect(),
    ))
}

fn preview_registered_worktree_dirtiness(path: &Path) -> Result<WorktreeGcDirtiness> {
    match bounded_repository_status_paths(
        path,
        MAX_WORKTREE_STATUS_ENTRIES,
        MAX_WORKTREE_STATUS_OUTPUT_BYTES,
        WORKTREE_GC_STATUS_TIMEOUT,
    ) {
        Ok(status) => gc_dirtiness_from_status(status),
        Err(_) => {
            // This fallback is restricted to the non-destructive legacy
            // preview. It cannot authorize apply-mode removal. Some hosts
            // cannot provide the process-containment mount layout required by
            // the bounded Git subprocess, but libgit2 can still expose the
            // ordinary tracked/untracked status needed to make old registered
            // lanes visible.
            let repo = crate::git_repository::open(path).with_context(|| {
                format!(
                    "failed to open registered worktree preview {}",
                    path.display()
                )
            })?;
            let mut options = StatusOptions::new();
            options
                .include_untracked(true)
                .recurse_untracked_dirs(true)
                .include_ignored(false)
                .include_unmodified(false)
                .renames_head_to_index(false)
                .renames_index_to_workdir(false);
            let statuses = repo
                .statuses(Some(&mut options))
                .context("failed to inspect registered worktree preview status")?;
            if statuses.len() > MAX_WORKTREE_STATUS_ENTRIES {
                bail!("registered worktree preview status exceeds its entry limit");
            }
            let mut total_bytes = 0usize;
            let mut untracked = Vec::new();
            for entry in statuses.iter() {
                let entry_path = entry
                    .path()
                    .context("registered worktree preview status path is not valid UTF-8")?;
                total_bytes = total_bytes
                    .checked_add(entry_path.len())
                    .context("registered worktree preview status byte count overflowed")?;
                if total_bytes > MAX_WORKTREE_STATUS_OUTPUT_BYTES {
                    bail!("registered worktree preview status exceeds its output limit");
                }
                if entry.status() != Status::WT_NEW {
                    return Ok(WorktreeGcDirtiness::TrackedDirty);
                }
                let path = PathBuf::from(entry_path);
                if path.is_absolute()
                    || path
                        .components()
                        .any(|component| !matches!(component, std::path::Component::Normal(_)))
                {
                    bail!("registered worktree preview returned an unsafe status path");
                }
                untracked.push(path);
            }
            untracked.sort();
            untracked.dedup();
            if untracked.is_empty() {
                Ok(WorktreeGcDirtiness::Clean)
            } else {
                Ok(WorktreeGcDirtiness::UntrackedOnly(untracked))
            }
        }
    }
}

fn managed_gc_dirtiness_snapshot(
    dirtiness: &WorktreeGcDirtiness,
) -> Result<ManagedGcDirtinessSnapshot> {
    match dirtiness {
        WorktreeGcDirtiness::Clean => Ok(ManagedGcDirtinessSnapshot::Clean),
        WorktreeGcDirtiness::TrackedDirty => {
            bail!("tracked-dirty worktree state cannot be approved for GC")
        }
        WorktreeGcDirtiness::UntrackedOnly(paths) => {
            Ok(ManagedGcDirtinessSnapshot::UntrackedOnly {
                paths: paths
                    .iter()
                    .map(|path| worktree_report_path_wire(path))
                    .collect(),
            })
        }
    }
}

fn normalize_gc_allowed_untracked_paths(paths: &[PathBuf]) -> Result<BTreeSet<PathBuf>> {
    if paths.len() > MAX_GC_ALLOWED_UNTRACKED_PATHS {
        bail!("untracked path allowlist exceeds its {MAX_GC_ALLOWED_UNTRACKED_PATHS}-entry limit");
    }
    let mut normalized = BTreeSet::new();
    let mut total_bytes = 0usize;
    for path in paths {
        if path.as_os_str().is_empty()
            || path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            bail!(
                "allowed untracked path must be an exact repository-relative path: {}",
                path.display()
            );
        }
        let path_bytes = worktree_path_native_bytes(path);
        if path_bytes > MAX_GC_ALLOWED_UNTRACKED_PATH_BYTES {
            bail!(
                "allowed untracked path exceeds its {MAX_GC_ALLOWED_UNTRACKED_PATH_BYTES}-byte limit"
            );
        }
        total_bytes = total_bytes
            .checked_add(path_bytes)
            .context("untracked path allowlist byte count overflowed")?;
        if total_bytes > MAX_GC_ALLOWED_UNTRACKED_TOTAL_BYTES {
            bail!(
                "untracked path allowlist exceeds its {MAX_GC_ALLOWED_UNTRACKED_TOTAL_BYTES}-byte aggregate limit"
            );
        }
        normalized.insert(path.clone());
    }
    Ok(normalized)
}

fn worktree_path_native_bytes(path: &Path) -> usize {
    #[cfg(unix)]
    {
        return path.as_os_str().as_bytes().len();
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::ffi::OsStrExt;
        return path.as_os_str().encode_wide().count().saturating_mul(2);
    }

    #[allow(unreachable_code)]
    path.to_string_lossy().len()
}

fn gc_created_at(binding: &ManagedWorktreeBinding) -> i64 {
    binding.created_at_unix_nanos.unwrap_or(0)
}

fn worktree_retention_is_configured(retention: WorktreeRetentionPolicy) -> bool {
    retention.max_age.is_some()
        || retention.max_count.is_some()
        || retention.max_total_bytes.is_some()
}

fn retention_age_or_count_selects_gc_candidate(
    binding: &ManagedWorktreeBinding,
    index: usize,
    now: i64,
    retention: WorktreeRetentionPolicy,
) -> bool {
    let count_expired = retention
        .max_count
        .is_some_and(|max_count| index >= max_count);
    let age_expired = retention.max_age.is_some_and(|max_age| {
        binding
            .created_at_unix_nanos
            .and_then(|created| now.checked_sub(created))
            .and_then(|age_nanos| u128::try_from(age_nanos.max(0)).ok())
            .is_some_and(|age_nanos| age_nanos >= max_age.as_nanos())
    });
    count_expired || age_expired
}

fn worktree_gc_retention_decision(
    candidate: &WorktreeGcCandidate,
    now: i64,
    targets_only: bool,
    retention: WorktreeRetentionPolicy,
    state: WorktreeGcRetentionState,
) -> Result<WorktreeGcRetentionDecision> {
    if candidate.superseded && !targets_only {
        return Ok(WorktreeGcRetentionDecision {
            should_remove: true,
            committed_state: state,
        });
    }
    if !candidate.branch_merged && !candidate.superseded && !targets_only {
        return Ok(WorktreeGcRetentionDecision {
            should_remove: false,
            committed_state: state,
        });
    }
    let age_or_count_selects = retention_age_or_count_selects_gc_candidate(
        &candidate.binding,
        state.eligible_count,
        now,
        retention,
    );
    let mut committed_state = state;
    committed_state.eligible_count = committed_state
        .eligible_count
        .checked_add(1)
        .context("worktree GC eligible count overflowed")?;
    let size_selects = if age_or_count_selects {
        false
    } else if let Some(max_total_bytes) = retention.max_total_bytes {
        if state.size_budget_exhausted {
            true
        } else {
            let retained_bytes = state
                .retained_apparent_bytes
                .checked_add(candidate.apparent_worktree_bytes)
                .context("worktree GC retained apparent byte count overflowed")?;
            if retained_bytes <= max_total_bytes {
                committed_state.retained_apparent_bytes = retained_bytes;
                false
            } else {
                committed_state.size_budget_exhausted = true;
                true
            }
        }
    } else {
        false
    };
    Ok(WorktreeGcRetentionDecision {
        should_remove: !targets_only
            && (!worktree_retention_is_configured(retention)
                || age_or_count_selects
                || size_selects),
        committed_state,
    })
}

fn worktree_gc_completion_reason(candidate: &WorktreeGcCandidate) -> WorktreeGcReason {
    if candidate.superseded {
        WorktreeGcReason::SupersededLane
    } else {
        WorktreeGcReason::FinishedBranch
    }
}

fn normalize_gc_agent_id_set(ids: &BTreeSet<String>, label: &str) -> Result<BTreeSet<String>> {
    ids.iter()
        .map(|id| {
            let normalized = normalize_agent_id(id)?;
            if normalized != *id {
                bail!("{label} worktree selector '{id}' is not canonical");
            }
            Ok(normalized)
        })
        .collect()
}

fn normalize_gc_supersession_map(
    superseded_by: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>> {
    superseded_by
        .iter()
        .map(|(predecessor, successor)| {
            let normalized_predecessor = normalize_agent_id(predecessor)?;
            let normalized_successor = normalize_agent_id(successor)?;
            if normalized_predecessor != *predecessor || normalized_successor != *successor {
                bail!(
                    "retry supersession selectors '{predecessor}' -> '{successor}' are not canonical"
                );
            }
            Ok((normalized_predecessor, normalized_successor))
        })
        .collect()
}

fn resolve_lifecycle_trunk_tip(repo: &Repository, reference: &str) -> Result<(String, Oid)> {
    if !reference.starts_with("refs/heads/")
        || reference.trim() != reference
        || reference.contains("..")
    {
        bail!("lifecycle trunk reference must be an exact local reference such as refs/heads/main");
    }
    let reference_name =
        git2::Reference::normalize_name(reference, git2::ReferenceFormat::ALLOW_ONELEVEL)
            .context("lifecycle trunk reference is invalid")?;
    if reference_name != reference {
        bail!("lifecycle trunk reference is not canonical");
    }
    let trunk = repo
        .find_reference(reference)
        .with_context(|| format!("lifecycle trunk reference '{reference}' was not found"))?;
    if !trunk.is_branch() {
        bail!("lifecycle trunk reference is not a local branch");
    }
    let oid = trunk
        .peel_to_commit()
        .with_context(|| format!("lifecycle trunk reference '{reference}' is not a commit"))?
        .id();
    Ok((reference.to_string(), oid))
}

fn worktree_gc_candidate_remains_merged(
    repo: &Repository,
    candidate: &WorktreeGcCandidate,
) -> Result<bool> {
    let Some(reference) = candidate.merged_into_reference.as_deref() else {
        return Ok(true);
    };
    let (_, trunk_oid) = resolve_lifecycle_trunk_tip(repo, reference)?;
    Ok(candidate.branch_oid == trunk_oid
        || repo
            .graph_descendant_of(trunk_oid, candidate.branch_oid)
            .context("failed to recheck managed branch ancestry from trunk at apply boundary")?)
}

fn worktree_gc_dirtiness_disposition(
    dirtiness: WorktreeGcDirtiness,
    targets_only: bool,
    allowed_untracked_paths: &BTreeSet<PathBuf>,
) -> WorktreeGcDirtinessDisposition {
    match dirtiness {
        WorktreeGcDirtiness::Clean => WorktreeGcDirtinessDisposition::Eligible(Vec::new()),
        WorktreeGcDirtiness::TrackedDirty => WorktreeGcDirtinessDisposition::Protected {
            reason: WorktreeGcReason::Dirty,
            untracked_paths: Vec::new(),
        },
        WorktreeGcDirtiness::UntrackedOnly(paths)
            if targets_only
                || paths
                    .iter()
                    .all(|path| allowed_untracked_paths.contains(path)) =>
        {
            WorktreeGcDirtinessDisposition::Eligible(paths)
        }
        WorktreeGcDirtiness::UntrackedOnly(paths) => WorktreeGcDirtinessDisposition::Protected {
            reason: WorktreeGcReason::UntrackedOnly,
            untracked_paths: paths,
        },
    }
}

fn worktree_gc_target_bindings_match(
    expected: Option<&WorktreeGcTarget>,
    observed: Option<&WorktreeGcTarget>,
) -> bool {
    match (expected, observed) {
        (None, None) => true,
        (Some(expected), Some(observed)) => {
            expected.path == observed.path
                && expected.canonical_path == observed.canonical_path
                && expected.identity == observed.identity
                && expected.lane_canonical_path == observed.lane_canonical_path
                && expected.lane_identity == observed.lane_identity
        }
        (None, Some(_)) | (Some(_), None) => false,
    }
}

fn add_gc_candidate_protection(
    report: &mut WorktreeGcReport,
    candidate: &WorktreeGcCandidate,
    reason: WorktreeGcReason,
    target_path: Option<PathBuf>,
    target_liveness: Option<WorktreeTargetLivenessEvidence>,
    untracked_paths: Vec<PathBuf>,
) -> Result<()> {
    report.protected_count = report
        .protected_count
        .checked_add(1)
        .context("worktree GC protected count overflowed")?;
    report.entries.push(WorktreeGcEntry {
        name: candidate.binding.name.clone(),
        branch: Some(candidate.binding.branch.clone()),
        path: candidate.binding.path.clone(),
        status: WorktreeGcStatus::Protected,
        reason,
        target_path,
        target_liveness,
        apparent_worktree_bytes: Some(candidate.apparent_worktree_bytes),
        apparent_target_bytes: candidate.apparent_target_bytes,
        untracked_paths,
        gate_denial: None,
        retention_operation_id: None,
    });
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WorktreeGcSizeEstimate {
    worktree_bytes: u64,
    target_bytes: Option<u64>,
}

fn gc_worktree_size_estimate(worktree_path: &Path) -> Result<WorktreeGcSizeEstimate> {
    let target = gc_target_if_present(worktree_path)?;
    let mut worktree_bytes = 0u64;
    let mut target_bytes = 0u64;
    BoundedTreeWalker::walk_with(
        worktree_path,
        BoundedTreeWalkLimits {
            max_depth: 128,
            max_entries: MAX_WORKTREE_GC_SIZE_ENTRIES,
            max_path_bytes: MAX_PERSISTED_PATH_BYTES,
            max_total_path_bytes: MAX_WORKTREE_GC_SIZE_TOTAL_PATH_BYTES,
            max_duration: WORKTREE_GC_SIZE_TIMEOUT,
            // Linux supplies statx mount identities for strict mount confinement.
            // Other Unix platforms still get descriptor-relative, no-follow walking.
            same_device: cfg!(target_os = "linux"),
        },
        |entry| {
            worktree_bytes = worktree_bytes
                .checked_add(entry.size_bytes)
                .context("worktree apparent byte estimate overflowed")?;
            if target.is_some() && entry.relative_path.starts_with(Path::new("target")) {
                target_bytes = target_bytes
                    .checked_add(entry.size_bytes)
                    .context("worktree target apparent byte estimate overflowed")?;
            }
            Ok(if entry.kind == BoundedTreeEntryKind::Directory {
                BoundedTreeWalkAction::RecordAndDescend
            } else {
                BoundedTreeWalkAction::Skip
            })
        },
    )
    .with_context(|| {
        format!(
            "failed to measure apparent bytes beneath managed worktree {}",
            worktree_path.display()
        )
    })?;
    Ok(WorktreeGcSizeEstimate {
        worktree_bytes,
        target_bytes: target.map(|_| target_bytes),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorktreeGcTarget {
    path: PathBuf,
    canonical_path: PathBuf,
    identity: FileIdentity,
    lane_canonical_path: PathBuf,
    lane_identity: FileIdentity,
}

fn gc_target_if_present(worktree_path: &Path) -> Result<Option<WorktreeGcTarget>> {
    let target_path = worktree_path.join("target");
    match fs::symlink_metadata(&target_path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            let identity = identity_for_path(&target_path)?;
            let canonical_path = fs::canonicalize(&target_path).with_context(|| {
                format!(
                    "failed to resolve worktree target {}",
                    target_path.display()
                )
            })?;
            let lane_canonical_path = fs::canonicalize(worktree_path).with_context(|| {
                format!(
                    "failed to resolve managed worktree {}",
                    worktree_path.display()
                )
            })?;
            let lane_identity = identity_for_path(worktree_path)?;
            Ok(Some(WorktreeGcTarget {
                path: target_path,
                canonical_path,
                identity,
                lane_canonical_path,
                lane_identity,
            }))
        }
        Ok(_) => bail!(
            "worktree target path is not a plain directory: {}",
            target_path.display()
        ),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect {}", target_path.display()))
        }
    }
}

fn gc_target_at_apply_boundary(
    worktree_path: &Path,
    preflight_target: Option<&WorktreeGcTarget>,
) -> Result<Option<WorktreeGcTarget>> {
    match gc_target_if_present(worktree_path) {
        Ok(target) => Ok(target),
        Err(error) if preflight_target.is_some() => {
            let target_path = worktree_path.join("target");
            match fs::symlink_metadata(&target_path) {
                Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => Ok(None),
                Err(inspect_error) if inspect_error.kind() == ErrorKind::NotFound => Ok(None),
                Ok(_) | Err(_) => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}

fn worktree_gc_target_identity_is_current(target: &WorktreeGcTarget) -> bool {
    identity_for_path(&target.path)
        .ok()
        .is_some_and(|identity| identity == target.identity)
}

fn target_identity_changed_evidence() -> WorktreeTargetLivenessEvidence {
    target_liveness_evidence(
        None,
        WorktreeTargetLivenessSource::TargetIdentity,
        WorktreeTargetLivenessCause::IdentityChanged,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WorktreeTargetLiveness {
    Clear,
    Live(WorktreeTargetLivenessEvidence),
    Unknown(WorktreeTargetLivenessEvidence),
}

fn gc_target_liveness_protection<F>(
    target: &WorktreeGcTarget,
    target_liveness: &F,
) -> Option<(WorktreeGcReason, WorktreeTargetLivenessEvidence)>
where
    F: Fn(&WorktreeGcTarget) -> WorktreeTargetLiveness,
{
    match target_liveness(target) {
        WorktreeTargetLiveness::Clear => None,
        WorktreeTargetLiveness::Live(evidence) => Some((WorktreeGcReason::LiveTarget, evidence)),
        WorktreeTargetLiveness::Unknown(evidence) => {
            Some((WorktreeGcReason::TargetLivenessUnknown, evidence))
        }
    }
}

fn target_liveness_evidence(
    pid: Option<u32>,
    source: WorktreeTargetLivenessSource,
    cause: WorktreeTargetLivenessCause,
) -> WorktreeTargetLivenessEvidence {
    WorktreeTargetLivenessEvidence { pid, source, cause }
}

#[cfg(target_os = "linux")]
fn worktree_target_liveness(target: &WorktreeGcTarget) -> WorktreeTargetLiveness {
    if identity_for_path(&target.path)
        .ok()
        .as_ref()
        .is_none_or(|identity| identity != &target.identity)
    {
        return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
            None,
            WorktreeTargetLivenessSource::TargetIdentity,
            WorktreeTargetLivenessCause::IdentityChanged,
        ));
    }
    let deadline = match Instant::now().checked_add(WORKTREE_GC_PROC_SCAN_TIMEOUT) {
        Some(deadline) => deadline,
        None => {
            return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
                None,
                WorktreeTargetLivenessSource::ProcScan,
                WorktreeTargetLivenessCause::LimitExceeded,
            ))
        }
    };
    let entries = match fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(_) => {
            return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
                None,
                WorktreeTargetLivenessSource::ProcScan,
                WorktreeTargetLivenessCause::ReadFailed,
            ))
        }
    };
    let current_uid = unsafe { libc::geteuid() };
    let mut observed = 0usize;
    let mut scan_unknown = None;
    for entry in entries {
        if Instant::now() >= deadline {
            return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
                None,
                WorktreeTargetLivenessSource::ProcScan,
                WorktreeTargetLivenessCause::TimedOut,
            ));
        }
        observed = match observed.checked_add(1) {
            Some(observed) if observed <= MAX_WORKTREE_GC_PROC_ENTRIES => observed,
            _ => {
                return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
                    None,
                    WorktreeTargetLivenessSource::ProcScan,
                    WorktreeTargetLivenessCause::LimitExceeded,
                ))
            }
        };
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
                    None,
                    WorktreeTargetLivenessSource::ProcScan,
                    WorktreeTargetLivenessCause::ReadFailed,
                ))
            }
        };
        let pid = match entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        {
            Some(pid) => pid,
            None => continue,
        };
        let process_root = PathBuf::from("/proc").join(pid.to_string());
        let metadata = match fs::metadata(&process_root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(_) => {
                return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
                    Some(pid),
                    WorktreeTargetLivenessSource::ProcScan,
                    WorktreeTargetLivenessCause::ReadFailed,
                ))
            }
        };
        if metadata.uid() != current_uid {
            continue;
        }
        match linux_process_target_liveness(&process_root, pid, target, deadline) {
            WorktreeTargetLiveness::Clear => {}
            WorktreeTargetLiveness::Live(evidence) => {
                return WorktreeTargetLiveness::Live(evidence)
            }
            WorktreeTargetLiveness::Unknown(evidence) => {
                scan_unknown.get_or_insert(evidence);
            }
        }
    }
    match scan_unknown {
        Some(evidence) => WorktreeTargetLiveness::Unknown(evidence),
        None => WorktreeTargetLiveness::Clear,
    }
}

#[cfg(target_os = "linux")]
fn linux_process_target_liveness(
    process_root: &Path,
    pid: u32,
    target: &WorktreeGcTarget,
    deadline: Instant,
) -> WorktreeTargetLiveness {
    if linux_process_is_inert_user_manager(process_root) {
        // The per-user systemd manager can be non-dumpable even to its owner,
        // which makes environ/root/ns reads fail. It does not execute build
        // work itself; any spawned build process is enumerated independently.
        // Recognize only the exact init.scope manager shape so unrelated
        // unreadable processes continue to fail closed.
        return WorktreeTargetLiveness::Clear;
    }
    let cargo_like = linux_process_is_cargo_like(process_root);
    if !cargo_like && linux_process_is_non_build_user_service(process_root) {
        // Non-dumpable user services commonly deny environ/root/ns reads. The
        // service process itself is not a build process; any cargo/rustc child
        // remains a separate /proc entry and is scanned normally. Limit this
        // exception to an exact systemd user-service cgroup and a readable,
        // non-empty command line.
        return WorktreeTargetLiveness::Clear;
    }
    let process_view = match LinuxProcessView::open(process_root) {
        Ok(Some(view)) => view,
        Ok(None) => return WorktreeTargetLiveness::Clear,
        Err(_)
            if !cargo_like
                && linux_process_cmdline(process_root)
                    .ok()
                    .flatten()
                    .is_some_and(|cmdline| !cmdline.is_empty()) =>
        {
            // A readable non-build command line plus an unreadable namespace
            // is the common non-dumpable desktop-application shape. It cannot
            // resolve paths for build work itself; any cargo/rustc descendant
            // is scanned independently.
            return WorktreeTargetLiveness::Clear;
        }
        Err(cause) => {
            return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
                Some(pid),
                WorktreeTargetLivenessSource::MountNamespace,
                cause,
            ))
        }
    };
    let mut environment_unknown = None;
    match linux_process_environ(process_root) {
        Ok(Some(environ)) => {
            for variable in environ.split(|byte| *byte == 0) {
                let Some(value) = variable.strip_prefix(b"CARGO_TARGET_DIR=") else {
                    continue;
                };
                if value.is_empty() {
                    environment_unknown.get_or_insert_with(|| {
                        target_liveness_evidence(
                            Some(pid),
                            WorktreeTargetLivenessSource::ProcessEnvironment,
                            WorktreeTargetLivenessCause::InvalidValue,
                        )
                    });
                    continue;
                }
                let configured = PathBuf::from(OsString::from_vec(value.to_vec()));
                let configured = match process_view.resolve_configured_path(&configured) {
                    Ok(configured) => configured,
                    Err(cause) => {
                        environment_unknown.get_or_insert_with(|| {
                            target_liveness_evidence(
                                Some(pid),
                                WorktreeTargetLivenessSource::MountNamespace,
                                cause,
                            )
                        });
                        continue;
                    }
                };
                match process_path_overlaps_target(&configured, target) {
                    WorktreePathOverlap::Overlap => {
                        return WorktreeTargetLiveness::Live(target_liveness_evidence(
                            Some(pid),
                            WorktreeTargetLivenessSource::CargoTargetDir,
                            WorktreeTargetLivenessCause::PathOverlap,
                        ));
                    }
                    WorktreePathOverlap::Unknown => {
                        environment_unknown.get_or_insert_with(|| {
                            target_liveness_evidence(
                                Some(pid),
                                WorktreeTargetLivenessSource::MountNamespace,
                                WorktreeTargetLivenessCause::NamespaceUnresolved,
                            )
                        });
                    }
                    WorktreePathOverlap::Separate => {}
                }
            }
        }
        Ok(None) => return WorktreeTargetLiveness::Clear,
        Err(cause) => {
            environment_unknown = Some(target_liveness_evidence(
                Some(pid),
                WorktreeTargetLivenessSource::ProcessEnvironment,
                cause,
            ));
        }
    }

    let mut unknown = environment_unknown;
    match linux_process_cmdline_liveness(&process_view, pid, target, cargo_like) {
        WorktreeTargetLiveness::Live(evidence) => return WorktreeTargetLiveness::Live(evidence),
        WorktreeTargetLiveness::Unknown(evidence) => {
            unknown.get_or_insert(evidence);
        }
        WorktreeTargetLiveness::Clear => {}
    }

    match linux_process_target_association(&process_view, pid, target, deadline, cargo_like) {
        WorktreeTargetLiveness::Live(evidence) => WorktreeTargetLiveness::Live(evidence),
        WorktreeTargetLiveness::Unknown(evidence) => WorktreeTargetLiveness::Unknown(evidence),
        WorktreeTargetLiveness::Clear => match unknown {
            Some(evidence) => WorktreeTargetLiveness::Unknown(evidence),
            None => WorktreeTargetLiveness::Clear,
        },
    }
}

#[cfg(target_os = "linux")]
fn linux_process_is_non_build_user_service(process_root: &Path) -> bool {
    if linux_process_cmdline(process_root)
        .ok()
        .flatten()
        .is_none_or(|cmdline| cmdline.is_empty())
    {
        return false;
    }
    let mut cgroup = Vec::new();
    if fs::File::open(process_root.join("cgroup"))
        .and_then(|file| file.take(4097).read_to_end(&mut cgroup))
        .is_err()
        || cgroup.len() > 4096
    {
        return false;
    }
    cgroup.split(|byte| *byte == b'\n').any(|line| {
        line.starts_with(b"0::/user.slice/user-")
            && line
                .rsplit(|byte| *byte == b'/')
                .next()
                .is_some_and(|unit| unit.ends_with(b".service"))
    })
}

#[cfg(target_os = "linux")]
fn linux_process_is_inert_user_manager(process_root: &Path) -> bool {
    let mut comm = Vec::new();
    if fs::File::open(process_root.join("comm"))
        .and_then(|file| file.take(64).read_to_end(&mut comm))
        .is_err()
    {
        return false;
    }
    while matches!(comm.last(), Some(b'\n' | b'\r')) {
        comm.pop();
    }
    let cmdline = linux_process_cmdline(process_root).ok().flatten();
    let recognized_manager_process = if comm == b"systemd" {
        cmdline.as_deref().is_some_and(|bytes| {
            bytes
                .split(|byte| *byte == 0)
                .any(|argument| argument == b"--user")
        })
    } else if comm == b"(sd-pam)" {
        cmdline
            .as_deref()
            .is_some_and(|bytes| bytes == b"(sd-pam)\0")
    } else {
        false
    };
    if !recognized_manager_process {
        return false;
    }
    let mut cgroup = Vec::new();
    if fs::File::open(process_root.join("cgroup"))
        .and_then(|file| file.take(4097).read_to_end(&mut cgroup))
        .is_err()
        || cgroup.len() > 4096
    {
        return false;
    }
    cgroup.split(|byte| *byte == b'\n').any(|line| {
        line.starts_with(b"0::/user.slice/user-") && line.ends_with(b".service/init.scope")
    })
}

#[cfg(target_os = "linux")]
fn linux_process_environ(
    process_root: &Path,
) -> std::result::Result<Option<Vec<u8>>, WorktreeTargetLivenessCause> {
    let mut environ = Vec::new();
    let file = match fs::File::open(process_root.join("environ")) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(WorktreeTargetLivenessCause::ReadFailed),
    };
    file.take(MAX_WORKTREE_GC_PROC_ENVIRON_BYTES.saturating_add(1))
        .read_to_end(&mut environ)
        .map_err(|_| WorktreeTargetLivenessCause::ReadFailed)?;
    if u64::try_from(environ.len())
        .ok()
        .is_none_or(|length| length > MAX_WORKTREE_GC_PROC_ENVIRON_BYTES)
    {
        return Err(WorktreeTargetLivenessCause::LimitExceeded);
    }
    Ok(Some(environ))
}

#[cfg(target_os = "linux")]
fn linux_process_cmdline(
    process_root: &Path,
) -> std::result::Result<Option<Vec<u8>>, WorktreeTargetLivenessCause> {
    let mut cmdline = Vec::new();
    let file = match fs::File::open(process_root.join("cmdline")) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(WorktreeTargetLivenessCause::ReadFailed),
    };
    file.take(MAX_WORKTREE_GC_PROC_CMDLINE_BYTES.saturating_add(1))
        .read_to_end(&mut cmdline)
        .map_err(|_| WorktreeTargetLivenessCause::ReadFailed)?;
    if u64::try_from(cmdline.len())
        .ok()
        .is_none_or(|length| length > MAX_WORKTREE_GC_PROC_CMDLINE_BYTES)
    {
        return Err(WorktreeTargetLivenessCause::LimitExceeded);
    }
    Ok(Some(cmdline))
}

#[cfg(target_os = "linux")]
fn linux_process_cmdline_liveness(
    process_view: &LinuxProcessView,
    pid: u32,
    target: &WorktreeGcTarget,
    cargo_like: bool,
) -> WorktreeTargetLiveness {
    let cmdline = match linux_process_cmdline(&process_view.process_root) {
        Ok(Some(cmdline)) => cmdline,
        Ok(None) => return WorktreeTargetLiveness::Clear,
        Err(cause) => {
            return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
                Some(pid),
                WorktreeTargetLivenessSource::ProcessCommandLine,
                cause,
            ))
        }
    };
    let arguments = cmdline
        .split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty())
        .take(MAX_WORKTREE_GC_PROC_CMDLINE_ARGS.saturating_add(1))
        .collect::<Vec<_>>();
    if arguments.len() > MAX_WORKTREE_GC_PROC_CMDLINE_ARGS {
        return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
            Some(pid),
            WorktreeTargetLivenessSource::ProcessCommandLine,
            WorktreeTargetLivenessCause::LimitExceeded,
        ));
    }
    let cargo_like = cargo_like
        || arguments
            .first()
            .and_then(|argument| argument.rsplit(|byte| *byte == b'/').next())
            .is_some_and(linux_build_process_name);
    if !cargo_like {
        return WorktreeTargetLiveness::Clear;
    }

    let mut explicit_output_seen = false;
    let mut manifest_in_lane = false;
    let mut unknown = None;
    let mut index = 0usize;
    while index < arguments.len() {
        let argument = arguments[index];
        let mut consumed_value = false;
        let directive = [b"--target-dir".as_slice(), b"--out-dir".as_slice()]
            .into_iter()
            .find_map(|flag| {
                command_line_directive_value(argument, flag).map(|value| (flag, value))
            })
            .map(|(_, value)| (true, value))
            .or_else(|| {
                command_line_directive_value(argument, b"--manifest-path")
                    .map(|value| (false, value))
            });
        let Some((is_output, inline_value)) = directive else {
            index += 1;
            continue;
        };
        if is_output {
            explicit_output_seen = true;
        }
        let value = match inline_value {
            Some(value) if !value.is_empty() => value,
            Some(_) => {
                unknown.get_or_insert_with(|| {
                    target_liveness_evidence(
                        Some(pid),
                        WorktreeTargetLivenessSource::ProcessCommandLine,
                        WorktreeTargetLivenessCause::InvalidValue,
                    )
                });
                index += 1;
                continue;
            }
            None => match arguments.get(index.saturating_add(1)).copied() {
                Some(value) if !value.is_empty() => {
                    consumed_value = true;
                    value
                }
                _ => {
                    unknown.get_or_insert_with(|| {
                        target_liveness_evidence(
                            Some(pid),
                            WorktreeTargetLivenessSource::ProcessCommandLine,
                            WorktreeTargetLivenessCause::InvalidValue,
                        )
                    });
                    index += 1;
                    continue;
                }
            },
        };
        let configured = PathBuf::from(OsString::from_vec(value.to_vec()));
        let resolved = match process_view.resolve_configured_path(&configured) {
            Ok(resolved) => resolved,
            Err(cause) => {
                unknown.get_or_insert_with(|| {
                    target_liveness_evidence(
                        Some(pid),
                        WorktreeTargetLivenessSource::MountNamespace,
                        cause,
                    )
                });
                index += if consumed_value { 2 } else { 1 };
                continue;
            }
        };
        let overlap = if is_output {
            process_path_overlaps_target(&resolved, target)
        } else {
            process_path_is_within_or_identical_to_lane(&resolved, target)
        };
        match overlap {
            WorktreePathOverlap::Overlap if is_output => {
                return WorktreeTargetLiveness::Live(target_liveness_evidence(
                    Some(pid),
                    WorktreeTargetLivenessSource::ProcessCommandLine,
                    WorktreeTargetLivenessCause::PathOverlap,
                ));
            }
            WorktreePathOverlap::Overlap => manifest_in_lane = true,
            WorktreePathOverlap::Unknown => {
                unknown.get_or_insert_with(|| {
                    target_liveness_evidence(
                        Some(pid),
                        WorktreeTargetLivenessSource::MountNamespace,
                        WorktreeTargetLivenessCause::NamespaceUnresolved,
                    )
                });
            }
            WorktreePathOverlap::Separate => {}
        }
        index += if consumed_value { 2 } else { 1 };
    }

    if manifest_in_lane && !explicit_output_seen {
        WorktreeTargetLiveness::Live(target_liveness_evidence(
            Some(pid),
            WorktreeTargetLivenessSource::DefaultCargoTarget,
            WorktreeTargetLivenessCause::CargoLikeProcessInLane,
        ))
    } else {
        match unknown {
            Some(evidence) => WorktreeTargetLiveness::Unknown(evidence),
            None => WorktreeTargetLiveness::Clear,
        }
    }
}

#[cfg(target_os = "linux")]
fn command_line_directive_value<'a>(argument: &'a [u8], flag: &[u8]) -> Option<Option<&'a [u8]>> {
    if argument == flag {
        return Some(None);
    }
    argument
        .strip_prefix(flag)
        .and_then(|value| value.strip_prefix(b"="))
        .map(Some)
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct LinuxProcessView {
    process_root: PathBuf,
    same_mount_namespace: bool,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct LinuxProcessPath {
    rooted_access_path: PathBuf,
    observer_canonical_path: Option<PathBuf>,
    process_path: PathBuf,
    deleted: bool,
    same_mount_namespace: bool,
}

#[cfg(target_os = "linux")]
enum LinuxProcLinkTarget {
    Pseudo,
    Filesystem { path: PathBuf, deleted: bool },
}

#[cfg(target_os = "linux")]
impl LinuxProcessView {
    fn open(process_root: &Path) -> std::result::Result<Option<Self>, WorktreeTargetLivenessCause> {
        let process_namespace = match fs::metadata(process_root.join("ns/mnt")) {
            Ok(metadata) => FileIdentity {
                device: metadata.dev(),
                file: metadata.ino(),
            },
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(WorktreeTargetLivenessCause::ReadFailed),
        };
        let observer_namespace = fs::metadata("/proc/self/ns/mnt")
            .map(|metadata| FileIdentity {
                device: metadata.dev(),
                file: metadata.ino(),
            })
            .map_err(|_| WorktreeTargetLivenessCause::ReadFailed)?;
        Ok(Some(Self {
            process_root: process_root.to_path_buf(),
            same_mount_namespace: process_namespace == observer_namespace,
        }))
    }

    #[cfg(test)]
    fn for_test(process_root: &Path, same_mount_namespace: bool) -> Self {
        Self {
            process_root: process_root.to_path_buf(),
            same_mount_namespace,
        }
    }

    fn resolve_configured_path(
        &self,
        configured: &Path,
    ) -> std::result::Result<LinuxProcessPath, WorktreeTargetLivenessCause> {
        if configured.is_absolute() {
            return self.resolve_absolute_process_path(configured, false);
        }
        let cwd = match self.read_link("cwd")? {
            LinuxProcLinkTarget::Filesystem {
                path,
                deleted: false,
            } => path,
            LinuxProcLinkTarget::Filesystem { deleted: true, .. } | LinuxProcLinkTarget::Pseudo => {
                return Err(WorktreeTargetLivenessCause::NamespaceUnresolved)
            }
        };
        self.resolve_absolute_process_path(&cwd.join(configured), false)
    }

    fn resolve_filesystem_link_target(
        &self,
        target: &Path,
    ) -> std::result::Result<Option<LinuxProcessPath>, WorktreeTargetLivenessCause> {
        match classify_linux_proc_link_target(target)? {
            LinuxProcLinkTarget::Pseudo => Ok(None),
            LinuxProcLinkTarget::Filesystem { path, deleted } => {
                self.resolve_absolute_process_path(&path, deleted).map(Some)
            }
        }
    }

    fn read_link(
        &self,
        link: &str,
    ) -> std::result::Result<LinuxProcLinkTarget, WorktreeTargetLivenessCause> {
        let target = fs::read_link(self.process_root.join(link))
            .map_err(|_| WorktreeTargetLivenessCause::ReadFailed)?;
        classify_linux_proc_link_target(&target)
    }

    fn resolve_absolute_process_path(
        &self,
        process_path: &Path,
        deleted: bool,
    ) -> std::result::Result<LinuxProcessPath, WorktreeTargetLivenessCause> {
        let process_path = normalize_proc_target_path(process_path)
            .ok_or(WorktreeTargetLivenessCause::InvalidValue)?;
        let relative = process_path
            .strip_prefix(Path::new("/"))
            .map_err(|_| WorktreeTargetLivenessCause::InvalidValue)?;
        let rooted_access_path = self.process_root.join("root").join(relative);
        let observer_canonical_path = if self.same_mount_namespace && !deleted {
            Some(
                fs::canonicalize(&rooted_access_path)
                    .map_err(|_| WorktreeTargetLivenessCause::NamespaceUnresolved)?,
            )
        } else {
            None
        };
        Ok(LinuxProcessPath {
            rooted_access_path,
            observer_canonical_path,
            process_path,
            deleted,
            same_mount_namespace: self.same_mount_namespace,
        })
    }
}

#[cfg(target_os = "linux")]
fn classify_linux_proc_link_target(
    target: &Path,
) -> std::result::Result<LinuxProcLinkTarget, WorktreeTargetLivenessCause> {
    let bytes = target.as_os_str().as_bytes();
    if [b"pipe:[".as_slice(), b"socket:[", b"anon_inode:"]
        .into_iter()
        .any(|prefix| bytes.starts_with(prefix))
        || bytes.starts_with(b"memfd:")
        || bytes.starts_with(b"/memfd:")
        || bytes.starts_with(b"/dmabuf:")
    {
        return Ok(LinuxProcLinkTarget::Pseudo);
    }
    let (path, deleted) = match bytes.strip_suffix(b" (deleted)") {
        Some(path) => (path, true),
        None => (bytes, false),
    };
    let path = PathBuf::from(OsString::from_vec(path.to_vec()));
    if !path.is_absolute() {
        return Err(WorktreeTargetLivenessCause::InvalidValue);
    }
    Ok(LinuxProcLinkTarget::Filesystem { path, deleted })
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorktreePathOverlap {
    Overlap,
    Separate,
    Unknown,
}

#[cfg(target_os = "linux")]
fn identity_ancestry_contains<I>(expected: &FileIdentity, ancestry: I) -> Result<bool>
where
    I: IntoIterator<Item = Result<FileIdentity>>,
{
    let mut observed = 0usize;
    for identity in ancestry {
        observed = observed
            .checked_add(1)
            .context("target identity ancestry count overflowed")?;
        if observed > MAX_WORKTREE_GC_IDENTITY_ANCESTORS {
            bail!("target identity ancestry exceeds its bound");
        }
        if identity? == *expected {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(target_os = "linux")]
fn path_overlaps_bound_directory(
    path: &Path,
    bound_path: &Path,
    bound_identity: &FileIdentity,
    bidirectional: bool,
) -> WorktreePathOverlap {
    if path.starts_with(bound_path) || (bidirectional && bound_path.starts_with(path)) {
        return WorktreePathOverlap::Overlap;
    }
    let path_identity = match identity_for_path(path) {
        Ok(identity) => identity,
        Err(_) => return WorktreePathOverlap::Unknown,
    };
    let path_contains_bound =
        identity_ancestry_contains(bound_identity, path.ancestors().map(identity_for_path));
    match path_contains_bound {
        Ok(true) => return WorktreePathOverlap::Overlap,
        Ok(false) => {}
        Err(_) => return WorktreePathOverlap::Unknown,
    }
    if bidirectional {
        match identity_ancestry_contains(
            &path_identity,
            bound_path.ancestors().map(identity_for_path),
        ) {
            Ok(true) => return WorktreePathOverlap::Overlap,
            Ok(false) => {}
            Err(_) => return WorktreePathOverlap::Unknown,
        }
    }
    WorktreePathOverlap::Separate
}

#[cfg(target_os = "linux")]
fn process_path_overlaps_bound_directory(
    path: &LinuxProcessPath,
    bound_path: &Path,
    bound_identity: &FileIdentity,
    bidirectional: bool,
) -> WorktreePathOverlap {
    if path.deleted {
        if path.same_mount_namespace {
            return if path.process_path.starts_with(bound_path)
                || (bidirectional && bound_path.starts_with(&path.process_path))
            {
                WorktreePathOverlap::Overlap
            } else {
                WorktreePathOverlap::Separate
            };
        }
        return WorktreePathOverlap::Unknown;
    }
    if let Some(observer_path) = path.observer_canonical_path.as_deref() {
        return path_overlaps_bound_directory(
            observer_path,
            bound_path,
            bound_identity,
            bidirectional,
        );
    }
    path_overlaps_bound_directory_by_identity(
        &path.rooted_access_path,
        bound_path,
        bound_identity,
        bidirectional,
    )
}

#[cfg(target_os = "linux")]
fn path_overlaps_bound_directory_by_identity(
    path: &Path,
    bound_path: &Path,
    bound_identity: &FileIdentity,
    bidirectional: bool,
) -> WorktreePathOverlap {
    let path_identity = match identity_for_path(path) {
        Ok(identity) => identity,
        Err(_) => return WorktreePathOverlap::Unknown,
    };
    match identity_ancestry_contains(bound_identity, path.ancestors().map(identity_for_path)) {
        Ok(true) => return WorktreePathOverlap::Overlap,
        Ok(false) => {}
        Err(_) => return WorktreePathOverlap::Unknown,
    }
    if bidirectional {
        match identity_ancestry_contains(
            &path_identity,
            bound_path.ancestors().map(identity_for_path),
        ) {
            Ok(true) => return WorktreePathOverlap::Overlap,
            Ok(false) => {}
            Err(_) => return WorktreePathOverlap::Unknown,
        }
    }
    WorktreePathOverlap::Separate
}

#[cfg(target_os = "linux")]
fn process_path_overlaps_target(
    path: &LinuxProcessPath,
    target: &WorktreeGcTarget,
) -> WorktreePathOverlap {
    process_path_overlaps_bound_directory(path, &target.canonical_path, &target.identity, true)
}

#[cfg(target_os = "linux")]
fn process_path_is_within_or_identical_to_target(
    path: &LinuxProcessPath,
    target: &WorktreeGcTarget,
) -> WorktreePathOverlap {
    process_path_overlaps_bound_directory(path, &target.canonical_path, &target.identity, false)
}

#[cfg(target_os = "linux")]
fn process_path_is_within_or_identical_to_lane(
    path: &LinuxProcessPath,
    target: &WorktreeGcTarget,
) -> WorktreePathOverlap {
    process_path_overlaps_bound_directory(
        path,
        &target.lane_canonical_path,
        &target.lane_identity,
        false,
    )
}

#[cfg(target_os = "linux")]
fn linux_process_is_cargo_like(process_root: &Path) -> bool {
    let mut comm = Vec::new();
    if let Ok(file) = fs::File::open(process_root.join("comm")) {
        let _ = file.take(64).read_to_end(&mut comm);
    }
    while matches!(comm.last(), Some(b'\n' | b'\r')) {
        comm.pop();
    }
    if linux_build_process_name(&comm) {
        return true;
    }
    fs::read_link(process_root.join("exe"))
        .ok()
        .and_then(|path| path.file_name().map(|name| name.as_bytes().to_vec()))
        .is_some_and(|name| linux_build_process_name(&name))
        || linux_process_cmdline(process_root)
            .ok()
            .flatten()
            .and_then(|cmdline| {
                cmdline
                    .split(|byte| *byte == 0)
                    .find(|argument| !argument.is_empty())
                    .map(|argument| argument.to_vec())
            })
            .and_then(|argument| {
                argument
                    .rsplit(|byte| *byte == b'/')
                    .next()
                    .map(|name| name.to_vec())
            })
            .is_some_and(|name| linux_build_process_name(&name))
}

#[cfg(target_os = "linux")]
fn linux_build_process_name(name: &[u8]) -> bool {
    matches!(name, b"cargo" | b"rustc" | b"rustdoc" | b"sccache")
        || name.starts_with(b"cargo-")
        || name.starts_with(b"rustc-")
}

#[cfg(target_os = "linux")]
fn linux_process_target_association(
    process_view: &LinuxProcessView,
    pid: u32,
    target: &WorktreeGcTarget,
    deadline: Instant,
    cargo_like: bool,
) -> WorktreeTargetLiveness {
    for (link, source) in [
        ("cwd", WorktreeTargetLivenessSource::ProcessCwd),
        ("exe", WorktreeTargetLivenessSource::ProcessExecutable),
    ] {
        match process_view.read_link(link) {
            Ok(LinuxProcLinkTarget::Filesystem { path, deleted }) => {
                let path = match process_view.resolve_absolute_process_path(&path, deleted) {
                    Ok(path) => path,
                    Err(cause) => {
                        return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
                            Some(pid),
                            WorktreeTargetLivenessSource::MountNamespace,
                            cause,
                        ))
                    }
                };
                match process_path_is_within_or_identical_to_target(&path, target) {
                    WorktreePathOverlap::Overlap => {
                        return WorktreeTargetLiveness::Live(target_liveness_evidence(
                            Some(pid),
                            source,
                            WorktreeTargetLivenessCause::PathOverlap,
                        ));
                    }
                    WorktreePathOverlap::Unknown => {
                        return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
                            Some(pid),
                            WorktreeTargetLivenessSource::MountNamespace,
                            WorktreeTargetLivenessCause::NamespaceUnresolved,
                        ));
                    }
                    WorktreePathOverlap::Separate => {}
                }
                match process_path_is_within_or_identical_to_lane(&path, target) {
                    WorktreePathOverlap::Overlap if cargo_like => {
                        return WorktreeTargetLiveness::Live(target_liveness_evidence(
                            Some(pid),
                            WorktreeTargetLivenessSource::DefaultCargoTarget,
                            WorktreeTargetLivenessCause::CargoLikeProcessInLane,
                        ));
                    }
                    WorktreePathOverlap::Overlap => {
                        return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
                            Some(pid),
                            source,
                            WorktreeTargetLivenessCause::PathOverlap,
                        ));
                    }
                    WorktreePathOverlap::Unknown => {
                        return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
                            Some(pid),
                            WorktreeTargetLivenessSource::MountNamespace,
                            WorktreeTargetLivenessCause::NamespaceUnresolved,
                        ));
                    }
                    WorktreePathOverlap::Separate => {}
                }
            }
            Ok(LinuxProcLinkTarget::Pseudo) => {
                return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
                    Some(pid),
                    source,
                    WorktreeTargetLivenessCause::InvalidValue,
                ));
            }
            Err(cause) => {
                return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
                    Some(pid),
                    source,
                    cause,
                ));
            }
        }
    }

    let descriptors = match fs::read_dir(process_view.process_root.join("fd")) {
        Ok(descriptors) => descriptors,
        Err(_) => return bounded_association_failure(pid),
    };
    let mut observed = 0usize;
    for descriptor in descriptors {
        if Instant::now() >= deadline {
            return bounded_association_failure_with_cause(
                pid,
                WorktreeTargetLivenessCause::TimedOut,
            );
        }
        observed = match observed.checked_add(1) {
            Some(observed) if observed <= MAX_WORKTREE_GC_PROC_FDS => observed,
            _ => {
                return bounded_association_failure_with_cause(
                    pid,
                    WorktreeTargetLivenessCause::LimitExceeded,
                )
            }
        };
        let descriptor = match descriptor {
            Ok(descriptor) => descriptor,
            Err(_) => return bounded_association_failure(pid),
        };
        let link_target = match fs::read_link(descriptor.path()) {
            Ok(target) => target,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(_) => return bounded_association_failure(pid),
        };
        match process_view.resolve_filesystem_link_target(&link_target) {
            Ok(None) => continue,
            Ok(Some(path)) => match process_path_is_within_or_identical_to_target(&path, target) {
                WorktreePathOverlap::Overlap => {
                    return WorktreeTargetLiveness::Live(target_liveness_evidence(
                        Some(pid),
                        WorktreeTargetLivenessSource::ProcessFileDescriptor,
                        WorktreeTargetLivenessCause::PathOverlap,
                    ));
                }
                WorktreePathOverlap::Unknown => {
                    return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
                        Some(pid),
                        WorktreeTargetLivenessSource::MountNamespace,
                        WorktreeTargetLivenessCause::NamespaceUnresolved,
                    ));
                }
                WorktreePathOverlap::Separate => {}
            },
            Err(cause) => return bounded_association_failure_with_cause(pid, cause),
        }
    }
    WorktreeTargetLiveness::Clear
}

#[cfg(target_os = "linux")]
fn bounded_association_failure(pid: u32) -> WorktreeTargetLiveness {
    bounded_association_failure_with_cause(pid, WorktreeTargetLivenessCause::ReadFailed)
}

#[cfg(target_os = "linux")]
fn bounded_association_failure_with_cause(
    pid: u32,
    cause: WorktreeTargetLivenessCause,
) -> WorktreeTargetLiveness {
    WorktreeTargetLiveness::Unknown(target_liveness_evidence(
        Some(pid),
        WorktreeTargetLivenessSource::ProcessFileDescriptor,
        cause,
    ))
}

#[cfg(target_os = "linux")]
fn normalize_proc_target_path(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::RootDir => {
                normalized.push(Path::new(std::path::MAIN_SEPARATOR_STR));
            }
            std::path::Component::Normal(segment) => normalized.push(segment),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !normalized.pop() {
                    return None;
                }
            }
            std::path::Component::Prefix(_) => return None,
        }
    }
    Some(normalized)
}

#[cfg(not(target_os = "linux"))]
fn worktree_target_liveness(_target: &WorktreeGcTarget) -> WorktreeTargetLiveness {
    WorktreeTargetLiveness::Unknown(target_liveness_evidence(
        None,
        WorktreeTargetLivenessSource::Platform,
        WorktreeTargetLivenessCause::Unsupported,
    ))
}

enum WorktreeTargetRemovalOutcome {
    Removed,
    IdentityChanged,
}

fn remove_worktree_target_dir(
    worktree_path: &Path,
    target: &WorktreeGcTarget,
) -> Result<WorktreeTargetRemovalOutcome> {
    let root = SafeRoot::open_existing(worktree_path)?;
    match remove_direct_child_tree(
        &root,
        "target",
        Some(&target.identity),
        TreeLinkPolicy::UnlinkLinks,
    ) {
        Ok(()) => Ok(WorktreeTargetRemovalOutcome::Removed),
        Err(_error)
            if identity_for_path(&target.path)
                .ok()
                .as_ref()
                .is_none_or(|identity| identity != &target.identity) =>
        {
            Ok(WorktreeTargetRemovalOutcome::IdentityChanged)
        }
        Err(error) => Err(error),
    }
}

fn prune_unregistered_worktree_directories(
    repo: &Repository,
    worktree_root: &Path,
    registered_names: &BTreeSet<String>,
    dry_run: bool,
    machine_global_retention: Option<&MachineGlobalRetentionBinding>,
    report: &mut WorktreeGcReport,
) -> Result<()> {
    if !path_entry_exists(worktree_root)? {
        return Ok(());
    }
    let root = SafeRoot::open_existing(worktree_root)?;
    let git_registered = git_registered_worktree_names(repo, root.path())?;
    let mut orphans = Vec::new();
    for child_name in root.direct_child_names_bounded(MAX_MANAGED_RECORDS)? {
        if child_name.to_string_lossy().starts_with(".maco-") {
            continue;
        }
        let Some(name) = child_name.to_str() else {
            bail!("managed worktree root contains a non-UTF-8 child name");
        };
        if normalize_agent_id(name)? != name {
            bail!("managed worktree root contains a noncanonical child name: {name}");
        }
        if registered_names.contains(name) || git_registered.contains(name) {
            continue;
        }
        let path = root.direct_child(&child_name)?;
        orphans.push((name.to_string(), path));
    }
    if orphans.is_empty() {
        return Ok(());
    }
    if dry_run {
        for (name, path) in orphans {
            report.orphan_removed_count = report
                .orphan_removed_count
                .checked_add(1)
                .context("worktree GC orphan count overflowed")?;
            report.entries.push(WorktreeGcEntry {
                name,
                branch: None,
                path,
                status: WorktreeGcStatus::OrphanWouldPrune,
                reason: WorktreeGcReason::UnregisteredOrphan,
                target_path: None,
                target_liveness: None,
                apparent_worktree_bytes: None,
                apparent_target_bytes: None,
                untracked_paths: Vec::new(),
                gate_denial: None,
                retention_operation_id: None,
            });
        }
        return Ok(());
    }

    let binding = machine_global_retention.context(
        "destructive worktree orphan GC requires an explicit machine-global config/root binding",
    )?;
    let store = MachineGlobalStore::open_config(&binding.config)
        .context("failed to open machine-global binding for worktree orphan GC")?;
    let targets = orphans
        .iter()
        .map(|(_, path)| {
            store
                .coordinate_for_existing_directory(&binding.root_id, path)
                .map(DestructiveTargetInput::Declared)
        })
        .collect::<Result<Vec<_>>>()
        .context("worktree orphan GC target is outside the reviewed machine-global root")?;
    match store.quarantine(&binding.owner, &binding.correction_correlation_id, targets)? {
        GateOutcome::Allowed(operation) => {
            let operation_id = operation.id;
            report.orphan_removed_count = report
                .orphan_removed_count
                .checked_add(orphans.len())
                .context("worktree GC orphan count overflowed")?;
            for (name, path) in orphans {
                report.entries.push(WorktreeGcEntry {
                    name,
                    branch: None,
                    path,
                    status: WorktreeGcStatus::OrphanQuarantined,
                    reason: WorktreeGcReason::UnregisteredOrphan,
                    target_path: None,
                    target_liveness: None,
                    apparent_worktree_bytes: None,
                    apparent_target_bytes: None,
                    untracked_paths: Vec::new(),
                    gate_denial: None,
                    retention_operation_id: Some(operation_id),
                });
            }
        }
        GateOutcome::Denied(denial) => {
            report.protected_count = report
                .protected_count
                .checked_add(orphans.len())
                .context("worktree GC protected count overflowed")?;
            for (name, path) in orphans {
                report.entries.push(WorktreeGcEntry {
                    name,
                    branch: None,
                    path,
                    status: WorktreeGcStatus::Protected,
                    reason: WorktreeGcReason::MachineGlobalGate,
                    target_path: None,
                    target_liveness: None,
                    apparent_worktree_bytes: None,
                    apparent_target_bytes: None,
                    untracked_paths: Vec::new(),
                    gate_denial: Some(denial.clone()),
                    retention_operation_id: None,
                });
            }
        }
    }
    Ok(())
}

fn git_registered_worktree_names(
    repo: &Repository,
    worktree_root: &Path,
) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    let list = repo.worktrees().context("failed to list Git worktrees")?;
    for index in 0..list.len() {
        let Some(name) = list
            .get(index)
            .context("failed to read Git worktree name")?
        else {
            continue;
        };
        let worktree = repo
            .find_worktree(name)
            .with_context(|| format!("failed to inspect Git worktree '{name}'"))?;
        let path = fs::canonicalize(worktree.path()).with_context(|| {
            format!(
                "failed to resolve Git worktree path {}",
                worktree.path().display()
            )
        })?;
        if path.parent() == Some(worktree_root) {
            names.insert(name.to_string());
        }
    }
    Ok(names)
}

fn git_registered_worktree_names_for_reconciliation(
    repo: &Repository,
    worktree_root: &Path,
) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    let list = repo
        .worktrees()
        .context("failed to list Git worktrees during startup reconciliation")?;
    if list.len() > MAX_MANAGED_RECORDS {
        bail!("startup reconciliation exceeds its bounded Git registration limit");
    }
    for index in 0..list.len() {
        let Some(name) = list
            .get(index)
            .context("failed to read a Git worktree name during startup reconciliation")?
        else {
            continue;
        };
        let worktree = repo.find_worktree(name).with_context(|| {
            format!("failed to inspect Git worktree '{name}' during startup reconciliation")
        })?;
        let path = worktree.path();
        let belongs_to_root = path.parent() == Some(worktree_root)
            || fs::canonicalize(path)
                .ok()
                .is_some_and(|canonical| canonical.parent() == Some(worktree_root));
        if belongs_to_root {
            names.insert(name.to_string());
        }
    }
    Ok(names)
}

fn unix_now_nanos() -> Result<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?;
    i64::try_from(duration.as_nanos()).context("current Unix time exceeds supported range")
}

struct VerifiedManagedWorktree {
    path: PathBuf,
    branch_oid: Oid,
}

fn reject_pending_managed_operation(
    registry: &ManagedWorktreeRegistry,
) -> std::result::Result<(), ExistingWorktreeRevalidationError> {
    if let Some(operation) = registry.operations.values().next() {
        return Err(ExistingWorktreeRevalidationError::PendingOperation {
            name: operation.name.clone(),
            kind: managed_operation_kind_label(operation.kind).to_string(),
            phase: managed_operation_phase_label(operation.phase).to_string(),
        });
    }
    Ok(())
}

fn verify_existing_worktree_request(
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
    authenticated: &AuthenticatedManagedState,
    request: &ExistingWorktreeBindingRequest<'_>,
    expected_head_oid: Oid,
    expected_ref_oid: Oid,
) -> std::result::Result<(), ExistingWorktreeRevalidationError> {
    let name = normalize_agent_id(&request.agent_id).map_err(|source| {
        ExistingWorktreeRevalidationError::BindingInvalid {
            agent_id: request.agent_id.clone(),
            source,
        }
    })?;
    if request.lease.record.name != name
        || request.lease.record != request.expected_record
        || request.lease.repository != store.repository
    {
        return Err(ExistingWorktreeRevalidationError::LeaseAuthorityMismatch {
            agent_id: request.agent_id.clone(),
        });
    }
    store
        .verify_lock(lock)
        .map_err(|source| ExistingWorktreeRevalidationError::StateUnavailable { source })?;
    let incarnation = authenticated
        .incarnations
        .get(&name)
        .filter(|incarnation| incarnation.active)
        .ok_or_else(
            || ExistingWorktreeRevalidationError::LeaseIncarnationMismatch {
                agent_id: request.agent_id.clone(),
            },
        )?;
    let lease_name = managed_worktree_lease_name(&name, incarnation)
        .map_err(|source| ExistingWorktreeRevalidationError::StateUnavailable { source })?;
    let lease_path = store
        .state_root
        .direct_child(&lease_name)
        .map_err(|source| ExistingWorktreeRevalidationError::StateUnavailable { source })?;
    if request.lease._process_lease.kind != ManagedProcessLeaseKind::Exclusive
        || request.lease._process_lease.key != lease_name
        || request.lease._lock.path() != lease_path
    {
        return Err(
            ExistingWorktreeRevalidationError::LeaseIncarnationMismatch {
                agent_id: request.agent_id.clone(),
            },
        );
    }
    request
        .lease
        ._lock
        .verify_direct_binding(&store.state_root)
        .map_err(
            |_| ExistingWorktreeRevalidationError::LeaseIncarnationMismatch {
                agent_id: request.agent_id.clone(),
            },
        )?;

    let binding = authenticated.registry.records.get(&name).ok_or_else(|| {
        ExistingWorktreeRevalidationError::BindingInvalid {
            agent_id: request.agent_id.clone(),
            source: anyhow::anyhow!("managed worktree has no authenticated record"),
        }
    })?;
    inspect_expected_worktree_head(
        &request.expected_record.path,
        &request.agent_id,
        &request.expected_record.branch,
        expected_head_oid,
        expected_ref_oid,
    )?;
    let record = verified_worktree_record(
        &crate::git_repository::open(&store.repo_path).map_err(|source| {
            ExistingWorktreeRevalidationError::BindingInvalid {
                agent_id: request.agent_id.clone(),
                source: source.into(),
            }
        })?,
        &store.repository,
        binding,
    )
    .map_err(|source| ExistingWorktreeRevalidationError::BindingInvalid {
        agent_id: request.agent_id.clone(),
        source,
    })?;
    if record != request.expected_record {
        return Err(ExistingWorktreeRevalidationError::RecordMismatch {
            agent_id: request.agent_id.clone(),
        });
    }
    inspect_expected_worktree_head(
        &record.path,
        &request.agent_id,
        &record.branch,
        expected_head_oid,
        expected_ref_oid,
    )
}

fn inspect_expected_worktree_head(
    path: &Path,
    agent_id: &str,
    branch: &str,
    expected_head_oid: Oid,
    expected_ref_oid: Oid,
) -> std::result::Result<(), ExistingWorktreeRevalidationError> {
    let repository = crate::git_repository::open(path).map_err(|source| {
        ExistingWorktreeRevalidationError::BindingInvalid {
            agent_id: agent_id.to_string(),
            source: source.into(),
        }
    })?;
    let head = repository.find_reference("HEAD").map_err(|source| {
        ExistingWorktreeRevalidationError::BindingInvalid {
            agent_id: agent_id.to_string(),
            source: source.into(),
        }
    })?;
    let actual_ref = head.symbolic_target().map_err(|source| {
        ExistingWorktreeRevalidationError::BindingInvalid {
            agent_id: agent_id.to_string(),
            source: source.into(),
        }
    })?;
    let Some(actual_ref) = actual_ref else {
        return Err(ExistingWorktreeRevalidationError::DetachedHead {
            agent_id: agent_id.to_string(),
        });
    };
    let expected_ref = format!("refs/heads/{branch}");
    if actual_ref != expected_ref {
        return Err(ExistingWorktreeRevalidationError::WrongBranch {
            agent_id: agent_id.to_string(),
            expected: expected_ref,
            actual: actual_ref.to_string(),
        });
    }
    let actual_head_oid = repository
        .head()
        .and_then(|head| {
            head.target()
                .ok_or_else(|| git2::Error::from_str("worktree HEAD has no direct target"))
        })
        .map_err(|source| ExistingWorktreeRevalidationError::BindingInvalid {
            agent_id: agent_id.to_string(),
            source: source.into(),
        })?;
    if actual_head_oid != expected_head_oid {
        return Err(ExistingWorktreeRevalidationError::HeadOidMismatch {
            agent_id: agent_id.to_string(),
            expected: expected_head_oid,
            actual: actual_head_oid,
        });
    }
    let actual_ref_oid = repository
        .find_reference(&expected_ref)
        .and_then(|reference| {
            reference
                .target()
                .ok_or_else(|| git2::Error::from_str("managed branch ref has no direct target"))
        })
        .map_err(|source| ExistingWorktreeRevalidationError::BindingInvalid {
            agent_id: agent_id.to_string(),
            source: source.into(),
        })?;
    if actual_ref_oid != expected_ref_oid {
        return Err(ExistingWorktreeRevalidationError::RefOidMismatch {
            agent_id: agent_id.to_string(),
            expected: expected_ref_oid,
            actual: actual_ref_oid,
        });
    }
    Ok(())
}

fn verified_worktree_record(
    repo: &Repository,
    repository: &ManagedRepositoryBinding,
    binding: &ManagedWorktreeBinding,
) -> Result<WorktreeRecord> {
    if binding.creation_lock_pending {
        bail!(
            "managed worktree '{}' still has an incomplete creation lock",
            binding.name
        );
    }
    let verified = verify_managed_worktree_binding(repo, repository, binding, false)?;
    let worktree = repo
        .find_worktree(&binding.name)
        .with_context(|| format!("managed worktree '{}' is not registered", binding.name))?;
    worktree
        .validate()
        .with_context(|| format!("managed worktree '{}' failed Git validation", binding.name))?;
    let registered_name = worktree
        .name()
        .context("managed worktree registration name is not valid UTF-8")?;
    if registered_name != Some(binding.name.as_str()) {
        bail!("managed worktree registration name changed");
    }
    let registered_path = fs::canonicalize(worktree.path()).with_context(|| {
        format!(
            "failed to resolve registered path for managed worktree '{}'",
            binding.name
        )
    })?;
    if registered_path != verified.path {
        bail!(
            "managed worktree '{}' Git registration points outside its verified binding",
            binding.name
        );
    }
    Ok(WorktreeRecord {
        name: binding.name.clone(),
        path: verified.path,
        branch: binding.branch.clone(),
    })
}

impl ManagedWorktreeRegistryStore {
    fn open(repo: &Repository) -> Result<Self> {
        let repository = managed_repository_binding(repo)?;
        let state_root = repository.common_dir.join("maco").join("state");
        Ok(Self {
            repo_path: repo.workdir().unwrap_or_else(|| repo.path()).to_path_buf(),
            state_root: SafeRoot::open_or_create(state_root)?,
            repository,
        })
    }

    fn open_existing(repo: &Repository) -> Result<Option<Self>> {
        let repository = managed_repository_binding(repo)?;
        let state_path = repository.common_dir.join("maco").join("state");
        match fs::symlink_metadata(&state_path) {
            Ok(_) => Ok(Some(Self {
                repo_path: repo.workdir().unwrap_or_else(|| repo.path()).to_path_buf(),
                state_root: SafeRoot::open_existing(&state_path)
                    .context("existing MACO state root is unsafe")?,
                repository,
            })),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).with_context(|| {
                format!(
                    "failed to inspect existing MACO state root {}",
                    state_path.display()
                )
            }),
        }
    }

    fn lock(&self) -> Result<ManagedWorktreeRegistryLock> {
        #[cfg(test)]
        reject_neutered_managed_registry_mutation()?;
        let lock = KernelStateLock::acquire_direct(&self.state_root, "managed_worktrees.lock")?;
        let bound = ManagedWorktreeRegistryLock {
            root_identity: self.state_root.identity().clone(),
            lock_identity: lock.identity().clone(),
            lock,
        };
        self.verify_lock(&bound)?;
        Ok(bound)
    }

    fn lock_existing(&self) -> Result<ManagedWorktreeRegistryLock> {
        let lock = match KernelStateLock::try_acquire_existing_exclusive_direct(
            &self.state_root,
            "managed_worktrees.lock",
        )? {
            ExistingExclusiveLock::Acquired(lock) => lock,
            ExistingExclusiveLock::Busy => {
                bail!("managed worktree registry is active elsewhere")
            }
            ExistingExclusiveLock::Missing => {
                bail!("authenticated managed worktree state is missing its stable registry lock")
            }
        };
        let bound = ManagedWorktreeRegistryLock {
            root_identity: self.state_root.identity().clone(),
            lock_identity: lock.identity().clone(),
            lock,
        };
        self.verify_lock(&bound)?;
        Ok(bound)
    }

    fn lock_existing_for_revalidation(
        &self,
    ) -> std::result::Result<ManagedWorktreeRegistryLock, ExistingWorktreeRevalidationError> {
        let lock = match KernelStateLock::try_acquire_existing_exclusive_direct(
            &self.state_root,
            "managed_worktrees.lock",
        )
        .map_err(|source| ExistingWorktreeRevalidationError::StateUnavailable { source })?
        {
            ExistingExclusiveLock::Acquired(lock) => lock,
            ExistingExclusiveLock::Busy => {
                return Err(ExistingWorktreeRevalidationError::RegistryBusy)
            }
            ExistingExclusiveLock::Missing => {
                return Err(ExistingWorktreeRevalidationError::RegistryLockMissing)
            }
        };
        let bound = ManagedWorktreeRegistryLock {
            root_identity: self.state_root.identity().clone(),
            lock_identity: lock.identity().clone(),
            lock,
        };
        self.verify_lock(&bound)
            .map_err(|source| ExistingWorktreeRevalidationError::StateUnavailable { source })?;
        Ok(bound)
    }

    fn load_existing_read_only(&self) -> Result<Option<ManagedWorktreeRegistry>> {
        if !self
            .state_root
            .direct_child_exists(ManagedSnapshotSpec::ROOT_NAME)?
        {
            if self
                .state_root
                .direct_child_exists("managed_worktrees.json")?
            {
                bail!("legacy managed worktree state requires explicit migration before read-only inspection");
            }
            return Ok(None);
        }
        let lock = self.lock_existing()?;
        Ok(Some(
            self.load_existing_authenticated_state(&lock)?.registry,
        ))
    }

    fn load_existing_authenticated_state(
        &self,
        lock: &ManagedWorktreeRegistryLock,
    ) -> Result<AuthenticatedManagedState> {
        self.verify_lock(lock)?;
        if !self
            .state_root
            .direct_child_exists(ManagedSnapshotSpec::ROOT_NAME)?
        {
            if self
                .state_root
                .direct_child_exists("managed_worktrees.json")?
            {
                bail!(
                    "legacy managed worktree state requires explicit migration before read-only inspection"
                );
            }
            bail!("authenticated managed worktree snapshot is absent");
        }
        let authenticator = repository_authenticator_key_only(&self.repo_path)?;
        let existing: ExistingAuthenticatedSnapshot<AuthenticatedManagedState> =
            AuthenticatedSnapshotStore::<ManagedSnapshotSpec, AuthenticatedManagedState>::
                read_existing_current_with_identity(authenticator, MANAGED_LOGICAL_ID)?;
        self.validate_authenticated_snapshot(&existing.snapshot, &existing.identity.repository)?;
        verify_existing_active_legacy_retirement::<ManagedSnapshotSpec>(
            &self.repo_path,
            "managed_worktrees",
            "managed_worktrees.json",
            LEGACY_RETIREMENT_DOMAIN,
            &existing.identity,
            existing.snapshot.generation,
        )?;
        self.verify_lock(lock)?;
        Ok(existing.snapshot.value)
    }

    fn try_acquire_shared_worktree_read_lock(
        &self,
        registry_lock: &ManagedWorktreeRegistryLock,
        name: &str,
    ) -> Result<(KernelStateLock, ManagedProcessLease)> {
        let incarnation = self.active_incarnation(registry_lock, name)?;
        let lease_name = managed_worktree_lease_name(name, &incarnation)?;
        let lock = KernelStateLock::try_acquire_shared_direct(&self.state_root, &lease_name)?;
        let process_lease = ManagedProcessLease::acquire_shared(&lease_name, lock.path())?;
        Ok((lock, process_lease))
    }

    fn try_acquire_exclusive_worktree_write_lock(
        &self,
        registry_lock: &ManagedWorktreeRegistryLock,
        name: &str,
    ) -> Result<(KernelStateLock, ManagedProcessLease)> {
        let incarnation = self.active_incarnation(registry_lock, name)?;
        let lease_name = managed_worktree_lease_name(name, &incarnation)?;
        let lock = KernelStateLock::try_acquire_exclusive_direct(&self.state_root, &lease_name)?;
        let process_lease = ManagedProcessLease::acquire_exclusive(&lease_name, lock.path())?;
        Ok((lock, process_lease))
    }

    fn try_acquire_worktree_removal_lease(
        &self,
        registry_lock: &ManagedWorktreeRegistryLock,
        name: &str,
    ) -> Result<ManagedWorktreeRemovalLease> {
        let incarnation = self.active_incarnation(registry_lock, name)?;
        let lease_name = managed_worktree_lease_name(name, &incarnation)?;
        let lock = KernelStateLock::try_acquire_exclusive_direct(&self.state_root, &lease_name)?;
        let process_lease = ManagedProcessLease::acquire_exclusive(&lease_name, lock.path())?;
        Ok(ManagedWorktreeRemovalLease {
            name: name.to_string(),
            incarnation_generation: incarnation.generation,
            incarnation_nonce: incarnation.nonce,
            _lock: lock,
            _process_lease: process_lease,
        })
    }

    fn worktree_has_active_execution_lease(
        &self,
        registry_lock: &ManagedWorktreeRegistryLock,
        name: &str,
    ) -> Result<bool> {
        let incarnation = self.active_incarnation(registry_lock, name)?;
        let lease_name = managed_worktree_lease_name(name, &incarnation)?;
        if ManagedProcessLease::is_active(&lease_name) {
            return Ok(true);
        }
        match KernelStateLock::try_acquire_existing_exclusive_direct(&self.state_root, &lease_name)?
        {
            ExistingExclusiveLock::Missing => Ok(false),
            ExistingExclusiveLock::Busy => Ok(true),
            ExistingExclusiveLock::Acquired(_lock) => Ok(false),
        }
    }

    fn load(&self, lock: &ManagedWorktreeRegistryLock) -> Result<ManagedWorktreeRegistry> {
        self.verify_lock(lock)?;
        let result = self
            .ensure_authenticated_state(lock)
            .map(|store| store.current().value.registry.clone());
        finish_with_registry_lock_verification(result, self.verify_lock(lock))
    }

    fn save(
        &self,
        lock: &ManagedWorktreeRegistryLock,
        registry: &mut ManagedWorktreeRegistry,
    ) -> Result<()> {
        self.verify_lock(lock)?;
        run_managed_registry_after_precheck_hook();
        let result = (|| -> Result<()> {
            self.verify_lock(lock)?;
            normalize_managed_registry(registry, &self.repository)?;
            let mut store = self.ensure_authenticated_state(lock)?;
            let mut incarnations = store.current().value.incarnations.clone();
            let retired_incarnations = reconcile_managed_incarnations(&mut incarnations, registry)?;
            let mut retired_leases = store.current().value.retired_leases.clone();
            self.queue_retired_leases(&retired_incarnations, &incarnations, &mut retired_leases)?;
            let revision = store
                .current()
                .value
                .snapshot_revision
                .checked_add(1)
                .context("authenticated managed registry revision exhausted")?;
            let value = AuthenticatedManagedState {
                version: 1,
                snapshot_revision: revision,
                repository: store.current().value.repository.clone(),
                registry: registry.clone(),
                incarnations,
                retired_leases,
            };
            self.verify_lock(lock)?;
            if revision % 4_096 == 0 {
                let authenticator = repository_authenticator_key_only(&self.repo_path)?;
                store = store.rollover(authenticator, revision, value)?;
            } else {
                store.commit(revision, value)?;
            }
            store = self.scavenge_retired_leases(store, lock)?;
            self.validate_authenticated_state(&store)?;
            self.finalize_legacy_retirement(&store, lock)?;
            self.verify_lock(lock)
        })();
        finish_with_registry_lock_verification(result, self.verify_lock(lock))
    }

    fn verify_lock(&self, lock: &ManagedWorktreeRegistryLock) -> Result<()> {
        if lock.root_identity != *self.state_root.identity() {
            bail!("managed worktree registry lock belongs to a different state root");
        }
        lock.lock.verify_direct_binding(&self.state_root)?;
        if lock.lock.identity() != &lock.lock_identity {
            bail!("managed worktree registry lock identity changed unexpectedly");
        }
        Ok(())
    }

    fn empty_registry(&self) -> ManagedWorktreeRegistry {
        ManagedWorktreeRegistry {
            version: MANAGED_WORKTREE_REGISTRY_VERSION,
            checksum: String::new(),
            repository: self.repository.clone(),
            records: BTreeMap::new(),
            operations: BTreeMap::new(),
        }
    }

    fn ensure_authenticated_state(
        &self,
        lock: &ManagedWorktreeRegistryLock,
    ) -> Result<AuthenticatedSnapshotStore<ManagedSnapshotSpec, AuthenticatedManagedState>> {
        self.verify_lock(lock)?;
        if self
            .state_root
            .direct_child_exists(ManagedSnapshotSpec::ROOT_NAME)?
        {
            let authenticator = repository_authenticator_key_only(&self.repo_path)?;
            if AuthenticatedSnapshotStore::<ManagedSnapshotSpec, AuthenticatedManagedState>::initialized(
                &authenticator,
                MANAGED_LOGICAL_ID,
            )? {
                let store = AuthenticatedSnapshotStore::open_instance(
                    authenticator,
                    MANAGED_LOGICAL_ID,
                )?;
                let store = self.scavenge_retired_leases(store, lock)?;
                self.validate_authenticated_state(&store)?;
                self.finalize_legacy_retirement(&store, lock)?;
                self.verify_lock(lock)?;
                return Ok(store);
            }
        }
        let preparation = prepare_legacy_retirement::<ManagedSnapshotSpec>(
            &self.repo_path,
            "managed_worktrees",
            "managed_worktrees.json",
            LEGACY_RETIREMENT_DOMAIN,
            &|| self.verify_lock(lock),
        )?;
        let (adoption, writer) = preparation.into_parts();
        let mut registry = match adoption {
            LegacyAdoption::Missing => self.empty_registry(),
            LegacyAdoption::Present(bytes) => {
                let registry: ManagedWorktreeRegistry = serde_json::from_slice(&bytes)
                    .context("signed legacy managed worktree registry is malformed")?;
                if registry.version != MANAGED_WORKTREE_REGISTRY_VERSION
                    || registry.repository != self.repository
                    || registry.checksum != managed_registry_checksum(&registry)?
                {
                    bail!("signed legacy managed registry failed repository/checksum validation");
                }
                if !registry.operations.is_empty() {
                    bail!("legacy managed registry contains in-flight operations; complete or recover them with the old binary before authenticated adoption");
                }
                registry
            }
        };
        normalize_managed_registry(&mut registry, &self.repository)?;
        let mut incarnations = BTreeMap::new();
        let retired = reconcile_managed_incarnations(&mut incarnations, &registry)?;
        if !retired.is_empty() {
            bail!("new authenticated managed state unexpectedly retired an incarnation");
        }
        let initial = AuthenticatedManagedState {
            version: 1,
            snapshot_revision: 1,
            repository: writer.authenticator().binding().clone(),
            registry,
            incarnations,
            retired_leases: BTreeMap::new(),
        };
        let store = AuthenticatedSnapshotStore::create(
            writer.into_authenticator()?,
            MANAGED_LOGICAL_ID,
            1,
            initial,
        )?;
        self.validate_authenticated_state(&store)?;
        self.finalize_legacy_retirement(&store, lock)?;
        self.verify_lock(lock)?;
        Ok(store)
    }

    fn open_authenticated_state(
        &self,
        lock: &ManagedWorktreeRegistryLock,
    ) -> Result<AuthenticatedSnapshotStore<ManagedSnapshotSpec, AuthenticatedManagedState>> {
        self.verify_lock(lock)?;
        let authenticator = repository_authenticator_key_only(&self.repo_path)?;
        let store = AuthenticatedSnapshotStore::open_instance(authenticator, MANAGED_LOGICAL_ID)?;
        let store = self.scavenge_retired_leases(store, lock)?;
        self.validate_authenticated_state(&store)?;
        self.finalize_legacy_retirement(&store, lock)?;
        self.verify_lock(lock)?;
        Ok(store)
    }

    fn validate_authenticated_state(
        &self,
        store: &AuthenticatedSnapshotStore<ManagedSnapshotSpec, AuthenticatedManagedState>,
    ) -> Result<()> {
        let snapshot = store.current();
        self.validate_authenticated_snapshot(snapshot, &store.identity().repository)
    }

    fn validate_authenticated_snapshot(
        &self,
        snapshot: &AuthenticatedSnapshot<AuthenticatedManagedState>,
        repository_binding: &RepositoryAuthBinding,
    ) -> Result<()> {
        if snapshot.value.version != 1
            || snapshot.value.snapshot_revision != snapshot.generation
            || snapshot.value.snapshot_revision != snapshot.token
            || snapshot.value.repository != *repository_binding
        {
            bail!("authenticated managed registry binding or revision is inconsistent");
        }
        if snapshot.value.registry.repository != self.repository
            || snapshot.value.registry.version != MANAGED_WORKTREE_REGISTRY_VERSION
            || snapshot.value.registry.checksum
                != managed_registry_checksum(&snapshot.value.registry)?
        {
            bail!("authenticated managed registry repository/checksum binding is inconsistent");
        }
        validate_registry_bounds(&snapshot.value.registry)?;
        validate_managed_incarnations(&snapshot.value.incarnations, &snapshot.value.registry)?;
        validate_retired_managed_leases(
            &snapshot.value.retired_leases,
            &snapshot.value.incarnations,
        )
    }

    fn finalize_legacy_retirement(
        &self,
        store: &AuthenticatedSnapshotStore<ManagedSnapshotSpec, AuthenticatedManagedState>,
        lock: &ManagedWorktreeRegistryLock,
    ) -> Result<()> {
        finalize_legacy_retirement::<ManagedSnapshotSpec>(
            &self.repo_path,
            "managed_worktrees",
            "managed_worktrees.json",
            LEGACY_RETIREMENT_DOMAIN,
            store.identity(),
            store.current().generation,
            &|| self.verify_lock(lock),
        )
    }

    fn active_incarnation(
        &self,
        lock: &ManagedWorktreeRegistryLock,
        name: &str,
    ) -> Result<ManagedIncarnation> {
        let store = self.open_authenticated_state(lock)?;
        let incarnation = store
            .current()
            .value
            .incarnations
            .get(name)
            .filter(|incarnation| incarnation.active)
            .cloned()
            .with_context(|| {
                format!("managed worktree '{name}' has no active signed incarnation")
            })?;
        Ok(incarnation)
    }

    fn verify_authenticated_registry(
        &self,
        lock: &ManagedWorktreeRegistryLock,
        registry: &ManagedWorktreeRegistry,
    ) -> Result<()> {
        self.verify_lock(lock)?;
        let store = self.open_authenticated_state(lock)?;
        if &store.current().value.registry != registry {
            bail!("managed worktree registry changed since its authenticated destructive precheck");
        }
        self.verify_lock(lock)
    }

    fn verify_removal_lease_current(
        &self,
        lock: &ManagedWorktreeRegistryLock,
        lease: &ManagedWorktreeRemovalLease,
    ) -> Result<()> {
        let incarnation = self.active_incarnation(lock, &lease.name)?;
        if incarnation.generation != lease.incarnation_generation
            || incarnation.nonce != lease.incarnation_nonce
        {
            bail!("managed worktree removal lease belongs to a stale incarnation");
        }
        Ok(())
    }

    fn queue_retired_leases(
        &self,
        retired: &[(String, ManagedIncarnation)],
        active: &BTreeMap<String, ManagedIncarnation>,
        queue: &mut BTreeMap<String, FileIdentity>,
    ) -> Result<()> {
        for (name, incarnation) in retired {
            let lease_name = managed_worktree_lease_name(name, incarnation)?;
            let lease_name = lease_name
                .into_string()
                .map_err(|_| anyhow::anyhow!("managed worktree lease name is not UTF-8"))?;
            if active.iter().any(|(active_name, active_incarnation)| {
                managed_worktree_lease_name(active_name, active_incarnation)
                    .ok()
                    .is_some_and(|candidate| candidate == OsStr::new(&lease_name))
            }) {
                bail!("retired managed lease collides with an active incarnation");
            }
            let path = self.state_root.direct_child(&lease_name)?;
            match fs::symlink_metadata(&path) {
                Ok(_) => {
                    let identity = identity_for_path(&path)?;
                    if queue.insert(lease_name, identity).is_some() {
                        bail!("managed worktree retired lease was queued twice");
                    }
                }
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("failed to inspect retired lease file"),
            }
        }
        validate_retired_managed_leases(queue, active)
    }

    fn scavenge_retired_leases(
        &self,
        mut store: AuthenticatedSnapshotStore<ManagedSnapshotSpec, AuthenticatedManagedState>,
        lock: &ManagedWorktreeRegistryLock,
    ) -> Result<AuthenticatedSnapshotStore<ManagedSnapshotSpec, AuthenticatedManagedState>> {
        self.verify_lock(lock)?;
        let active = store.current().value.incarnations.clone();
        let mut queue = store.current().value.retired_leases.clone();
        validate_retired_managed_leases(&queue, &active)?;
        let mut cleaned = false;
        for (name, expected_identity) in store.current().value.retired_leases.clone() {
            let acquired =
                KernelStateLock::try_acquire_existing_exclusive_direct(&self.state_root, &name)
                    .context("failed to inspect retired managed lease")?;
            match acquired {
                ExistingExclusiveLock::Busy => continue,
                ExistingExclusiveLock::Missing => {
                    queue.remove(&name);
                    cleaned = true;
                }
                ExistingExclusiveLock::Acquired(lease) => {
                    if lease.identity() != &expected_identity {
                        bail!("retired managed lease path has a foreign or rebound identity");
                    }
                    lease.unlink_exact_direct(&self.state_root)?;
                    queue.remove(&name);
                    cleaned = true;
                }
            }
        }
        if !cleaned {
            return Ok(store);
        }
        let revision = store
            .current()
            .value
            .snapshot_revision
            .checked_add(1)
            .context("authenticated managed registry revision exhausted")?;
        let mut value = store.current().value.clone();
        value.snapshot_revision = revision;
        value.retired_leases = queue;
        self.verify_lock(lock)?;
        if revision % 4_096 == 0 {
            let authenticator = repository_authenticator_key_only(&self.repo_path)?;
            store = store.rollover(authenticator, revision, value)?;
        } else {
            store.commit(revision, value)?;
        }
        self.verify_lock(lock)?;
        Ok(store)
    }
}

fn finish_with_registry_lock_verification<T>(
    result: Result<T>,
    verification: Result<()>,
) -> Result<T> {
    match (result, verification) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(lock_error)) => Err(lock_error),
        (Err(error), Err(lock_error)) => Err(error.context(format!(
            "operation also lost its managed registry lock-path binding: {lock_error:#}"
        ))),
    }
}

#[cfg(test)]
thread_local! {
    static MANAGED_REGISTRY_AFTER_PRECHECK_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
    static MANAGED_REGISTRY_MUTATIONS_NEUTERED: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) struct ManagedRegistryMutationNeuter {
    previous: bool,
}

#[cfg(test)]
impl Drop for ManagedRegistryMutationNeuter {
    fn drop(&mut self) {
        MANAGED_REGISTRY_MUTATIONS_NEUTERED.with(|slot| slot.set(self.previous));
    }
}

#[cfg(test)]
pub(crate) fn neuter_managed_registry_mutations() -> ManagedRegistryMutationNeuter {
    let previous = MANAGED_REGISTRY_MUTATIONS_NEUTERED.with(|slot| slot.replace(true));
    ManagedRegistryMutationNeuter { previous }
}

#[cfg(test)]
fn reject_neutered_managed_registry_mutation() -> Result<()> {
    if MANAGED_REGISTRY_MUTATIONS_NEUTERED.with(std::cell::Cell::get) {
        bail!("managed registry mutation surface was neutered by the test")
    }
    Ok(())
}

#[cfg(test)]
fn set_managed_registry_after_precheck_hook(hook: impl FnOnce() + 'static) {
    MANAGED_REGISTRY_AFTER_PRECHECK_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_managed_registry_after_precheck_hook() {
    let hook = MANAGED_REGISTRY_AFTER_PRECHECK_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(not(test))]
fn run_managed_registry_after_precheck_hook() {}

fn managed_worktree_lease_name(name: &str, incarnation: &ManagedIncarnation) -> Result<OsString> {
    let normalized = normalize_agent_id(name)?;
    if normalized != name {
        bail!("managed worktree lease name is not canonical");
    }
    validate_managed_incarnation(incarnation)?;
    Ok(OsString::from(format!(
        "managed-worktree-{name}-{}-{}.execution.lock",
        incarnation.generation, incarnation.nonce
    )))
}

fn normalize_managed_registry(
    registry: &mut ManagedWorktreeRegistry,
    repository: &ManagedRepositoryBinding,
) -> Result<()> {
    registry.version = MANAGED_WORKTREE_REGISTRY_VERSION;
    registry.repository = repository.clone();
    validate_registry_bounds(registry)?;
    registry.checksum = managed_registry_checksum(registry)?;
    let bytes = serde_json::to_vec(registry)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_MANAGED_REGISTRY_BYTES {
        bail!("managed worktree registry exceeds its serialized size limit");
    }
    Ok(())
}

fn reconcile_managed_incarnations(
    incarnations: &mut BTreeMap<String, ManagedIncarnation>,
    registry: &ManagedWorktreeRegistry,
) -> Result<Vec<(String, ManagedIncarnation)>> {
    let active = registry
        .records
        .keys()
        .chain(registry.operations.keys())
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let retired_names = incarnations
        .keys()
        .filter(|name| !active.contains(*name))
        .cloned()
        .collect::<Vec<_>>();
    let mut retired = Vec::with_capacity(retired_names.len());
    for name in retired_names {
        let incarnation = incarnations
            .remove(&name)
            .context("managed worktree incarnation disappeared during pruning")?;
        retired.push((name, incarnation));
    }
    for name in active {
        match incarnations.get_mut(&name) {
            Some(incarnation) if incarnation.active => {}
            Some(_) => bail!("active managed incarnation is marked inactive"),
            None => {
                incarnations.insert(
                    name,
                    ManagedIncarnation {
                        generation: 1,
                        nonce: random_identifier()?,
                        active: true,
                    },
                );
            }
        }
    }
    validate_managed_incarnations(incarnations, registry)?;
    Ok(retired)
}

fn validate_managed_incarnation(incarnation: &ManagedIncarnation) -> Result<()> {
    if incarnation.generation == 0
        || incarnation.nonce.len() != 64
        || !incarnation
            .nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("managed worktree incarnation is malformed");
    }
    Ok(())
}

fn validate_managed_incarnations(
    incarnations: &BTreeMap<String, ManagedIncarnation>,
    registry: &ManagedWorktreeRegistry,
) -> Result<()> {
    if incarnations.len() > MAX_MANAGED_RECORDS.saturating_add(MAX_MANAGED_OPERATIONS) {
        bail!("managed worktree incarnation registry exceeds its bound");
    }
    for (name, incarnation) in incarnations {
        if normalize_agent_id(name)? != *name {
            bail!("managed worktree incarnation key is not canonical");
        }
        validate_managed_incarnation(incarnation)?;
        let expected_active =
            registry.records.contains_key(name) || registry.operations.contains_key(name);
        if !incarnation.active || !expected_active {
            bail!("managed worktree incarnation activity does not match the signed registry");
        }
    }
    for name in registry.records.keys().chain(registry.operations.keys()) {
        if !incarnations
            .get(name)
            .is_some_and(|incarnation| incarnation.active)
        {
            bail!("signed managed registry entry has no active incarnation");
        }
    }
    Ok(())
}

fn validate_retired_managed_leases(
    leases: &BTreeMap<String, FileIdentity>,
    active: &BTreeMap<String, ManagedIncarnation>,
) -> Result<()> {
    if leases.len() > MAX_MANAGED_RECORDS.saturating_add(MAX_MANAGED_OPERATIONS) {
        bail!("retired managed lease cleanup queue exceeds its bound");
    }
    let active_names = active
        .iter()
        .map(|(name, incarnation)| managed_worktree_lease_name(name, incarnation))
        .collect::<Result<std::collections::BTreeSet<_>>>()?;
    for (name, identity) in leases {
        let parsed = parse_managed_worktree_lease_name(name)?;
        if active_names.contains(OsStr::new(name))
            || identity.device == 0
            || identity.file == 0
            || parsed.0.is_empty()
        {
            bail!("retired managed lease cleanup entry is malformed or active");
        }
    }
    Ok(())
}

fn parse_managed_worktree_lease_name(name: &str) -> Result<(String, ManagedIncarnation)> {
    let body = name
        .strip_prefix("managed-worktree-")
        .and_then(|value| value.strip_suffix(".execution.lock"))
        .context("retired managed lease name is not canonical")?;
    let (prefix, nonce) = body
        .rsplit_once('-')
        .context("retired managed lease nonce is missing")?;
    let (agent_id, generation) = prefix
        .rsplit_once('-')
        .context("retired managed lease generation is missing")?;
    let generation = generation
        .parse::<u64>()
        .context("retired managed lease generation is malformed")?;
    let incarnation = ManagedIncarnation {
        generation,
        nonce: nonce.to_string(),
        active: true,
    };
    if managed_worktree_lease_name(agent_id, &incarnation)?.to_str() != Some(name) {
        bail!("retired managed lease name is not canonical");
    }
    Ok((agent_id.to_string(), incarnation))
}

fn managed_registry_checksum(registry: &ManagedWorktreeRegistry) -> Result<String> {
    let payload = serde_json::to_vec(&(
        registry.version,
        &registry.repository,
        &registry.records,
        &registry.operations,
    ))
    .context("failed to encode managed worktree registry checksum payload")?;
    Ok(stable_checksum(&payload))
}

fn validate_registry_bounds(registry: &ManagedWorktreeRegistry) -> Result<()> {
    if registry.records.len() > MAX_MANAGED_RECORDS {
        bail!(
            "managed worktree registry has {} records, exceeding its limit of {MAX_MANAGED_RECORDS}",
            registry.records.len()
        );
    }
    if registry.operations.len() > MAX_MANAGED_OPERATIONS {
        bail!(
            "managed worktree registry has {} operations, exceeding its limit of {MAX_MANAGED_OPERATIONS}",
            registry.operations.len()
        );
    }
    for (name, binding) in &registry.records {
        if normalize_agent_id(name)? != *name || binding.name != *name {
            bail!("managed worktree registry record key/name is not canonical");
        }
        validate_branch_name(&binding.branch)?;
    }
    for (name, operation) in &registry.operations {
        if normalize_agent_id(name)? != *name || operation.name != *name {
            bail!("managed worktree registry operation key/name is not canonical");
        }
        validate_branch_name(&operation.branch)?;
        if let Some(checksum) = operation.gc_dirtiness_checksum.as_deref() {
            if operation.kind != ManagedWorktreeOperationKind::Remove
                || checksum.len() > 128
                || !checksum.starts_with("maco-v1-")
                || !checksum.bytes().all(|byte| byte.is_ascii_graphic())
                || operation.removal_safety.is_some()
            {
                bail!("managed worktree operation has invalid legacy GC safety state");
            }
        }
        if let Some(safety) = operation.removal_safety.as_ref() {
            if operation.kind != ManagedWorktreeOperationKind::Remove {
                bail!("managed worktree create operation has removal safety state");
            }
            validate_managed_removal_safety(operation, safety)?;
        }
    }
    Ok(())
}

fn validate_managed_removal_safety(
    operation: &ManagedWorktreeOperation,
    safety: &ManagedRemovalSafety,
) -> Result<()> {
    match safety {
        ManagedRemovalSafety::Explicit => Ok(()),
        ManagedRemovalSafety::GarbageCollection { dirtiness, target } => {
            if !operation.force || operation.delete_branch {
                bail!("managed GC removal safety state has incompatible removal flags");
            }
            match dirtiness {
                ManagedGcDirtinessSnapshot::Clean => {}
                ManagedGcDirtinessSnapshot::UntrackedOnly { paths } => {
                    if paths.is_empty() || paths.len() > MAX_GC_ALLOWED_UNTRACKED_PATHS {
                        bail!("managed GC dirtiness snapshot path count is out of bounds");
                    }
                    let mut total_bytes = 0usize;
                    let mut previous = None;
                    for wire in paths {
                        let path = worktree_report_path_from_wire(wire)?;
                        if previous
                            .as_ref()
                            .is_some_and(|prior: &PathBuf| prior >= &path)
                        {
                            bail!("managed GC dirtiness snapshot paths are not canonical");
                        }
                        total_bytes = total_bytes
                            .checked_add(worktree_path_native_bytes(&path))
                            .context("managed GC dirtiness snapshot byte count overflowed")?;
                        if total_bytes > MAX_GC_ALLOWED_UNTRACKED_TOTAL_BYTES {
                            bail!("managed GC dirtiness snapshot exceeds its aggregate byte bound");
                        }
                        previous = Some(path);
                    }
                }
            }
            if let ManagedGcTargetSnapshot::Present { identity } = target {
                if identity.device == 0 || identity.file == 0 {
                    bail!("managed GC target snapshot has an invalid filesystem identity");
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
fn recover_pending_operations(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
) -> Result<()> {
    recover_pending_operations_with_authority(
        repo,
        store,
        lock,
        registry,
        None,
        CreationCleanliness::TestOnly,
    )
}

#[cfg(not(test))]
fn recover_pending_operations(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
) -> Result<()> {
    recover_pending_operations_without_creation_cleanliness(repo, store, lock, registry, None)
}

fn recover_pending_operations_with_creation_cleanliness(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
    cleanliness: CreationCleanliness<'_>,
) -> Result<()> {
    recover_pending_operations_with_authority(repo, store, lock, registry, None, cleanliness)
}

#[cfg(test)]
fn recover_pending_operations_with_held_removal_lease(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
    held_removal_lease: Option<&ManagedWorktreeRemovalLease>,
) -> Result<()> {
    recover_pending_operations_with_authority(
        repo,
        store,
        lock,
        registry,
        held_removal_lease,
        CreationCleanliness::TestOnly,
    )
}

#[cfg(not(test))]
fn recover_pending_operations_with_held_removal_lease(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
    held_removal_lease: Option<&ManagedWorktreeRemovalLease>,
) -> Result<()> {
    recover_pending_operations_without_creation_cleanliness(
        repo,
        store,
        lock,
        registry,
        held_removal_lease,
    )
}

#[cfg(not(test))]
fn recover_pending_operations_without_creation_cleanliness(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
    held_removal_lease: Option<&ManagedWorktreeRemovalLease>,
) -> Result<()> {
    if registry
        .operations
        .values()
        .any(|operation| operation.kind == ManagedWorktreeOperationKind::Create)
        || registry
            .records
            .values()
            .any(|binding| binding.creation_lock_pending)
    {
        bail!(
            "managed worktree create recovery requires a capability-bound repository cleanliness input"
        );
    }

    let names = registry.operations.keys().cloned().collect::<Vec<_>>();
    for name in names {
        store.verify_authenticated_registry(lock, registry)?;
        let operation = registry
            .operations
            .get(&name)
            .cloned()
            .context("managed worktree operation disappeared during recovery")?;
        if operation.name != name {
            bail!("managed worktree operation key/name mismatch for '{name}'");
        }
        if operation.kind != ManagedWorktreeOperationKind::Remove {
            bail!("managed worktree create recovery reached an unbound recovery path");
        }
        recover_remove_operation_with_lease(
            repo,
            store,
            lock,
            registry,
            operation,
            held_removal_lease,
        )?;
    }
    store.verify_authenticated_registry(lock, registry)
}

fn recover_pending_operations_with_authority(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
    held_removal_lease: Option<&ManagedWorktreeRemovalLease>,
    cleanliness: CreationCleanliness<'_>,
) -> Result<()> {
    let names = registry.operations.keys().cloned().collect::<Vec<_>>();
    for name in names {
        store.verify_authenticated_registry(lock, registry)?;
        let operation = registry
            .operations
            .get(&name)
            .cloned()
            .context("managed worktree operation disappeared during recovery")?;
        if operation.name != name {
            bail!("managed worktree operation key/name mismatch for '{name}'");
        }
        match operation.kind {
            ManagedWorktreeOperationKind::Create => {
                recover_create_operation(repo, store, lock, registry, operation, cleanliness)?
            }
            ManagedWorktreeOperationKind::Remove => recover_remove_operation_with_lease(
                repo,
                store,
                lock,
                registry,
                operation,
                held_removal_lease,
            )?,
        }
    }
    reconcile_creation_locks(repo, store, lock, registry, cleanliness)
}

fn recover_remove_operation_with_lease(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
    operation: ManagedWorktreeOperation,
    held_removal_lease: Option<&ManagedWorktreeRemovalLease>,
) -> Result<()> {
    recover_remove_operation_with_lease_using_target_liveness(
        repo,
        store,
        lock,
        registry,
        operation,
        held_removal_lease,
        &worktree_target_liveness,
    )
}

fn recover_remove_operation_with_lease_using_target_liveness(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
    operation: ManagedWorktreeOperation,
    held_removal_lease: Option<&ManagedWorktreeRemovalLease>,
    target_liveness: &dyn Fn(&WorktreeGcTarget) -> WorktreeTargetLiveness,
) -> Result<()> {
    let name = operation.name.clone();
    let _lease = if let Some(lease) =
        held_removal_lease.filter(|lease| lease.name.as_str() == name.as_str())
    {
        store.verify_removal_lease_current(lock, lease)?;
        None
    } else {
        Some(
            store
                .try_acquire_worktree_removal_lease(lock, &name)
                .with_context(|| {
                    format!(
                        "managed worktree '{name}' has an active cooperative execution lease; pending removal remains durable"
                    )
                })?,
        )
    };
    recover_remove_operation(repo, store, lock, registry, operation, target_liveness)
}

fn recover_create_operation(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
    mut operation: ManagedWorktreeOperation,
    cleanliness: CreationCleanliness<'_>,
) -> Result<()> {
    if operation.phase == ManagedWorktreeOperationPhase::CreateIntent {
        store.verify_authenticated_registry(lock, registry)?;
        let root = SafeRoot::open_existing(&operation.root)?;
        if root.identity() != &operation.root_identity
            || root.direct_child(&operation.name)? != operation.path
        {
            bail!(
                "create intent '{}' root/path binding changed; refusing recovery",
                operation.name
            );
        }
        let metadata_dir = store
            .repository
            .common_dir
            .join("worktrees")
            .join(&operation.name);
        if path_entry_exists(&metadata_dir)? {
            bail!(
                "create intent '{}' unexpectedly has Git metadata; refusing recovery",
                operation.name
            );
        }
        match (
            operation.branch_preexisting_oid.as_deref(),
            local_branch_oid(repo, &operation.branch)?,
        ) {
            (Some(expected), Some(observed))
                if Oid::from_str(expected)
                    .context("create intent has malformed pre-existing branch OID")?
                    == observed => {}
            (Some(_), _) => bail!(
                "pre-existing branch '{}' changed during create-intent recovery",
                operation.branch
            ),
            (None, None) => {}
            (None, Some(_)) => bail!(
                "create intent '{}' unexpectedly created branch '{}' before reservation was durable",
                operation.name,
                operation.branch
            ),
        }
        if let Some(staging_root_path) = operation.staging_root.as_ref() {
            if staging_root_path.parent() != Some(root.path()) {
                bail!("create intent staging root escaped its managed root");
            }
            if let Some(staging_path) = operation.staging_path.as_ref() {
                if staging_path.parent() != Some(staging_root_path.as_path())
                    || staging_path.file_name() != Some(OsStr::new(&operation.name))
                {
                    bail!("create intent staging path binding is inconsistent");
                }
            }
            if path_entry_exists(staging_root_path)? {
                bail!(
                    "create intent '{}' found an unbound staging directory with no persisted child identity; preserving it for manual recovery",
                    operation.name
                );
            }
        }
        if path_entry_exists(&operation.path)? {
            bail!(
                "create intent '{}' found an unbound target directory with no persisted child identity; preserving it for manual recovery",
                operation.name
            );
        }
        registry.operations.remove(&operation.name);
        store.save(lock, registry)?;
        return Ok(());
    }

    if !matches!(
        operation.phase,
        ManagedWorktreeOperationPhase::CreatePrepared
            | ManagedWorktreeOperationPhase::CreateStaged
            | ManagedWorktreeOperationPhase::CreateObserved
    ) {
        bail!(
            "create operation '{}' has invalid phase {:?}",
            operation.name,
            operation.phase
        );
    }

    if operation.phase == ManagedWorktreeOperationPhase::CreatePrepared {
        store.verify_authenticated_registry(lock, registry)?;
        let root = SafeRoot::open_existing(&operation.root)?;
        if root.identity() != &operation.root_identity {
            bail!(
                "create operation '{}' root identity changed; refusing recovery",
                operation.name
            );
        }
        if root.direct_child(&operation.name)? != operation.path {
            bail!(
                "create operation '{}' path binding is inconsistent",
                operation.name
            );
        }
        let metadata_dir = store
            .repository
            .common_dir
            .join("worktrees")
            .join(&operation.name);
        let metadata_exists = path_entry_exists(&metadata_dir)?;
        let final_path_exists = path_entry_exists(&operation.path)?;
        let prepared_identity = operation.prepared_path_identity.as_ref().with_context(|| {
            format!(
                "create operation '{}' has no prepared directory identity",
                operation.name
            )
        })?;
        let (staging_root, staging_path, staging_root_identity) =
            open_operation_staging_root(&root, &operation)?;
        let staging_path_exists = path_entry_exists(&staging_path)?;

        if !metadata_exists {
            if staging_path_exists {
                bail!(
                    "create operation '{}' left an unbound staging child with no persisted identity; preserving it for manual recovery",
                    operation.name
                );
            }
            if final_path_exists {
                let reserved = root.bind_existing_direct_child_directory(&operation.name)?;
                if reserved.identity() != prepared_identity || !reserved.is_empty()? {
                    bail!(
                        "create operation '{}' left a changed or non-empty unbound path; preserving it for manual recovery",
                        operation.name
                    );
                }
                record_pre_worktree_bypass(
                    &operation.name,
                    "delete_empty_pre_worktree_reservation_recovery",
                    reserved.path(),
                );
                remove_direct_child_tree(
                    &root,
                    &operation.name,
                    Some(prepared_identity),
                    TreeLinkPolicy::UnlinkLinks,
                )?;
            }
            remove_staging_root_if_empty(
                &root,
                &staging_root,
                &staging_root_identity,
                &operation.name,
            )?;
            cleanup_create_branch_if_owned(repo, &operation)?;
            registry.operations.remove(&operation.name);
            store.save(lock, registry)?;
            return Ok(());
        }
        if !staging_path_exists {
            bail!(
                "create operation '{}' has Git metadata but no staged worktree path; refusing automatic recovery",
                operation.name
            );
        }
        if !final_path_exists
            || root
                .bind_existing_direct_child_directory(&operation.name)?
                .identity()
                != prepared_identity
        {
            bail!(
                "create operation '{}' final reservation identity changed before recovery",
                operation.name
            );
        }
        ensure_creation_worktree_locked(repo, &operation.name)?;
        let _branch_guard = lock_branch_reference(repo, &operation.branch)?;
        let expected_branch_oid = verify_create_branch_exact(repo, &operation)?;
        verify_worktree_clean_at(
            &staging_path,
            &operation.branch,
            expected_branch_oid,
            cleanliness,
        )?;
        let staged = staging_root.bind_existing_managed_direct_child_directory(&operation.name)?;
        let staged_metadata = capture_staged_worktree_metadata(
            &store.repository,
            &operation.name,
            &operation.branch,
            &staging_path,
        )?;
        operation.phase = ManagedWorktreeOperationPhase::CreateStaged;
        operation.staged_path_identity = Some(staged.identity().clone());
        operation.staged_metadata = Some(staged_metadata);
        registry
            .operations
            .insert(operation.name.clone(), operation.clone());
        store.save(lock, registry)?;
    }

    if operation.phase == ManagedWorktreeOperationPhase::CreateStaged {
        store.verify_authenticated_registry(lock, registry)?;
        let root = SafeRoot::open_existing(&operation.root)?;
        if root.identity() != &operation.root_identity {
            bail!(
                "create-staged root identity changed for '{}'",
                operation.name
            );
        }
        ensure_creation_worktree_locked(repo, &operation.name)?;
        let _branch_guard = lock_branch_reference(repo, &operation.branch)?;
        let expected_branch_oid = verify_create_branch_exact(repo, &operation)?;
        let prepared_identity = operation
            .prepared_path_identity
            .as_ref()
            .context("create-staged operation lacks final reservation identity")?;
        let staged_identity = operation
            .staged_path_identity
            .as_ref()
            .context("create-staged operation lacks staged worktree identity")?;
        let (staging_root, staging_path, _staging_root_identity) =
            open_operation_staging_root(&root, &operation)?;
        let metadata_dir = store
            .repository
            .common_dir
            .join("worktrees")
            .join(&operation.name);
        if !path_entry_exists(&metadata_dir)? {
            bail!(
                "create-staged operation '{}' lost Git metadata",
                operation.name
            );
        }
        let staged_metadata = operation
            .staged_metadata
            .as_ref()
            .context("create-staged operation lacks staged metadata identity")?;
        let worktree_git_file = staging_path.join(".git");
        let metadata_gitdir_file = metadata_dir.join("gitdir");
        let staging_exists = path_entry_exists(&staging_path)?;
        let current_worktree_path = if staging_exists {
            staging_path.as_path()
        } else {
            operation.path.as_path()
        };
        let original_gitdir_identity = verify_staged_worktree_metadata(
            staged_metadata,
            &store.repository,
            &operation.branch,
            current_worktree_path,
        )?;
        if !original_gitdir_identity {
            if staging_exists {
                bail!("staged gitdir metadata changed before the final directory rename");
            }
            verify_gitdir_backlinks(
                &operation.path.join(".git"),
                &metadata_dir,
                &metadata_gitdir_file,
                &operation.path,
            )?;
        }
        if staging_exists {
            let final_reserved = root.bind_existing_direct_child_directory(&operation.name)?;
            if final_reserved.identity() != prepared_identity {
                bail!("final worktree reservation changed before staged rename");
            }
            let staged =
                staging_root.bind_existing_managed_direct_child_directory(&operation.name)?;
            if staged.identity() != staged_identity {
                bail!("staged worktree identity changed before final rename");
            }
            verify_gitdir_backlinks(
                &worktree_git_file,
                &metadata_dir,
                &metadata_gitdir_file,
                &staging_path,
            )?;
            record_pre_worktree_bypass(
                &operation.name,
                "replace_empty_pre_worktree_reservation_with_staged_worktree",
                final_reserved.path(),
            );
            let moved_identity =
                replace_reserved_directory_from(&root, &final_reserved, &staging_root, &staged)?;
            if &moved_identity != staged_identity {
                bail!("staged worktree identity changed during final rename");
            }
        } else {
            let final_worktree =
                root.bind_existing_managed_direct_child_directory(&operation.name)?;
            if final_worktree.identity() != staged_identity {
                bail!("neither staging nor final path matches the staged worktree identity");
            }
        }

        let metadata_root = SafeRoot::open_existing(&metadata_dir)?;
        let backlink = gitdir_backlink_bytes(&operation.path.join(".git"))?;
        AtomicStateWriter::write_direct(&metadata_root, "gitdir", &backlink)?;
        verify_gitdir_backlinks(
            &operation.path.join(".git"),
            &metadata_dir,
            &metadata_gitdir_file,
            &operation.path,
        )?;
        verify_worktree_clean_at(
            &operation.path,
            &operation.branch,
            expected_branch_oid,
            cleanliness,
        )?;
        verify_local_branch_oid(repo, &operation.branch, expected_branch_oid)?;
        let base_oid =
            Oid::from_str(&operation.base_oid).context("create operation base OID is malformed")?;
        let mut binding = capture_managed_worktree_binding(
            repo,
            &store.repository,
            &root,
            &operation.name,
            &operation.branch,
            operation.branch_ownership == ManagedBranchOwnership::CreatedByMaco,
            base_oid,
            expected_branch_oid,
        )?;
        binding.created_at_unix_nanos = Some(unix_now_nanos()?);
        operation.phase = ManagedWorktreeOperationPhase::CreateObserved;
        operation.binding = Some(binding);
        registry
            .operations
            .insert(operation.name.clone(), operation.clone());
        // Persist the authenticated observed binding before the final
        // registration/guard phase. There is intentionally no guard mutation
        // before this durable phase, and relative pre-existing hooksPath values
        // now resolve from the final worktree rather than temporary staging.
        store.save(lock, registry)?;
    }

    if operation.phase == ManagedWorktreeOperationPhase::CreateObserved {
        store.verify_authenticated_registry(lock, registry)?;
        ensure_creation_worktree_locked(repo, &operation.name)?;
        let _branch_guard = lock_branch_reference(repo, &operation.branch)?;
        let expected_branch_oid = verify_create_branch_exact(repo, &operation)?;
        verify_worktree_clean_at(
            &operation.path,
            &operation.branch,
            expected_branch_oid,
            cleanliness,
        )?;
        let root = SafeRoot::open_existing(&operation.root)?;
        if root.identity() != &operation.root_identity {
            bail!("create-observed root identity changed before finalization");
        }
        let base_oid =
            Oid::from_str(&operation.base_oid).context("create operation base OID is malformed")?;
        let binding = operation.binding.clone().with_context(|| {
            format!(
                "create operation '{}' reached observed phase without a binding",
                operation.name
            )
        })?;
        let mut observed_binding = capture_managed_worktree_binding(
            repo,
            &store.repository,
            &root,
            &operation.name,
            &operation.branch,
            operation.branch_ownership == ManagedBranchOwnership::CreatedByMaco,
            base_oid,
            expected_branch_oid,
        )?;
        observed_binding.created_at_unix_nanos = binding.created_at_unix_nanos;
        if binding != observed_binding {
            bail!(
                "create operation '{}' binding changed before finalization",
                operation.name
            );
        }
        if let (Some(staging_root_path), Some(staging_root_identity)) = (
            operation.staging_root.as_ref(),
            operation.staging_root_identity.as_ref(),
        ) {
            if path_entry_exists(staging_root_path)? {
                let staging_root = SafeRoot::open_existing(staging_root_path)?;
                if staging_root.identity() != staging_root_identity {
                    bail!("create-observed staging root identity changed before cleanup");
                }
                remove_staging_root_if_empty(
                    &root,
                    &staging_root,
                    staging_root_identity,
                    &operation.name,
                )?;
            }
        }
        if let Some(existing) = registry.records.get(&operation.name) {
            if existing != &binding {
                bail!(
                    "create operation '{}' conflicts with a different finalized binding",
                    operation.name
                );
            }
        } else {
            registry
                .records
                .insert(operation.name.clone(), binding.clone());
        }
        // Keep CreateObserved durable alongside the authenticated record until
        // the guard has been installed and the lane identity has been checked
        // again. A crash cannot expose guard state for an unregistered lane,
        // and a failed install remains recoverable under the creation lock.
        store.save(lock, registry)?;
        install_managed_worktree_guard(&operation.path, &operation.branch).with_context(|| {
            format!(
                "failed to verify worktree guard for registered managed lane '{}'",
                operation.name
            )
        })?;
        verify_worktree_clean_at(
            &operation.path,
            &operation.branch,
            expected_branch_oid,
            cleanliness,
        )?;
        let mut guarded_binding = capture_managed_worktree_binding(
            repo,
            &store.repository,
            &root,
            &operation.name,
            &operation.branch,
            operation.branch_ownership == ManagedBranchOwnership::CreatedByMaco,
            base_oid,
            expected_branch_oid,
        )?;
        guarded_binding.created_at_unix_nanos = binding.created_at_unix_nanos;
        if guarded_binding != binding {
            bail!(
                "create operation '{}' binding changed during guard installation",
                operation.name
            );
        }
        registry.operations.remove(&operation.name);
        store.save(lock, registry)?;
        complete_creation_lock(repo, store, lock, registry, &operation.name, cleanliness)?;
        return Ok(());
    }

    bail!(
        "create operation '{}' did not reach its observed phase",
        operation.name
    )
}

fn open_operation_staging_root(
    root: &SafeRoot,
    operation: &ManagedWorktreeOperation,
) -> Result<(SafeRoot, PathBuf, FileIdentity)> {
    let staging_root_path = operation
        .staging_root
        .as_ref()
        .context("create operation lacks a staging root")?;
    let staging_root_identity = operation
        .staging_root_identity
        .as_ref()
        .context("create operation lacks a staging root identity")?;
    if staging_root_path.parent() != Some(root.path()) {
        bail!("create operation staging root escaped its managed root");
    }
    let staging_root = SafeRoot::open_existing(staging_root_path)?;
    if staging_root.identity() != staging_root_identity {
        bail!("create operation staging root identity changed");
    }
    let staging_path = operation
        .staging_path
        .clone()
        .context("create operation lacks a staging path")?;
    if staging_path.parent() != Some(staging_root.path())
        || staging_path.file_name() != Some(OsStr::new(&operation.name))
    {
        bail!("create operation staging path binding is inconsistent");
    }
    Ok((staging_root, staging_path, staging_root_identity.clone()))
}

fn remove_staging_root_if_empty(
    managed_root: &SafeRoot,
    staging_root: &SafeRoot,
    expected: &FileIdentity,
    actor: &str,
) -> Result<()> {
    if !staging_root.is_empty()? {
        bail!(
            "staging root is not empty after worktree recovery: {}",
            staging_root.path().display()
        );
    }
    let name = staging_root
        .path()
        .file_name()
        .context("staging root has no final component")?;
    record_pre_worktree_bypass(
        actor,
        "delete_empty_pre_worktree_staging_recovery_or_finalize",
        staging_root.path(),
    );
    remove_direct_child_tree(
        managed_root,
        name,
        Some(expected),
        TreeLinkPolicy::UnlinkLinks,
    )
}

fn record_pre_worktree_bypass(actor: &str, operation: &str, path: &Path) {
    tracing::warn!(
        actor,
        operation,
        target = %path.display(),
        process_attribution = "not_process_observable",
        "machine-global cleanup bypass"
    );
}

#[cfg(unix)]
fn gitdir_backlink_bytes(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = path.as_os_str().as_bytes().to_vec();
    if bytes.contains(&b'\n') || bytes.contains(&b'\r') {
        bail!("Git metadata backlink path contains a newline");
    }
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(not(unix))]
fn gitdir_backlink_bytes(path: &Path) -> Result<Vec<u8>> {
    let _ = path;
    bail!("byte-exact Git metadata backlink writes are unsupported on this platform")
}

fn lock_branch_reference<'repo>(
    repo: &'repo Repository,
    branch: &str,
) -> Result<Transaction<'repo>> {
    validate_branch_name(branch)?;
    let reference_name = format!("refs/heads/{branch}");
    let mut transaction = repo
        .transaction()
        .context("failed to start Git reference transaction")?;
    transaction
        .lock_ref(&reference_name)
        .with_context(|| format!("failed to lock branch '{branch}' during worktree creation"))?;
    Ok(transaction)
}

fn expected_create_branch_oid(operation: &ManagedWorktreeOperation) -> Result<Oid> {
    match operation.branch_ownership {
        ManagedBranchOwnership::Unknown => {
            bail!("create operation branch ownership is unknown; refusing finalization")
        }
        ManagedBranchOwnership::CreatedByMaco => {
            let expected = operation
                .owned_branch_oid
                .as_deref()
                .map(Oid::from_str)
                .transpose()
                .context("create operation owned branch OID is malformed")?
                .context("create operation lacks its owned branch OID")?;
            let base = Oid::from_str(&operation.base_oid)
                .context("create operation base OID is malformed")?;
            if expected != base {
                bail!("MACO-created branch did not remain at its requested base OID");
            }
            Ok(expected)
        }
        ManagedBranchOwnership::Preexisting => operation
            .branch_preexisting_oid
            .as_deref()
            .map(Oid::from_str)
            .transpose()
            .context("create operation has malformed pre-existing branch OID")?
            .context("create operation lacks its pre-existing branch OID"),
    }
}

fn verify_local_branch_oid(repo: &Repository, branch: &str, expected: Oid) -> Result<Oid> {
    let current = local_branch_oid(repo, branch)?
        .with_context(|| format!("create operation has no local branch '{branch}'"))?;
    if current != expected {
        bail!(
            "branch '{branch}' changed during worktree creation: expected {expected}, observed {current}"
        );
    }
    Ok(current)
}

fn verify_create_branch_exact(
    repo: &Repository,
    operation: &ManagedWorktreeOperation,
) -> Result<Oid> {
    let expected = expected_create_branch_oid(operation)?;
    verify_local_branch_oid(repo, &operation.branch, expected)
}

fn ensure_creation_worktree_locked(repo: &Repository, name: &str) -> Result<()> {
    let worktree = repo
        .find_worktree(name)
        .with_context(|| format!("failed to find in-progress worktree '{name}'"))?;
    match worktree
        .is_locked()
        .with_context(|| format!("failed to inspect creation lock for worktree '{name}'"))?
    {
        WorktreeLockStatus::Locked(_) => Ok(()),
        WorktreeLockStatus::Unlocked => {
            bail!("in-progress worktree '{name}' lost its Git creation lock")
        }
    }
}

fn verify_worktree_clean_at(
    path: &Path,
    branch: &str,
    expected: Oid,
    cleanliness: CreationCleanliness<'_>,
) -> Result<()> {
    let worktree_repo = crate::git_repository::open(path)
        .with_context(|| format!("failed to open created worktree {}", path.display()))?;
    let expected_reference = format!("refs/heads/{branch}");
    let verify_head = || -> Result<()> {
        let head = worktree_repo
            .head()
            .context("failed to inspect created worktree HEAD")?;
        let head_name = head
            .name()
            .context("created worktree HEAD name is not valid UTF-8")?;
        if !head.is_branch() || head_name != expected_reference {
            bail!("created worktree HEAD is not bound to '{expected_reference}'");
        }
        let observed = head
            .target()
            .context("created worktree HEAD has no direct target")?;
        if observed != expected {
            bail!(
                "created worktree HEAD changed during finalization: expected {expected}, observed {observed}"
            );
        }
        Ok(())
    };
    verify_head()?;
    cleanliness
        .require_clean_related_worktree(path)
        .context("created worktree is not clean at its persisted branch OID")?;

    let mut index = worktree_repo
        .index()
        .context("failed to open created worktree index")?;
    if index.len() > MAX_WORKTREE_STATUS_ENTRIES {
        bail!(
            "created worktree index has {} entries, exceeding its limit of {MAX_WORKTREE_STATUS_ENTRIES}",
            index.len()
        );
    }
    let index_tree = index
        .write_tree()
        .context("failed to materialize created worktree index tree")?;
    let expected_tree = worktree_repo
        .find_commit(expected)
        .context("failed to find created worktree commit")?
        .tree_id();
    if index_tree != expected_tree {
        bail!("created worktree index does not match its persisted branch OID");
    }

    verify_head()
}

fn complete_creation_lock(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
    name: &str,
    cleanliness: CreationCleanliness<'_>,
) -> Result<()> {
    let binding = registry
        .records
        .get(name)
        .cloned()
        .with_context(|| format!("creation lock binding disappeared for '{name}'"))?;
    if !binding.creation_lock_pending {
        return Ok(());
    }
    let verified = verify_managed_worktree_binding(repo, &store.repository, &binding, false)?;
    let expected = Oid::from_str(&binding.created_branch_oid)
        .context("managed creation-lock branch OID is malformed")?;
    verify_local_branch_oid(repo, &binding.branch, expected)?;
    verify_worktree_clean_at(&verified.path, &binding.branch, expected, cleanliness)?;
    let worktree = repo
        .find_worktree(name)
        .with_context(|| format!("failed to find finalized worktree '{name}'"))?;
    match worktree
        .is_locked()
        .with_context(|| format!("failed to inspect finalized worktree lock for '{name}'"))?
    {
        WorktreeLockStatus::Locked(_) => worktree
            .unlock()
            .with_context(|| format!("failed to release creation lock for worktree '{name}'"))?,
        WorktreeLockStatus::Unlocked => {}
    }
    registry
        .records
        .get_mut(name)
        .context("creation lock binding disappeared before completion")?
        .creation_lock_pending = false;
    store.save(lock, registry)
}

fn reconcile_creation_locks(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
    cleanliness: CreationCleanliness<'_>,
) -> Result<()> {
    let names = registry
        .records
        .iter()
        .filter(|(_, binding)| binding.creation_lock_pending)
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    for name in names {
        let branch = registry
            .records
            .get(&name)
            .context("creation lock binding disappeared during recovery")?
            .branch
            .clone();
        let _branch_guard = lock_branch_reference(repo, &branch)?;
        complete_creation_lock(repo, store, lock, registry, &name, cleanliness)?;
    }
    Ok(())
}

fn ensure_gc_target_snapshot_matches(
    operation_name: &str,
    expected: &ManagedGcTargetSnapshot,
    current: Option<&WorktreeGcTarget>,
) -> Result<()> {
    match (expected, current) {
        (ManagedGcTargetSnapshot::Absent, None) => Ok(()),
        (ManagedGcTargetSnapshot::Present { identity }, Some(target))
            if identity == &target.identity =>
        {
            Ok(())
        }
        (ManagedGcTargetSnapshot::Absent, Some(_)) => bail!(
            "pending GC removal '{}' target changed from absent to present before quarantine",
            operation_name
        ),
        (ManagedGcTargetSnapshot::Present { .. }, None) => bail!(
            "pending GC removal '{}' target changed from present to absent before quarantine",
            operation_name
        ),
        (ManagedGcTargetSnapshot::Present { .. }, Some(_)) => bail!(
            "pending GC removal '{}' target filesystem identity changed before quarantine",
            operation_name
        ),
    }
}

fn recover_remove_operation(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
    mut operation: ManagedWorktreeOperation,
    target_liveness: &dyn Fn(&WorktreeGcTarget) -> WorktreeTargetLiveness,
) -> Result<()> {
    let binding = operation.binding.clone().with_context(|| {
        format!(
            "remove operation '{}' has no create-time binding",
            operation.name
        )
    })?;
    if operation.removal_safety.is_none() {
        bail!(
            "legacy pending removal '{}' has ambiguous safety state in phase {}; rerun explicit remove --force to reauthorize it",
            operation.name,
            managed_operation_phase_label(operation.phase)
        );
    }
    let expected_branch_oid = operation
        .expected_branch_oid
        .as_deref()
        .map(Oid::from_str)
        .transpose()
        .context("remove operation has malformed expected branch OID")?;
    if operation.delete_branch && !binding.branch_created_by_maco {
        bail!(
            "remove operation '{}' cannot delete a branch that predates MACO",
            operation.name
        );
    }

    if operation.phase == ManagedWorktreeOperationPhase::RemovePrepared {
        store.verify_authenticated_registry(lock, registry)?;
        let worktree_quarantine = operation_worktree_quarantine_path(&operation)?;
        let path_exists = path_entry_exists(&binding.path)?;
        let quarantine_exists = path_entry_exists(&worktree_quarantine)?;
        if path_exists == quarantine_exists {
            bail!(
                "remove operation '{}' requires exactly one of its worktree source and quarantine to exist",
                operation.name
            );
        }
        let metadata_quarantine = operation_metadata_quarantine_path(&operation)?;
        let metadata_exists = path_entry_exists(&binding.metadata_dir)?;
        let metadata_quarantine_exists = path_entry_exists(&metadata_quarantine)?;
        if !metadata_exists || metadata_quarantine_exists {
            bail!(
                "remove operation '{}' metadata state is inconsistent before worktree quarantine",
                operation.name
            );
        }
        verify_recovering_branch(
            repo,
            &binding,
            expected_branch_oid,
            operation.delete_branch,
            true,
        )?;
        if path_exists {
            let verified = verify_managed_worktree_binding(
                repo,
                &store.repository,
                &binding,
                operation.delete_branch,
            )?;
            let current_target = gc_target_if_present(&verified.path)?;
            if let Some(ManagedRemovalSafety::GarbageCollection { target, .. }) =
                operation.removal_safety.as_ref()
            {
                ensure_gc_target_snapshot_matches(
                    &operation.name,
                    target,
                    current_target.as_ref(),
                )?;
            }
            if let Some(target) = current_target.as_ref() {
                match target_liveness(target) {
                    WorktreeTargetLiveness::Clear => {}
                    WorktreeTargetLiveness::Live(evidence) => bail!(
                        "pending removal '{}' refused target liveness state=live before quarantine: {}",
                        operation.name,
                        serde_json::to_string(&evidence)
                            .context("failed to encode target liveness evidence")?
                    ),
                    WorktreeTargetLiveness::Unknown(evidence) => bail!(
                        "pending removal '{}' refused target liveness state=unknown before quarantine: {}",
                        operation.name,
                        serde_json::to_string(&evidence)
                            .context("failed to encode target liveness evidence")?
                    ),
                }
            }
            match operation.removal_safety.as_ref() {
                Some(ManagedRemovalSafety::GarbageCollection { dirtiness, .. }) => {
                    let current = gc_worktree_dirtiness(&verified.path)?;
                    let current_snapshot =
                        managed_gc_dirtiness_snapshot(&current).with_context(|| {
                            format!(
                            "pending GC removal '{}' observed tracked changes before quarantine",
                            operation.name
                        )
                        })?;
                    if &current_snapshot != dirtiness {
                        bail!(
                            "pending GC removal '{}' dirtiness changed before quarantine",
                            operation.name
                        );
                    }
                }
                Some(ManagedRemovalSafety::Explicit) if operation.force => {}
                Some(ManagedRemovalSafety::Explicit) => {
                    ensure_clean_worktree(&verified.path).with_context(|| {
                        format!(
                            "pending explicit removal '{}' requires a clean worktree",
                            operation.name
                        )
                    })?;
                }
                None => bail!(
                    "legacy pending removal '{}' has ambiguous safety state; rerun explicit remove --force to reauthorize it",
                    operation.name
                ),
            }
        }
        ensure_removal_worktree_lock(repo, &binding)?;
        let quarantined = quarantine_bound_directory(
            &binding.root,
            &binding.path,
            &worktree_quarantine,
            &binding.path_identity,
        )?;
        operation.phase = ManagedWorktreeOperationPhase::WorktreeQuarantined;
        operation.worktree_quarantine_identity = Some(quarantined);
        registry
            .operations
            .insert(operation.name.clone(), operation.clone());
        store.save(lock, registry)?;
    }

    if operation.phase == ManagedWorktreeOperationPhase::WorktreeQuarantined {
        store.verify_authenticated_registry(lock, registry)?;
        let worktree_quarantine = operation_worktree_quarantine_path(&operation)?;
        let worktree_quarantine_identity = operation
            .worktree_quarantine_identity
            .as_ref()
            .context("worktree-quarantined operation lacks its quarantine identity")?;
        if worktree_quarantine_identity != &binding.path_identity {
            bail!("worktree quarantine identity differs from its create-time binding");
        }
        quarantine_bound_directory(
            &binding.root,
            &binding.path,
            &worktree_quarantine,
            worktree_quarantine_identity,
        )?;
        let metadata_quarantine = operation_metadata_quarantine_path(&operation)?;
        let metadata_exists = path_entry_exists(&binding.metadata_dir)?;
        let metadata_quarantine_exists = path_entry_exists(&metadata_quarantine)?;
        if metadata_exists == metadata_quarantine_exists {
            bail!(
                "remove operation '{}' requires exactly one of its metadata source and quarantine to exist",
                operation.name
            );
        }
        if metadata_exists {
            verify_metadata_binding_after_worktree_removal(&store.repository, &binding)?;
            ensure_removal_worktree_lock(repo, &binding)?;
        } else {
            quarantine_bound_directory(
                &store.repository.common_dir.join("worktrees"),
                &binding.metadata_dir,
                &metadata_quarantine,
                &binding.metadata_dir_identity,
            )?;
        }
        let guard_metadata_dir = if metadata_exists {
            &binding.metadata_dir
        } else {
            &metadata_quarantine
        };
        #[cfg(unix)]
        uninstall_bound_managed_worktree_guard(repo, &binding, guard_metadata_dir).with_context(
            || {
                format!(
                    "failed to restore prior hooks after quarantining managed lane '{}'",
                    operation.name
                )
            },
        )?;
        let metadata_root = store.repository.common_dir.join("worktrees");
        let quarantined = quarantine_bound_directory(
            &metadata_root,
            &binding.metadata_dir,
            &metadata_quarantine,
            &binding.metadata_dir_identity,
        )?;
        operation.phase = ManagedWorktreeOperationPhase::MetadataQuarantined;
        operation.metadata_quarantine_identity = Some(quarantined);
        registry
            .operations
            .insert(operation.name.clone(), operation.clone());
        store.save(lock, registry)?;
    }

    if operation.phase == ManagedWorktreeOperationPhase::MetadataQuarantined {
        store.verify_authenticated_registry(lock, registry)?;
        ensure_original_binding_absent(&binding.path, "worktree")?;
        ensure_original_binding_absent(&binding.metadata_dir, "metadata")?;
        let worktree_quarantine = operation_worktree_quarantine_path(&operation)?;
        let worktree_quarantine_identity = operation
            .worktree_quarantine_identity
            .as_ref()
            .context("metadata-quarantined operation lacks worktree quarantine identity")?;
        remove_quarantined_bound_directory(
            &binding.root,
            &worktree_quarantine,
            worktree_quarantine_identity,
        )?;
        operation.phase = ManagedWorktreeOperationPhase::WorktreeDeleted;
        registry
            .operations
            .insert(operation.name.clone(), operation.clone());
        store.save(lock, registry)?;
    }

    if operation.phase == ManagedWorktreeOperationPhase::WorktreeDeleted {
        store.verify_authenticated_registry(lock, registry)?;
        ensure_original_binding_absent(&binding.path, "worktree")?;
        ensure_original_binding_absent(&binding.metadata_dir, "metadata")?;
        let metadata_quarantine = operation_metadata_quarantine_path(&operation)?;
        let metadata_quarantine_identity = operation
            .metadata_quarantine_identity
            .as_ref()
            .context("worktree-deleted operation lacks metadata quarantine identity")?;
        remove_quarantined_bound_directory(
            &store.repository.common_dir.join("worktrees"),
            &metadata_quarantine,
            metadata_quarantine_identity,
        )?;
        operation.phase = ManagedWorktreeOperationPhase::MetadataDeleted;
        registry
            .operations
            .insert(operation.name.clone(), operation.clone());
        store.save(lock, registry)?;
    }

    if operation.phase == ManagedWorktreeOperationPhase::MetadataDeleted {
        store.verify_authenticated_registry(lock, registry)?;
        ensure_original_binding_absent(&binding.path, "worktree")?;
        ensure_original_binding_absent(&binding.metadata_dir, "metadata")?;
        if operation.delete_branch {
            compare_and_delete_local_branch(
                repo,
                &binding.branch,
                expected_branch_oid.context("remove operation lacks expected branch OID")?,
                true,
                "managed worktree removal",
            )?;
        }
        operation.phase = ManagedWorktreeOperationPhase::BranchDeleted;
        registry
            .operations
            .insert(operation.name.clone(), operation.clone());
        store.save(lock, registry)?;
    }

    if operation.phase != ManagedWorktreeOperationPhase::BranchDeleted {
        bail!(
            "remove operation '{}' has invalid phase {:?}",
            operation.name,
            operation.phase
        );
    }
    store.verify_authenticated_registry(lock, registry)?;
    registry.records.remove(&operation.name);
    registry.operations.remove(&operation.name);
    store.save(lock, registry)
}

fn path_entry_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

fn deterministic_remove_quarantine_path(
    root: &Path,
    kind: &str,
    name: &str,
    identity: &FileIdentity,
) -> PathBuf {
    let payload = format!(
        "{kind}\0{name}\0{:016x}\0{:016x}",
        identity.device, identity.file
    );
    root.join(format!(
        ".maco-remove-{kind}-{}",
        stable_checksum(payload.as_bytes())
    ))
}

fn operation_worktree_quarantine_path(operation: &ManagedWorktreeOperation) -> Result<PathBuf> {
    let binding = operation
        .binding
        .as_ref()
        .context("remove operation lacks its managed binding")?;
    let expected = deterministic_remove_quarantine_path(
        &binding.root,
        "worktree",
        &binding.name,
        &binding.path_identity,
    );
    let observed = operation
        .worktree_quarantine_path
        .as_ref()
        .context("remove operation lacks its worktree quarantine path")?;
    if observed != &expected {
        bail!("remove operation worktree quarantine path is not deterministic");
    }
    Ok(expected)
}

fn operation_metadata_quarantine_path(operation: &ManagedWorktreeOperation) -> Result<PathBuf> {
    let binding = operation
        .binding
        .as_ref()
        .context("remove operation lacks its managed binding")?;
    let metadata_root = binding
        .metadata_dir
        .parent()
        .context("managed metadata binding has no parent")?;
    let expected = deterministic_remove_quarantine_path(
        metadata_root,
        "metadata",
        &binding.name,
        &binding.metadata_dir_identity,
    );
    let observed = operation
        .metadata_quarantine_path
        .as_ref()
        .context("remove operation lacks its metadata quarantine path")?;
    if observed != &expected {
        bail!("remove operation metadata quarantine path is not deterministic");
    }
    Ok(expected)
}

fn quarantine_bound_directory(
    root_path: &Path,
    source_path: &Path,
    quarantine_path: &Path,
    expected: &FileIdentity,
) -> Result<FileIdentity> {
    let root = SafeRoot::open_existing(root_path)?;
    if source_path.parent() != Some(root.path()) || quarantine_path.parent() != Some(root.path()) {
        bail!("bound source or quarantine is not a direct child of its recorded root");
    }
    let source_name = source_path
        .file_name()
        .context("bound source directory has no final component")?;
    let quarantine_name = quarantine_path
        .file_name()
        .context("bound quarantine directory has no final component")?;
    quarantine_direct_child_directory(&root, source_name, quarantine_name, expected)
}

fn remove_quarantined_bound_directory(
    root_path: &Path,
    quarantine_path: &Path,
    expected: &FileIdentity,
) -> Result<bool> {
    let root = SafeRoot::open_existing(root_path)?;
    if quarantine_path.parent() != Some(root.path()) {
        bail!("bound quarantine is not a direct child of its recorded root");
    }
    let quarantine_name = quarantine_path
        .file_name()
        .context("bound quarantine directory has no final component")?;
    remove_quarantined_direct_child_tree(
        &root,
        quarantine_name,
        expected,
        TreeLinkPolicy::UnlinkLinks,
    )
}

fn ensure_original_binding_absent(path: &Path, kind: &str) -> Result<()> {
    if path_entry_exists(path)? {
        bail!("{kind} source path reappeared after durable quarantine");
    }
    Ok(())
}

fn ensure_removal_worktree_lock(repo: &Repository, binding: &ManagedWorktreeBinding) -> Result<()> {
    if path_entry_exists(&binding.metadata_dir.join("index.lock"))? {
        bail!(
            "managed worktree '{}' has an active Git index lock; stop the child before removal",
            binding.name
        );
    }
    let worktree = repo.find_worktree(&binding.name).with_context(|| {
        format!(
            "failed to find worktree '{}' before quarantine",
            binding.name
        )
    })?;
    match worktree
        .is_locked()
        .with_context(|| format!("failed to inspect worktree lock for '{}'", binding.name))?
    {
        WorktreeLockStatus::Unlocked => worktree
            .lock(Some(REMOVAL_LOCK_REASON))
            .with_context(|| format!("failed to lock worktree '{}' for removal", binding.name))?,
        WorktreeLockStatus::Locked(Some(reason)) if reason == REMOVAL_LOCK_REASON => {}
        WorktreeLockStatus::Locked(_) => bail!(
            "managed worktree '{}' is locked by another owner; stop it before removal",
            binding.name
        ),
    }
    match worktree
        .is_locked()
        .with_context(|| format!("failed to recheck worktree lock for '{}'", binding.name))?
    {
        WorktreeLockStatus::Locked(Some(reason)) if reason == REMOVAL_LOCK_REASON => Ok(()),
        _ => bail!("managed worktree removal lock was not retained"),
    }
}

fn cleanup_create_branch_if_owned(
    repo: &Repository,
    operation: &ManagedWorktreeOperation,
) -> Result<()> {
    if operation.branch_ownership != ManagedBranchOwnership::CreatedByMaco {
        return Ok(());
    }
    let expected = operation
        .owned_branch_oid
        .as_deref()
        .map(Oid::from_str)
        .transpose()
        .context("create operation owned branch OID is malformed")?
        .context("create operation marked branch-owned without an owned OID")?;
    compare_and_delete_local_branch(
        repo,
        &operation.branch,
        expected,
        true,
        "failed worktree creation cleanup",
    )
}

fn compare_and_delete_local_branch(
    repo: &Repository,
    branch: &str,
    expected: Oid,
    missing_ok: bool,
    action: &str,
) -> Result<()> {
    validate_branch_name(branch)?;
    let reference_name = format!("refs/heads/{branch}");
    let mut transaction = repo
        .transaction()
        .with_context(|| format!("failed to start ref transaction for {action}"))?;
    transaction
        .lock_ref(&reference_name)
        .with_context(|| format!("failed to lock branch '{branch}' for {action}"))?;
    match local_branch_oid(repo, branch)? {
        None if missing_ok => return Ok(()),
        None => bail!("branch '{branch}' disappeared before {action}"),
        Some(observed) if observed != expected => bail!(
            "branch '{branch}' changed before {action}; expected {expected}, observed {observed}; preserving it"
        ),
        Some(_) => {}
    }
    transaction
        .remove(&reference_name)
        .with_context(|| format!("failed to stage branch '{branch}' deletion for {action}"))?;
    transaction
        .commit()
        .with_context(|| format!("failed to commit branch '{branch}' deletion for {action}"))
}

fn local_branch_oid(repo: &Repository, branch: &str) -> Result<Option<Oid>> {
    match repo.find_branch(branch, BranchType::Local) {
        Ok(branch) => Ok(branch.get().target()),
        Err(error) if error.code() == ErrorCode::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect local branch '{branch}'"))
        }
    }
}

fn verify_recovering_branch(
    repo: &Repository,
    binding: &ManagedWorktreeBinding,
    expected_oid: Option<Oid>,
    delete_branch: bool,
    worktree_or_metadata_exists: bool,
) -> Result<()> {
    if !delete_branch {
        return Ok(());
    }
    match local_branch_oid(repo, &binding.branch)? {
        Some(observed) if Some(observed) == expected_oid => Ok(()),
        Some(_) => bail!(
            "managed branch '{}' changed during remove recovery",
            binding.branch
        ),
        None if !worktree_or_metadata_exists => Ok(()),
        None => bail!(
            "managed branch '{}' disappeared before bound directories were removed",
            binding.branch
        ),
    }
}

fn verify_metadata_binding_after_worktree_removal(
    repository: &ManagedRepositoryBinding,
    binding: &ManagedWorktreeBinding,
) -> Result<()> {
    let metadata_root = SafeRoot::open_existing(repository.common_dir.join("worktrees"))?;
    if binding.metadata_dir.parent() != Some(metadata_root.path())
        || identity_for_path(&binding.metadata_dir)? != binding.metadata_dir_identity
    {
        bail!("managed metadata directory changed during remove recovery");
    }
    let gitdir = binding.metadata_dir.join("gitdir");
    let head = binding.metadata_dir.join("HEAD");
    if BoundedRegularReader::identity(&gitdir)? != binding.metadata_gitdir_file_identity
        || BoundedRegularReader::identity(&head)? != binding.metadata_head_file_identity
    {
        bail!("managed metadata file identity changed during remove recovery");
    }
    verify_metadata_branch(&head, &binding.branch)?;
    let backlink = read_git_metadata_path(&gitdir, false)?;
    let backlink = resolve_metadata_path(&binding.metadata_dir, &backlink);
    if backlink != binding.path.join(".git") {
        bail!("managed metadata gitdir backlink changed during remove recovery");
    }
    Ok(())
}

fn managed_repository_binding(repo: &Repository) -> Result<ManagedRepositoryBinding> {
    let common_dir = fs::canonicalize(repo.commondir()).with_context(|| {
        format!(
            "failed to resolve Git common directory {}",
            repo.commondir().display()
        )
    })?;
    let repository_workdir = repo
        .workdir()
        .context("managed worktrees require a non-bare repository")?;
    let repository_workdir = fs::canonicalize(repository_workdir).with_context(|| {
        format!(
            "failed to resolve repository workdir {}",
            repository_workdir.display()
        )
    })?;
    if common_dir.parent() != Some(repository_workdir.as_path()) || repo.path() != repo.commondir()
    {
        bail!(
            "managed worktree mutation currently requires invocation from the primary worktree with an embedded .git common directory; linked-worktree and --separate-git-dir mutation are refused"
        );
    }
    Ok(ManagedRepositoryBinding {
        common_dir_identity: identity_for_path(&common_dir)?,
        repository_workdir_identity: identity_for_path(&repository_workdir)?,
        common_dir,
        repository_workdir,
    })
}

fn capture_staged_worktree_metadata(
    repository: &ManagedRepositoryBinding,
    name: &str,
    branch: &str,
    staged_path: &Path,
) -> Result<StagedWorktreeMetadata> {
    let metadata_parent = repository.common_dir.join("worktrees");
    let metadata_root = SafeRoot::open_existing(&metadata_parent)?;
    let metadata_binding = metadata_root.bind_existing_managed_direct_child_directory(name)?;
    let metadata_dir = metadata_binding.path().to_path_buf();
    let worktree_git_file = staged_path.join(".git");
    let metadata_gitdir_file = metadata_dir.join("gitdir");
    let metadata_head_file = metadata_dir.join("HEAD");
    verify_gitdir_backlinks(
        &worktree_git_file,
        &metadata_dir,
        &metadata_gitdir_file,
        staged_path,
    )?;
    verify_metadata_branch(&metadata_head_file, branch)?;
    Ok(StagedWorktreeMetadata {
        metadata_dir_identity: metadata_binding.identity().clone(),
        worktree_git_file_identity: BoundedRegularReader::identity(&worktree_git_file)?,
        metadata_gitdir_file_identity: BoundedRegularReader::identity(&metadata_gitdir_file)?,
        metadata_head_file_identity: BoundedRegularReader::identity(&metadata_head_file)?,
        metadata_dir,
    })
}

fn verify_staged_worktree_metadata(
    expected: &StagedWorktreeMetadata,
    repository: &ManagedRepositoryBinding,
    branch: &str,
    current_worktree_path: &Path,
) -> Result<bool> {
    let metadata_root = SafeRoot::open_existing(repository.common_dir.join("worktrees"))?;
    let name = expected
        .metadata_dir
        .file_name()
        .context("staged metadata directory has no final component")?;
    let metadata_binding = metadata_root.bind_existing_managed_direct_child_directory(name)?;
    if expected.metadata_dir.parent() != Some(metadata_root.path())
        || metadata_binding.path() != expected.metadata_dir
        || metadata_binding.identity() != &expected.metadata_dir_identity
    {
        bail!("staged worktree metadata directory identity changed");
    }
    let worktree_git_file = current_worktree_path.join(".git");
    let metadata_gitdir_file = expected.metadata_dir.join("gitdir");
    let metadata_head_file = expected.metadata_dir.join("HEAD");
    if BoundedRegularReader::identity(&worktree_git_file)? != expected.worktree_git_file_identity
        || BoundedRegularReader::identity(&metadata_head_file)?
            != expected.metadata_head_file_identity
    {
        bail!("staged worktree metadata file identity changed");
    }
    verify_metadata_branch(&metadata_head_file, branch)?;
    Ok(BoundedRegularReader::identity(&metadata_gitdir_file)?
        == expected.metadata_gitdir_file_identity)
}

#[allow(clippy::too_many_arguments)]
fn capture_managed_worktree_binding(
    repo: &Repository,
    repository: &ManagedRepositoryBinding,
    root: &SafeRoot,
    name: &str,
    branch: &str,
    branch_created_by_maco: bool,
    base_oid: Oid,
    created_branch_oid: Oid,
) -> Result<ManagedWorktreeBinding> {
    root.verify()?;
    let path = fs::canonicalize(root.path().join(name))
        .with_context(|| format!("failed to resolve created worktree path for '{name}'"))?;
    if path.parent() != Some(root.path()) || path.file_name() != Some(OsStr::new(name)) {
        bail!("created worktree path is not a direct child of its managed root");
    }
    let metadata_parent = repository.common_dir.join("worktrees");
    let metadata_root = SafeRoot::open_existing(&metadata_parent)?;
    let metadata_dir = fs::canonicalize(metadata_parent.join(name))
        .with_context(|| format!("failed to resolve created worktree metadata for '{name}'"))?;
    if metadata_dir.parent() != Some(metadata_root.path())
        || metadata_dir.file_name() != Some(OsStr::new(name))
    {
        bail!("created worktree metadata is not bound beneath the Git common directory");
    }

    let worktree_git_file = path.join(".git");
    let metadata_gitdir_file = metadata_dir.join("gitdir");
    let metadata_head_file = metadata_dir.join("HEAD");
    verify_gitdir_backlinks(
        &worktree_git_file,
        &metadata_dir,
        &metadata_gitdir_file,
        &path,
    )?;
    verify_metadata_branch(&metadata_head_file, branch)?;
    let observed_branch = repo
        .find_branch(branch, BranchType::Local)
        .with_context(|| format!("failed to find created branch '{branch}'"))?
        .get()
        .target()
        .with_context(|| format!("created branch '{branch}' has no direct target"))?;
    if observed_branch != created_branch_oid {
        bail!("created branch OID changed while recording worktree binding");
    }

    Ok(ManagedWorktreeBinding {
        name: name.to_string(),
        root: root.path().to_path_buf(),
        root_identity: root.identity().clone(),
        path_identity: identity_for_path(&path)?,
        path,
        metadata_dir_identity: identity_for_path(&metadata_dir)?,
        metadata_dir,
        worktree_git_file_identity: BoundedRegularReader::identity(&worktree_git_file)?,
        metadata_gitdir_file_identity: BoundedRegularReader::identity(&metadata_gitdir_file)?,
        metadata_head_file_identity: BoundedRegularReader::identity(&metadata_head_file)?,
        branch: branch.to_string(),
        branch_created_by_maco,
        base_oid: base_oid.to_string(),
        created_branch_oid: created_branch_oid.to_string(),
        created_at_unix_nanos: None,
        creation_lock_pending: true,
    })
}

fn verify_managed_worktree_binding(
    repo: &Repository,
    repository: &ManagedRepositoryBinding,
    binding: &ManagedWorktreeBinding,
    delete_branch: bool,
) -> Result<VerifiedManagedWorktree> {
    if managed_repository_binding(repo)? != *repository {
        bail!("repository identity changed since the managed worktree registry was opened");
    }
    let normalized_name = normalize_agent_id(&binding.name)?;
    if normalized_name != binding.name {
        bail!("managed worktree name is not canonical");
    }
    let root = SafeRoot::open_existing(&binding.root)?;
    if root.identity() != &binding.root_identity {
        bail!(
            "managed worktree root identity changed for '{}'",
            binding.name
        );
    }
    let path = fs::canonicalize(&binding.path)
        .with_context(|| format!("managed worktree path is missing for '{}'", binding.name))?;
    if path != binding.path
        || path.parent() != Some(root.path())
        || path.file_name() != Some(OsStr::new(&binding.name))
        || identity_for_path(&path)? != binding.path_identity
    {
        bail!(
            "managed worktree path binding changed for '{}'; --force cannot bypass this check",
            binding.name
        );
    }

    let metadata_parent = repository.common_dir.join("worktrees");
    let metadata_root = SafeRoot::open_existing(&metadata_parent)?;
    let metadata_dir = fs::canonicalize(&binding.metadata_dir).with_context(|| {
        format!(
            "managed worktree metadata is missing for '{}'",
            binding.name
        )
    })?;
    if metadata_dir != binding.metadata_dir
        || metadata_dir.parent() != Some(metadata_root.path())
        || metadata_dir.file_name() != Some(OsStr::new(&binding.name))
        || identity_for_path(&metadata_dir)? != binding.metadata_dir_identity
    {
        bail!(
            "managed worktree metadata binding changed for '{}'; --force cannot bypass this check",
            binding.name
        );
    }

    let worktree_git_file = path.join(".git");
    let metadata_gitdir_file = metadata_dir.join("gitdir");
    let metadata_head_file = metadata_dir.join("HEAD");
    if BoundedRegularReader::identity(&worktree_git_file)? != binding.worktree_git_file_identity
        || BoundedRegularReader::identity(&metadata_gitdir_file)?
            != binding.metadata_gitdir_file_identity
        || BoundedRegularReader::identity(&metadata_head_file)?
            != binding.metadata_head_file_identity
    {
        bail!(
            "managed worktree metadata file identity changed for '{}'; refusing removal",
            binding.name
        );
    }
    verify_gitdir_backlinks(
        &worktree_git_file,
        &metadata_dir,
        &metadata_gitdir_file,
        &path,
    )?;
    verify_metadata_branch(&metadata_head_file, &binding.branch)?;

    let branch_oid = repo
        .find_branch(&binding.branch, BranchType::Local)
        .with_context(|| format!("managed branch '{}' is missing", binding.branch))?
        .get()
        .target()
        .with_context(|| format!("managed branch '{}' has no direct target", binding.branch))?;
    let base_oid = Oid::from_str(&binding.base_oid).context("managed base OID is malformed")?;
    let created_oid =
        Oid::from_str(&binding.created_branch_oid).context("managed branch OID is malformed")?;
    if binding.branch_created_by_maco
        && created_oid != base_oid
        && !repo
            .graph_descendant_of(created_oid, base_oid)
            .context("failed to verify create-time branch ancestry")?
    {
        bail!("create-time branch OID is not derived from the recorded base OID");
    }
    if branch_oid != created_oid
        && !repo
            .graph_descendant_of(branch_oid, created_oid)
            .context("failed to verify current managed branch ancestry")?
    {
        bail!(
            "managed branch '{}' was rewritten outside its recorded ancestry; refusing removal",
            binding.branch
        );
    }
    if delete_branch && !binding.branch_created_by_maco {
        bail!(
            "refusing to delete branch '{}' because it predated this managed worktree",
            binding.branch
        );
    }

    Ok(VerifiedManagedWorktree { path, branch_oid })
}

fn verify_gitdir_backlinks(
    worktree_git_file: &Path,
    metadata_dir: &Path,
    metadata_gitdir_file: &Path,
    worktree_path: &Path,
) -> Result<()> {
    let worktree_target = read_git_metadata_path(worktree_git_file, true)?;
    let worktree_target = resolve_metadata_path(worktree_path, &worktree_target);
    let worktree_target = fs::canonicalize(&worktree_target).with_context(|| {
        format!(
            "failed to resolve worktree gitdir backlink {}",
            worktree_target.display()
        )
    })?;
    if worktree_target != metadata_dir {
        bail!("worktree .git file does not point to its recorded metadata directory");
    }

    let metadata_target = read_git_metadata_path(metadata_gitdir_file, false)?;
    let metadata_target = resolve_metadata_path(metadata_dir, &metadata_target);
    let metadata_target = fs::canonicalize(&metadata_target).with_context(|| {
        format!(
            "failed to resolve metadata gitdir backlink {}",
            metadata_target.display()
        )
    })?;
    if metadata_target != worktree_git_file {
        bail!("worktree metadata gitdir does not point back to the recorded .git file");
    }
    Ok(())
}

#[cfg(unix)]
fn read_git_metadata_path(path: &Path, worktree_git_file: bool) -> Result<PathBuf> {
    let mut bytes = BoundedRegularReader::read(path, MAX_WORKTREE_METADATA_BYTES)?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    if worktree_git_file {
        bytes = bytes
            .strip_prefix(b"gitdir: ")
            .context("worktree .git file has no canonical gitdir prefix")?
            .to_vec();
    }
    if bytes.is_empty() || bytes.iter().any(|byte| matches!(byte, 0 | b'\n' | b'\r')) {
        bail!("Git metadata path is empty or contains an unrepresentable byte");
    }
    Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
}

#[cfg(not(unix))]
fn read_git_metadata_path(path: &Path, _worktree_git_file: bool) -> Result<PathBuf> {
    bail!(
        "lossless Git metadata path decoding is unsupported on this platform: {}",
        path.display()
    )
}

fn verify_metadata_branch(head_file: &Path, branch: &str) -> Result<()> {
    let head = BoundedRegularReader::read_utf8(head_file, MAX_WORKTREE_METADATA_BYTES)?;
    let expected = format!("ref: refs/heads/{branch}");
    if head.trim() != expected {
        bail!(
            "managed worktree HEAD binding mismatch: expected '{expected}', observed '{}'",
            head.trim()
        );
    }
    Ok(())
}

fn repository_info(repo: &Repository) -> Result<RepositoryInfo> {
    let path = repo
        .workdir()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| repo.path().to_path_buf());
    repo.find_reference("HEAD")
        .context("failed to inspect repository HEAD backlink")?
        .symbolic_target()
        .context("repository HEAD symbolic target is not valid UTF-8")?;
    let head = match repo.head() {
        Ok(head) => Some(
            head.shorthand()
                .map(ToOwned::to_owned)
                .context("repository HEAD shorthand is not valid UTF-8")?,
        ),
        Err(error) if error.code() == ErrorCode::UnbornBranch => None,
        Err(error) => return Err(error).context("failed to read repository HEAD"),
    };

    Ok(RepositoryInfo {
        path,
        git_dir: repo.path().to_path_buf(),
        head,
    })
}

pub fn normalize_agent_id(agent_id: &str) -> Result<String> {
    let trimmed = agent_id.trim();
    if trimmed.is_empty() {
        bail!("agent id cannot be empty");
    }
    if matches!(trimmed, "." | "..") {
        bail!("agent id cannot be '.' or '..'");
    }
    if trimmed.len() > MAX_AGENT_ID_BYTES {
        bail!("agent id exceeds its {MAX_AGENT_ID_BYTES}-byte limit");
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("agent id may only contain ASCII letters, digits, '.', '_' and '-'");
    }

    Ok(trimmed.to_string())
}

fn default_branch_name(name: &str) -> String {
    format!("{DEFAULT_BRANCH_PREFIX}/{name}")
}

fn validate_branch_name(branch_name: &str) -> Result<()> {
    if branch_name.len() > MAX_BRANCH_NAME_BYTES {
        bail!("branch name exceeds its {MAX_BRANCH_NAME_BYTES}-byte limit");
    }
    if !Branch::name_is_valid(branch_name).context("failed to validate branch name")? {
        bail!("branch name is not a valid Git branch: {branch_name}");
    }

    Ok(())
}

fn default_worktree_root(repo: &Repository) -> PathBuf {
    let repo_root = repo.workdir().unwrap_or_else(|| repo.path());
    let repo_name = repo_root
        .file_name()
        .and_then(|name| name.to_str())
        .map(sanitize_path_segment)
        .unwrap_or_else(|| "repository".to_string());
    repo_root
        .parent()
        .unwrap_or(repo_root)
        .join(".maco")
        .join("worktrees")
        .join(repo_name)
}

fn resolve_metadata_path(metadata_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        metadata_dir.join(path)
    }
}

fn sanitize_path_segment(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn resolve_base_commit<'repo>(
    repo: &'repo Repository,
    base: Option<&str>,
) -> Result<git2::Commit<'repo>> {
    let object = match base {
        Some(base) => repo
            .revparse_single(base)
            .with_context(|| format!("failed to resolve base revision '{base}'"))?,
        None => repo
            .head()
            .context("repository has no committed HEAD; create an initial commit first")?
            .peel(ObjectType::Commit)
            .context("failed to peel HEAD to a commit")?,
    };

    object
        .peel_to_commit()
        .context("base revision does not resolve to a commit")
}

fn ensure_branch<'repo>(
    repo: &'repo Repository,
    branch_name: &str,
    commit: &git2::Commit<'repo>,
) -> Result<(git2::Branch<'repo>, bool)> {
    match repo.find_branch(branch_name, BranchType::Local) {
        Ok(branch) => Ok((branch, false)),
        Err(error) if error.code() == ErrorCode::NotFound => repo
            .branch(branch_name, commit, false)
            .map(|branch| (branch, true))
            .with_context(|| format!("failed to create local branch '{branch_name}'")),
        Err(error) => Err(error).with_context(|| format!("failed to open branch '{branch_name}'")),
    }
}

fn ensure_branch_for_creation<'repo>(
    repo: &'repo Repository,
    branch_name: &str,
    commit: &git2::Commit<'repo>,
    creation_policy: WorktreeCreationPolicy,
) -> Result<(git2::Branch<'repo>, bool)> {
    match creation_policy {
        WorktreeCreationPolicy::Standard => ensure_branch(repo, branch_name, commit),
        WorktreeCreationPolicy::NeutralFresh { .. } => repo
            .branch(branch_name, commit, false)
            .map(|branch| (branch, true))
            .with_context(|| {
                format!("failed to create fresh neutral worktree branch '{branch_name}'")
            }),
    }
}

fn find_worktree(repo: &Repository, name: &str) -> Result<Option<git2::Worktree>> {
    match repo.find_worktree(name) {
        Ok(worktree) => Ok(Some(worktree)),
        Err(error) if error.code() == ErrorCode::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to inspect worktree '{name}'")),
    }
}

#[cfg(not(test))]
fn ensure_clean_worktree(_path: &Path) -> Result<()> {
    bail!(
        "effectful worktree cleanliness decisions are unsupported without a capability-bound repository input"
    )
}

#[cfg(test)]
fn ensure_clean_worktree(path: &Path) -> Result<()> {
    if !bounded_worktree_is_clean(
        path,
        MAX_WORKTREE_STATUS_ENTRIES,
        MAX_WORKTREE_STATUS_OUTPUT_BYTES,
        WORKTREE_STATUS_TIMEOUT,
    )? {
        bail!("worktree is dirty; rerun with --force to remove it anyway");
    }
    Ok(())
}

#[derive(Debug)]
enum GitAssociationMarker {
    Directory(DirectoryBindingGuard),
    File(RegularFileBindingGuard),
}

impl GitAssociationMarker {
    fn bind(path: &Path) -> Result<Self> {
        let metadata = fs::symlink_metadata(path).with_context(|| {
            format!(
                "failed to inspect Git association marker {}",
                path.display()
            )
        })?;
        if metadata.file_type().is_symlink() {
            bail!(
                "Git association marker must not be a symbolic link: {}",
                path.display()
            );
        }
        if metadata.is_dir() {
            return DirectoryBindingGuard::bind(path).map(Self::Directory);
        }
        if metadata.is_file() {
            return RegularFileBindingGuard::bind(path, MAX_WORKTREE_GIT_TEXT_FILE_BYTES)
                .map(Self::File);
        }
        bail!(
            "Git association marker has an unsupported file type: {}",
            path.display()
        )
    }

    fn verify(&self) -> Result<()> {
        match self {
            Self::Directory(binding) => {
                if identity_for_path(binding.path())? != *binding.identity() {
                    bail!("Git directory association marker changed");
                }
                Ok(())
            }
            Self::File(binding) => binding.verify(),
        }
    }
}

/// Binds the complete repository pathname association, including the
/// worktree `.git` marker and an optional linked-worktree `commondir` file.
/// Reopening the repository must resolve to the exact held Git and common
/// directories before any security decision may be accepted.
#[derive(Debug)]
pub(crate) struct RepositoryBindingGuard {
    worktree: DirectoryBindingGuard,
    git_marker: GitAssociationMarker,
    git_dir: DirectoryBindingGuard,
    common_dir: DirectoryBindingGuard,
    objects_dir: DirectoryBindingGuard,
    commondir_marker: Option<RegularFileBindingGuard>,
}

impl RepositoryBindingGuard {
    pub(crate) fn bind(path: &Path) -> Result<Self> {
        let worktree =
            DirectoryBindingGuard::bind(path).context("failed to bind repository worktree")?;
        let git_marker = GitAssociationMarker::bind(&worktree.path().join(".git"))?;
        let repository = crate::git_repository::open(worktree.path()).with_context(|| {
            format!(
                "failed to open bound repository {}",
                worktree.path().display()
            )
        })?;
        let repository_worktree = repository
            .workdir()
            .context("repository binding requires a non-bare worktree")?;
        if identity_for_path(repository_worktree)? != *worktree.identity() {
            bail!("Git repository worktree does not match the bound worktree directory");
        }
        let git_dir = DirectoryBindingGuard::bind(repository.path())?;
        let common_dir = DirectoryBindingGuard::bind(repository.commondir())?;
        let objects_dir = DirectoryBindingGuard::bind(repository.commondir().join("objects"))?;
        let commondir_path = git_dir.path().join("commondir");
        let commondir_marker = match fs::symlink_metadata(&commondir_path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Some(
                RegularFileBindingGuard::bind(&commondir_path, MAX_WORKTREE_GIT_TEXT_FILE_BYTES)?,
            ),
            Ok(_) => bail!(
                "Git commondir association marker has an unsupported file type: {}",
                commondir_path.display()
            ),
            Err(error) if error.kind() == ErrorKind::NotFound => None,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect Git commondir marker {}",
                        commondir_path.display()
                    )
                })
            }
        };
        let binding = Self {
            worktree,
            git_marker,
            git_dir,
            common_dir,
            objects_dir,
            commondir_marker,
        };
        binding.verify()?;
        Ok(binding)
    }

    pub(crate) fn worktree(&self) -> &Path {
        self.worktree.path()
    }

    pub(crate) fn worktree_binding(&self) -> &DirectoryBindingGuard {
        &self.worktree
    }

    pub(crate) fn git_dir(&self) -> &Path {
        self.git_dir.path()
    }

    pub(crate) fn common_dir(&self) -> &Path {
        self.common_dir.path()
    }

    pub(crate) fn read_git_relative(&self, relative: &Path, max_bytes: u64) -> Result<Vec<u8>> {
        self.git_dir.read_relative(relative, max_bytes)
    }

    pub(crate) fn read_git_relative_optional(
        &self,
        relative: &Path,
        max_bytes: u64,
    ) -> Result<Option<Vec<u8>>> {
        self.git_dir.read_relative_optional(relative, max_bytes)
    }

    pub(crate) fn read_common_relative_optional(
        &self,
        relative: &Path,
        max_bytes: u64,
    ) -> Result<Option<Vec<u8>>> {
        self.common_dir.read_relative_optional(relative, max_bytes)
    }

    pub(crate) fn verify(&self) -> Result<()> {
        self.worktree
            .verify()
            .context("repository worktree changed")?;
        self.git_marker
            .verify()
            .context("repository .git association changed")?;
        if identity_for_path(self.git_dir.path())? != *self.git_dir.identity()
            || identity_for_path(self.common_dir.path())? != *self.common_dir.identity()
            || identity_for_path(self.objects_dir.path())? != *self.objects_dir.identity()
        {
            bail!("repository Git directory association changed");
        }
        let commondir_path = self.git_dir.path().join("commondir");
        match &self.commondir_marker {
            Some(binding) => binding
                .verify()
                .context("repository commondir association changed")?,
            None => match fs::symlink_metadata(&commondir_path) {
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Ok(_) => bail!("repository commondir association appeared during operation"),
                Err(error) => return Err(error).context("failed to recheck repository commondir"),
            },
        }
        let reopened = crate::git_repository::open(self.worktree.path())
            .context("failed to reopen bound repository association")?;
        let reopened_worktree = reopened
            .workdir()
            .context("reopened repository is unexpectedly bare")?;
        if identity_for_path(reopened_worktree)? != *self.worktree.identity()
            || identity_for_path(reopened.path())? != *self.git_dir.identity()
            || identity_for_path(reopened.commondir())? != *self.common_dir.identity()
            || identity_for_path(reopened.commondir().join("objects"))?
                != *self.objects_dir.identity()
        {
            bail!("repository pathname association resolved to different filesystem objects");
        }
        self.git_marker
            .verify()
            .context("repository .git association changed after reopen")?;
        if let Some(binding) = &self.commondir_marker {
            binding
                .verify()
                .context("repository commondir association changed after reopen")?;
        }
        Ok(())
    }

    pub(crate) fn verify_status_generation(&self) -> Result<()> {
        self.worktree.verify()?;
        self.git_dir.verify()?;
        self.common_dir.verify()?;
        self.objects_dir.verify()?;
        self.git_marker.verify()?;
        if let Some(binding) = &self.commondir_marker {
            binding.verify()?;
        }
        Ok(())
    }
}

#[allow(dead_code)]
impl RepositoryCleanlinessCapability {
    fn capture(manager: &WorktreeManager) -> Result<Self> {
        let repository_handle = manager.open_repository()?;
        let repository = managed_repository_binding(&repository_handle)?;
        let capability = Self { repository };
        capability.require_clean_for_manager(manager)?;
        Ok(capability)
    }

    fn require_clean_for_manager(&self, manager: &WorktreeManager) -> Result<()> {
        let repository_handle = manager.open_repository()?;
        let repository = managed_repository_binding(&repository_handle)?;
        self.require_clean_for_repository(&repository)
    }

    fn require_clean_for_repository(&self, repository: &ManagedRepositoryBinding) -> Result<()> {
        if repository != &self.repository {
            bail!("repository cleanliness capability belongs to a different managed repository");
        }
        let binding = RepositoryBindingGuard::bind(&repository.repository_workdir)
            .context("failed to rebind managed repository cleanliness capability")?;
        self.verify_primary_association(repository, &binding)?;
        require_bound_repository_clean(&binding, "primary repository")?;
        self.verify_primary_association(repository, &binding)
    }

    fn require_clean_related_worktree(&self, path: &Path) -> Result<()> {
        let primary = RepositoryBindingGuard::bind(&self.repository.repository_workdir)
            .context("failed to rebind managed repository cleanliness capability")?;
        self.verify_primary_association(&self.repository, &primary)?;
        let worktree = RepositoryBindingGuard::bind(path)
            .context("failed to bind created managed worktree cleanliness")?;
        if worktree.common_dir.path() != self.repository.common_dir
            || worktree.common_dir.identity() != &self.repository.common_dir_identity
        {
            bail!(
                "created managed worktree does not belong to the repository cleanliness capability"
            );
        }
        require_bound_repository_clean(&worktree, "created managed worktree")?;
        primary.verify()?;
        self.verify_primary_association(&self.repository, &primary)
    }

    fn verify_primary_association(
        &self,
        repository: &ManagedRepositoryBinding,
        binding: &RepositoryBindingGuard,
    ) -> Result<()> {
        binding.verify()?;
        if binding.worktree.path() != repository.repository_workdir
            || binding.worktree.identity() != &repository.repository_workdir_identity
            || binding.git_dir.path() != repository.common_dir
            || binding.git_dir.identity() != &repository.common_dir_identity
            || binding.common_dir.path() != repository.common_dir
            || binding.common_dir.identity() != &repository.common_dir_identity
        {
            bail!("repository cleanliness capability binding no longer matches its repository");
        }
        Ok(())
    }
}

impl CreationCleanliness<'_> {
    fn require_clean_for_repository(&self, repository: &ManagedRepositoryBinding) -> Result<()> {
        match self {
            Self::Bound(cleanliness) => cleanliness.require_clean_for_repository(repository),
            #[cfg(test)]
            Self::TestOnly => Ok(()),
        }
    }

    fn require_clean_related_worktree(&self, path: &Path) -> Result<()> {
        match self {
            Self::Bound(cleanliness) => cleanliness.require_clean_related_worktree(path),
            #[cfg(test)]
            Self::TestOnly => Ok(()),
        }
    }
}

fn require_bound_repository_clean(binding: &RepositoryBindingGuard, label: &str) -> Result<()> {
    let dirty = bounded_repository_status_paths_bound(
        binding,
        MAX_WORKTREE_STATUS_ENTRIES,
        MAX_WORKTREE_STATUS_OUTPUT_BYTES,
        WORKTREE_GC_STATUS_TIMEOUT,
    )?;
    if !dirty.is_empty() {
        bail!("{label} is dirty; managed worktree creation requires clean repository state");
    }
    binding.verify()
}

#[cfg(test)]
fn bounded_worktree_is_clean(
    path: &Path,
    max_entries: usize,
    max_output_bytes: usize,
    timeout: Duration,
) -> Result<bool> {
    Ok(
        bounded_worktree_records(path, max_entries, max_output_bytes, timeout)?
            .status
            .is_empty(),
    )
}

/// Returns a fail-closed, output-bounded Git porcelain status snapshot.  Git
/// runs in the existing killable read-only containment boundary instead of in
/// an in-process libgit2 call whose wall-clock work cannot be interrupted.
pub(crate) fn bounded_repository_status_paths(
    path: &Path,
    max_entries: usize,
    max_output_bytes: usize,
    timeout: Duration,
) -> Result<BoundedStatusPathRecords> {
    let binding = RepositoryBindingGuard::bind(path)?;
    bounded_repository_status_paths_bound(&binding, max_entries, max_output_bytes, timeout)
}

fn bounded_repository_gc_status_paths(
    path: &Path,
    max_entries: usize,
    max_output_bytes: usize,
    timeout: Duration,
) -> Result<BoundedStatusPathRecords> {
    let binding = RepositoryBindingGuard::bind(path)?;
    binding.verify()?;
    let records =
        bounded_worktree_records_with_ignored(path, max_entries, max_output_bytes, timeout)?;
    let mut merged = parse_porcelain_v1_z(&records.status, max_entries)?
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let ignored = parse_nul_paths(&records.ignored, max_entries)?;
    for path in ignored {
        if is_bounded_status_runtime_path(&path) {
            continue;
        }
        merged.entry(path).or_insert([b'?', b'?']);
        if merged.len() > max_entries {
            bail!("bounded GC status exceeded its combined parsed entry limit");
        }
    }
    binding.verify()?;
    Ok(merged.into_iter().collect())
}

type BoundedStatusPathRecords = Vec<(PathBuf, [u8; 2])>;

pub(crate) fn bounded_repository_status_paths_bound(
    binding: &RepositoryBindingGuard,
    max_entries: usize,
    max_output_bytes: usize,
    timeout: Duration,
) -> Result<BoundedStatusPathRecords> {
    let (paths, _) = bounded_repository_status_paths_bound_with_process_wait(
        binding,
        max_entries,
        max_output_bytes,
        timeout,
    )?;
    Ok(paths)
}

pub(crate) fn bounded_repository_status_paths_bound_with_process_wait(
    binding: &RepositoryBindingGuard,
    max_entries: usize,
    max_output_bytes: usize,
    timeout: Duration,
) -> Result<(BoundedStatusPathRecords, Duration)> {
    binding.verify()?;
    let records =
        bounded_worktree_records(binding.worktree(), max_entries, max_output_bytes, timeout)?;
    binding.verify()?;
    Ok((
        parse_porcelain_v1_z(&records.status, max_entries)?,
        records.process_queue_wait,
    ))
}

pub(crate) fn bounded_repository_visible_paths_bound_with_process_wait(
    binding: &RepositoryBindingGuard,
    max_entries: usize,
    max_output_bytes: usize,
    timeout: Duration,
) -> Result<(Vec<PathBuf>, Duration)> {
    binding.verify()?;
    let records =
        bounded_worktree_records(binding.worktree(), max_entries, max_output_bytes, timeout)?;
    binding.verify()?;
    Ok((
        parse_nul_paths(&records.visible, max_entries)?,
        records.process_queue_wait,
    ))
}

struct BoundedWorktreeRecords {
    visible: Vec<u8>,
    status: Vec<u8>,
    ignored: Vec<u8>,
    process_queue_wait: Duration,
}

fn bounded_worktree_records(
    path: &Path,
    max_entries: usize,
    max_output_bytes: usize,
    timeout: Duration,
) -> Result<BoundedWorktreeRecords> {
    bounded_worktree_records_mode(path, max_entries, max_output_bytes, timeout, false)
}

fn bounded_worktree_records_with_ignored(
    path: &Path,
    max_entries: usize,
    max_output_bytes: usize,
    timeout: Duration,
) -> Result<BoundedWorktreeRecords> {
    bounded_worktree_records_mode(path, max_entries, max_output_bytes, timeout, true)
}

fn bounded_worktree_records_mode(
    path: &Path,
    max_entries: usize,
    max_output_bytes: usize,
    timeout: Duration,
    collect_ignored: bool,
) -> Result<BoundedWorktreeRecords> {
    let (_process_lock, deadline, process_queue_wait) =
        enter_bounded_status_process_scope(timeout)?;
    ensure_worktree_status_deadline(deadline, "before bounded-status runtime-root setup")?;
    let state_root = bounded_status_runtime_root(path)?;
    ensure_worktree_status_deadline(deadline, "after bounded-status runtime-root setup")?;
    let mut records = bounded_worktree_status_in_runtime_until(
        path,
        max_entries,
        max_output_bytes,
        &state_root,
        |_| Ok(()),
        deadline,
        collect_ignored,
    )?;
    records.process_queue_wait = process_queue_wait;
    Ok(records)
}

fn enter_bounded_status_process_scope(
    timeout: Duration,
) -> Result<(std::sync::MutexGuard<'static, ()>, Instant, Duration)> {
    validate_worktree_status_timeout(timeout)?;
    let queued_at = Instant::now();
    let process_lock = lock_bounded_status_process();
    let process_queue_wait = queued_at.elapsed();
    let deadline = worktree_status_deadline(timeout)?;
    Ok((process_lock, deadline, process_queue_wait))
}

fn lock_bounded_status_process() -> std::sync::MutexGuard<'static, ()> {
    let lock = BOUNDED_STATUS_PROCESS_LOCK.get_or_init(|| std::sync::Mutex::new(()));
    match lock.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
fn bounded_worktree_is_clean_in_runtime<F>(
    path: &Path,
    max_entries: usize,
    max_output_bytes: usize,
    timeout: Duration,
    state_root: &SafeRoot,
    after_index_snapshot: F,
) -> Result<bool>
where
    F: FnOnce(&SafeRoot) -> Result<()>,
{
    let (_process_lock, deadline, _) = enter_bounded_status_process_scope(timeout)?;
    bounded_worktree_status_in_runtime_until(
        path,
        max_entries,
        max_output_bytes,
        state_root,
        after_index_snapshot,
        deadline,
        false,
    )
    .map(|records| records.status.is_empty())
}

#[cfg(test)]
fn bounded_worktree_is_clean_in_runtime_unlocked<F>(
    path: &Path,
    max_entries: usize,
    max_output_bytes: usize,
    timeout: Duration,
    state_root: &SafeRoot,
    after_index_snapshot: F,
) -> Result<bool>
where
    F: FnOnce(&SafeRoot) -> Result<()>,
{
    let deadline = worktree_status_deadline(timeout)?;
    bounded_worktree_status_in_runtime_until(
        path,
        max_entries,
        max_output_bytes,
        state_root,
        after_index_snapshot,
        deadline,
        false,
    )
    .map(|records| records.status.is_empty())
}

fn bounded_worktree_status_in_runtime_until<F>(
    path: &Path,
    max_entries: usize,
    max_output_bytes: usize,
    state_root: &SafeRoot,
    after_index_snapshot: F,
    deadline: Instant,
    collect_ignored: bool,
) -> Result<BoundedWorktreeRecords>
where
    F: FnOnce(&SafeRoot) -> Result<()>,
{
    let repository_binding = RepositoryBindingGuard::bind(path)
        .context("failed to bind bounded-status repository association")?;
    let worktree_binding = repository_binding.worktree_binding();
    let lock_timeout = remaining_worktree_status_time(
        deadline,
        "before global bounded-status runtime lock acquisition",
    )?
    .min(WORKTREE_STATUS_LOCK_TIMEOUT);
    let status_lock = KernelStateLock::acquire_direct_with_timeout(
        state_root,
        WORKTREE_STATUS_RUNTIME_LOCK,
        lock_timeout,
    )
    .context("failed to acquire global bounded-status runtime lock")?;
    ensure_worktree_status_deadline(deadline, "after bounded-status runtime lock acquisition")?;
    status_lock.verify_direct_binding(state_root)?;
    scavenge_bounded_status_runtimes_until(state_root, WORKTREE_STATUS_SCAVENGE_LIMITS, deadline)
        .context("failed to scavenge bounded-status crash residue")?;
    status_lock.verify_direct_binding(state_root)?;
    ensure_worktree_status_deadline(deadline, "after bounded-status startup cleanup")?;
    let git_dir_binding = DirectoryBindingGuard::bind(repository_binding.git_dir())
        .context("failed to bind bounded-status Git directory")?;
    let common_dir_binding = DirectoryBindingGuard::bind(repository_binding.common_dir())
        .context("failed to bind bounded-status Git common directory")?;
    verify_repository_status_bindings(worktree_binding, &git_dir_binding, &common_dir_binding)?;
    let git_text_inputs = validate_bounded_git_text_inputs_bound(&repository_binding, deadline)?;
    ensure_worktree_status_deadline(deadline, "after opening bounded-status repository")?;
    let raw_head = repository_binding
        .read_git_relative(Path::new("HEAD"), MAX_WORKTREE_HEAD_BYTES)
        .context("failed to capture bounded-status HEAD")?;
    validate_bounded_head(&raw_head)?;
    let head = resolve_bounded_head(&repository_binding, &raw_head)?;
    ensure_worktree_status_deadline(deadline, "after capturing bounded-status HEAD")?;
    let index = repository_binding
        .read_git_relative_optional(Path::new("index"), MAX_WORKTREE_INDEX_BYTES)
        .context("failed to capture bounded-status index")?;
    if let Some(index) = &index {
        validate_bounded_index_bytes(index)?;
    }
    ensure_worktree_status_deadline(deadline, "after capturing bounded-status index")?;
    let common_objects = SafeRoot::open_existing(repository_binding.common_dir().join("objects"))?;
    ensure_worktree_status_deadline(deadline, "after binding bounded-status objects")?;
    let runtime = state_root.reserve_random_direct_child_directory(WORKTREE_STATUS_RUNTIME_SEED)?;
    ensure_worktree_status_deadline(deadline, "after reserving bounded-status runtime")?;
    let result = (|| -> Result<BoundedWorktreeRecords> {
        let runtime_root = SafeRoot::open_existing(runtime.path())?;
        ensure_worktree_status_deadline(deadline, "after opening bounded-status runtime")?;
        runtime_root.reserve_direct_child_directory("home")?;
        ensure_worktree_status_deadline(deadline, "after bounded-status HOME setup")?;
        runtime_root.reserve_direct_child_directory("tmp")?;
        ensure_worktree_status_deadline(deadline, "after bounded-status TMP setup")?;
        let git_dir = runtime_root.reserve_direct_child_directory("git")?;
        let git_root = SafeRoot::open_existing(git_dir.path())?;
        git_root.reserve_direct_child_directory("refs")?;
        let info_dir = git_root.reserve_direct_child_directory("info")?;
        if let Some(exclude) = &git_text_inputs.info_exclude {
            let info_root = SafeRoot::open_existing(info_dir.path())?;
            AtomicStateWriter::write_direct(&info_root, "exclude", exclude)?;
        }
        ensure_worktree_status_deadline(deadline, "after bounded-status Git root setup")?;
        if let Some(index) = &index {
            AtomicStateWriter::write_direct(&git_root, "index", index)?;
        }
        ensure_worktree_status_deadline(deadline, "after bounded-status index staging")?;
        after_index_snapshot(&runtime_root)?;
        ensure_worktree_status_deadline(deadline, "after bounded-status setup callback")?;
        AtomicStateWriter::write_direct(&git_root, "HEAD", &head)?;
        ensure_worktree_status_deadline(deadline, "after bounded-status HEAD staging")?;
        create_validated_object_link(&git_root, common_objects.path())?;
        ensure_worktree_status_deadline(deadline, "after bounded-status object-link setup")?;
        let worktree_alias = create_bounded_status_worktree_link(&runtime_root, path)?;
        ensure_worktree_status_deadline(deadline, "after bounded-status worktree-link setup")?;
        let git_context = BoundedGitContext {
            worktree: &worktree_alias,
            worktree_target: path,
            runtime_root: &runtime_root,
            git_dir: git_dir.path(),
            objects_target: common_objects.path(),
        };
        let visible = run_bounded_git_records(
            &git_context,
            [
                "--no-optional-locks",
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
            ],
            max_entries,
            max_output_bytes,
            deadline,
            "bounded managed-worktree index listing",
        )?;
        ensure_worktree_status_deadline(deadline, "after bounded managed-worktree index listing")?;
        let index_flags = run_bounded_git_records(
            &git_context,
            [
                "--no-optional-locks",
                "ls-files",
                "--stage",
                "-v",
                "-z",
                "--sparse",
            ],
            max_entries,
            max_output_bytes,
            deadline,
            "bounded managed-worktree index flag validation",
        )?;
        validate_bounded_git_index_records(&index_flags, max_entries)?;
        let fsmonitor_flags = run_bounded_git_records(
            &git_context,
            [
                "--no-optional-locks",
                "ls-files",
                "--stage",
                "-f",
                "-z",
                "--sparse",
            ],
            max_entries,
            max_output_bytes,
            deadline,
            "bounded managed-worktree fsmonitor flag validation",
        )?;
        validate_bounded_git_index_records(&fsmonitor_flags, max_entries)?;
        let bytes = run_bounded_git_records(
            &git_context,
            [
                "--no-optional-locks",
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--no-renames",
                "--ignore-submodules=all",
            ],
            max_entries,
            max_output_bytes,
            deadline,
            "bounded managed-worktree status",
        )?;
        ensure_worktree_status_deadline(deadline, "after bounded managed-worktree status")?;
        let status_entries = bytes.iter().filter(|byte| **byte == 0).count();
        let remaining_entries = max_entries
            .checked_sub(status_entries)
            .context("bounded worktree status exceeded its combined entry limit")?;
        let remaining_output_bytes = max_output_bytes
            .checked_sub(bytes.len())
            .context("bounded worktree status exceeded its combined output limit")?;
        let ignored = if collect_ignored {
            let ignored = run_bounded_git_records(
                &git_context,
                [
                    "--no-optional-locks",
                    "ls-files",
                    "-z",
                    "--others",
                    "--ignored",
                    "--exclude-standard",
                    "--exclude=!.maco",
                    "--exclude=!.maco/**",
                    "--exclude=!.maco-cache",
                    "--exclude=!.maco-cache/**",
                    "--exclude=!target",
                    "--exclude=!target/**",
                    "--exclude=!.agent/temp",
                    "--exclude=!.agent/temp/**",
                    "--exclude=!.agent/storage",
                    "--exclude=!.agent/storage/**",
                    "--exclude=!.agents/live",
                    "--exclude=!.agents/live/**",
                    "--exclude=!.agents/temp",
                    "--exclude=!.agents/temp/**",
                    "--exclude=!.agents/storage",
                    "--exclude=!.agents/storage/**",
                ],
                remaining_entries,
                remaining_output_bytes,
                deadline,
                "bounded managed-worktree ignored listing",
            )?;
            ensure_worktree_status_deadline(deadline, "after bounded ignored listing")?;
            ignored
        } else {
            Vec::new()
        };
        verify_repository_status_bindings(worktree_binding, &git_dir_binding, &common_dir_binding)?;
        Ok(BoundedWorktreeRecords {
            visible,
            status: bytes,
            ignored,
            process_queue_wait: Duration::ZERO,
        })
    })();
    let cleanup = (|| -> Result<usize> {
        status_lock.verify_direct_binding(state_root)?;
        let removed = scavenge_bounded_status_runtimes_until(
            state_root,
            WORKTREE_STATUS_SCAVENGE_LIMITS,
            deadline,
        )
        .context("failed to remove bounded-status private runtime")?;
        status_lock.verify_direct_binding(state_root)?;
        Ok(removed)
    })();
    let finished = match (result, cleanup) {
        (Ok(clean), Ok(_)) => Ok(clean),
        (Err(error), Ok(_)) => Err(error),
        (Ok(_), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), Err(cleanup_error)) => Err(error.context(format!(
            "bounded-status runtime cleanup also failed: {cleanup_error:#}"
        ))),
    };
    let finished = finish_with_status_lock_verification(
        finished,
        status_lock.verify_direct_binding(state_root),
    );
    finish_with_repository_binding_verification(
        finished,
        repository_binding.verify_status_generation(),
    )
}

fn validate_bounded_head(bytes: &[u8]) -> Result<()> {
    let value = std::str::from_utf8(bytes)
        .context("bounded-status HEAD is not UTF-8")?
        .trim();
    if value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(());
    }
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("bounded-status supports only SHA-1 repositories");
    }
    let Some(reference) = value.strip_prefix("ref: ") else {
        bail!("bounded-status HEAD is neither an object id nor symbolic reference");
    };
    if !reference.starts_with("refs/heads/")
        || reference.ends_with(['/', '.'])
        || reference.contains("..")
        || reference.contains("@{")
        || reference.contains("//")
        || reference.bytes().any(|byte| {
            byte.is_ascii_control()
                || byte == b' '
                || matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        })
    {
        bail!("bounded-status HEAD contains an unsafe symbolic reference");
    }
    Ok(())
}

fn verify_repository_status_bindings(
    worktree: &DirectoryBindingGuard,
    git_dir: &DirectoryBindingGuard,
    common_dir: &DirectoryBindingGuard,
) -> Result<()> {
    worktree
        .verify()
        .context("bounded-status worktree changed")?;
    git_dir
        .verify()
        .context("bounded-status Git directory changed")?;
    common_dir
        .verify()
        .context("bounded-status Git common directory changed")
}

fn finish_with_repository_binding_verification<T>(
    result: Result<T>,
    verification: Result<()>,
) -> Result<T> {
    match (result, verification) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(binding_error)) => Err(binding_error),
        (Err(error), Err(binding_error)) => Err(error.context(format!(
            "operation also lost its repository pathname binding: {binding_error:#}"
        ))),
    }
}

fn resolve_bounded_head(repository: &RepositoryBindingGuard, head: &[u8]) -> Result<Vec<u8>> {
    let value = std::str::from_utf8(head)
        .context("bounded-status HEAD is not UTF-8")?
        .trim();
    if value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(format!("{}\n", value.to_ascii_lowercase()).into_bytes());
    }
    let reference = value
        .strip_prefix("ref: ")
        .context("bounded-status HEAD has no supported target")?;
    let reference_path = Path::new(reference);
    if repository.git_dir() != repository.common_dir()
        && repository
            .read_git_relative_optional(reference_path, MAX_WORKTREE_HEAD_BYTES)?
            .is_some()
    {
        bail!("bounded-status rejects a linked-worktree shadow branch reference");
    }
    let loose =
        repository.read_common_relative_optional(reference_path, MAX_WORKTREE_HEAD_BYTES)?;
    if let Some(loose) = loose {
        let oid = parse_bounded_loose_reference(&loose)?;
        return Ok(format!("{oid}\n").into_bytes());
    }
    if let Some(packed) = repository
        .read_common_relative_optional(Path::new("packed-refs"), MAX_WORKTREE_GIT_TEXT_FILE_BYTES)?
    {
        if let Some(oid) = parse_bounded_packed_reference(&packed, reference)? {
            return Ok(format!("{oid}\n").into_bytes());
        }
    }
    // A symbolic target absent from both loose and packed refs is the exact
    // unborn-branch representation. Preserve it only after bounded lookup.
    Ok(format!("ref: {reference}\n").into_bytes())
}

fn parse_bounded_loose_reference(bytes: &[u8]) -> Result<String> {
    let value = std::str::from_utf8(bytes)
        .context("bounded-status loose reference is not UTF-8")?
        .trim();
    if value.starts_with("ref: ") {
        bail!("bounded-status rejects symbolic loose-reference chains");
    }
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("bounded-status loose reference is not a SHA-1 object id");
    }
    Ok(value.to_ascii_lowercase())
}

fn parse_bounded_packed_reference(bytes: &[u8], reference: &str) -> Result<Option<String>> {
    let contents = std::str::from_utf8(bytes).context("bounded-status packed-refs is not UTF-8")?;
    let mut found = None;
    for line in contents.lines() {
        if line.is_empty() || line.starts_with('#') || line.starts_with('^') {
            continue;
        }
        let mut fields = line.split(' ');
        let oid = fields
            .next()
            .context("packed-refs entry omitted object id")?;
        let name = fields
            .next()
            .context("packed-refs entry omitted reference name")?;
        if fields.next().is_some()
            || oid.len() != 40
            || !oid.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !name.starts_with("refs/")
        {
            bail!("bounded-status packed-refs contains a malformed entry");
        }
        if name == reference && found.replace(oid.to_ascii_lowercase()).is_some() {
            bail!("bounded-status packed-refs contains a duplicate reference");
        }
    }
    Ok(found)
}

fn validate_bounded_index_bytes(bytes: &[u8]) -> Result<()> {
    const HEADER_BYTES: usize = 12;
    const ENTRY_FIXED_BYTES: usize = 62;
    const CHECKSUM_BYTES: usize = 20;
    const CE_EXTENDED: u16 = 0x4000;
    const CE_VALID: u16 = 0x8000;
    const GITLINK_MODE: u32 = 0o160000;
    const SPARSE_DIRECTORY_MODE: u32 = 0o040000;

    if bytes.len() < HEADER_BYTES.saturating_add(CHECKSUM_BYTES) || &bytes[..4] != b"DIRC" {
        bail!("bounded-status SHA-1 index has an invalid header");
    }
    let payload_end = bytes.len() - CHECKSUM_BYTES;
    let expected_checksum = sha1_digest(&bytes[..payload_end])?;
    let checksum_mismatch = expected_checksum
        .iter()
        .zip(&bytes[payload_end..])
        .fold(0_u8, |difference, (expected, observed)| {
            difference | (expected ^ observed)
        });
    if checksum_mismatch != 0 {
        bail!("bounded-status index checksum is invalid");
    }
    let version = bounded_index_u32(bytes, 4)?;
    if !matches!(version, 2 | 3) {
        bail!("bounded-status index version {version} is unsupported");
    }
    let entry_count = usize::try_from(bounded_index_u32(bytes, 8)?)
        .context("bounded-status index entry count overflowed")?;
    if entry_count > MAX_WORKTREE_STATUS_ENTRIES {
        bail!("bounded-status index exceeds its entry limit");
    }
    let mut cursor = HEADER_BYTES;
    for _ in 0..entry_count {
        let fixed_end = cursor
            .checked_add(ENTRY_FIXED_BYTES)
            .context("bounded-status index entry offset overflowed")?;
        if fixed_end > payload_end {
            bail!("bounded-status index entry is truncated");
        }
        let mode = bounded_index_u32(bytes, cursor + 24)?;
        if matches!(mode, GITLINK_MODE | SPARSE_DIRECTORY_MODE) {
            bail!("bounded-status rejects gitlink and sparse-directory index entries");
        }
        let flags = bounded_index_u16(bytes, cursor + 60)?;
        if flags & CE_VALID != 0 {
            bail!("bounded-status rejects assume-unchanged index entries");
        }
        if flags & CE_EXTENDED != 0 {
            bail!("bounded-status rejects extended index flags");
        }
        let path_end = bytes[fixed_end..payload_end]
            .iter()
            .position(|byte| *byte == 0)
            .map(|offset| fixed_end + offset)
            .context("bounded-status index entry path is not terminated")?;
        let path_len = path_end.saturating_sub(fixed_end);
        let encoded_len = usize::from(flags & 0x0fff);
        if path_len == 0 || (encoded_len < 0x0fff && encoded_len != path_len) {
            bail!("bounded-status index entry path length is invalid");
        }
        let unpadded = path_end
            .checked_add(1)
            .and_then(|end| end.checked_sub(cursor))
            .context("bounded-status index entry length overflowed")?;
        let padded = unpadded
            .checked_add((8 - (unpadded % 8)) % 8)
            .context("bounded-status index padding overflowed")?;
        cursor = cursor
            .checked_add(padded)
            .context("bounded-status index cursor overflowed")?;
        if cursor > payload_end {
            bail!("bounded-status index entry padding is truncated");
        }
    }
    let mut saw_tree = false;
    while cursor < payload_end {
        let header_end = cursor
            .checked_add(8)
            .context("bounded-status index extension offset overflowed")?;
        if header_end > payload_end {
            bail!("bounded-status index extension header is truncated");
        }
        let signature = &bytes[cursor..cursor + 4];
        let length = usize::try_from(bounded_index_u32(bytes, cursor + 4)?)
            .context("bounded-status index extension length overflowed")?;
        let extension_end = header_end
            .checked_add(length)
            .context("bounded-status index extension length overflowed")?;
        if extension_end > payload_end {
            bail!("bounded-status index extension payload is truncated");
        }
        if signature != b"TREE" || saw_tree {
            bail!("bounded-status rejects unsupported, duplicate, or stateful index extensions");
        }
        saw_tree = true;
        cursor = extension_end;
    }
    Ok(())
}

fn sha1_digest(bytes: &[u8]) -> Result<[u8; 20]> {
    let byte_length = u64::try_from(bytes.len()).context("SHA-1 input length overflowed")?;
    let bit_length = byte_length
        .checked_mul(8)
        .context("SHA-1 bit length overflowed")?;
    let mut state = [
        0x6745_2301_u32,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    let mut chunks = bytes.chunks_exact(64);
    for chunk in &mut chunks {
        let mut block = [0_u8; 64];
        block.copy_from_slice(chunk);
        sha1_compress(&mut state, &block);
    }
    let remainder = chunks.remainder();
    let tail_blocks = if remainder.len() < 56 { 1 } else { 2 };
    let tail_len = tail_blocks * 64;
    let mut tail = [0_u8; 128];
    tail[..remainder.len()].copy_from_slice(remainder);
    tail[remainder.len()] = 0x80;
    tail[tail_len - 8..tail_len].copy_from_slice(&bit_length.to_be_bytes());
    for block in tail[..tail_len].chunks_exact(64) {
        let mut block_array = [0_u8; 64];
        block_array.copy_from_slice(block);
        sha1_compress(&mut state, &block_array);
    }
    let mut digest = [0_u8; 20];
    for (word, output) in state.iter().zip(digest.chunks_exact_mut(4)) {
        output.copy_from_slice(&word.to_be_bytes());
    }
    Ok(digest)
}

fn sha1_compress(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut words = [0_u32; 80];
    for (index, bytes) in block.chunks_exact(4).enumerate() {
        words[index] = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    for index in 16..80 {
        words[index] =
            (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
                .rotate_left(1);
    }
    let [mut a, mut b, mut c, mut d, mut e] = *state;
    for (index, word) in words.iter().enumerate() {
        let (function, constant) = match index {
            0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999),
            20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
            _ => (b ^ c ^ d, 0xca62_c1d6),
        };
        let next = a
            .rotate_left(5)
            .wrapping_add(function)
            .wrapping_add(e)
            .wrapping_add(constant)
            .wrapping_add(*word);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = next;
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

fn bounded_index_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .context("bounded-status index integer offset overflowed")?;
    let raw: [u8; 4] = bytes
        .get(offset..end)
        .context("bounded-status index integer is truncated")?
        .try_into()
        .context("bounded-status index integer has the wrong width")?;
    Ok(u32::from_be_bytes(raw))
}

fn bounded_index_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let end = offset
        .checked_add(2)
        .context("bounded-status index integer offset overflowed")?;
    let raw: [u8; 2] = bytes
        .get(offset..end)
        .context("bounded-status index integer is truncated")?
        .try_into()
        .context("bounded-status index integer has the wrong width")?;
    Ok(u16::from_be_bytes(raw))
}

fn validate_bounded_git_index_records(bytes: &[u8], max_entries: usize) -> Result<()> {
    let mut entries = 0usize;
    for record in bytes
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        entries = entries.saturating_add(1);
        if entries > max_entries {
            bail!("bounded-status index validation exceeded its entry limit");
        }
        let separator = record
            .iter()
            .position(|byte| *byte == b'\t')
            .context("bounded-status index validation omitted a path separator")?;
        let header = &record[..separator];
        if header.len() < 3 || header[1] != b' ' {
            bail!("bounded-status index validation returned a malformed header");
        }
        let tag = header[0];
        if tag == b'S' || tag.is_ascii_lowercase() {
            bail!("bounded-status rejects hidden index-entry state");
        }
        let header = std::str::from_utf8(&header[2..])
            .context("bounded-status index validation header is not ASCII")?;
        let mode = header
            .split_ascii_whitespace()
            .next()
            .context("bounded-status index validation omitted an entry mode")?;
        if matches!(mode, "160000" | "040000") {
            bail!("bounded-status rejects gitlink and sparse-directory index entries");
        }
    }
    Ok(())
}

struct BoundedGitTextInputs {
    info_exclude: Option<Vec<u8>>,
}

const MACO_STATUS_EXCLUDES: &[u8] = b"\n.maco/\n.maco-cache/\n.agent/temp/\n.agent/storage/\n.agents/live/\n.agents/temp/\n.agents/storage/\ntarget/\n";

fn is_bounded_status_runtime_path(path: &Path) -> bool {
    path.starts_with(".maco")
        || path.starts_with(".maco-cache")
        || path.starts_with("target")
        || path.starts_with(".agent/temp")
        || path.starts_with(".agent/storage")
        || path.starts_with(".agents/live")
        || path.starts_with(".agents/temp")
        || path.starts_with(".agents/storage")
}

#[cfg(test)]
fn validate_bounded_git_text_inputs(
    worktree: &Path,
    git_dir: &Path,
    common_dir: &Path,
    deadline: Instant,
) -> Result<BoundedGitTextInputs> {
    let binding = RepositoryBindingGuard::bind(worktree)?;
    if binding.git_dir() != git_dir || binding.common_dir() != common_dir {
        bail!("bounded-status repository metadata paths changed before prevalidation");
    }
    validate_bounded_git_text_inputs_bound(&binding, deadline)
}

fn validate_bounded_git_text_inputs_bound(
    repository: &RepositoryBindingGuard,
    deadline: Instant,
) -> Result<BoundedGitTextInputs> {
    let git_dir = repository.git_dir();
    let common_dir = repository.common_dir();
    if repository
        .read_common_relative_optional(
            Path::new("objects/info/alternates"),
            MAX_WORKTREE_GIT_TEXT_FILE_BYTES,
        )?
        .is_some_and(|bytes| !bytes.is_empty())
    {
        bail!("bounded-status rejects Git object alternates");
    }
    let inventory = BoundedTreeWalker::walk_bound_with(
        repository.worktree_binding(),
        BoundedTreeWalkLimits {
            max_depth: 128,
            max_entries: MAX_WORKTREE_STATUS_ENTRIES,
            max_path_bytes: MAX_PERSISTED_PATH_BYTES,
            max_total_path_bytes: MAX_WORKTREE_STATUS_OUTPUT_BYTES.saturating_mul(32),
            max_duration: remaining_worktree_status_time(
                deadline,
                "before Git ignore prevalidation",
            )?,
            same_device: true,
        },
        |entry| {
            if entry.relative_path == Path::new(".git") {
                return Ok(BoundedTreeWalkAction::Skip);
            }
            if entry.relative_path.file_name() == Some(OsStr::new(".git")) {
                bail!("bounded-status rejects nested Git repository markers");
            }
            if entry.relative_path.file_name() == Some(OsStr::new(".gitmodules")) {
                bail!("bounded-status rejects submodule metadata");
            }
            if is_bounded_status_runtime_path(&entry.relative_path) {
                return Ok(BoundedTreeWalkAction::Skip);
            }
            if entry.kind == BoundedTreeEntryKind::Directory {
                return Ok(BoundedTreeWalkAction::RecordAndDescend);
            }
            if entry.relative_path.file_name() == Some(OsStr::new(".gitignore")) {
                if !entry.is_safe_regular_file() {
                    bail!("Git ignore input is not a safe single-link regular file");
                }
                return Ok(BoundedTreeWalkAction::Record);
            }
            Ok(BoundedTreeWalkAction::Skip)
        },
    )?;
    if inventory
        .iter()
        .filter(|entry| entry.kind == BoundedTreeEntryKind::RegularFile)
        .count()
        > MAX_WORKTREE_GIT_TEXT_FILES
    {
        bail!("repository exceeds its Git ignore file count limit");
    }
    let mut total = 0_u64;
    for entry in inventory
        .iter()
        .filter(|entry| entry.kind == BoundedTreeEntryKind::RegularFile)
    {
        let bytes = repository
            .worktree_binding()
            .read_relative(&entry.relative_path, MAX_WORKTREE_GIT_TEXT_FILE_BYTES)?;
        total = total
            .checked_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
            .context("Git ignore aggregate byte count overflowed")?;
        if total > MAX_WORKTREE_GIT_TEXT_TOTAL_BYTES {
            bail!("repository exceeds its Git ignore aggregate byte limit");
        }
        ensure_worktree_status_deadline(deadline, "during Git ignore prevalidation")?;
    }
    if common_dir != git_dir
        && repository
            .read_git_relative_optional(
                Path::new("info/exclude"),
                MAX_WORKTREE_GIT_TEXT_FILE_BYTES,
            )?
            .is_some()
    {
        bail!("bounded-status rejects a linked-worktree shadow info/exclude");
    }
    let info_exclude = repository
        .read_common_relative_optional(Path::new("info/exclude"), MAX_WORKTREE_GIT_TEXT_FILE_BYTES)?
        .map(|bytes| String::from_utf8(bytes).context("Git exclude file is not UTF-8"))
        .transpose()?
        .map(String::into_bytes);
    for bytes in info_exclude.iter() {
        total = total
            .checked_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
            .context("Git metadata aggregate byte count overflowed")?;
    }
    for bytes in [
        repository
            .read_git_relative_optional(Path::new("config"), MAX_WORKTREE_GIT_TEXT_FILE_BYTES)?,
        repository
            .read_common_relative_optional(Path::new("config"), MAX_WORKTREE_GIT_TEXT_FILE_BYTES)?,
        repository.read_common_relative_optional(
            Path::new("config.worktree"),
            MAX_WORKTREE_GIT_TEXT_FILE_BYTES,
        )?,
    ]
    .into_iter()
    .flatten()
    {
        total = total
            .checked_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
            .context("Git metadata aggregate byte count overflowed")?;
        if total > MAX_WORKTREE_GIT_TEXT_TOTAL_BYTES {
            bail!("repository exceeds its Git metadata aggregate byte limit");
        }
    }
    if total > MAX_WORKTREE_GIT_TEXT_TOTAL_BYTES {
        bail!("repository exceeds its Git metadata aggregate byte limit");
    }
    ensure_worktree_status_deadline(deadline, "after Git metadata prevalidation")?;
    let mut effective_exclude = info_exclude.unwrap_or_default();
    effective_exclude.extend_from_slice(MACO_STATUS_EXCLUDES);
    Ok(BoundedGitTextInputs {
        info_exclude: Some(effective_exclude),
    })
}

#[cfg(unix)]
fn parse_porcelain_v1_z(bytes: &[u8], max_entries: usize) -> Result<Vec<(PathBuf, [u8; 2])>> {
    let mut records = Vec::new();
    for raw in bytes
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        if raw.len() < 4 || raw[2] != b' ' {
            bail!("bounded worktree status returned a malformed porcelain record");
        }
        let status = [raw[0], raw[1]];
        if !status
            .iter()
            .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
        {
            bail!("bounded worktree status returned malformed status bytes");
        }
        let path = PathBuf::from(OsString::from_vec(raw[3..].to_vec()));
        if path.as_os_str().is_empty()
            || path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            bail!("bounded worktree status returned an unsafe repository path");
        }
        records.push((path, status));
        if records.len() > max_entries {
            bail!("bounded worktree status exceeded its parsed entry limit");
        }
    }
    Ok(records)
}

#[cfg(unix)]
fn parse_nul_paths(bytes: &[u8], max_entries: usize) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for raw in bytes
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let path = PathBuf::from(OsString::from_vec(raw.to_vec()));
        if path.as_os_str().is_empty()
            || path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            bail!("bounded Git inventory returned an unsafe repository path");
        }
        paths.push(path);
        if paths.len() > max_entries {
            bail!("bounded Git inventory exceeded its parsed entry limit");
        }
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

#[cfg(not(unix))]
fn parse_nul_paths(_bytes: &[u8], _max_entries: usize) -> Result<Vec<PathBuf>> {
    bail!("lossless bounded Git inventory parsing is unsupported on this platform")
}

#[cfg(not(unix))]
fn parse_porcelain_v1_z(_bytes: &[u8], _max_entries: usize) -> Result<Vec<(PathBuf, [u8; 2])>> {
    bail!("lossless bounded Git status parsing is unsupported on this platform")
}

fn finish_with_status_lock_verification<T>(
    result: Result<T>,
    verification: Result<()>,
) -> Result<T> {
    match (result, verification) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(lock_error)) => Err(lock_error),
        (Err(error), Err(lock_error)) => Err(error.context(format!(
            "operation also lost its bounded-status lock-path binding: {lock_error:#}"
        ))),
    }
}

#[cfg(test)]
fn scavenge_bounded_status_runtimes(
    state_root: &SafeRoot,
    limits: PrivateDirectoryScavengeLimits,
) -> Result<usize> {
    scavenge_private_random_directories(
        state_root,
        WORKTREE_STATUS_RUNTIME_LOCK,
        WORKTREE_STATUS_RUNTIME_SEED,
        limits,
    )
}

fn scavenge_bounded_status_runtimes_until(
    state_root: &SafeRoot,
    mut limits: PrivateDirectoryScavengeLimits,
    deadline: Instant,
) -> Result<usize> {
    limits.max_duration =
        remaining_worktree_status_time(deadline, "before bounded-status runtime scavenging")?;
    scavenge_private_random_directories_until(
        state_root,
        WORKTREE_STATUS_RUNTIME_LOCK,
        WORKTREE_STATUS_RUNTIME_SEED,
        limits,
        deadline,
    )
}

fn validate_worktree_status_timeout(timeout: Duration) -> Result<()> {
    if timeout.is_zero() {
        bail!("worktree status total time budget must be non-zero");
    }
    Ok(())
}

fn worktree_status_deadline(timeout: Duration) -> Result<Instant> {
    validate_worktree_status_timeout(timeout)?;
    Instant::now()
        .checked_add(timeout)
        .context("worktree status total time budget overflowed")
}

fn remaining_worktree_status_time(deadline: Instant, phase: &str) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .with_context(|| format!("worktree status exhausted its total time budget {phase}"))
}

fn ensure_worktree_status_deadline(deadline: Instant, phase: &str) -> Result<()> {
    remaining_worktree_status_time(deadline, phase).map(|_| ())
}

struct BoundedGitContext<'a> {
    worktree: &'a Path,
    worktree_target: &'a Path,
    runtime_root: &'a SafeRoot,
    git_dir: &'a Path,
    objects_target: &'a Path,
}

#[cfg(all(target_os = "linux", not(test)))]
fn bounded_status_runtime_root(_worktree: &Path) -> Result<SafeRoot> {
    SafeRoot::open_or_create(PathBuf::from(format!(
        "/tmp/maco-worktree-status-{}",
        unsafe { libc::geteuid() }
    )))
}

#[cfg(all(target_os = "linux", test))]
fn bounded_status_runtime_root(worktree: &Path) -> Result<SafeRoot> {
    let repository = crate::git_repository::open(worktree).with_context(|| {
        format!(
            "failed to open test bounded-status repository {}",
            worktree.display()
        )
    })?;
    let common_dir = repository.commondir();
    let common_ancestor = worktree
        .ancestors()
        .find(|ancestor| common_dir.starts_with(ancestor))
        .context("test worktree and Git common directory have no common ancestor")?;
    let outside_worktree = if common_ancestor == worktree {
        common_ancestor
            .parent()
            .context("test worktree common ancestor has no parent")?
    } else {
        common_ancestor
    };
    let anchor = outside_worktree
        .ancestors()
        .find(|ancestor| ancestor.to_str().is_some())
        .context("test worktree has no UTF-8 ancestor for its private status alias")?;
    let binding = stable_checksum(worktree.as_os_str().as_bytes());
    SafeRoot::open_or_create(anchor.join(format!(".maco-test-worktree-status-{binding}")))
}

#[cfg(not(target_os = "linux"))]
fn bounded_status_runtime_root(_worktree: &Path) -> Result<SafeRoot> {
    bail!("bounded worktree status requires the verified Linux containment boundary")
}

#[cfg(unix)]
fn create_bounded_status_worktree_link(runtime: &SafeRoot, worktree: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::symlink;

    runtime.ensure_direct_child_absent("worktree")?;
    let alias = runtime.direct_child("worktree")?;
    symlink(worktree, &alias).with_context(|| {
        format!(
            "failed to bind private status context to worktree {}",
            worktree.display()
        )
    })?;
    Ok(alias)
}

#[cfg(not(unix))]
fn create_bounded_status_worktree_link(_runtime: &SafeRoot, worktree: &Path) -> Result<PathBuf> {
    bail!(
        "lossless private Git worktree binding is unsupported on this platform: {}",
        worktree.display()
    )
}

#[cfg(unix)]
fn create_validated_object_link(git_root: &SafeRoot, object_directory: &Path) -> Result<()> {
    use std::os::unix::fs::symlink;

    git_root.ensure_direct_child_absent("objects")?;
    symlink(object_directory, git_root.path().join("objects")).with_context(|| {
        format!(
            "failed to link private Git context to validated objects {}",
            object_directory.display()
        )
    })?;
    Ok(())
}

#[cfg(not(unix))]
fn create_validated_object_link(_git_root: &SafeRoot, object_directory: &Path) -> Result<()> {
    bail!(
        "lossless private Git object binding is unsupported on this platform: {}",
        object_directory.display()
    )
}

fn run_bounded_git_records<const N: usize>(
    context: &BoundedGitContext<'_>,
    args: [&str; N],
    max_entries: usize,
    max_output_bytes: usize,
    deadline: Instant,
    label: &str,
) -> Result<Vec<u8>> {
    let git = crate::merge::resolve_trusted_executable("git")
        .context("failed to resolve trusted Git for bounded worktree status")?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .context("worktree status exhausted its total time budget")?
        .min(WORKTREE_STATUS_COMMAND_TIMEOUT);
    context.runtime_root.verify()?;
    let mut environment = BTreeMap::new();
    environment.insert("GIT_ATTR_NOSYSTEM".to_string(), "1".to_string());
    environment.insert("GIT_CONFIG_GLOBAL".to_string(), "/dev/null".to_string());
    environment.insert("GIT_CONFIG_NOSYSTEM".to_string(), "1".to_string());
    environment.insert("GIT_OPTIONAL_LOCKS".to_string(), "0".to_string());
    environment.insert("GIT_PAGER".to_string(), "cat".to_string());
    environment.insert("GIT_TERMINAL_PROMPT".to_string(), "0".to_string());
    environment.insert("HOME".to_string(), "home".to_string());
    environment.insert("LANG".to_string(), "C".to_string());
    environment.insert("LC_ALL".to_string(), "C".to_string());
    environment.insert("PAGER".to_string(), "cat".to_string());
    environment.insert("TEMP".to_string(), "tmp".to_string());
    environment.insert("TMP".to_string(), "tmp".to_string());
    environment.insert("TMPDIR".to_string(), "tmp".to_string());
    environment.insert("XDG_CACHE_HOME".to_string(), "home/cache".to_string());
    environment.insert("XDG_CONFIG_HOME".to_string(), "home/config".to_string());
    let mut command_args = Vec::with_capacity(args.len().saturating_add(20));
    for config in [
        "core.fsmonitor=false",
        "core.untrackedCache=false",
        "core.splitIndex=false",
        "index.sparse=false",
        "submodule.recurse=false",
        "fetch.recurseSubmodules=false",
        "status.submoduleSummary=false",
        "extensions.objectFormat=sha1",
    ] {
        command_args.push(std::ffi::OsString::from("-c"));
        command_args.push(std::ffi::OsString::from(config));
    }
    command_args.push(std::ffi::OsString::from("--git-dir"));
    command_args.push(context.git_dir.as_os_str().to_os_string());
    command_args.push(std::ffi::OsString::from("--work-tree"));
    command_args.push(context.worktree.as_os_str().to_os_string());
    command_args.extend(args.into_iter().map(std::ffi::OsString::from));
    let mut side_effects = StrictOfflineWorkspaceProfile::read_write(context.runtime_root.path())
        .with_visible_read_only_root(context.worktree_target);
    if !context.objects_target.starts_with(context.worktree_target) {
        side_effects = side_effects.with_visible_read_only_root(context.objects_target);
    }
    let spec = ProcessSpec::direct(
        label,
        git,
        command_args,
        context.runtime_root.path(),
        max_output_bytes,
    )
    .with_environment(EnvironmentMode::ClearAndSet(environment))
    .with_containment(ContainmentPolicy::Required)
    .with_side_effect_confinement(SideEffectConfinementProfile::StrictOfflineWorkspace(
        side_effects,
    ))
    .with_stdin(StdinMode::Null)
    .with_timeout(Some(remaining));
    let output = run_process(spec).context("bounded worktree status command failed")?;
    if output.timed_out {
        bail!(
            "worktree status exceeded its {} millisecond time budget",
            remaining.as_millis()
        );
    }
    if output.stdout.is_truncated() || output.stderr.is_truncated() {
        bail!("worktree status exceeded its {max_output_bytes}-byte output budget");
    }
    require_verified_worktree_status_process(&output)?;
    let status = output
        .status
        .context("worktree status command returned no exit status")?;
    if !status.success() {
        let stderr = output.stderr.summarize_chars(512);
        bail!("worktree status command failed: {}", stderr.text);
    }
    let bytes = output.stdout.as_bytes();
    if !bytes.is_empty() && !bytes.ends_with(&[0]) {
        bail!("worktree status returned a malformed non-NUL-terminated record");
    }
    let entries = bytes.iter().filter(|byte| **byte == 0).count();
    if entries > max_entries {
        bail!("worktree status reported {entries} entries, exceeding its limit of {max_entries}");
    }
    Ok(bytes.to_vec())
}

fn require_verified_worktree_status_process(output: &ProcessOutput) -> Result<()> {
    if output.process_error.is_some() || output.stdin_error.is_some() {
        bail!("worktree status process cleanup was not verified");
    }
    if !output.safety_evidence_verified() {
        bail!("worktree status process safety evidence was not verified");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use git2::{Oid, Signature};
    #[cfg(unix)]
    use std::process::{Command, Output};
    use tempfile::TempDir;

    #[test]
    fn issue_84_pending_registry_operation_stops_existing_only_revalidation() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let base = commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-a".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root.clone()),
            })
            .expect("create managed worker");
        let lease = manager
            .acquire_write_execution_lease("agent-a")
            .expect("exclusive worker lease");
        let root = SafeRoot::open_or_create_managed(&worktree_root).expect("managed root");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
        let lock = store.lock().expect("registry lock");
        let mut registry = store.load(&lock).expect("registry");
        let pending_name = "pending-other".to_string();
        registry.operations.insert(
            pending_name.clone(),
            ManagedWorktreeOperation {
                kind: ManagedWorktreeOperationKind::Create,
                phase: ManagedWorktreeOperationPhase::CreateIntent,
                name: pending_name.clone(),
                root: root.path().to_path_buf(),
                root_identity: root.identity().clone(),
                path: root.path().join(&pending_name),
                prepared_path_identity: None,
                staging_root: None,
                staging_root_identity: None,
                staging_path: None,
                staged_path_identity: None,
                staged_metadata: None,
                branch: "maco/pending-other".to_string(),
                base_oid: base.to_string(),
                branch_preexisting_oid: None,
                branch_ownership: ManagedBranchOwnership::Unknown,
                owned_branch_oid: None,
                binding: None,
                delete_branch: false,
                force: false,
                expected_branch_oid: None,
                gc_dirtiness_checksum: None,
                removal_safety: None,
                worktree_quarantine_path: None,
                worktree_quarantine_identity: None,
                metadata_quarantine_path: None,
                metadata_quarantine_identity: None,
            },
        );
        store.save(&lock, &mut registry).expect("save pending op");
        drop(lock);
        drop(store);
        let error = manager
            .revalidate_existing_write_leases(vec![ExistingWorktreeBindingRequest {
                agent_id: "agent-a".to_string(),
                lease: &lease,
                expected_record: lease.record().clone(),
                expected_head_oid: base,
                expected_ref_oid: base,
            }])
            .expect_err("pending registry operation must stop the harness");
        assert!(
            matches!(
                error,
                ExistingWorktreeRevalidationError::PendingOperation { .. }
            ),
            "unexpected error: {error:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn managed_worktree_guard_blocks_branch_mismatch_and_allows_own_branch() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let remote_path = temp.path().join("remote.git");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        assert_test_git_success(
            temp.path(),
            &[
                "init",
                "--bare",
                remote_path.to_str().expect("UTF-8 remote path"),
            ],
        );
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        configure_test_git_identity(&repo);
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let cleanliness = manager
            .acquire_repository_cleanliness()
            .expect("capture clean repository capability");
        let lane = manager
            .create_with_repository_cleanliness(
                WorktreeCreateOptions {
                    agent_id: "guarded-lane".to_string(),
                    branch: None,
                    base: None,
                    worktree_root: Some(worktree_root),
                },
                &cleanliness,
            )
            .expect("create guarded worktree");
        let lane_repo = crate::git_repository::open(&lane.path).expect("open lane");
        let verified = verify_worktree_guard(
            &lane_repo,
            &WorktreeGuardMode::Managed {
                expected_branch: lane.branch.clone(),
            },
        )
        .expect("verify creation-time guard");
        assert_eq!(verified.status, WorktreeGuardStatus::Verified);
        let bootstrapped = ensure_registered_managed_worktree_guard(&lane.path)
            .expect("supervisor bootstrap must resolve the primary registry");
        assert_eq!(bootstrapped.status, WorktreeGuardStatus::AlreadyInstalled);

        let unregistered_path = temp.path().join("unregistered-linked");
        assert_test_git_success(
            &repo_path,
            &[
                "worktree",
                "add",
                "-b",
                "unregistered-guard-lane",
                unregistered_path.to_str().expect("UTF-8 unregistered path"),
            ],
        );
        let unregistered_error = ensure_registered_managed_worktree_guard(&unregistered_path)
            .expect_err("unregistered linked worktree must fail closed");
        assert!(unregistered_error
            .to_string()
            .contains("has no verified registry identity"));
        let unregistered_repo =
            crate::git_repository::open(&unregistered_path).expect("open unregistered worktree");
        assert!(!unregistered_repo
            .path()
            .join(WORKTREE_GUARD_DIRECTORY)
            .exists());
        assert_test_git_success(
            &lane.path,
            &[
                "remote",
                "add",
                "origin",
                remote_path.to_str().expect("UTF-8 remote path"),
            ],
        );

        fs::write(lane.path.join("README.md"), "# own branch\n").expect("edit own branch");
        assert_test_git_success(&lane.path, &["add", "README.md"]);
        let own_commit = run_test_git(&lane.path, &["commit", "-m", "own branch"], &[]);
        assert!(
            own_commit.status.success(),
            "own-branch commit must pass: {}",
            String::from_utf8_lossy(&own_commit.stderr)
        );
        let own_push = run_test_git(&lane.path, &["push", "-u", "origin", "HEAD"], &[]);
        assert!(
            own_push.status.success(),
            "own-branch push must pass: {}",
            String::from_utf8_lossy(&own_push.stderr)
        );

        assert_test_git_success(&lane.path, &["switch", "-c", "foreign-branch"]);
        fs::write(lane.path.join("README.md"), "# foreign branch\n").expect("edit foreign branch");
        assert_test_git_success(&lane.path, &["add", "README.md"]);
        let blocked = run_test_git(&lane.path, &["commit", "-m", "foreign blocked"], &[]);
        assert!(!blocked.status.success(), "foreign branch must be blocked");
        let blocked_stderr = String::from_utf8_lossy(&blocked.stderr);
        assert!(blocked_stderr.contains("managed lane branch 'foreign-branch'"));
        let environment_bypass = run_test_git(
            &lane.path,
            &["commit", "-m", "environment bypass"],
            &[("MACO_GUARD_ALLOW", "1")],
        );
        assert!(!environment_bypass.status.success());
        let prepared = run_test_git(
            &lane.path,
            &[
                "-c",
                "core.hooksPath=/dev/null",
                "commit",
                "-m",
                "prepare foreign push",
            ],
            &[],
        );
        assert!(prepared.status.success());
        let blocked_push = run_test_git(
            &lane.path,
            &["push", "origin", "HEAD:refs/heads/foreign-branch"],
            &[],
        );
        assert!(!blocked_push.status.success());
        assert!(String::from_utf8_lossy(&blocked_push.stderr)
            .contains("push from managed lane branch 'foreign-branch'"));
    }

    #[cfg(unix)]
    #[test]
    fn managed_worktree_guard_resolves_relative_prior_hooks_from_the_final_lane_path() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        configure_test_git_identity(&repo);
        commit_readme(&repo).expect("initial commit");

        let relative_hooks = repo_path.join(".githooks");
        fs::create_dir(&relative_hooks).expect("create relative hooks directory");
        let relative_pre_commit = relative_hooks.join("pre-commit");
        fs::write(
            &relative_pre_commit,
            "#!/bin/sh\nprintf 'relative-pre-commit\\n' >> \"$(git rev-parse --git-common-dir)/relative-hook-ran\"\n",
        )
        .expect("write relative pre-commit hook");
        fs::set_permissions(&relative_pre_commit, fs::Permissions::from_mode(0o700))
            .expect("make relative pre-commit hook executable");
        assert_test_git_success(&repo_path, &["add", ".githooks/pre-commit"]);
        assert_test_git_success(&repo_path, &["commit", "-m", "add relative hook"]);
        assert_test_git_success(&repo_path, &["config", "core.hooksPath", ".githooks"]);

        let lane = WorktreeManager::new(&repo_path)
            .create_for_test(WorktreeCreateOptions {
                agent_id: "relative-hook-lane".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create guarded worktree");
        let lane_repo = crate::git_repository::open(&lane.path).expect("open lane");
        let layout = worktree_guard_layout(&lane_repo).expect("resolve guard layout");
        assert_eq!(
            read_guard_path_line(&layout.root.join("previous-hooks-path"))
                .expect("read chained hooks path"),
            lane.path.join(".githooks")
        );
        assert_eq!(
            read_guard_path_line(&layout.root.join("previous-git-dir-hooks-path"))
                .expect("read chained Git-directory hooks path"),
            layout.git_dir.join(".githooks")
        );

        fs::write(lane.path.join("README.md"), "# relative hook lane\n").expect("edit lane");
        assert_test_git_success(&lane.path, &["add", "README.md"]);
        assert_test_git_success(&lane.path, &["commit", "-m", "exercise relative hook"]);
        assert_eq!(
            read_test_hook_log(&repo, "relative-hook-ran"),
            "relative-pre-commit\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn primary_worktree_guard_blocks_agent_and_custom_managed_branches_and_chains_hooks() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        configure_test_git_identity(&repo);
        commit_readme(&repo).expect("initial commit");
        install_test_repository_hooks(&repo);
        let lane = WorktreeManager::new(&repo_path)
            .create_for_test(WorktreeCreateOptions {
                agent_id: "custom-lane".to_string(),
                branch: Some("workers/custom-lane".to_string()),
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create custom-branch lane");
        let primary_guard =
            install_primary_worktree_guard(&repo_path).expect("install primary guard");

        fs::write(repo_path.join("README.md"), "# primary main\n").expect("edit primary main");
        assert_test_git_success(&repo_path, &["add", "README.md"]);
        let allowed = run_test_git(&repo_path, &["commit", "-m", "primary main"], &[]);
        assert!(
            allowed.status.success(),
            "primary main commit must pass: {}",
            String::from_utf8_lossy(&allowed.stderr)
        );
        assert_eq!(read_test_hook_log(&repo, "pre-commit-ran"), "pre-commit\n");
        assert_eq!(read_test_hook_log(&repo, "commit-msg-ran"), "commit-msg\n");
        let allowed_push =
            run_test_hook(&repo_path, &primary_guard.hooks_path.join("pre-push"), &[]);
        assert!(
            allowed_push.status.success(),
            "primary human-branch push hook must pass: {}",
            String::from_utf8_lossy(&allowed_push.stderr)
        );
        assert_eq!(read_test_hook_log(&repo, "pre-push-ran"), "pre-push\n");

        assert_test_git_success(&repo_path, &["switch", "-c", "task/human-owned"]);
        fs::write(repo_path.join("README.md"), "# primary human branch\n")
            .expect("edit primary human branch");
        assert_test_git_success(&repo_path, &["add", "README.md"]);
        assert_test_git_success(&repo_path, &["commit", "-m", "human branch"]);
        let human_push = run_test_hook(&repo_path, &primary_guard.hooks_path.join("pre-push"), &[]);
        assert!(human_push.status.success());

        assert_test_git_success(&repo_path, &["switch", "-c", "maco/rogue"]);
        fs::write(repo_path.join("README.md"), "# rogue\n").expect("edit rogue branch");
        assert_test_git_success(&repo_path, &["add", "README.md"]);
        let maco_blocked = run_test_git(&repo_path, &["commit", "-m", "rogue"], &[]);
        assert!(!maco_blocked.status.success());
        let maco_stderr = String::from_utf8_lossy(&maco_blocked.stderr);
        assert!(maco_stderr.contains("primary worktree on agent branch 'maco/rogue'"));
        assert_eq!(
            read_test_hook_log(&repo, "pre-commit-ran"),
            "pre-commit\npre-commit\n"
        );
        let blocked_push =
            run_test_hook(&repo_path, &primary_guard.hooks_path.join("pre-push"), &[]);
        assert!(!blocked_push.status.success());
        assert!(String::from_utf8_lossy(&blocked_push.stderr)
            .contains("push from the primary worktree on agent branch 'maco/rogue'"));
        assert_eq!(
            read_test_hook_log(&repo, "pre-push-ran"),
            "pre-push\npre-push\n"
        );

        assert_test_git_success(&repo_path, &["reset", "--hard", "HEAD"]);
        assert_test_git_success(&repo_path, &["switch", "main"]);
        assert_test_git_success(&lane.path, &["switch", "-c", "lane-parking"]);
        assert_test_git_success(&repo_path, &["switch", "workers/custom-lane"]);
        fs::write(repo_path.join("README.md"), "# custom managed\n")
            .expect("edit custom managed branch");
        assert_test_git_success(&repo_path, &["add", "README.md"]);
        let custom_blocked = run_test_git(&repo_path, &["commit", "-m", "custom"], &[]);
        assert!(!custom_blocked.status.success());
        assert!(String::from_utf8_lossy(&custom_blocked.stderr)
            .contains("primary worktree on managed branch 'workers/custom-lane'"));
    }

    #[cfg(unix)]
    #[test]
    fn worktree_guard_reinstall_is_idempotent_and_uninstall_restores_existing_hooks() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        configure_test_git_identity(&repo);
        commit_readme(&repo).expect("initial commit");
        install_test_repository_hooks(&repo);

        let first = install_primary_worktree_guard(&repo_path).expect("first install");
        let second = install_primary_worktree_guard(&repo_path).expect("idempotent reinstall");
        assert_eq!(first.status, WorktreeGuardStatus::Installed);
        assert_eq!(second.status, WorktreeGuardStatus::AlreadyInstalled);
        assert_eq!(first.hooks_path, second.hooks_path);
        let layout = worktree_guard_layout(&repo).expect("resolve default-hook guard layout");
        for state_name in ["previous-hooks-path", "previous-git-dir-hooks-path"] {
            assert_eq!(
                read_guard_path_line(&layout.root.join(state_name))
                    .expect("read default chained hooks path"),
                repo.commondir().join("hooks")
            );
        }
        let removed = uninstall_primary_worktree_guard(&repo_path).expect("uninstall guard");
        assert_eq!(removed.status, WorktreeGuardStatus::Removed);
        let absent = uninstall_primary_worktree_guard(&repo_path).expect("idempotent uninstall");
        assert_eq!(absent.status, WorktreeGuardStatus::AlreadyAbsent);

        assert_test_git_success(&repo_path, &["switch", "-c", "maco/unguarded"]);
        fs::write(repo_path.join("README.md"), "# restored hooks\n").expect("edit after uninstall");
        assert_test_git_success(&repo_path, &["add", "README.md"]);
        let commit = run_test_git(&repo_path, &["commit", "-m", "restored"], &[]);
        assert!(
            commit.status.success(),
            "uninstall must restore existing hooks: {}",
            String::from_utf8_lossy(&commit.stderr)
        );
        assert_eq!(read_test_hook_log(&repo, "pre-commit-ran"), "pre-commit\n");
        assert_eq!(read_test_hook_log(&repo, "commit-msg-ran"), "commit-msg\n");
    }

    #[cfg(unix)]
    #[test]
    fn worktree_guard_dispatchers_satisfy_current_human_authorship_v3_check() {
        let marker = HUMAN_AUTHORSHIP_GUARD_V3_MARKER;
        assert!(!WORKTREE_GUARD_ASSET
            .windows(marker.len())
            .any(|window| window == marker));

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        configure_test_git_identity(&repo);
        commit_readme(&repo).expect("initial commit");
        install_test_repository_hooks(&repo);
        let report = install_primary_worktree_guard(&repo_path).expect("install guard");

        // This is the current install-human-authorship-guard --check contract:
        // the effective commit-msg and pre-push hooks are executable and each
        // contains the exact v3 compatibility marker.
        for hook_name in ["commit-msg", "pre-push"] {
            let hook = report.hooks_path.join(hook_name);
            assert_ne!(
                fs::metadata(&hook)
                    .expect("inspect composing dispatcher")
                    .permissions()
                    .mode()
                    & 0o111,
                0
            );
            assert!(fs::read(&hook)
                .expect("read composing dispatcher")
                .windows(marker.len())
                .any(|window| window == marker));
        }

        let prior_commit_msg = repo.commondir().join("hooks/commit-msg");
        fs::write(&prior_commit_msg, b"#!/bin/sh\nexit 0\n")
            .expect("remove prior v3 compatibility marker");
        verify_primary_worktree_guard(&repo_path).expect(
            "persisted install-time composition must not be rederived from mutable prior hooks",
        );

        let plain_path = temp.path().join("plain");
        WorktreeManager::init_repository(&plain_path, "main").expect("init marker-absent repo");
        let plain = crate::git_repository::open(&plain_path).expect("open marker-absent repo");
        configure_test_git_identity(&plain);
        commit_readme(&plain).expect("initial marker-absent commit");
        let plain_report =
            install_primary_worktree_guard(&plain_path).expect("install marker-absent guard");
        for hook_name in ["commit-msg", "pre-push"] {
            let hook = plain_report.hooks_path.join(hook_name);
            assert!(!fs::read(&hook)
                .expect("read marker-absent dispatcher")
                .windows(marker.len())
                .any(|window| window == marker));
        }

        assert_test_git_success(&plain_path, &["switch", "-c", "maco/backup-slot"]);
        let pre_push = plain_report.hooks_path.join("pre-push");
        let backup = plain_report
            .hooks_path
            .join("pre-push.human-authorship-previous");
        fs::rename(&pre_push, &backup).expect("simulate human installer backup move");
        let blocked = run_test_hook(&plain_path, &backup, &[]);
        assert!(!blocked.status.success());
        assert!(String::from_utf8_lossy(&blocked.stderr)
            .contains("push from the primary worktree on agent branch 'maco/backup-slot'"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn worktree_guard_verify_and_uninstall_preserve_later_human_v3_and_custom_hooks() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        configure_test_git_identity(&repo);
        commit_readme(&repo).expect("initial commit");
        let prior = repo_path.join("custom-hooks");
        fs::create_dir(&prior).expect("create prior hooks");
        let custom_commit = b"#!/bin/sh\nprintf 'custom commit-msg\\n' >/dev/null\n";
        let custom_push = b"#!/bin/sh\ncat >/dev/null\n";
        for (name, bytes) in [
            ("commit-msg", custom_commit.as_slice()),
            ("pre-push", custom_push.as_slice()),
        ] {
            let hook = prior.join(name);
            fs::write(&hook, bytes).expect("write custom prior hook");
            fs::set_permissions(&hook, fs::Permissions::from_mode(0o711))
                .expect("make custom prior hook executable");
        }
        repo.config()
            .expect("open config")
            .set_str("core.hooksPath", "custom-hooks")
            .expect("configure custom hooks");
        let report = install_primary_worktree_guard(&repo_path).expect("install MACO guard");

        for (name, wrapper) in [
            ("commit-msg", HUMAN_AUTHORSHIP_COMMIT_MSG_V3),
            ("pre-push", HUMAN_AUTHORSHIP_PRE_PUSH_V3),
        ] {
            let hook = report.hooks_path.join(name);
            let backup = report
                .hooks_path
                .join(format!("{name}.human-authorship-previous"));
            fs::rename(&hook, &backup).expect("primary v3 installer preserves MACO hook");
            fs::write(&hook, wrapper).expect("write exact primary v3 dispatcher shape");
            fs::set_permissions(&hook, fs::Permissions::from_mode(0o755))
                .expect("make v3 dispatcher executable");
        }

        verify_primary_worktree_guard(&repo_path)
            .expect("verify must accept exact later-installed v3 wrapper and MACO backup");
        uninstall_primary_worktree_guard(&repo_path)
            .expect("uninstall must migrate v3 while preserving custom hooks");
        assert_eq!(
            repo.config()
                .expect("reopen config")
                .get_path("core.hooksPath")
                .expect("restored hooks path"),
            PathBuf::from("custom-hooks")
        );
        for (name, wrapper, custom) in [
            (
                "commit-msg",
                HUMAN_AUTHORSHIP_COMMIT_MSG_V3,
                custom_commit.as_slice(),
            ),
            (
                "pre-push",
                HUMAN_AUTHORSHIP_PRE_PUSH_V3,
                custom_push.as_slice(),
            ),
        ] {
            assert_eq!(
                fs::read(prior.join(name)).expect("read migrated v3"),
                wrapper
            );
            let backup = prior.join(format!("{name}.human-authorship-previous"));
            assert_eq!(
                fs::read(&backup).expect("read preserved custom hook"),
                custom
            );
            assert_eq!(
                fs::metadata(&backup)
                    .expect("inspect preserved custom hook")
                    .permissions()
                    .mode()
                    & 0o7777,
                0o711
            );
        }
        assert!(!repo.path().join(WORKTREE_GUARD_DIRECTORY).exists());
    }

    #[cfg(unix)]
    #[test]
    fn worktree_guard_hook_refuses_cross_repository_invocation() {
        let temp = TempDir::new().expect("tempdir");
        let guarded_path = temp.path().join("guarded");
        let other_path = temp.path().join("other");
        WorktreeManager::init_repository(&guarded_path, "main").expect("init guarded repo");
        WorktreeManager::init_repository(&other_path, "main").expect("init other repo");
        let guarded = crate::git_repository::open(&guarded_path).expect("open guarded repo");
        let other = crate::git_repository::open(&other_path).expect("open other repo");
        configure_test_git_identity(&guarded);
        configure_test_git_identity(&other);
        commit_readme(&guarded).expect("commit guarded repo");
        commit_readme(&other).expect("commit other repo");
        let report = install_primary_worktree_guard(&guarded_path).expect("install guard");

        let output = run_test_hook(&other_path, &report.hooks_path.join("pre-commit"), &[]);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr)
            .contains("commit because the Git directory identity changed"));
    }

    #[cfg(unix)]
    #[test]
    fn worktree_guard_install_refuses_markerless_expected_name_without_mutation() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        configure_test_git_identity(&repo);
        commit_readme(&repo).expect("initial commit");

        let guard_root = repo.path().join(WORKTREE_GUARD_DIRECTORY);
        fs::create_dir(&guard_root).expect("create foreign guard root");
        fs::set_permissions(&guard_root, fs::Permissions::from_mode(0o751))
            .expect("set foreign root mode");
        let foreign_state = guard_root.join("mode");
        let foreign_bytes = b"foreign markerless expected-name content\n";
        fs::write(&foreign_state, foreign_bytes).expect("write foreign expected-name state");
        fs::set_permissions(&foreign_state, fs::Permissions::from_mode(0o640))
            .expect("set foreign state mode");

        let config_path = repo.path().join("config");
        let root_before = fs::symlink_metadata(&guard_root).expect("inspect foreign root");
        let state_before = fs::symlink_metadata(&foreign_state).expect("inspect foreign state");
        let config_before = fs::read(&config_path).expect("read Git config before refusal");
        let config_mode_before = fs::metadata(&config_path)
            .expect("inspect Git config before refusal")
            .permissions()
            .mode();

        let error = install_primary_worktree_guard(&repo_path)
            .expect_err("markerless foreign guard state must be rejected");
        assert!(error
            .to_string()
            .contains("directory exists without an ownership marker; refusing collision"));

        let root_after = fs::symlink_metadata(&guard_root).expect("reinspect foreign root");
        let state_after = fs::symlink_metadata(&foreign_state).expect("reinspect foreign state");
        assert_eq!(root_after.dev(), root_before.dev());
        assert_eq!(root_after.ino(), root_before.ino());
        assert_eq!(
            root_after.permissions().mode(),
            root_before.permissions().mode()
        );
        assert_eq!(state_after.dev(), state_before.dev());
        assert_eq!(state_after.ino(), state_before.ino());
        assert_eq!(
            state_after.permissions().mode(),
            state_before.permissions().mode()
        );
        assert_eq!(
            fs::read(&foreign_state).expect("read foreign state after refusal"),
            foreign_bytes
        );
        assert!(!guard_root.join("marker").exists());
        assert_eq!(
            fs::read_dir(&guard_root)
                .expect("enumerate foreign root after refusal")
                .map(|entry| entry.expect("read foreign entry").file_name())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([OsString::from("mode")])
        );
        assert_eq!(
            fs::read(&config_path).expect("read Git config after refusal"),
            config_before
        );
        assert_eq!(
            fs::metadata(&config_path)
                .expect("inspect Git config after refusal")
                .permissions()
                .mode(),
            config_mode_before
        );
    }

    #[cfg(unix)]
    #[test]
    fn worktree_guard_reinstall_refuses_changed_regular_hook_without_overwrite() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        configure_test_git_identity(&repo);
        commit_readme(&repo).expect("initial commit");
        let report = install_primary_worktree_guard(&repo_path).expect("install guard");
        let hook = report.hooks_path.join("commit-msg");
        let changed = b"#!/bin/sh\n# locally changed regular hook\nexit 0\n";
        fs::write(&hook, changed).expect("replace fixture dispatcher bytes");

        let error = install_primary_worktree_guard(&repo_path)
            .expect_err("reinstall must not overwrite changed regular hook");
        assert!(error
            .to_string()
            .contains("refusing to overwrite changed or non-MACO guard hook"));
        assert_eq!(
            fs::read(&hook).expect("read refused hook"),
            changed,
            "reinstall refusal must preserve changed hook bytes"
        );
    }

    #[cfg(unix)]
    #[test]
    fn orchestrated_git_hooks_path_null_remains_unaffected_by_advisory_guard() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        configure_test_git_identity(&repo);
        commit_readme(&repo).expect("initial commit");
        install_test_repository_hooks(&repo);
        install_primary_worktree_guard(&repo_path).expect("install guard");
        assert_test_git_success(&repo_path, &["switch", "-c", "maco/orchestrated"]);
        fs::write(repo_path.join("README.md"), "# command scoped bypass\n")
            .expect("edit agent branch");
        assert_test_git_success(&repo_path, &["add", "README.md"]);

        let commit = run_test_git(
            &repo_path,
            &[
                "-c",
                "core.hooksPath=/dev/null",
                "commit",
                "-m",
                "trusted orchestration",
            ],
            &[],
        );
        assert!(
            commit.status.success(),
            "command-scoped hooksPath isolation must bypass all repository hooks: {}",
            String::from_utf8_lossy(&commit.stderr)
        );
        assert_eq!(read_test_hook_log(&repo, "pre-commit-ran"), "");
        assert_eq!(read_test_hook_log(&repo, "commit-msg-ran"), "");
    }

    #[cfg(unix)]
    #[test]
    fn bounded_status_parsers_are_lossless_and_fail_closed() {
        let parsed = parse_porcelain_v1_z(b" M src/lib.rs\0?? new file.rs\0", 2)
            .expect("parse status records");
        assert_eq!(parsed[0], (PathBuf::from("src/lib.rs"), [b' ', b'M']));
        assert_eq!(parsed[1], (PathBuf::from("new file.rs"), [b'?', b'?']));
        assert!(parse_porcelain_v1_z(b" M ../escape\0", 2).is_err());
        assert!(parse_porcelain_v1_z(b"bad\0", 2).is_err());

        let visible = parse_nul_paths(b"README.md\0src/lib.rs\0", 2).expect("parse visible paths");
        assert_eq!(
            visible,
            vec![PathBuf::from("README.md"), PathBuf::from("src/lib.rs")]
        );
        assert!(parse_nul_paths(b"../escape\0", 2).is_err());
    }

    #[test]
    fn bounded_index_accepts_only_plain_sha1_entries_and_tree_cache() {
        fn empty_index(extension: Option<(&[u8; 4], &[u8])>) -> Vec<u8> {
            let mut bytes = b"DIRC\0\0\0\x02\0\0\0\0".to_vec();
            if let Some((signature, payload)) = extension {
                bytes.extend_from_slice(signature);
                bytes.extend_from_slice(
                    &u32::try_from(payload.len())
                        .expect("extension length")
                        .to_be_bytes(),
                );
                bytes.extend_from_slice(payload);
            }
            let checksum = sha1_digest(&bytes).expect("index checksum");
            bytes.extend_from_slice(&checksum);
            bytes
        }

        fn refresh_checksum(bytes: &mut Vec<u8>) {
            bytes.truncate(bytes.len() - 20);
            let checksum = sha1_digest(bytes).expect("refresh index checksum");
            bytes.extend_from_slice(&checksum);
        }

        validate_bounded_index_bytes(&empty_index(None)).expect("plain empty index");
        validate_bounded_index_bytes(&empty_index(Some((b"TREE", b""))))
            .expect("ordinary TREE cache extension");
        assert!(validate_bounded_index_bytes(&empty_index(Some((b"FSMN", b"")))).is_err());
        assert!(validate_bounded_index_bytes(&empty_index(Some((b"link", b"")))).is_err());

        let mut entry = b"DIRC\0\0\0\x02\0\0\0\x01".to_vec();
        entry.extend_from_slice(&[0; 62]);
        entry[12 + 24..12 + 28].copy_from_slice(&0o100644_u32.to_be_bytes());
        entry[12 + 60..12 + 62].copy_from_slice(&1_u16.to_be_bytes());
        entry.push(b'a');
        entry.push(0);
        let checksum = sha1_digest(&entry).expect("entry checksum");
        entry.extend_from_slice(&checksum);
        validate_bounded_index_bytes(&entry).expect("ordinary SHA-1 index entry");

        let mut all_zero_checksum = entry.clone();
        let checksum_start = all_zero_checksum.len() - 20;
        all_zero_checksum[checksum_start..].fill(0);
        assert!(validate_bounded_index_bytes(&all_zero_checksum).is_err());

        let mut tampered = entry.clone();
        tampered[12 + 24] ^= 1;
        assert!(validate_bounded_index_bytes(&tampered).is_err());

        let mut assume_unchanged = entry.clone();
        assume_unchanged[12 + 60..12 + 62].copy_from_slice(&(0x8000_u16 | 1).to_be_bytes());
        refresh_checksum(&mut assume_unchanged);
        assert!(validate_bounded_index_bytes(&assume_unchanged).is_err());

        let mut extended = entry;
        extended[12 + 60..12 + 62].copy_from_slice(&(0x4000_u16 | 1).to_be_bytes());
        refresh_checksum(&mut extended);
        assert!(validate_bounded_index_bytes(&extended).is_err());
    }

    #[test]
    fn internal_sha1_matches_nist_abc_vector() {
        assert_eq!(
            sha1_digest(b"abc").expect("SHA-1 digest"),
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
            ]
        );
    }

    #[test]
    fn bounded_head_resolution_distinguishes_normal_and_unborn_branches() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let unborn = RepositoryBindingGuard::bind(&repo_path).expect("bind unborn repo");
        let unborn_head = unborn
            .read_git_relative(Path::new("HEAD"), MAX_WORKTREE_HEAD_BYTES)
            .expect("read unborn HEAD");
        assert!(std::str::from_utf8(
            &resolve_bounded_head(&unborn, &unborn_head).expect("resolve unborn HEAD")
        )
        .expect("UTF-8 unborn HEAD")
        .starts_with("ref: refs/heads/main"));

        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let oid = commit_readme(&repo).expect("commit README");
        let committed = RepositoryBindingGuard::bind(&repo_path).expect("bind committed repo");
        let committed_head = committed
            .read_git_relative(Path::new("HEAD"), MAX_WORKTREE_HEAD_BYTES)
            .expect("read committed HEAD");
        assert_eq!(
            std::str::from_utf8(
                &resolve_bounded_head(&committed, &committed_head).expect("resolve committed HEAD")
            )
            .expect("UTF-8 committed HEAD")
            .trim(),
            oid.to_string()
        );
    }

    #[test]
    fn repository_binding_rejects_git_association_replacement() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let binding = RepositoryBindingGuard::bind(&repo_path).expect("bind repository");
        fs::rename(repo_path.join(".git"), repo_path.join(".git-displaced"))
            .expect("displace git marker");
        fs::create_dir(repo_path.join(".git")).expect("replace git marker");

        assert!(binding.verify().is_err());
    }

    #[test]
    fn effectful_worktree_cleanliness_entries_fail_closed_before_repository_access() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo-must-not-be-opened");
        let manager = WorktreeManager::new(&repo_path);
        let create_error = manager
            .create(WorktreeCreateOptions {
                agent_id: "worker".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(temp.path().join("must-not-be-created")),
            })
            .expect_err("worktree create must fail closed");
        let remove_error = manager
            .remove("worker", false, true)
            .expect_err("non-force removal must fail closed");

        assert!(create_error.to_string().contains("capability-bound"));
        assert!(remove_error.to_string().contains("capability-bound"));
        assert_eq!(fs::read_dir(temp.path()).expect("read temp").count(), 0);
    }

    #[test]
    fn neutral_worktree_rejects_each_normalized_source_identity_before_repository_access() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo-must-not-be-opened");
        let worktree_root = temp.path().join("must-not-be-created");
        let manager = WorktreeManager::new(&repo_path);

        for source_agent_ids in [
            [" arbiter ".to_string(), "source-b".to_string()],
            ["source-a".to_string(), "\tarbiter\n".to_string()],
        ] {
            let error = manager
                .create_neutral_for_test(NeutralWorktreeCreateOptions {
                    arbiter_agent_id: "arbiter".to_string(),
                    source_agent_ids,
                    base_oid: Oid::ZERO_SHA1,
                    worktree_root: Some(worktree_root.clone()),
                })
                .expect_err("arbiter identity equal to either source must be refused");
            assert!(error
                .to_string()
                .contains("must differ from both normalized source agent ids"));
        }

        assert!(!repo_path.exists());
        assert!(!worktree_root.exists());
    }

    #[test]
    fn neutral_worktree_refuses_inherited_durable_claim_without_mutating_it() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let base_oid = commit_readme(&repo).expect("initial commit");
        let claims = SyncStore::open(&repo_path).expect("open claims");
        let inherited = claims
            .claim_paths("neutral-arbiter", ["src"])
            .expect("seed inherited claim");
        let manager = WorktreeManager::new(&repo_path);

        let error = manager
            .create_neutral_for_test(NeutralWorktreeCreateOptions {
                arbiter_agent_id: "neutral-arbiter".to_string(),
                source_agent_ids: ["source-a".to_string(), "source-b".to_string()],
                base_oid,
                worktree_root: Some(worktree_root.clone()),
            })
            .expect_err("inherited durable claim must be refused");

        assert!(error
            .to_string()
            .contains("active durable path claim; refusing inherited claim authority"));
        assert_eq!(
            claims.snapshot().expect("claims after refusal"),
            vec![inherited]
        );
        assert!(repo
            .find_branch("maco/neutral-arbiter", BranchType::Local)
            .is_err());
        assert!(!worktree_root.join("neutral-arbiter").exists());
    }

    #[test]
    fn neutral_worktree_refuses_preexisting_default_branch() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let base_oid = commit_readme(&repo).expect("initial commit");
        let base = repo.find_commit(base_oid).expect("find base commit");
        repo.branch("maco/neutral-arbiter", &base, false)
            .expect("seed branch");
        let manager = WorktreeManager::new(&repo_path);

        let error = manager
            .create_neutral_for_test(NeutralWorktreeCreateOptions {
                arbiter_agent_id: "neutral-arbiter".to_string(),
                source_agent_ids: ["source-a".to_string(), "source-b".to_string()],
                base_oid,
                worktree_root: Some(worktree_root.clone()),
            })
            .expect_err("preexisting default branch must be refused");

        assert!(error
            .to_string()
            .contains("requires a fresh MACO-owned default branch"));
        assert_eq!(
            repo.find_branch("maco/neutral-arbiter", BranchType::Local)
                .expect("preexisting branch remains")
                .get()
                .target(),
            Some(base_oid)
        );
        assert!(manager
            .list_managed_verified()
            .expect("list managed worktrees")
            .is_empty());
        assert!(!worktree_root.join("neutral-arbiter").exists());
    }

    #[test]
    fn neutral_worktree_refuses_existing_managed_identity() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let base_oid = commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let existing = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "neutral-arbiter".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root.clone()),
            })
            .expect("seed managed worktree");

        let error = manager
            .create_neutral_for_test(NeutralWorktreeCreateOptions {
                arbiter_agent_id: "neutral-arbiter".to_string(),
                source_agent_ids: ["source-a".to_string(), "source-b".to_string()],
                base_oid,
                worktree_root: Some(worktree_root),
            })
            .expect_err("existing managed identity must be refused");

        assert!(error
            .to_string()
            .contains("already has managed worktree state; refusing reuse"));
        assert_eq!(
            manager
                .list_managed_verified()
                .expect("list existing managed worktree"),
            vec![existing]
        );
    }

    #[test]
    fn neutral_worktree_uses_fresh_default_branch_at_exact_base_without_claim() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let exact_base_oid = commit_readme(&repo).expect("initial commit");
        let newer_oid = commit_descendant(&repo, "README.md", "# Newer\n").expect("newer commit");
        let manager = WorktreeManager::new(&repo_path);

        let record = manager
            .create_neutral_for_test(NeutralWorktreeCreateOptions {
                arbiter_agent_id: "neutral-arbiter".to_string(),
                source_agent_ids: ["source-a".to_string(), "source-b".to_string()],
                base_oid: exact_base_oid,
                worktree_root: Some(worktree_root),
            })
            .expect("create neutral worktree");

        assert_eq!(record.name, "neutral-arbiter");
        assert_eq!(record.branch, "maco/neutral-arbiter");
        assert_eq!(
            repo.find_branch(&record.branch, BranchType::Local)
                .expect("fresh neutral branch")
                .get()
                .target(),
            Some(exact_base_oid)
        );
        assert_eq!(
            repo.head()
                .expect("primary HEAD")
                .target()
                .expect("primary HEAD target"),
            newer_oid
        );
        assert_eq!(
            fs::read_to_string(record.path.join("README.md")).expect("read neutral README"),
            "# Test\n"
        );
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
        let lock = store.lock().expect("registry lock");
        let registry = store.load(&lock).expect("registry");
        let binding = registry
            .records
            .get("neutral-arbiter")
            .expect("neutral binding");
        assert!(binding.branch_created_by_maco);
        assert_eq!(binding.base_oid, exact_base_oid.to_string());
        assert_eq!(binding.created_branch_oid, exact_base_oid.to_string());
        assert!(SyncStore::open(&repo_path)
            .expect("open claims")
            .snapshot()
            .expect("claims after neutral create")
            .is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn neutral_worktree_production_cleanliness_seam_uses_exact_base_without_claim() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let exact_base_oid = commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let cleanliness = manager
            .acquire_repository_cleanliness()
            .expect("capture clean repository capability");

        let record = manager
            .create_neutral_with_repository_cleanliness(
                NeutralWorktreeCreateOptions {
                    arbiter_agent_id: "neutral-production-arbiter".to_string(),
                    source_agent_ids: ["agent-a".to_string(), "agent-b".to_string()],
                    base_oid: exact_base_oid,
                    worktree_root: Some(worktree_root),
                },
                &cleanliness,
            )
            .expect("create production capability-bound neutral worktree");

        assert_eq!(record.name, "neutral-production-arbiter");
        assert_eq!(record.branch, "maco/neutral-production-arbiter");
        assert_eq!(
            repo.find_branch("maco/neutral-production-arbiter", BranchType::Local)
                .expect("fresh neutral branch")
                .get()
                .target(),
            Some(exact_base_oid)
        );
        assert!(SyncStore::open(&repo_path)
            .expect("open claims")
            .snapshot()
            .expect("claims after production neutral create")
            .is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn repository_cleanliness_capability_creates_clean_managed_worktree() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let cleanliness = manager
            .acquire_repository_cleanliness()
            .expect("capture clean repository capability");

        let record = manager
            .create_with_repository_cleanliness(
                WorktreeCreateOptions {
                    agent_id: "capability-worker".to_string(),
                    branch: None,
                    base: None,
                    worktree_root: Some(worktree_root),
                },
                &cleanliness,
            )
            .expect("create capability-bound worktree");

        assert_eq!(record.name, "capability-worker");
        assert_eq!(record.branch, "maco/capability-worker");
        assert!(record.path.join("README.md").is_file());
        assert!(bounded_repository_status_paths(
            &record.path,
            MAX_WORKTREE_STATUS_ENTRIES,
            MAX_WORKTREE_STATUS_OUTPUT_BYTES,
            WORKTREE_GC_STATUS_TIMEOUT,
        )
        .expect("inspect created worktree")
        .is_empty());
        assert_eq!(
            manager.list_managed_verified().expect("list worktrees"),
            vec![record]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn repository_cleanliness_capability_refuses_dirty_primary_before_create() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let cleanliness = manager
            .acquire_repository_cleanliness()
            .expect("capture clean repository capability");
        fs::write(repo_path.join("README.md"), "dirty\n").expect("dirty primary");

        let error = manager
            .create_with_repository_cleanliness(
                WorktreeCreateOptions {
                    agent_id: "must-not-exist".to_string(),
                    branch: None,
                    base: None,
                    worktree_root: Some(worktree_root.clone()),
                },
                &cleanliness,
            )
            .expect_err("dirty primary must be refused");

        assert!(error.to_string().contains("primary repository is dirty"));
        assert!(!worktree_root.exists());
        assert!(repo
            .find_branch("maco/must-not-exist", BranchType::Local)
            .is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn repository_cleanliness_capability_rejects_cross_repository_use() {
        let temp = TempDir::new().expect("tempdir");
        let first_path = temp.path().join("first");
        let second_path = temp.path().join("second");
        WorktreeManager::init_repository(&first_path, "main").expect("init first repo");
        WorktreeManager::init_repository(&second_path, "main").expect("init second repo");
        commit_readme(&crate::git_repository::open(&first_path).expect("open first"))
            .expect("commit first");
        commit_readme(&crate::git_repository::open(&second_path).expect("open second"))
            .expect("commit second");
        let first = WorktreeManager::new(&first_path);
        let second = WorktreeManager::new(&second_path);
        let cleanliness = first
            .acquire_repository_cleanliness()
            .expect("capture first capability");
        let second_worktrees = temp.path().join("second-worktrees");

        let error = second
            .create_with_repository_cleanliness(
                WorktreeCreateOptions {
                    agent_id: "cross-repository".to_string(),
                    branch: None,
                    base: None,
                    worktree_root: Some(second_worktrees.clone()),
                },
                &cleanliness,
            )
            .expect_err("cross-repository capability must be refused");

        assert!(error.to_string().contains("different managed repository"));
        assert!(!second_worktrees.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn repository_cleanliness_capability_rejects_binding_drift() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let cleanliness = manager
            .acquire_repository_cleanliness()
            .expect("capture repository capability");
        fs::rename(repo_path.join(".git"), repo_path.join(".git-displaced"))
            .expect("displace git directory");
        fs::create_dir(repo_path.join(".git")).expect("replace git directory");

        let error = manager
            .create_with_repository_cleanliness(
                WorktreeCreateOptions {
                    agent_id: "binding-drift".to_string(),
                    branch: None,
                    base: None,
                    worktree_root: Some(worktree_root.clone()),
                },
                &cleanliness,
            )
            .expect_err("binding drift must be refused");

        let message = format!("{error:#}");
        assert!(
            message.contains("association changed")
                || message.contains("failed to open repository"),
            "unexpected binding-drift error: {message}"
        );
        assert!(!worktree_root.exists());
    }

    #[test]
    fn pending_inspection_is_read_only_and_force_cleanup_is_explicit() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let oid = commit_readme(&repo).expect("initial commit");
        let root = SafeRoot::open_or_create_managed(&worktree_root).expect("worktree root");
        let manager = WorktreeManager::new(&repo_path);
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
        let lock = store.lock().expect("registry lock");
        let mut registry = store.load(&lock).expect("registry");
        let name = "agent-pending".to_string();
        let staging_root = root.path().join("pending-stage");
        registry.operations.insert(
            name.clone(),
            ManagedWorktreeOperation {
                kind: ManagedWorktreeOperationKind::Create,
                phase: ManagedWorktreeOperationPhase::CreateIntent,
                name: name.clone(),
                root: root.path().to_path_buf(),
                root_identity: root.identity().clone(),
                path: root.path().join(&name),
                prepared_path_identity: None,
                staging_root: Some(staging_root.clone()),
                staging_root_identity: None,
                staging_path: Some(staging_root.join(&name)),
                staged_path_identity: None,
                staged_metadata: None,
                branch: "maco/agent-pending".to_string(),
                base_oid: oid.to_string(),
                branch_preexisting_oid: None,
                branch_ownership: ManagedBranchOwnership::Unknown,
                owned_branch_oid: None,
                binding: None,
                delete_branch: false,
                force: false,
                expected_branch_oid: None,
                gc_dirtiness_checksum: None,
                removal_safety: None,
                worktree_quarantine_path: None,
                worktree_quarantine_identity: None,
                metadata_quarantine_path: None,
                metadata_quarantine_identity: None,
            },
        );
        store.save(&lock, &mut registry).expect("save intent");
        drop(lock);
        drop(store);
        drop(repo);

        let pending = manager
            .pending_operations()
            .expect("inspect pending intent");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].name, name);
        assert_eq!(pending[0].kind, "create");
        assert_eq!(pending[0].phase, "create_intent");
        assert!(!pending[0].force);
        assert!(manager
            .list_managed_verified()
            .expect("list without recovery")
            .is_empty());
        assert_eq!(
            manager
                .pending_operations()
                .expect("intent must remain pending"),
            pending
        );
        assert!(!root.path().join(&name).exists());
        assert!(!staging_root.exists());

        let authenticated_root_path = repo_path
            .join(".git/maco/state")
            .join(ManagedSnapshotSpec::ROOT_NAME);
        let authenticated_root =
            SafeRoot::open_existing(&authenticated_root_path).expect("authenticated root");
        let locator_name = fs::read_dir(&authenticated_root_path)
            .expect("authenticated entries")
            .map(|entry| entry.expect("authenticated entry").file_name())
            .find(|entry| {
                entry
                    .to_str()
                    .is_some_and(|name| name.starts_with(".snapshot-locator-"))
            })
            .expect("managed snapshot locator");
        AtomicStateWriter::write_direct_fenced(
            &authenticated_root,
            &locator_name,
            b"crash-temp",
            || bail!("injected locator temp"),
        )
        .expect_err("leave transitional metadata residue");
        let residue_inventory = fs::read_dir(&authenticated_root_path)
            .expect("inventory with residue")
            .map(|entry| entry.expect("residue entry").file_name())
            .collect::<std::collections::BTreeSet<_>>();
        let error = manager
            .pending_operations()
            .expect_err("pending reader must refuse transitional metadata");
        assert!(error.to_string().contains("unexpected file"));
        assert_eq!(
            fs::read_dir(&authenticated_root_path)
                .expect("inventory after refusal")
                .map(|entry| entry.expect("residue entry").file_name())
                .collect::<std::collections::BTreeSet<_>>(),
            residue_inventory,
            "pending inspection scavenged metadata residue"
        );

        let cleanup_error = manager
            .remove(&name, true, false)
            .expect_err("force must recover the intent before reporting no binding");
        assert!(cleanup_error
            .to_string()
            .contains("has no create-time managed binding"));
        assert!(manager
            .pending_operations()
            .expect("inspect cleaned operations")
            .is_empty());
    }

    #[test]
    fn pending_inspection_of_fresh_repository_creates_no_maco_state() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let common_dir = repo.path().to_path_buf();
        assert!(!common_dir.join("maco").exists());

        let pending = WorktreeManager::new(&repo_path)
            .pending_operations()
            .expect("fresh repository has no pending operations");

        assert!(pending.is_empty());
        assert!(!common_dir.join("maco").exists());
    }

    #[test]
    fn linked_worktree_rejects_shadow_branch_and_exclude_authority() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let linked_path = temp.path().join("linked");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let first = commit_readme(&repo).expect("first commit");
        let second = commit_descendant(&repo, "README.md", "# Second\n").expect("second commit");
        let first_commit = repo.find_commit(first).expect("find first commit");
        let branch = repo
            .branch("topic", &first_commit, false)
            .expect("create topic");
        let reference = branch.into_reference();
        let mut options = WorktreeAddOptions::new();
        options.reference(Some(&reference));
        repo.worktree("linked-authority", &linked_path, Some(&options))
            .expect("create linked worktree");
        repo.find_reference("refs/heads/topic")
            .expect("find topic")
            .set_target(second, "advance authoritative topic")
            .expect("advance topic");
        let binding = RepositoryBindingGuard::bind(&linked_path).expect("bind linked worktree");
        let shadow_ref = binding.git_dir().join("refs/heads/topic");
        fs::create_dir_all(shadow_ref.parent().expect("shadow ref parent"))
            .expect("create shadow ref parent");
        fs::write(&shadow_ref, format!("{first}\n")).expect("write shadow ref");
        let head = binding
            .read_git_relative(Path::new("HEAD"), MAX_WORKTREE_HEAD_BYTES)
            .expect("read linked HEAD");
        assert!(resolve_bounded_head(&binding, &head).is_err());

        fs::remove_file(&shadow_ref).expect("remove shadow ref");
        let common_exclude = binding.common_dir().join("info/exclude");
        fs::create_dir_all(common_exclude.parent().expect("common exclude parent"))
            .expect("create common exclude parent");
        fs::write(&common_exclude, b"common-only\n").expect("write common exclude");
        let shadow_exclude = binding.git_dir().join("info/exclude");
        fs::create_dir_all(shadow_exclude.parent().expect("shadow exclude parent"))
            .expect("create shadow exclude parent");
        fs::write(&shadow_exclude, b"shadow\n").expect("write shadow exclude");
        assert!(validate_bounded_git_text_inputs(
            &linked_path,
            binding.git_dir(),
            binding.common_dir(),
            Instant::now() + Duration::from_secs(2),
        )
        .is_err());

        fs::remove_file(&shadow_exclude).expect("remove shadow exclude");
        let inputs = validate_bounded_git_text_inputs(
            &linked_path,
            binding.git_dir(),
            binding.common_dir(),
            Instant::now() + Duration::from_secs(2),
        )
        .expect("accept common exclude");
        assert!(inputs
            .info_exclude
            .expect("effective exclude")
            .starts_with(b"common-only\n"));
    }

    #[cfg(unix)]
    #[test]
    fn bounded_git_input_preflight_rejects_oversized_and_linked_ignore_files() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let ignore = repo_path.join(".gitignore");
        let oversized = fs::File::create(&ignore).expect("create ignore");
        oversized
            .set_len(MAX_WORKTREE_GIT_TEXT_FILE_BYTES + 1)
            .expect("size ignore");
        let deadline = Instant::now() + Duration::from_secs(2);
        assert!(validate_bounded_git_text_inputs(
            &repo_path,
            repo.path(),
            repo.commondir(),
            deadline,
        )
        .is_err());

        fs::remove_file(&ignore).expect("remove ignore");
        let outside = temp.path().join("outside-ignore");
        fs::write(&outside, "target/\n").expect("write outside ignore");
        symlink(&outside, &ignore).expect("link ignore");
        let deadline = Instant::now() + Duration::from_secs(2);
        assert!(validate_bounded_git_text_inputs(
            &repo_path,
            repo.path(),
            repo.commondir(),
            deadline,
        )
        .is_err());

        fs::remove_file(&ignore).expect("remove linked ignore");
        let gitmodules = repo_path.join(".gitmodules");
        fs::write(&gitmodules, b"[submodule \"unsafe\"]\n").expect("write gitmodules");
        assert!(validate_bounded_git_text_inputs(
            &repo_path,
            repo.path(),
            repo.commondir(),
            Instant::now() + Duration::from_secs(2),
        )
        .is_err());

        fs::remove_file(&gitmodules).expect("remove gitmodules");
        let alternates = repo.commondir().join("objects/info/alternates");
        fs::create_dir_all(alternates.parent().expect("alternates parent"))
            .expect("create alternates parent");
        fs::write(&alternates, b"/tmp/objects\n").expect("write alternates");
        assert!(validate_bounded_git_text_inputs(
            &repo_path,
            repo.path(),
            repo.commondir(),
            Instant::now() + Duration::from_secs(2),
        )
        .is_err());
    }

    #[test]
    fn bounded_status_rejects_unverified_side_effect_evidence() {
        let output = ProcessOutput {
            status: None,
            duration: Duration::ZERO,
            timed_out: false,
            process_tree: crate::process_runner::ProcessTreeEvidence::VerifiedEmpty(
                crate::process_runner::ContainmentBackend::DirectChild,
            ),
            side_effects: crate::process_runner::SideEffectConfinementEvidence::Unverified(
                crate::process_runner::SideEffectConfinementProfileKind::StrictOfflineWorkspace,
            ),
            stdout: crate::process_runner::CapturedBytes::default(),
            stderr: crate::process_runner::CapturedBytes::default(),
            process_error: None,
            stdin_error: None,
        };

        let error = require_verified_worktree_status_process(&output).unwrap_err();

        assert!(error
            .to_string()
            .contains("safety evidence was not verified"));
    }

    #[test]
    fn initializes_repository_with_requested_initial_branch() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");

        let info = WorktreeManager::init_repository(&repo_path, "main").expect("init repo");

        assert_eq!(info.path, repo_path);
        assert_eq!(info.head, None);
        assert!(info.git_dir.ends_with(".git"));
    }

    #[cfg(unix)]
    #[test]
    fn repository_info_fails_closed_on_non_utf8_head_target() -> Result<()> {
        let temp = TempDir::new()?;
        let repository = Repository::init(temp.path())?;
        assert_eq!(repository_info(&repository)?.head, None);
        fs::write(repository.path().join("HEAD"), b"ref: refs/heads/non\xff\n")?;

        let error = repository_info(&repository).expect_err("non-UTF-8 HEAD must fail");
        assert!(error
            .to_string()
            .contains("repository HEAD symbolic target is not valid UTF-8"));
        Ok(())
    }

    #[test]
    fn creates_lists_and_removes_worktree() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");

        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-a".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");

        assert_eq!(created.name, "agent-a");
        assert_eq!(created.branch, "maco/agent-a");
        assert!(created.path.join("README.md").exists());

        let listed = manager.list().expect("list worktrees");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "agent-a");

        let removed = manager
            .remove("agent-a", true, true)
            .expect("force remove worktree");
        assert_eq!(removed.name, "agent-a");
        assert!(!removed.path.exists());
        assert!(repo.find_branch("maco/agent-a", BranchType::Local).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn workspace_sweep_defaults_to_dry_run_and_requires_apply_for_removal() {
        let temp = TempDir::new().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let repo_path = workspace.join("repo+name");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let worktree_root = workspace.join(".maco/worktrees/repo_name");
        let created = create_gc_worktree(
            &WorktreeManager::new(&repo_path),
            "sweep-default",
            &worktree_root,
        );

        let preview = sweep_workspace_worktrees(workspace_sweep_options(&workspace, false))
            .expect("preview workspace sweep");
        assert!(preview.dry_run);
        assert!(!preview.apply);
        assert_eq!(preview.repository_discovered_count, 1);
        assert_eq!(preview.repository_inspected_count, 1);
        assert_eq!(preview.repository_failure_count, 0);
        assert_eq!(preview.removed_count, 1);
        assert_eq!(
            preview.repositories[0].status,
            WorktreeSweepRepositoryStatus::Inspected
        );
        let preview_gc = preview.repositories[0]
            .gc_report
            .as_ref()
            .expect("preview GC report");
        assert_eq!(preview_gc.entries[0].status, WorktreeGcStatus::WouldRemove);
        assert_eq!(
            preview.apparent_considered_bytes,
            preview_gc.apparent_considered_bytes
        );
        assert_eq!(
            preview.estimated_reclaimable_bytes,
            preview_gc.estimated_reclaimable_bytes
        );
        assert_eq!(preview.estimated_reclaimed_bytes, 0);
        assert!(created.path.exists());

        let applied = sweep_workspace_worktrees(workspace_sweep_options(&workspace, true))
            .expect("apply workspace sweep");
        assert!(!applied.dry_run);
        assert!(applied.apply);
        assert_eq!(applied.removed_count, 1);
        assert_eq!(
            applied.repositories[0]
                .gc_report
                .as_ref()
                .expect("applied GC report")
                .entries[0]
                .status,
            WorktreeGcStatus::Removed
        );
        assert!(!created.path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn workspace_sweep_discovers_repository_local_worktree_root() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let worktree_root = repo_path.join(".worktrees");
        let created = create_gc_worktree(
            &WorktreeManager::new(&repo_path),
            "repo-local-lane",
            &worktree_root,
        );

        let report = sweep_workspace_worktrees(workspace_sweep_options(&repo_path, false))
            .expect("sweep repository-local root");

        assert_eq!(
            report.discovery_status,
            WorktreeSweepDiscoveryStatus::RootsDiscovered
        );
        assert_eq!(report.worktree_root_discovered_count, 1);
        assert_eq!(report.repository_discovered_count, 1);
        assert_eq!(report.repository_inspected_count, 1);
        assert_eq!(report.considered_count, 1);
        assert_eq!(report.removed_count, 1, "{report:#?}");
        assert_eq!(
            report.repositories[0].root_kind,
            WorktreeSweepRootKind::RepositoryLocal
        );
        assert_eq!(report.repositories[0].worktree_root, worktree_root);
        assert!(created.path.exists(), "sweep remains dry-run by default");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn repository_local_sweep_uses_primary_hint_despite_stale_lane_metadata() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let worktree_root = repo_path.join(".worktrees");
        let created = create_gc_worktree(
            &WorktreeManager::new(&repo_path),
            "healthy-lane",
            &worktree_root,
        );
        let stale = worktree_root.join("stale-registration");
        fs::create_dir(&stale).expect("stale lane directory");
        fs::write(
            stale.join(".git"),
            "gitdir: /definitely/missing/worktree-metadata\n",
        )
        .expect("stale Git marker");

        let report = sweep_workspace_worktrees(workspace_sweep_options(&repo_path, false))
            .expect("repository-local primary hint remains authoritative");

        assert_eq!(report.repository_inspected_count, 1, "{report:#?}");
        assert_eq!(report.repository_pre_gc_skipped_count, 0, "{report:#?}");
        assert!(report.repositories[0]
            .gc_report
            .as_ref()
            .expect("GC report")
            .entries
            .iter()
            .any(|entry| {
                entry.name == created.name && entry.status == WorktreeGcStatus::WouldRemove
            }));
        assert!(created.path.exists());
        assert!(stale.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn repository_local_dry_run_previews_registered_only_untracked_lane() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = repo_path.join(".worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let oid = commit_readme(&repo).expect("initial commit");
        fs::create_dir(&worktree_root).expect("repository-local worktree root");
        let commit = repo.find_commit(oid).expect("commit");
        let branch = repo
            .branch("topic/legacy", &commit, false)
            .expect("legacy branch");
        let reference = branch.into_reference();
        let mut add = WorktreeAddOptions::new();
        add.reference(Some(&reference));
        let lane = worktree_root.join("legacy-lane");
        repo.worktree("legacy-lane", &lane, Some(&add))
            .expect("registered-only worktree");
        fs::write(lane.join("TASK.md"), "task brief\n").expect("untracked task brief");

        let state = repo.path().join("maco/state");
        fs::create_dir_all(&state).expect("legacy state directory");
        fs::set_permissions(&state, fs::Permissions::from_mode(0o755))
            .expect("legacy public state mode");

        let protected = sweep_workspace_worktrees(workspace_sweep_options(&repo_path, false))
            .expect("registered-only protected preview");
        let protected_entry = protected.repositories[0]
            .gc_report
            .as_ref()
            .expect("fallback preview")
            .entries
            .iter()
            .find(|entry| entry.name == "legacy-lane")
            .expect("legacy lane classification");
        assert_eq!(protected_entry.status, WorktreeGcStatus::Protected);
        assert_eq!(protected_entry.reason, WorktreeGcReason::UntrackedOnly);
        assert_eq!(
            protected_entry.untracked_paths,
            vec![PathBuf::from("TASK.md")]
        );

        let mut allowed = workspace_sweep_options(&repo_path, false);
        allowed.allowed_untracked_paths = vec![PathBuf::from("TASK.md")];
        let reclaimable = sweep_workspace_worktrees(allowed)
            .expect("registered-only reclaimable preview with exact override");
        let reclaimable_entry = reclaimable.repositories[0]
            .gc_report
            .as_ref()
            .expect("fallback preview")
            .entries
            .iter()
            .find(|entry| entry.name == "legacy-lane")
            .expect("legacy lane classification");
        assert_eq!(reclaimable_entry.status, WorktreeGcStatus::WouldRemove);
        assert_eq!(reclaimable_entry.reason, WorktreeGcReason::FinishedBranch);
        assert_eq!(
            reclaimable_entry.untracked_paths,
            vec![PathBuf::from("TASK.md")]
        );
        assert!(lane.exists(), "dry-run must preserve registered-only lane");
        assert!(lane.join("TASK.md").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn workspace_sweep_discovers_direct_child_repo_local_and_managed_roots_once_each() {
        let temp = TempDir::new().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let repo_path = workspace.join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let managed_root = workspace.join(".maco/worktrees/repo");
        let local_root = repo_path.join(".worktrees");
        let managed_old = create_gc_worktree(&manager, "managed-old-lane", &managed_root);
        fs::write(managed_old.path.join("sizing.bin"), vec![b'm'; 64 * 1024])
            .expect("managed old artifact");
        let managed_new = create_gc_worktree(&manager, "managed-new-lane", &managed_root);
        fs::write(managed_new.path.join("sizing.bin"), vec![b'n'; 64])
            .expect("managed new artifact");
        let local_old = create_gc_worktree(&manager, "local-old-lane", &local_root);
        fs::write(local_old.path.join("sizing.bin"), vec![b'l'; 128 * 1024])
            .expect("local old artifact");
        let local_new = create_gc_worktree(&manager, "local-new-lane", &local_root);
        fs::write(local_new.path.join("sizing.bin"), vec![b'r'; 128]).expect("local new artifact");
        let managed_old_size =
            gc_worktree_size_estimate(&managed_old.path).expect("managed old size");
        let managed_new_size =
            gc_worktree_size_estimate(&managed_new.path).expect("managed new size");
        let local_old_size = gc_worktree_size_estimate(&local_old.path).expect("local old size");
        let local_new_size = gc_worktree_size_estimate(&local_new.path).expect("local new size");
        let per_root_budget = managed_new_size
            .worktree_bytes
            .max(local_new_size.worktree_bytes);
        assert!(managed_old_size.worktree_bytes > per_root_budget);
        assert!(local_old_size.worktree_bytes > per_root_budget);

        let mut options = workspace_sweep_options(&workspace, false);
        options.remove_targets = false;
        options.retention.max_total_bytes = Some(per_root_budget);
        options.allowed_untracked_paths = vec![PathBuf::from("sizing.bin")];
        let report =
            sweep_workspace_worktrees(options).expect("sweep direct-child repository roots");

        assert_eq!(report.worktree_root_discovered_count, 2);
        assert_eq!(report.repository_inspected_count, 2);
        assert_eq!(report.considered_count, 4);
        assert_eq!(report.removed_count, 2, "{report:#?}");
        assert_eq!(report.retained_count, 2, "{report:#?}");
        let nested_apparent_bytes = report
            .repositories
            .iter()
            .try_fold(0u64, |total, entry| {
                total.checked_add(
                    entry
                        .gc_report
                        .as_ref()
                        .expect("nested GC report")
                        .apparent_considered_bytes,
                )
            })
            .expect("nested apparent byte sum");
        let nested_reclaimable_bytes = report
            .repositories
            .iter()
            .try_fold(0u64, |total, entry| {
                total.checked_add(
                    entry
                        .gc_report
                        .as_ref()
                        .expect("nested GC report")
                        .estimated_reclaimable_bytes,
                )
            })
            .expect("nested reclaimable byte sum");
        assert!(nested_apparent_bytes > 0);
        assert_eq!(report.apparent_considered_bytes, nested_apparent_bytes);
        assert_eq!(report.estimated_reclaimable_bytes, nested_reclaimable_bytes);
        assert_eq!(report.estimated_reclaimed_bytes, 0);
        assert_eq!(
            report
                .repositories
                .iter()
                .map(|entry| (
                    entry.root_kind,
                    entry.gc_report.as_ref().map(|gc| (
                        gc.considered_count,
                        gc.removed_count,
                        gc.retained_count,
                        gc.max_total_bytes,
                    ))
                ))
                .collect::<Vec<_>>(),
            vec![
                (
                    WorktreeSweepRootKind::WorkspaceManaged,
                    Some((2, 1, 1, Some(per_root_budget))),
                ),
                (
                    WorktreeSweepRootKind::RepositoryLocal,
                    Some((2, 1, 1, Some(per_root_budget))),
                ),
            ]
        );
        for (root_kind, retained_name, expected_reclaimable) in [
            (
                WorktreeSweepRootKind::WorkspaceManaged,
                managed_new.name.as_str(),
                managed_old_size.worktree_bytes,
            ),
            (
                WorktreeSweepRootKind::RepositoryLocal,
                local_new.name.as_str(),
                local_old_size.worktree_bytes,
            ),
        ] {
            let gc = report
                .repositories
                .iter()
                .find(|entry| entry.root_kind == root_kind)
                .and_then(|entry| entry.gc_report.as_ref())
                .expect("per-root GC report");
            assert_eq!(gc.estimated_reclaimable_bytes, expected_reclaimable);
            assert!(gc.entries.iter().any(|entry| {
                entry.name == retained_name
                    && entry.status == WorktreeGcStatus::Retained
                    && entry.reason == WorktreeGcReason::RetentionKeep
            }));
        }
        assert!(managed_old.path.exists());
        assert!(managed_new.path.exists());
        assert!(local_old.path.exists());
        assert!(local_new.path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn workspace_sweep_refuses_symlinked_repository_local_root() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).expect("outside root");
        let sentinel = outside.join("sentinel");
        fs::write(&sentinel, "preserve\n").expect("outside sentinel");
        symlink(&outside, repo_path.join(".worktrees")).expect("symlink local root");

        let report = sweep_workspace_worktrees(workspace_sweep_options(&repo_path, true))
            .expect("typed symlinked root refusal");

        assert_eq!(report.worktree_root_discovered_count, 1);
        assert_eq!(report.repository_inspected_count, 0);
        assert_eq!(report.repository_pre_gc_skipped_count, 1);
        assert_eq!(
            report.repositories[0].root_kind,
            WorktreeSweepRootKind::RepositoryLocal
        );
        assert!(report.repositories[0]
            .failure
            .as_ref()
            .expect("typed refusal")
            .message
            .contains("not a plain directory"));
        assert!(sentinel.exists());
    }

    #[test]
    fn workspace_sweep_reports_zero_roots_as_a_distinct_discovery_state() {
        let temp = TempDir::new().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace");

        let report = sweep_workspace_worktrees(workspace_sweep_options(&workspace, false))
            .expect("empty workspace sweep");

        assert_eq!(
            report.discovery_status,
            WorktreeSweepDiscoveryStatus::NoRootsDiscovered
        );
        assert_eq!(report.worktree_root_discovered_count, 0);
        assert_eq!(report.repository_discovered_count, 0);
        assert_eq!(report.repository_inspected_count, 0);
        let json = serde_json::to_value(&report).expect("serialize sweep report");
        assert_eq!(json["discovery_status"], "no_roots_discovered");
        assert_eq!(json["worktree_root_discovered_count"], 0);

        let repo_path = temp.path().join("empty-repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init empty repo");
        let repo = crate::git_repository::open(&repo_path).expect("open empty repo");
        commit_readme(&repo).expect("initial empty repo commit");
        fs::create_dir(repo_path.join(".worktrees")).expect("empty supported root");

        let clean_empty = sweep_workspace_worktrees(workspace_sweep_options(&repo_path, false))
            .expect("sweep existing empty root");
        assert_eq!(
            clean_empty.discovery_status,
            WorktreeSweepDiscoveryStatus::RootsDiscovered
        );
        assert_eq!(clean_empty.worktree_root_discovered_count, 1);
        assert_eq!(clean_empty.repository_inspected_count, 1);
        assert_eq!(clean_empty.considered_count, 0);
        assert_eq!(clean_empty.removed_count, 0);
        assert_eq!(clean_empty.protected_count, 0);
        assert_eq!(clean_empty.retained_count, 0);
        let clean_json = serde_json::to_value(&clean_empty).expect("serialize clean empty sweep");
        assert_eq!(clean_json["discovery_status"], "roots_discovered");
        assert_ne!(json["discovery_status"], clean_json["discovery_status"]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_scopes_managed_bindings_to_the_exact_requested_root() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let local = create_gc_worktree(&manager, "local-lane", &repo_path.join(".worktrees"));
        let other = create_gc_worktree(&manager, "other-lane", &repo_path.join(".other-worktrees"));

        let report = manager
            .gc(gc_options(Some(PathBuf::from(".worktrees")), false))
            .expect("GC one relative managed root");

        assert_eq!(report.considered_count, 1);
        assert_eq!(report.removed_count, 1, "{report:#?}");
        assert!(!local.path.exists());
        assert!(other.path.exists());
        assert_eq!(manager.list().expect("remaining worktrees"), vec![other]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_without_requested_root_preserves_all_authenticated_root_scope() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let first = create_gc_worktree(&manager, "first-lane", &repo_path.join(".worktrees"));
        let second =
            create_gc_worktree(&manager, "second-lane", &repo_path.join(".other-worktrees"));

        let report = manager
            .gc(gc_options(None, false))
            .expect("default GC spans authenticated managed roots");

        assert_eq!(report.considered_count, 2);
        assert_eq!(report.removed_count, 2);
        assert!(!first.path.exists());
        assert!(!second.path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_rejects_requested_root_beneath_intermediate_symlink() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let actual_parent = temp.path().join("actual-parent");
        fs::create_dir(&actual_parent).expect("actual parent");
        let actual_root = actual_parent.join("worktrees");
        let created = create_gc_worktree(&manager, "linked-root-lane", &actual_root);
        let linked_parent = temp.path().join("linked-parent");
        symlink(&actual_parent, &linked_parent).expect("intermediate parent symlink");

        let error = manager
            .gc(gc_options(Some(linked_parent.join("worktrees")), false))
            .expect_err("intermediate symlink must be rejected");

        assert!(error.to_string().contains("failed to bind worktree root"));
        assert!(created.path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn workspace_sweep_inspects_repository_and_group_with_maco_prefix() {
        let temp = TempDir::new().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let repo_path = workspace.join(".maco-repository");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let worktree_root = workspace.join(".maco/worktrees/.maco-repository");
        let created = create_gc_worktree(
            &WorktreeManager::new(&repo_path),
            "prefixed-lane",
            &worktree_root,
        );

        let report = sweep_workspace_worktrees(workspace_sweep_options(&workspace, false))
            .expect("sweep prefixed repository");
        assert_eq!(report.repository_discovered_count, 1);
        assert_eq!(report.repository_inspected_count, 1);
        assert_eq!(report.repository_failure_count, 0);
        assert_eq!(report.repositories.len(), 1);
        assert_eq!(report.repositories[0].group, ".maco-repository");
        assert_eq!(
            report.repositories[0].status,
            WorktreeSweepRepositoryStatus::Inspected
        );
        assert_eq!(
            report.repositories[0].repository.as_deref(),
            Some(repo_path.as_path())
        );
        assert!(created.path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn workspace_sweep_rejects_symlinked_metadata_root_before_outside_gc() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let repo_path = workspace.join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let outside_metadata = temp.path().join("outside-metadata");
        let outside_worktree_root = outside_metadata.join("worktrees/repo");
        let created = create_gc_worktree(
            &WorktreeManager::new(&repo_path),
            "outside-lane",
            &outside_worktree_root,
        );
        symlink(&outside_metadata, workspace.join(".maco")).expect("link metadata root");

        let error = sweep_workspace_worktrees(workspace_sweep_options(&workspace, true))
            .expect_err("symlinked metadata root must fail closed");
        assert!(error
            .to_string()
            .contains("workspace metadata root is not a plain directory"));
        assert!(created.path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn workspace_sweep_reports_symlinked_group_and_continues_valid_group() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let linked_repo_path = workspace.join("a-linked");
        WorktreeManager::init_repository(&linked_repo_path, "main").expect("init linked repo");
        let linked_repo = crate::git_repository::open(&linked_repo_path).expect("open linked repo");
        commit_readme(&linked_repo).expect("initial linked commit");
        let outside_group = temp.path().join("outside-group");
        let outside_lane = create_gc_worktree(
            &WorktreeManager::new(&linked_repo_path),
            "outside-lane",
            &outside_group,
        );

        let valid_repo_path = workspace.join("z-valid");
        WorktreeManager::init_repository(&valid_repo_path, "main").expect("init valid repo");
        let valid_repo = crate::git_repository::open(&valid_repo_path).expect("open valid repo");
        commit_readme(&valid_repo).expect("initial valid commit");
        let worktrees_root = workspace.join(".maco/worktrees");
        let valid_group = worktrees_root.join("z-valid");
        let valid_lane = create_gc_worktree(
            &WorktreeManager::new(&valid_repo_path),
            "valid-lane",
            &valid_group,
        );
        symlink(&outside_group, worktrees_root.join("a-linked")).expect("link group");

        let report = sweep_workspace_worktrees(workspace_sweep_options(&workspace, true))
            .expect("sweep with symlinked group");
        assert_eq!(report.repository_discovered_count, 2);
        assert_eq!(report.repository_inspected_count, 1);
        assert_eq!(report.repository_pre_gc_skipped_count, 1);
        assert_eq!(report.repository_gc_failed_count, 0);
        assert_eq!(report.repository_failure_count, 1);
        assert_eq!(
            report
                .repositories
                .iter()
                .map(|entry| entry.group.as_str())
                .collect::<Vec<_>>(),
            vec!["a-linked", "z-valid"]
        );
        let linked = &report.repositories[0];
        assert_eq!(linked.status, WorktreeSweepRepositoryStatus::Skipped);
        assert!(!linked.gc_attempted);
        assert!(!linked.effects_may_have_occurred);
        assert_eq!(
            linked.failure.as_ref().expect("typed group failure").kind,
            WorktreeSweepFailureKind::RepositoryAssociation
        );
        assert!(linked
            .failure
            .as_ref()
            .expect("group failure")
            .message
            .contains("not a plain directory"));
        assert_eq!(
            report.repositories[1].status,
            WorktreeSweepRepositoryStatus::Inspected
        );
        assert!(outside_lane.path.exists());
        assert!(!valid_lane.path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn workspace_sweep_continues_after_typed_repository_open_failure() {
        let temp = TempDir::new().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let repo_path = workspace.join("valid+repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let valid_root = workspace.join(".maco/worktrees/valid_repo");
        let valid =
            create_gc_worktree(&WorktreeManager::new(&repo_path), "valid-lane", &valid_root);
        let broken_lane = workspace.join(".maco/worktrees/broken/lane");
        fs::create_dir_all(&broken_lane).expect("broken lane");
        fs::write(
            broken_lane.join(".git"),
            "gitdir: /definitely/missing/git-dir\n",
        )
        .expect("broken Git marker");

        let first = sweep_workspace_worktrees(workspace_sweep_options(&workspace, false))
            .expect("workspace sweep with broken group");
        let second = sweep_workspace_worktrees(workspace_sweep_options(&workspace, false))
            .expect("repeat deterministic workspace sweep");
        assert_eq!(
            serde_json::to_string(&first).expect("serialize first report"),
            serde_json::to_string(&second).expect("serialize second report")
        );
        assert_eq!(first.repository_discovered_count, 2);
        assert_eq!(first.repository_inspected_count, 1);
        assert_eq!(first.repository_pre_gc_skipped_count, 1);
        assert_eq!(first.repository_gc_failed_count, 0);
        assert_eq!(first.repository_failure_count, 1);
        assert_eq!(
            first
                .repositories
                .iter()
                .map(|entry| entry.group.as_str())
                .collect::<Vec<_>>(),
            vec!["broken", "valid_repo"]
        );
        let broken = &first.repositories[0];
        assert_eq!(broken.status, WorktreeSweepRepositoryStatus::Skipped);
        assert!(!broken.gc_attempted);
        assert!(!broken.effects_may_have_occurred);
        assert_eq!(
            broken.failure.as_ref().expect("typed open failure").kind,
            WorktreeSweepFailureKind::RepositoryOpen
        );
        assert_eq!(
            serde_json::to_value(broken)
                .expect("serialize broken entry")
                .get("status"),
            Some(&serde_json::json!("skipped"))
        );
        assert_eq!(
            first.repositories[1].status,
            WorktreeSweepRepositoryStatus::Inspected
        );
        assert!(valid.path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn workspace_sweep_passes_retention_and_keep_target_options_to_gc() {
        let temp = TempDir::new().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let repo_path = workspace.join("retained+repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let worktree_root = workspace.join(".maco/worktrees/retained_repo");
        let old = create_gc_worktree(
            &WorktreeManager::new(&repo_path),
            "retention-old",
            &worktree_root,
        );
        let new = create_gc_worktree(
            &WorktreeManager::new(&repo_path),
            "retention-new",
            &worktree_root,
        );
        fs::create_dir_all(new.path.join("target/debug")).expect("new target");
        let mut options = workspace_sweep_options(&workspace, false);
        options.remove_targets = false;
        options.retention = WorktreeRetentionPolicy {
            max_age: Some(Duration::from_secs(3600)),
            max_count: Some(1),
            max_total_bytes: Some(u64::MAX),
        };

        let report = sweep_workspace_worktrees(options).expect("retained workspace sweep");
        assert_eq!(report.max_age_seconds, Some(3600));
        assert_eq!(report.max_count, Some(1));
        assert_eq!(report.max_total_bytes, Some(u64::MAX));
        assert!(!report.remove_targets);
        assert_eq!(report.removed_count, 1, "{report:#?}");
        assert_eq!(report.retained_count, 1);
        assert_eq!(report.target_removed_count, 0);
        let gc = report.repositories[0]
            .gc_report
            .as_ref()
            .expect("nested GC report");
        assert_eq!(gc.max_age_seconds, Some(3600));
        assert_eq!(gc.max_count, Some(1));
        assert_eq!(gc.max_total_bytes, Some(u64::MAX));
        assert!(!gc.remove_targets);
        assert!(gc.entries.iter().any(|entry| {
            entry.status == WorktreeGcStatus::Retained
                && entry.reason == WorktreeGcReason::RetentionKeep
        }));
        assert!(old.path.exists());
        assert!(new.path.exists());
        assert!(new.path.join("target").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn workspace_sweep_inherits_combined_active_claim_and_lease_protection() {
        let temp = TempDir::new().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let repo_path = workspace.join("protected+repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let worktree_root = workspace.join(".maco/worktrees/protected_repo");
        let claimed = create_gc_worktree(&manager, "claimed-lane", &worktree_root);
        let leased = create_gc_worktree(&manager, "leased-lane", &worktree_root);
        SyncStore::open(&repo_path)
            .expect("open claims")
            .claim_paths("claimed-lane", [PathBuf::from("src")])
            .expect("claim path");
        let _lease = manager
            .acquire_read_execution_lease("leased-lane")
            .expect("active lease");

        let report = sweep_workspace_worktrees(workspace_sweep_options(&workspace, true))
            .expect("protected workspace sweep");
        assert_eq!(report.repository_inspected_count, 1);
        assert_eq!(report.protected_count, 2);
        assert_eq!(report.removed_count, 0);
        let reasons = report.repositories[0]
            .gc_report
            .as_ref()
            .expect("nested GC report")
            .entries
            .iter()
            .map(|entry| entry.reason)
            .collect::<Vec<_>>();
        assert_eq!(reasons.len(), 2);
        assert!(reasons.contains(&WorktreeGcReason::ActiveClaim));
        assert!(reasons.contains(&WorktreeGcReason::ActiveLease));
        assert!(claimed.path.exists());
        assert!(leased.path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn workspace_sweep_marks_gc_error_as_effectful_failure_without_clean_report() {
        let temp = TempDir::new().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let repo_path = workspace.join("orphan+repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let orphan = workspace.join(".maco/worktrees/orphan_repo/plain-orphan");
        fs::create_dir_all(&orphan).expect("orphan lane");

        let report = sweep_workspace_worktrees(workspace_sweep_options(&workspace, true))
            .expect("aggregate GC failure");
        assert_eq!(report.repository_discovered_count, 1);
        assert_eq!(report.repository_inspected_count, 0);
        assert_eq!(report.repository_pre_gc_skipped_count, 0);
        assert_eq!(report.repository_gc_failed_count, 1);
        assert_eq!(report.repository_failure_count, 1);
        let failed = &report.repositories[0];
        assert_eq!(failed.status, WorktreeSweepRepositoryStatus::Failed);
        assert!(failed.gc_attempted);
        assert!(failed.effects_may_have_occurred);
        assert!(failed.gc_report.is_none());
        assert_eq!(
            failed.failure.as_ref().expect("typed GC failure").kind,
            WorktreeSweepFailureKind::GarbageCollection
        );
        assert!(orphan.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_removes_finished_clean_worktree_and_keeps_branch() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = create_gc_worktree(&manager, "agent-finished", &worktree_root);

        let report = manager
            .gc(gc_options(Some(worktree_root.clone()), false))
            .expect("gc finished worktree");

        assert_eq!(report.removed_count, 1, "{report:#?}");
        assert_eq!(report.entries[0].status, WorktreeGcStatus::Removed);
        assert_eq!(report.entries[0].reason, WorktreeGcReason::FinishedBranch);
        assert!(!created.path.exists());
        assert!(repo
            .find_branch("maco/agent-finished", BranchType::Local)
            .is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_protects_dirty_worktree() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = create_gc_worktree(&manager, "agent-dirty-gc", &worktree_root);
        fs::write(created.path.join("README.md"), "tracked local work\n")
            .expect("dirty tracked worktree");

        let report = manager
            .gc(gc_options(Some(worktree_root), false))
            .expect("gc dirty worktree");

        assert_eq!(report.removed_count, 0);
        assert_eq!(report.protected_count, 1);
        assert_eq!(report.entries[0].status, WorktreeGcStatus::Protected);
        assert_eq!(report.entries[0].reason, WorktreeGcReason::Dirty);
        assert!(report.entries[0].untracked_paths.is_empty());
        assert!(created.path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_classifies_untracked_only_and_requires_exact_allowlist_for_lane_removal() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = create_gc_worktree(&manager, "agent-untracked-gc", &worktree_root);
        fs::write(created.path.join("TASK.md"), "task brief\n").expect("untracked task brief");

        let protected = manager
            .gc(gc_options(Some(worktree_root.clone()), false))
            .expect("classify untracked-only worktree");

        assert_eq!(protected.removed_count, 0);
        assert_eq!(protected.protected_count, 1);
        assert_eq!(protected.entries[0].status, WorktreeGcStatus::Protected);
        assert_eq!(protected.entries[0].reason, WorktreeGcReason::UntrackedOnly);
        assert_eq!(
            protected.entries[0].untracked_paths,
            vec![PathBuf::from("TASK.md")]
        );
        assert!(created.path.exists());

        fs::write(created.path.join("result.txt"), "worker output\n")
            .expect("second untracked output");
        let mut partial = gc_options(Some(worktree_root.clone()), false);
        partial.allowed_untracked_paths = vec![PathBuf::from("TASK.md")];
        let partially_allowed = manager
            .gc(partial)
            .expect("partial allowlist remains protected");
        assert_eq!(partially_allowed.removed_count, 0);
        assert_eq!(partially_allowed.protected_count, 1);
        assert_eq!(
            partially_allowed.entries[0].reason,
            WorktreeGcReason::UntrackedOnly
        );
        assert!(partially_allowed.entries[0]
            .untracked_paths
            .contains(&PathBuf::from("result.txt")));
        assert!(created.path.exists());
        fs::remove_file(created.path.join("result.txt")).expect("remove second output");

        let mut allowed = gc_options(Some(worktree_root), false);
        allowed.allowed_untracked_paths = vec![PathBuf::from("TASK.md")];
        let reclaimed = manager
            .gc(allowed)
            .expect("reclaim explicitly allowed task brief");

        assert_eq!(reclaimed.removed_count, 1);
        assert_eq!(reclaimed.protected_count, 0);
        assert_eq!(
            reclaimed.allowed_untracked_paths,
            vec![PathBuf::from("TASK.md")]
        );
        assert_eq!(reclaimed.entries[0].status, WorktreeGcStatus::Removed);
        assert_eq!(
            reclaimed.entries[0].untracked_paths,
            vec![PathBuf::from("TASK.md")]
        );
        assert!(!created.path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_protects_ignored_only_output_until_its_exact_path_is_allowed() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        commit_descendant(&repo, ".gitignore", "scratch/\n").expect("ignore scratch");
        let manager = WorktreeManager::new(&repo_path);
        let created = create_gc_worktree(&manager, "ignored-output", &worktree_root);
        fs::create_dir(created.path.join("scratch")).expect("scratch directory");
        fs::write(created.path.join("scratch/result.bin"), "only copy\n")
            .expect("ignored worker output");

        let protected = manager
            .gc(gc_options(Some(worktree_root.clone()), false))
            .expect("ignored-only protection");
        assert_eq!(protected.removed_count, 0, "{protected:#?}");
        assert_eq!(protected.protected_count, 1, "{protected:#?}");
        assert_eq!(protected.entries[0].reason, WorktreeGcReason::UntrackedOnly);
        assert_eq!(
            protected.entries[0].untracked_paths,
            vec![PathBuf::from("scratch/result.bin")]
        );
        assert!(created.path.exists());

        let mut allowed = gc_options(Some(worktree_root), false);
        allowed.allowed_untracked_paths = vec![PathBuf::from("scratch/result.bin")];
        let reclaimed = manager.gc(allowed).expect("exact ignored path reclaim");
        assert_eq!(reclaimed.removed_count, 1, "{reclaimed:#?}");
        assert!(!created.path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_refuses_late_ignored_output_after_reviewed_snapshot() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        commit_descendant(&repo, ".gitignore", "scratch/\n").expect("ignore scratch");
        let manager = WorktreeManager::new(&repo_path);
        let created = create_gc_worktree(&manager, "late-ignored-output", &worktree_root);
        fs::create_dir(created.path.join("scratch")).expect("scratch directory");
        fs::write(created.path.join("scratch/approved.bin"), "approved\n")
            .expect("approved ignored output");
        fs::create_dir_all(created.path.join("target/debug")).expect("target");
        let mut options = gc_options(Some(worktree_root), false);
        options.allowed_untracked_paths = vec![PathBuf::from("scratch/approved.bin")];
        let report = manager
            .gc_with_target_liveness(options, |_| {
                fs::write(created.path.join("scratch/late.bin"), "only copy\n")
                    .expect("late ignored output");
                WorktreeTargetLiveness::Clear
            })
            .expect("late ignored output protection");
        assert_eq!(report.removed_count, 0, "{report:#?}");
        assert_eq!(report.protected_count, 1, "{report:#?}");
        assert_eq!(report.entries[0].reason, WorktreeGcReason::UntrackedOnly);
        assert!(report.entries[0]
            .untracked_paths
            .contains(&PathBuf::from("scratch/late.bin")));
        assert!(created.path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_ignored_inventory_excludes_large_runtime_categories_before_bounds() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        commit_descendant(&repo, ".gitignore", "scratch/\n").expect("ignore scratch");
        let manager = WorktreeManager::new(&repo_path);
        let created = create_gc_worktree(&manager, "runtime-inventory", &worktree_root);
        for root in ["target/debug", ".agents/temp/runtime"] {
            fs::create_dir_all(created.path.join(root)).expect("runtime directory");
            for index in 0..3 {
                fs::write(created.path.join(root).join(index.to_string()), "runtime\n")
                    .expect("runtime entry");
            }
        }
        assert!(matches!(
            gc_worktree_dirtiness(&created.path).expect("runtime-only dirtiness"),
            WorktreeGcDirtiness::Clean
        ));
        let runtime_only =
            bounded_repository_gc_status_paths(&created.path, 4, 4096, WORKTREE_GC_STATUS_TIMEOUT)
                .expect("runtime inventory must not spend ignored entry bounds");
        assert!(runtime_only.is_empty());

        fs::create_dir(created.path.join("scratch")).expect("scratch directory");
        fs::write(created.path.join("scratch/output.bin"), "only copy\n")
            .expect("arbitrary ignored output");
        let with_output =
            bounded_repository_gc_status_paths(&created.path, 4, 4096, WORKTREE_GC_STATUS_TIMEOUT)
                .expect("one arbitrary ignored path fits the bound");
        assert_eq!(
            with_output,
            vec![(PathBuf::from("scratch/output.bin"), [b'?', b'?'])]
        );
        for index in 0..5 {
            fs::write(
                created.path.join("scratch").join(format!("extra-{index}")),
                "ignored\n",
            )
            .expect("extra arbitrary ignored output");
        }
        let general_status =
            bounded_repository_status_paths(&created.path, 4, 4096, WORKTREE_GC_STATUS_TIMEOUT)
                .expect("general status must not collect or spend bounds on ignored inventory");
        assert!(general_status.is_empty());
    }

    #[test]
    fn gc_rejects_non_exact_untracked_allowlist_paths() {
        let absolute = normalize_gc_allowed_untracked_paths(&[PathBuf::from("/tmp/TASK.md")])
            .expect_err("absolute allowlist path");
        assert!(absolute
            .to_string()
            .contains("must be an exact repository-relative path"));
        let escaping = normalize_gc_allowed_untracked_paths(&[PathBuf::from("../TASK.md")])
            .expect_err("escaping allowlist path");
        assert!(escaping
            .to_string()
            .contains("must be an exact repository-relative path"));
    }

    #[cfg(unix)]
    #[test]
    fn gc_report_serializes_non_utf8_untracked_paths_losslessly_and_escapes_human_text() {
        use std::os::unix::ffi::OsStringExt;

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = create_gc_worktree(&manager, "agent-non-utf8-gc", &worktree_root);
        let raw_name = b"odd,\n\t-\xff.txt".to_vec();
        let relative = PathBuf::from(OsString::from_vec(raw_name.clone()));
        fs::write(created.path.join(&relative), "worker output\n").expect("non-UTF-8 output");

        let report = manager
            .gc(gc_options(Some(worktree_root), true))
            .expect("classify non-UTF-8 output");
        let json = serde_json::to_value(&report).expect("lossless report JSON");
        let wire = &json["entries"][0]["untracked_paths"][0];
        assert_eq!(wire["encoding"], "unix-bytes-hex-v1");
        assert_eq!(
            wire["data"],
            raw_name
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let human = worktree_report_path_text(&relative);
        assert_eq!(human, "odd\\x2C\\n\\t-\\xFF.txt");
        assert!(!human.contains(','));
        assert!(!human.contains('\n'));
        assert!(!human.contains('\t'));
    }

    #[test]
    fn gc_untracked_allowlist_is_bounded_before_report_cloning() {
        let too_many = vec![PathBuf::from("TASK.md"); MAX_GC_ALLOWED_UNTRACKED_PATHS + 1];
        assert!(normalize_gc_allowed_untracked_paths(&too_many)
            .expect_err("entry bound")
            .to_string()
            .contains("entry limit"));

        let oversized = PathBuf::from("x".repeat(MAX_GC_ALLOWED_UNTRACKED_PATH_BYTES + 1));
        assert!(normalize_gc_allowed_untracked_paths(&[oversized])
            .expect_err("path byte bound")
            .to_string()
            .contains("byte limit"));

        let aggregate =
            vec![
                PathBuf::from("x".repeat(MAX_GC_ALLOWED_UNTRACKED_PATH_BYTES));
                MAX_GC_ALLOWED_UNTRACKED_TOTAL_BYTES / MAX_GC_ALLOWED_UNTRACKED_PATH_BYTES + 1
            ];
        assert!(normalize_gc_allowed_untracked_paths(&aggregate)
            .expect_err("aggregate byte bound")
            .to_string()
            .contains("aggregate limit"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_protects_active_execution_lease() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = create_gc_worktree(&manager, "agent-leased-gc", &worktree_root);
        let _lease = manager
            .acquire_read_execution_lease("agent-leased-gc")
            .expect("active read lease");

        let report = manager
            .gc(gc_options(Some(worktree_root), false))
            .expect("gc leased worktree");

        assert_eq!(report.removed_count, 0);
        assert_eq!(report.protected_count, 1);
        assert_eq!(report.entries[0].status, WorktreeGcStatus::Protected);
        assert_eq!(report.entries[0].reason, WorktreeGcReason::ActiveLease);
        assert!(created.path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_protects_active_path_claim_for_agent() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = create_gc_worktree(&manager, "agent-claimed-gc", &worktree_root);
        SyncStore::open(&repo_path)
            .expect("open claims")
            .claim_paths("agent-claimed-gc", [PathBuf::from("src")])
            .expect("claim path");

        let report = manager
            .gc(gc_options(Some(worktree_root), false))
            .expect("gc claimed worktree");

        assert_eq!(report.removed_count, 0);
        assert_eq!(report.protected_count, 1);
        assert_eq!(report.entries[0].status, WorktreeGcStatus::Protected);
        assert_eq!(report.entries[0].reason, WorktreeGcReason::ActiveClaim);
        assert!(created.path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_retention_keeps_newest_and_removes_retained_target() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let old = create_gc_worktree(&manager, "agent-old-gc", &worktree_root);
        let new = create_gc_worktree(&manager, "agent-new-gc", &worktree_root);
        fs::create_dir_all(old.path.join("target/debug")).expect("old target");
        fs::create_dir_all(new.path.join("target/debug")).expect("new target");

        let report = manager
            .gc_with_target_liveness(
                WorktreeGcOptions {
                    worktree_root: Some(worktree_root),
                    dry_run: false,
                    remove_targets: true,
                    targets_only: false,
                    retention: WorktreeRetentionPolicy {
                        max_age: None,
                        max_count: Some(1),
                        max_total_bytes: None,
                    },
                    allowed_untracked_paths: Vec::new(),
                    exclude_agent_id: None,
                    candidate_agent_ids: None,
                    merged_into_reference: None,
                    superseded_by_agent_id: BTreeMap::new(),
                    machine_global_retention: None,
                },
                |_| WorktreeTargetLiveness::Clear,
            )
            .expect("gc with retention");

        assert_eq!(report.removed_count, 1, "{report:#?}");
        assert_eq!(report.retained_count, 1);
        assert_eq!(report.target_removed_count, 1, "{report:#?}");
        assert!(!old.path.exists());
        assert!(new.path.exists());
        assert!(!new.path.join("target").exists());
        assert!(report
            .entries
            .iter()
            .any(|entry| entry.name == "agent-new-gc"
                && entry.reason == WorktreeGcReason::TargetRemoved));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_size_retention_keeps_the_newest_prefix_and_counts_lane_bytes_once() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let protected = create_gc_worktree(&manager, "size-protected", &worktree_root);
        fs::write(protected.path.join("README.md"), vec![b'p'; 64 * 1024])
            .expect("protected tracked edit");
        let old = create_gc_worktree(&manager, "size-old", &worktree_root);
        fs::create_dir_all(old.path.join("target/debug")).expect("old target");
        fs::write(
            old.path.join("target/debug/artifact"),
            vec![b'o'; 32 * 1024],
        )
        .expect("old artifact");
        let new = create_gc_worktree(&manager, "size-new", &worktree_root);
        fs::create_dir_all(new.path.join("target/debug")).expect("new target");
        fs::write(new.path.join("target/debug/artifact"), vec![b'n'; 128]).expect("new artifact");
        let protected_size = gc_worktree_size_estimate(&protected.path).expect("protected size");
        let old_size = gc_worktree_size_estimate(&old.path).expect("old size");
        let new_size = gc_worktree_size_estimate(&new.path).expect("new size");
        assert!(old_size.worktree_bytes > new_size.worktree_bytes);

        let mut options = gc_options(Some(worktree_root), false);
        options.remove_targets = false;
        options.retention.max_total_bytes = Some(new_size.worktree_bytes);
        let report = manager
            .gc_with_target_liveness(options, |_| WorktreeTargetLiveness::Clear)
            .expect("size-retained GC");

        assert_eq!(report.max_total_bytes, Some(new_size.worktree_bytes));
        assert_eq!(report.removed_count, 1, "{report:#?}");
        assert_eq!(report.retained_count, 1, "{report:#?}");
        assert_eq!(report.protected_count, 1, "{report:#?}");
        assert_eq!(
            report.apparent_considered_bytes,
            protected_size
                .worktree_bytes
                .checked_add(old_size.worktree_bytes)
                .expect("test protected and old size sum")
                .checked_add(new_size.worktree_bytes)
                .expect("test size sum")
        );
        assert_eq!(report.estimated_reclaimable_bytes, old_size.worktree_bytes);
        assert_eq!(report.estimated_reclaimed_bytes, old_size.worktree_bytes);
        let json = serde_json::to_value(&report).expect("serialize size report");
        assert_eq!(json["max_total_bytes"], new_size.worktree_bytes);
        assert_eq!(json["estimated_reclaimable_bytes"], old_size.worktree_bytes);
        assert!(
            old_size.target_bytes.expect("old target size") < old_size.worktree_bytes,
            "full-lane bytes must include, not double-count, target bytes"
        );
        let removed = report
            .entries
            .iter()
            .find(|entry| entry.name == old.name)
            .expect("removed size entry");
        assert_eq!(
            removed.apparent_worktree_bytes,
            Some(old_size.worktree_bytes)
        );
        assert_eq!(removed.apparent_target_bytes, old_size.target_bytes);
        assert!(!old.path.exists());
        assert!(protected.path.exists());
        assert!(new.path.exists());
        assert!(new.path.join("target").exists());
        assert!(repo.find_branch(&old.branch, BranchType::Local).is_ok());
        assert_eq!(
            report
                .entries
                .iter()
                .find(|entry| entry.name == protected.name)
                .expect("protected size entry")
                .reason,
            WorktreeGcReason::Dirty
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_late_protection_does_not_consume_count_or_size_retention() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let old = create_gc_worktree(&manager, "late-protection-old", &worktree_root);
        fs::create_dir_all(old.path.join("target/debug")).expect("old target");
        fs::write(old.path.join("target/debug/artifact"), vec![b'o'; 64]).expect("old artifact");
        let new = create_gc_worktree(&manager, "late-protection-new", &worktree_root);
        fs::create_dir_all(new.path.join("target/debug")).expect("new target");
        fs::write(
            new.path.join("target/debug/artifact"),
            vec![b'n'; 64 * 1024],
        )
        .expect("new artifact");
        let old_size = gc_worktree_size_estimate(&old.path).expect("old size");
        let new_size = gc_worktree_size_estimate(&new.path).expect("new size");
        assert!(new_size.worktree_bytes > old_size.worktree_bytes);

        let mut options = gc_options(Some(worktree_root), false);
        options.remove_targets = false;
        options.retention = WorktreeRetentionPolicy {
            max_age: None,
            max_count: Some(1),
            max_total_bytes: Some(old_size.worktree_bytes),
        };
        let liveness_calls = std::cell::Cell::new(0usize);
        let report = manager
            .gc_with_target_liveness(options, |target| {
                liveness_calls.set(liveness_calls.get().saturating_add(1));
                assert_eq!(target.path, new.path.join("target"));
                test_live_target_liveness()
            })
            .expect("late-protected retention GC");

        assert_eq!(liveness_calls.get(), 1, "retained lane is not probed");
        assert_eq!(report.removed_count, 0, "{report:#?}");
        assert_eq!(report.retained_count, 1, "{report:#?}");
        assert_eq!(report.protected_count, 1, "{report:#?}");
        assert_eq!(report.estimated_reclaimable_bytes, 0, "{report:#?}");
        assert_eq!(report.estimated_reclaimed_bytes, 0, "{report:#?}");
        assert_eq!(
            report
                .entries
                .iter()
                .find(|entry| entry.name == new.name)
                .expect("new protected entry")
                .reason,
            WorktreeGcReason::LiveTarget
        );
        assert_eq!(
            report
                .entries
                .iter()
                .find(|entry| entry.name == old.name)
                .expect("old retained entry")
                .reason,
            WorktreeGcReason::RetentionKeep
        );
        assert!(old.path.join("target").exists());
        assert!(new.path.join("target").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_size_measurement_failure_protects_the_lane_without_byte_credit() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = create_gc_worktree(&manager, "size-failure", &worktree_root);
        let outside = temp.path().join("outside-target");
        fs::create_dir(&outside).expect("outside target");
        symlink(&outside, created.path.join("target")).expect("linked target");

        let report = manager
            .gc_with_target_liveness(gc_options(Some(worktree_root), false), |_| {
                panic!("a failed size binding must not reach liveness")
            })
            .expect("structured size failure");

        assert_eq!(report.removed_count, 0, "{report:#?}");
        assert_eq!(report.protected_count, 1, "{report:#?}");
        assert_eq!(report.apparent_considered_bytes, 0);
        assert_eq!(report.estimated_reclaimable_bytes, 0);
        assert_eq!(report.estimated_reclaimed_bytes, 0);
        assert_eq!(
            report.entries[0].reason,
            WorktreeGcReason::SizeMeasurementFailed
        );
        assert_eq!(report.entries[0].apparent_worktree_bytes, None);
        assert!(created.path.exists());
        assert!(outside.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_targets_only_reclaims_untracked_lane_target_and_keeps_lane_branch_and_orphan() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = create_gc_worktree(&manager, "target-only-lane", &worktree_root);
        fs::write(created.path.join("TASK.md"), "task brief\n").expect("untracked task brief");
        fs::create_dir_all(created.path.join("target/debug")).expect("lane target");
        fs::write(created.path.join("target/debug/artifact"), "artifact\n")
            .expect("target artifact");
        let orphan = worktree_root.join("unregistered-orphan");
        fs::create_dir(&orphan).expect("unregistered orphan");

        let report = manager
            .gc_with_target_liveness(gc_targets_only_options(Some(worktree_root), false), |_| {
                WorktreeTargetLiveness::Clear
            })
            .expect("target-only GC");

        assert!(report.targets_only);
        assert_eq!(report.removed_count, 0);
        assert_eq!(report.target_removed_count, 1, "{report:#?}");
        assert_eq!(report.orphan_removed_count, 0);
        assert_eq!(report.entries[0].status, WorktreeGcStatus::Retained);
        assert_eq!(report.entries[0].reason, WorktreeGcReason::TargetRemoved);
        let target_bytes = report.entries[0]
            .apparent_target_bytes
            .expect("target byte estimate");
        assert_eq!(report.estimated_reclaimable_bytes, target_bytes);
        assert_eq!(report.estimated_reclaimed_bytes, target_bytes);
        assert!(report.apparent_considered_bytes >= target_bytes);
        assert_eq!(
            report.entries[0].untracked_paths,
            vec![PathBuf::from("TASK.md")]
        );
        assert!(created.path.exists());
        assert!(!created.path.join("target").exists());
        assert!(created.path.join("TASK.md").exists());
        assert!(orphan.exists());
        assert!(repo
            .find_branch("maco/target-only-lane", BranchType::Local)
            .is_ok());
        assert_eq!(manager.list().expect("retained lane"), vec![created]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_refuses_live_nested_cargo_target_for_full_and_target_only_reclaim() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = create_gc_worktree(&manager, "live-target-lane", &worktree_root);
        fs::create_dir_all(created.path.join("target/issue69")).expect("nested cargo target");

        let full = manager
            .gc_with_target_liveness(gc_options(Some(worktree_root.clone()), false), |_| {
                test_live_target_liveness()
            })
            .expect("full GC live-target refusal");
        assert_eq!(full.removed_count, 0);
        assert_eq!(full.protected_count, 1);
        assert_eq!(full.entries[0].reason, WorktreeGcReason::LiveTarget);
        assert!(created.path.exists());

        let target_only = manager
            .gc_with_target_liveness(
                gc_targets_only_options(Some(worktree_root.clone()), false),
                |_| test_live_target_liveness(),
            )
            .expect("target-only live-target refusal");
        assert_eq!(target_only.target_removed_count, 0);
        assert_eq!(target_only.protected_count, 1);
        assert_eq!(target_only.entries[0].reason, WorktreeGcReason::LiveTarget);
        assert!(created.path.join("target").exists());

        let reclaimed = manager
            .gc_with_target_liveness(gc_targets_only_options(Some(worktree_root), false), |_| {
                WorktreeTargetLiveness::Clear
            })
            .expect("reclaim stopped target");
        assert_eq!(reclaimed.target_removed_count, 1);
        assert!(created.path.exists());
        assert!(!created.path.join("target").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_refuses_target_replacement_between_probe_and_removal() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);

        for (root_name, targets_only) in [("full-root", false), ("target-root", true)] {
            let worktree_root = temp.path().join(root_name);
            let created = create_gc_worktree(
                &manager,
                &format!("replacement-{root_name}"),
                &worktree_root,
            );
            let target = created.path.join("target");
            let moved = created.path.join("target-original");
            fs::create_dir_all(target.join("debug")).expect("target");
            let mut options = if targets_only {
                gc_targets_only_options(Some(worktree_root), false)
            } else {
                gc_options(Some(worktree_root), false)
            };
            options.targets_only = targets_only;

            let report = manager
                .gc_with_target_liveness(options, |_| {
                    fs::rename(&target, &moved).expect("move probed target");
                    fs::create_dir(&target).expect("create replacement target");
                    WorktreeTargetLiveness::Clear
                })
                .expect("replacement must become a structured protection");

            assert_eq!(report.removed_count, 0, "{report:#?}");
            assert_eq!(report.target_removed_count, 0, "{report:#?}");
            assert_eq!(report.protected_count, 1, "{report:#?}");
            assert_eq!(report.estimated_reclaimable_bytes, 0, "{report:#?}");
            assert_eq!(report.estimated_reclaimed_bytes, 0, "{report:#?}");
            assert_eq!(
                report.entries[0].reason,
                WorktreeGcReason::TargetIdentityChanged
            );
            assert_eq!(
                report.entries[0]
                    .target_liveness
                    .as_ref()
                    .expect("identity evidence")
                    .source,
                WorktreeTargetLivenessSource::TargetIdentity
            );
            assert!(created.path.exists());
            assert!(target.exists(), "replacement target must survive");
            assert!(moved.exists(), "original target must survive");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_apply_boundary_maps_file_and_symlink_target_replacements_to_identity_change() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("tempdir");
        for replacement in ["file", "symlink"] {
            let lane = temp.path().join(format!("{replacement}-lane"));
            let target = lane.join("target");
            fs::create_dir_all(target.join("debug")).expect("preflight target");
            let preflight = gc_target_if_present(&lane)
                .expect("bind preflight target")
                .expect("preflight target exists");
            fs::remove_dir_all(&target).expect("remove preflight target");
            if replacement == "file" {
                fs::write(&target, "replacement\n").expect("file replacement");
            } else {
                let outside = temp.path().join("outside-target");
                fs::create_dir_all(&outside).expect("outside target");
                symlink(&outside, &target).expect("symlink replacement");
            }

            let boundary = gc_target_at_apply_boundary(&lane, Some(&preflight))
                .expect("replacement becomes structured absence");
            assert!(boundary.is_none());
            assert!(!worktree_gc_target_bindings_match(
                Some(&preflight),
                boundary.as_ref()
            ));
            assert!(fs::symlink_metadata(&target).is_ok());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_unknown_and_live_evidence_protects_every_target_reclaim_path() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);

        for (root_name, targets_only, retained, live) in [
            ("full-unknown", false, false, false),
            ("retained-unknown", false, true, false),
            ("target-unknown", true, false, false),
            ("retained-live", false, true, true),
        ] {
            let worktree_root = temp.path().join(root_name);
            let created = create_gc_worktree(&manager, root_name, &worktree_root);
            fs::create_dir_all(created.path.join("target/debug")).expect("target");
            let mut options = if targets_only {
                gc_targets_only_options(Some(worktree_root), false)
            } else {
                gc_options(Some(worktree_root), false)
            };
            if retained {
                options.retention.max_count = Some(1);
            }
            let report = manager
                .gc_with_target_liveness(options, |_| {
                    if live {
                        test_live_target_liveness()
                    } else {
                        test_unknown_target_liveness()
                    }
                })
                .expect("liveness refusal report");
            assert_eq!(report.removed_count, 0, "{report:#?}");
            assert_eq!(report.target_removed_count, 0, "{report:#?}");
            assert_eq!(report.protected_count, 1, "{report:#?}");
            assert_eq!(report.estimated_reclaimable_bytes, 0, "{report:#?}");
            assert_eq!(report.estimated_reclaimed_bytes, 0, "{report:#?}");
            assert_eq!(
                report.entries[0].reason,
                if live {
                    WorktreeGcReason::LiveTarget
                } else {
                    WorktreeGcReason::TargetLivenessUnknown
                }
            );
            let evidence = report.entries[0]
                .target_liveness
                .as_ref()
                .expect("actionable evidence");
            assert_eq!(evidence.pid, Some(if live { 42 } else { 43 }));
            let json = serde_json::to_value(&report.entries[0]).expect("serialize evidence");
            assert_eq!(
                json.pointer("/target_liveness/pid"),
                Some(&serde_json::json!(if live { 42 } else { 43 }))
            );
            assert!(json.pointer("/target_liveness/source").is_some());
            assert!(json.pointer("/target_liveness/cause").is_some());
            assert!(created.path.join("target").exists());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_target_liveness_observes_absolute_and_relative_cargo_target_dirs() {
        let temp = TempDir::new().expect("tempdir");
        let lane = temp.path().join("lane");
        let target_path = lane.join("target");
        let absolute = target_path.join("absolute");
        let relative = target_path.join("relative");
        fs::create_dir_all(&absolute).expect("absolute target");
        fs::create_dir_all(&relative).expect("relative target");

        for (configured, cwd) in [
            (absolute.as_os_str().to_owned(), None),
            (OsString::from("target/relative"), Some(lane.as_path())),
        ] {
            let mut command = std::process::Command::new("sleep");
            command.arg("60").env("CARGO_TARGET_DIR", configured);
            if let Some(cwd) = cwd {
                command.current_dir(cwd);
            }
            let mut child = command.spawn().expect("spawn target process");
            let mut observed_live = None;
            for _ in 0..100 {
                let target = gc_target_if_present(&lane)
                    .expect("bind target")
                    .expect("target exists");
                if let WorktreeTargetLiveness::Live(evidence) = worktree_target_liveness(&target) {
                    if evidence.pid == Some(child.id()) {
                        observed_live = Some(evidence);
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let _ = child.kill();
            let _ = child.wait();
            let evidence = observed_live.expect("child CARGO_TARGET_DIR must be observed");
            assert_eq!(
                evidence.source,
                WorktreeTargetLivenessSource::CargoTargetDir
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_target_liveness_skips_only_exact_user_manager_shape() {
        let temp = TempDir::new().expect("tempdir");
        fs::write(temp.path().join("comm"), "systemd\n").expect("comm");
        fs::write(
            temp.path().join("cmdline"),
            b"/run/current-system/systemd/lib/systemd/systemd\0--user\0",
        )
        .expect("cmdline");
        fs::write(
            temp.path().join("cgroup"),
            "0::/user.slice/user-1000.slice/user@1000.service/init.scope\n",
        )
        .expect("cgroup");
        assert!(linux_process_is_inert_user_manager(temp.path()));

        fs::write(temp.path().join("comm"), "(sd-pam)\n").expect("PAM helper comm");
        fs::write(temp.path().join("cmdline"), b"(sd-pam)\0").expect("PAM helper cmdline");
        assert!(linux_process_is_inert_user_manager(temp.path()));

        fs::write(
            temp.path().join("cgroup"),
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/build.service\n",
        )
        .expect("non-manager cgroup");
        assert!(!linux_process_is_inert_user_manager(temp.path()));
        assert!(linux_process_is_non_build_user_service(temp.path()));

        fs::write(
            temp.path().join("cgroup"),
            "0::/user.slice/user-1000.slice/session-1.scope\n",
        )
        .expect("interactive scope");
        assert!(!linux_process_is_non_build_user_service(temp.path()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_target_liveness_observes_default_cargo_target_from_process_cwd() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("tempdir");
        let lane = temp.path().join("lane");
        fs::create_dir_all(lane.join("target/debug")).expect("target");
        let bash = std::process::Command::new("sh")
            .args(["-c", "command -v bash"])
            .output()
            .expect("locate bash");
        assert!(bash.status.success());
        let bash = String::from_utf8(bash.stdout)
            .expect("bash path utf8")
            .trim()
            .to_string();
        let cargo = temp.path().join("cargo");
        symlink(bash, &cargo).expect("cargo-named bash shim");
        let mut child = std::process::Command::new(&cargo)
            .args(["-c", "while :; do :; done"])
            .current_dir(&lane)
            .env_remove("CARGO_TARGET_DIR")
            .spawn()
            .expect("spawn cargo-like process");
        let target = gc_target_if_present(&lane)
            .expect("bind target")
            .expect("target exists");
        let mut observed = None;
        for _ in 0..100 {
            if let WorktreeTargetLiveness::Live(evidence) = worktree_target_liveness(&target) {
                if evidence.pid == Some(child.id()) {
                    observed = Some(evidence);
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = child.kill();
        let _ = child.wait();
        let evidence = observed.expect("default cargo target must be observed");
        assert_eq!(
            evidence.source,
            WorktreeTargetLivenessSource::DefaultCargoTarget
        );
        assert_eq!(
            evidence.cause,
            WorktreeTargetLivenessCause::CargoLikeProcessInLane
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_target_liveness_parses_bounded_build_output_and_manifest_arguments() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("tempdir");
        let lane = temp.path().join("lane");
        let target_path = lane.join("target");
        let cargo_target = target_path.join("cargo");
        let rustc_out = target_path.join("rustc");
        fs::create_dir_all(&cargo_target).expect("cargo target");
        fs::create_dir_all(&rustc_out).expect("rustc out");
        fs::write(lane.join("Cargo.toml"), "[workspace]\n").expect("manifest");
        let bash = std::process::Command::new("sh")
            .args(["-c", "command -v bash"])
            .output()
            .expect("locate bash");
        assert!(bash.status.success());
        let bash = String::from_utf8(bash.stdout)
            .expect("bash path utf8")
            .trim()
            .to_string();
        let cargo = temp.path().join("cargo");
        symlink(bash, &cargo).expect("cargo-named bash shim");
        let target = gc_target_if_present(&lane)
            .expect("bind target")
            .expect("target exists");
        let cases = [
            (
                vec![
                    OsString::from("--target-dir"),
                    cargo_target.into_os_string(),
                ],
                WorktreeTargetLivenessSource::ProcessCommandLine,
            ),
            (
                vec![OsString::from(format!(
                    "--manifest-path={}",
                    lane.join("Cargo.toml").display()
                ))],
                WorktreeTargetLivenessSource::DefaultCargoTarget,
            ),
            (
                vec![OsString::from(format!("--out-dir={}", rustc_out.display()))],
                WorktreeTargetLivenessSource::ProcessCommandLine,
            ),
        ];
        for (arguments, expected_source) in cases {
            let mut child = std::process::Command::new(&cargo)
                .args(["-c", "while :; do :; done", "cargo-script"])
                .args(arguments)
                .current_dir(temp.path())
                .env_remove("CARGO_TARGET_DIR")
                .spawn()
                .expect("spawn cargo-like command line");
            let process_root = PathBuf::from("/proc").join(child.id().to_string());
            let process_view = LinuxProcessView::for_test(&process_root, true);
            let mut observed = None;
            for _ in 0..100 {
                if let WorktreeTargetLiveness::Live(evidence) =
                    linux_process_cmdline_liveness(&process_view, child.id(), &target, true)
                {
                    observed = Some(evidence);
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let _ = child.kill();
            let _ = child.wait();
            let evidence = observed.expect("build path argument must be observed");
            assert_eq!(evidence.pid, Some(child.id()));
            assert_eq!(evidence.source, expected_source);
        }
        assert_eq!(
            command_line_directive_value(b"--target-dir=target/debug", b"--target-dir"),
            Some(Some(b"target/debug".as_slice()))
        );
        assert_eq!(
            command_line_directive_value(b"--target-dir", b"--target-dir"),
            Some(None)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn identity_ancestry_detects_alias_containment_in_both_directions_and_bounds() {
        let target = FileIdentity {
            device: 11,
            file: 22,
        };
        let alias = FileIdentity {
            device: 33,
            file: 44,
        };
        let other = FileIdentity {
            device: 55,
            file: 66,
        };
        assert!(
            identity_ancestry_contains(&target, [Ok(other.clone()), Ok(target.clone())])
                .expect("process alias ancestry")
        );
        assert!(
            identity_ancestry_contains(&alias, [Ok(target), Ok(alias.clone())])
                .expect("target alias ancestry")
        );
        let oversized = std::iter::repeat_with(|| Ok(other.clone()))
            .take(MAX_WORKTREE_GC_IDENTITY_ANCESTORS.saturating_add(1));
        assert!(identity_ancestry_contains(&alias, oversized).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_revalidates_tracked_and_unapproved_output_after_liveness() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);

        for (root_name, tracked) in [("late-tracked", true), ("late-untracked", false)] {
            let worktree_root = temp.path().join(root_name);
            let created = create_gc_worktree(&manager, root_name, &worktree_root);
            fs::create_dir_all(created.path.join("target/debug")).expect("target");
            let report = manager
                .gc_with_target_liveness(gc_options(Some(worktree_root), false), |_| {
                    if tracked {
                        fs::write(created.path.join("README.md"), "changed\n")
                            .expect("late tracked output");
                    } else {
                        fs::write(created.path.join("worker-output.txt"), "only copy\n")
                            .expect("late untracked output");
                    }
                    WorktreeTargetLiveness::Clear
                })
                .expect("late output protection");
            assert_eq!(report.removed_count, 0, "{report:#?}");
            assert_eq!(report.protected_count, 1, "{report:#?}");
            assert_eq!(report.estimated_reclaimable_bytes, 0, "{report:#?}");
            assert_eq!(report.estimated_reclaimed_bytes, 0, "{report:#?}");
            assert_eq!(
                report.entries[0].reason,
                if tracked {
                    WorktreeGcReason::Dirty
                } else {
                    WorktreeGcReason::UntrackedOnly
                }
            );
            assert!(created.path.exists());
            assert!(manager
                .pending_operations()
                .expect("pending operations")
                .is_empty());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_target_cleanup_rechecks_dirtiness_after_boundary_liveness() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);

        for (root_name, targets_only) in [
            ("boundary-target-only", true),
            ("boundary-retained-target", false),
        ] {
            let worktree_root = temp.path().join(root_name);
            let created = create_gc_worktree(&manager, root_name, &worktree_root);
            fs::create_dir_all(created.path.join("target/debug")).expect("target");
            fs::write(created.path.join("target/debug/artifact"), "artifact\n")
                .expect("target artifact");
            let mut options = if targets_only {
                gc_targets_only_options(Some(worktree_root), false)
            } else {
                let mut options = gc_options(Some(worktree_root), false);
                options.retention.max_count = Some(1);
                options
            };
            options.targets_only = targets_only;
            let liveness_calls = std::cell::Cell::new(0usize);

            let report = manager
                .gc_with_target_liveness(options, |_| {
                    let call = liveness_calls.get();
                    liveness_calls.set(call.saturating_add(1));
                    if call == 1 {
                        fs::write(created.path.join("README.md"), "late tracked edit\n")
                            .expect("late tracked edit");
                    }
                    WorktreeTargetLiveness::Clear
                })
                .expect("boundary dirtiness protection");

            assert_eq!(liveness_calls.get(), 2, "preflight and boundary probes");
            assert_eq!(report.removed_count, 0, "{report:#?}");
            assert_eq!(report.target_removed_count, 0, "{report:#?}");
            assert_eq!(report.protected_count, 1, "{report:#?}");
            assert_eq!(report.estimated_reclaimable_bytes, 0, "{report:#?}");
            assert_eq!(report.estimated_reclaimed_bytes, 0, "{report:#?}");
            assert_eq!(report.entries[0].reason, WorktreeGcReason::Dirty);
            assert!(created.path.exists());
            assert!(created.path.join("target").exists());
            assert!(repo.find_branch(&created.branch, BranchType::Local).is_ok());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_full_removal_reports_final_approved_untracked_paths() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = create_gc_worktree(&manager, "final-untracked", &worktree_root);
        fs::create_dir_all(created.path.join("target/debug")).expect("target");
        let final_path = PathBuf::from("late-approved.txt");
        let mut options = gc_options(Some(worktree_root), false);
        options.allowed_untracked_paths = vec![final_path.clone()];
        let liveness_calls = std::cell::Cell::new(0usize);

        let report = manager
            .gc_with_target_liveness(options, |_| {
                let call = liveness_calls.get();
                liveness_calls.set(call.saturating_add(1));
                if call == 1 {
                    fs::write(created.path.join(&final_path), "late approved output\n")
                        .expect("late approved output");
                }
                WorktreeTargetLiveness::Clear
            })
            .expect("full removal with final approved output");

        assert!(liveness_calls.get() >= 2);
        assert_eq!(report.removed_count, 1, "{report:#?}");
        assert_eq!(report.protected_count, 0, "{report:#?}");
        assert_eq!(report.entries[0].status, WorktreeGcStatus::Removed);
        assert_eq!(report.entries[0].untracked_paths, vec![final_path]);
        assert!(!created.path.exists());
        assert!(repo.find_branch(&created.branch, BranchType::Local).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_boundary_protection_does_not_consume_count_or_size_retention() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let old = create_gc_worktree(&manager, "boundary-protection-old", &worktree_root);
        fs::create_dir_all(old.path.join("target/debug")).expect("old target");
        fs::write(old.path.join("target/debug/artifact"), vec![b'o'; 64]).expect("old artifact");
        let new = create_gc_worktree(&manager, "boundary-protection-new", &worktree_root);
        fs::create_dir_all(new.path.join("target/debug")).expect("new target");
        fs::write(
            new.path.join("target/debug/artifact"),
            vec![b'n'; 64 * 1024],
        )
        .expect("new artifact");
        let old_size = gc_worktree_size_estimate(&old.path).expect("old size");
        let new_size = gc_worktree_size_estimate(&new.path).expect("new size");
        assert!(new_size.worktree_bytes > old_size.worktree_bytes);

        let mut options = gc_options(Some(worktree_root), false);
        options.remove_targets = false;
        options.retention = WorktreeRetentionPolicy {
            max_age: None,
            max_count: Some(1),
            max_total_bytes: Some(old_size.worktree_bytes),
        };
        let liveness_calls = std::cell::Cell::new(0usize);
        let report = manager
            .gc_with_target_liveness(options, |target| {
                let call = liveness_calls.get();
                liveness_calls.set(call.saturating_add(1));
                assert_eq!(target.path, new.path.join("target"));
                if call == 1 {
                    fs::write(new.path.join("README.md"), "late tracked edit\n")
                        .expect("late tracked edit");
                }
                WorktreeTargetLiveness::Clear
            })
            .expect("boundary-protected retention GC");

        assert_eq!(liveness_calls.get(), 2, "preflight and boundary probes");
        assert_eq!(report.removed_count, 0, "{report:#?}");
        assert_eq!(report.retained_count, 1, "{report:#?}");
        assert_eq!(report.protected_count, 1, "{report:#?}");
        assert_eq!(report.estimated_reclaimable_bytes, 0, "{report:#?}");
        assert_eq!(report.estimated_reclaimed_bytes, 0, "{report:#?}");
        assert_eq!(
            report
                .entries
                .iter()
                .find(|entry| entry.name == new.name)
                .expect("new protected entry")
                .reason,
            WorktreeGcReason::Dirty
        );
        assert_eq!(
            report
                .entries
                .iter()
                .find(|entry| entry.name == old.name)
                .expect("old retained entry")
                .reason,
            WorktreeGcReason::RetentionKeep
        );
        assert!(old.path.join("target").exists());
        assert!(new.path.join("target").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn explicit_force_remove_recovery_still_refuses_live_or_unknown_target() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = create_gc_worktree(&manager, "recovery-live", &worktree_root);
        fs::create_dir_all(created.path.join("target/debug")).expect("target");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let lock = store.lock().expect("lock");
        let mut registry = store.load(&lock).expect("registry");
        let (binding, _, _, _) =
            prepare_remove_operation_for_test(&repo, &store, &lock, &mut registry);
        registry
            .operations
            .get_mut(&binding.name)
            .expect("prepared removal")
            .removal_safety = Some(ManagedRemovalSafety::Explicit);
        store
            .save(&lock, &mut registry)
            .expect("persist explicit removal origin");
        let operation = registry
            .operations
            .get(&binding.name)
            .cloned()
            .expect("prepared removal");

        for (label, probe) in [
            (
                "live",
                test_live_target_liveness as fn() -> WorktreeTargetLiveness,
            ),
            ("unknown", test_unknown_target_liveness),
        ] {
            let error = recover_remove_operation_with_lease_using_target_liveness(
                &repo,
                &store,
                &lock,
                &mut registry,
                operation.clone(),
                None,
                &|_| probe(),
            )
            .expect_err("recovery liveness must refuse quarantine");
            assert!(error.to_string().contains(label), "{error:#}");
            assert!(error.to_string().contains("\"pid\""), "{error:#}");
            assert!(binding.path.exists());
        }

        fs::write(
            binding.path.join("force-output.txt"),
            "explicit force output\n",
        )
        .expect("force output");
        recover_remove_operation_with_lease_using_target_liveness(
            &repo,
            &store,
            &lock,
            &mut registry,
            operation,
            None,
            &|_| WorktreeTargetLiveness::Clear,
        )
        .expect("explicit force removal bypasses dirtiness after liveness clears");
        assert!(!binding.path.exists());
        assert!(!registry.operations.contains_key(&binding.name));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn remove_prepared_gc_recovery_refuses_changed_dirtiness_snapshot() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = create_gc_worktree(&manager, "recovery-dirty", &worktree_root);
        fs::create_dir_all(created.path.join("target/debug")).expect("target");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let lock = store.lock().expect("lock");
        let mut registry = store.load(&lock).expect("registry");
        let (binding, _, _, _) =
            prepare_remove_operation_for_test(&repo, &store, &lock, &mut registry);
        let approved = gc_worktree_dirtiness(&binding.path).expect("approved dirtiness");
        let dirtiness = managed_gc_dirtiness_snapshot(&approved).expect("approved snapshot");
        let target = gc_target_if_present(&binding.path)
            .expect("target inspection")
            .expect("target exists");
        let operation = registry
            .operations
            .get_mut(&binding.name)
            .expect("prepared removal");
        operation.delete_branch = false;
        operation.removal_safety = Some(ManagedRemovalSafety::GarbageCollection {
            dirtiness,
            target: ManagedGcTargetSnapshot::Present {
                identity: target.identity,
            },
        });
        store
            .save(&lock, &mut registry)
            .expect("persist GC safety snapshot");
        fs::write(binding.path.join("worker-output.txt"), "only copy\n")
            .expect("late worker output");
        let operation = registry
            .operations
            .get(&binding.name)
            .cloned()
            .expect("prepared removal");

        let error = recover_remove_operation_with_lease_using_target_liveness(
            &repo,
            &store,
            &lock,
            &mut registry,
            operation,
            None,
            &|_| WorktreeTargetLiveness::Clear,
        )
        .expect_err("changed GC snapshot must refuse quarantine");
        assert!(error.to_string().contains("dirtiness changed"), "{error:#}");
        assert!(binding.path.exists());
        assert!(registry.operations.contains_key(&binding.name));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_recovery_refuses_target_presence_and_identity_changes_before_liveness() {
        for replacement in [false, true] {
            let temp = TempDir::new().expect("tempdir");
            let repo_path = temp.path().join("repo");
            let worktree_root = temp.path().join("worktrees");
            WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
            let repo = crate::git_repository::open(&repo_path).expect("open repo");
            commit_readme(&repo).expect("initial commit");
            let manager = WorktreeManager::new(&repo_path);
            let created = create_gc_worktree(
                &manager,
                if replacement {
                    "recovery-target-replacement"
                } else {
                    "recovery-target-appearance"
                },
                &worktree_root,
            );
            if replacement {
                fs::create_dir_all(created.path.join("target/debug")).expect("original target");
            }
            let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
            let lock = store.lock().expect("lock");
            let mut registry = store.load(&lock).expect("registry");
            let (binding, _, _, _) =
                prepare_remove_operation_for_test(&repo, &store, &lock, &mut registry);
            let target = match gc_target_if_present(&binding.path).expect("target snapshot") {
                Some(target) => ManagedGcTargetSnapshot::Present {
                    identity: target.identity,
                },
                None => ManagedGcTargetSnapshot::Absent,
            };
            let operation = registry
                .operations
                .get_mut(&binding.name)
                .expect("prepared removal");
            operation.delete_branch = false;
            operation.removal_safety = Some(ManagedRemovalSafety::GarbageCollection {
                dirtiness: ManagedGcDirtinessSnapshot::Clean,
                target,
            });
            store.save(&lock, &mut registry).expect("persist GC safety");

            if replacement {
                fs::rename(
                    binding.path.join("target"),
                    binding.path.join("target-original"),
                )
                .expect("move original target");
                fs::create_dir(binding.path.join("target")).expect("replacement target");
            } else {
                fs::create_dir(binding.path.join("target")).expect("new target");
            }
            let operation = registry
                .operations
                .get(&binding.name)
                .cloned()
                .expect("prepared removal");
            let liveness_calls = std::cell::Cell::new(0usize);
            let error = recover_remove_operation_with_lease_using_target_liveness(
                &repo,
                &store,
                &lock,
                &mut registry,
                operation,
                None,
                &|_| {
                    liveness_calls.set(liveness_calls.get().saturating_add(1));
                    WorktreeTargetLiveness::Clear
                },
            )
            .expect_err("changed target snapshot must refuse recovery");
            let message = error.to_string();
            assert!(
                message.contains("target changed from")
                    || message.contains("target filesystem identity changed"),
                "{error:#}"
            );
            assert_eq!(
                liveness_calls.get(),
                0,
                "liveness ran before identity check"
            );
            assert!(binding.path.exists());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn clean_legacy_remove_refuses_until_explicit_force_reauthorization() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = create_gc_worktree(&manager, "legacy-removal", &worktree_root);
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let lock = store.lock().expect("lock");
        let mut registry = store.load(&lock).expect("registry");
        let (binding, _, _, _) =
            prepare_remove_operation_for_test(&repo, &store, &lock, &mut registry);
        registry
            .operations
            .get_mut(&binding.name)
            .expect("prepared removal")
            .removal_safety = None;
        store
            .save(&lock, &mut registry)
            .expect("persist authenticated legacy origin");
        let operation = registry
            .operations
            .get(&binding.name)
            .cloned()
            .expect("prepared removal");
        let error = recover_remove_operation_with_lease_using_target_liveness(
            &repo,
            &store,
            &lock,
            &mut registry,
            operation,
            None,
            &|_| WorktreeTargetLiveness::Clear,
        )
        .expect_err("clean legacy removal must still require reauthorization");
        assert!(
            error.to_string().contains("ambiguous safety state"),
            "{error:#}"
        );
        assert!(binding.path.exists());
        drop(lock);
        drop(store);
        drop(repo);

        let removed = manager
            .remove(&binding.name, true, true)
            .expect("explicit force reauthorizes pending legacy removal");
        assert_eq!(removed.path, created.path);
        assert!(!binding.path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn quarantined_legacy_remove_requires_reauthorization_and_adopts_exact_branch_scope() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        create_gc_worktree(&manager, "legacy-quarantined", &worktree_root);
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let lock = store.lock().expect("lock");
        let mut registry = store.load(&lock).expect("registry");
        let (binding, worktree_quarantine, _, _) =
            prepare_remove_operation_for_test(&repo, &store, &lock, &mut registry);
        ensure_removal_worktree_lock(&repo, &binding).expect("removal lock");
        quarantine_bound_directory(
            &binding.root,
            &binding.path,
            &worktree_quarantine,
            &binding.path_identity,
        )
        .expect("quarantine worktree");
        let operation = registry
            .operations
            .get_mut(&binding.name)
            .expect("prepared removal");
        operation.phase = ManagedWorktreeOperationPhase::WorktreeQuarantined;
        operation.worktree_quarantine_identity = Some(binding.path_identity.clone());
        operation.removal_safety = None;
        assert!(
            operation.delete_branch,
            "legacy operation starts branch-destructive"
        );
        store
            .save(&lock, &mut registry)
            .expect("persist quarantined legacy operation");

        let error = recover_pending_operations(&repo, &store, &lock, &mut registry)
            .expect_err("quarantined legacy operation must require reauthorization");
        assert!(
            error.to_string().contains("worktree_quarantined"),
            "{error:#}"
        );
        assert!(worktree_quarantine.exists());
        drop(lock);
        drop(store);
        drop(repo);

        manager
            .remove(&binding.name, true, false)
            .expect("explicit force reauthorizes without branch deletion");
        assert!(!binding.path.exists());
        let repo = crate::git_repository::open(&repo_path).expect("reopen repo");
        assert!(repo.find_branch(&binding.branch, BranchType::Local).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn f3_legacy_digest_round_trips_authenticated_and_remains_ambiguous() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        create_gc_worktree(&manager, "f3-digest", &worktree_root);
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let lock = store.lock().expect("lock");
        let mut registry = store.load(&lock).expect("registry");
        let (binding, _, _, _) =
            prepare_remove_operation_for_test(&repo, &store, &lock, &mut registry);
        let digest = stable_checksum(b"legacy-f3-reviewed-state");
        let operation = registry
            .operations
            .get_mut(&binding.name)
            .expect("prepared removal");
        operation.removal_safety = None;
        operation.gc_dirtiness_checksum = Some(digest.clone());
        store
            .save(&lock, &mut registry)
            .expect("persist f3-compatible digest field");
        drop(lock);
        drop(store);

        let store = ManagedWorktreeRegistryStore::open(&repo).expect("reopen store");
        let lock = store.lock().expect("reopen lock");
        let mut registry = store.load(&lock).expect("authenticated legacy load");
        let operation = registry
            .operations
            .get(&binding.name)
            .cloned()
            .expect("round-tripped operation");
        assert_eq!(
            operation.gc_dirtiness_checksum.as_deref(),
            Some(digest.as_str())
        );
        assert!(operation.removal_safety.is_none());
        let error = recover_remove_operation_with_lease_using_target_liveness(
            &repo,
            &store,
            &lock,
            &mut registry,
            operation,
            None,
            &|_| WorktreeTargetLiveness::Clear,
        )
        .expect_err("legacy digest must never authorize recovery");
        assert!(
            error.to_string().contains("ambiguous safety state"),
            "{error:#}"
        );
        assert!(binding.path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_dirtiness_snapshot_preserves_non_utf8_paths_and_detects_exact_change() {
        for changed in [false, true] {
            let temp = TempDir::new().expect("tempdir");
            let repo_path = temp.path().join("repo");
            let worktree_root = temp.path().join("worktrees");
            WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
            let repo = crate::git_repository::open(&repo_path).expect("open repo");
            commit_readme(&repo).expect("initial commit");
            let manager = WorktreeManager::new(&repo_path);
            create_gc_worktree(&manager, "non-utf8-snapshot", &worktree_root);
            let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
            let lock = store.lock().expect("lock");
            let mut registry = store.load(&lock).expect("registry");
            let (binding, _, _, _) =
                prepare_remove_operation_for_test(&repo, &store, &lock, &mut registry);
            let original = PathBuf::from(OsString::from_vec(b"worker-\xff".to_vec()));
            fs::write(binding.path.join(&original), "only copy\n").expect("non-UTF8 output");
            let approved = gc_worktree_dirtiness(&binding.path).expect("approved dirtiness");
            let snapshot = managed_gc_dirtiness_snapshot(&approved).expect("exact snapshot");
            let round_trip: ManagedGcDirtinessSnapshot = serde_json::from_slice(
                &serde_json::to_vec(&snapshot).expect("serialize exact snapshot"),
            )
            .expect("deserialize exact snapshot");
            assert_eq!(round_trip, snapshot);
            let operation = registry
                .operations
                .get_mut(&binding.name)
                .expect("prepared removal");
            operation.delete_branch = false;
            operation.removal_safety = Some(ManagedRemovalSafety::GarbageCollection {
                dirtiness: snapshot,
                target: ManagedGcTargetSnapshot::Absent,
            });
            store
                .save(&lock, &mut registry)
                .expect("persist exact GC snapshot");
            if changed {
                let changed_path = PathBuf::from(OsString::from_vec(b"worker-\xfe".to_vec()));
                fs::rename(
                    binding.path.join(&original),
                    binding.path.join(changed_path),
                )
                .expect("change exact non-UTF8 path");
            }
            let operation = registry
                .operations
                .get(&binding.name)
                .cloned()
                .expect("prepared removal");
            let result = recover_remove_operation_with_lease_using_target_liveness(
                &repo,
                &store,
                &lock,
                &mut registry,
                operation,
                None,
                &|_| WorktreeTargetLiveness::Clear,
            );
            if changed {
                let error = result.expect_err("exact path change must refuse removal");
                assert!(error.to_string().contains("dirtiness changed"), "{error:#}");
                assert!(binding.path.exists());
            } else {
                result.expect("unchanged exact path snapshot");
                assert!(!binding.path.exists());
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pseudo_file_descriptor_targets_do_not_make_liveness_unknown() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("tempdir");
        let lane = temp.path().join("lane");
        fs::create_dir_all(lane.join("target/debug")).expect("target");
        let process_root = temp.path().join("proc-entry");
        fs::create_dir_all(process_root.join("fd")).expect("fd directory");
        symlink("/", process_root.join("root")).expect("process root link");
        symlink(temp.path(), process_root.join("cwd")).expect("cwd link");
        symlink(
            std::env::current_exe().expect("current exe"),
            process_root.join("exe"),
        )
        .expect("exe link");
        for (fd, target) in [
            ("3", "pipe:[123]"),
            ("4", "socket:[456]"),
            ("5", "anon_inode:[eventpoll]"),
            ("6", "/memfd:rustc (deleted)"),
            ("7", "anon_inode:inotify"),
            ("8", "/dmabuf:"),
        ] {
            symlink(target, process_root.join("fd").join(fd)).expect("pseudo fd link");
        }
        let target = gc_target_if_present(&lane)
            .expect("bind target")
            .expect("target exists");
        let view = LinuxProcessView::for_test(&process_root, true);
        assert_eq!(
            linux_process_target_association(
                &view,
                42,
                &target,
                Instant::now() + Duration::from_secs(1),
                false,
            ),
            WorktreeTargetLiveness::Clear
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn different_mount_namespace_process_path_uses_rooted_identity_ancestry() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("tempdir");
        let lane = temp.path().join("lane");
        fs::create_dir_all(lane.join("target/debug")).expect("target");
        let process_root = temp.path().join("proc-entry");
        fs::create_dir(&process_root).expect("process root");
        symlink("/", process_root.join("root")).expect("root link");
        let target = gc_target_if_present(&lane)
            .expect("bind target")
            .expect("target exists");
        let view = LinuxProcessView::for_test(&process_root, false);
        let resolved = view
            .resolve_configured_path(&lane.join("target/debug"))
            .expect("rooted process path");
        assert!(resolved.observer_canonical_path.is_none());
        assert_eq!(
            process_path_overlaps_target(&resolved, &target),
            WorktreePathOverlap::Overlap
        );
    }

    #[test]
    fn target_only_mode_rejects_conflicting_gc_policies() {
        let retention = WorktreeRetentionPolicy {
            max_age: None,
            max_count: Some(1),
            max_total_bytes: None,
        };
        assert!(validate_worktree_gc_mode(true, true, retention, &[], false)
            .expect_err("retention conflict")
            .to_string()
            .contains("retention filters"));
        assert!(validate_worktree_gc_mode(
            true,
            true,
            WorktreeRetentionPolicy {
                max_age: None,
                max_count: None,
                max_total_bytes: Some(1),
            },
            &[],
            false,
        )
        .expect_err("size retention conflict")
        .to_string()
        .contains("retention filters"));
        assert!(validate_worktree_gc_mode(
            true,
            true,
            WorktreeRetentionPolicy::default(),
            &[PathBuf::from("TASK.md")],
            false,
        )
        .expect_err("allowlist conflict")
        .to_string()
        .contains("untracked-path allowances"));
        assert!(validate_worktree_gc_mode(
            true,
            false,
            WorktreeRetentionPolicy::default(),
            &[],
            false,
        )
        .expect_err("keep target conflict")
        .to_string()
        .contains("keeping target"));
        assert!(validate_worktree_gc_mode(
            true,
            true,
            WorktreeRetentionPolicy::default(),
            &[],
            true,
        )
        .expect_err("machine-global conflict")
        .to_string()
        .contains("machine-global"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unreadable_process_liveness_protects_even_without_prior_build_association() {
        let WorktreeTargetLiveness::Unknown(evidence) = bounded_association_failure(42) else {
            panic!("unreadable process association must be unknown");
        };
        assert_eq!(evidence.pid, Some(42));
        assert_eq!(
            evidence.source,
            WorktreeTargetLivenessSource::ProcessFileDescriptor
        );
        assert_eq!(evidence.cause, WorktreeTargetLivenessCause::ReadFailed);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn create_retention_applies_after_new_worktree_creation() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let old = create_gc_worktree(&manager, "agent-create-old", &worktree_root);

        let new = manager
            .create_for_test_with_retention(
                WorktreeCreateOptions {
                    agent_id: "agent-create-new".to_string(),
                    branch: None,
                    base: None,
                    worktree_root: Some(worktree_root),
                },
                WorktreeRetentionPolicy {
                    max_age: None,
                    max_count: Some(1),
                    max_total_bytes: None,
                },
            )
            .expect("create with retention");

        assert!(!old.path.exists());
        assert!(new.path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn create_size_retention_reserves_the_new_lane_before_reclaiming_older_lanes() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let old = create_gc_worktree(&manager, "size-create-old", &worktree_root);
        fs::create_dir(old.path.join(".maco")).expect("old runtime directory");
        fs::write(old.path.join(".maco/cache"), vec![b'o'; 1024]).expect("old runtime artifact");

        let new = manager
            .create_for_test_with_retention(
                WorktreeCreateOptions {
                    agent_id: "size-create-new".to_string(),
                    branch: None,
                    base: None,
                    worktree_root: Some(worktree_root),
                },
                WorktreeRetentionPolicy {
                    max_age: None,
                    max_count: None,
                    max_total_bytes: Some(0),
                },
            )
            .expect("create with size retention");

        assert!(!old.path.exists());
        assert!(
            new.path.exists(),
            "the just-created lane is always reserved"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_prunes_unregistered_leftover_directory_second_pass() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let orphan = worktree_root.join("agent-orphan-gc");
        fs::create_dir_all(orphan.join("target/debug")).expect("orphan directory");
        fs::write(orphan.join("leftover.txt"), "partial delete residue\n").expect("orphan file");
        let manager = WorktreeManager::new(&repo_path);
        let mut options = gc_options(Some(worktree_root.clone()), false);
        options.machine_global_retention = Some(machine_global_gc_binding(
            temp.path(),
            &worktree_root,
            "orphan-quarantine",
        ));

        let report = manager.gc(options).expect("gc orphan");

        assert_eq!(report.orphan_removed_count, 1);
        assert!(report.entries.iter().any(|entry| {
            entry.name == "agent-orphan-gc"
                && entry.status == WorktreeGcStatus::OrphanQuarantined
                && entry.reason == WorktreeGcReason::UnregisteredOrphan
                && entry.retention_operation_id.is_some()
        }));
        let public_wire = serde_json::to_string(&report).expect("serialize public GC report");
        assert!(public_wire.contains("retention_operation_id"));
        assert!(
            !public_wire.contains("\"token\""),
            "public GC report must not expose the bearer purge token"
        );
        assert!(!orphan.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn machine_global_claim_refuses_unregistered_worktree_gc_before_any_orphan_moves() {
        use crate::gate_denial::{DestructiveTargetDenial, GateDenialReason};

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let first = worktree_root.join("agent-orphan-first");
        let second = worktree_root.join("agent-orphan-second");
        for orphan in [&first, &second] {
            fs::create_dir_all(orphan).expect("orphan directory");
            fs::write(orphan.join("sentinel"), b"must survive").expect("orphan sentinel");
        }
        let binding = machine_global_gc_binding(temp.path(), &worktree_root, "claimed-orphan-gc");
        let store =
            MachineGlobalStore::open_config(&binding.config).expect("open machine-global config");
        let claimed = store
            .coordinate_for_existing_directory(&binding.root_id, &second)
            .expect("second orphan coordinate");
        let claim = store
            .claim("repair-agent", "repairing-orphan", vec![claimed.clone()])
            .expect("claim orphan");
        assert!(matches!(claim, GateOutcome::Allowed(_)));

        let manager = WorktreeManager::new(&repo_path);
        let mut options = gc_options(Some(worktree_root), false);
        options.machine_global_retention = Some(binding);
        let report = manager.gc(options).expect("refused orphan GC report");

        assert_eq!(report.orphan_removed_count, 0);
        assert_eq!(report.protected_count, 2);
        assert!(report.entries.iter().all(|entry| {
            entry.status == WorktreeGcStatus::Protected
                && entry.reason == WorktreeGcReason::MachineGlobalGate
        }));
        let denial = report
            .entries
            .first()
            .and_then(|entry| entry.gate_denial.as_ref())
            .expect("typed gate denial");
        assert!(matches!(
            denial.reason,
            GateDenialReason::DestructiveTarget {
                denial: ref target_denial
            } if matches!(
                target_denial.as_ref(),
                DestructiveTargetDenial::ActiveClaimIntersection {
                    target,
                    active_claim
                } if target == &claimed && active_claim == &claimed
            )
        ));
        for orphan in [&first, &second] {
            assert_eq!(
                fs::read(orphan.join("sentinel")).expect("read preserved sentinel"),
                b"must survive"
            );
        }
        assert!(store
            .status()
            .expect("machine-global status")
            .retention_operations
            .is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn destructive_unregistered_worktree_gc_refuses_without_machine_global_binding() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let orphan = worktree_root.join("agent-unbound-orphan");
        fs::create_dir_all(&orphan).expect("orphan directory");
        fs::write(orphan.join("sentinel"), b"must survive").expect("orphan sentinel");

        let error = WorktreeManager::new(&repo_path)
            .gc(gc_options(Some(worktree_root), false))
            .expect_err("unbound destructive orphan GC must fail closed");

        assert!(error.to_string().contains(
            "destructive worktree orphan GC requires an explicit machine-global config/root binding"
        ));
        assert_eq!(
            fs::read(orphan.join("sentinel")).expect("read preserved sentinel"),
            b"must survive"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_dry_run_reports_without_removing_worktree_or_target() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = create_gc_worktree(&manager, "agent-dry-run-gc", &worktree_root);
        fs::create_dir_all(created.path.join("target/debug")).expect("target");

        let report = manager
            .gc_with_target_liveness(gc_options(Some(worktree_root), true), |_| {
                WorktreeTargetLiveness::Clear
            })
            .expect("dry-run gc");

        assert!(report.dry_run);
        assert_eq!(report.removed_count, 1, "{report:#?}");
        assert_eq!(report.entries[0].status, WorktreeGcStatus::WouldRemove);
        assert_eq!(report.entries[0].reason, WorktreeGcReason::FinishedBranch);
        let lane_bytes = report.entries[0]
            .apparent_worktree_bytes
            .expect("dry-run lane byte estimate");
        assert_eq!(report.apparent_considered_bytes, lane_bytes);
        assert_eq!(report.estimated_reclaimable_bytes, lane_bytes);
        assert_eq!(report.estimated_reclaimed_bytes, 0);
        assert!(created.path.exists());
        assert!(created.path.join("target").exists());
    }

    #[cfg(unix)]
    #[test]
    fn shared_read_execution_leases_coexist_and_block_remove_before_intent() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-leased".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");

        let first = manager
            .acquire_read_execution_lease("agent-leased")
            .expect("first shared lease");
        let second = manager
            .acquire_read_execution_lease("agent-leased")
            .expect("second shared lease");
        let compatibility = manager
            .acquire_execution_lease("agent-leased")
            .expect("compatibility shared lease");
        assert_eq!(first.record(), &created);
        assert_eq!(second.record(), &created);
        assert_eq!(compatibility.path(), created.path);
        let error = manager
            .remove("agent-leased", true, true)
            .expect_err("active shared lease must block removal");
        assert!(error
            .to_string()
            .contains("active cooperative execution lease"));
        assert!(created.path.exists());
        assert!(repo
            .find_branch("maco/agent-leased", BranchType::Local)
            .is_ok());
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
        let lock = store.lock().expect("registry lock");
        assert!(store.load(&lock).expect("registry").operations.is_empty());
        drop(lock);

        drop(compatibility);
        drop(second);
        drop(first);
        manager
            .remove("agent-leased", true, true)
            .expect("force remove after shared leases release");
    }

    #[cfg(unix)]
    #[test]
    fn read_and_write_execution_leases_exclude_mutating_overlap() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-write-exclusion".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");

        let read = manager
            .acquire_read_execution_lease("agent-write-exclusion")
            .expect("shared read lease");
        let error = manager
            .acquire_write_execution_lease("agent-write-exclusion")
            .expect_err("reader must exclude writer");
        assert!(format!("{error:#}").contains("kernel state lock is already held"));
        drop(read);

        let write = manager
            .acquire_write_execution_lease("agent-write-exclusion")
            .expect("exclusive write lease");
        assert_eq!(write.record(), &created);
        assert_eq!(write.path(), created.path);
        let read_error = manager
            .acquire_read_execution_lease("agent-write-exclusion")
            .expect_err("writer must exclude reader");
        assert!(format!("{read_error:#}").contains("kernel state lock is already held"));
        let write_error = manager
            .acquire_write_execution_lease("agent-write-exclusion")
            .expect_err("writer must exclude another writer");
        assert!(format!("{write_error:#}").contains("kernel state lock is already held"));
        drop(write);

        let _read_after = manager
            .acquire_read_execution_lease("agent-write-exclusion")
            .expect("reader after writer release");
    }

    #[cfg(unix)]
    #[test]
    fn write_execution_lease_blocks_remove_before_intent_is_persisted() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-writer-removal".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");
        let write = manager
            .acquire_write_execution_lease("agent-writer-removal")
            .expect("exclusive write lease");

        let error = manager
            .remove("agent-writer-removal", true, true)
            .expect_err("writer must block removal");
        assert!(error
            .to_string()
            .contains("active cooperative execution lease"));
        assert!(created.path.exists());
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
        let lock = store.lock().expect("registry lock");
        assert!(store.load(&lock).expect("registry").operations.is_empty());
        drop(lock);

        drop(write);
        manager
            .remove("agent-writer-removal", true, true)
            .expect("force remove after writer release");
    }

    #[cfg(unix)]
    #[test]
    fn execution_leases_for_unrelated_worktrees_are_independent() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        for agent_id in ["agent-independent-a", "agent-independent-b"] {
            manager
                .create_for_test(WorktreeCreateOptions {
                    agent_id: agent_id.to_string(),
                    branch: None,
                    base: None,
                    worktree_root: Some(worktree_root.clone()),
                })
                .expect("create independent worktree");
        }

        let write_a = manager
            .acquire_write_execution_lease("agent-independent-a")
            .expect("writer for first worktree");
        let read_b = manager
            .acquire_read_execution_lease("agent-independent-b")
            .expect("reader for unrelated worktree");
        drop(read_b);
        let write_b = manager
            .acquire_write_execution_lease("agent-independent-b")
            .expect("writer for unrelated worktree");

        assert_ne!(write_a.path(), write_b.path());
    }

    #[test]
    fn recreated_worktree_uses_new_incarnation_and_rejects_stale_removal_lease() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let options = || WorktreeCreateOptions {
            agent_id: "agent-incarnation".to_string(),
            branch: None,
            base: None,
            worktree_root: Some(worktree_root.clone()),
        };
        manager
            .create_for_test(options())
            .expect("first incarnation");

        let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
        let lock = store.lock().expect("registry lock");
        let first = store
            .active_incarnation(&lock, "agent-incarnation")
            .expect("first incarnation evidence");
        drop(lock);
        manager
            .remove("agent-incarnation", true, true)
            .expect("remove first incarnation");
        let old_lease_name =
            managed_worktree_lease_name("agent-incarnation", &first).expect("old lease name");
        let stale_lock =
            KernelStateLock::try_acquire_exclusive_direct(&store.state_root, &old_lease_name)
                .expect("stale incarnation lock");

        manager
            .create_for_test(options())
            .expect("second incarnation");
        let lock = store.lock().expect("registry lock");
        let second = store
            .active_incarnation(&lock, "agent-incarnation")
            .expect("second incarnation evidence");
        assert_eq!(second.generation, 1);
        assert_ne!(second.nonce, first.nonce);
        let stale_lease_name =
            managed_worktree_lease_name("agent-incarnation", &first).expect("stale lease name");
        let stale_process_lease =
            ManagedProcessLease::acquire_exclusive(&stale_lease_name, stale_lock.path())
                .expect("stale process lease");
        let stale = ManagedWorktreeRemovalLease {
            name: "agent-incarnation".to_string(),
            incarnation_generation: first.generation,
            incarnation_nonce: first.nonce,
            _lock: stale_lock,
            _process_lease: stale_process_lease,
        };
        let error = store
            .verify_removal_lease_current(&lock, &stale)
            .expect_err("stale removal lease must not authorize the new incarnation");
        assert!(error.to_string().contains("stale incarnation"));
        let authenticated = store
            .open_authenticated_state(&lock)
            .expect("authenticated managed state");
        assert_eq!(authenticated.current().value.incarnations.len(), 1);
        assert!(authenticated
            .current()
            .value
            .retired_leases
            .contains_key(old_lease_name.to_str().expect("UTF-8 lease name")));
        drop(authenticated);
        drop(lock);

        let _current = manager
            .acquire_read_execution_lease("agent-incarnation")
            .expect("old-incarnation lock must not block current lease");
        assert!(store.state_root.path().join(&old_lease_name).exists());
        drop(stale);
        manager.list().expect("scavenge released retired lease");
        assert!(!store.state_root.path().join(&old_lease_name).exists());
    }

    #[test]
    fn inactive_incarnation_churn_is_pruned_instead_of_exhausting_the_registry() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
        let registry = store.empty_registry();
        let mut incarnations = BTreeMap::new();

        for index in 0..MAX_MANAGED_RECORDS.saturating_mul(4) {
            let name = format!("retired-{index}");
            incarnations.insert(
                name.clone(),
                ManagedIncarnation {
                    generation: 1,
                    nonce: format!("{index:064x}"),
                    active: true,
                },
            );
            let retired = reconcile_managed_incarnations(&mut incarnations, &registry)
                .expect("prune inactive incarnation");
            assert_eq!(retired.len(), 1);
            assert_eq!(retired[0].0, name);
            assert!(incarnations.is_empty());
        }
    }

    #[cfg(unix)]
    #[test]
    fn retired_lease_scavenger_refuses_rebound_or_foreign_inode() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-retired-rebind".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
        let lock = store.lock().expect("registry lock");
        let incarnation = store
            .active_incarnation(&lock, "agent-retired-rebind")
            .expect("incarnation");
        drop(lock);
        manager
            .remove("agent-retired-rebind", true, true)
            .expect("remove worktree");
        let lease_name =
            managed_worktree_lease_name("agent-retired-rebind", &incarnation).expect("lease name");
        let lease_path = store.state_root.path().join(&lease_name);
        let moved_path = store.state_root.path().join("retired-lease-original");
        crate::safe_state::set_kernel_lock_after_flock_hook({
            let lease_name = lease_name.clone();
            let moved_path = moved_path.clone();
            move |path| {
                if path.file_name() != Some(lease_name.as_os_str()) {
                    return false;
                }
                fs::rename(path, &moved_path).expect("move expected retired lease");
                fs::write(path, b"").expect("foreign replacement");
                fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                    .expect("replacement mode");
                true
            }
        });

        let error = manager
            .list()
            .expect_err("rebound retired lease must fail closed");
        let chain = format!("{error:#}");
        assert!(
            chain.contains("does not name its opened descriptor") || chain.contains("rebound"),
            "unexpected error: {chain}"
        );
        assert!(
            lease_path.exists(),
            "foreign replacement must not be deleted"
        );
        assert!(
            moved_path.exists(),
            "expected inode must remain for inspection"
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_execution_lease_rejects_lock_path_rebind_after_flock() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-write-rebind".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
        let registry_lock = store.lock().expect("registry lock");
        let incarnation = store
            .active_incarnation(&registry_lock, "agent-write-rebind")
            .expect("active incarnation");
        drop(registry_lock);
        let lease_name =
            managed_worktree_lease_name("agent-write-rebind", &incarnation).expect("lease name");
        let moved_path = store
            .state_root
            .path()
            .join("managed-worktree-agent-write-rebind.execution.lock.original");
        crate::safe_state::set_kernel_lock_after_flock_hook({
            let lease_name = lease_name.clone();
            let moved_path = moved_path.clone();
            move |path| {
                if path.file_name() != Some(lease_name.as_os_str()) {
                    return false;
                }
                fs::rename(path, &moved_path).expect("move acquired lease inode");
                fs::write(path, b"").expect("create replacement lease inode");
                fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                    .expect("private replacement mode");
                true
            }
        });

        let error = manager
            .acquire_write_execution_lease("agent-write-rebind")
            .expect_err("rebound write-lease path must fail closed");
        let chain = format!("{error:#}");
        assert!(
            chain.contains("does not name its opened descriptor") || chain.contains("was rebound"),
            "unexpected error: {chain}"
        );
        let replacement_path = store.state_root.path().join(&lease_name);
        assert_ne!(
            identity_for_path(&replacement_path).expect("replacement identity"),
            identity_for_path(&moved_path).expect("original identity")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pending_remove_refuses_active_lease_then_recovers_after_release() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-pending-lease".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");
        let execution = manager
            .acquire_read_execution_lease("agent-pending-lease")
            .expect("shared execution lease");
        let worktree_quarantine = {
            let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
            let lock = store.lock().expect("registry lock");
            let mut registry = store.load(&lock).expect("registry");
            let (_, worktree_quarantine, _, _) =
                prepare_remove_operation_for_test(&repo, &store, &lock, &mut registry);
            worktree_quarantine
        };

        let assert_still_bound = |error: anyhow::Error| {
            assert!(error
                .to_string()
                .contains("pending removal remains durable"));
            assert!(created.path.exists());
            assert!(!worktree_quarantine.exists());
            assert!(repo.find_worktree("agent-pending-lease").is_ok());
        };
        assert!(manager
            .list()
            .expect("list must stay read-only during pending removal")
            .is_empty());
        assert!(created.path.exists());
        assert!(!worktree_quarantine.exists());
        assert!(repo.find_worktree("agent-pending-lease").is_ok());
        assert_still_bound(
            manager
                .get_managed_verified("agent-pending-lease")
                .expect_err("get must refuse active execution lease"),
        );
        assert_still_bound(
            manager
                .acquire_execution_lease("agent-pending-lease")
                .expect_err("new execution lease must refuse pending removal"),
        );
        assert_still_bound(
            manager
                .acquire_write_execution_lease("agent-pending-lease")
                .expect_err("new writer must refuse pending removal"),
        );
        assert_still_bound(
            manager
                .create_for_test(WorktreeCreateOptions {
                    agent_id: "unrelated-create".to_string(),
                    branch: None,
                    base: None,
                    worktree_root: None,
                })
                .expect_err("create entrypoint must refuse active pending removal"),
        );
        assert_still_bound(
            manager
                .remove("agent-pending-lease", true, true)
                .expect_err("remove entrypoint must refuse active pending removal"),
        );

        drop(execution);
        assert!(manager
            .list()
            .expect("list stays read-only after lease release")
            .is_empty());
        assert!(created.path.exists());
        manager
            .remove("agent-pending-lease", true, true)
            .expect("recover pending removal after lease release");
        assert!(!created.path.exists());
        assert!(repo
            .find_branch("maco/agent-pending-lease", BranchType::Local)
            .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn persisted_paths_round_trip_non_utf8_and_reject_noncanonical_wire_values() {
        let path = PathBuf::from(std::ffi::OsString::from_vec(
            b"/tmp/maco-path-\xff".to_vec(),
        ));
        let wire = encode_persisted_path(&path).expect("encode non-UTF-8 path");
        assert_eq!(
            decode_persisted_path(wire).expect("decode non-UTF-8 path"),
            path
        );

        let wrong_platform = PersistedPathWire {
            platform: "wrong-platform".to_string(),
            encoding: "unix-bytes-hex-v1".to_string(),
            data: "2f746d70".to_string(),
        };
        assert!(decode_persisted_path(wrong_platform)
            .expect_err("wrong platform must fail")
            .contains("does not match"));
        let uppercase = PersistedPathWire {
            platform: std::env::consts::OS.to_string(),
            encoding: "unix-bytes-hex-v1".to_string(),
            data: "2F746d70".to_string(),
        };
        assert!(decode_persisted_path(uppercase)
            .expect_err("uppercase hex must fail")
            .contains("noncanonical"));
        assert!(encode_persisted_path(Path::new("/tmp/../escape"))
            .expect_err("parent component must fail")
            .contains("canonical"));
        let oversized = PathBuf::from(format!(
            "/{}",
            "x/".repeat(MAX_PERSISTED_PATH_BYTES).trim_end_matches('/')
        ));
        assert!(encode_persisted_path(&oversized)
            .expect_err("oversized path must fail")
            .contains("byte limit"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn non_utf8_repository_registry_survives_reopen_recovery_and_remove() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp
            .path()
            .join(std::ffi::OsString::from_vec(b"repo-non-utf8-\xff".to_vec()));
        let worktree_root = temp.path().join(std::ffi::OsString::from_vec(
            b"worktrees-non-utf8-\xfe".to_vec(),
        ));
        WorktreeManager::init_repository(&repo_path, "main").expect("init non-UTF-8 repo");
        let repo = crate::git_repository::open(&repo_path).expect("open non-UTF-8 repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "non-utf8-agent".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create non-UTF-8 managed worktree");
        let write = manager
            .acquire_write_execution_lease("non-utf8-agent")
            .expect("acquire writer in non-UTF-8 repository");
        assert_eq!(write.record(), &created);
        assert_eq!(write.path(), created.path);
        drop(write);

        {
            let store = ManagedWorktreeRegistryStore::open(&repo).expect("open registry");
            let lock = store.lock().expect("registry lock");
            let mut registry = store.load(&lock).expect("load registry");
            repo.find_worktree("non-utf8-agent")
                .expect("managed worktree")
                .lock(Some("simulate crash before lock completion"))
                .expect("re-lock worktree");
            registry
                .records
                .get_mut("non-utf8-agent")
                .expect("managed binding")
                .creation_lock_pending = true;
            let bytes = serde_json::to_vec(&registry).expect("serialize registry bytes");
            assert!(bytes
                .windows(b"unix-bytes-hex-v1".len())
                .any(|window| { window == b"unix-bytes-hex-v1" }));
            assert!(!bytes.windows(3).any(|window| window == [0xef, 0xbf, 0xbd]));
            store
                .save(&lock, &mut registry)
                .expect("persist crash fixture");
        }

        let recovered = manager
            .get_managed_verified("non-utf8-agent")
            .expect("recover non-UTF-8 worktree");
        assert_eq!(recovered.path, created.path);
        let listed = manager.list().expect("list recovered non-UTF-8 worktree");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].path, created.path);
        manager
            .remove("non-utf8-agent", true, true)
            .expect("force remove non-UTF-8 worktree");
        assert!(manager.list().expect("empty verified list").is_empty());
    }

    #[test]
    fn recovers_durable_creation_lock_before_returning_managed_worktree() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-lock".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");

        let worktree = repo.find_worktree("agent-lock").expect("worktree");
        assert_eq!(
            worktree.is_locked().expect("initial lock status"),
            WorktreeLockStatus::Unlocked
        );
        worktree
            .lock(Some("simulate crash before creation-lock completion"))
            .expect("re-lock worktree");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let lock = store.lock().expect("registry lock");
        let mut registry = store.load(&lock).expect("registry");
        registry
            .records
            .get_mut("agent-lock")
            .expect("binding")
            .creation_lock_pending = true;
        store.save(&lock, &mut registry).expect("save pending lock");

        recover_pending_operations(&repo, &store, &lock, &mut registry)
            .expect("recover creation lock");

        assert!(
            !registry
                .records
                .get("agent-lock")
                .expect("binding after recovery")
                .creation_lock_pending
        );
        assert_eq!(
            repo.find_worktree("agent-lock")
                .expect("worktree after recovery")
                .is_locked()
                .expect("recovered lock status"),
            WorktreeLockStatus::Unlocked
        );
    }

    #[test]
    fn verified_list_excludes_unbound_git_worktrees() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let managed_root = temp.path().join("managed");
        let unbound_path = temp.path().join("external-unbound");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let oid = commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "managed-agent".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(managed_root),
            })
            .expect("create managed worktree");
        let commit = repo.find_commit(oid).expect("commit");
        let branch = repo
            .branch("topic/unbound", &commit, false)
            .expect("unbound branch");
        let reference = branch.into_reference();
        let mut options = WorktreeAddOptions::new();
        options.reference(Some(&reference));
        repo.worktree("unbound-agent", &unbound_path, Some(&options))
            .expect("unbound worktree");

        let listed = manager.list().expect("verified list");

        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "managed-agent");
        let error = manager
            .get_managed_verified("unbound-agent")
            .expect_err("unbound worktree must require adoption");
        assert!(error.to_string().contains("explicit adoption"));
    }

    #[test]
    fn rejects_unsafe_agent_id() {
        let error = normalize_agent_id("../agent").expect_err("unsafe id should fail");
        assert!(error.to_string().contains("ASCII letters"));
    }

    #[test]
    fn rejects_path_segment_agent_id() {
        let dot_error = normalize_agent_id(".").expect_err("dot id should fail");
        assert!(dot_error.to_string().contains("cannot be"));

        let parent_error = normalize_agent_id("..").expect_err("parent id should fail");
        assert!(parent_error.to_string().contains("cannot be"));
    }

    #[test]
    fn rejects_oversized_agent_and_branch_names() {
        let agent = "a".repeat(MAX_AGENT_ID_BYTES + 1);
        let error = normalize_agent_id(&agent).expect_err("oversized agent id");
        assert!(error.to_string().contains("byte limit"));

        let branch = "b".repeat(MAX_BRANCH_NAME_BYTES + 1);
        let error = validate_branch_name(&branch).expect_err("oversized branch");
        assert!(error.to_string().contains("byte limit"));
    }

    #[test]
    fn bounded_status_refuses_entry_output_and_time_budget_exhaustion() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        for index in 0..3 {
            fs::write(repo_path.join(format!("untracked-{index}")), "dirty")
                .expect("untracked file");
        }

        let index_entries = bounded_worktree_is_clean(
            &repo_path,
            0,
            MAX_WORKTREE_STATUS_OUTPUT_BYTES,
            WORKTREE_STATUS_TIMEOUT,
        )
        .expect_err("tracked index entry budget must fail");
        assert!(
            index_entries.to_string().contains("entries"),
            "unexpected bounded index error: {index_entries:#}"
        );

        let entries = bounded_worktree_is_clean(
            &repo_path,
            2,
            MAX_WORKTREE_STATUS_OUTPUT_BYTES,
            WORKTREE_STATUS_TIMEOUT,
        )
        .expect_err("entry budget must fail");
        assert!(
            entries.to_string().contains("entries"),
            "unexpected bounded status error: {entries:#}"
        );

        let output = bounded_worktree_is_clean(&repo_path, 10, 1, WORKTREE_STATUS_TIMEOUT)
            .expect_err("output budget must fail");
        assert!(output.to_string().contains("output budget"));

        bounded_worktree_is_clean(
            &repo_path,
            10,
            MAX_WORKTREE_STATUS_OUTPUT_BYTES,
            Duration::ZERO,
        )
        .expect_err("zero time budget must fail before unbounded traversal");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_status_ignores_ambient_and_repository_process_helpers() {
        use std::os::unix::fs::PermissionsExt;

        struct EnvGuard(Vec<(&'static str, Option<std::ffi::OsString>)>);

        impl EnvGuard {
            fn set(values: &[(&'static str, &str)]) -> Self {
                let prior = values
                    .iter()
                    .map(|(name, value)| {
                        let prior = std::env::var_os(name);
                        std::env::set_var(name, value);
                        (*name, prior)
                    })
                    .collect();
                Self(prior)
            }
        }

        impl Drop for EnvGuard {
            fn drop(&mut self) {
                for (name, prior) in self.0.drain(..) {
                    match prior {
                        Some(value) => std::env::set_var(name, value),
                        None => std::env::remove_var(name),
                    }
                }
            }
        }

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");

        let marker = temp.path().join("helper-ran");
        let helper = temp.path().join("malicious-fsmonitor");
        fs::write(
            &helper,
            format!(
                "#!/bin/sh\ntouch '{}'\n/usr/bin/setsid /bin/true\nexit 0\n",
                marker.display()
            ),
        )
        .expect("write malicious helper");
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700))
            .expect("chmod malicious helper");
        let mut config = repo.config().expect("open local config");
        config
            .set_str("core.fsmonitor", helper.to_str().expect("UTF-8 helper"))
            .expect("configure fsmonitor helper");
        config
            .set_str(
                "filter.evil.clean",
                &format!(
                    "sh -c \"touch '{}'; /usr/bin/setsid /bin/true; cat\"",
                    marker.display()
                ),
            )
            .expect("configure filter helper");
        fs::write(repo_path.join(".gitattributes"), "README.md filter=evil\n")
            .expect("write malicious attributes");
        fs::write(repo_path.join("README.md"), "changed\n").expect("change filtered file");

        let count = "1";
        let key = "core.fsmonitor";
        let value = helper.to_str().expect("UTF-8 helper");
        let _ambient = EnvGuard::set(&[
            ("GIT_CONFIG_COUNT", count),
            ("GIT_CONFIG_KEY_0", key),
            ("GIT_CONFIG_VALUE_0", value),
            ("GIT_DIR", "/definitely/not/the/repository"),
        ]);
        assert!(
            !bounded_worktree_is_clean(
                &repo_path,
                MAX_WORKTREE_STATUS_ENTRIES,
                MAX_WORKTREE_STATUS_OUTPUT_BYTES,
                WORKTREE_STATUS_TIMEOUT,
            )
            .expect("bounded private status"),
            "changed worktree must remain dirty"
        );
        assert!(
            !marker.exists(),
            "ambient or repository-configured helper executed"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_status_setup_failure_cleans_large_index_snapshot() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let payload_len = usize::try_from(MAX_WORKTREE_INDEX_BYTES)
            .expect("index limit fits usize")
            .saturating_sub(12 + 8 + 20 + 4096);
        let mut index = b"DIRC".to_vec();
        index.extend_from_slice(&2_u32.to_be_bytes());
        index.extend_from_slice(&0_u32.to_be_bytes());
        index.extend_from_slice(b"TREE");
        index.extend_from_slice(
            &u32::try_from(payload_len)
                .expect("payload length fits u32")
                .to_be_bytes(),
        );
        index.extend(std::iter::repeat_n(b't', payload_len));
        let checksum = sha1_digest(&index).expect("index checksum");
        index.extend_from_slice(&checksum);
        fs::write(repo.path().join("index"), index).expect("write valid large index");
        let runtime_root =
            SafeRoot::open_or_create(temp.path().join("status-root")).expect("runtime root");

        let error = bounded_worktree_is_clean_in_runtime(
            &repo_path,
            MAX_WORKTREE_STATUS_ENTRIES,
            MAX_WORKTREE_STATUS_OUTPUT_BYTES,
            WORKTREE_STATUS_TIMEOUT,
            &runtime_root,
            |_| bail!("injected setup failure after index snapshot"),
        )
        .expect_err("injected setup failure");

        assert!(error.to_string().contains("injected setup failure"));
        assert_status_root_contains_only_lock(&runtime_root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_status_total_deadline_caps_lock_wait() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let runtime_root =
            SafeRoot::open_or_create(temp.path().join("status-root")).expect("runtime root");
        let _held = KernelStateLock::acquire_direct(&runtime_root, WORKTREE_STATUS_RUNTIME_LOCK)
            .expect("hold runtime lock");

        let started = Instant::now();
        let error = bounded_worktree_is_clean_in_runtime_unlocked(
            &repo_path,
            MAX_WORKTREE_STATUS_ENTRIES,
            MAX_WORKTREE_STATUS_OUTPUT_BYTES,
            Duration::from_millis(50),
            &runtime_root,
            |_| Ok(()),
        )
        .expect_err("total deadline must cap lock acquisition");
        assert!(format!("{error:#}").contains("runtime lock"));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "lock wait ignored the total operation deadline"
        );
    }

    #[test]
    fn bounded_status_process_lock_wait_does_not_consume_execution_budget() {
        let held = lock_bounded_status_process();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || -> Result<()> {
            ready_tx
                .send(())
                .context("failed to signal bounded-status process-lock wait")?;
            let (_guard, deadline, _process_queue_wait) =
                enter_bounded_status_process_scope(Duration::from_millis(100))?;
            ensure_worktree_status_deadline(
                deadline,
                "immediately after bounded-status process lock acquisition",
            )
        });

        ready_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("worker started waiting for process lock");
        std::thread::sleep(Duration::from_millis(150));
        drop(held);
        worker
            .join()
            .expect("bounded-status process-lock worker panicked")
            .expect("process-lock queue wait must be excluded from execution budget");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_status_expired_setup_leaves_resumable_runtime() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let runtime_root =
            SafeRoot::open_or_create(temp.path().join("status-root")).expect("runtime root");

        let error = bounded_worktree_is_clean_in_runtime_unlocked(
            &repo_path,
            MAX_WORKTREE_STATUS_ENTRIES,
            MAX_WORKTREE_STATUS_OUTPUT_BYTES,
            Duration::from_millis(500),
            &runtime_root,
            |_| {
                std::thread::sleep(Duration::from_millis(600));
                Ok(())
            },
        )
        .expect_err("setup callback must consume the same total deadline");
        assert!(format!("{error:#}").contains("total time budget"));
        assert!(
            fs::read_dir(runtime_root.path())
                .expect("runtime entries")
                .count()
                > 1,
            "expired cleanup should leave an authenticated resumable residue"
        );

        let _lock = KernelStateLock::acquire_direct(&runtime_root, WORKTREE_STATUS_RUNTIME_LOCK)
            .expect("recovery lock");
        scavenge_bounded_status_runtimes(&runtime_root, WORKTREE_STATUS_SCAVENGE_LIMITS)
            .expect("resume cleanup");
        assert_status_root_contains_only_lock(&runtime_root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_status_scavenges_prior_crash_index_and_symlink_tree() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let runtime_root =
            SafeRoot::open_or_create(temp.path().join("status-root")).expect("runtime root");
        let residue = runtime_root
            .reserve_random_direct_child_directory(WORKTREE_STATUS_RUNTIME_SEED)
            .expect("crash residue");
        let residue_root = SafeRoot::open_existing(residue.path()).expect("residue root");
        residue_root
            .reserve_direct_child_directory("home")
            .expect("home");
        residue_root
            .reserve_direct_child_directory("tmp")
            .expect("tmp");
        let git = residue_root
            .reserve_direct_child_directory("git")
            .expect("git");
        let git_root = SafeRoot::open_existing(git.path()).expect("git root");
        git_root
            .reserve_direct_child_directory("refs")
            .expect("refs");
        AtomicStateWriter::write_direct(&git_root, "index", b"stale index\n").expect("stale index");
        AtomicStateWriter::write_direct(&git_root, "HEAD", b"deadbeef\n").expect("stale HEAD");
        let external = temp.path().join("external");
        fs::create_dir(&external).expect("external");
        fs::write(external.join("sentinel"), b"keep\n").expect("sentinel");
        symlink(&external, git_root.path().join("objects")).expect("objects link");
        symlink(&repo_path, residue_root.path().join("worktree")).expect("worktree link");
        let residue_path = residue.path().to_path_buf();

        assert!(bounded_worktree_is_clean_in_runtime(
            &repo_path,
            MAX_WORKTREE_STATUS_ENTRIES,
            MAX_WORKTREE_STATUS_OUTPUT_BYTES,
            WORKTREE_STATUS_TIMEOUT,
            &runtime_root,
            |_| Ok(()),
        )
        .expect("status after crash recovery"));

        assert!(!residue_path.exists());
        assert!(external.join("sentinel").exists());
        assert_status_root_contains_only_lock(&runtime_root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_status_scavenger_refuses_unexpected_and_symlink_prefix_entries() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("tempdir");
        let unexpected_root =
            SafeRoot::open_or_create(temp.path().join("unexpected-root")).expect("root");
        let _unexpected_lock =
            KernelStateLock::acquire_direct(&unexpected_root, WORKTREE_STATUS_RUNTIME_LOCK)
                .expect("lock");
        AtomicStateWriter::write_direct(&unexpected_root, "foreign", b"inspect\n")
            .expect("unexpected file");
        let error =
            scavenge_bounded_status_runtimes(&unexpected_root, WORKTREE_STATUS_SCAVENGE_LIMITS)
                .expect_err("unexpected entry must fail closed");
        assert!(error.to_string().contains("unexpected entry"));
        assert!(unexpected_root.path().join("foreign").exists());

        let symlink_root =
            SafeRoot::open_or_create(temp.path().join("symlink-root")).expect("root");
        let _symlink_lock =
            KernelStateLock::acquire_direct(&symlink_root, WORKTREE_STATUS_RUNTIME_LOCK)
                .expect("lock");
        let external = temp.path().join("external-directory");
        fs::create_dir(&external).expect("external");
        let matching_name = ".git-status.1-2.tmp";
        symlink(&external, symlink_root.path().join(matching_name)).expect("matching symlink");
        let error =
            scavenge_bounded_status_runtimes(&symlink_root, WORKTREE_STATUS_SCAVENGE_LIMITS)
                .expect_err("matching symlink must fail closed");
        assert!(error.to_string().contains("owner-private directory"));
        assert!(symlink_root.path().join(matching_name).exists());
        assert!(external.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_status_scavenger_enforces_root_directory_tree_and_byte_budgets() {
        let temp = TempDir::new().expect("tempdir");

        let root_entry_root =
            SafeRoot::open_or_create(temp.path().join("root-entry-budget")).expect("root");
        let _root_entry_lock =
            KernelStateLock::acquire_direct(&root_entry_root, WORKTREE_STATUS_RUNTIME_LOCK)
                .expect("lock");
        let root_entry_residue = root_entry_root
            .reserve_random_direct_child_directory(WORKTREE_STATUS_RUNTIME_SEED)
            .expect("residue");
        let error = scavenge_bounded_status_runtimes(
            &root_entry_root,
            PrivateDirectoryScavengeLimits {
                max_root_entries: 1,
                max_directories: 1,
                max_tree_entries: 1,
                max_total_bytes: 1,
                max_duration: Duration::from_secs(10),
            },
        )
        .expect_err("root entry budget");
        assert!(error.to_string().contains("entry budget"));
        assert!(root_entry_residue.path().exists());

        let directory_root =
            SafeRoot::open_or_create(temp.path().join("directory-budget")).expect("root");
        let _directory_lock =
            KernelStateLock::acquire_direct(&directory_root, WORKTREE_STATUS_RUNTIME_LOCK)
                .expect("lock");
        let first = directory_root
            .reserve_random_direct_child_directory(WORKTREE_STATUS_RUNTIME_SEED)
            .expect("first residue");
        let second = directory_root
            .reserve_random_direct_child_directory(WORKTREE_STATUS_RUNTIME_SEED)
            .expect("second residue");
        let error = scavenge_bounded_status_runtimes(
            &directory_root,
            PrivateDirectoryScavengeLimits {
                max_root_entries: 3,
                max_directories: 1,
                max_tree_entries: 1,
                max_total_bytes: 1,
                max_duration: Duration::from_secs(10),
            },
        )
        .expect_err("directory work budget");
        assert!(error.to_string().contains("cleanup limit"));
        assert!(first.path().exists());
        assert!(second.path().exists());

        let tree_root = SafeRoot::open_or_create(temp.path().join("tree-budget")).expect("root");
        let _tree_lock = KernelStateLock::acquire_direct(&tree_root, WORKTREE_STATUS_RUNTIME_LOCK)
            .expect("lock");
        let tree_residue = tree_root
            .reserve_random_direct_child_directory(WORKTREE_STATUS_RUNTIME_SEED)
            .expect("residue");
        let tree_residue_root = SafeRoot::open_existing(tree_residue.path()).expect("residue root");
        AtomicStateWriter::write_direct(&tree_residue_root, "first", b"1").expect("first");
        AtomicStateWriter::write_direct(&tree_residue_root, "second", b"2").expect("second");
        let error = scavenge_bounded_status_runtimes(
            &tree_root,
            PrivateDirectoryScavengeLimits {
                max_root_entries: 2,
                max_directories: 1,
                max_tree_entries: 1,
                max_total_bytes: 2,
                max_duration: Duration::from_secs(10),
            },
        )
        .expect_err("tree entry budget");
        assert!(error.to_string().contains("bounded safety contract"));
        assert!(tree_residue.path().exists());

        let byte_root = SafeRoot::open_or_create(temp.path().join("byte-budget")).expect("root");
        let _byte_lock = KernelStateLock::acquire_direct(&byte_root, WORKTREE_STATUS_RUNTIME_LOCK)
            .expect("lock");
        let byte_residue = byte_root
            .reserve_random_direct_child_directory(WORKTREE_STATUS_RUNTIME_SEED)
            .expect("residue");
        let byte_residue_root = SafeRoot::open_existing(byte_residue.path()).expect("residue root");
        AtomicStateWriter::write_direct(&byte_residue_root, "large", b"123456789")
            .expect("large file");
        let error = scavenge_bounded_status_runtimes(
            &byte_root,
            PrivateDirectoryScavengeLimits {
                max_root_entries: 2,
                max_directories: 1,
                max_tree_entries: 1,
                max_total_bytes: 8,
                max_duration: Duration::from_secs(10),
            },
        )
        .expect_err("byte budget");
        assert!(format!("{error:#}").contains("byte cleanup budget"));
        assert!(byte_residue.path().exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_status_concurrent_lifecycles_serialize_without_cross_deletion() {
        use std::{sync::mpsc, thread};

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let runtime_root =
            SafeRoot::open_or_create(temp.path().join("status-root")).expect("runtime root");
        let (first_entered_tx, first_entered_rx) = mpsc::channel();
        let (release_first_tx, release_first_rx) = mpsc::channel();
        let first_repo = repo_path.clone();
        let first_root = runtime_root.clone();
        let first = thread::spawn(move || {
            bounded_worktree_is_clean_in_runtime_unlocked(
                &first_repo,
                MAX_WORKTREE_STATUS_ENTRIES,
                MAX_WORKTREE_STATUS_OUTPUT_BYTES,
                WORKTREE_STATUS_TIMEOUT,
                &first_root,
                move |runtime| {
                    first_entered_tx
                        .send(runtime.path().to_path_buf())
                        .context("send first runtime")?;
                    release_first_rx.recv().context("release first runtime")?;
                    Ok(())
                },
            )
        });
        let first_runtime = first_entered_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("first lifecycle entered");
        let (second_entered_tx, second_entered_rx) = mpsc::channel();
        let second_repo = repo_path.clone();
        let second_root = runtime_root.clone();
        let second = thread::spawn(move || {
            bounded_worktree_is_clean_in_runtime_unlocked(
                &second_repo,
                MAX_WORKTREE_STATUS_ENTRIES,
                MAX_WORKTREE_STATUS_OUTPUT_BYTES,
                WORKTREE_STATUS_TIMEOUT,
                &second_root,
                move |_| {
                    second_entered_tx.send(()).context("send second entry")?;
                    Ok(())
                },
            )
        });

        assert!(matches!(
            second_entered_rx.recv_timeout(Duration::from_millis(200)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        assert!(first_runtime.exists());
        release_first_tx.send(()).expect("release first lifecycle");
        assert!(first.join().expect("first thread").expect("first status"));
        second_entered_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("second lifecycle entered after first cleanup");
        assert!(second
            .join()
            .expect("second thread")
            .expect("second status"));
        assert_status_root_contains_only_lock(&runtime_root);
    }

    #[test]
    fn rejects_invalid_custom_branch_name() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");

        let manager = WorktreeManager::new(&repo_path);
        let error = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-invalid".to_string(),
                branch: Some("bad branch".to_string()),
                base: None,
                worktree_root: Some(worktree_root.clone()),
            })
            .expect_err("invalid branch should fail");

        assert!(error.to_string().contains("valid Git branch"));
        assert!(!worktree_root.join("agent-invalid").exists());
    }

    #[test]
    fn refuses_separate_git_directory_before_worktree_mutation() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        drop(repo);
        let separate_git_dir = temp.path().join("separate.git");
        fs::rename(repo_path.join(".git"), &separate_git_dir).expect("move git directory");
        fs::write(
            repo_path.join(".git"),
            format!("gitdir: {}\n", separate_git_dir.display()),
        )
        .expect("write gitdir file");

        let error = WorktreeManager::new(&repo_path)
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-separated".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root.clone()),
            })
            .expect_err("separate git dir must fail closed");
        assert!(error.to_string().contains("--separate-git-dir"));
        assert!(!worktree_root.exists());
        let reopened = crate::git_repository::open(&repo_path).expect("reopen repo");
        assert!(reopened
            .find_branch("maco/agent-separated", BranchType::Local)
            .is_err());
    }

    #[test]
    fn non_force_remove_is_unsupported_without_inspecting_dirty_worktree() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");

        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-dirty".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");
        fs::write(created.path.join("scratch.txt"), "local edits\n").expect("write scratch");

        let error = manager
            .remove("agent-dirty", false, true)
            .expect_err("non-force removal must be unsupported");

        assert!(error.to_string().contains("capability-bound"));
        assert!(created.path.exists());
        assert!(repo
            .find_branch("maco/agent-dirty", BranchType::Local)
            .is_ok());
    }

    #[test]
    fn force_removes_dirty_worktree_and_branch() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");

        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-force".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");
        fs::write(created.path.join("scratch.txt"), "local edits\n").expect("write scratch");

        let removed = manager
            .remove("agent-force", true, true)
            .expect("force remove worktree");

        assert_eq!(removed.name, "agent-force");
        assert!(!removed.path.exists());
        assert!(repo
            .find_branch("maco/agent-force", BranchType::Local)
            .is_err());
    }

    #[test]
    fn force_removes_worktree_with_untracked_nested_directory() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");

        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-residue".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");
        let residue = created.path.join("scratch/nested/deps");
        fs::create_dir_all(&residue).expect("create residue directory");
        fs::write(residue.join("artifact.d"), "untracked worker output\n").expect("write residue");

        let removed = manager
            .remove("agent-residue", true, true)
            .expect("force remove worktree with residue");

        assert_eq!(removed.name, "agent-residue");
        assert!(!removed.path.exists());
        assert!(repo
            .find_branch("maco/agent-residue", BranchType::Local)
            .is_err());
    }

    #[test]
    fn force_remove_refuses_missing_create_time_metadata_binding() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");

        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-repeat".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");
        fs::create_dir_all(created.path.join("target/debug/deps"))
            .expect("create residue directory");
        fs::remove_file(created.path.join(".git")).expect("remove worktree git file");

        let error = manager
            .remove("agent-repeat", true, true)
            .expect_err("force must not bypass missing metadata binding");
        let message = error.to_string();

        assert!(message.contains("without following links"));
        assert!(created.path.exists());
        assert!(repo
            .find_branch("maco/agent-repeat", BranchType::Local)
            .is_ok());
    }

    #[test]
    fn remove_reports_custom_worktree_branch() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");

        let manager = WorktreeManager::new(&repo_path);
        manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-b".to_string(),
                branch: Some("topic/agent-b".to_string()),
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");

        let removed = manager
            .remove("agent-b", true, true)
            .expect("force remove worktree");

        assert_eq!(removed.branch, "topic/agent-b");
        assert!(repo
            .find_branch("topic/agent-b", BranchType::Local)
            .is_err());
    }

    #[test]
    fn force_remove_refuses_forged_gitdir_backlink_and_preserves_victim() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-forged".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");
        let victim = temp.path().join("victim");
        fs::create_dir(&victim).expect("victim");
        fs::write(victim.join("keep"), "keep").expect("victim file");
        let metadata_gitdir = repo
            .commondir()
            .join("worktrees")
            .join("agent-forged")
            .join("gitdir");
        fs::write(
            &metadata_gitdir,
            format!("{}\n", victim.join(".git").display()),
        )
        .expect("forge gitdir");

        manager
            .list_managed_verified()
            .expect_err("verified list must reject forged metadata");

        let error = manager
            .remove("agent-forged", true, true)
            .expect_err("forged backlink must be refused");
        assert!(error.to_string().contains("gitdir"));
        assert!(victim.join("keep").exists());
        assert!(created.path.exists());
        assert!(repo
            .find_branch("maco/agent-forged", BranchType::Local)
            .is_ok());
    }

    #[test]
    fn force_remove_refuses_forged_head_branch() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-head".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");
        let metadata_head = repo
            .commondir()
            .join("worktrees")
            .join("agent-head")
            .join("HEAD");
        fs::write(&metadata_head, "ref: refs/heads/main\n").expect("forge HEAD");

        let error = manager
            .remove("agent-head", true, true)
            .expect_err("forged HEAD must be refused");
        assert!(error.to_string().contains("HEAD binding mismatch"));
        assert!(created.path.exists());
        assert!(repo.find_branch("main", BranchType::Local).is_ok());
        assert!(repo
            .find_branch("maco/agent-head", BranchType::Local)
            .is_ok());
    }

    #[test]
    fn delete_branch_refuses_branch_that_predated_managed_worktree() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let oid = commit_readme(&repo).expect("initial commit");
        let commit = repo.find_commit(oid).expect("commit");
        repo.branch("topic/shared", &commit, false)
            .expect("pre-existing branch");
        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-shared".to_string(),
                branch: Some("topic/shared".to_string()),
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");

        let error = manager
            .remove("agent-shared", true, true)
            .expect_err("pre-existing branch deletion must be refused");
        assert!(error.to_string().contains("predated"));
        assert!(created.path.exists());
        assert!(repo.find_branch("topic/shared", BranchType::Local).is_ok());
    }

    #[test]
    fn transactional_branch_delete_refuses_concurrent_ref_lock_and_preserves_branch() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let oid = commit_readme(&repo).expect("initial commit");
        let commit = repo.find_commit(oid).expect("commit");
        repo.branch("topic/locked-delete", &commit, false)
            .expect("branch");
        let mut concurrent = repo.transaction().expect("concurrent transaction");
        concurrent
            .lock_ref("refs/heads/topic/locked-delete")
            .expect("concurrent ref lock");

        let error = compare_and_delete_local_branch(
            &repo,
            "topic/locked-delete",
            oid,
            false,
            "test deletion",
        )
        .expect_err("concurrent ref lock must refuse deletion");

        assert!(error.to_string().contains("failed to lock branch"));
        assert_eq!(
            local_branch_oid(&repo, "topic/locked-delete").expect("branch oid"),
            Some(oid)
        );
        drop(concurrent);
        compare_and_delete_local_branch(&repo, "topic/locked-delete", oid, false, "test deletion")
            .expect("delete after lock release");
        assert!(local_branch_oid(&repo, "topic/locked-delete")
            .expect("missing branch")
            .is_none());

        let commit = repo.find_commit(oid).expect("commit for advanced branch");
        repo.branch("topic/advanced-delete", &commit, false)
            .expect("advanced branch");
        let advanced =
            commit_descendant(&repo, "README.md", "# Ref advanced\n").expect("advanced commit");
        repo.find_branch("topic/advanced-delete", BranchType::Local)
            .expect("advanced branch ref")
            .into_reference()
            .set_target(advanced, "simulate concurrent update-ref")
            .expect("advance deletion target");
        let error = compare_and_delete_local_branch(
            &repo,
            "topic/advanced-delete",
            oid,
            false,
            "test deletion",
        )
        .expect_err("changed branch must be preserved");
        assert!(error.to_string().contains("preserving it"));
        assert_eq!(
            local_branch_oid(&repo, "topic/advanced-delete").expect("advanced oid"),
            Some(advanced)
        );
    }

    #[test]
    fn recovers_create_prepare_by_cleaning_only_unchanged_new_branch() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let oid = commit_readme(&repo).expect("initial commit");
        let root = SafeRoot::open_or_create_managed(&worktree_root).expect("root");
        let reserved = root
            .reserve_direct_child_directory("agent-crash")
            .expect("reserve path");
        let staging = root
            .reserve_random_direct_child_directory("test-stage")
            .expect("staging root");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let lock = store.lock().expect("lock");
        let mut registry = store.load(&lock).expect("registry");
        let name = "agent-crash".to_string();
        registry.operations.insert(
            name.clone(),
            ManagedWorktreeOperation {
                kind: ManagedWorktreeOperationKind::Create,
                phase: ManagedWorktreeOperationPhase::CreatePrepared,
                name: name.clone(),
                root: root.path().to_path_buf(),
                root_identity: root.identity().clone(),
                path: root.path().join(&name),
                prepared_path_identity: Some(reserved.identity().clone()),
                staging_root: Some(staging.path().to_path_buf()),
                staging_root_identity: Some(staging.identity().clone()),
                staging_path: Some(staging.path().join(&name)),
                staged_path_identity: None,
                staged_metadata: None,
                branch: "maco/agent-crash".to_string(),
                base_oid: oid.to_string(),
                branch_preexisting_oid: None,
                branch_ownership: ManagedBranchOwnership::CreatedByMaco,
                owned_branch_oid: Some(oid.to_string()),
                binding: None,
                delete_branch: false,
                force: false,
                expected_branch_oid: None,
                gc_dirtiness_checksum: None,
                removal_safety: None,
                worktree_quarantine_path: None,
                worktree_quarantine_identity: None,
                metadata_quarantine_path: None,
                metadata_quarantine_identity: None,
            },
        );
        store.save(&lock, &mut registry).expect("save prepare");
        let commit = repo.find_commit(oid).expect("commit");
        repo.branch("maco/agent-crash", &commit, false)
            .expect("create branch before crash");

        recover_pending_operations(&repo, &store, &lock, &mut registry).expect("recover create");
        assert!(registry.operations.is_empty());
        assert!(registry.records.is_empty());
        assert!(repo
            .find_branch("maco/agent-crash", BranchType::Local)
            .is_err());
    }

    #[test]
    fn create_prepared_preserves_foreign_empty_staging_child_without_persisted_identity() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let oid = commit_readme(&repo).expect("initial commit");
        let root = SafeRoot::open_or_create_managed(&worktree_root).expect("root");
        let name = "agent-prepared-foreign".to_string();
        let reserved = root
            .reserve_direct_child_directory(&name)
            .expect("reserve exact final child");
        let staging = root
            .reserve_random_direct_child_directory("test-stage")
            .expect("staging root");
        let staging_root = SafeRoot::open_existing(staging.path()).expect("open staging root");
        let foreign = staging_root
            .reserve_direct_child_directory(&name)
            .expect("foreign empty staging child");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let lock = store.lock().expect("lock");
        let mut registry = store.load(&lock).expect("registry");
        registry.operations.insert(
            name.clone(),
            ManagedWorktreeOperation {
                kind: ManagedWorktreeOperationKind::Create,
                phase: ManagedWorktreeOperationPhase::CreatePrepared,
                name: name.clone(),
                root: root.path().to_path_buf(),
                root_identity: root.identity().clone(),
                path: root.path().join(&name),
                prepared_path_identity: Some(reserved.identity().clone()),
                staging_root: Some(staging.path().to_path_buf()),
                staging_root_identity: Some(staging.identity().clone()),
                staging_path: Some(staging.path().join(&name)),
                staged_path_identity: None,
                staged_metadata: None,
                branch: "maco/agent-prepared-foreign".to_string(),
                base_oid: oid.to_string(),
                branch_preexisting_oid: None,
                branch_ownership: ManagedBranchOwnership::Unknown,
                owned_branch_oid: None,
                binding: None,
                delete_branch: false,
                force: true,
                expected_branch_oid: None,
                gc_dirtiness_checksum: None,
                removal_safety: None,
                worktree_quarantine_path: None,
                worktree_quarantine_identity: None,
                metadata_quarantine_path: None,
                metadata_quarantine_identity: None,
            },
        );
        store
            .save(&lock, &mut registry)
            .expect("save prepared operation");

        let error = recover_pending_operations(&repo, &store, &lock, &mut registry)
            .expect_err("foreign staging child must be preserved");

        assert!(error.to_string().contains("manual recovery"));
        assert!(foreign.path().exists());
        assert_eq!(
            identity_for_path(foreign.path()).expect("foreign identity"),
            *foreign.identity()
        );
        assert!(reserved.path().exists());
        assert!(registry.operations.contains_key(&name));
    }

    #[test]
    fn create_intent_preserves_foreign_empty_target_and_staging_directories() {
        for with_staging in [false, true] {
            let temp = TempDir::new().expect("tempdir");
            let repo_path = temp.path().join("repo");
            let worktree_root = temp.path().join("worktrees");
            WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
            let repo = crate::git_repository::open(&repo_path).expect("open repo");
            let oid = commit_readme(&repo).expect("initial commit");
            let root = SafeRoot::open_or_create_managed(&worktree_root).expect("root");
            let name = "agent-intent".to_string();
            let staging_name = "stage-intent";
            let staging_root_path = root.path().join(staging_name);
            let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
            let lock = store.lock().expect("lock");
            let mut registry = store.load(&lock).expect("registry");
            registry.operations.insert(
                name.clone(),
                ManagedWorktreeOperation {
                    kind: ManagedWorktreeOperationKind::Create,
                    phase: ManagedWorktreeOperationPhase::CreateIntent,
                    name: name.clone(),
                    root: root.path().to_path_buf(),
                    root_identity: root.identity().clone(),
                    path: root.path().join(&name),
                    prepared_path_identity: None,
                    staging_root: Some(staging_root_path.clone()),
                    staging_root_identity: None,
                    staging_path: Some(staging_root_path.join(&name)),
                    staged_path_identity: None,
                    staged_metadata: None,
                    branch: "maco/agent-intent".to_string(),
                    base_oid: oid.to_string(),
                    branch_preexisting_oid: None,
                    branch_ownership: ManagedBranchOwnership::Unknown,
                    owned_branch_oid: None,
                    binding: None,
                    delete_branch: false,
                    force: true,
                    expected_branch_oid: None,
                    gc_dirtiness_checksum: None,
                    removal_safety: None,
                    worktree_quarantine_path: None,
                    worktree_quarantine_identity: None,
                    metadata_quarantine_path: None,
                    metadata_quarantine_identity: None,
                },
            );
            store.save(&lock, &mut registry).expect("save intent");
            root.reserve_direct_child_directory(&name)
                .expect("simulate final mkdir");
            if with_staging {
                root.reserve_direct_child_directory(staging_name)
                    .expect("simulate staging mkdir");
            }

            let error = recover_pending_operations(&repo, &store, &lock, &mut registry)
                .expect_err("identity-free directories require manual recovery");
            assert!(error.to_string().contains("manual recovery"));
            assert!(root.path().join(&name).exists());
            assert_eq!(staging_root_path.exists(), with_staging);
            assert!(registry.operations.contains_key(&name));
        }
    }

    #[test]
    fn unknown_branch_ownership_is_preserved_during_intent_recovery() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let oid = commit_readme(&repo).expect("initial commit");
        let root = SafeRoot::open_or_create_managed(&worktree_root).expect("root");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let lock = store.lock().expect("lock");
        let mut registry = store.load(&lock).expect("registry");
        let name = "agent-branch-race".to_string();
        let staging_root_path = root.path().join("stage-branch-race");
        registry.operations.insert(
            name.clone(),
            ManagedWorktreeOperation {
                kind: ManagedWorktreeOperationKind::Create,
                phase: ManagedWorktreeOperationPhase::CreateIntent,
                name: name.clone(),
                root: root.path().to_path_buf(),
                root_identity: root.identity().clone(),
                path: root.path().join(&name),
                prepared_path_identity: None,
                staging_root: Some(staging_root_path.clone()),
                staging_root_identity: None,
                staging_path: Some(staging_root_path.join(&name)),
                staged_path_identity: None,
                staged_metadata: None,
                branch: "maco/agent-branch-race".to_string(),
                base_oid: oid.to_string(),
                branch_preexisting_oid: None,
                branch_ownership: ManagedBranchOwnership::Unknown,
                owned_branch_oid: None,
                binding: None,
                delete_branch: false,
                force: false,
                expected_branch_oid: None,
                gc_dirtiness_checksum: None,
                removal_safety: None,
                worktree_quarantine_path: None,
                worktree_quarantine_identity: None,
                metadata_quarantine_path: None,
                metadata_quarantine_identity: None,
            },
        );
        store.save(&lock, &mut registry).expect("save intent");
        let commit = repo.find_commit(oid).expect("commit");
        repo.branch("maco/agent-branch-race", &commit, false)
            .expect("external branch creation");

        let error = recover_pending_operations(&repo, &store, &lock, &mut registry)
            .expect_err("unknown ownership must not be inferred");
        assert!(error.to_string().contains("unexpectedly created branch"));
        assert!(repo
            .find_branch("maco/agent-branch-race", BranchType::Local)
            .is_ok());
        assert!(registry.operations.contains_key(&name));
    }

    #[test]
    fn creation_lock_recovery_refuses_descendant_branch_movement() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-advanced".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");
        let worktree = repo.find_worktree("agent-advanced").expect("worktree");
        worktree
            .lock(Some("simulate incomplete handoff"))
            .expect("lock worktree");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let lock = store.lock().expect("registry lock");
        let mut registry = store.load(&lock).expect("registry");
        registry
            .records
            .get_mut("agent-advanced")
            .expect("binding")
            .creation_lock_pending = true;
        store
            .save(&lock, &mut registry)
            .expect("save pending handoff");

        let advanced =
            commit_descendant(&repo, "README.md", "# Advanced\n").expect("descendant commit");
        repo.find_branch("maco/agent-advanced", BranchType::Local)
            .expect("managed branch")
            .into_reference()
            .set_target(advanced, "simulate concurrent update-ref")
            .expect("advance managed branch");

        let error = recover_pending_operations(&repo, &store, &lock, &mut registry)
            .expect_err("branch advancement must block incomplete handoff");

        assert!(error
            .to_string()
            .contains("changed during worktree creation"));
        assert!(
            registry
                .records
                .get("agent-advanced")
                .expect("binding after refusal")
                .creation_lock_pending
        );
        assert!(matches!(
            repo.find_worktree("agent-advanced")
                .expect("worktree after refusal")
                .is_locked()
                .expect("lock status"),
            WorktreeLockStatus::Locked(_)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn registry_store_refuses_state_root_replacement_after_lock() {
        use std::os::unix::fs::PermissionsExt;
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let lock = store.lock().expect("lock");
        let old_root = store.state_root.path().with_file_name("state-old");
        fs::rename(store.state_root.path(), &old_root).expect("rename state root");
        fs::create_dir(store.state_root.path()).expect("replacement root");
        fs::set_permissions(store.state_root.path(), fs::Permissions::from_mode(0o700))
            .expect("replacement mode");

        let error = store
            .load(&lock)
            .expect_err("replaced state root must fail");
        assert!(error.to_string().contains("replaced"));
    }

    #[cfg(unix)]
    #[test]
    fn registry_lock_rebind_after_precheck_preserves_newer_record_and_live_temp() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-a".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root.clone()),
            })
            .expect("create initial worktree");

        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let stale_lock = store.lock().expect("stale lock");
        let mut stale_registry = store.load(&stale_lock).expect("stale registry");
        let mut newer_binding = stale_registry
            .records
            .get("agent-a")
            .cloned()
            .expect("initial binding");
        newer_binding.name = "agent-b".to_string();
        newer_binding.branch = "maco/agent-b".to_string();
        let lock_path = stale_lock.lock.path().to_path_buf();
        let moved_lock = lock_path.with_file_name("managed_worktrees.lock.stale-original");
        let live_temp = store
            .state_root
            .path()
            .join(".managed_worktrees.json.live-writer.tmp");
        set_managed_registry_after_precheck_hook({
            let live_temp = live_temp.clone();
            let repo_path = repo_path.clone();
            move || {
                fs::rename(&lock_path, &moved_lock).expect("move held registry lock");
                fs::write(&lock_path, b"").expect("create replacement registry lock");
                fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))
                    .expect("private replacement lock");
                let replacement_repo =
                    crate::git_repository::open(&repo_path).expect("replacement repo");
                let replacement_store = ManagedWorktreeRegistryStore::open(&replacement_repo)
                    .expect("replacement store");
                let replacement_lock = replacement_store.lock().expect("replacement lock");
                let mut newer_registry = replacement_store
                    .load(&replacement_lock)
                    .expect("replacement registry");
                newer_registry
                    .records
                    .insert("agent-b".to_string(), newer_binding);
                replacement_store
                    .save(&replacement_lock, &mut newer_registry)
                    .expect("commit newer replacement-domain record");
                fs::write(&live_temp, b"live writer staging").expect("create live temp");
                fs::set_permissions(&live_temp, fs::Permissions::from_mode(0o600))
                    .expect("private live temp");
            }
        });

        let error = store
            .save(&stale_lock, &mut stale_registry)
            .expect_err("stale lock-domain save must fail before temp scavenging");
        assert!(
            error
                .to_string()
                .contains("does not name its opened descriptor")
                || error.to_string().contains("was rebound"),
            "unexpected stale-save error: {error:#}"
        );
        assert!(
            live_temp.exists(),
            "stale writer deleted a live-domain temp"
        );
        drop(stale_lock);

        let fresh_lock = store.lock().expect("fresh lock");
        let current = store.load(&fresh_lock).expect("newer registry");
        assert!(current.records.contains_key("agent-a"));
        assert!(current.records.contains_key("agent-b"));
        assert_eq!(
            current.checksum,
            managed_registry_checksum(&current).expect("current checksum")
        );
        assert!(
            live_temp.exists(),
            "read path unexpectedly scavenged live temp"
        );
    }

    #[test]
    fn registry_store_enforces_record_operation_and_serialized_size_limits() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        WorktreeManager::new(&repo_path)
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-limits".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let lock = store.lock().expect("registry lock");
        let loaded = store.load(&lock).expect("registry");
        let binding = loaded
            .records
            .get("agent-limits")
            .cloned()
            .expect("binding");

        let mut too_many_records = store.empty_registry();
        for index in 0..=MAX_MANAGED_RECORDS {
            too_many_records
                .records
                .insert(format!("record-{index}"), binding.clone());
        }
        let error = store
            .save(&lock, &mut too_many_records)
            .expect_err("record count limit");
        assert!(error.to_string().contains("records"));

        let template_operation = ManagedWorktreeOperation {
            kind: ManagedWorktreeOperationKind::Create,
            phase: ManagedWorktreeOperationPhase::CreateIntent,
            name: "template".to_string(),
            root: binding.root.clone(),
            root_identity: binding.root_identity.clone(),
            path: binding.path.clone(),
            prepared_path_identity: None,
            staging_root: None,
            staging_root_identity: None,
            staging_path: None,
            staged_path_identity: None,
            staged_metadata: None,
            branch: "maco/template".to_string(),
            base_oid: binding.base_oid.clone(),
            branch_preexisting_oid: None,
            branch_ownership: ManagedBranchOwnership::Unknown,
            owned_branch_oid: None,
            binding: None,
            delete_branch: false,
            force: false,
            expected_branch_oid: None,
            gc_dirtiness_checksum: None,
            removal_safety: None,
            worktree_quarantine_path: None,
            worktree_quarantine_identity: None,
            metadata_quarantine_path: None,
            metadata_quarantine_identity: None,
        };
        let mut too_many_operations = store.empty_registry();
        for index in 0..=MAX_MANAGED_OPERATIONS {
            too_many_operations
                .operations
                .insert(format!("operation-{index}"), template_operation.clone());
        }
        let error = store
            .save(&lock, &mut too_many_operations)
            .expect_err("operation count limit");
        assert!(error.to_string().contains("operations"));

        let mut oversized = store.empty_registry();
        let large_path = PathBuf::from(format!("/{}", "x/".repeat(7_000).trim_end_matches('/')));
        for index in 0..400 {
            let mut oversized_binding = binding.clone();
            oversized_binding.name = format!("oversized-{index}");
            oversized_binding.root = large_path.clone();
            oversized
                .records
                .insert(oversized_binding.name.clone(), oversized_binding);
        }
        let error = store
            .save(&lock, &mut oversized)
            .expect_err("serialized size limit");
        assert!(error.to_string().contains("serialized size"));

        AtomicStateWriter::write_direct(
            &store.state_root,
            "managed_worktrees.json",
            &vec![b' '; MAX_MANAGED_REGISTRY_BYTES as usize + 1],
        )
        .expect("write oversized registry fixture");
        store.load(&lock).expect_err("load size limit");
    }

    #[test]
    fn recovers_remove_after_worktree_quarantine_rename_before_phase_save() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-remove-crash".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let lock = store.lock().expect("lock");
        let mut registry = store.load(&lock).expect("registry");
        let binding = registry
            .records
            .get("agent-remove-crash")
            .cloned()
            .expect("binding");
        let verified = verify_managed_worktree_binding(&repo, &store.repository, &binding, true)
            .expect("verify");
        let worktree_quarantine_path = deterministic_remove_quarantine_path(
            &binding.root,
            "worktree",
            &binding.name,
            &binding.path_identity,
        );
        let metadata_quarantine_path = deterministic_remove_quarantine_path(
            &store.repository.common_dir.join("worktrees"),
            "metadata",
            &binding.name,
            &binding.metadata_dir_identity,
        );
        registry.operations.insert(
            binding.name.clone(),
            ManagedWorktreeOperation {
                kind: ManagedWorktreeOperationKind::Remove,
                phase: ManagedWorktreeOperationPhase::RemovePrepared,
                name: binding.name.clone(),
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
                delete_branch: true,
                force: true,
                expected_branch_oid: Some(verified.branch_oid.to_string()),
                gc_dirtiness_checksum: None,
                removal_safety: Some(ManagedRemovalSafety::Explicit),
                worktree_quarantine_path: Some(worktree_quarantine_path.clone()),
                worktree_quarantine_identity: None,
                metadata_quarantine_path: Some(metadata_quarantine_path),
                metadata_quarantine_identity: None,
            },
        );
        store
            .save(&lock, &mut registry)
            .expect("save remove prepare");
        ensure_removal_worktree_lock(&repo, &binding).expect("lock before quarantine");
        quarantine_bound_directory(
            &binding.root,
            &binding.path,
            &worktree_quarantine_path,
            &binding.path_identity,
        )
        .expect("simulate worktree quarantine rename before phase save");

        recover_pending_operations(&repo, &store, &lock, &mut registry).expect("recover remove");
        assert!(!created.path.exists());
        assert!(!binding.metadata_dir.exists());
        assert!(repo
            .find_branch("maco/agent-remove-crash", BranchType::Local)
            .is_err());
        assert!(registry.records.is_empty());
        assert!(registry.operations.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn remove_recovery_resumes_every_durable_quarantine_boundary() {
        let boundaries = [
            "worktree_persisted",
            "metadata_renamed",
            "metadata_persisted",
            "partial_worktree_cleanup",
            "worktree_deleted_persisted",
            "partial_metadata_cleanup",
            "metadata_deleted_persisted",
            "branch_deleted_before_persist",
        ];
        for boundary in boundaries {
            let temp = TempDir::new().expect("tempdir");
            let repo_path = temp.path().join("repo");
            let worktree_root = temp.path().join("worktrees");
            WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
            let repo = crate::git_repository::open(&repo_path).expect("open repo");
            commit_readme(&repo).expect("initial commit");
            let manager = WorktreeManager::new(&repo_path);
            manager
                .create_for_test(WorktreeCreateOptions {
                    agent_id: "agent-boundary".to_string(),
                    branch: None,
                    base: None,
                    worktree_root: Some(worktree_root),
                })
                .expect("create worktree");
            let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
            let lock = store.lock().expect("registry lock");
            let mut registry = store.load(&lock).expect("registry");
            let (binding, worktree_quarantine, metadata_quarantine, expected_oid) =
                prepare_remove_operation_for_test(&repo, &store, &lock, &mut registry);

            ensure_removal_worktree_lock(&repo, &binding).expect("removal lock");
            quarantine_bound_directory(
                &binding.root,
                &binding.path,
                &worktree_quarantine,
                &binding.path_identity,
            )
            .expect("quarantine worktree");
            {
                let operation = registry
                    .operations
                    .get_mut(&binding.name)
                    .expect("remove operation");
                operation.phase = ManagedWorktreeOperationPhase::WorktreeQuarantined;
                operation.worktree_quarantine_identity = Some(binding.path_identity.clone());
            }
            store
                .save(&lock, &mut registry)
                .expect("persist worktree quarantine");
            if boundary == "worktree_persisted" {
                recover_pending_operations(&repo, &store, &lock, &mut registry)
                    .expect("recover after worktree persist");
                assert_completed_remove(&repo, &registry, &binding);
                continue;
            }

            verify_metadata_binding_after_worktree_removal(&store.repository, &binding)
                .expect("metadata binding");
            quarantine_bound_directory(
                &store.repository.common_dir.join("worktrees"),
                &binding.metadata_dir,
                &metadata_quarantine,
                &binding.metadata_dir_identity,
            )
            .expect("quarantine metadata");
            if boundary == "metadata_renamed" {
                recover_pending_operations(&repo, &store, &lock, &mut registry)
                    .expect("recover metadata rename before phase save");
                assert_completed_remove(&repo, &registry, &binding);
                continue;
            }
            {
                let operation = registry
                    .operations
                    .get_mut(&binding.name)
                    .expect("remove operation");
                operation.phase = ManagedWorktreeOperationPhase::MetadataQuarantined;
                operation.metadata_quarantine_identity =
                    Some(binding.metadata_dir_identity.clone());
            }
            store
                .save(&lock, &mut registry)
                .expect("persist metadata quarantine");
            if boundary == "metadata_persisted" {
                recover_pending_operations(&repo, &store, &lock, &mut registry)
                    .expect("recover after metadata persist");
                assert_completed_remove(&repo, &registry, &binding);
                continue;
            }
            if boundary == "partial_worktree_cleanup" {
                fs::remove_file(worktree_quarantine.join("README.md"))
                    .expect("simulate partial worktree cleanup");
                recover_pending_operations(&repo, &store, &lock, &mut registry)
                    .expect("resume partial worktree cleanup");
                assert_completed_remove(&repo, &registry, &binding);
                continue;
            }

            remove_quarantined_bound_directory(
                &binding.root,
                &worktree_quarantine,
                &binding.path_identity,
            )
            .expect("delete worktree quarantine");
            {
                let operation = registry
                    .operations
                    .get_mut(&binding.name)
                    .expect("remove operation");
                operation.phase = ManagedWorktreeOperationPhase::WorktreeDeleted;
            }
            store
                .save(&lock, &mut registry)
                .expect("persist worktree deletion");
            if boundary == "worktree_deleted_persisted" {
                recover_pending_operations(&repo, &store, &lock, &mut registry)
                    .expect("recover after worktree deletion persist");
                assert_completed_remove(&repo, &registry, &binding);
                continue;
            }
            if boundary == "partial_metadata_cleanup" {
                let removable = fs::read_dir(&metadata_quarantine)
                    .expect("metadata quarantine entries")
                    .filter_map(std::result::Result::ok)
                    .find(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
                    .expect("metadata regular file");
                fs::remove_file(removable.path()).expect("simulate partial metadata cleanup");
                recover_pending_operations(&repo, &store, &lock, &mut registry)
                    .expect("resume partial metadata cleanup");
                assert_completed_remove(&repo, &registry, &binding);
                continue;
            }

            remove_quarantined_bound_directory(
                &store.repository.common_dir.join("worktrees"),
                &metadata_quarantine,
                &binding.metadata_dir_identity,
            )
            .expect("delete metadata quarantine");
            {
                let operation = registry
                    .operations
                    .get_mut(&binding.name)
                    .expect("remove operation");
                operation.phase = ManagedWorktreeOperationPhase::MetadataDeleted;
            }
            store
                .save(&lock, &mut registry)
                .expect("persist metadata deletion");
            if boundary == "metadata_deleted_persisted" {
                recover_pending_operations(&repo, &store, &lock, &mut registry)
                    .expect("recover after metadata deletion persist");
                assert_completed_remove(&repo, &registry, &binding);
                continue;
            }

            compare_and_delete_local_branch(
                &repo,
                &binding.branch,
                expected_oid,
                true,
                "test crash before branch phase persist",
            )
            .expect("delete branch before phase persist");
            recover_pending_operations(&repo, &store, &lock, &mut registry)
                .expect("recover branch deletion before phase save");
            assert_completed_remove(&repo, &registry, &binding);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn remove_prepared_refuses_both_absent_and_both_present_states() {
        for both_present in [false, true] {
            let temp = TempDir::new().expect("tempdir");
            let repo_path = temp.path().join("repo");
            let worktree_root = temp.path().join("worktrees");
            WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
            let repo = crate::git_repository::open(&repo_path).expect("open repo");
            commit_readme(&repo).expect("initial commit");
            let manager = WorktreeManager::new(&repo_path);
            manager
                .create_for_test(WorktreeCreateOptions {
                    agent_id: "agent-ambiguous".to_string(),
                    branch: None,
                    base: None,
                    worktree_root: Some(worktree_root),
                })
                .expect("create worktree");
            let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
            let lock = store.lock().expect("registry lock");
            let mut registry = store.load(&lock).expect("registry");
            let (binding, worktree_quarantine, _, _) =
                prepare_remove_operation_for_test(&repo, &store, &lock, &mut registry);
            if both_present {
                fs::create_dir(&worktree_quarantine).expect("ambiguous quarantine");
            } else {
                fs::remove_dir_all(&binding.path).expect("simulate missing source");
            }

            let error = recover_pending_operations(&repo, &store, &lock, &mut registry)
                .expect_err("ambiguous remove state must fail closed");
            assert!(error.to_string().contains("exactly one"));
            assert!(registry.operations.contains_key(&binding.name));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn worktree_quarantined_refuses_ambiguous_metadata_states() {
        for both_present in [false, true] {
            let temp = TempDir::new().expect("tempdir");
            let repo_path = temp.path().join("repo");
            let worktree_root = temp.path().join("worktrees");
            WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
            let repo = crate::git_repository::open(&repo_path).expect("open repo");
            commit_readme(&repo).expect("initial commit");
            WorktreeManager::new(&repo_path)
                .create_for_test(WorktreeCreateOptions {
                    agent_id: "agent-metadata-state".to_string(),
                    branch: None,
                    base: None,
                    worktree_root: Some(worktree_root),
                })
                .expect("create worktree");
            let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
            let lock = store.lock().expect("registry lock");
            let mut registry = store.load(&lock).expect("registry");
            let (binding, worktree_quarantine, metadata_quarantine, _) =
                prepare_remove_operation_for_test(&repo, &store, &lock, &mut registry);
            ensure_removal_worktree_lock(&repo, &binding).expect("removal lock");
            quarantine_bound_directory(
                &binding.root,
                &binding.path,
                &worktree_quarantine,
                &binding.path_identity,
            )
            .expect("worktree quarantine");
            {
                let operation = registry
                    .operations
                    .get_mut(&binding.name)
                    .expect("operation");
                operation.phase = ManagedWorktreeOperationPhase::WorktreeQuarantined;
                operation.worktree_quarantine_identity = Some(binding.path_identity.clone());
            }
            store
                .save(&lock, &mut registry)
                .expect("persist worktree phase");
            if both_present {
                fs::create_dir(&metadata_quarantine).expect("ambiguous metadata quarantine");
            } else {
                fs::remove_dir_all(&binding.metadata_dir).expect("simulate missing metadata");
            }

            let error = recover_pending_operations(&repo, &store, &lock, &mut registry)
                .expect_err("ambiguous metadata state must fail closed");
            assert!(error.to_string().contains("exactly one"));
            assert!(registry.operations.contains_key(&binding.name));
        }
    }

    #[cfg(target_os = "linux")]
    fn assert_status_root_contains_only_lock(root: &SafeRoot) {
        let mut names = fs::read_dir(root.path())
            .expect("read status root")
            .map(|entry| entry.expect("status entry").file_name())
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(names, vec![OsString::from(WORKTREE_STATUS_RUNTIME_LOCK)]);
    }

    fn prepare_remove_operation_for_test(
        repo: &Repository,
        store: &ManagedWorktreeRegistryStore,
        lock: &ManagedWorktreeRegistryLock,
        registry: &mut ManagedWorktreeRegistry,
    ) -> (ManagedWorktreeBinding, PathBuf, PathBuf, Oid) {
        let binding = registry
            .records
            .values()
            .next()
            .cloned()
            .expect("managed binding");
        let verified = verify_managed_worktree_binding(repo, &store.repository, &binding, true)
            .expect("verify binding");
        let worktree_quarantine = deterministic_remove_quarantine_path(
            &binding.root,
            "worktree",
            &binding.name,
            &binding.path_identity,
        );
        let metadata_quarantine = deterministic_remove_quarantine_path(
            &store.repository.common_dir.join("worktrees"),
            "metadata",
            &binding.name,
            &binding.metadata_dir_identity,
        );
        registry.operations.insert(
            binding.name.clone(),
            ManagedWorktreeOperation {
                kind: ManagedWorktreeOperationKind::Remove,
                phase: ManagedWorktreeOperationPhase::RemovePrepared,
                name: binding.name.clone(),
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
                delete_branch: true,
                force: true,
                expected_branch_oid: Some(verified.branch_oid.to_string()),
                gc_dirtiness_checksum: None,
                removal_safety: Some(ManagedRemovalSafety::Explicit),
                worktree_quarantine_path: Some(worktree_quarantine.clone()),
                worktree_quarantine_identity: None,
                metadata_quarantine_path: Some(metadata_quarantine.clone()),
                metadata_quarantine_identity: None,
            },
        );
        store.save(lock, registry).expect("persist remove prepare");
        (
            binding,
            worktree_quarantine,
            metadata_quarantine,
            verified.branch_oid,
        )
    }

    fn assert_completed_remove(
        repo: &Repository,
        registry: &ManagedWorktreeRegistry,
        binding: &ManagedWorktreeBinding,
    ) {
        assert!(!binding.path.exists());
        assert!(!binding.metadata_dir.exists());
        assert!(repo
            .find_branch(&binding.branch, BranchType::Local)
            .is_err());
        assert!(!registry.records.contains_key(&binding.name));
        assert!(!registry.operations.contains_key(&binding.name));
    }

    fn create_gc_worktree(
        manager: &WorktreeManager,
        agent_id: &str,
        worktree_root: &Path,
    ) -> WorktreeRecord {
        manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: agent_id.to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root.to_path_buf()),
            })
            .expect("create GC worktree")
    }

    fn gc_options(worktree_root: Option<PathBuf>, dry_run: bool) -> WorktreeGcOptions {
        WorktreeGcOptions {
            worktree_root,
            dry_run,
            remove_targets: true,
            targets_only: false,
            retention: WorktreeRetentionPolicy::default(),
            allowed_untracked_paths: Vec::new(),
            exclude_agent_id: None,
            candidate_agent_ids: None,
            merged_into_reference: None,
            superseded_by_agent_id: BTreeMap::new(),
            machine_global_retention: None,
        }
    }

    fn gc_targets_only_options(worktree_root: Option<PathBuf>, dry_run: bool) -> WorktreeGcOptions {
        let mut options = gc_options(worktree_root, dry_run);
        options.targets_only = true;
        options
    }

    fn test_live_target_liveness() -> WorktreeTargetLiveness {
        WorktreeTargetLiveness::Live(target_liveness_evidence(
            Some(42),
            WorktreeTargetLivenessSource::CargoTargetDir,
            WorktreeTargetLivenessCause::PathOverlap,
        ))
    }

    fn test_unknown_target_liveness() -> WorktreeTargetLiveness {
        WorktreeTargetLiveness::Unknown(target_liveness_evidence(
            Some(43),
            WorktreeTargetLivenessSource::MountNamespace,
            WorktreeTargetLivenessCause::NamespaceUnresolved,
        ))
    }

    fn workspace_sweep_options(workspace: &Path, apply: bool) -> WorktreeSweepOptions {
        WorktreeSweepOptions {
            workspace: workspace.to_path_buf(),
            apply,
            remove_targets: true,
            targets_only: false,
            retention: WorktreeRetentionPolicy::default(),
            allowed_untracked_paths: Vec::new(),
        }
    }

    #[cfg(target_os = "linux")]
    fn machine_global_gc_binding(
        test_root: &Path,
        worktree_root: &Path,
        correlation: &str,
    ) -> MachineGlobalRetentionBinding {
        use std::os::unix::fs::PermissionsExt;

        let state_root = test_root.join(format!("machine-global-state-{correlation}"));
        fs::create_dir(&state_root).expect("machine-global state root");
        fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700))
            .expect("private machine-global state root");
        let config = test_root.join(format!("machine-global-{correlation}.json"));
        fs::write(
            &config,
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": 1,
                "state_root": state_root,
                "roots": [{
                    "id": "worktrees",
                    "path": worktree_root,
                    "protected_paths": [],
                    "quarantine_grace_seconds": 60
                }]
            }))
            .expect("serialize machine-global config"),
        )
        .expect("write machine-global config");
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600))
            .expect("private machine-global config");
        MachineGlobalRetentionBinding {
            config,
            root_id: "worktrees".to_string(),
            owner: "maco-worktree-gc".to_string(),
            correction_correlation_id: correlation.to_string(),
        }
    }

    #[test]
    fn lifecycle_defaults_are_inert_and_o2_defaults_are_bounded_and_conservative() {
        let missing = WorktreeManager::new("/definitely/missing/lifecycle-default-off");
        let report = missing
            .lifecycle(WorktreeLifecycleOptions::default())
            .expect("disabled lifecycle must not inspect repository state");
        assert!(!report.enabled);
        assert!(report.worktree_gc.is_none());
        assert!(report.artifact_prune.is_none());
        assert_eq!(report.actual_reclaimed_bytes, 0);

        let defaults = WorktreeLifecycleOptions::o2_launch_defaults();
        assert!(!defaults.auto_reap_merged);
        assert!(!defaults.apply);
        assert!(!defaults.remove_targets);
        assert_eq!(
            defaults.worktree_retention,
            WorktreeRetentionPolicy::default()
        );
        assert_eq!(O2_LAUNCH_WORKTREE_MAX_COUNT, 10);
        let policy = defaults.artifact_retention.expect("O2 artifact policy");
        assert_eq!(policy.max_count, O2_LAUNCH_ARTIFACT_KEEP_COUNT);
        assert_eq!(policy.unfinalized_grace, Some(O2_LAUNCH_UNFINALIZED_GRACE));
        assert!(!policy.reclaim_unverifiable);
        assert!(!policy.external_writers_stopped);
    }

    #[test]
    fn retry_suffix_parser_accepts_only_canonical_generations() {
        assert_eq!(parse_retry_predecessor("foo-r2"), Ok(Some("foo".into())));
        assert_eq!(parse_retry_predecessor("foo-r3"), Ok(Some("foo-r2".into())));
        assert_eq!(
            parse_retry_predecessor("foo-round2"),
            Ok(Some("foo".into()))
        );
        assert_eq!(parse_retry_predecessor("foo"), Ok(None));
        for malformed in ["foo-r0", "foo-r1", "foo-r02", "foo-rx", "foo-round3"] {
            assert!(parse_retry_predecessor(malformed).is_err(), "{malformed}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn lifecycle_requires_explicit_trunk_containment_without_changing_manual_gc() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let lane = create_gc_worktree(&manager, "merge-lane", &root);
        let lane_repo = crate::git_repository::open(&lane.path).expect("open lane");
        let lane_oid =
            commit_descendant(&lane_repo, "lane.txt", "unmerged\n").expect("lane descendant");

        let manual = manager
            .gc_with_target_liveness(gc_options(Some(root.clone()), true), |_| {
                WorktreeTargetLiveness::Clear
            })
            .expect("manual preview");
        assert_eq!(
            manual.removed_count, 1,
            "manual GC behavior changed: {manual:#?}"
        );

        let mut lifecycle_options = gc_options(Some(root.clone()), true);
        lifecycle_options.merged_into_reference = Some("refs/heads/main".to_string());
        let retained = manager
            .gc_with_target_liveness(lifecycle_options, |_| WorktreeTargetLiveness::Clear)
            .expect("unmerged lifecycle preview");
        assert_eq!(retained.removed_count, 0, "{retained:#?}");
        assert_eq!(retained.entries[0].status, WorktreeGcStatus::Retained);
        assert_eq!(retained.entries[0].reason, WorktreeGcReason::UnmergedBranch);
        assert!(lane.path.exists());

        repo.reference("refs/heads/main", lane_oid, true, "test fast-forward")
            .expect("advance primary HEAD");
        let mut lifecycle_options = gc_options(Some(root.clone()), true);
        lifecycle_options.merged_into_reference = Some("refs/heads/main".to_string());
        let preview = manager
            .gc_with_target_liveness(lifecycle_options, |_| WorktreeTargetLiveness::Clear)
            .expect("merged preview");
        assert_eq!(preview.removed_count, 1, "{preview:#?}");
        assert_eq!(preview.entries[0].status, WorktreeGcStatus::WouldRemove);
        assert_eq!(preview.entries[0].reason, WorktreeGcReason::FinishedBranch);
        assert!(lane.path.exists(), "dry-run must preserve the lane");

        let mut lifecycle_options = gc_options(Some(root), false);
        lifecycle_options.merged_into_reference = Some("refs/heads/main".to_string());
        let applied = manager
            .gc_with_target_liveness(lifecycle_options, |_| WorktreeTargetLiveness::Clear)
            .expect("merged apply");
        assert_eq!(applied.removed_count, 1, "{applied:#?}");
        assert_eq!(applied.entries[0].status, WorktreeGcStatus::Removed);
        assert!(!lane.path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn lifecycle_retry_supersedes_exact_authenticated_predecessor_despite_retention() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let predecessor = create_gc_worktree(&manager, "retry-task", &root);
        let successor = create_gc_worktree(&manager, "retry-task-r2", &root);
        let predecessor_repo =
            crate::git_repository::open(&predecessor.path).expect("predecessor repo");
        commit_descendant(&predecessor_repo, "attempt.txt", "unmerged attempt\n")
            .expect("unmerged predecessor commit");

        let mut options = WorktreeLifecycleOptions {
            retry_successor_agent_id: Some(successor.name.clone()),
            worktree_root: Some(root.clone()),
            worktree_retention: WorktreeRetentionPolicy {
                max_count: Some(10),
                ..WorktreeRetentionPolicy::default()
            },
            ..WorktreeLifecycleOptions::default()
        };
        let preview = manager.lifecycle(options.clone()).expect("retry preview");
        assert_eq!(preview.retry.status, RetrySupersessionStatus::Selected);
        let gc = preview.worktree_gc.as_ref().expect("retry GC");
        assert_eq!(gc.considered_count, 1, "{gc:#?}");
        assert_eq!(gc.removed_count, 1, "{gc:#?}");
        assert_eq!(gc.entries[0].reason, WorktreeGcReason::SupersededLane);
        assert!(predecessor.path.exists());
        assert!(successor.path.exists());

        options.apply = true;
        let applied = manager.lifecycle(options).expect("retry apply");
        assert_eq!(applied.worktree_gc.expect("GC").removed_count, 1);
        assert!(!predecessor.path.exists());
        assert!(successor.path.exists());
        assert!(repo
            .find_branch("maco/retry-task-r2", BranchType::Local)
            .is_ok());
    }

    #[test]
    fn retry_supersession_requires_exact_authenticated_successor_and_root() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        create_gc_worktree(&manager, "isolated", &temp.path().join("root-a"));

        let missing = resolve_retry_supersession(&repo, "isolated-r2").expect("classification");
        assert_eq!(missing.status, RetrySupersessionStatus::Ambiguous);
        assert!(missing
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("successor")));

        create_gc_worktree(&manager, "isolated-r2", &temp.path().join("root-b"));
        let different_root =
            resolve_retry_supersession(&repo, "isolated-r2").expect("classification");
        assert_eq!(
            different_root.status,
            RetrySupersessionStatus::PredecessorNotFound
        );
    }

    #[test]
    fn retry_supersession_refuses_a_crash_orphaned_successor_binding() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let predecessor = create_gc_worktree(&manager, "stale-retry", &root);
        let successor = create_gc_worktree(&manager, "stale-retry-r2", &root);
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let lock = store.lock().expect("lock");
        let registry = store.load(&lock).expect("registry");
        let successor_binding = registry
            .records
            .get(&successor.name)
            .cloned()
            .expect("successor binding");
        drop(lock);
        fs::remove_dir_all(&successor_binding.path).expect("remove successor path");
        fs::remove_dir_all(&successor_binding.metadata_dir).expect("remove successor metadata");

        let classification =
            resolve_retry_supersession(&repo, &successor.name).expect("classification");
        assert_eq!(classification.status, RetrySupersessionStatus::Ambiguous);
        assert!(classification
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("not live and verified")));
        let report = manager
            .lifecycle(WorktreeLifecycleOptions {
                apply: true,
                retry_successor_agent_id: Some(successor.name),
                worktree_root: Some(root),
                ..WorktreeLifecycleOptions::default()
            })
            .expect("fail-closed retry lifecycle report");
        assert!(report.worktree_gc.is_none());
        assert!(predecessor.path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn lifecycle_dry_run_aggregates_worktree_and_explicit_o2_artifact_policy() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let lane = create_gc_worktree(&manager, "aggregate-lane", &root);
        let run = repo_path.join(".maco/o2-autopilot/runs/run-a");
        fs::create_dir_all(&run).expect("O2 run");
        fs::set_permissions(
            repo_path.join(".maco/o2-autopilot/runs"),
            fs::Permissions::from_mode(0o700),
        )
        .expect("private O2 root");
        fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).expect("private O2 run");
        fs::write(run.join("events.jsonl"), b"events\n").expect("O2 artifact");
        let mut policy = ArtifactRetentionPolicy {
            max_count: 0,
            max_age: None,
            max_total_bytes: None,
            unfinalized_grace: Some(Duration::ZERO),
            reclaim_unverifiable: false,
            external_writers_stopped: false,
        };
        let mut options = WorktreeLifecycleOptions {
            auto_reap_merged: true,
            candidate_agent_ids: Some(BTreeSet::from([lane.name.clone()])),
            merged_into_reference: Some("refs/heads/main".to_string()),
            worktree_root: Some(root),
            artifact_retention: Some(policy.clone()),
            ..WorktreeLifecycleOptions::default()
        };
        let refused = manager.lifecycle(options.clone()).expect("refused preview");
        assert_eq!(refused.worktree_gc.as_ref().expect("GC").removed_count, 1);
        let refused_artifact = refused.artifact_prune.as_ref().expect("artifact report");
        assert_eq!(refused_artifact.refused_unfinalized_count, 1);
        assert_eq!(refused_artifact.would_reclaim_bytes, 0);
        assert!(lane.path.exists());
        assert!(run.exists());

        policy.external_writers_stopped = true;
        options.artifact_retention = Some(policy);
        let aggregate = manager.lifecycle(options).expect("explicit preview");
        let gc = aggregate.worktree_gc.as_ref().expect("GC");
        let artifacts = aggregate.artifact_prune.as_ref().expect("artifacts");
        assert_eq!(
            aggregate.apparent_checked_bytes,
            gc.apparent_considered_bytes + artifacts.scanned_bytes
        );
        assert_eq!(
            aggregate.projected_reclaimable_bytes,
            gc.estimated_reclaimable_bytes + artifacts.would_reclaim_bytes
        );
        assert_eq!(aggregate.actual_reclaimed_bytes, 0);
        assert!(aggregate.projected_reclaimable_bytes > gc.estimated_reclaimable_bytes);
        let output = serde_json::to_string_pretty(&aggregate).expect("serialize lifecycle report");
        println!("LIFECYCLE_DRY_RUN_REPORT={output}");
        assert!(lane.path.exists());
        assert!(run.exists());
    }

    #[test]
    fn startup_reconciliation_is_report_only_then_forgets_exact_missing_both_record() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let lane = create_gc_worktree(&manager, "crash-orphan", &root);
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let lock = store.lock().expect("lock");
        let registry = store.load(&lock).expect("registry");
        let binding = registry.records.get(&lane.name).cloned().expect("binding");
        drop(lock);
        fs::remove_dir_all(&binding.path).expect("simulate missing worktree path");
        fs::remove_dir_all(&binding.metadata_dir).expect("simulate missing Git metadata");

        let mut options = WorktreeLifecycleOptions {
            startup_reconcile: true,
            ..WorktreeLifecycleOptions::default()
        };
        let preview = manager
            .lifecycle(options.clone())
            .expect("reconciliation preview");
        assert_eq!(preview.reconciliation.forgotten_record_count, 0);
        assert_eq!(
            preview.reconciliation.entries[0].state,
            WorktreeReconciliationState::AuthenticatedMissingBoth
        );
        assert_eq!(
            preview.reconciliation.entries[0].action,
            WorktreeReconciliationAction::ReportOnly
        );
        assert!(ManagedWorktreeRegistryStore::open(&repo)
            .expect("store")
            .load(
                &ManagedWorktreeRegistryStore::open(&repo)
                    .expect("store")
                    .lock()
                    .expect("lock")
            )
            .expect("registry")
            .records
            .contains_key(&lane.name));

        options.apply = true;
        options.destructive_reconciliation = true;
        let applied = manager.lifecycle(options).expect("reconciliation apply");
        assert_eq!(applied.reconciliation.forgotten_record_count, 1);
        assert_eq!(
            applied.reconciliation.entries[0].action,
            WorktreeReconciliationAction::ForgotAuthenticatedRecord
        );
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let lock = store.lock().expect("lock");
        assert!(!store
            .load(&lock)
            .expect("registry")
            .records
            .contains_key(&lane.name));
        assert!(repo.find_branch(&lane.branch, BranchType::Local).is_ok());
    }

    #[test]
    fn startup_reconciliation_active_claim_protects_missing_both_record() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let lane = create_gc_worktree(&manager, "claimed-crash-orphan", &root);
        SyncStore::open(&repo_path)
            .expect("claims")
            .claim_paths(&lane.name, ["src"])
            .expect("claim lane");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let lock = store.lock().expect("lock");
        let binding = store
            .load(&lock)
            .expect("registry")
            .records
            .get(&lane.name)
            .cloned()
            .expect("binding");
        drop(lock);
        fs::remove_dir_all(&binding.path).expect("remove path");
        fs::remove_dir_all(&binding.metadata_dir).expect("remove metadata");

        let report = manager
            .lifecycle(WorktreeLifecycleOptions {
                apply: true,
                startup_reconcile: true,
                destructive_reconciliation: true,
                worktree_root: Some(root),
                ..WorktreeLifecycleOptions::default()
            })
            .expect("claimed reconciliation report");
        let entry = report
            .reconciliation
            .entries
            .iter()
            .find(|entry| entry.name == lane.name)
            .expect("claimed entry");
        assert_eq!(entry.action, WorktreeReconciliationAction::Protected);
        assert!(entry.detail.contains("active durable claim"));
        let lock = store.lock().expect("lock");
        assert!(store
            .load(&lock)
            .expect("registry")
            .records
            .contains_key(&lane.name));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn startup_reconciliation_quarantines_unregistered_on_disk_lane_with_explicit_binding() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let orphan = root.join("deregistered-lane");
        fs::create_dir_all(orphan.join("target/debug")).expect("orphan tree");
        fs::write(orphan.join("sentinel"), b"crash residue").expect("orphan sentinel");
        let binding = machine_global_gc_binding(temp.path(), &root, "startup-orphan");
        let manager = WorktreeManager::new(&repo_path);

        let preview = manager
            .lifecycle(WorktreeLifecycleOptions {
                startup_reconcile: true,
                worktree_root: Some(root.clone()),
                ..WorktreeLifecycleOptions::default()
            })
            .expect("startup preview");
        let preview_entry = preview
            .reconciliation
            .entries
            .iter()
            .find(|entry| entry.name == "deregistered-lane")
            .expect("orphan preview");
        assert_eq!(
            preview_entry.state,
            WorktreeReconciliationState::PresentDeregistered
        );
        assert_eq!(
            preview_entry.action,
            WorktreeReconciliationAction::ReportOnly
        );
        assert!(orphan.exists());

        let applied = manager
            .lifecycle(WorktreeLifecycleOptions {
                apply: true,
                startup_reconcile: true,
                destructive_reconciliation: true,
                worktree_root: Some(root),
                machine_global_retention: Some(binding),
                ..WorktreeLifecycleOptions::default()
            })
            .expect("startup quarantine");
        assert_eq!(applied.reconciliation.quarantined_directory_count, 1);
        assert_eq!(
            applied.reconciliation.entries[0].action,
            WorktreeReconciliationAction::QuarantinedDirectory
        );
        assert!(!orphan.exists());
    }

    #[test]
    fn startup_reconciliation_prunes_only_exact_authenticated_missing_path_registration() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let lane = create_gc_worktree(&manager, "registered-missing", &root);
        fs::remove_dir_all(&lane.path).expect("remove registered path");

        let report = manager
            .lifecycle(WorktreeLifecycleOptions {
                apply: true,
                startup_reconcile: true,
                destructive_reconciliation: true,
                worktree_root: Some(root),
                ..WorktreeLifecycleOptions::default()
            })
            .expect("exact stale registration reconciliation");
        assert_eq!(report.reconciliation.pruned_registration_count, 1);
        assert_eq!(report.reconciliation.forgotten_record_count, 1);
        assert_eq!(
            report.reconciliation.entries[0].action,
            WorktreeReconciliationAction::PrunedRegistrationAndForgotRecord
        );
        assert!(repo.find_worktree(&lane.name).is_err());
        assert!(repo.find_branch(&lane.branch, BranchType::Local).is_ok());
    }

    #[test]
    fn post_reap_prune_preserves_unrelated_stale_registration() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let selected = create_gc_worktree(&manager, "selected-stale", &root);
        let unrelated = create_gc_worktree(&manager, "unrelated-stale", &root);
        fs::remove_dir_all(&selected.path).expect("remove selected path");
        fs::remove_dir_all(&unrelated.path).expect("remove unrelated path");

        let report = prune_stale_worktree_registrations(
            &repo,
            &BTreeSet::from([selected.name.clone()]),
            true,
        )
        .expect("scoped prune");
        assert_eq!(report.stale_registration_count, 2);
        assert_eq!(report.pruned_registration_count, 1);
        assert_eq!(report.protected_registration_count, 1);
        assert!(repo.find_worktree(&selected.name).is_err());
        assert!(repo.find_worktree(&unrelated.name).is_ok());
    }

    #[cfg(unix)]
    fn configure_test_git_identity(repo: &Repository) {
        let mut config = repo.config().expect("open test Git config");
        config
            .set_str("user.name", "MACO guard test")
            .expect("set test Git name");
        config
            .set_str("user.email", "maco-guard-test@example.invalid")
            .expect("set test Git email");
    }

    #[cfg(unix)]
    fn install_test_repository_hooks(repo: &Repository) {
        let hooks = repo.commondir().join("hooks");
        fs::create_dir_all(&hooks).expect("create fixture hooks directory");
        for (name, marker) in [
            ("pre-commit", "pre-commit-ran"),
            ("commit-msg", "commit-msg-ran"),
            ("pre-push", "pre-push-ran"),
        ] {
            let compatibility = if matches!(name, "commit-msg" | "pre-push") {
                "# human-authorship-guard dispatcher v3\n"
            } else {
                ""
            };
            let script = format!(
                "#!/bin/sh\n{compatibility}printf '%s\\n' '{name}' >> \"$(git rev-parse --git-common-dir)/{marker}\"\n"
            );
            let path = hooks.join(name);
            fs::write(&path, script).expect("write fixture hook");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("make fixture hook executable");
        }
    }

    #[cfg(unix)]
    fn read_test_hook_log(repo: &Repository, name: &str) -> String {
        match fs::read_to_string(repo.commondir().join(name)) {
            Ok(contents) => contents,
            Err(error) if error.kind() == ErrorKind::NotFound => String::new(),
            Err(error) => panic!("failed to read fixture hook log: {error}"),
        }
    }

    #[cfg(unix)]
    fn run_test_git(worktree: &Path, args: &[&str], environment: &[(&str, &str)]) -> Output {
        let mut command = Command::new("git");
        command.arg("-C").arg(worktree).args(args);
        for (name, value) in environment {
            command.env(name, value);
        }
        command.output().expect("run fixture Git command")
    }

    #[cfg(unix)]
    fn run_test_hook(worktree: &Path, hook: &Path, environment: &[(&str, &str)]) -> Output {
        let mut command = Command::new(hook);
        command.current_dir(worktree).args(["origin", "unused"]);
        for (name, value) in environment {
            command.env(name, value);
        }
        command.output().expect("run fixture Git hook")
    }

    #[cfg(unix)]
    fn assert_test_git_success(worktree: &Path, args: &[&str]) {
        let output = run_test_git(worktree, args, &[]);
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn commit_readme(repo: &Repository) -> Result<Oid> {
        let workdir = repo.workdir().context("test repo must have workdir")?;
        fs::write(workdir.join("README.md"), "# Test\n").context("write README")?;

        let mut index = repo.index().context("open index")?;
        index
            .add_path(Path::new("README.md"))
            .context("add README")?;
        index.write().context("write index")?;
        let tree_id = index.write_tree().context("write tree")?;
        let tree = repo.find_tree(tree_id).context("find tree")?;
        let signature =
            Signature::now("maco test", "maco-test@example.invalid").context("signature")?;
        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            "initial commit",
            &tree,
            &[],
        )
        .context("commit")
    }

    fn commit_descendant(repo: &Repository, path: &str, contents: &str) -> Result<Oid> {
        let workdir = repo.workdir().context("test repo must have workdir")?;
        fs::write(workdir.join(path), contents).context("write descendant contents")?;
        let mut index = repo.index().context("open index")?;
        index.add_path(Path::new(path)).context("add path")?;
        index.write().context("write index")?;
        let tree_id = index.write_tree().context("write tree")?;
        let tree = repo.find_tree(tree_id).context("find tree")?;
        let parent = repo
            .head()
            .context("find parent HEAD")?
            .peel_to_commit()
            .context("peel parent commit")?;
        let signature =
            Signature::now("maco test", "maco-test@example.invalid").context("signature")?;
        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            "descendant commit",
            &tree,
            &[&parent],
        )
        .context("commit descendant")
    }
}
