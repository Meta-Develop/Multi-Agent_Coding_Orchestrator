#[cfg(test)]
use crate::safe_state::scavenge_private_random_directories;
use crate::{
    artifacts::{
        repository_authenticator_key_only,
        state_auth::{random_identifier, AuthenticationDomain, RepositoryAuthBinding},
    },
    authenticated_snapshot::{AuthenticatedSnapshot, AuthenticatedSnapshotStore, SnapshotSpec},
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
        finalize_legacy_retirement, prepare_legacy_retirement, LegacyAdoption,
        LEGACY_RETIREMENT_DOMAIN,
    },
    sync_store::{LockedClaimsSnapshot, SyncStore},
};
use anyhow::{bail, Context, Result};
use git2::{
    Branch, BranchType, ErrorCode, ObjectType, Oid, Repository, RepositoryInitOptions, Transaction,
    WorktreeAddOptions, WorktreeLockStatus,
};
use serde::{Deserialize, Serialize};
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

const DEFAULT_BRANCH_PREFIX: &str = "maco";
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

static BOUNDED_STATUS_PROCESS_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> =
    std::sync::OnceLock::new();

/// Configures the one Git repository extension whose on-disk semantics MACO
/// explicitly supports in addition to libgit2's built-in extension set.
///
/// # Safety
///
/// This must run exactly once during process bootstrap, before any libgit2
/// operation can run concurrently. `git2::opts::set_extensions` mutates
/// libgit2 process-global state and provides no internal synchronization.
#[doc(hidden)]
pub unsafe fn configure_libgit2_repository_extensions() -> Result<(), git2::Error> {
    // SAFETY: The caller upholds the pre-thread, pre-libgit2 bootstrap
    // requirement documented above. The exact suffix keeps extension checking
    // enabled and opts in only to relative worktree metadata.
    unsafe { git2::opts::set_extensions(&["relativeworktrees"]) }
}

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
}

#[derive(Debug, Clone)]
pub struct WorktreeGcOptions {
    pub worktree_root: Option<PathBuf>,
    pub dry_run: bool,
    pub remove_targets: bool,
    pub retention: WorktreeRetentionPolicy,
    pub exclude_agent_id: Option<String>,
    pub machine_global_retention: Option<MachineGlobalRetentionBinding>,
}

#[derive(Debug, Clone)]
pub struct WorktreeSweepOptions {
    pub workspace: PathBuf,
    pub apply: bool,
    pub remove_targets: bool,
    pub retention: WorktreeRetentionPolicy,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WorktreeSweepReport {
    pub workspace: PathBuf,
    pub apply: bool,
    pub dry_run: bool,
    pub remove_targets: bool,
    pub max_age_seconds: Option<u64>,
    pub max_count: Option<usize>,
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
    pub repositories: Vec<WorktreeSweepRepositoryReport>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WorktreeSweepRepositoryReport {
    pub group: String,
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
    pub max_age_seconds: Option<u64>,
    pub max_count: Option<usize>,
    pub considered_count: usize,
    pub removed_count: usize,
    pub protected_count: usize,
    pub retained_count: usize,
    pub target_removed_count: usize,
    pub orphan_removed_count: usize,
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
    RetentionKeep,
    ExcludedCurrentWorktree,
    Dirty,
    ActiveLease,
    ActiveClaim,
    TargetRemoved,
    TargetWouldRemove,
    NoTarget,
    UnregisteredOrphan,
    MachineGlobalGate,
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
            Repository::open(path)
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
        if retention.max_age.is_some() || retention.max_count.is_some() {
            let retention = WorktreeRetentionPolicy {
                max_age: retention.max_age,
                max_count: retention
                    .max_count
                    .map(|max_count| max_count.saturating_sub(1)),
            };
            self.gc(WorktreeGcOptions {
                worktree_root,
                dry_run: false,
                remove_targets: true,
                retention,
                exclude_agent_id,
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
        if retention.max_age.is_some() || retention.max_count.is_some() {
            let retention = WorktreeRetentionPolicy {
                max_age: retention.max_age,
                max_count: retention
                    .max_count
                    .map(|max_count| max_count.saturating_sub(1)),
            };
            self.gc(WorktreeGcOptions {
                worktree_root,
                dry_run: false,
                remove_targets: true,
                retention,
                exclude_agent_id,
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
                operation.delete_branch |= delete_branch;
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
        let repo = self.open_repository()?;
        let worktree_root = resolve_worktree_root(&repo, options.worktree_root.clone())?;
        let active_claims = active_claim_agent_ids(&repo)?;
        let exclude_agent_id = options
            .exclude_agent_id
            .as_deref()
            .map(normalize_agent_id)
            .transpose()?;
        let mut report = WorktreeGcReport {
            dry_run: options.dry_run,
            remove_targets: options.remove_targets,
            max_age_seconds: options.retention.max_age.map(|age| age.as_secs()),
            max_count: options.retention.max_count,
            considered_count: 0,
            removed_count: 0,
            protected_count: 0,
            retained_count: 0,
            target_removed_count: 0,
            orphan_removed_count: 0,
            entries: Vec::new(),
        };

        let mut registered_names = BTreeSet::new();
        let registry_store = ManagedWorktreeRegistryStore::open(&repo)?;
        let registry_lock = registry_store.lock()?;
        let mut registry = registry_store.load(&registry_lock)?;
        recover_pending_operations(&repo, &registry_store, &registry_lock, &mut registry)?;
        for name in registry.records.keys() {
            registered_names.insert(name.clone());
        }

        let mut candidates = Vec::new();
        let bindings = registry.records.values().cloned().collect::<Vec<_>>();
        for binding in bindings {
            if registry.operations.contains_key(&binding.name) {
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
            if !gc_worktree_is_clean(&verified.path)? {
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
                    gate_denial: None,
                    retention_operation_id: None,
                });
                continue;
            }
            candidates.push(WorktreeGcCandidate {
                binding,
                branch_oid: verified.branch_oid,
                removal_lease,
            });
        }

        let now = unix_now_nanos()?;
        candidates.sort_by(|left, right| {
            gc_created_at(&right.binding)
                .cmp(&gc_created_at(&left.binding))
                .then_with(|| left.binding.name.cmp(&right.binding.name))
        });
        for (index, candidate) in candidates.into_iter().enumerate() {
            let should_remove =
                retention_selects_gc_candidate(&candidate.binding, index, now, options.retention);
            if should_remove {
                let target_path = gc_target_path_if_present(&candidate.binding.path)?;
                if options.dry_run {
                    report.removed_count = report
                        .removed_count
                        .checked_add(1)
                        .context("worktree GC removed count overflowed")?;
                    report.entries.push(WorktreeGcEntry {
                        name: candidate.binding.name,
                        branch: Some(candidate.binding.branch),
                        path: candidate.binding.path,
                        status: WorktreeGcStatus::WouldRemove,
                        reason: WorktreeGcReason::FinishedBranch,
                        target_path,
                        gate_denial: None,
                        retention_operation_id: None,
                    });
                    continue;
                }
                remove_gc_candidate(
                    &repo,
                    &registry_store,
                    &registry_lock,
                    &mut registry,
                    &candidate,
                )?;
                registered_names.remove(&candidate.binding.name);
                report.removed_count = report
                    .removed_count
                    .checked_add(1)
                    .context("worktree GC removed count overflowed")?;
                report.entries.push(WorktreeGcEntry {
                    name: candidate.binding.name,
                    branch: Some(candidate.binding.branch),
                    path: candidate.binding.path,
                    status: WorktreeGcStatus::Removed,
                    reason: WorktreeGcReason::FinishedBranch,
                    target_path,
                    gate_denial: None,
                    retention_operation_id: None,
                });
                continue;
            }

            let target_path = gc_target_path_if_present(&candidate.binding.path)?;
            if options.remove_targets {
                if let Some(target_path) = target_path {
                    let reason = if options.dry_run {
                        WorktreeGcReason::TargetWouldRemove
                    } else {
                        remove_worktree_target_dir(&candidate.binding.path)?;
                        report.target_removed_count = report
                            .target_removed_count
                            .checked_add(1)
                            .context("worktree GC target count overflowed")?;
                        WorktreeGcReason::TargetRemoved
                    };
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
                        target_path: Some(target_path),
                        gate_denial: None,
                        retention_operation_id: None,
                    });
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
                reason: if options.remove_targets {
                    WorktreeGcReason::NoTarget
                } else {
                    WorktreeGcReason::RetentionKeep
                },
                target_path: None,
                gate_denial: None,
                retention_operation_id: None,
            });
        }

        prune_unregistered_worktree_directories(
            &repo,
            &worktree_root,
            &registered_names,
            options.dry_run,
            options.machine_global_retention.as_ref(),
            &mut report,
        )?;
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
        Repository::open(&self.repo_path)
            .with_context(|| format!("failed to open repository {}", self.repo_path.display()))
    }
}

pub fn sweep_workspace_worktrees(options: WorktreeSweepOptions) -> Result<WorktreeSweepReport> {
    let workspace = fs::canonicalize(&options.workspace).with_context(|| {
        format!(
            "failed to resolve workspace {}",
            options.workspace.display()
        )
    })?;
    require_plain_directory(&workspace, "workspace")?;
    let metadata_root = workspace.join(".maco");
    let worktrees_root = metadata_root.join("worktrees");
    let group_names = match fs::symlink_metadata(&metadata_root) {
        Ok(_) => {
            require_plain_directory(&metadata_root, "workspace metadata root")?;
            match fs::symlink_metadata(&worktrees_root) {
                Ok(_) => bounded_plain_direct_child_names(
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
    let mut groups = Vec::new();
    for group_name in group_names {
        let group = group_name
            .to_str()
            .context("workspace worktree group name is not valid UTF-8")?;
        if group.is_empty() || group.len() > MAX_WORKSPACE_SWEEP_GROUP_NAME_BYTES {
            bail!("workspace worktree group name is invalid or out of bounds");
        }
        groups.push(group.to_string());
    }

    let dry_run = !options.apply;
    let mut report = WorktreeSweepReport {
        workspace: workspace.clone(),
        apply: options.apply,
        dry_run,
        remove_targets: options.remove_targets,
        max_age_seconds: options.retention.max_age.map(|age| age.as_secs()),
        max_count: options.retention.max_count,
        repository_discovered_count: groups.len(),
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
        repositories: Vec::with_capacity(groups.len()),
    };

    for group in groups {
        let group_root = worktrees_root.join(&group);
        let repository = match resolve_sweep_repository(&workspace, &group_root, &group) {
            Ok(repository) => repository,
            Err(failure) => {
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
                    worktree_root: group_root,
                    repository: None,
                    status: WorktreeSweepRepositoryStatus::Skipped,
                    gc_attempted: false,
                    effects_may_have_occurred: false,
                    failure: Some(failure),
                    gc_report: None,
                });
                continue;
            }
        };
        let gc_result = WorktreeManager::new(&repository).gc(WorktreeGcOptions {
            worktree_root: Some(group_root.clone()),
            dry_run,
            remove_targets: options.remove_targets,
            retention: options.retention,
            exclude_agent_id: None,
            machine_global_retention: None,
        });
        match gc_result {
            Ok(gc_report) => {
                add_sweep_gc_counts(&mut report, &gc_report)?;
                report.repository_inspected_count = report
                    .repository_inspected_count
                    .checked_add(1)
                    .context("workspace sweep inspected repository count overflowed")?;
                report.repositories.push(WorktreeSweepRepositoryReport {
                    group,
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
                    worktree_root: group_root,
                    repository: Some(repository),
                    status: WorktreeSweepRepositoryStatus::Failed,
                    gc_attempted: true,
                    effects_may_have_occurred: true,
                    failure: Some(WorktreeSweepFailure {
                        kind: WorktreeSweepFailureKind::GarbageCollection,
                        message: format!("{error:#}"),
                    }),
                    gc_report: None,
                });
            }
        }
    }

    Ok(report)
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
    Ok(())
}

fn resolve_sweep_repository(
    workspace: &Path,
    group_root: &Path,
    group: &str,
) -> std::result::Result<PathBuf, WorktreeSweepFailure> {
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
        let lane_repo = Repository::open(&lane_path).map_err(|error| {
            sweep_failure(
                WorktreeSweepFailureKind::RepositoryOpen,
                anyhow::Error::new(error).context(format!(
                    "failed to open lane repository {}",
                    lane_path.display()
                )),
            )
        })?;
        let (common_dir, primary) =
            validate_lane_sweep_association(workspace, group_root, &lane_path, &lane_repo)?;
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
        let workspace_primary =
            resolve_sweep_repository_from_workspace(workspace, group_root, group)?;
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

    resolve_sweep_repository_from_workspace(workspace, group_root, group)
}

fn resolve_sweep_repository_from_workspace(
    workspace: &Path,
    group_root: &Path,
    group: &str,
) -> std::result::Result<PathBuf, WorktreeSweepFailure> {
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
    let primary = Repository::open(&candidate_path).map_err(|error| {
        sweep_failure(
            WorktreeSweepFailureKind::RepositoryOpen,
            anyhow::Error::new(error).context(format!(
                "failed to open primary repository {}",
                candidate_path.display()
            )),
        )
    })?;
    validate_primary_sweep_association(workspace, group_root, &candidate_path, &primary, None)
        .map(|(_, path)| path)
}

fn validate_lane_sweep_association(
    workspace: &Path,
    group_root: &Path,
    lane_path: &Path,
    lane: &Repository,
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
    let primary = Repository::open(&primary_path).map_err(|error| {
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
    )
}

fn validate_primary_sweep_association(
    workspace: &Path,
    group_root: &Path,
    primary_path: &Path,
    primary: &Repository,
    expected_common_dir: Option<&Path>,
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
    if canonical_primary.parent() != Some(workspace) {
        return Err(WorktreeSweepFailure {
            kind: WorktreeSweepFailureKind::RepositoryAssociation,
            message: "primary repository is not a direct workspace child".to_string(),
        });
    }
    let canonical_group_root = fs::canonicalize(group_root).map_err(|error| {
        sweep_failure(
            WorktreeSweepFailureKind::RepositoryAssociation,
            anyhow::Error::new(error).context("failed to resolve workspace worktree group"),
        )
    })?;
    let expected_group_root = default_worktree_root(primary);
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
    removal_lease: Option<ManagedWorktreeRemovalLease>,
}

fn remove_gc_candidate(
    repo: &Repository,
    registry_store: &ManagedWorktreeRegistryStore,
    registry_lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
    candidate: &WorktreeGcCandidate,
) -> Result<()> {
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
            delete_branch: false,
            force: true,
            expected_branch_oid: Some(candidate.branch_oid.to_string()),
            worktree_quarantine_path: Some(worktree_quarantine_path),
            worktree_quarantine_identity: None,
            metadata_quarantine_path: Some(metadata_quarantine_path),
            metadata_quarantine_identity: None,
        },
    );
    registry_store.save(registry_lock, registry)?;
    recover_pending_operations_with_held_removal_lease(
        repo,
        registry_store,
        registry_lock,
        registry,
        Some(removal_lease),
    )
}

fn resolve_worktree_root(repo: &Repository, requested_root: Option<PathBuf>) -> Result<PathBuf> {
    let root = requested_root.unwrap_or_else(|| default_worktree_root(repo));
    if root.is_absolute() {
        Ok(root)
    } else {
        Ok(repo
            .workdir()
            .context("worktree GC requires a non-bare repository")?
            .join(root))
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

fn gc_worktree_is_clean(path: &Path) -> Result<bool> {
    Ok(bounded_repository_status_paths(
        path,
        MAX_WORKTREE_STATUS_ENTRIES,
        MAX_WORKTREE_STATUS_OUTPUT_BYTES,
        WORKTREE_GC_STATUS_TIMEOUT,
    )?
    .is_empty())
}

fn gc_created_at(binding: &ManagedWorktreeBinding) -> i64 {
    binding.created_at_unix_nanos.unwrap_or(0)
}

fn retention_selects_gc_candidate(
    binding: &ManagedWorktreeBinding,
    index: usize,
    now: i64,
    retention: WorktreeRetentionPolicy,
) -> bool {
    if retention.max_age.is_none() && retention.max_count.is_none() {
        return true;
    }
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

fn gc_target_path_if_present(worktree_path: &Path) -> Result<Option<PathBuf>> {
    let target_path = worktree_path.join("target");
    match fs::symlink_metadata(&target_path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            Ok(Some(target_path))
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

fn remove_worktree_target_dir(worktree_path: &Path) -> Result<()> {
    let root = SafeRoot::open_existing(worktree_path)?;
    remove_direct_child_tree(&root, "target", None, TreeLinkPolicy::UnlinkLinks)
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
        let authenticator = repository_authenticator_key_only(&self.repo_path)?;
        let auth_binding = authenticator.binding().clone();
        let snapshot = AuthenticatedSnapshotStore::<
            ManagedSnapshotSpec,
            AuthenticatedManagedState,
        >::read_existing_current(authenticator, MANAGED_LOGICAL_ID)?;
        self.validate_authenticated_snapshot(&snapshot, &auth_binding)?;
        self.verify_lock(&lock)?;
        Ok(Some(snapshot.value.registry))
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
    }
    Ok(())
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
    recover_remove_operation(repo, store, lock, registry, operation)
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
            registry.records.insert(operation.name.clone(), binding);
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
    let worktree_repo = Repository::open(path)
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

fn recover_remove_operation(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
    mut operation: ManagedWorktreeOperation,
) -> Result<()> {
    let binding = operation.binding.clone().with_context(|| {
        format!(
            "remove operation '{}' has no create-time binding",
            operation.name
        )
    })?;
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
            if !operation.force {
                ensure_clean_worktree(&verified.path)?;
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
        }
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
        let repository = Repository::open(worktree.path()).with_context(|| {
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
        let reopened = Repository::open(self.worktree.path())
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
    process_queue_wait: Duration,
}

fn bounded_worktree_records(
    path: &Path,
    max_entries: usize,
    max_output_bytes: usize,
    timeout: Duration,
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
        verify_repository_status_bindings(worktree_binding, &git_dir_binding, &common_dir_binding)?;
        Ok(BoundedWorktreeRecords {
            visible,
            status: bytes,
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
    let repository = Repository::open(worktree).with_context(|| {
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
    use tempfile::TempDir;

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

        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        commit_readme(&Repository::open(&first_path).expect("open first")).expect("commit first");
        commit_readme(&Repository::open(&second_path).expect("open second"))
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        assert_eq!(
            preview.repositories[0]
                .gc_report
                .as_ref()
                .expect("preview GC report")
                .entries[0]
                .status,
            WorktreeGcStatus::WouldRemove
        );
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
    fn workspace_sweep_inspects_repository_and_group_with_maco_prefix() {
        let temp = TempDir::new().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let repo_path = workspace.join(".maco-repository");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
    fn workspace_sweep_continues_after_typed_repository_open_failure() {
        let temp = TempDir::new().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let repo_path = workspace.join("valid+repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        fs::create_dir_all(old.path.join("target/debug")).expect("old target");
        fs::create_dir_all(new.path.join("target/debug")).expect("new target");
        let mut options = workspace_sweep_options(&workspace, false);
        options.remove_targets = false;
        options.retention = WorktreeRetentionPolicy {
            max_age: Some(Duration::from_secs(3600)),
            max_count: Some(1),
        };

        let report = sweep_workspace_worktrees(options).expect("retained workspace sweep");
        assert_eq!(report.max_age_seconds, Some(3600));
        assert_eq!(report.max_count, Some(1));
        assert!(!report.remove_targets);
        assert_eq!(report.removed_count, 1);
        assert_eq!(report.retained_count, 1);
        assert_eq!(report.target_removed_count, 0);
        let gc = report.repositories[0]
            .gc_report
            .as_ref()
            .expect("nested GC report");
        assert_eq!(gc.max_age_seconds, Some(3600));
        assert_eq!(gc.max_count, Some(1));
        assert!(!gc.remove_targets);
        assert!(gc.entries.iter().any(|entry| {
            entry.status == WorktreeGcStatus::Retained
                && entry.reason == WorktreeGcReason::RetentionKeep
        }));
        assert!(old.path.exists());
        assert!(new.path.exists());
        assert!(old.path.join("target").exists());
        assert!(new.path.join("target").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn workspace_sweep_inherits_combined_active_claim_and_lease_protection() {
        let temp = TempDir::new().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let repo_path = workspace.join("protected+repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = create_gc_worktree(&manager, "agent-finished", &worktree_root);
        fs::create_dir_all(created.path.join("target/debug")).expect("create target");

        let report = manager
            .gc(gc_options(Some(worktree_root.clone()), false))
            .expect("gc finished worktree");

        assert_eq!(report.removed_count, 1);
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
        let repo = Repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = create_gc_worktree(&manager, "agent-dirty-gc", &worktree_root);
        fs::write(created.path.join("scratch.txt"), "local work\n").expect("dirty worktree");

        let report = manager
            .gc(gc_options(Some(worktree_root), false))
            .expect("gc dirty worktree");

        assert_eq!(report.removed_count, 0);
        assert_eq!(report.protected_count, 1);
        assert_eq!(report.entries[0].status, WorktreeGcStatus::Protected);
        assert_eq!(report.entries[0].reason, WorktreeGcReason::Dirty);
        assert!(created.path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_protects_active_execution_lease() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let old = create_gc_worktree(&manager, "agent-old-gc", &worktree_root);
        let new = create_gc_worktree(&manager, "agent-new-gc", &worktree_root);
        fs::create_dir_all(old.path.join("target/debug")).expect("old target");
        fs::create_dir_all(new.path.join("target/debug")).expect("new target");

        let report = manager
            .gc(WorktreeGcOptions {
                worktree_root: Some(worktree_root),
                dry_run: false,
                remove_targets: true,
                retention: WorktreeRetentionPolicy {
                    max_age: None,
                    max_count: Some(1),
                },
                exclude_agent_id: None,
                machine_global_retention: None,
            })
            .expect("gc with retention");

        assert_eq!(report.removed_count, 1);
        assert_eq!(report.retained_count, 1);
        assert_eq!(report.target_removed_count, 1);
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
    fn create_retention_applies_after_new_worktree_creation() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = Repository::open(&repo_path).expect("open repo");
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
                },
            )
            .expect("create with retention");

        assert!(!old.path.exists());
        assert!(new.path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_prunes_unregistered_leftover_directory_second_pass() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = create_gc_worktree(&manager, "agent-dry-run-gc", &worktree_root);
        fs::create_dir_all(created.path.join("target/debug")).expect("target");

        let report = manager
            .gc(gc_options(Some(worktree_root), true))
            .expect("dry-run gc");

        assert!(report.dry_run);
        assert_eq!(report.removed_count, 1);
        assert_eq!(report.entries[0].status, WorktreeGcStatus::WouldRemove);
        assert_eq!(report.entries[0].reason, WorktreeGcReason::FinishedBranch);
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open non-UTF-8 repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let reopened = Repository::open(&repo_path).expect("reopen repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let residue = created.path.join("target/debug/deps");
        fs::create_dir_all(&residue).expect("create residue directory");
        fs::write(residue.join("artifact.d"), "ignored build output\n").expect("write residue");

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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
            let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
                let replacement_repo = Repository::open(&repo_path).expect("replacement repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
            let repo = Repository::open(&repo_path).expect("open repo");
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
            let repo = Repository::open(&repo_path).expect("open repo");
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
            let repo = Repository::open(&repo_path).expect("open repo");
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
            retention: WorktreeRetentionPolicy::default(),
            exclude_agent_id: None,
            machine_global_retention: None,
        }
    }

    fn workspace_sweep_options(workspace: &Path, apply: bool) -> WorktreeSweepOptions {
        WorktreeSweepOptions {
            workspace: workspace.to_path_buf(),
            apply,
            remove_targets: true,
            retention: WorktreeRetentionPolicy::default(),
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
