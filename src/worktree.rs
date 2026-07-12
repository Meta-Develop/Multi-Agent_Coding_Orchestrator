#[cfg(test)]
use crate::safe_state::scavenge_private_random_directories;
use crate::{
    artifacts::{
        repository_authenticator_key_only,
        state_auth::{random_identifier, AuthenticationDomain, RepositoryAuthBinding},
    },
    authenticated_snapshot::{AuthenticatedSnapshotStore, SnapshotSpec},
    process_runner::{
        run_process, ContainmentPolicy, EnvironmentMode, ProcessOutput, ProcessSpec,
        SideEffectConfinementProfile, StdinMode, StrictOfflineWorkspaceProfile,
    },
    safe_state::{
        identity_for_path, quarantine_direct_child_directory, remove_direct_child_tree,
        remove_quarantined_direct_child_tree, replace_reserved_directory_from,
        scavenge_private_random_directories_until, stable_checksum, AtomicStateWriter,
        BoundedRegularReader, FileIdentity, KernelStateLock, PrivateDirectoryScavengeLimits,
        SafeRoot, TreeLinkPolicy,
    },
    state_journal::JournalSpec,
    state_migration::{
        finalize_legacy_retirement, prepare_legacy_retirement, LegacyAdoption,
        LEGACY_RETIREMENT_DOMAIN,
    },
};
use anyhow::{bail, Context, Result};
use git2::{
    Branch, BranchType, ErrorCode, ObjectType, Oid, Repository, RepositoryInitOptions, Transaction,
    WorktreeAddOptions, WorktreeLockStatus,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    time::{Duration, Instant},
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
const MAX_PERSISTED_PATH_BYTES: usize = 16 * 1024;
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
const WORKTREE_STATUS_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
// The total budget includes contention on the process-wide runtime lock,
// startup scavenging, repository/index capture, private Git setup, both Git
// commands, and resumable cleanup. Individual Git commands remain bounded by
// the same absolute deadline; this larger envelope prevents unrelated local
// repositories from spuriously exhausting the shared runtime-lock budget.
const WORKTREE_STATUS_TIMEOUT: Duration = Duration::from_secs(60);
const REMOVAL_LOCK_REASON: &str = "MACO removal quarantine; child process must be stopped";
const MANAGED_LOGICAL_ID: &str = "managed-worktrees";

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

#[derive(Debug, Clone)]
pub struct WorktreeManager {
    repo_path: PathBuf,
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
}

#[derive(Debug, Clone)]
pub struct WorktreeCreateOptions {
    pub agent_id: String,
    pub branch: Option<String>,
    pub base: Option<String>,
    pub worktree_root: Option<PathBuf>,
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
        let repo = self.open_repository()?;
        let registry_store = ManagedWorktreeRegistryStore::open(&repo)?;
        let registry_lock = registry_store.lock()?;
        let mut registry = registry_store.load(&registry_lock)?;
        recover_pending_operations(&repo, &registry_store, &registry_lock, &mut registry)?;
        let name = normalize_agent_id(&options.agent_id)?;
        let branch_name = options.branch.unwrap_or_else(|| default_branch_name(&name));
        validate_branch_name(&branch_name)?;
        if registry.records.contains_key(&name) {
            bail!("managed worktree '{name}' already has a registry binding");
        }
        if registry.records.len() >= MAX_MANAGED_RECORDS {
            bail!("managed worktree registry has no remaining record capacity");
        }
        if registry.operations.len() >= MAX_MANAGED_OPERATIONS {
            bail!("managed worktree registry has no remaining operation capacity");
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

        let commit = resolve_base_commit(&repo, options.base.as_deref())?;
        let branch_preexisting_oid =
            local_branch_oid(&repo, &branch_name)?.map(|oid| oid.to_string());
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
                force: false,
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
                recover_pending_operations(&repo, &registry_store, &registry_lock, &mut registry)?;
                return Err(error);
            }
        };
        let staging_reserved = match root.reserve_direct_child_directory(&staging_name) {
            Ok(reserved) => reserved,
            Err(error) => {
                remove_direct_child_tree(
                    &root,
                    &name,
                    Some(reserved.identity()),
                    TreeLinkPolicy::UnlinkLinks,
                )?;
                recover_pending_operations(&repo, &registry_store, &registry_lock, &mut registry)?;
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
            remove_direct_child_tree(
                &root,
                staging_reserved
                    .path()
                    .file_name()
                    .context("staging reservation has no final name")?,
                Some(staging_reserved.identity()),
                TreeLinkPolicy::UnlinkLinks,
            )?;
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
                let (branch, created_by_maco) = ensure_branch(&repo, &branch_name, &commit)?;
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
                verify_worktree_clean_at(&staging_path, &branch_name, branch_oid)?;
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
        let recovery_result =
            recover_pending_operations(&repo, &registry_store, &registry_lock, &mut registry);
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

        Ok(WorktreeRecord {
            name,
            path: binding.path.clone(),
            branch: branch_name,
        })
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
        let repo = self.open_repository()?;
        let name = normalize_agent_id(agent_id)?;
        let registry_store = ManagedWorktreeRegistryStore::open(&repo)?;
        let registry_lock = registry_store.lock()?;
        let mut registry = registry_store.load(&registry_lock)?;
        recover_pending_operations(&repo, &registry_store, &registry_lock, &mut registry)?;
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

        if !force {
            ensure_clean_worktree(&verified.path)?;
        }
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
        let mut registry = registry_store.load(&registry_lock)?;
        recover_pending_operations(&repo, &registry_store, &registry_lock, &mut registry)?;
        let mut records = Vec::with_capacity(registry.records.len());
        for binding in registry.records.values() {
            records.push(verified_worktree_record(
                &repo,
                &registry_store.repository,
                binding,
            )?);
        }
        records.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(records)
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
        let lock = finish_with_registry_lock_verification(
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
        let lock = finish_with_registry_lock_verification(
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
    if worktree.name() != Some(binding.name.as_str()) {
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

    fn try_acquire_shared_worktree_read_lock(
        &self,
        registry_lock: &ManagedWorktreeRegistryLock,
        name: &str,
    ) -> Result<KernelStateLock> {
        let incarnation = self.active_incarnation(registry_lock, name)?;
        KernelStateLock::try_acquire_shared_direct(
            &self.state_root,
            managed_worktree_lease_name(name, &incarnation)?,
        )
    }

    fn try_acquire_exclusive_worktree_write_lock(
        &self,
        registry_lock: &ManagedWorktreeRegistryLock,
        name: &str,
    ) -> Result<KernelStateLock> {
        let incarnation = self.active_incarnation(registry_lock, name)?;
        KernelStateLock::try_acquire_exclusive_direct(
            &self.state_root,
            managed_worktree_lease_name(name, &incarnation)?,
        )
    }

    fn try_acquire_worktree_removal_lease(
        &self,
        registry_lock: &ManagedWorktreeRegistryLock,
        name: &str,
    ) -> Result<ManagedWorktreeRemovalLease> {
        let incarnation = self.active_incarnation(registry_lock, name)?;
        let lock = KernelStateLock::try_acquire_exclusive_direct(
            &self.state_root,
            managed_worktree_lease_name(name, &incarnation)?,
        )?;
        Ok(ManagedWorktreeRemovalLease {
            name: name.to_string(),
            incarnation_generation: incarnation.generation,
            incarnation_nonce: incarnation.nonce,
            _lock: lock,
        })
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
            reconcile_managed_incarnations(&mut incarnations, registry)?;
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
            };
            self.verify_lock(lock)?;
            if revision % 4_096 == 0 {
                let authenticator = repository_authenticator_key_only(&self.repo_path)?;
                store = store.rollover(authenticator, revision, value)?;
            } else {
                store.commit(revision, value)?;
            }
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
        reconcile_managed_incarnations(&mut incarnations, &registry)?;
        let initial = AuthenticatedManagedState {
            version: 1,
            snapshot_revision: 1,
            repository: writer.authenticator().binding().clone(),
            registry,
            incarnations,
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
        if snapshot.value.version != 1
            || snapshot.value.snapshot_revision != snapshot.generation
            || snapshot.value.snapshot_revision != snapshot.token
            || snapshot.value.repository != store.identity().repository
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
        validate_managed_incarnations(&snapshot.value.incarnations, &snapshot.value.registry)
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
) -> Result<()> {
    let active = registry
        .records
        .keys()
        .chain(registry.operations.keys())
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    for (name, incarnation) in incarnations.iter_mut() {
        if !active.contains(name) {
            incarnation.active = false;
        }
    }
    for name in active {
        match incarnations.get_mut(&name) {
            Some(incarnation) if incarnation.active => {}
            Some(incarnation) => {
                incarnation.generation = incarnation
                    .generation
                    .checked_add(1)
                    .context("managed worktree incarnation generation exhausted")?;
                incarnation.nonce = random_identifier()?;
                incarnation.active = true;
            }
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
    validate_managed_incarnations(incarnations, registry)
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
        if incarnation.active != expected_active {
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

fn recover_pending_operations(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
) -> Result<()> {
    recover_pending_operations_with_held_removal_lease(repo, store, lock, registry, None)
}

fn recover_pending_operations_with_held_removal_lease(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
    held_removal_lease: Option<&ManagedWorktreeRemovalLease>,
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
                recover_create_operation(repo, store, lock, registry, operation)?
            }
            ManagedWorktreeOperationKind::Remove => {
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
                recover_remove_operation(repo, store, lock, registry, operation)?
            }
        }
    }
    reconcile_creation_locks(repo, store, lock, registry)
}

fn recover_create_operation(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
    mut operation: ManagedWorktreeOperation,
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
                let staging_name = staging_root_path
                    .file_name()
                    .context("create intent staging root has no final name")?;
                let staging = root.bind_existing_direct_child_directory(staging_name)?;
                if !staging.is_empty()? {
                    bail!(
                        "create intent '{}' found a non-empty unbound staging directory; preserving it",
                        operation.name
                    );
                }
                remove_direct_child_tree(
                    &root,
                    staging_name,
                    Some(staging.identity()),
                    TreeLinkPolicy::UnlinkLinks,
                )?;
            }
        }
        if path_entry_exists(&operation.path)? {
            let reserved = root.bind_existing_direct_child_directory(&operation.name)?;
            if !reserved.is_empty()? {
                bail!(
                    "create intent '{}' found a non-empty unbound directory; preserving it",
                    operation.name
                );
            }
            remove_direct_child_tree(
                &root,
                &operation.name,
                Some(reserved.identity()),
                TreeLinkPolicy::UnlinkLinks,
            )?;
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
                let staged =
                    staging_root.bind_existing_managed_direct_child_directory(&operation.name)?;
                if !staged.is_empty()? {
                    bail!(
                        "create operation '{}' left a non-empty unbound staging path; preserving it for manual recovery",
                        operation.name
                    );
                }
                remove_direct_child_tree(
                    &staging_root,
                    &operation.name,
                    Some(staged.identity()),
                    TreeLinkPolicy::UnlinkLinks,
                )?;
            }
            if final_path_exists {
                let reserved = root.bind_existing_direct_child_directory(&operation.name)?;
                if reserved.identity() != prepared_identity || !reserved.is_empty()? {
                    bail!(
                        "create operation '{}' left a changed or non-empty unbound path; preserving it for manual recovery",
                        operation.name
                    );
                }
                remove_direct_child_tree(
                    &root,
                    &operation.name,
                    Some(prepared_identity),
                    TreeLinkPolicy::UnlinkLinks,
                )?;
            }
            remove_staging_root_if_empty(&root, &staging_root, &staging_root_identity)?;
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
        verify_worktree_clean_at(&staging_path, &operation.branch, expected_branch_oid)?;
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
        verify_worktree_clean_at(&operation.path, &operation.branch, expected_branch_oid)?;
        verify_local_branch_oid(repo, &operation.branch, expected_branch_oid)?;
        let base_oid =
            Oid::from_str(&operation.base_oid).context("create operation base OID is malformed")?;
        let binding = capture_managed_worktree_binding(
            repo,
            &store.repository,
            &root,
            &operation.name,
            &operation.branch,
            operation.branch_ownership == ManagedBranchOwnership::CreatedByMaco,
            base_oid,
            expected_branch_oid,
        )?;
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
        verify_worktree_clean_at(&operation.path, &operation.branch, expected_branch_oid)?;
        let root = SafeRoot::open_existing(&operation.root)?;
        if root.identity() != &operation.root_identity {
            bail!("create-observed root identity changed before finalization");
        }
        let base_oid =
            Oid::from_str(&operation.base_oid).context("create operation base OID is malformed")?;
        let observed_binding = capture_managed_worktree_binding(
            repo,
            &store.repository,
            &root,
            &operation.name,
            &operation.branch,
            operation.branch_ownership == ManagedBranchOwnership::CreatedByMaco,
            base_oid,
            expected_branch_oid,
        )?;
        let binding = operation.binding.clone().with_context(|| {
            format!(
                "create operation '{}' reached observed phase without a binding",
                operation.name
            )
        })?;
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
                remove_staging_root_if_empty(&root, &staging_root, staging_root_identity)?;
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
        complete_creation_lock(repo, store, lock, registry, &operation.name)?;
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
    remove_direct_child_tree(
        managed_root,
        name,
        Some(expected),
        TreeLinkPolicy::UnlinkLinks,
    )
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

fn verify_worktree_clean_at(path: &Path, branch: &str, expected: Oid) -> Result<()> {
    let worktree_repo = Repository::open(path)
        .with_context(|| format!("failed to open created worktree {}", path.display()))?;
    let expected_reference = format!("refs/heads/{branch}");
    let verify_head = || -> Result<()> {
        let head = worktree_repo
            .head()
            .context("failed to inspect created worktree HEAD")?;
        if !head.is_branch() || head.name() != Some(expected_reference.as_str()) {
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
    ensure_clean_worktree(path)
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
    verify_worktree_clean_at(&verified.path, &binding.branch, expected)?;
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
        complete_creation_lock(repo, store, lock, registry, &name)?;
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
    let head = match repo.head() {
        Ok(head) => head.shorthand().map(ToOwned::to_owned),
        Err(error) if error.code() == ErrorCode::UnbornBranch => None,
        Err(error) if error.code() == ErrorCode::NotFound => None,
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

fn find_worktree(repo: &Repository, name: &str) -> Result<Option<git2::Worktree>> {
    match repo.find_worktree(name) {
        Ok(worktree) => Ok(Some(worktree)),
        Err(error) if error.code() == ErrorCode::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to inspect worktree '{name}'")),
    }
}

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

fn bounded_worktree_is_clean(
    path: &Path,
    max_entries: usize,
    max_output_bytes: usize,
    timeout: Duration,
) -> Result<bool> {
    let deadline = worktree_status_deadline(timeout)?;
    ensure_worktree_status_deadline(deadline, "before bounded-status runtime-root setup")?;
    let state_root = bounded_status_runtime_root(path)?;
    ensure_worktree_status_deadline(deadline, "after bounded-status runtime-root setup")?;
    bounded_worktree_is_clean_in_runtime_until(
        path,
        max_entries,
        max_output_bytes,
        &state_root,
        |_| Ok(()),
        deadline,
    )
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
    let deadline = worktree_status_deadline(timeout)?;
    bounded_worktree_is_clean_in_runtime_until(
        path,
        max_entries,
        max_output_bytes,
        state_root,
        after_index_snapshot,
        deadline,
    )
}

fn bounded_worktree_is_clean_in_runtime_until<F>(
    path: &Path,
    max_entries: usize,
    max_output_bytes: usize,
    state_root: &SafeRoot,
    after_index_snapshot: F,
    deadline: Instant,
) -> Result<bool>
where
    F: FnOnce(&SafeRoot) -> Result<()>,
{
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
    let repository = Repository::open(path).with_context(|| {
        format!(
            "failed to open bounded-status repository {}",
            path.display()
        )
    })?;
    ensure_worktree_status_deadline(deadline, "after opening bounded-status repository")?;
    let head = repository
        .head()
        .context("failed to inspect bounded-status HEAD")?
        .target()
        .context("bounded-status HEAD has no direct target")?;
    ensure_worktree_status_deadline(deadline, "after capturing bounded-status HEAD")?;
    let index_path = repository.path().join("index");
    let index = BoundedRegularReader::read(&index_path, MAX_WORKTREE_INDEX_BYTES)
        .context("failed to capture bounded-status index")?;
    ensure_worktree_status_deadline(deadline, "after capturing bounded-status index")?;
    let common_objects = SafeRoot::open_existing(repository.commondir().join("objects"))?;
    ensure_worktree_status_deadline(deadline, "after binding bounded-status objects")?;
    let runtime = state_root.reserve_random_direct_child_directory(WORKTREE_STATUS_RUNTIME_SEED)?;
    ensure_worktree_status_deadline(deadline, "after reserving bounded-status runtime")?;
    let result = (|| -> Result<bool> {
        let runtime_root = SafeRoot::open_existing(runtime.path())?;
        ensure_worktree_status_deadline(deadline, "after opening bounded-status runtime")?;
        runtime_root.reserve_direct_child_directory("home")?;
        ensure_worktree_status_deadline(deadline, "after bounded-status HOME setup")?;
        runtime_root.reserve_direct_child_directory("tmp")?;
        ensure_worktree_status_deadline(deadline, "after bounded-status TMP setup")?;
        let git_dir = runtime_root.reserve_direct_child_directory("git")?;
        let git_root = SafeRoot::open_existing(git_dir.path())?;
        git_root.reserve_direct_child_directory("refs")?;
        ensure_worktree_status_deadline(deadline, "after bounded-status Git root setup")?;
        AtomicStateWriter::write_direct(&git_root, "index", &index)?;
        ensure_worktree_status_deadline(deadline, "after bounded-status index staging")?;
        after_index_snapshot(&runtime_root)?;
        ensure_worktree_status_deadline(deadline, "after bounded-status setup callback")?;
        AtomicStateWriter::write_direct(&git_root, "HEAD", format!("{head}\n").as_bytes())?;
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
        run_bounded_git_records(
            &git_context,
            ["--no-optional-locks", "ls-files", "-z", "--cached"],
            max_entries,
            max_output_bytes,
            deadline,
            "bounded managed-worktree index listing",
        )?;
        ensure_worktree_status_deadline(deadline, "after bounded managed-worktree index listing")?;
        let bytes = run_bounded_git_records(
            &git_context,
            [
                "--no-optional-locks",
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--no-renames",
            ],
            max_entries,
            max_output_bytes,
            deadline,
            "bounded managed-worktree status",
        )?;
        ensure_worktree_status_deadline(deadline, "after bounded managed-worktree status")?;
        Ok(bytes.is_empty())
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
    finish_with_status_lock_verification(finished, status_lock.verify_direct_binding(state_root))
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

fn worktree_status_deadline(timeout: Duration) -> Result<Instant> {
    if timeout.is_zero() {
        bail!("worktree status total time budget must be non-zero");
    }
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
    let mut command_args = Vec::with_capacity(args.len().saturating_add(4));
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
            .create(WorktreeCreateOptions {
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
            .remove("agent-a", false, true)
            .expect("remove worktree");
        assert_eq!(removed.name, "agent-a");
        assert!(!removed.path.exists());
        assert!(repo.find_branch("maco/agent-a", BranchType::Local).is_err());
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
            .create(WorktreeCreateOptions {
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
            .remove("agent-leased", false, true)
            .expect("remove after shared leases release");
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
            .create(WorktreeCreateOptions {
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
            .create(WorktreeCreateOptions {
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
            .remove("agent-writer-removal", false, true)
            .expect("remove after writer release");
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
                .create(WorktreeCreateOptions {
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
        manager.create(options()).expect("first incarnation");

        let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
        let lock = store.lock().expect("registry lock");
        let first = store
            .active_incarnation(&lock, "agent-incarnation")
            .expect("first incarnation evidence");
        drop(lock);
        manager
            .remove("agent-incarnation", true, true)
            .expect("remove first incarnation");
        let stale_lock = KernelStateLock::try_acquire_exclusive_direct(
            &store.state_root,
            managed_worktree_lease_name("agent-incarnation", &first).expect("old lease name"),
        )
        .expect("stale incarnation lock");

        manager.create(options()).expect("second incarnation");
        let lock = store.lock().expect("registry lock");
        let second = store
            .active_incarnation(&lock, "agent-incarnation")
            .expect("second incarnation evidence");
        assert_eq!(second.generation, first.generation + 1);
        assert_ne!(second.nonce, first.nonce);
        let stale = ManagedWorktreeRemovalLease {
            name: "agent-incarnation".to_string(),
            incarnation_generation: first.generation,
            incarnation_nonce: first.nonce,
            _lock: stale_lock,
        };
        let error = store
            .verify_removal_lease_current(&lock, &stale)
            .expect_err("stale removal lease must not authorize the new incarnation");
        assert!(error.to_string().contains("stale incarnation"));
        drop(lock);

        let _current = manager
            .acquire_read_execution_lease("agent-incarnation")
            .expect("old-incarnation lock must not block current lease");
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
            .create(WorktreeCreateOptions {
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
            .create(WorktreeCreateOptions {
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
        assert_still_bound(
            manager
                .list()
                .expect_err("list must refuse active execution lease"),
        );
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
                .create(WorktreeCreateOptions {
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
            .expect("recover pending removal after lease release")
            .is_empty());
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
            .create(WorktreeCreateOptions {
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
            store
                .save(&lock, &mut registry)
                .expect("persist crash fixture");
            let bytes = BoundedRegularReader::read_direct(
                &store.state_root,
                "managed_worktrees.json",
                MAX_MANAGED_REGISTRY_BYTES,
            )
            .expect("read registry bytes");
            assert!(bytes
                .windows(b"unix-bytes-hex-v1".len())
                .any(|window| { window == b"unix-bytes-hex-v1" }));
            assert!(!bytes.windows(3).any(|window| window == [0xef, 0xbf, 0xbd]));
        }

        let listed = manager.list().expect("recover and list non-UTF-8 worktree");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].path, created.path);
        manager
            .remove("non-utf8-agent", false, true)
            .expect("remove non-UTF-8 worktree");
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
            .create(WorktreeCreateOptions {
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
            .create(WorktreeCreateOptions {
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
            Duration::from_secs(2),
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
            Duration::from_secs(2),
        )
        .expect_err("entry budget must fail");
        assert!(
            entries.to_string().contains("entries"),
            "unexpected bounded status error: {entries:#}"
        );

        let output = bounded_worktree_is_clean(&repo_path, 10, 1, Duration::from_secs(2))
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
        let index = fs::OpenOptions::new()
            .write(true)
            .open(repo.path().join("index"))
            .expect("open index");
        index
            .set_len(MAX_WORKTREE_INDEX_BYTES - 4096)
            .expect("expand index fixture");
        drop(index);
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
        let error = bounded_worktree_is_clean_in_runtime(
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

        let error = bounded_worktree_is_clean_in_runtime(
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
            bounded_worktree_is_clean_in_runtime(
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
            .recv_timeout(Duration::from_secs(5))
            .expect("first lifecycle entered");
        let (second_entered_tx, second_entered_rx) = mpsc::channel();
        let second_repo = repo_path.clone();
        let second_root = runtime_root.clone();
        let second = thread::spawn(move || {
            bounded_worktree_is_clean_in_runtime(
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
            .recv_timeout(Duration::from_secs(5))
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
            .create(WorktreeCreateOptions {
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
            .create(WorktreeCreateOptions {
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
    fn remove_refuses_dirty_worktree_without_force() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = Repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");

        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create(WorktreeCreateOptions {
                agent_id: "agent-dirty".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");
        fs::write(created.path.join("scratch.txt"), "local edits\n").expect("write scratch");

        let error = manager
            .remove("agent-dirty", false, true)
            .expect_err("dirty worktree should require force");

        assert!(error.to_string().contains("worktree is dirty"));
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
            .create(WorktreeCreateOptions {
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
            .create(WorktreeCreateOptions {
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
            .create(WorktreeCreateOptions {
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
            .create(WorktreeCreateOptions {
                agent_id: "agent-b".to_string(),
                branch: Some("topic/agent-b".to_string()),
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");

        let removed = manager
            .remove("agent-b", false, true)
            .expect("remove worktree");

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
            .create(WorktreeCreateOptions {
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
            .create(WorktreeCreateOptions {
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
            .create(WorktreeCreateOptions {
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
    fn recovers_create_intent_at_final_and_staging_mkdir_boundaries() {
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
                    force: false,
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

            recover_pending_operations(&repo, &store, &lock, &mut registry)
                .expect("recover intent");
            assert!(!root.path().join(&name).exists());
            assert!(!staging_root_path.exists());
            assert!(registry.operations.is_empty());
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
            .create(WorktreeCreateOptions {
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
            .create(WorktreeCreateOptions {
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
            .create(WorktreeCreateOptions {
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
            .create(WorktreeCreateOptions {
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
                .create(WorktreeCreateOptions {
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
                .create(WorktreeCreateOptions {
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
                .create(WorktreeCreateOptions {
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
