//! Explicit, offline migration of legacy repository state into an authenticated
//! generation-one manifest.
//!
//! The migration is deliberately opt-in. Dry-run performs bounded no-follow
//! validation and takes every existing legacy kernel lock without modifying
//! the repository. Apply holds those locks for its full lifecycle, hardens the
//! legacy state tree, and publishes a signed immutable manifest. A private
//! transaction outside the state root makes the chmod-to-manifest crash window
//! forward recoverable.

use crate::{
    artifacts::{
        repository_auth_writer, repository_authenticator_key_only,
        state_auth::{sha256_hex, AuthenticationDomain, RepositoryAuthBinding},
    },
    authenticated_snapshot::{AuthenticatedSnapshotStore, SnapshotSpec},
    safe_state::{
        identity_for_path, stable_checksum, AtomicStateWriter, BoundedRegularReader, FileIdentity,
        KernelStateLock, SafeRoot,
    },
    semantic_coord::SemanticIntent,
    state_journal::{JournalSpec, JOURNAL_ROOT_NAME},
    sync::PathClaim,
};
use anyhow::{bail, Context, Result};
use git2::Repository;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::{
    ffi::{OsStrExt, OsStringExt},
    fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    io::AsRawFd,
};

const MIGRATION_VERSION: u32 = 1;
const MANIFEST_INSTANCE_ID: &str = "legacy-state-v1";
const MANIFEST_ROOT_NAME: &str = "state-migration-manifests-v1";
const TRANSACTION_ROOT_NAME: &str = "maco-state-migration-v1";
const TRANSACTION_FILE: &str = "transaction.json";
const RECEIPT_FILE: &str = "receipt.json";
const TRANSACTION_LOCK: &str = "migration.lock";
const MAX_LEGACY_STATE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_TRANSACTION_BYTES: u64 = 2 * 1024 * 1024;
const MAX_STATE_ENTRIES: usize = 4_096;
const AUTH_KEY_FILE: &str = "artifact_finalization_hmac_v1.key";
const AUTH_KEY_LOCK: &str = "artifact_finalization_hmac_v1.lock";
const AUTH_EPOCH_FILE: &str = "repository_auth_epoch_v1";
const LEGACY_STORES: [(&str, &str); 3] = [
    ("claims", "claims.json"),
    ("semantic_intents", "semantic_intents.json"),
    ("managed_worktrees", "managed_worktrees.json"),
];
const LEGACY_LOCKS: [&str; 3] = [
    "claims.lock",
    "semantic_intents.lock",
    "managed_worktrees.lock",
];

pub(crate) enum StateMigrationManifestSpec {}

impl JournalSpec for StateMigrationManifestSpec {
    const FORMAT_VERSION: u32 = 1;
    const NAMESPACE: &'static str = "state_migration_manifest";
    const ROOT_NAME: &'static str = MANIFEST_ROOT_NAME;
    const ROOT_LOCK_NAME: &'static str = ".state-migrations.lock";
    const INSTANCE_LOCK_NAME: &'static str = ".state-migration.lock";
    const HEAD_FILE_NAME: &'static str = ".head.json";
    const RECORD_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0state-migration-record\0v1\0");
    const HEAD_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0state-migration-head\0v1\0");
    const MAX_RECORDS: usize = 16;
    const MAX_RECORD_BYTES: u64 = 8 * 1024 * 1024;
    const MAX_TOTAL_BYTES: u64 = 16 * 1024 * 1024;
    const MAX_PHASE_BYTES: usize = 64;
    const MAX_SUBJECT_BYTES: usize = 128;
    const MAX_INSTANCE_ID_BYTES: usize = 128;
}

impl SnapshotSpec for StateMigrationManifestSpec {
    const SNAPSHOT_FORMAT_VERSION: u32 = 1;
    const LOCATOR_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0state-migration-locator\0v1\0");
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StateMigrationMode {
    DryRun,
    Apply,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StateMigrationStatus {
    Ready,
    Applied,
    AlreadyApplied,
    NoLegacyState,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LegacyStateEntry {
    pub store: String,
    pub file: String,
    pub present: bool,
    pub size: u64,
    pub sha256: Option<String>,
    pub legacy_checksum: Option<String>,
    pub file_identity: Option<FileIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StateMigrationManifest {
    pub version: u32,
    pub repository: RepositoryAuthBinding,
    pub entries: Vec<LegacyStateEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StateMigrationReport {
    pub version: u32,
    pub mode: StateMigrationMode,
    pub status: StateMigrationStatus,
    pub legacy_state_root: String,
    pub transaction_phase: Option<MigrationPhase>,
    pub entries: Vec<LegacyStateEntry>,
    pub hardened: bool,
    pub manifest_generation: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MigrationPhase {
    Planned,
    PermissionsHardened,
    ManifestPublished,
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MigrationTransaction {
    version: u32,
    phase: MigrationPhase,
    common_dir_identity: FileIdentity,
    state_root_identity: FileIdentity,
    original_state_mode: u32,
    original_file_modes: BTreeMap<String, u32>,
    created_locks: Vec<String>,
    entries: Vec<LegacyStateEntry>,
    checksum: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MigrationReceipt {
    version: u32,
    manifest_generation: u64,
    manifest_token: u64,
    manifest_sha256: String,
    entries: Vec<LegacyStateEntry>,
}

#[derive(Debug)]
struct LegacyPreflight {
    common_dir: PathBuf,
    common_dir_identity: FileIdentity,
    state_root: SafeRoot,
    original_state_mode: u32,
    original_file_modes: BTreeMap<String, u32>,
    entries: Vec<LegacyStateEntry>,
    existing_lock_names: Vec<String>,
    expected_bindings: ExpectedLegacyBindings,
}

/// Validates or applies the offline migration. `apply == false` is guaranteed
/// not to create, chmod, rewrite, or remove repository state.
pub(crate) fn migrate_repository_state(
    repo_path: impl AsRef<Path>,
    apply: bool,
) -> Result<StateMigrationReport> {
    let repo_path = repo_path.as_ref();
    let repository = Repository::discover(repo_path).with_context(|| {
        format!(
            "failed to discover repository for state migration from {}",
            repo_path.display()
        )
    })?;
    let common_dir = repository.commondir().to_path_buf();
    let state_path = common_dir.join("maco/state");
    if fs::symlink_metadata(&state_path).is_err() {
        return Ok(StateMigrationReport {
            version: MIGRATION_VERSION,
            mode: migration_mode(apply),
            status: StateMigrationStatus::NoLegacyState,
            legacy_state_root: ".git/maco/state".to_string(),
            transaction_phase: None,
            entries: missing_manifest_entries(),
            hardened: false,
            manifest_generation: None,
        });
    }

    let preflight = preflight_legacy_state(&common_dir, &state_path)?;
    let mut locks = acquire_existing_locks(&preflight)?;
    let transaction = load_transaction_if_present(&preflight)?;
    if let Some(transaction) = &transaction {
        validate_transaction(transaction, &preflight)?;
    }

    if manifest_exists(&preflight.state_root)? {
        let report = verify_existing_manifest(repo_path, apply, &preflight, transaction.as_ref())?;
        return Ok(report);
    }

    if !apply {
        return Ok(StateMigrationReport {
            version: MIGRATION_VERSION,
            mode: StateMigrationMode::DryRun,
            status: StateMigrationStatus::Ready,
            legacy_state_root: ".git/maco/state".to_string(),
            transaction_phase: transaction.as_ref().map(|value| value.phase),
            entries: preflight.entries.clone(),
            hardened: state_is_hardened(&preflight)?,
            manifest_generation: None,
        });
    }

    let transaction_root = SafeRoot::open_or_create(common_dir.join(TRANSACTION_ROOT_NAME))
        .context("failed to open owner-private state migration transaction root")?;
    let transaction_lock = KernelStateLock::acquire_direct(&transaction_root, TRANSACTION_LOCK)?;
    transaction_lock.verify_direct_binding(&transaction_root)?;

    create_and_acquire_missing_legacy_locks(&preflight, &mut locks)?;
    revalidate_preflight(&preflight)?;

    apply_migration(
        repo_path,
        &preflight,
        &transaction_root,
        transaction,
        locks,
        transaction_lock,
    )
}

fn migration_mode(apply: bool) -> StateMigrationMode {
    if apply {
        StateMigrationMode::Apply
    } else {
        StateMigrationMode::DryRun
    }
}

fn preflight_legacy_state(common_dir: &Path, state_path: &Path) -> Result<LegacyPreflight> {
    let common_root = SafeRoot::open_existing(common_dir)
        .context("Git common directory is unsafe for state migration")?;
    let state_root = SafeRoot::open_existing(state_path)
        .context("legacy state root is not a current-user-owned no-follow directory")?;
    let state_metadata = fs::symlink_metadata(state_root.path())?;
    validate_owned_directory(&state_metadata, state_root.path())?;

    let mut original_file_modes = BTreeMap::new();
    let mut existing_lock_names = Vec::new();
    let mut observed_files = BTreeSet::new();
    let mut count = 0_usize;
    for entry in fs::read_dir(state_root.path()).context("failed to enumerate legacy state root")? {
        let entry = entry.context("failed to inspect legacy state entry")?;
        count = count
            .checked_add(1)
            .context("legacy state entry count overflowed")?;
        if count > MAX_STATE_ENTRIES {
            bail!("legacy state root exceeds its bounded entry count");
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("legacy state entry name is not UTF-8"))?;
        let path = state_root.direct_child(&name)?;
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_dir() {
            if !is_known_authenticated_directory(&name) {
                bail!("unexpected directory in legacy state root: {name}");
            }
            validate_owned_directory(&metadata, &path)?;
            continue;
        }
        if !is_known_state_file(&name) {
            bail!("unexpected file in legacy state root: {name}");
        }
        validate_owned_regular_file(&metadata, &path, file_bound(&name))?;
        let mode = file_mode(&metadata);
        original_file_modes.insert(name.clone(), mode);
        observed_files.insert(name.clone());
        if is_known_lock_name(&name) {
            existing_lock_names.push(name);
        }
    }
    state_root.verify()?;
    common_root.verify()?;

    let managed_repository = if observed_files.contains("managed_worktrees.json") {
        let primary_workdir = common_root
            .path()
            .file_name()
            .is_some_and(|name| name == ".git")
            .then(|| common_root.path().parent())
            .flatten()
            .context(
                "managed worktree registry migration requires an embedded primary .git directory",
            )?;
        let primary_root = SafeRoot::open_existing(primary_workdir)
            .context("primary repository workdir is unsafe for managed state migration")?;
        Some(ManagedRepositoryBindingWire {
            common_dir: encode_persisted_path_wire(common_root.path())?,
            common_dir_identity: common_root.identity().clone(),
            repository_workdir: encode_persisted_path_wire(primary_root.path())?,
            repository_workdir_identity: primary_root.identity().clone(),
        })
    } else {
        None
    };
    let expected_bindings = ExpectedLegacyBindings {
        repository_state: LegacyRepositoryBinding {
            common_dir_path_checksum: stable_checksum(&filesystem_path_bytes(common_root.path())),
            common_dir_identity: common_root.identity().clone(),
        },
        managed_repository,
    };

    let mut entries = Vec::with_capacity(LEGACY_STORES.len());
    for (store, file_name) in LEGACY_STORES {
        if observed_files.contains(file_name) {
            let bytes =
                BoundedRegularReader::read_direct(&state_root, file_name, MAX_LEGACY_STATE_BYTES)?;
            let checksum = validate_legacy_checksum(file_name, &bytes, &expected_bindings)?;
            entries.push(LegacyStateEntry {
                store: store.to_string(),
                file: file_name.to_string(),
                present: true,
                size: u64::try_from(bytes.len()).context("legacy state size overflowed")?,
                sha256: Some(sha256_hex(&bytes)),
                legacy_checksum: Some(checksum),
                file_identity: Some(identity_for_path(state_root.direct_child(file_name)?)?),
            });
        } else {
            entries.push(missing_manifest_entry(store, file_name));
        }
    }

    existing_lock_names.sort();
    Ok(LegacyPreflight {
        common_dir: common_dir.to_path_buf(),
        common_dir_identity: common_root.identity().clone(),
        state_root,
        original_state_mode: file_mode(&state_metadata),
        original_file_modes,
        entries,
        existing_lock_names,
        expected_bindings,
    })
}

fn missing_manifest_entries() -> Vec<LegacyStateEntry> {
    LEGACY_STORES
        .iter()
        .map(|(store, file)| missing_manifest_entry(store, file))
        .collect()
}

fn missing_manifest_entry(store: &str, file: &str) -> LegacyStateEntry {
    LegacyStateEntry {
        store: store.to_string(),
        file: file.to_string(),
        present: false,
        size: 0,
        sha256: None,
        legacy_checksum: None,
        file_identity: None,
    }
}

fn is_known_authenticated_directory(name: &str) -> bool {
    matches!(
        name,
        MANIFEST_ROOT_NAME | JOURNAL_ROOT_NAME | "authenticated-effect-wals-v1"
    )
}

fn is_known_state_file(name: &str) -> bool {
    LEGACY_STORES.iter().any(|(_, file)| *file == name)
        || is_known_lock_name(name)
        || matches!(name, AUTH_KEY_FILE | AUTH_EPOCH_FILE)
}

fn is_known_lock_name(name: &str) -> bool {
    LEGACY_LOCKS.contains(&name)
        || matches!(
            name,
            AUTH_KEY_LOCK
                | "repository-mutation.lock"
                | ".journals.lock"
                | ".effect-wals.lock"
                | ".state-migrations.lock"
        )
        || name
            .strip_prefix("managed-worktree-")
            .and_then(|tail| tail.strip_suffix(".execution.lock"))
            .is_some_and(is_canonical_lock_component)
}

fn is_canonical_lock_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn file_bound(name: &str) -> u64 {
    if name.ends_with(".json") {
        MAX_LEGACY_STATE_BYTES
    } else if matches!(name, AUTH_KEY_FILE | AUTH_EPOCH_FILE) {
        32
    } else {
        0
    }
}

#[cfg(unix)]
fn validate_owned_directory(metadata: &fs::Metadata, path: &Path) -> Result<()> {
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() < 2
        || metadata.permissions().mode() & 0o022 != 0
    {
        bail!(
            "state migration directory is not a current-user-owned, non-writable no-follow directory: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_owned_directory(_metadata: &fs::Metadata, path: &Path) -> Result<()> {
    bail!(
        "state migration directory ACL validation is unsupported: {}",
        path.display()
    )
}

#[cfg(unix)]
fn validate_owned_regular_file(metadata: &fs::Metadata, path: &Path, max_bytes: u64) -> Result<()> {
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.len() > max_bytes
    {
        bail!(
            "legacy state entry is not a bounded current-user-owned single-link regular file: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_owned_regular_file(
    _metadata: &fs::Metadata,
    path: &Path,
    _max_bytes: u64,
) -> Result<()> {
    bail!(
        "legacy state file ACL validation is unsupported: {}",
        path.display()
    )
}

#[cfg(unix)]
fn file_mode(metadata: &fs::Metadata) -> u32 {
    metadata.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn file_mode(_metadata: &fs::Metadata) -> u32 {
    0
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyRepositoryBinding {
    common_dir_path_checksum: String,
    common_dir_identity: FileIdentity,
}

#[derive(Debug, Clone)]
struct ExpectedLegacyBindings {
    repository_state: LegacyRepositoryBinding,
    managed_repository: Option<ManagedRepositoryBindingWire>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyClaimsState {
    version: u32,
    checksum: String,
    repository: LegacyRepositoryBinding,
    next_token: u64,
    claims: Vec<PathClaim>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacySemanticState {
    version: u32,
    checksum: String,
    repository: LegacyRepositoryBinding,
    next_token: u64,
    intents: Vec<SemanticIntent>,
}

fn validate_legacy_checksum(
    file_name: &str,
    bytes: &[u8],
    expected: &ExpectedLegacyBindings,
) -> Result<String> {
    match file_name {
        "claims.json" => {
            let state: LegacyClaimsState = serde_json::from_slice(bytes)
                .context("failed to decode checksummed claims state")?;
            if state.version != 2 || state.next_token == 0 {
                bail!("claims state is not supported checksummed version 2");
            }
            if state.repository != expected.repository_state {
                bail!("claims state repository binding does not match the migration repository");
            }
            let payload = serde_json::to_vec(&(
                state.version,
                &state.repository,
                state.next_token,
                &state.claims,
            ))?;
            verify_legacy_checksum(&state.checksum, &payload, file_name)
        }
        "semantic_intents.json" => {
            let state: LegacySemanticState = serde_json::from_slice(bytes)
                .context("failed to decode checksummed semantic intent state")?;
            if state.version != 2 || state.next_token == 0 {
                bail!("semantic intent state is not supported checksummed version 2");
            }
            if state.repository != expected.repository_state {
                bail!(
                    "semantic intent state repository binding does not match the migration repository"
                );
            }
            let payload = serde_json::to_vec(&(
                state.version,
                &state.repository,
                state.next_token,
                &state.intents,
            ))?;
            verify_legacy_checksum(&state.checksum, &payload, file_name)
        }
        "managed_worktrees.json" => validate_managed_worktree_checksum(
            bytes,
            expected
                .managed_repository
                .as_ref()
                .context("managed worktree migration binding is unavailable")?,
        ),
        _ => bail!("unsupported legacy state file: {file_name}"),
    }
}

fn verify_legacy_checksum(checksum: &str, payload: &[u8], file_name: &str) -> Result<String> {
    let expected = stable_checksum(payload);
    if checksum != expected {
        bail!("legacy state checksum mismatch in {file_name}");
    }
    Ok(expected)
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedPathWire {
    platform: String,
    encoding: String,
    data: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagedRepositoryBindingWire {
    common_dir: PersistedPathWire,
    common_dir_identity: FileIdentity,
    repository_workdir: PersistedPathWire,
    repository_workdir_identity: FileIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagedWorktreeBindingWire {
    name: String,
    root: PersistedPathWire,
    root_identity: FileIdentity,
    path: PersistedPathWire,
    path_identity: FileIdentity,
    metadata_dir: PersistedPathWire,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ManagedWorktreeOperationKindWire {
    Create,
    Remove,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ManagedWorktreeOperationPhaseWire {
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
enum ManagedBranchOwnershipWire {
    Unknown,
    Preexisting,
    CreatedByMaco,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StagedWorktreeMetadataWire {
    metadata_dir: PersistedPathWire,
    metadata_dir_identity: FileIdentity,
    worktree_git_file_identity: FileIdentity,
    metadata_gitdir_file_identity: FileIdentity,
    metadata_head_file_identity: FileIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagedWorktreeOperationWire {
    kind: ManagedWorktreeOperationKindWire,
    phase: ManagedWorktreeOperationPhaseWire,
    name: String,
    root: PersistedPathWire,
    root_identity: FileIdentity,
    path: PersistedPathWire,
    prepared_path_identity: Option<FileIdentity>,
    #[serde(default)]
    staging_root: Option<PersistedPathWire>,
    staging_root_identity: Option<FileIdentity>,
    #[serde(default)]
    staging_path: Option<PersistedPathWire>,
    staged_path_identity: Option<FileIdentity>,
    staged_metadata: Option<StagedWorktreeMetadataWire>,
    branch: String,
    base_oid: String,
    branch_preexisting_oid: Option<String>,
    branch_ownership: ManagedBranchOwnershipWire,
    owned_branch_oid: Option<String>,
    binding: Option<ManagedWorktreeBindingWire>,
    delete_branch: bool,
    force: bool,
    expected_branch_oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    worktree_quarantine_path: Option<PersistedPathWire>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    worktree_quarantine_identity: Option<FileIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    metadata_quarantine_path: Option<PersistedPathWire>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    metadata_quarantine_identity: Option<FileIdentity>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagedWorktreeRegistryWire {
    version: u32,
    checksum: String,
    repository: ManagedRepositoryBindingWire,
    records: BTreeMap<String, ManagedWorktreeBindingWire>,
    operations: BTreeMap<String, ManagedWorktreeOperationWire>,
}

fn validate_managed_worktree_checksum(
    bytes: &[u8],
    expected_repository: &ManagedRepositoryBindingWire,
) -> Result<String> {
    let registry: ManagedWorktreeRegistryWire = serde_json::from_slice(bytes)
        .context("failed to decode checksummed managed worktree registry")?;
    if registry.version != 2 {
        bail!("managed worktree registry is not supported checksummed version 2");
    }
    if &registry.repository != expected_repository {
        bail!(
            "managed worktree registry repository binding does not match the migration repository"
        );
    }
    validate_managed_repository(&registry.repository)?;
    if registry.records.len() > 4_096 || registry.operations.len() > 4_096 {
        bail!("managed worktree registry exceeds its bounded record count");
    }
    for (name, binding) in &registry.records {
        if name != &binding.name || !is_canonical_lock_component(name) {
            bail!("managed worktree registry has a noncanonical record name");
        }
        validate_managed_binding(binding)?;
    }
    for (name, operation) in &registry.operations {
        if name != &operation.name || !is_canonical_lock_component(name) {
            bail!("managed worktree registry has a noncanonical operation name");
        }
        validate_managed_operation(operation)?;
    }
    let payload = serde_json::to_vec(&(
        registry.version,
        &registry.repository,
        &registry.records,
        &registry.operations,
    ))?;
    verify_legacy_checksum(&registry.checksum, &payload, "managed_worktrees.json")
}

fn validate_managed_repository(repository: &ManagedRepositoryBindingWire) -> Result<()> {
    decode_persisted_path_wire(&repository.common_dir)?;
    decode_persisted_path_wire(&repository.repository_workdir)?;
    validate_file_identity(&repository.common_dir_identity)?;
    validate_file_identity(&repository.repository_workdir_identity)
}

fn validate_managed_binding(binding: &ManagedWorktreeBindingWire) -> Result<()> {
    if !is_canonical_lock_component(&binding.name)
        || binding.branch.is_empty()
        || binding.branch.len() > 1_024
        || !valid_oid(&binding.base_oid)
        || !valid_oid(&binding.created_branch_oid)
    {
        bail!("managed worktree binding has malformed names, branch, or object ids");
    }
    for path in [&binding.root, &binding.path, &binding.metadata_dir] {
        decode_persisted_path_wire(path)?;
    }
    for identity in [
        &binding.root_identity,
        &binding.path_identity,
        &binding.metadata_dir_identity,
        &binding.worktree_git_file_identity,
        &binding.metadata_gitdir_file_identity,
        &binding.metadata_head_file_identity,
    ] {
        validate_file_identity(identity)?;
    }
    Ok(())
}

fn validate_managed_operation(operation: &ManagedWorktreeOperationWire) -> Result<()> {
    if !is_canonical_lock_component(&operation.name)
        || operation.branch.is_empty()
        || operation.branch.len() > 1_024
        || !valid_oid(&operation.base_oid)
        || !valid_optional_oid(operation.branch_preexisting_oid.as_deref())
        || !valid_optional_oid(operation.owned_branch_oid.as_deref())
        || !valid_optional_oid(operation.expected_branch_oid.as_deref())
    {
        bail!("managed worktree operation has malformed names, branch, or object ids");
    }
    for path in [&operation.root, &operation.path] {
        decode_persisted_path_wire(path)?;
    }
    for path in [
        operation.staging_root.as_ref(),
        operation.staging_path.as_ref(),
        operation.worktree_quarantine_path.as_ref(),
        operation.metadata_quarantine_path.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        decode_persisted_path_wire(path)?;
    }
    validate_file_identity(&operation.root_identity)?;
    for identity in [
        operation.prepared_path_identity.as_ref(),
        operation.staging_root_identity.as_ref(),
        operation.staged_path_identity.as_ref(),
        operation.worktree_quarantine_identity.as_ref(),
        operation.metadata_quarantine_identity.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        validate_file_identity(identity)?;
    }
    if let Some(staged) = &operation.staged_metadata {
        decode_persisted_path_wire(&staged.metadata_dir)?;
        for identity in [
            &staged.metadata_dir_identity,
            &staged.worktree_git_file_identity,
            &staged.metadata_gitdir_file_identity,
            &staged.metadata_head_file_identity,
        ] {
            validate_file_identity(identity)?;
        }
    }
    if let Some(binding) = &operation.binding {
        validate_managed_binding(binding)?;
    }
    validate_managed_operation_phase(operation)?;
    Ok(())
}

fn validate_managed_operation_phase(operation: &ManagedWorktreeOperationWire) -> Result<()> {
    let create_phase = matches!(
        operation.phase,
        ManagedWorktreeOperationPhaseWire::CreateIntent
            | ManagedWorktreeOperationPhaseWire::CreatePrepared
            | ManagedWorktreeOperationPhaseWire::CreateStaged
            | ManagedWorktreeOperationPhaseWire::CreateObserved
    );
    let remove_phase = !create_phase;
    if (operation.kind == ManagedWorktreeOperationKindWire::Create) != create_phase
        || (operation.kind == ManagedWorktreeOperationKindWire::Remove) != remove_phase
    {
        bail!("managed worktree operation kind does not match its phase family");
    }
    if create_phase {
        if operation.staging_root.is_none()
            || operation.staging_path.is_none()
            || operation.delete_branch
            || operation.force
            || operation.expected_branch_oid.is_some()
            || operation.worktree_quarantine_path.is_some()
            || operation.worktree_quarantine_identity.is_some()
            || operation.metadata_quarantine_path.is_some()
            || operation.metadata_quarantine_identity.is_some()
        {
            bail!("managed create operation has impossible removal or staging fields");
        }
        let prepared = !matches!(
            operation.phase,
            ManagedWorktreeOperationPhaseWire::CreateIntent
        );
        let staged = matches!(
            operation.phase,
            ManagedWorktreeOperationPhaseWire::CreateStaged
                | ManagedWorktreeOperationPhaseWire::CreateObserved
        );
        let observed = matches!(
            operation.phase,
            ManagedWorktreeOperationPhaseWire::CreateObserved
        );
        if operation.prepared_path_identity.is_some() != prepared
            || operation.staging_root_identity.is_some() != prepared
            || operation.staged_path_identity.is_some() != staged
            || operation.staged_metadata.is_some() != staged
            || operation.binding.is_some() != observed
        {
            bail!("managed create operation fields do not match its durable phase");
        }
        return Ok(());
    }

    if operation.staging_root.is_some()
        || operation.staging_root_identity.is_some()
        || operation.staging_path.is_some()
        || operation.staged_path_identity.is_some()
        || operation.staged_metadata.is_some()
        || operation.prepared_path_identity.is_none()
        || operation.binding.is_none()
        || operation.expected_branch_oid.is_none()
        || operation.worktree_quarantine_path.is_none()
        || operation.metadata_quarantine_path.is_none()
    {
        bail!("managed remove operation is missing required binding or quarantine fields");
    }
    let after_worktree_quarantine = !matches!(
        operation.phase,
        ManagedWorktreeOperationPhaseWire::RemovePrepared
    );
    let after_metadata_quarantine = matches!(
        operation.phase,
        ManagedWorktreeOperationPhaseWire::MetadataQuarantined
            | ManagedWorktreeOperationPhaseWire::WorktreeDeleted
            | ManagedWorktreeOperationPhaseWire::MetadataDeleted
            | ManagedWorktreeOperationPhaseWire::BranchDeleted
    );
    if operation.worktree_quarantine_identity.is_some() != after_worktree_quarantine
        || operation.metadata_quarantine_identity.is_some() != after_metadata_quarantine
    {
        bail!("managed remove operation quarantine identities do not match its phase");
    }
    Ok(())
}

fn validate_file_identity(identity: &FileIdentity) -> Result<()> {
    if identity.file == 0 {
        bail!("managed worktree registry contains an invalid filesystem identity");
    }
    Ok(())
}

fn valid_oid(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_optional_oid(value: Option<&str>) -> bool {
    value.is_none_or(valid_oid)
}

fn decode_persisted_path_wire(path: &PersistedPathWire) -> Result<PathBuf> {
    if path.platform != std::env::consts::OS
        || path.encoding != "unix-bytes-hex-v1"
        || path.data.is_empty()
        || !path.data.len().is_multiple_of(2)
        || path.data.len() > 128 * 1024
        || !path
            .data
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("managed worktree registry contains a malformed persisted path");
    }
    #[cfg(unix)]
    {
        let mut bytes = Vec::with_capacity(path.data.len() / 2);
        for pair in path.data.as_bytes().chunks_exact(2) {
            let digit = |byte| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                _ => None,
            };
            bytes.push(
                digit(pair[0])
                    .and_then(|high| digit(pair[1]).map(|low| (high << 4) | low))
                    .context("managed worktree path hex is malformed")?,
            );
        }
        if bytes.contains(&0) {
            bail!("managed worktree path contains a NUL byte");
        }
        let decoded = PathBuf::from(std::ffi::OsString::from_vec(bytes));
        if !decoded.is_absolute()
            || decoded.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            })
        {
            bail!("managed worktree path is not absolute and lexically canonical");
        }
        let mut normalized = PathBuf::new();
        for component in decoded.components() {
            match component {
                std::path::Component::RootDir => normalized.push(std::path::MAIN_SEPARATOR_STR),
                std::path::Component::Normal(value) => normalized.push(value),
                std::path::Component::Prefix(_) => normalized.push(component.as_os_str()),
                std::path::Component::CurDir | std::path::Component::ParentDir => {
                    bail!("managed worktree path is not lexically canonical")
                }
            }
        }
        if normalized.as_os_str() != decoded.as_os_str() {
            bail!("managed worktree path contains repeated or trailing separators");
        }
        Ok(decoded)
    }
    #[cfg(not(unix))]
    bail!("managed worktree path decoding is unsupported on this platform")
}

fn encode_persisted_path_wire(path: &Path) -> Result<PersistedPathWire> {
    #[cfg(unix)]
    {
        let bytes = path.as_os_str().as_bytes();
        if bytes.is_empty() || bytes.len() > 64 * 1024 || bytes.contains(&0) {
            bail!("managed worktree path exceeds its canonical bound");
        }
        let mut data = String::with_capacity(bytes.len() * 2);
        use std::fmt::Write as _;
        for byte in bytes {
            write!(&mut data, "{byte:02x}")?;
        }
        let wire = PersistedPathWire {
            platform: std::env::consts::OS.to_string(),
            encoding: "unix-bytes-hex-v1".to_string(),
            data,
        };
        decode_persisted_path_wire(&wire)?;
        Ok(wire)
    }
    #[cfg(not(unix))]
    bail!("managed worktree path encoding is unsupported on this platform")
}

#[cfg(unix)]
fn filesystem_path_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().as_bytes().to_vec()
}

#[cfg(windows)]
fn filesystem_path_bytes(path: &Path) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect()
}

#[cfg(not(any(unix, windows)))]
fn filesystem_path_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().to_string_lossy().as_bytes().to_vec()
}

#[derive(Debug)]
struct MigrationHeldLock {
    name: String,
    file: File,
    identity: FileIdentity,
    created: bool,
}

impl MigrationHeldLock {
    fn open_existing(root: &SafeRoot, name: &str) -> Result<Self> {
        let path = root.direct_child(name)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options
            .open(&path)
            .with_context(|| format!("failed to open legacy state lock {name}"))?;
        let metadata = file.metadata()?;
        validate_owned_regular_file(&metadata, &path, 0)?;
        try_exclusive_flock(&file, &path)?;
        let lock = Self {
            name: name.to_string(),
            identity: identity_for_path(&path)?,
            file,
            created: false,
        };
        lock.verify(root)?;
        Ok(lock)
    }

    fn create(root: &SafeRoot, name: &str) -> Result<Self> {
        let path = root.direct_child(name)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options
            .open(&path)
            .with_context(|| format!("failed to create missing legacy state lock {name}"))?;
        file.sync_all()?;
        try_exclusive_flock(&file, &path)?;
        let lock = Self {
            name: name.to_string(),
            identity: identity_for_path(&path)?,
            file,
            created: true,
        };
        lock.verify(root)?;
        sync_directory(root.path())?;
        Ok(lock)
    }

    fn verify(&self, root: &SafeRoot) -> Result<()> {
        root.verify()?;
        let path = root.direct_child(&self.name)?;
        let metadata = self.file.metadata()?;
        validate_owned_regular_file(&metadata, &path, 0)?;
        if identity_for_path(path)? != self.identity {
            bail!(
                "legacy state lock path was rebound while held: {}",
                self.name
            );
        }
        Ok(())
    }
}

impl Drop for MigrationHeldLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[cfg(unix)]
fn try_exclusive_flock(file: &File, path: &Path) -> Result<()> {
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = std::io::Error::last_os_error();
        bail!(
            "legacy state lock is active; migration requires an offline repository: {} ({error})",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn try_exclusive_flock(_file: &File, path: &Path) -> Result<()> {
    bail!(
        "nonblocking state lock validation is unsupported: {}",
        path.display()
    )
}

fn acquire_existing_locks(preflight: &LegacyPreflight) -> Result<Vec<MigrationHeldLock>> {
    let mut locks = Vec::with_capacity(preflight.existing_lock_names.len());
    for name in &preflight.existing_lock_names {
        locks.push(MigrationHeldLock::open_existing(
            &preflight.state_root,
            name,
        )?);
    }
    revalidate_preflight(preflight)?;
    Ok(locks)
}

fn create_and_acquire_missing_legacy_locks(
    preflight: &LegacyPreflight,
    locks: &mut Vec<MigrationHeldLock>,
) -> Result<()> {
    let held = locks
        .iter()
        .map(|lock| lock.name.as_str())
        .collect::<BTreeSet<_>>();
    let missing = LEGACY_LOCKS
        .iter()
        .filter(|name| !held.contains(**name))
        .copied()
        .collect::<Vec<_>>();
    for name in missing {
        locks.push(MigrationHeldLock::create(&preflight.state_root, name)?);
    }
    for lock in locks.iter() {
        lock.verify(&preflight.state_root)?;
    }
    Ok(())
}

fn revalidate_preflight(preflight: &LegacyPreflight) -> Result<()> {
    preflight.state_root.verify()?;
    for entry in &preflight.entries {
        let path = preflight.state_root.direct_child(&entry.file)?;
        if !entry.present {
            if fs::symlink_metadata(path).is_ok() {
                bail!(
                    "legacy state appeared during migration preflight: {}",
                    entry.file
                );
            }
            continue;
        }
        let bytes = BoundedRegularReader::read_direct(
            &preflight.state_root,
            &entry.file,
            MAX_LEGACY_STATE_BYTES,
        )?;
        if Some(sha256_hex(&bytes)) != entry.sha256
            || Some(identity_for_path(path)?) != entry.file_identity
        {
            bail!(
                "legacy state changed during migration preflight: {}",
                entry.file
            );
        }
        validate_legacy_checksum(&entry.file, &bytes, &preflight.expected_bindings)?;
    }
    preflight.state_root.verify()
}

fn manifest_exists(state_root: &SafeRoot) -> Result<bool> {
    state_root.direct_child_exists(MANIFEST_ROOT_NAME)
}

fn load_transaction_if_present(
    preflight: &LegacyPreflight,
) -> Result<Option<MigrationTransaction>> {
    let root_path = preflight.common_dir.join(TRANSACTION_ROOT_NAME);
    let metadata = match fs::symlink_metadata(&root_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("failed to inspect migration transaction root"),
    };
    validate_owned_directory(&metadata, &root_path)?;
    if file_mode(&metadata) != 0o700 {
        bail!("migration transaction root is not owner-private mode 0700");
    }
    let root = SafeRoot::open_existing(&root_path)?;
    for entry in fs::read_dir(root.path())? {
        let name = entry?.file_name();
        if !matches!(
            name.to_str(),
            Some(TRANSACTION_FILE | RECEIPT_FILE | TRANSACTION_LOCK)
        ) {
            bail!("unexpected entry in migration transaction root");
        }
    }
    if !root.direct_child_exists(TRANSACTION_FILE)? {
        return Ok(None);
    }
    let bytes = BoundedRegularReader::read_direct(&root, TRANSACTION_FILE, MAX_TRANSACTION_BYTES)?;
    let transaction: MigrationTransaction =
        serde_json::from_slice(&bytes).context("failed to decode migration transaction")?;
    let expected = transaction_checksum(&transaction)?;
    if transaction.checksum != expected {
        bail!("migration transaction checksum mismatch");
    }
    Ok(Some(transaction))
}

fn validate_transaction(
    transaction: &MigrationTransaction,
    preflight: &LegacyPreflight,
) -> Result<()> {
    if transaction.version != MIGRATION_VERSION
        || transaction.common_dir_identity != preflight.common_dir_identity
        || transaction.state_root_identity != *preflight.state_root.identity()
        || transaction.entries != preflight.entries
    {
        bail!("migration transaction does not match the current repository state");
    }
    Ok(())
}

fn transaction_checksum(transaction: &MigrationTransaction) -> Result<String> {
    let payload = serde_json::to_vec(&(
        transaction.version,
        transaction.phase,
        &transaction.common_dir_identity,
        &transaction.state_root_identity,
        transaction.original_state_mode,
        &transaction.original_file_modes,
        &transaction.created_locks,
        &transaction.entries,
    ))?;
    Ok(stable_checksum(&payload))
}

fn write_transaction(
    root: &SafeRoot,
    lock: &KernelStateLock,
    transaction: &mut MigrationTransaction,
) -> Result<()> {
    transaction.checksum.clear();
    transaction.checksum = transaction_checksum(transaction)?;
    let mut bytes = serde_json::to_vec_pretty(transaction)?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_TRANSACTION_BYTES {
        bail!("migration transaction exceeds its size bound");
    }
    AtomicStateWriter::scavenge_direct_temps(root, TRANSACTION_FILE)?;
    AtomicStateWriter::write_direct_fenced(root, TRANSACTION_FILE, &bytes, || {
        lock.verify_direct_binding(root)
    })
}

fn apply_migration(
    repo_path: &Path,
    preflight: &LegacyPreflight,
    transaction_root: &SafeRoot,
    existing_transaction: Option<MigrationTransaction>,
    mut locks: Vec<MigrationHeldLock>,
    transaction_lock: KernelStateLock,
) -> Result<StateMigrationReport> {
    let mut transaction = existing_transaction.unwrap_or_else(|| MigrationTransaction {
        version: MIGRATION_VERSION,
        phase: MigrationPhase::Planned,
        common_dir_identity: preflight.common_dir_identity.clone(),
        state_root_identity: preflight.state_root.identity().clone(),
        original_state_mode: preflight.original_state_mode,
        original_file_modes: preflight.original_file_modes.clone(),
        created_locks: Vec::new(),
        entries: preflight.entries.clone(),
        checksum: String::new(),
    });
    for lock in &locks {
        if lock.created && !transaction.created_locks.contains(&lock.name) {
            transaction.created_locks.push(lock.name.clone());
        }
    }
    transaction.created_locks.sort();
    transaction.created_locks.dedup();
    write_transaction(transaction_root, &transaction_lock, &mut transaction)?;

    if transaction.phase == MigrationPhase::Planned {
        if let Err(error) = harden_state(preflight, &locks) {
            return rollback_error(
                error,
                preflight,
                transaction_root,
                &transaction_lock,
                &transaction,
                &locks,
            );
        }
        transaction.phase = MigrationPhase::PermissionsHardened;
        if let Err(error) = write_transaction(transaction_root, &transaction_lock, &mut transaction)
        {
            return rollback_error(
                error,
                preflight,
                transaction_root,
                &transaction_lock,
                &transaction,
                &locks,
            );
        }
    } else {
        ensure_hardened_state(preflight)?;
    }

    if let Some(action) = take_migration_fault(MigrationFaultPoint::AfterPermissions) {
        let error = anyhow::anyhow!("injected state migration fault after permission hardening");
        if action == MigrationFaultAction::Crash {
            return Err(error.context("migration transaction remains forward-recoverable"));
        }
        return rollback_error(
            error,
            preflight,
            transaction_root,
            &transaction_lock,
            &transaction,
            &locks,
        );
    }

    // A pre-existing legacy authentication lock has already been proven idle;
    // release only that descriptor before the canonical key writer acquires
    // the same inode. All consumer locks remain held until return.
    if let Some(index) = locks.iter().position(|lock| lock.name == AUTH_KEY_LOCK) {
        locks.remove(index);
    }
    let key_preexisted = preflight.state_root.direct_child_exists(AUTH_KEY_FILE)?;
    let writer = match repository_auth_writer(repo_path) {
        Ok(writer) => writer,
        Err(error) => {
            let key_now_exists = preflight.state_root.direct_child_exists(AUTH_KEY_FILE)?;
            if key_now_exists && !key_preexisted {
                return Err(error.context(
                    "authentication bootstrap crossed its durable key boundary; rerun apply to recover forward",
                ));
            }
            return rollback_error(
                error,
                preflight,
                transaction_root,
                &transaction_lock,
                &transaction,
                &locks,
            );
        }
    };
    let binding = writer.authenticator().binding().clone();
    let manifest = StateMigrationManifest {
        version: MIGRATION_VERSION,
        repository: binding,
        entries: preflight.entries.clone(),
    };
    let authenticator = writer.into_authenticator()?;
    let store = match AuthenticatedSnapshotStore::<
        StateMigrationManifestSpec,
        StateMigrationManifest,
    >::create(authenticator, MANIFEST_INSTANCE_ID, 1, manifest.clone())
    {
        Ok(store) => store,
        Err(error) => {
            return Err(error.context(
                "authentication state is durable; migration remains forward-recoverable",
            ));
        }
    };
    transaction.phase = MigrationPhase::ManifestPublished;
    write_transaction(transaction_root, &transaction_lock, &mut transaction)?;

    if take_migration_fault(MigrationFaultPoint::AfterManifest) == Some(MigrationFaultAction::Crash)
    {
        return Err(anyhow::anyhow!(
            "injected state migration crash after signed manifest publication; rerun apply"
        ));
    }

    let snapshot = store.current();
    write_receipt(
        transaction_root,
        &transaction_lock,
        &manifest,
        snapshot.generation,
        snapshot.token,
    )?;
    transaction.phase = MigrationPhase::Completed;
    write_transaction(transaction_root, &transaction_lock, &mut transaction)?;
    transaction_lock.verify_direct_binding(transaction_root)?;
    for lock in &locks {
        lock.verify(&preflight.state_root)?;
    }

    Ok(StateMigrationReport {
        version: MIGRATION_VERSION,
        mode: StateMigrationMode::Apply,
        status: StateMigrationStatus::Applied,
        legacy_state_root: ".git/maco/state".to_string(),
        transaction_phase: Some(MigrationPhase::Completed),
        entries: preflight.entries.clone(),
        hardened: true,
        manifest_generation: Some(snapshot.generation),
    })
}

fn verify_existing_manifest(
    repo_path: &Path,
    apply: bool,
    preflight: &LegacyPreflight,
    transaction: Option<&MigrationTransaction>,
) -> Result<StateMigrationReport> {
    let authenticator = repository_authenticator_key_only(repo_path)?;
    authenticator.verify_epoch()?;
    let store = AuthenticatedSnapshotStore::<StateMigrationManifestSpec, StateMigrationManifest>::open_instance(
        authenticator,
        MANIFEST_INSTANCE_ID,
    )?;
    let snapshot = store.current();
    if snapshot.generation != 1
        || snapshot.token != 1
        || snapshot.value.version != MIGRATION_VERSION
        || snapshot.value.repository != store.identity().repository
        || snapshot.value.entries != preflight.entries
    {
        bail!("signed state migration manifest does not match the current legacy state");
    }

    let mut phase = transaction.map(|value| value.phase);
    if apply && phase != Some(MigrationPhase::Completed) {
        let mut transaction = transaction
            .cloned()
            .context("signed migration manifest is missing its durable transaction")?;
        let transaction_root =
            SafeRoot::open_existing(preflight.common_dir.join(TRANSACTION_ROOT_NAME))?;
        let lock = KernelStateLock::acquire_direct(&transaction_root, TRANSACTION_LOCK)?;
        write_receipt(
            &transaction_root,
            &lock,
            &snapshot.value,
            snapshot.generation,
            snapshot.token,
        )?;
        transaction.phase = MigrationPhase::Completed;
        write_transaction(&transaction_root, &lock, &mut transaction)?;
        phase = Some(MigrationPhase::Completed);
    }

    Ok(StateMigrationReport {
        version: MIGRATION_VERSION,
        mode: migration_mode(apply),
        status: StateMigrationStatus::AlreadyApplied,
        legacy_state_root: ".git/maco/state".to_string(),
        transaction_phase: phase,
        entries: preflight.entries.clone(),
        hardened: state_is_hardened(preflight)?,
        manifest_generation: Some(snapshot.generation),
    })
}

fn write_receipt(
    root: &SafeRoot,
    lock: &KernelStateLock,
    manifest: &StateMigrationManifest,
    generation: u64,
    token: u64,
) -> Result<()> {
    let manifest_bytes = serde_json::to_vec(manifest)?;
    let receipt = MigrationReceipt {
        version: MIGRATION_VERSION,
        manifest_generation: generation,
        manifest_token: token,
        manifest_sha256: sha256_hex(&manifest_bytes),
        entries: manifest.entries.clone(),
    };
    let mut bytes = serde_json::to_vec_pretty(&receipt)?;
    bytes.push(b'\n');
    AtomicStateWriter::scavenge_direct_temps(root, RECEIPT_FILE)?;
    AtomicStateWriter::write_direct_fenced(root, RECEIPT_FILE, &bytes, || {
        lock.verify_direct_binding(root)
    })
}

#[cfg(unix)]
fn harden_state(preflight: &LegacyPreflight, locks: &[MigrationHeldLock]) -> Result<()> {
    revalidate_preflight(preflight)?;
    for entry in fs::read_dir(preflight.state_root.path())? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_file() {
            validate_owned_regular_file(
                &metadata,
                &path,
                file_bound(entry.file_name().to_str().unwrap_or("")),
            )?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        } else if metadata.file_type().is_dir() {
            validate_owned_directory(&metadata, &path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        } else {
            bail!("unsafe state entry appeared during permission hardening");
        }
    }
    fs::set_permissions(
        preflight.state_root.path(),
        fs::Permissions::from_mode(0o700),
    )?;
    sync_directory(preflight.state_root.path())?;
    for lock in locks {
        lock.verify(&preflight.state_root)?;
    }
    ensure_hardened_state(preflight)
}

#[cfg(not(unix))]
fn harden_state(_preflight: &LegacyPreflight, _locks: &[MigrationHeldLock]) -> Result<()> {
    bail!("state permission hardening is unsupported on this platform")
}

fn ensure_hardened_state(preflight: &LegacyPreflight) -> Result<()> {
    if !state_is_hardened(preflight)? {
        bail!("migration transaction says permissions are hardened but state is not private");
    }
    Ok(())
}

fn state_is_hardened(preflight: &LegacyPreflight) -> Result<bool> {
    if file_mode(&fs::symlink_metadata(preflight.state_root.path())?) != 0o700 {
        return Ok(false);
    }
    for entry in fs::read_dir(preflight.state_root.path())? {
        let metadata = fs::symlink_metadata(entry?.path())?;
        if metadata.file_type().is_file() && file_mode(&metadata) != 0o600 {
            return Ok(false);
        }
        if metadata.file_type().is_dir() && file_mode(&metadata) != 0o700 {
            return Ok(false);
        }
    }
    Ok(true)
}

fn rollback_error<T>(
    error: anyhow::Error,
    preflight: &LegacyPreflight,
    transaction_root: &SafeRoot,
    transaction_lock: &KernelStateLock,
    transaction: &MigrationTransaction,
    locks: &[MigrationHeldLock],
) -> Result<T> {
    match rollback_permissions(preflight, transaction, locks) {
        Ok(()) => {
            let mut reset = transaction.clone();
            reset.phase = MigrationPhase::Planned;
            if let Err(reset_error) =
                write_transaction(transaction_root, transaction_lock, &mut reset)
            {
                return Err(error.context(format!(
                    "state migration rolled back, but its transaction could not be reset: {reset_error:#}"
                )));
            }
            Err(error.context("state migration rolled back before authentication publication"))
        }
        Err(rollback_error) => Err(error.context(format!(
            "state migration also failed to roll back safely: {rollback_error:#}"
        ))),
    }
}

#[cfg(unix)]
fn rollback_permissions(
    preflight: &LegacyPreflight,
    transaction: &MigrationTransaction,
    locks: &[MigrationHeldLock],
) -> Result<()> {
    for (name, mode) in &transaction.original_file_modes {
        let path = preflight.state_root.direct_child(name)?;
        if fs::symlink_metadata(&path).is_ok() {
            fs::set_permissions(path, fs::Permissions::from_mode(*mode))?;
        }
    }
    for name in &transaction.created_locks {
        if let Some(lock) = locks.iter().find(|lock| &lock.name == name) {
            lock.verify(&preflight.state_root)?;
        }
        let path = preflight.state_root.direct_child(name)?;
        if fs::symlink_metadata(&path).is_ok() {
            fs::remove_file(path)?;
        }
    }
    fs::set_permissions(
        preflight.state_root.path(),
        fs::Permissions::from_mode(transaction.original_state_mode),
    )?;
    sync_directory(preflight.state_root.path())
}

#[cfg(not(unix))]
fn rollback_permissions(
    _preflight: &LegacyPreflight,
    _transaction: &MigrationTransaction,
    _locks: &[MigrationHeldLock],
) -> Result<()> {
    bail!("state permission rollback is unsupported on this platform")
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<()> {
    bail!("directory durability is unsupported on this platform")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MigrationFaultPoint {
    AfterPermissions,
    AfterManifest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum MigrationFaultAction {
    Error,
    Crash,
}

#[cfg(test)]
thread_local! {
    static MIGRATION_FAULT: std::cell::Cell<Option<(MigrationFaultPoint, MigrationFaultAction)>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn set_migration_fault(point: MigrationFaultPoint, action: MigrationFaultAction) {
    MIGRATION_FAULT.with(|slot| slot.set(Some((point, action))));
}

#[cfg(test)]
fn take_migration_fault(point: MigrationFaultPoint) -> Option<MigrationFaultAction> {
    MIGRATION_FAULT.with(|slot| {
        let value = slot.get();
        if value.is_some_and(|(candidate, _)| candidate == point) {
            slot.set(None);
            value.map(|(_, action)| action)
        } else {
            None
        }
    })
}

#[cfg(not(test))]
fn take_migration_fault(_point: MigrationFaultPoint) -> Option<MigrationFaultAction> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync_store::SyncStore;
    use tempfile::TempDir;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn repository_with_claims() -> (TempDir, PathBuf, PathBuf) {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("repo");
        let repository = Repository::init(&path).expect("repository");
        SyncStore::open(&path)
            .expect("sync store")
            .claim_paths("migration-test", [Path::new("src")])
            .expect("claim");
        let state = repository.commondir().join("maco/state");
        (temp, path, state)
    }

    fn empty_repository_state() -> (TempDir, PathBuf, SafeRoot) {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("repo");
        let repository = Repository::init(&path).expect("repository");
        let state = SafeRoot::open_or_create(repository.commondir().join("maco/state"))
            .expect("state root");
        (temp, path, state)
    }

    fn expected_bindings_for(path: &Path) -> ExpectedLegacyBindings {
        let repository = Repository::open(path).expect("repository");
        let common = SafeRoot::open_existing(repository.commondir()).expect("common root");
        let primary =
            SafeRoot::open_existing(common.path().parent().expect("embedded primary workdir"))
                .expect("primary root");
        ExpectedLegacyBindings {
            repository_state: LegacyRepositoryBinding {
                common_dir_path_checksum: stable_checksum(&filesystem_path_bytes(common.path())),
                common_dir_identity: common.identity().clone(),
            },
            managed_repository: Some(ManagedRepositoryBindingWire {
                common_dir: encode_persisted_path_wire(common.path()).expect("common path"),
                common_dir_identity: common.identity().clone(),
                repository_workdir: encode_persisted_path_wire(primary.path())
                    .expect("primary path"),
                repository_workdir_identity: primary.identity().clone(),
            }),
        }
    }

    #[cfg(unix)]
    fn make_legacy_permissions(state: &Path) {
        fs::set_permissions(state, fs::Permissions::from_mode(0o755)).expect("state mode");
        for name in ["claims.json", "claims.lock"] {
            fs::set_permissions(state.join(name), fs::Permissions::from_mode(0o644))
                .expect("legacy file mode");
        }
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    }

    #[cfg(unix)]
    #[test]
    fn dry_run_is_non_mutating_and_apply_is_signed_and_idempotent() {
        let (_temp, path, state) = repository_with_claims();
        make_legacy_permissions(&state);
        let repo = Repository::open(&path).expect("repo");
        let transaction_root = repo.commondir().join(TRANSACTION_ROOT_NAME);

        let dry = migrate_repository_state(&path, false).expect("dry run");
        assert_eq!(dry.status, StateMigrationStatus::Ready);
        assert!(!dry.hardened);
        assert_eq!(mode(&state), 0o755);
        assert_eq!(mode(&state.join("claims.json")), 0o644);
        assert!(!transaction_root.exists());

        let applied = migrate_repository_state(&path, true).expect("apply");
        assert_eq!(applied.status, StateMigrationStatus::Applied);
        assert_eq!(applied.manifest_generation, Some(1));
        assert!(applied
            .entries
            .iter()
            .any(|entry| entry.store == "managed_worktrees" && !entry.present));
        assert_eq!(mode(&state), 0o700);
        for name in [
            "claims.json",
            "claims.lock",
            "semantic_intents.lock",
            "managed_worktrees.lock",
        ] {
            assert_eq!(mode(&state.join(name)), 0o600);
        }
        assert!(transaction_root.join(RECEIPT_FILE).is_file());

        let repeated = migrate_repository_state(&path, true).expect("idempotent apply");
        assert_eq!(repeated.status, StateMigrationStatus::AlreadyApplied);
        assert_eq!(repeated.transaction_phase, Some(MigrationPhase::Completed));
    }

    #[cfg(unix)]
    #[test]
    fn corrupt_checksum_refuses_without_any_change() {
        let (_temp, path, state) = repository_with_claims();
        make_legacy_permissions(&state);
        let claims = state.join("claims.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&claims).expect("claims")).expect("JSON");
        value["next_token"] = serde_json::json!(999);
        fs::write(&claims, serde_json::to_vec_pretty(&value).expect("encode"))
            .expect("tamper checksum");
        fs::set_permissions(&claims, fs::Permissions::from_mode(0o644)).expect("mode");

        let error = migrate_repository_state(&path, false).expect_err("checksum mismatch");
        assert!(error.to_string().contains("checksum mismatch"));
        assert_eq!(mode(&state), 0o755);
        let repo = Repository::open(&path).expect("repo");
        assert!(!repo.commondir().join(TRANSACTION_ROOT_NAME).exists());
    }

    #[cfg(unix)]
    #[test]
    fn active_legacy_lock_refuses_without_changes() {
        let (_temp, path, state) = repository_with_claims();
        let root = SafeRoot::open_existing(&state).expect("state root");
        let _held = KernelStateLock::acquire_direct(&root, "claims.lock").expect("held lock");
        let error = migrate_repository_state(&path, false).expect_err("active lock refusal");
        assert!(error.to_string().contains("active"));
        assert_eq!(mode(&state), 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn normal_fault_rolls_back_while_crash_fault_recovers_forward() {
        let (_temp, path, state) = repository_with_claims();
        make_legacy_permissions(&state);
        set_migration_fault(
            MigrationFaultPoint::AfterPermissions,
            MigrationFaultAction::Error,
        );
        migrate_repository_state(&path, true).expect_err("normal injected failure");
        assert_eq!(mode(&state), 0o755);
        assert_eq!(mode(&state.join("claims.json")), 0o644);
        assert!(!state.join(AUTH_KEY_FILE).exists());

        set_migration_fault(
            MigrationFaultPoint::AfterPermissions,
            MigrationFaultAction::Crash,
        );
        migrate_repository_state(&path, true).expect_err("crash injected failure");
        assert_eq!(mode(&state), 0o700);
        assert_eq!(mode(&state.join("claims.json")), 0o600);
        let recovered = migrate_repository_state(&path, true).expect("forward recovery");
        assert_eq!(recovered.status, StateMigrationStatus::Applied);
    }

    #[test]
    fn foreign_claims_state_is_refused_even_with_a_valid_checksum() {
        let (_source_temp, _source_path, source_state) = repository_with_claims();
        let (_target_temp, target_path, target_state) = empty_repository_state();
        AtomicStateWriter::write_direct(
            &target_state,
            "claims.json",
            &fs::read(source_state.join("claims.json")).expect("source claims"),
        )
        .expect("copy foreign claims");
        let error = migrate_repository_state(&target_path, false)
            .expect_err("foreign claims binding must fail");
        assert!(error.to_string().contains("repository binding"));
    }

    #[test]
    fn foreign_semantic_state_is_refused_even_with_a_valid_checksum() {
        let (_source_temp, source_path, _source_state) = repository_with_claims();
        let source_binding = expected_bindings_for(&source_path).repository_state;
        let mut foreign = LegacySemanticState {
            version: 2,
            checksum: String::new(),
            repository: source_binding,
            next_token: 1,
            intents: Vec::new(),
        };
        foreign.checksum = stable_checksum(
            &serde_json::to_vec(&(
                foreign.version,
                &foreign.repository,
                foreign.next_token,
                &foreign.intents,
            ))
            .expect("semantic checksum payload"),
        );
        let (_target_temp, target_path, target_state) = empty_repository_state();
        AtomicStateWriter::write_direct(
            &target_state,
            "semantic_intents.json",
            &serde_json::to_vec_pretty(&foreign).expect("semantic state"),
        )
        .expect("write foreign semantic state");
        let error = migrate_repository_state(&target_path, false)
            .expect_err("foreign semantic binding must fail");
        assert!(error.to_string().contains("repository binding"));
    }

    #[test]
    fn foreign_managed_registry_is_refused_even_with_a_valid_checksum() {
        let (_source_temp, source_path, _source_state) = repository_with_claims();
        let source_repository = expected_bindings_for(&source_path)
            .managed_repository
            .expect("managed source binding");
        let mut foreign = ManagedWorktreeRegistryWire {
            version: 2,
            checksum: String::new(),
            repository: source_repository,
            records: BTreeMap::new(),
            operations: BTreeMap::new(),
        };
        foreign.checksum = stable_checksum(
            &serde_json::to_vec(&(
                foreign.version,
                &foreign.repository,
                &foreign.records,
                &foreign.operations,
            ))
            .expect("managed checksum payload"),
        );
        let (_target_temp, target_path, target_state) = empty_repository_state();
        AtomicStateWriter::write_direct(
            &target_state,
            "managed_worktrees.json",
            &serde_json::to_vec_pretty(&foreign).expect("managed state"),
        )
        .expect("write foreign managed registry");
        let error = migrate_repository_state(&target_path, false)
            .expect_err("foreign managed binding must fail");
        assert!(error.to_string().contains("repository binding"));
    }
}
