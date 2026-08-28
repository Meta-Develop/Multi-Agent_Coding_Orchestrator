#[path = "state_auth.rs"]
pub(crate) mod state_auth;

use self::state_auth::{
    sha256_hex, AuthenticationTag, RepositoryAuthWriter, RepositoryAuthenticator,
};
#[cfg(unix)]
use crate::safe_state::device_id_to_u64;
use crate::{
    orchestrator::RunId,
    safe_state::{
        identity_for_path, remove_direct_child_tree, stable_checksum, unsigned_to_u64,
        AtomicStateWriter, BoundedRegularReader, BoundedTreeEntryKind, BoundedTreeWalkAction,
        BoundedTreeWalkLimits, BoundedTreeWalker, ExistingExclusiveLock, FileIdentity,
        KernelStateLock, ReservedDirectory, SafeRoot, TreeLinkPolicy,
    },
};

#[cfg(test)]
use self::state_auth::{
    authentication_key_file_name, authentication_key_length, authentication_key_lock_name,
    BoundStateLock,
};
use anyhow::{bail, Context, Result};
use git2::Repository;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{hash_map::RandomState, BTreeMap, BTreeSet},
    ffi::OsStr,
    fs::{self, File},
    hash::{BuildHasher, Hash, Hasher},
    io::Write,
    path::{Component, Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::{
    ffi::{CStr, CString},
    fs::OpenOptions,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        io::{AsRawFd, FromRawFd},
    },
};

const ARTIFACT_FORMAT_VERSION: u32 = 2;
const FINALIZATION_MARKER: &str = ".maco-artifact-final.json";
const RUN_LOCK_FILE: &str = ".artifact.lock";
const ROOT_LOCK_FILE: &str = ".runs.lock";
const QUARANTINE_DIRECTORY: &str = ".quarantine";
const RETENTION_LOCK_FILE: &str = ".artifact-retention.lock";
const RETENTION_QUARANTINE_DIRECTORY: &str = ".artifact-retention-quarantine";
const MAX_FINALIZATION_BYTES: u64 = 512 * 1024;
const MAX_ARTIFACT_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ARTIFACT_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ARTIFACT_FILES: usize = 4_096;
const MAX_ARTIFACT_PATH_BYTES: usize = 4_096;
const MAX_ARTIFACT_PATH_COMPONENTS: usize = 64;
const MAX_PRODUCER_BYTES: usize = 128;
const MAX_ARTIFACT_SCRATCH_DIRECTORIES: usize = 64;
const MAX_ARTIFACT_SCRATCH_NAME_BYTES: usize = 128;
static RESERVATION_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArtifactAppendFaultPoint {
    #[cfg(test)]
    PartialWrite,
    AfterWriteBeforeFileSync,
    AfterFileSyncBeforeParentSync,
}

struct ArtifactAppendRecovery<'a> {
    relative: &'a Path,
    previous_contents: &'a [u8],
    attempted_append: &'a [u8],
    disposition: ArtifactFileDisposition,
    opened_identity: &'a FileIdentity,
    file: &'a mut File,
    parent: &'a SafeRoot,
    create: bool,
    new_file_bytes: u64,
    proposed_total: u64,
}

#[cfg(test)]
thread_local! {
    static ARTIFACT_APPEND_FAULT: std::cell::Cell<Option<ArtifactAppendFaultPoint>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
const MAX_RUN_ROOT_ENTRIES: usize = 64;
#[cfg(not(test))]
const MAX_RUN_ROOT_ENTRIES: usize = 4_096;
#[cfg(test)]
const MAX_REGISTERED_ARTIFACT_WORKTREES: usize = 16;
#[cfg(not(test))]
const MAX_REGISTERED_ARTIFACT_WORKTREES: usize = 1_024;
const MAX_REGISTERED_WORKTREE_NAME_BYTES: usize = 1_024;
const MAX_REGISTERED_WORKTREE_PATH_BYTES: usize = 32 * 1_024;
const MAX_REGISTERED_WORKTREE_PATH_COMPONENTS: usize = 256;
const MAX_MARKER_SCAN_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
#[cfg(test)]
const MAX_RETENTION_TREE_ENTRIES: usize = 1_024;
#[cfg(not(test))]
const MAX_RETENTION_TREE_ENTRIES: usize = 131_072;
const MAX_RETENTION_TREE_DEPTH: usize = 64;
const MAX_RETENTION_TREE_PATH_BYTES: usize = 8 * 1024;
const MAX_RETENTION_TREE_TOTAL_PATH_BYTES: usize = 64 * 1024 * 1024;
const RETENTION_TREE_MAX_DURATION: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunArtifactFamily {
    Autopilot,
    Consult,
    Inbox,
    Supervise,
}

impl RunArtifactFamily {
    pub fn label(self) -> &'static str {
        match self {
            Self::Autopilot => "autopilot",
            Self::Consult => "consult",
            Self::Inbox => "inbox",
            Self::Supervise => "supervise",
        }
    }

    pub fn generated_prefix(self) -> &'static str {
        match self {
            Self::Autopilot => "autopilot",
            Self::Consult => "consult",
            Self::Inbox => "inbox",
            Self::Supervise => "o2",
        }
    }

    pub fn run_root(self) -> PathBuf {
        match self {
            Self::Autopilot => PathBuf::from(".maco").join("autopilot").join("runs"),
            Self::Consult => PathBuf::from(".maco").join("consult").join("runs"),
            Self::Inbox => PathBuf::from(".maco").join("inbox").join("runs"),
            Self::Supervise => PathBuf::from(".maco").join("o2").join("runs"),
        }
    }

    pub fn final_report_relative_path(self) -> PathBuf {
        match self {
            Self::Autopilot | Self::Inbox => PathBuf::from("final-report.json"),
            Self::Consult => PathBuf::from("trusted").join("consultant-report.json"),
            Self::Supervise => PathBuf::from("reports").join("supervisor-final.json"),
        }
    }
}

/// Every repository-local bulk artifact store covered by retention.
///
/// The first four variants are authenticated [`ArtifactRunWriter`] stores.
/// The remaining variants are produced by external or legacy drivers and do
/// not have a finalization MAC, so their reclamation always requires the
/// unfinalized grace policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactRetentionFamily {
    Autopilot,
    Consult,
    Inbox,
    Supervise,
    O2Autopilot,
    InboxWorkspace,
    Program,
}

impl ArtifactRetentionFamily {
    pub const ALL: [Self; 7] = [
        Self::Autopilot,
        Self::Consult,
        Self::Inbox,
        Self::Supervise,
        Self::O2Autopilot,
        Self::InboxWorkspace,
        Self::Program,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Autopilot => "autopilot",
            Self::Consult => "consult",
            Self::Inbox => "inbox",
            Self::Supervise => "supervise",
            Self::O2Autopilot => "o2_autopilot",
            Self::InboxWorkspace => "inbox_workspace",
            Self::Program => "program",
        }
    }

    pub fn run_root(self) -> PathBuf {
        match self {
            Self::Autopilot => RunArtifactFamily::Autopilot.run_root(),
            Self::Consult => RunArtifactFamily::Consult.run_root(),
            Self::Inbox => RunArtifactFamily::Inbox.run_root(),
            Self::Supervise => RunArtifactFamily::Supervise.run_root(),
            Self::O2Autopilot => PathBuf::from(".maco").join("o2-autopilot").join("runs"),
            Self::InboxWorkspace => PathBuf::from(".maco").join("inbox-workspace").join("runs"),
            // Program artifacts are direct `program-*` children of this root.
            Self::Program => PathBuf::from(".maco"),
        }
    }

    fn authenticated(self) -> Option<RunArtifactFamily> {
        match self {
            Self::Autopilot => Some(RunArtifactFamily::Autopilot),
            Self::Consult => Some(RunArtifactFamily::Consult),
            Self::Inbox => Some(RunArtifactFamily::Inbox),
            Self::Supervise => Some(RunArtifactFamily::Supervise),
            Self::O2Autopilot | Self::InboxWorkspace | Self::Program => None,
        }
    }
}

impl From<RunArtifactFamily> for ArtifactRetentionFamily {
    fn from(family: RunArtifactFamily) -> Self {
        match family {
            RunArtifactFamily::Autopilot => Self::Autopilot,
            RunArtifactFamily::Consult => Self::Consult,
            RunArtifactFamily::Inbox => Self::Inbox,
            RunArtifactFamily::Supervise => Self::Supervise,
        }
    }
}

/// Policy input kept independent from CLI parsing so #65's scheduler can call
/// the same retention engine without reproducing selection or safety logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactRetentionPolicy {
    pub max_count: usize,
    pub max_age: Option<Duration>,
    pub max_total_bytes: Option<u64>,
    pub unfinalized_grace: Option<Duration>,
    /// Permit expiry of an authenticated run whose finalization marker is
    /// present but cannot be verified. This remains opt-in because corrupted
    /// evidence and an abandoned writer are otherwise indistinguishable.
    pub reclaim_unverifiable: bool,
    /// Assert that non-cooperating writers for external artifact stores have
    /// stopped. These stores have no per-item writer lock, so retention cannot
    /// safely infer quiescence from age alone.
    pub external_writers_stopped: bool,
}

impl ArtifactRetentionPolicy {
    pub fn count_only(max_count: usize) -> Self {
        Self {
            max_count,
            max_age: None,
            max_total_bytes: None,
            unfinalized_grace: None,
            reclaim_unverifiable: false,
            external_writers_stopped: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedRunId {
    pub repo: PathBuf,
    pub run_id: RunId,
    pub run_dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunArtifactListReport {
    pub family: RunArtifactFamily,
    pub run_root: PathBuf,
    pub ordering: &'static str,
    pub runs: Vec<RunArtifactSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunArtifactLatestReport {
    pub family: RunArtifactFamily,
    pub run_root: PathBuf,
    pub ordering: &'static str,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<RunArtifactSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunArtifactSummary {
    pub run_id: String,
    pub run_dir: PathBuf,
    pub final_report_path: PathBuf,
    pub final_report_exists: bool,
    pub final_report_status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_report_success: Option<bool>,
    pub final_report_readable: bool,
    pub final_report_corrupt: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_report_error: Option<String>,
    pub finalized: bool,
    pub publishable: bool,
    pub provenance_valid: bool,
    pub artifact_digests_verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finalization_error: Option<String>,
    #[serde(skip)]
    modified: SystemTime,
    #[serde(skip)]
    identity: FileIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunArtifactPruneReport<F = RunArtifactFamily> {
    pub family: F,
    pub run_root: PathBuf,
    pub ordering: &'static str,
    pub keep: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unfinalized_grace_seconds: Option<u64>,
    pub reclaim_unverifiable: bool,
    pub external_writers_stopped: bool,
    pub dry_run: bool,
    pub kept_count: usize,
    pub deleted_count: usize,
    pub refused_unfinalized_count: usize,
    pub delete_candidate_count: usize,
    pub scanned_bytes: u64,
    /// Apparent bytes from the bounded inventory snapshot, less deletions
    /// completed by this invocation. Concurrently refused trees may change
    /// after their snapshot. In dry-run this equals `scanned_bytes`.
    pub retained_bytes: u64,
    pub projected_retained_bytes: u64,
    pub reclaimed_bytes: u64,
    pub would_reclaim_bytes: u64,
    pub refused_bytes: u64,
    pub unfinalized_bytes: u64,
    pub compression_strategy: ArtifactCompressionStrategy,
    pub compressible_log_bytes: u64,
    pub compressed_bytes: u64,
    pub entries: Vec<RunArtifactPruneEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunArtifactPruneEntry {
    pub run_id: String,
    pub run_dir: PathBuf,
    pub bytes: u64,
    pub age_seconds: u64,
    pub action: RunArtifactPruneAction,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selected_by: Vec<ArtifactRetentionLimit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactRetentionLimit {
    MaxCount,
    MaxAge,
    MaxTotalBytes,
    UnfinalizedGrace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactCompressionStrategy {
    /// Retention never rewrites transcripts. Authenticated artifacts are
    /// immutable after finalization, while external logs can still be active;
    /// compression therefore requires a writer-side format migration.
    NoneRequiresWriterMigration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunArtifactPruneAction {
    Keep,
    Delete,
    WouldDelete,
    RefuseUnfinalized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactFileDisposition {
    Publishable,
    PrivateEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactProvenance {
    pub producer: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactFileRecord {
    pub path: PathBuf,
    pub bytes: u64,
    /// Content-integrity digest only; it confers no authority. Publishability
    /// also requires the private reservation and bound writer evidence
    /// verified by `ArtifactRunReader`.
    pub sha256: String,
    pub disposition: ArtifactFileDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactWriterEvidence {
    pub run_root_identity: FileIdentity,
    pub run_identity: FileIdentity,
    pub writer_lock_identity: FileIdentity,
    pub reservation_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactRepositoryBinding {
    common_dir_path_checksum: String,
    common_dir_identity: FileIdentity,
    worktree_path_checksum: String,
    worktree_identity: FileIdentity,
}

#[derive(Debug, Clone)]
struct ArtifactRepository {
    binding: ArtifactRepositoryBinding,
    common_dir: PathBuf,
    worktree: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactFinalization {
    /// The checksum and per-file SHA-256 values detect integrity changes only
    /// and confer no authority.
    version: u32,
    checksum: String,
    repository: ArtifactRepositoryBinding,
    pub family: RunArtifactFamily,
    pub run_id: String,
    pub provenance: ArtifactProvenance,
    pub writer_evidence: ArtifactWriterEvidence,
    pub mac_key_id: String,
    pub mac_key_identity: FileIdentity,
    pub final_report: PathBuf,
    pub files: Vec<ArtifactFileRecord>,
    pub publish_requested: bool,
    /// True only after the writer has bound the owner-private reservation,
    /// stable exclusive-writer lock identity, provenance and every file
    /// disposition into the atomic final marker. Readers revalidate all of
    /// those facts before exposing this value as trusted state.
    pub publishable: bool,
    hmac_sha256: String,
}

pub struct ArtifactRunWriter {
    repository: ArtifactRepository,
    family: RunArtifactFamily,
    run_id: RunId,
    run_root: SafeRoot,
    run: SafeRoot,
    provenance: ArtifactProvenance,
    writer_evidence: ArtifactWriterEvidence,
    files: BTreeMap<PathBuf, ArtifactFileRecord>,
    outstanding_scratches: BTreeMap<PathBuf, FileIdentity>,
    poisoned_appends: BTreeSet<PathBuf>,
    total_bytes: u64,
    run_lock: BoundArtifactLock,
}

/// Authenticated-journal payload required to reopen one unfinalized artifact run.
///
/// This value is not authority by itself. Callers must obtain it from repository-
/// authenticated state; reopening revalidates the repository, run-directory and
/// writer-lock identities plus every manifested byte before returning a writer.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArtifactRunResumeBinding {
    version: u32,
    repository: ArtifactRepositoryBinding,
    family: RunArtifactFamily,
    run_id: String,
    provenance: ArtifactProvenance,
    writer_evidence: ArtifactWriterEvidence,
    files: Vec<ArtifactFileRecord>,
}

pub(crate) struct ArtifactRecoveryFile<'a> {
    pub(crate) relative: &'a Path,
    pub(crate) contents: &'a [u8],
    pub(crate) disposition: ArtifactFileDisposition,
}

/// Proof supplied by an orchestration boundary after every process that could
/// mutate the run's invocation scratches has been joined or otherwise verified
/// quiescent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArtifactScratchQuiescence {
    Verified,
}

/// An identity-bound capability for a child-writable directory reserved inside
/// one artifact run. The directory must be discarded through the writer after
/// every process that could mutate it has stopped. Dropping this capability
/// does not delete the directory; the writer will refuse finalization while the
/// corresponding reservation remains outstanding.
#[derive(Debug)]
#[must_use = "artifact scratch directories must be discarded before finalization"]
pub struct ArtifactScratchDirectory {
    path: PathBuf,
    name: PathBuf,
    identity: FileIdentity,
    run_identity: FileIdentity,
    writer_reservation_id: String,
    reservation: ReservedDirectory,
}

impl ArtifactScratchDirectory {
    /// Path to pass to the confined child process as its writable output root.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Stable filesystem identity captured by the open reservation handle.
    pub fn identity(&self) -> &FileIdentity {
        &self.identity
    }
}

pub struct ArtifactRunReader {
    run: SafeRoot,
    finalization: ArtifactFinalization,
}

/// A kernel lock plus the inode that its pathname named at acquisition. MACO
/// revalidates the path before and after mutations so replacing a live lock
/// file cannot silently create two independent lock domains. An arbitrary
/// uncooperative process running as the same OS user remains outside this
/// cooperative lock boundary and requires an OS sandbox for isolation.
struct BoundArtifactLock {
    lock: KernelStateLock,
    root_identity: FileIdentity,
    lock_identity: FileIdentity,
}

impl BoundArtifactLock {
    fn acquire(root: &SafeRoot, name: &str) -> Result<Self> {
        let lock = KernelStateLock::acquire_direct(root, name)?;
        let lock_identity = lock.identity().clone();
        let bound = Self {
            lock,
            root_identity: root.identity().clone(),
            lock_identity,
        };
        bound.verify(root)?;
        Ok(bound)
    }

    fn verify(&self, root: &SafeRoot) -> Result<()> {
        root.verify()?;
        if self.root_identity != *root.identity() {
            bail!("artifact lock was presented with a different root inode");
        }
        self.lock.verify_direct_binding(root)?;
        if self.lock.identity() != &self.lock_identity {
            bail!(
                "artifact lock identity changed unexpectedly: {}",
                self.lock.path().display()
            );
        }
        Ok(())
    }
}

fn finish_with_artifact_lock_verification<T>(
    result: Result<T>,
    verification: Result<()>,
) -> Result<T> {
    match (result, verification) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(lock_error)) => Err(lock_error),
        (Err(error), Err(lock_error)) => Err(error.context(format!(
            "operation also lost its stable artifact lock-path binding: {lock_error:#}"
        ))),
    }
}

fn verify_optional_artifact_lock(lock: Option<&BoundArtifactLock>, root: &SafeRoot) -> Result<()> {
    match lock {
        Some(lock) => lock.verify(root),
        None => root.verify(),
    }
}

pub(crate) fn repository_auth_writer(repo: &Path) -> Result<RepositoryAuthWriter> {
    let repository = discover_artifact_repository(repo)?;
    open_artifact_auth_writer(&repository)
}

/// Opens only the repository-bound key and binding. Callers using an
/// unauthenticated external locator must verify its MAC before invoking the
/// repository-global state preflight.
pub(crate) fn repository_authenticator_key_only(repo: &Path) -> Result<RepositoryAuthenticator> {
    let repository = discover_artifact_repository(repo)?;
    repository_authenticator_key_only_for(&repository)
}

pub(crate) fn validate_repository_authenticated_state(
    repo: &Path,
    authenticator: &RepositoryAuthenticator,
) -> Result<()> {
    let repository = discover_artifact_repository(repo)?;
    validate_repository_authenticated_state_for(&repository, authenticator)
}

fn repository_authenticator_key_only_for(
    repository: &ArtifactRepository,
) -> Result<RepositoryAuthenticator> {
    let authenticator = RepositoryAuthenticator::open_existing(&repository.common_dir)?;
    authenticator.verify()?;
    Ok(authenticator)
}

fn validate_repository_authenticated_state_for(
    repository: &ArtifactRepository,
    authenticator: &RepositoryAuthenticator,
) -> Result<()> {
    authenticator.verify_epoch()?;
    scan_registered_finalization_markers(repository, Some(authenticator))?;
    authenticator.verify_epoch()
}

fn open_artifact_auth_writer(repository: &ArtifactRepository) -> Result<RepositoryAuthWriter> {
    let writer = RepositoryAuthWriter::open_or_create(&repository.common_dir, |state_root| {
        if scan_registered_finalization_markers(repository, None)? > 0 {
            bail!(
                "repository authentication key is missing while an existing final marker is present; refusing to establish a replacement key epoch"
            );
        }
        if state_root.direct_child_exists(crate::state_journal::JOURNAL_ROOT_NAME)? {
            bail!(
                "repository authentication key is missing while checkpoint journals exist; refusing to establish a replacement key epoch"
            );
        }
        Ok(())
    })?;
    writer.verify()?;
    scan_registered_finalization_markers(repository, Some(writer.authenticator()))?;
    writer.verify()?;
    Ok(writer)
}

impl ArtifactRunWriter {
    pub fn reserve(
        repo: impl AsRef<Path>,
        family: RunArtifactFamily,
        run_id: RunId,
        producer: impl Into<String>,
    ) -> Result<Self> {
        let producer = producer.into();
        validate_producer(&producer)?;
        let repository = discover_artifact_repository(repo.as_ref())?;
        let repo_handle =
            crate::git_repository::discover(&repository.worktree).with_context(|| {
                format!(
                    "failed to reopen artifact repository {}",
                    repository.worktree.display()
                )
            })?;
        let source_revision = repo_handle
            .head()
            .ok()
            .and_then(|head| head.target())
            .map(|oid| oid.to_string());
        let provenance = ArtifactProvenance {
            producer,
            source_revision,
        };
        let run_root = open_or_create_run_root(&repository, family)?;
        ensure_private_directory(run_root.path()).context(
            "ArtifactRunWriter requires an owner-private 0700 run root; legacy roots remain readable/nonpublishable but must be inspected and migrated before finalized writes",
        )?;
        let root_lock = BoundArtifactLock::acquire(&run_root, ROOT_LOCK_FILE)?;
        root_lock.verify(&run_root)?;
        let result = (|| -> Result<Self> {
            if run_root.direct_child_exists(run_id.as_str())? {
                bail!(
                    "{} run id '{}' already exists at {}; choose a new --run-id or prune old artifacts first",
                    family.label(),
                    run_id.as_str(),
                    run_root.path().join(run_id.as_str()).display()
                );
            }
            let reserved = run_root.reserve_direct_child_directory(run_id.as_str())?;
            let run = SafeRoot::open_or_create(reserved.path())?;
            let run_lock = BoundArtifactLock::acquire(&run, RUN_LOCK_FILE)?;
            let writer_evidence = ArtifactWriterEvidence {
                run_root_identity: run_root.identity().clone(),
                run_identity: run.identity().clone(),
                writer_lock_identity: run_lock.lock_identity.clone(),
                reservation_id: reservation_evidence_id(run_id.as_str(), run.identity()),
            };
            run_lock.verify(&run)?;

            Ok(Self {
                repository,
                family,
                run_id,
                run_root: run_root.clone(),
                run,
                provenance,
                writer_evidence,
                files: BTreeMap::new(),
                outstanding_scratches: BTreeMap::new(),
                poisoned_appends: BTreeSet::new(),
                total_bytes: 0,
                run_lock,
            })
        })();
        finish_with_artifact_lock_verification(result, root_lock.verify(&run_root))
    }

    pub(crate) fn resume_binding(&self) -> Result<ArtifactRunResumeBinding> {
        self.run_lock.verify(&self.run)?;
        if !self.outstanding_scratches.is_empty() || !self.poisoned_appends.is_empty() {
            bail!("artifact run is not at a resumable manifest boundary");
        }
        let audited = audit_artifact_tree(&self.run, true)?;
        verify_manifest_paths(&self.files, &audited)?;
        verify_manifest_contents(&self.run, self.files.values())?;
        Ok(ArtifactRunResumeBinding {
            version: ARTIFACT_FORMAT_VERSION,
            repository: self.repository.binding.clone(),
            family: self.family,
            run_id: self.run_id.as_str().to_string(),
            provenance: self.provenance.clone(),
            writer_evidence: self.writer_evidence.clone(),
            files: self.files.values().cloned().collect(),
        })
    }

    pub(crate) fn reopen_unfinalized(
        repo: impl AsRef<Path>,
        binding: &ArtifactRunResumeBinding,
    ) -> Result<Self> {
        Self::reopen_unfinalized_with_recovery(repo, binding, &[])
    }

    pub(crate) fn reopen_unfinalized_with_recovery(
        repo: impl AsRef<Path>,
        binding: &ArtifactRunResumeBinding,
        recoverable_files: &[ArtifactRecoveryFile<'_>],
    ) -> Result<Self> {
        validate_artifact_resume_binding(binding)?;
        let repository = discover_artifact_repository(repo.as_ref())?;
        if binding.repository != repository.binding {
            bail!("artifact resume binding belongs to a different repository");
        }
        let run_id = RunId::new(&binding.run_id)?;
        if run_id.as_str() != binding.run_id {
            bail!("artifact resume binding run id is not canonical");
        }
        let run_root = open_existing_run_root(&repository, binding.family)?;
        ensure_private_directory(run_root.path())?;
        let root_lock = BoundArtifactLock::acquire(&run_root, ROOT_LOCK_FILE)?;
        root_lock.verify(&run_root)?;
        let result = (|| -> Result<Self> {
            let reserved = run_root
                .bind_existing_direct_child_directory(run_id.as_str())
                .context("artifact resume run directory is missing or unsafe")?;
            let run = SafeRoot::open_existing(reserved.path())?;
            ensure_private_directory(run.path())?;
            if run.direct_child_exists(FINALIZATION_MARKER)? {
                bail!("artifact resume run is already finalized");
            }
            let run_lock = BoundArtifactLock::acquire(&run, RUN_LOCK_FILE)?;
            if binding.writer_evidence.run_root_identity != *run_root.identity()
                || binding.writer_evidence.run_identity != *run.identity()
                || binding.writer_evidence.writer_lock_identity != run_lock.lock_identity
            {
                bail!("artifact resume writer identity binding changed");
            }
            verify_writer_evidence(&binding.writer_evidence, &run_root, &run)?;

            let mut files = binding
                .files
                .iter()
                .cloned()
                .map(|record| (record.path.clone(), record))
                .collect::<BTreeMap<_, _>>();
            if files.len() != binding.files.len() {
                bail!("artifact resume binding contains duplicate manifest paths");
            }
            let mut total_bytes = binding.files.iter().try_fold(0_u64, |total, record| {
                total
                    .checked_add(record.bytes)
                    .context("artifact resume manifest byte total overflowed")
            })?;
            verify_manifest_contents(&run, files.values())?;

            let mut recovery_paths = BTreeSet::new();
            for recovery in recoverable_files {
                let relative = validate_artifact_relative_path(recovery.relative)?;
                if files.contains_key(&relative) || !recovery_paths.insert(relative) {
                    bail!("artifact recovery file conflicts with the authenticated manifest");
                }
            }
            let audited = audit_artifact_tree(&run, true)?;
            let manifested = files.keys().cloned().collect::<BTreeSet<_>>();
            if !audited.is_superset(&manifested)
                || !audited
                    .difference(&manifested)
                    .all(|path| recovery_paths.contains(path))
            {
                bail!("artifact tree contains state not authorized by the resume checkpoint");
            }

            let mut writer = Self {
                repository,
                family: binding.family,
                run_id,
                run_root: run_root.clone(),
                run,
                provenance: binding.provenance.clone(),
                writer_evidence: binding.writer_evidence.clone(),
                files: std::mem::take(&mut files),
                outstanding_scratches: BTreeMap::new(),
                poisoned_appends: BTreeSet::new(),
                total_bytes,
                run_lock,
            };
            for recovery in recoverable_files {
                let relative = validate_artifact_relative_path(recovery.relative)?;
                if audited.contains(&relative) {
                    let observed = BoundedRegularReader::read_relative(
                        writer.run.path(),
                        &relative,
                        MAX_ARTIFACT_FILE_BYTES,
                    )?;
                    if observed != recovery.contents {
                        bail!("recoverable artifact contents do not match the checkpoint plan");
                    }
                }
                let record =
                    writer.write_bytes(&relative, recovery.contents, recovery.disposition)?;
                total_bytes = total_bytes
                    .checked_add(record.bytes)
                    .context("artifact recovery byte total overflowed")?;
            }
            if writer.total_bytes != total_bytes {
                bail!("artifact recovery byte accounting is inconsistent");
            }
            writer.resume_binding()?;
            Ok(writer)
        })();
        finish_with_artifact_lock_verification(result, root_lock.verify(&run_root))
    }

    pub fn run_dir(&self) -> &Path {
        self.run.path()
    }

    /// Reserves one owner-private, child-writable scratch directory directly
    /// beneath this run. Only a canonical single-component name is accepted so
    /// cleanup can remain handle-relative and identity-bound. A launcher must
    /// expose only this scratch directory as writable to the child; the run
    /// parent remains parent-owned and must be read-only or hidden in the
    /// child's mount namespace.
    pub fn create_scratch_dir(
        &mut self,
        name: impl AsRef<Path>,
    ) -> Result<ArtifactScratchDirectory> {
        self.run_lock.verify(&self.run)?;
        let result = (|| -> Result<ArtifactScratchDirectory> {
            let name = validate_artifact_scratch_name(name.as_ref())?;
            if self.outstanding_scratches.contains_key(&name) {
                bail!(
                    "artifact scratch directory is already outstanding: {}",
                    name.display()
                );
            }
            if self.outstanding_scratches.len() >= MAX_ARTIFACT_SCRATCH_DIRECTORIES {
                bail!(
                    "artifact run exceeds its {} outstanding scratch-directory limit",
                    MAX_ARTIFACT_SCRATCH_DIRECTORIES
                );
            }
            if self
                .files
                .keys()
                .any(|path| artifact_path_starts_with(path, &name))
            {
                bail!(
                    "artifact scratch directory overlaps an already manifested artifact path: {}",
                    name.display()
                );
            }

            let reservation = self.run.reserve_direct_child_directory(name.as_os_str())?;
            reservation.verify(&self.run)?;
            let identity = reservation.identity().clone();
            self.outstanding_scratches
                .insert(name.clone(), identity.clone());
            Ok(ArtifactScratchDirectory {
                path: reservation.path().to_path_buf(),
                name,
                identity,
                run_identity: self.run.identity().clone(),
                writer_reservation_id: self.writer_evidence.reservation_id.clone(),
                reservation,
            })
        })();
        finish_with_artifact_lock_verification(result, self.run_lock.verify(&self.run))
    }

    /// Safely discards a previously reserved scratch tree. The caller must
    /// first stop every child process that could still mutate the tree. Links
    /// and special files inside the child-writable tree are unlinked as entries
    /// and never followed; filesystem-boundary and tree-budget violations fail
    /// closed and leave the reservation outstanding.
    pub fn discard_scratch(&mut self, scratch: &ArtifactScratchDirectory) -> Result<()> {
        self.run_lock.verify(&self.run)?;
        let result = (|| -> Result<()> {
            self.verify_scratch_capability(scratch)?;
            if self.run.direct_child_exists(scratch.name.as_os_str())? {
                scratch.reservation.verify(&self.run)?;
            }
            self.discard_tracked_scratch(&scratch.name, &scratch.identity)
        })();
        finish_with_artifact_lock_verification(result, self.run_lock.verify(&self.run))
    }

    /// Discards only this supervise writer's identity-bound invocation scratch
    /// reservations after the caller proves every possible scratch writer is
    /// quiescent. Other tracked scratch remains outstanding so resume and
    /// finalization continue to fail closed over foreign or leaked state.
    pub(crate) fn discard_supervisor_invocation_scratches_after_quiescence(
        &mut self,
        _quiescence: ArtifactScratchQuiescence,
    ) -> Result<usize> {
        self.run_lock.verify(&self.run)?;
        let result = (|| -> Result<usize> {
            if self.family != RunArtifactFamily::Supervise {
                bail!("supervisor invocation scratch cleanup requires a supervise artifact run");
            }
            let invocation_scratches = self
                .outstanding_scratches
                .iter()
                .filter(|(name, _)| is_supervisor_invocation_scratch_name(name))
                .map(|(name, identity)| (name.clone(), identity.clone()))
                .collect::<Vec<_>>();
            for (name, identity) in &invocation_scratches {
                self.discard_tracked_scratch(name, identity)?;
            }
            Ok(invocation_scratches.len())
        })();
        finish_with_artifact_lock_verification(result, self.run_lock.verify(&self.run))
    }

    fn discard_tracked_scratch(&mut self, name: &Path, identity: &FileIdentity) -> Result<()> {
        remove_artifact_scratch_tree(&self.run, name.as_os_str(), identity).with_context(|| {
            format!(
                "failed to safely discard artifact scratch directory {}",
                name.display()
            )
        })?;
        if self.run.direct_child_exists(name.as_os_str())? {
            bail!(
                "artifact scratch source name reappeared after cleanup: {}",
                name.display()
            );
        }
        let removed = self
            .outstanding_scratches
            .remove(name)
            .context("artifact scratch tracking disappeared during cleanup")?;
        if &removed != identity {
            bail!("artifact scratch tracking identity changed during cleanup");
        }
        Ok(())
    }

    fn verify_scratch_capability(&self, scratch: &ArtifactScratchDirectory) -> Result<()> {
        if scratch.run_identity != *self.run.identity()
            || scratch.writer_reservation_id != self.writer_evidence.reservation_id
            || scratch.path != self.run.path().join(&scratch.name)
        {
            bail!("artifact scratch capability belongs to a different run reservation");
        }
        let tracked = self
            .outstanding_scratches
            .get(&scratch.name)
            .context("artifact scratch capability is no longer outstanding")?;
        if tracked != &scratch.identity || scratch.reservation.identity() != &scratch.identity {
            bail!("artifact scratch capability identity does not match the tracked reservation");
        }
        Ok(())
    }

    pub fn write_bytes(
        &mut self,
        relative: impl AsRef<Path>,
        contents: &[u8],
        disposition: ArtifactFileDisposition,
    ) -> Result<ArtifactFileRecord> {
        self.run_lock.verify(&self.run)?;
        let result = (|| -> Result<ArtifactFileRecord> {
            let relative = validate_artifact_relative_path(relative.as_ref())?;
            if let Some(scratch) = self
                .outstanding_scratches
                .keys()
                .find(|scratch| artifact_path_starts_with(&relative, scratch))
            {
                bail!(
                    "artifact path overlaps outstanding scratch directory {}: {}",
                    scratch.display(),
                    relative.display()
                );
            }
            if u64::try_from(contents.len()).unwrap_or(u64::MAX) > MAX_ARTIFACT_FILE_BYTES {
                bail!(
                    "artifact file exceeds its {} byte limit: {}",
                    MAX_ARTIFACT_FILE_BYTES,
                    relative.display()
                );
            }
            let previous_bytes = self
                .files
                .get(&relative)
                .map(|record| record.bytes)
                .unwrap_or(0);
            let proposed_total = self
                .total_bytes
                .checked_sub(previous_bytes)
                .and_then(|total| total.checked_add(u64::try_from(contents.len()).ok()?))
                .context("artifact byte accounting overflow")?;
            if proposed_total > MAX_ARTIFACT_TOTAL_BYTES {
                bail!(
                    "artifact run exceeds its {} byte aggregate limit",
                    MAX_ARTIFACT_TOTAL_BYTES
                );
            }
            if let Some(previous) = self.files.get(&relative) {
                if previous.disposition != disposition {
                    bail!(
                        "artifact overwrite cannot change file disposition: {}",
                        relative.display()
                    );
                }
            } else if self.files.len() >= MAX_ARTIFACT_FILES {
                bail!(
                    "artifact run exceeds its {} file manifest limit",
                    MAX_ARTIFACT_FILES
                );
            }

            let (parent, file_name) = artifact_parent_and_name(&self.run, &relative, true)?;
            AtomicStateWriter::scavenge_direct_temps(&parent, file_name)?;
            AtomicStateWriter::write_direct_fenced(&parent, file_name, contents, || {
                self.run_lock.verify(&self.run)?;
                parent.verify()
            })
            .with_context(|| format!("failed to write artifact file {}", relative.display()))?;
            ensure_private_regular_file(&self.run.path().join(&relative))?;
            let observed = BoundedRegularReader::read_relative(
                self.run.path(),
                &relative,
                MAX_ARTIFACT_FILE_BYTES,
            )?;
            if observed != contents {
                bail!(
                    "artifact contents changed immediately after atomic write: {}",
                    relative.display()
                );
            }

            let record = ArtifactFileRecord {
                path: relative.clone(),
                bytes: u64::try_from(contents.len()).context("artifact length overflow")?,
                sha256: sha256_hex(contents),
                disposition,
            };
            self.files.insert(relative, record.clone());
            self.total_bytes = proposed_total;
            Ok(record)
        })();
        finish_with_artifact_lock_verification(result, self.run_lock.verify(&self.run))
    }

    pub fn write_json<T: Serialize>(
        &mut self,
        relative: impl AsRef<Path>,
        value: &T,
        disposition: ArtifactFileDisposition,
    ) -> Result<ArtifactFileRecord> {
        let mut contents =
            serde_json::to_vec_pretty(value).context("failed to serialize artifact JSON")?;
        contents.push(b'\n');
        self.write_bytes(relative, &contents, disposition)
    }

    /// Appends one compact JSON value and one trailing newline to an artifact.
    /// Existing bytes are never rewritten or truncated, and every append must
    /// retain the disposition established by the first record.
    pub fn append_json_line<T: Serialize>(
        &mut self,
        relative: impl AsRef<Path>,
        value: &T,
        disposition: ArtifactFileDisposition,
    ) -> Result<ArtifactFileRecord> {
        let mut line = serde_json::to_vec(value).context("failed to serialize artifact JSONL")?;
        line.push(b'\n');
        self.append_bytes(relative.as_ref(), &line, disposition)
    }

    fn append_bytes(
        &mut self,
        relative: &Path,
        contents: &[u8],
        disposition: ArtifactFileDisposition,
    ) -> Result<ArtifactFileRecord> {
        self.run_lock.verify(&self.run)?;
        let result = (|| -> Result<ArtifactFileRecord> {
            let relative = validate_artifact_relative_path(relative)?;
            if self.poisoned_appends.contains(&relative) {
                bail!(
                    "artifact append path is poisoned by an unrecovered prior write: {}",
                    relative.display()
                );
            }
            if let Some(scratch) = self
                .outstanding_scratches
                .keys()
                .find(|scratch| artifact_path_starts_with(&relative, scratch))
            {
                bail!(
                    "artifact path overlaps outstanding scratch directory {}: {}",
                    scratch.display(),
                    relative.display()
                );
            }
            let appended_bytes =
                u64::try_from(contents.len()).context("artifact append length overflow")?;
            let previous = self.files.get(&relative).cloned();
            if let Some(record) = &previous {
                if record.disposition != disposition {
                    bail!(
                        "artifact append cannot change file disposition: {}",
                        relative.display()
                    );
                }
            } else if self.files.len() >= MAX_ARTIFACT_FILES {
                bail!(
                    "artifact run exceeds its {} file manifest limit",
                    MAX_ARTIFACT_FILES
                );
            }
            let previous_bytes = previous.as_ref().map_or(0, |record| record.bytes);
            let new_file_bytes = previous_bytes
                .checked_add(appended_bytes)
                .context("artifact file byte accounting overflow")?;
            if new_file_bytes > MAX_ARTIFACT_FILE_BYTES {
                bail!(
                    "artifact file exceeds its {} byte limit: {}",
                    MAX_ARTIFACT_FILE_BYTES,
                    relative.display()
                );
            }
            let proposed_total = self
                .total_bytes
                .checked_add(appended_bytes)
                .context("artifact byte accounting overflow")?;
            if proposed_total > MAX_ARTIFACT_TOTAL_BYTES {
                bail!(
                    "artifact run exceeds its {} byte aggregate limit",
                    MAX_ARTIFACT_TOTAL_BYTES
                );
            }

            let (expected, expected_identity) = if let Some(record) = &previous {
                let path = self.run.path().join(&relative);
                let before = ensure_private_regular_file(&path)?;
                let contents = read_and_verify_record(&self.run, record)?;
                let after = ensure_private_regular_file(&path)?;
                if before != after {
                    bail!(
                        "artifact file identity changed while preparing append: {}",
                        relative.display()
                    );
                }
                (contents, Some(before))
            } else {
                (Vec::new(), None)
            };
            let (parent, file_name) = artifact_parent_and_name(&self.run, &relative, true)?;
            let path = self.run.path().join(&relative);
            let create = previous.is_none();
            if create && parent.direct_child_exists(file_name)? {
                bail!(
                    "refusing to adopt an existing unmanifested artifact for append: {}",
                    relative.display()
                );
            }
            let mut file = open_private_artifact_append_file(&parent, file_name, create)?;
            let opened_identity = ensure_private_regular_file_handle(&file, &path)?;
            if expected_identity
                .as_ref()
                .is_some_and(|identity| identity != &opened_identity)
            {
                bail!(
                    "artifact file identity changed before append: {}",
                    relative.display()
                );
            }
            let append_result = (|| -> Result<ArtifactFileRecord> {
                write_artifact_append(&mut file, contents, &relative)?;
                run_artifact_append_fault(ArtifactAppendFaultPoint::AfterWriteBeforeFileSync)?;
                file.sync_data().with_context(|| {
                    format!(
                        "failed to persist appended artifact file {}",
                        relative.display()
                    )
                })?;
                run_artifact_append_fault(ArtifactAppendFaultPoint::AfterFileSyncBeforeParentSync)?;
                if create {
                    parent.sync_directory_fenced()?;
                }
                let rebound_identity = ensure_private_regular_file(&path)?;
                if rebound_identity != opened_identity {
                    bail!(
                        "artifact file identity changed after append: {}",
                        relative.display()
                    );
                }
                let mut expected_after = expected.clone();
                expected_after.extend_from_slice(contents);
                let observed = BoundedRegularReader::read_relative(
                    self.run.path(),
                    &relative,
                    MAX_ARTIFACT_FILE_BYTES,
                )?;
                let post_read_identity = ensure_private_regular_file(&path)?;
                if post_read_identity != opened_identity {
                    bail!(
                        "artifact file identity changed while verifying append: {}",
                        relative.display()
                    );
                }
                if observed != expected_after {
                    bail!(
                        "artifact contents changed immediately after append: {}",
                        relative.display()
                    );
                }

                Ok(ArtifactFileRecord {
                    path: relative.clone(),
                    bytes: new_file_bytes,
                    sha256: sha256_hex(&observed),
                    disposition,
                })
            })();
            match append_result {
                Ok(record) => {
                    self.files.insert(relative, record.clone());
                    self.total_bytes = proposed_total;
                    Ok(record)
                }
                Err(error) => {
                    let recovery = self.reconcile_failed_artifact_append(ArtifactAppendRecovery {
                        relative: &relative,
                        previous_contents: &expected,
                        attempted_append: contents,
                        disposition,
                        opened_identity: &opened_identity,
                        file: &mut file,
                        parent: &parent,
                        create,
                        new_file_bytes,
                        proposed_total,
                    });
                    match recovery {
                        Ok(()) => Err(error),
                        Err(recovery_error) => {
                            self.poisoned_appends.insert(relative);
                            Err(error.context(format!(
                                "artifact append recovery also failed and poisoned this path: {recovery_error:#}"
                            )))
                        }
                    }
                }
            }
        })();
        finish_with_artifact_lock_verification(result, self.run_lock.verify(&self.run))
    }

    /// Completes and durably verifies the exact attempted line after any
    /// post-open append error. A short write is never manifested as valid
    /// JSONL: recovery appends the known remaining suffix. The caller poisons
    /// the path only when the filesystem no longer permits proving that exact
    /// durable result, which is an artifact-integrity failure rather than a
    /// routine journal error.
    fn reconcile_failed_artifact_append(
        &mut self,
        recovery: ArtifactAppendRecovery<'_>,
    ) -> Result<()> {
        let ArtifactAppendRecovery {
            relative,
            previous_contents,
            attempted_append,
            disposition,
            opened_identity,
            file,
            parent,
            create,
            new_file_bytes,
            proposed_total,
        } = recovery;
        let path = self.run.path().join(relative);
        let held = ensure_private_regular_file_handle(file, &path)?;
        if &held != opened_identity {
            bail!(
                "opened artifact file identity changed before append recovery: {}",
                relative.display()
            );
        }
        let before = ensure_private_regular_file(&path)?;
        if &before != opened_identity {
            bail!(
                "artifact file identity changed before append recovery: {}",
                relative.display()
            );
        }
        let observed = BoundedRegularReader::read_relative(
            self.run.path(),
            relative,
            MAX_ARTIFACT_FILE_BYTES,
        )?;
        let after = ensure_private_regular_file(&path)?;
        if after != before {
            bail!(
                "artifact file identity changed during append recovery: {}",
                relative.display()
            );
        }
        let appended = observed
            .strip_prefix(previous_contents)
            .context("artifact append recovery found prior bytes changed")?;
        if !attempted_append.starts_with(appended) {
            bail!("artifact append recovery found bytes outside the attempted append");
        }
        if appended.len() < attempted_append.len() {
            file.write_all(&attempted_append[appended.len()..])
                .with_context(|| {
                    format!(
                        "failed to complete partial artifact append {}",
                        relative.display()
                    )
                })?;
        }
        file.sync_data().with_context(|| {
            format!(
                "failed to persist recovered artifact append {}",
                relative.display()
            )
        })?;
        if create {
            parent.sync_directory_fenced().with_context(|| {
                format!(
                    "failed to persist recovered artifact parent {}",
                    parent.path().display()
                )
            })?;
        }
        let held_after_sync = ensure_private_regular_file_handle(file, &path)?;
        if &held_after_sync != opened_identity {
            bail!(
                "opened artifact file identity changed while syncing append recovery: {}",
                relative.display()
            );
        }
        let rebound = ensure_private_regular_file(&path)?;
        if &rebound != opened_identity {
            bail!(
                "artifact file identity changed after append recovery: {}",
                relative.display()
            );
        }
        let mut expected = previous_contents.to_vec();
        expected.extend_from_slice(attempted_append);
        let verified = BoundedRegularReader::read_relative(
            self.run.path(),
            relative,
            MAX_ARTIFACT_FILE_BYTES,
        )?;
        let after_read = ensure_private_regular_file(&path)?;
        if &after_read != opened_identity || verified != expected {
            bail!(
                "artifact append recovery could not verify the completed durable line: {}",
                relative.display()
            );
        }
        let record = ArtifactFileRecord {
            path: relative.to_path_buf(),
            bytes: new_file_bytes,
            sha256: sha256_hex(&verified),
            disposition,
        };
        self.files.insert(relative.to_path_buf(), record);
        self.total_bytes = proposed_total;
        self.poisoned_appends.remove(relative);
        Ok(())
    }

    pub fn finalize(
        self,
        final_report: impl AsRef<Path>,
        publish_requested: bool,
    ) -> Result<ArtifactFinalization> {
        self.run_lock.verify(&self.run)?;
        let result = self.finalize_locked(final_report.as_ref(), publish_requested);
        finish_with_artifact_lock_verification(result, self.run_lock.verify(&self.run))
    }

    fn finalize_locked(
        &self,
        final_report: &Path,
        publish_requested: bool,
    ) -> Result<ArtifactFinalization> {
        if !self.poisoned_appends.is_empty() {
            bail!(
                "artifact run has {} poisoned append path(s); refusing to finalize an incomplete append",
                self.poisoned_appends.len()
            );
        }
        if !self.outstanding_scratches.is_empty() {
            let noun = if self.outstanding_scratches.len() == 1 {
                "directory"
            } else {
                "directories"
            };
            bail!(
                "artifact run has {} outstanding scratch {}; discard every scratch tree before finalization",
                self.outstanding_scratches.len(),
                noun
            );
        }
        let final_report = validate_artifact_relative_path(final_report)?;
        if final_report != self.family.final_report_relative_path() {
            bail!(
                "final report path {} does not match the {} artifact contract {}",
                final_report.display(),
                self.family.label(),
                self.family.final_report_relative_path().display()
            );
        }
        if !self.files.contains_key(&final_report) {
            bail!(
                "final report was not written through ArtifactRunWriter: {}",
                final_report.display()
            );
        }
        let audited = audit_artifact_tree(&self.run, true)?;
        verify_manifest_paths(&self.files, &audited)?;
        verify_manifest_contents(&self.run, self.files.values())?;
        let mac_key = open_artifact_auth_writer(&self.repository)?;
        mac_key.verify()?;
        let result = (|| -> Result<ArtifactFinalization> {
            let files = self.files.values().cloned().collect::<Vec<_>>();
            let publishable = publish_requested
                && self.provenance.source_revision.is_some()
                && files
                    .iter()
                    .all(|file| file.disposition == ArtifactFileDisposition::Publishable);
            let mut finalization = ArtifactFinalization {
                version: ARTIFACT_FORMAT_VERSION,
                checksum: String::new(),
                repository: self.repository.binding.clone(),
                family: self.family,
                run_id: self.run_id.as_str().to_string(),
                provenance: self.provenance.clone(),
                writer_evidence: self.writer_evidence.clone(),
                mac_key_id: mac_key.authenticator().binding().repository_id.clone(),
                mac_key_identity: mac_key.authenticator().binding().key_identity.clone(),
                final_report,
                files,
                publish_requested,
                publishable,
                hmac_sha256: String::new(),
            };
            verify_writer_evidence(&finalization.writer_evidence, &self.run_root, &self.run)?;
            finalization.checksum = finalization_checksum(&finalization)?;
            finalization.hmac_sha256 = finalization_hmac(mac_key.authenticator(), &finalization)?;
            validate_finalization(&finalization)?;
            mac_key.verify()?;
            let mut marker = serde_json::to_vec_pretty(&finalization)
                .context("failed to serialize artifact finalization marker")?;
            marker.push(b'\n');
            if u64::try_from(marker.len()).unwrap_or(u64::MAX) > MAX_FINALIZATION_BYTES {
                bail!("artifact finalization marker exceeds its bounded size");
            }
            AtomicStateWriter::scavenge_direct_temps(&self.run, FINALIZATION_MARKER)?;
            AtomicStateWriter::write_direct_fenced(
                &self.run,
                FINALIZATION_MARKER,
                &marker,
                || {
                    self.run_lock.verify(&self.run)?;
                    mac_key.verify()
                },
            )?;
            ensure_private_regular_file(&self.run.path().join(FINALIZATION_MARKER))?;
            let post_audit = audit_artifact_tree(&self.run, true)?;
            verify_manifest_paths_with_marker(&finalization.files, &post_audit)?;
            self.run.verify()?;
            self.run_root.verify()?;
            self.run_lock.verify(&self.run)?;
            Ok(finalization)
        })();
        finish_with_artifact_lock_verification(result, mac_key.verify())
    }
}

impl ArtifactRunReader {
    pub fn open(repo: impl AsRef<Path>, family: RunArtifactFamily, run_id: &RunId) -> Result<Self> {
        let repository = discover_artifact_repository(repo.as_ref())?;
        let run_root = open_existing_run_root(&repository, family)?;
        ensure_private_directory(run_root.path())?;
        let reserved = run_root.bind_existing_direct_child_directory(run_id.as_str())?;
        let run = SafeRoot::open_existing(reserved.path())?;
        ensure_private_directory(run.path())?;
        if !run.direct_child_exists(FINALIZATION_MARKER)? {
            bail!(
                "artifact run '{}' is unfinalized; marker {} is missing",
                run_id.as_str(),
                FINALIZATION_MARKER
            );
        }
        ensure_private_regular_file(&run.path().join(FINALIZATION_MARKER))?;
        let marker =
            BoundedRegularReader::read_direct(&run, FINALIZATION_MARKER, MAX_FINALIZATION_BYTES)?;
        let finalization: ArtifactFinalization = serde_json::from_slice(&marker)
            .context("failed to parse artifact finalization marker")?;
        if finalization.version != ARTIFACT_FORMAT_VERSION {
            bail!(
                "unsupported artifact finalization version {}",
                finalization.version
            );
        }
        if finalization.repository != repository.binding {
            bail!("artifact finalization repository binding does not match this repository");
        }
        if finalization.family != family || finalization.run_id != run_id.as_str() {
            bail!("artifact finalization family/run binding does not match the requested run");
        }
        if finalization.checksum != finalization_checksum(&finalization)? {
            bail!("artifact finalization checksum mismatch");
        }
        validate_finalization(&finalization)?;
        let mac_key = RepositoryAuthenticator::open_existing(&repository.common_dir)?;
        mac_key.verify_epoch()?;
        if finalization.mac_key_id != mac_key.binding().repository_id
            || finalization.mac_key_identity != mac_key.binding().key_identity
        {
            bail!("artifact finalization MAC key binding does not match repository state");
        }
        verify_finalization_hmac(&mac_key, &finalization)?;
        verify_writer_evidence(&finalization.writer_evidence, &run_root, &run)?;
        let audited = audit_artifact_tree(&run, true)?;
        verify_manifest_paths_with_marker(&finalization.files, &audited)?;
        verify_manifest_contents(&run, finalization.files.iter())?;
        run.verify()?;
        run_root.verify()?;
        mac_key.verify_epoch()?;
        Ok(Self { run, finalization })
    }

    pub fn finalization(&self) -> &ArtifactFinalization {
        &self.finalization
    }

    pub fn read(&self, relative: impl AsRef<Path>) -> Result<Vec<u8>> {
        let relative = validate_artifact_relative_path(relative.as_ref())?;
        let record = self
            .finalization
            .files
            .iter()
            .find(|record| record.path == relative)
            .with_context(|| {
                format!(
                    "artifact file is not present in the finalized manifest: {}",
                    relative.display()
                )
            })?;
        let contents = read_and_verify_record(&self.run, record)?;
        self.run.verify()?;
        Ok(contents)
    }
}

#[cfg(test)]
fn set_artifact_append_fault(point: ArtifactAppendFaultPoint) {
    ARTIFACT_APPEND_FAULT.with(|fault| fault.set(Some(point)));
}

#[cfg(test)]
fn take_artifact_append_fault(point: ArtifactAppendFaultPoint) -> bool {
    ARTIFACT_APPEND_FAULT.with(|fault| {
        if fault.get() == Some(point) {
            fault.set(None);
            true
        } else {
            false
        }
    })
}

fn write_artifact_append(file: &mut File, contents: &[u8], relative: &Path) -> Result<()> {
    #[cfg(test)]
    if take_artifact_append_fault(ArtifactAppendFaultPoint::PartialWrite) {
        let partial = contents.len().saturating_sub(1).max(1).min(contents.len());
        file.write_all(&contents[..partial]).with_context(|| {
            format!(
                "failed to inject partial artifact append {}",
                relative.display()
            )
        })?;
        bail!("injected partial artifact append before completion");
    }
    file.write_all(contents)
        .with_context(|| format!("failed to append artifact file {}", relative.display()))
}

fn run_artifact_append_fault(point: ArtifactAppendFaultPoint) -> Result<()> {
    #[cfg(test)]
    let should_fail = take_artifact_append_fault(point);
    #[cfg(not(test))]
    let should_fail = false;
    if should_fail {
        bail!("injected artifact append failure at {point:?}");
    }
    Ok(())
}

pub fn discover_repo_root(repo_path: impl AsRef<Path>) -> Result<PathBuf> {
    Ok(discover_artifact_repository(repo_path.as_ref())?.worktree)
}

pub fn run_root(repo: &Path, family: RunArtifactFamily) -> PathBuf {
    repo.join(family.run_root())
}

pub fn run_dir(repo: &Path, family: RunArtifactFamily, run_id: &RunId) -> PathBuf {
    run_root(repo, family).join(run_id.as_str())
}

pub fn final_report_path(repo: &Path, family: RunArtifactFamily, run_id: &RunId) -> PathBuf {
    run_dir(repo, family, run_id).join(family.final_report_relative_path())
}

pub fn ensure_run_dir_available(
    repo: &Path,
    family: RunArtifactFamily,
    run_id: &RunId,
) -> Result<()> {
    let repository = discover_artifact_repository(repo)?;
    let root = open_or_create_run_root(&repository, family)?;
    let lock = BoundArtifactLock::acquire(&root, ROOT_LOCK_FILE)?;
    lock.verify(&root)?;
    let result = (|| -> Result<()> {
        if root.direct_child_exists(run_id.as_str())? {
            bail!(
                "{} run id '{}' already exists at {}; choose a new --run-id or prune old artifacts first",
                family.label(),
                run_id.as_str(),
                root.path().join(run_id.as_str()).display()
            );
        }
        let reserved = root.reserve_direct_child_directory(run_id.as_str())?;
        reserved.verify(&root)
    })();
    finish_with_artifact_lock_verification(result, lock.verify(&root))
}

pub fn resolve_run_id(
    repo: impl AsRef<Path>,
    family: RunArtifactFamily,
    explicit: Option<&str>,
) -> Result<ResolvedRunId> {
    let repo = discover_repo_root(repo)?;
    let run_id = match explicit {
        Some(value) => RunId::new(value)?,
        None => generate_run_id(&repo, family)?,
    };
    check_run_dir_available(&repo, family, &run_id)?;
    let run_dir = run_dir(&repo, family, &run_id);
    Ok(ResolvedRunId {
        repo,
        run_id,
        run_dir,
    })
}

pub fn generate_run_id(repo: &Path, family: RunArtifactFamily) -> Result<RunId> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX epoch")?
        .as_millis();
    let repository = discover_artifact_repository(repo)?;
    let root = open_optional_run_root(&repository, family)?;
    for suffix in 0..1000u16 {
        let candidate = RunId::new(format!(
            "{}-{}-{}-{}",
            family.generated_prefix(),
            millis,
            process::id(),
            suffix
        ))?;
        let exists = match &root {
            Some(root) => root.direct_child_exists(candidate.as_str())?,
            None => false,
        };
        if !exists {
            return Ok(candidate);
        }
    }
    bail!(
        "failed to generate a collision-free {} run id under {}",
        family.label(),
        run_root(repo, family).display()
    )
}

pub fn list_runs(
    repo: impl AsRef<Path>,
    family: RunArtifactFamily,
) -> Result<RunArtifactListReport> {
    let repository = discover_artifact_repository(repo.as_ref())?;
    let runs = match open_optional_run_root(&repository, family)? {
        Some(root) => sorted_run_summaries(&repository, &root, family)?,
        None => Vec::new(),
    };
    Ok(RunArtifactListReport {
        family,
        run_root: family.run_root(),
        ordering: artifact_ordering(),
        runs,
    })
}

pub fn latest_run(
    repo: impl AsRef<Path>,
    family: RunArtifactFamily,
) -> Result<RunArtifactLatestReport> {
    let list = list_runs(repo, family)?;
    Ok(RunArtifactLatestReport {
        family: list.family,
        run_root: list.run_root,
        ordering: list.ordering,
        run: list.runs.into_iter().next(),
    })
}

pub fn prune_runs(
    repo: impl AsRef<Path>,
    family: RunArtifactFamily,
    keep: usize,
    dry_run: bool,
) -> Result<RunArtifactPruneReport> {
    prune_runs_with_policy(
        repo,
        family,
        &ArtifactRetentionPolicy::count_only(keep),
        dry_run,
    )
}

pub fn prune_runs_with_policy(
    repo: impl AsRef<Path>,
    family: RunArtifactFamily,
    policy: &ArtifactRetentionPolicy,
    dry_run: bool,
) -> Result<RunArtifactPruneReport> {
    prune_artifacts_at(
        repo.as_ref(),
        family.into(),
        family,
        policy,
        dry_run,
        SystemTime::now(),
    )
}

pub fn prune_artifacts_with_policy(
    repo: impl AsRef<Path>,
    family: ArtifactRetentionFamily,
    policy: &ArtifactRetentionPolicy,
    dry_run: bool,
) -> Result<RunArtifactPruneReport<ArtifactRetentionFamily>> {
    prune_artifacts_at(
        repo.as_ref(),
        family,
        family,
        policy,
        dry_run,
        SystemTime::now(),
    )
}

fn prune_artifacts_at<F: Copy>(
    repo: &Path,
    family: ArtifactRetentionFamily,
    report_family: F,
    policy: &ArtifactRetentionPolicy,
    dry_run: bool,
    now: SystemTime,
) -> Result<RunArtifactPruneReport<F>> {
    let repository = discover_artifact_repository(repo)?;
    let Some(root) = open_optional_retention_root(&repository, family)? else {
        return Ok(empty_prune_report(family, report_family, policy, dry_run));
    };
    // Dry-run is strictly read-only, including coordination metadata. Apply
    // creates/acquires the family lock before taking its inventory.
    let root_lock = if dry_run {
        None
    } else {
        let lock_name = if family == ArtifactRetentionFamily::Program {
            RETENTION_LOCK_FILE
        } else {
            ROOT_LOCK_FILE
        };
        Some(BoundArtifactLock::acquire(&root, lock_name)?)
    };
    verify_optional_artifact_lock(root_lock.as_ref(), &root)?;
    let result = (|| -> Result<RunArtifactPruneReport<F>> {
        let items = retention_items(&repository, &root, family)?;
        let scanned_bytes = items.iter().try_fold(0u64, |total, item| {
            total
                .checked_add(item.bytes)
                .context("artifact retention byte total overflow")
        })?;
        let compressible_log_bytes = items.iter().try_fold(0u64, |total, item| {
            total
                .checked_add(item.compressible_log_bytes)
                .context("artifact compressible-log byte total overflow")
        })?;
        let unfinalized_bytes = items
            .iter()
            .filter(|item| item.state != RetentionItemState::Finalized)
            .try_fold(0u64, |total, item| {
                total
                    .checked_add(item.bytes)
                    .context("unfinalized artifact byte total overflow")
            })?;

        let mut quarantine = None;
        let mut entries = Vec::with_capacity(items.len());
        let mut cumulative_bytes = 0u64;
        let mut kept_count = 0usize;
        let mut deleted_count = 0usize;
        let mut refused_unfinalized_count = 0usize;
        let mut delete_candidate_count = 0usize;
        let mut reclaimed_bytes = 0u64;
        let mut would_reclaim_bytes = 0u64;
        let mut refused_bytes = 0u64;

        for (index, item) in items.into_iter().enumerate() {
            cumulative_bytes = cumulative_bytes
                .checked_add(item.bytes)
                .context("artifact retention cumulative byte total overflow")?;
            let age_seconds = artifact_age_seconds(now, item.modified);
            let mut selected_by = Vec::new();
            if index >= policy.max_count {
                selected_by.push(ArtifactRetentionLimit::MaxCount);
            }
            if policy
                .max_age
                .is_some_and(|max_age| age_seconds >= max_age.as_secs())
            {
                selected_by.push(ArtifactRetentionLimit::MaxAge);
            }
            if policy
                .max_total_bytes
                .is_some_and(|max_bytes| cumulative_bytes > max_bytes)
            {
                selected_by.push(ArtifactRetentionLimit::MaxTotalBytes);
            }
            if item.state != RetentionItemState::Finalized
                && policy
                    .unfinalized_grace
                    .is_some_and(|grace| age_seconds >= grace.as_secs())
            {
                selected_by.push(ArtifactRetentionLimit::UnfinalizedGrace);
            }

            if selected_by.is_empty() {
                kept_count = kept_count.saturating_add(1);
                entries.push(retention_entry(
                    item,
                    age_seconds,
                    RunArtifactPruneAction::Keep,
                    selected_by,
                    None,
                ));
                continue;
            }
            delete_candidate_count = delete_candidate_count.saturating_add(1);

            match item.state {
                RetentionItemState::InvalidFinalization if !policy.reclaim_unverifiable => {
                    kept_count = kept_count.saturating_add(1);
                    refused_unfinalized_count = refused_unfinalized_count.saturating_add(1);
                    refused_bytes = refused_bytes
                        .checked_add(item.bytes)
                        .context("refused artifact byte total overflow")?;
                    entries.push(retention_entry(
                        item,
                        age_seconds,
                        RunArtifactPruneAction::RefuseUnfinalized,
                        selected_by,
                        Some(
                            "refusing to reclaim an artifact with a present but unverifiable finalization marker without explicit opt-in"
                                .to_string(),
                        ),
                    ));
                }
                RetentionItemState::InvalidFinalization
                | RetentionItemState::MissingFinalization
                | RetentionItemState::External => {
                    if item.state == RetentionItemState::External
                        && !policy.external_writers_stopped
                    {
                        kept_count = kept_count.saturating_add(1);
                        refused_unfinalized_count = refused_unfinalized_count.saturating_add(1);
                        refused_bytes = refused_bytes
                            .checked_add(item.bytes)
                            .context("refused artifact byte total overflow")?;
                        entries.push(retention_entry(
                            item,
                            age_seconds,
                            RunArtifactPruneAction::RefuseUnfinalized,
                            selected_by,
                            Some(
                                "refusing to reclaim an external artifact without an explicit acknowledgement that its writers are stopped"
                                    .to_string(),
                            ),
                        ));
                        continue;
                    }
                    let Some(grace) = policy.unfinalized_grace else {
                        kept_count = kept_count.saturating_add(1);
                        refused_unfinalized_count = refused_unfinalized_count.saturating_add(1);
                        refused_bytes = refused_bytes
                            .checked_add(item.bytes)
                            .context("refused artifact byte total overflow")?;
                        entries.push(retention_entry(
                            item,
                            age_seconds,
                            RunArtifactPruneAction::RefuseUnfinalized,
                            selected_by,
                            Some(
                                "refusing to reclaim an unfinalized artifact because no expiry grace was configured"
                                    .to_string(),
                            ),
                        ));
                        continue;
                    };
                    if age_seconds < grace.as_secs() {
                        kept_count = kept_count.saturating_add(1);
                        refused_unfinalized_count = refused_unfinalized_count.saturating_add(1);
                        refused_bytes = refused_bytes
                            .checked_add(item.bytes)
                            .context("refused artifact byte total overflow")?;
                        entries.push(retention_entry(
                            item,
                            age_seconds,
                            RunArtifactPruneAction::RefuseUnfinalized,
                            selected_by,
                            Some(format!(
                                "refusing to reclaim a fresh unfinalized artifact before its {} second grace expires",
                                grace.as_secs()
                            )),
                        ));
                        continue;
                    }
                    if let Some(reason) = item.unsafe_reason.clone() {
                        kept_count = kept_count.saturating_add(1);
                        refused_unfinalized_count = refused_unfinalized_count.saturating_add(1);
                        refused_bytes = refused_bytes
                            .checked_add(item.bytes)
                            .context("refused artifact byte total overflow")?;
                        entries.push(retention_entry(
                            item,
                            age_seconds,
                            RunArtifactPruneAction::RefuseUnfinalized,
                            selected_by,
                            Some(format!(
                                "refusing to reclaim an unsafe unfinalized artifact: {reason}"
                            )),
                        ));
                        continue;
                    }

                    let mut held_unfinalized_lock = None;
                    if item.state != RetentionItemState::External {
                        let run = SafeRoot::open_existing(&item.absolute_path)?;
                        match KernelStateLock::try_acquire_existing_exclusive_direct(
                            &run,
                            RUN_LOCK_FILE,
                        )? {
                            ExistingExclusiveLock::Busy => {
                                kept_count = kept_count.saturating_add(1);
                                refused_unfinalized_count =
                                    refused_unfinalized_count.saturating_add(1);
                                refused_bytes = refused_bytes
                                    .checked_add(item.bytes)
                                    .context("refused artifact byte total overflow")?;
                                entries.push(retention_entry(
                                    item,
                                    age_seconds,
                                    RunArtifactPruneAction::RefuseUnfinalized,
                                    selected_by,
                                    Some(
                                        "refusing to reclaim an active unfinalized artifact whose writer lock is held"
                                            .to_string(),
                                    ),
                                ));
                                continue;
                            }
                            ExistingExclusiveLock::Missing => {
                                if !policy.external_writers_stopped {
                                    kept_count = kept_count.saturating_add(1);
                                    refused_unfinalized_count =
                                        refused_unfinalized_count.saturating_add(1);
                                    refused_bytes = refused_bytes
                                        .checked_add(item.bytes)
                                        .context("refused artifact byte total overflow")?;
                                    entries.push(retention_entry(
                                        item,
                                        age_seconds,
                                        RunArtifactPruneAction::RefuseUnfinalized,
                                        selected_by,
                                        Some(
                                            "refusing to reclaim a legacy artifact with no cooperative writer lock without an explicit acknowledgement that its writers are stopped"
                                                .to_string(),
                                        ),
                                    ));
                                    continue;
                                }
                            }
                            ExistingExclusiveLock::Acquired(lock) => {
                                held_unfinalized_lock = Some(lock);
                            }
                        }
                    }

                    if let Some(root_lock) = root_lock.as_ref() {
                        root_lock.verify(&root)?;
                    }
                    let rebound =
                        root.bind_existing_managed_direct_child_directory(&item.run_id)?;
                    if rebound.identity() != &item.identity {
                        bail!(
                            "artifact identity changed before unfinalized quarantine: {}",
                            item.run_id
                        );
                    }
                    let rebound_root = SafeRoot::open_existing(rebound.path())?;
                    if let Some(lock) = &held_unfinalized_lock {
                        lock.verify_direct_binding(&rebound_root)?;
                    }
                    let finalization_state_changed = match item.state {
                        RetentionItemState::MissingFinalization => {
                            rebound_root.direct_child_exists(FINALIZATION_MARKER)?
                        }
                        RetentionItemState::InvalidFinalization => {
                            let authenticated = family.authenticated().context(
                                "unverifiable retention item lacks an authenticated family",
                            )?;
                            let run_id = RunId::new(&item.run_id)?;
                            !rebound_root.direct_child_exists(FINALIZATION_MARKER)?
                                || ArtifactRunReader::open(
                                    &repository.worktree,
                                    authenticated,
                                    &run_id,
                                )
                                .is_ok()
                        }
                        RetentionItemState::External | RetentionItemState::Finalized => false,
                    };
                    if finalization_state_changed {
                        kept_count = kept_count.saturating_add(1);
                        refused_unfinalized_count = refused_unfinalized_count.saturating_add(1);
                        refused_bytes = refused_bytes
                            .checked_add(item.bytes)
                            .context("refused artifact byte total overflow")?;
                        entries.push(retention_entry(
                            item,
                            age_seconds,
                            RunArtifactPruneAction::RefuseUnfinalized,
                            selected_by,
                            Some(
                                "refusing to reclaim an artifact whose finalization state changed during pruning"
                                    .to_string(),
                            ),
                        ));
                        continue;
                    }
                    let refreshed = retention_inventory(&rebound_root)?;
                    let refreshed_age = artifact_age_seconds(now, refreshed.modified);
                    if let Some(reason) = refreshed.unsafe_reason {
                        kept_count = kept_count.saturating_add(1);
                        refused_unfinalized_count = refused_unfinalized_count.saturating_add(1);
                        refused_bytes = refused_bytes
                            .checked_add(item.bytes)
                            .context("refused artifact byte total overflow")?;
                        entries.push(retention_entry(
                            item,
                            refreshed_age,
                            RunArtifactPruneAction::RefuseUnfinalized,
                            selected_by,
                            Some(format!(
                                "refusing to reclaim an artifact that became unsafe during pruning: {reason}"
                            )),
                        ));
                        continue;
                    }
                    if refreshed_age < grace.as_secs() || refreshed.bytes != item.bytes {
                        kept_count = kept_count.saturating_add(1);
                        refused_unfinalized_count = refused_unfinalized_count.saturating_add(1);
                        refused_bytes = refused_bytes
                            .checked_add(item.bytes)
                            .context("refused artifact byte total overflow")?;
                        entries.push(retention_entry(
                            item,
                            refreshed_age,
                            RunArtifactPruneAction::RefuseUnfinalized,
                            selected_by,
                            Some(
                                "refusing to reclaim an unfinalized artifact that changed during pruning"
                                    .to_string(),
                            ),
                        ));
                        continue;
                    }
                    if dry_run {
                        would_reclaim_bytes = would_reclaim_bytes
                            .checked_add(item.bytes)
                            .context("would-reclaim artifact byte total overflow")?;
                        entries.push(retention_entry(
                            item,
                            refreshed_age,
                            RunArtifactPruneAction::WouldDelete,
                            selected_by,
                            Some(format!(
                                "idle artifact is older than its {} second grace",
                                grace.as_secs()
                            )),
                        ));
                        continue;
                    }

                    let root_lock = root_lock
                        .as_ref()
                        .context("apply retention is missing its root lock")?;
                    delete_retention_item(
                        &root,
                        root_lock,
                        &mut quarantine,
                        retention_quarantine_name(family),
                        &item,
                        held_unfinalized_lock.as_ref(),
                    )?;
                    reclaimed_bytes = reclaimed_bytes
                        .checked_add(item.bytes)
                        .context("reclaimed artifact byte total overflow")?;
                    deleted_count = deleted_count.saturating_add(1);
                    let expired_kind = match item.state {
                        RetentionItemState::InvalidFinalization => "unverifiable",
                        RetentionItemState::External => "external",
                        RetentionItemState::MissingFinalization => "unfinalized",
                        RetentionItemState::Finalized => "finalized",
                    };
                    entries.push(retention_entry(
                        item,
                        refreshed_age,
                        RunArtifactPruneAction::Delete,
                        selected_by,
                        Some(format!(
                            "expired {} artifact exceeded its {} second grace",
                            expired_kind,
                            grace.as_secs(),
                        )),
                    ));
                }
                RetentionItemState::Finalized => {
                    let authenticated = family
                        .authenticated()
                        .context("finalized retention item lacks an authenticated family")?;
                    let run_id = RunId::new(&item.run_id)?;
                    if let Err(error) =
                        ArtifactRunReader::open(&repository.worktree, authenticated, &run_id)
                    {
                        kept_count = kept_count.saturating_add(1);
                        refused_unfinalized_count = refused_unfinalized_count.saturating_add(1);
                        refused_bytes = refused_bytes
                            .checked_add(item.bytes)
                            .context("refused artifact byte total overflow")?;
                        entries.push(retention_entry(
                            item,
                            age_seconds,
                            RunArtifactPruneAction::RefuseUnfinalized,
                            selected_by,
                            Some(format!(
                                "refusing to reclaim an artifact that lost valid finalization: {error:#}"
                            )),
                        ));
                        continue;
                    }
                    if dry_run {
                        would_reclaim_bytes = would_reclaim_bytes
                            .checked_add(item.bytes)
                            .context("would-reclaim artifact byte total overflow")?;
                        entries.push(retention_entry(
                            item,
                            age_seconds,
                            RunArtifactPruneAction::WouldDelete,
                            selected_by,
                            None,
                        ));
                        continue;
                    }

                    let root_lock = root_lock
                        .as_ref()
                        .context("apply retention is missing its root lock")?;
                    root_lock.verify(&root)?;
                    let rebound =
                        root.bind_existing_managed_direct_child_directory(&item.run_id)?;
                    if rebound.identity() != &item.identity {
                        bail!(
                            "artifact run identity changed before quarantine: {}",
                            item.run_id
                        );
                    }
                    let rebound_root = SafeRoot::open_existing(rebound.path())?;
                    let run_lock = BoundArtifactLock::acquire(&rebound_root, RUN_LOCK_FILE)?;
                    run_lock.verify(&rebound_root)?;
                    let validation =
                        ArtifactRunReader::open(&repository.worktree, authenticated, &run_id);
                    let validation = finish_with_artifact_lock_verification(
                        validation,
                        run_lock.verify(&rebound_root),
                    );
                    if let Err(error) = validation {
                        kept_count = kept_count.saturating_add(1);
                        refused_unfinalized_count = refused_unfinalized_count.saturating_add(1);
                        refused_bytes = refused_bytes
                            .checked_add(item.bytes)
                            .context("refused artifact byte total overflow")?;
                        entries.push(retention_entry(
                            item,
                            age_seconds,
                            RunArtifactPruneAction::RefuseUnfinalized,
                            selected_by,
                            Some(format!(
                                "refusing to reclaim an artifact that lost valid finalization while waiting for its writer lock: {error:#}"
                            )),
                        ));
                        continue;
                    }
                    delete_retention_item(
                        &root,
                        root_lock,
                        &mut quarantine,
                        retention_quarantine_name(family),
                        &item,
                        Some(&run_lock.lock),
                    )?;
                    reclaimed_bytes = reclaimed_bytes
                        .checked_add(item.bytes)
                        .context("reclaimed artifact byte total overflow")?;
                    deleted_count = deleted_count.saturating_add(1);
                    entries.push(retention_entry(
                        item,
                        age_seconds,
                        RunArtifactPruneAction::Delete,
                        selected_by,
                        None,
                    ));
                }
            }
        }

        verify_optional_artifact_lock(root_lock.as_ref(), &root)?;
        let planned_reclaimed_bytes = if dry_run {
            would_reclaim_bytes
        } else {
            reclaimed_bytes
        };
        Ok(RunArtifactPruneReport {
            family: report_family,
            run_root: family.run_root(),
            ordering: retention_ordering(),
            keep: policy.max_count,
            max_age_seconds: policy.max_age.map(|age| age.as_secs()),
            max_total_bytes: policy.max_total_bytes,
            unfinalized_grace_seconds: policy.unfinalized_grace.map(|grace| grace.as_secs()),
            reclaim_unverifiable: policy.reclaim_unverifiable,
            external_writers_stopped: policy.external_writers_stopped,
            dry_run,
            kept_count,
            deleted_count,
            refused_unfinalized_count,
            delete_candidate_count,
            scanned_bytes,
            retained_bytes: scanned_bytes.saturating_sub(reclaimed_bytes),
            projected_retained_bytes: scanned_bytes.saturating_sub(planned_reclaimed_bytes),
            reclaimed_bytes,
            would_reclaim_bytes,
            refused_bytes,
            unfinalized_bytes,
            compression_strategy: ArtifactCompressionStrategy::NoneRequiresWriterMigration,
            compressible_log_bytes,
            compressed_bytes: 0,
            entries,
        })
    })();
    match root_lock.as_ref() {
        Some(root_lock) => finish_with_artifact_lock_verification(result, root_lock.verify(&root)),
        None => result,
    }
}

pub fn artifact_ordering() -> &'static str {
    "newest first by final-report modification time, then run directory modification time, ties by descending run id"
}

fn retention_ordering() -> &'static str {
    "newest first by latest bounded descendant activity, ties by descending artifact id"
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetentionItemState {
    Finalized,
    MissingFinalization,
    InvalidFinalization,
    External,
}

struct RetentionItem {
    run_id: String,
    run_dir: PathBuf,
    absolute_path: PathBuf,
    identity: FileIdentity,
    bytes: u64,
    compressible_log_bytes: u64,
    modified: SystemTime,
    unsafe_reason: Option<String>,
    state: RetentionItemState,
}

struct RetentionInventory {
    bytes: u64,
    compressible_log_bytes: u64,
    modified: SystemTime,
    unsafe_reason: Option<String>,
}

fn open_optional_retention_root(
    repository: &ArtifactRepository,
    family: ArtifactRetentionFamily,
) -> Result<Option<SafeRoot>> {
    if let Some(authenticated) = family.authenticated() {
        return open_optional_run_root(repository, authenticated);
    }
    let path = repository.worktree.join(family.run_root());
    match fs::symlink_metadata(&path) {
        Ok(_) => SafeRoot::open_existing(&path).map(Some).with_context(|| {
            format!(
                "existing {} retention root is unsafe: {}",
                family.label(),
                path.display()
            )
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error)
            .with_context(|| format!("failed to inspect retention root {}", path.display())),
    }
}

fn retention_items(
    repository: &ArtifactRepository,
    root: &SafeRoot,
    family: ArtifactRetentionFamily,
) -> Result<Vec<RetentionItem>> {
    let mut items = if let Some(authenticated) = family.authenticated() {
        authenticated_retention_items(repository, root, authenticated)?
    } else {
        external_retention_items(root, family)?
    };
    items.sort_by(|left, right| {
        right
            .modified
            .cmp(&left.modified)
            .then_with(|| right.run_id.cmp(&left.run_id))
    });
    Ok(items)
}

fn authenticated_retention_items(
    repository: &ArtifactRepository,
    root: &SafeRoot,
    family: RunArtifactFamily,
) -> Result<Vec<RetentionItem>> {
    let mut items = Vec::new();
    for summary in sorted_run_summaries(repository, root, family)? {
        let binding = root.bind_existing_managed_direct_child_directory(&summary.run_id)?;
        if binding.identity() != &summary.identity {
            bail!(
                "artifact run identity changed during retention inventory: {}",
                summary.run_id
            );
        }
        let run = SafeRoot::open_existing(binding.path())?;
        let marker_exists = run.direct_child_exists(FINALIZATION_MARKER)?;
        let inventory = retention_inventory(&run)?;
        let state = if summary.finalized {
            RetentionItemState::Finalized
        } else if marker_exists {
            RetentionItemState::InvalidFinalization
        } else {
            RetentionItemState::MissingFinalization
        };
        items.push(RetentionItem {
            run_id: summary.run_id,
            run_dir: summary.run_dir,
            absolute_path: binding.path().to_path_buf(),
            identity: binding.identity().clone(),
            bytes: inventory.bytes,
            compressible_log_bytes: inventory.compressible_log_bytes,
            modified: inventory.modified,
            unsafe_reason: inventory.unsafe_reason,
            state,
        });
    }
    Ok(items)
}

fn external_retention_items(
    root: &SafeRoot,
    family: ArtifactRetentionFamily,
) -> Result<Vec<RetentionItem>> {
    root.verify()?;
    let mut items = Vec::new();
    let mut entry_count = 0usize;
    for entry in fs::read_dir(root.path())
        .with_context(|| format!("failed to read retention root {}", root.path().display()))?
    {
        entry_count = entry_count
            .checked_add(1)
            .context("retention root entry count overflow")?;
        if entry_count > MAX_RETENTION_TREE_ENTRIES {
            bail!(
                "retention root exceeds its {} entry budget",
                MAX_RETENTION_TREE_ENTRIES
            );
        }
        let entry = entry.context("failed to inspect retention root entry")?;
        let name = entry.file_name();
        if name == ROOT_LOCK_FILE
            || name == RETENTION_LOCK_FILE
            || name == QUARANTINE_DIRECTORY
            || name == RETENTION_QUARANTINE_DIRECTORY
        {
            continue;
        }
        let run_id = name
            .to_str()
            .context("retention artifact id is not valid UTF-8")?
            .to_string();
        if family == ArtifactRetentionFamily::Program
            && (!run_id.starts_with("program-") || run_id == "program-")
        {
            continue;
        }
        let binding = root
            .bind_existing_managed_direct_child_directory(&name)
            .with_context(|| format!("unsafe {} artifact: {run_id}", family.label()))?;
        let item_root = SafeRoot::open_existing(binding.path())?;
        let inventory = retention_inventory(&item_root)?;
        items.push(RetentionItem {
            run_dir: family.run_root().join(&run_id),
            run_id,
            absolute_path: binding.path().to_path_buf(),
            identity: binding.identity().clone(),
            bytes: inventory.bytes,
            compressible_log_bytes: inventory.compressible_log_bytes,
            modified: inventory.modified,
            unsafe_reason: inventory.unsafe_reason,
            state: RetentionItemState::External,
        });
    }
    root.verify()?;
    Ok(items)
}

fn retention_inventory(root: &SafeRoot) -> Result<RetentionInventory> {
    root.verify()?;
    let mut bytes = 0u64;
    let mut compressible_log_bytes = 0u64;
    let mut modified = fs::symlink_metadata(root.path())
        .and_then(|metadata| metadata.modified())
        .unwrap_or(UNIX_EPOCH);
    let mut unsafe_reason = None;
    let entries = BoundedTreeWalker::walk_with(
        root.path(),
        BoundedTreeWalkLimits {
            max_depth: MAX_RETENTION_TREE_DEPTH,
            max_entries: MAX_RETENTION_TREE_ENTRIES,
            max_path_bytes: MAX_RETENTION_TREE_PATH_BYTES,
            max_total_path_bytes: MAX_RETENTION_TREE_TOTAL_PATH_BYTES,
            max_duration: RETENTION_TREE_MAX_DURATION,
            same_device: true,
        },
        |entry| {
            Ok(if entry.kind == BoundedTreeEntryKind::Directory {
                BoundedTreeWalkAction::RecordAndDescend
            } else {
                BoundedTreeWalkAction::Record
            })
        },
    )?;
    for entry in entries {
        modified = modified.max(retention_entry_modified(&entry));
        match entry.kind {
            BoundedTreeEntryKind::Directory => {}
            BoundedTreeEntryKind::RegularFile => {
                bytes = bytes
                    .checked_add(entry.size_bytes)
                    .context("artifact retention item byte total overflow")?;
                if is_compressible_log(&entry.relative_path) {
                    compressible_log_bytes =
                        compressible_log_bytes
                            .checked_add(entry.size_bytes)
                            .context("compressible artifact log byte total overflow")?;
                }
                if !entry.is_safe_regular_file() && unsafe_reason.is_none() {
                    unsafe_reason = Some(format!(
                        "regular file is multiply linked or has privileged mode bits: {}",
                        entry.relative_path.display()
                    ));
                }
            }
            BoundedTreeEntryKind::Symlink => {
                if unsafe_reason.is_none() {
                    unsafe_reason = Some(format!(
                        "symbolic link is present: {}",
                        entry.relative_path.display()
                    ));
                }
            }
            BoundedTreeEntryKind::Special => {
                if unsafe_reason.is_none() {
                    unsafe_reason = Some(format!(
                        "special file is present: {}",
                        entry.relative_path.display()
                    ));
                }
            }
        }
    }
    root.verify()?;
    Ok(RetentionInventory {
        bytes,
        compressible_log_bytes,
        modified,
        unsafe_reason,
    })
}

fn retention_entry_modified(entry: &crate::safe_state::BoundedTreeEntry) -> SystemTime {
    let nanoseconds = u32::try_from(entry.modified_nanoseconds)
        .ok()
        .filter(|value| *value < 1_000_000_000)
        .unwrap_or(0);
    if entry.modified_seconds >= 0 {
        UNIX_EPOCH
            .checked_add(Duration::new(entry.modified_seconds as u64, nanoseconds))
            .unwrap_or(UNIX_EPOCH)
    } else {
        UNIX_EPOCH
            .checked_sub(Duration::new(
                entry.modified_seconds.unsigned_abs(),
                nanoseconds,
            ))
            .unwrap_or(UNIX_EPOCH)
    }
}

fn is_compressible_log(path: &Path) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .is_some_and(|extension| matches!(extension, "jsonl" | "log"))
}

fn artifact_age_seconds(now: SystemTime, modified: SystemTime) -> u64 {
    now.duration_since(modified).unwrap_or_default().as_secs()
}

fn retention_entry(
    item: RetentionItem,
    age_seconds: u64,
    action: RunArtifactPruneAction,
    selected_by: Vec<ArtifactRetentionLimit>,
    reason: Option<String>,
) -> RunArtifactPruneEntry {
    RunArtifactPruneEntry {
        run_id: item.run_id,
        run_dir: item.run_dir,
        bytes: item.bytes,
        age_seconds,
        action,
        selected_by,
        reason,
    }
}

fn retention_quarantine_name(family: ArtifactRetentionFamily) -> &'static str {
    if family.authenticated().is_some() {
        QUARANTINE_DIRECTORY
    } else {
        RETENTION_QUARANTINE_DIRECTORY
    }
}

fn open_or_create_named_quarantine(root: &SafeRoot, name: &str) -> Result<SafeRoot> {
    let binding = if root.direct_child_exists(name)? {
        root.bind_existing_direct_child_directory(name)?
    } else {
        root.reserve_direct_child_directory(name)?
    };
    SafeRoot::open_or_create(binding.path())
}

fn delete_retention_item(
    root: &SafeRoot,
    root_lock: &BoundArtifactLock,
    quarantine: &mut Option<SafeRoot>,
    quarantine_directory: &str,
    item: &RetentionItem,
    run_lock: Option<&KernelStateLock>,
) -> Result<()> {
    root_lock.verify(root)?;
    if quarantine.is_none() {
        let created = open_or_create_named_quarantine(root, quarantine_directory)?;
        ensure_quarantine_empty(&created)?;
        *quarantine = Some(created);
    }
    let quarantine = quarantine
        .as_ref()
        .context("artifact quarantine unavailable")?;
    let quarantine_name = quarantine.random_direct_child_name(&item.run_id)?;
    rename_bound_directory(
        root,
        item.run_id.as_ref(),
        &item.identity,
        quarantine,
        &quarantine_name,
    )?;
    let quarantined_item = SafeRoot::open_existing(quarantine.path().join(&quarantine_name))?;
    if let Some(lock) = run_lock {
        lock.verify_direct_binding(&quarantined_item)?;
    }
    remove_direct_child_tree(
        quarantine,
        &quarantine_name,
        Some(&item.identity),
        TreeLinkPolicy::RejectLinksAndSpecialFiles,
    )
    .with_context(|| {
        format!(
            "artifact '{}' was quarantined but could not be safely deleted; inspect {}",
            item.run_id,
            quarantine.path().join(&quarantine_name).display()
        )
    })?;
    root_lock.verify(root)
}

fn check_run_dir_available(repo: &Path, family: RunArtifactFamily, run_id: &RunId) -> Result<()> {
    let repository = discover_artifact_repository(repo)?;
    if let Some(root) = open_optional_run_root(&repository, family)? {
        if root.direct_child_exists(run_id.as_str())? {
            bail!(
                "{} run id '{}' already exists at {}; choose a new --run-id or prune old artifacts first",
                family.label(),
                run_id.as_str(),
                root.path().join(run_id.as_str()).display()
            );
        }
    }
    Ok(())
}

fn discover_artifact_repository(repo_path: &Path) -> Result<ArtifactRepository> {
    let repo = crate::git_repository::discover(repo_path)
        .with_context(|| format!("failed to discover repository from {}", repo_path.display()))?;
    artifact_repository_from_open(&repo)
}

fn artifact_repository_from_open(repo: &Repository) -> Result<ArtifactRepository> {
    let worktree = repo
        .workdir()
        .context("repository command requires a non-bare repository")?;
    let worktree_root =
        SafeRoot::open_existing(worktree).context("repository worktree is not safely reachable")?;
    let common_root = SafeRoot::open_existing(repo.commondir())
        .context("Git common directory is not safely reachable")?;
    Ok(ArtifactRepository {
        binding: ArtifactRepositoryBinding {
            common_dir_path_checksum: stable_checksum(&filesystem_path_bytes(common_root.path())),
            common_dir_identity: common_root.identity().clone(),
            worktree_path_checksum: stable_checksum(&filesystem_path_bytes(worktree_root.path())),
            worktree_identity: worktree_root.identity().clone(),
        },
        common_dir: common_root.path().to_path_buf(),
        worktree: worktree_root.path().to_path_buf(),
    })
}

fn scan_registered_finalization_markers(
    repository: &ArtifactRepository,
    key: Option<&RepositoryAuthenticator>,
) -> Result<usize> {
    let mut entries = 0usize;
    let mut markers = 0usize;
    let mut marker_bytes = 0u64;
    for registered in registered_artifact_repositories(repository)? {
        for family in [
            RunArtifactFamily::Autopilot,
            RunArtifactFamily::Consult,
            RunArtifactFamily::Inbox,
            RunArtifactFamily::Supervise,
        ] {
            let Some(root) = open_optional_run_root(&registered, family)? else {
                continue;
            };
            root.verify()?;
            for entry in fs::read_dir(root.path()).with_context(|| {
                format!(
                    "failed to scan {} artifacts before MAC-key use",
                    family.label()
                )
            })? {
                observe_marker_scan_entry(&mut entries)?;
                let entry = entry.context("failed to inspect artifact marker-scan entry")?;
                let name = entry.file_name();
                if name == ROOT_LOCK_FILE {
                    ensure_private_regular_file(&entry.path())?;
                    continue;
                }
                if name == QUARANTINE_DIRECTORY {
                    let quarantine = root.bind_existing_direct_child_directory(&name)?;
                    let quarantine = SafeRoot::open_existing(quarantine.path())?;
                    scan_markers_in_quarantine(
                        &registered,
                        family,
                        &quarantine,
                        key,
                        &mut entries,
                        &mut markers,
                        &mut marker_bytes,
                    )?;
                    continue;
                }
                let run = root.bind_existing_managed_direct_child_directory(&name)?;
                let run = SafeRoot::open_existing(run.path())?;
                observe_finalization_marker(
                    &registered,
                    family,
                    &run,
                    key,
                    &mut markers,
                    &mut marker_bytes,
                )?;
            }
            root.verify()?;
        }
    }
    Ok(markers)
}

fn scan_markers_in_quarantine(
    repository: &ArtifactRepository,
    family: RunArtifactFamily,
    quarantine: &SafeRoot,
    key: Option<&RepositoryAuthenticator>,
    entries: &mut usize,
    markers: &mut usize,
    marker_bytes: &mut u64,
) -> Result<()> {
    quarantine.verify()?;
    for entry in fs::read_dir(quarantine.path()).with_context(|| {
        format!(
            "failed to scan artifact quarantine {} for final markers",
            quarantine.path().display()
        )
    })? {
        observe_marker_scan_entry(entries)?;
        let entry = entry.context("failed to inspect quarantined artifact run")?;
        let run = quarantine.bind_existing_managed_direct_child_directory(entry.file_name())?;
        let run = SafeRoot::open_existing(run.path())?;
        observe_finalization_marker(repository, family, &run, key, markers, marker_bytes)?;
    }
    quarantine.verify()?;
    Ok(())
}

fn observe_marker_scan_entry(entries: &mut usize) -> Result<()> {
    *entries = entries
        .checked_add(1)
        .context("artifact marker scan entry count overflow")?;
    if *entries > MAX_RUN_ROOT_ENTRIES.saturating_mul(8) {
        bail!("artifact marker scan exceeded its global entry budget");
    }
    Ok(())
}

fn observe_finalization_marker(
    repository: &ArtifactRepository,
    family: RunArtifactFamily,
    run: &SafeRoot,
    key: Option<&RepositoryAuthenticator>,
    markers: &mut usize,
    marker_bytes: &mut u64,
) -> Result<()> {
    if !run.direct_child_exists(FINALIZATION_MARKER)? {
        return Ok(());
    }
    *markers = markers
        .checked_add(1)
        .context("artifact finalization marker count overflow")?;
    if let Some(key) = key {
        verify_finalization_marker_key_binding(repository, family, run, key, marker_bytes)?;
    }
    Ok(())
}

fn verify_finalization_marker_key_binding(
    repository: &ArtifactRepository,
    family: RunArtifactFamily,
    run: &SafeRoot,
    key: &RepositoryAuthenticator,
    marker_bytes: &mut u64,
) -> Result<()> {
    ensure_private_regular_file(&run.path().join(FINALIZATION_MARKER))?;
    let marker =
        BoundedRegularReader::read_direct(run, FINALIZATION_MARKER, MAX_FINALIZATION_BYTES)?;
    *marker_bytes = marker_bytes
        .checked_add(u64::try_from(marker.len()).context("marker length overflow")?)
        .context("artifact marker scan byte count overflow")?;
    if *marker_bytes > MAX_MARKER_SCAN_TOTAL_BYTES {
        bail!(
            "artifact marker scan exceeds its {} byte aggregate budget",
            MAX_MARKER_SCAN_TOTAL_BYTES
        );
    }
    let finalization: ArtifactFinalization = serde_json::from_slice(&marker)
        .context("failed to parse existing artifact finalization marker during key validation")?;
    if finalization.version != ARTIFACT_FORMAT_VERSION {
        bail!(
            "existing artifact finalization marker has unsupported version {}",
            finalization.version
        );
    }
    if finalization.repository != repository.binding || finalization.family != family {
        bail!("existing artifact finalization marker has the wrong repository/family binding");
    }
    if finalization.checksum != finalization_checksum(&finalization)? {
        bail!("existing artifact finalization marker checksum mismatch");
    }
    validate_finalization(&finalization)?;
    if finalization.mac_key_id != key.binding().repository_id
        || finalization.mac_key_identity != key.binding().key_identity
    {
        bail!("artifact finalization MAC key does not match existing marker binding");
    }
    verify_finalization_hmac(key, &finalization)?;
    run.verify()
}

fn registered_artifact_repositories(
    repository: &ArtifactRepository,
) -> Result<Vec<ArtifactRepository>> {
    let common_repo = crate::git_repository::open(&repository.common_dir).with_context(|| {
        format!(
            "failed to open common repository while scanning artifact key scope {}",
            repository.common_dir.display()
        )
    })?;
    let common_root = SafeRoot::open_existing(&repository.common_dir)?;
    let registered_names = bounded_registered_worktree_names(&common_root)?;
    let listed = common_repo
        .worktrees()
        .context("failed to enumerate registered linked worktrees for artifact key validation")?;
    if listed.len() > MAX_REGISTERED_ARTIFACT_WORKTREES {
        bail!(
            "registered linked worktree count exceeds its {} entry budget",
            MAX_REGISTERED_ARTIFACT_WORKTREES
        );
    }
    let mut listed_names = BTreeSet::new();
    for name in listed.iter() {
        let name = name
            .context("failed to decode registered linked worktree name")?
            .context("registered linked worktree name is missing")?;
        if name.is_empty() || name.len() > MAX_REGISTERED_WORKTREE_NAME_BYTES {
            bail!("registered linked worktree name exceeds its bounded format");
        }
        if !listed_names.insert(name.to_string()) {
            bail!("duplicate registered linked worktree name: {name}");
        }
    }
    if listed_names != registered_names {
        bail!("Git linked-worktree registry changed or contains unreadable/stale entries");
    }

    let main = artifact_repository_from_open(&common_repo)
        .context("failed to bind the main worktree for artifact key validation")?;
    verify_common_artifact_repository(repository, &main)?;
    let mut repositories = vec![main];
    let mut paths = BTreeSet::from([repositories[0].worktree.clone()]);
    let mut identities = BTreeSet::from([(
        repositories[0].binding.worktree_identity.device,
        repositories[0].binding.worktree_identity.file,
    )]);

    for name in listed_names {
        let worktree = common_repo
            .find_worktree(&name)
            .with_context(|| format!("failed to open registered linked worktree '{name}'"))?;
        worktree
            .validate()
            .with_context(|| format!("registered linked worktree '{name}' is stale or invalid"))?;
        validate_registered_worktree_path(worktree.path())?;
        let worktree_root = SafeRoot::open_existing(worktree.path()).with_context(|| {
            format!("registered linked worktree '{name}' is not safely reachable without links")
        })?;
        let linked_repo = crate::git_repository::open(worktree_root.path())
            .with_context(|| format!("failed to open registered linked worktree '{name}'"))?;
        let linked = artifact_repository_from_open(&linked_repo)
            .with_context(|| format!("failed to bind registered linked worktree '{name}'"))?;
        verify_common_artifact_repository(repository, &linked)?;
        if linked.binding.worktree_identity != *worktree_root.identity() {
            bail!("registered linked worktree '{name}' changed identity while opening");
        }
        if !paths.insert(linked.worktree.clone())
            || !identities.insert((
                linked.binding.worktree_identity.device,
                linked.binding.worktree_identity.file,
            ))
        {
            bail!("registered linked worktree '{name}' aliases another worktree");
        }
        repositories.push(linked);
    }
    if !repositories.iter().any(|candidate| {
        candidate.worktree == repository.worktree
            && candidate.binding.worktree_identity == repository.binding.worktree_identity
    }) {
        bail!("calling artifact worktree is not the main or a valid registered linked worktree");
    }
    common_root.verify()?;
    Ok(repositories)
}

fn bounded_registered_worktree_names(common_root: &SafeRoot) -> Result<BTreeSet<String>> {
    if !common_root.direct_child_exists("worktrees")? {
        return Ok(BTreeSet::new());
    }
    let registry = common_root.bind_existing_managed_direct_child_directory("worktrees")?;
    let registry = SafeRoot::open_existing(registry.path())?;
    let mut names = BTreeSet::new();
    for entry in
        fs::read_dir(registry.path()).context("failed to preflight Git linked-worktree registry")?
    {
        if names.len() >= MAX_REGISTERED_ARTIFACT_WORKTREES {
            bail!(
                "registered linked worktree count exceeds its {} entry budget",
                MAX_REGISTERED_ARTIFACT_WORKTREES
            );
        }
        let entry = entry.context("failed to inspect Git linked-worktree registry entry")?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("registered linked worktree name is not valid UTF-8"))?;
        if name.is_empty() || name.len() > MAX_REGISTERED_WORKTREE_NAME_BYTES {
            bail!("registered linked worktree name exceeds its bounded format");
        }
        registry.bind_existing_managed_direct_child_directory(&name)?;
        if !names.insert(name.clone()) {
            bail!("duplicate registered linked worktree name: {name}");
        }
    }
    registry.verify()?;
    Ok(names)
}

fn verify_common_artifact_repository(
    expected: &ArtifactRepository,
    observed: &ArtifactRepository,
) -> Result<()> {
    if observed.common_dir != expected.common_dir
        || observed.binding.common_dir_identity != expected.binding.common_dir_identity
        || observed.binding.common_dir_path_checksum != expected.binding.common_dir_path_checksum
    {
        bail!("registered worktree does not belong to the expected Git common directory");
    }
    Ok(())
}

fn validate_registered_worktree_path(path: &Path) -> Result<()> {
    let bytes = filesystem_path_bytes(path).len();
    if !path.is_absolute() || bytes == 0 || bytes > MAX_REGISTERED_WORKTREE_PATH_BYTES {
        bail!("registered linked worktree path exceeds its bounded format");
    }
    if path.components().count() > MAX_REGISTERED_WORKTREE_PATH_COMPONENTS {
        bail!("registered linked worktree path exceeds its component budget");
    }
    Ok(())
}

fn open_or_create_run_root(
    repository: &ArtifactRepository,
    family: RunArtifactFamily,
) -> Result<SafeRoot> {
    let path = repository.worktree.join(family.run_root());
    match fs::symlink_metadata(&path) {
        Ok(_) => SafeRoot::open_existing(&path).with_context(|| {
            format!(
                "existing {} artifact root is unsafe; independently verify ownership and contents before migration: {}",
                family.label(),
                path.display()
            )
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => SafeRoot::open_or_create(&path)
            .context("failed to create owner-private artifact run root"),
        Err(error) => Err(error)
            .with_context(|| format!("failed to inspect artifact run root {}", path.display())),
    }
}

fn open_existing_run_root(
    repository: &ArtifactRepository,
    family: RunArtifactFamily,
) -> Result<SafeRoot> {
    SafeRoot::open_existing(repository.worktree.join(family.run_root()))
        .context("failed to open artifact run root without following links")
}

fn open_optional_run_root(
    repository: &ArtifactRepository,
    family: RunArtifactFamily,
) -> Result<Option<SafeRoot>> {
    let path = repository.worktree.join(family.run_root());
    match fs::symlink_metadata(&path) {
        Ok(_) => open_existing_run_root(repository, family).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error)
            .with_context(|| format!("failed to inspect artifact root {}", path.display())),
    }
}

fn sorted_run_summaries(
    repository: &ArtifactRepository,
    root: &SafeRoot,
    family: RunArtifactFamily,
) -> Result<Vec<RunArtifactSummary>> {
    root.verify()?;
    let mut runs = Vec::new();
    let mut entry_count = 0usize;
    for entry in fs::read_dir(root.path())
        .with_context(|| format!("failed to read run root {}", root.path().display()))?
    {
        entry_count = entry_count
            .checked_add(1)
            .context("artifact run-root entry count overflow")?;
        if entry_count > MAX_RUN_ROOT_ENTRIES {
            bail!(
                "artifact run root exceeds its {} entry budget",
                MAX_RUN_ROOT_ENTRIES
            );
        }
        let entry = entry
            .with_context(|| format!("failed to inspect run root {}", root.path().display()))?;
        let name = entry.file_name();
        if name == ROOT_LOCK_FILE {
            ensure_private_regular_file(&entry.path())?;
            continue;
        }
        if name == QUARANTINE_DIRECTORY {
            root.bind_existing_direct_child_directory(&name)?;
            continue;
        }
        let run_id = name
            .to_str()
            .context("artifact run id is not valid UTF-8")?
            .to_string();
        let validated = RunId::new(&run_id)?;
        if validated.as_str() != run_id {
            bail!("artifact run id is not canonical: {run_id}");
        }
        let binding = root.bind_existing_managed_direct_child_directory(&name)?;
        runs.push(summarize_run(
            repository,
            family,
            run_id,
            binding.path().to_path_buf(),
            binding.identity().clone(),
        )?);
    }
    root.verify()?;
    runs.sort_by(|left, right| {
        right
            .modified
            .cmp(&left.modified)
            .then_with(|| right.run_id.cmp(&left.run_id))
    });
    Ok(runs)
}

fn summarize_run(
    repository: &ArtifactRepository,
    family: RunArtifactFamily,
    run_id: String,
    absolute_run_dir: PathBuf,
    identity: FileIdentity,
) -> Result<RunArtifactSummary> {
    let final_relative = family.final_report_relative_path();
    let modified = fs::symlink_metadata(&absolute_run_dir)
        .and_then(|metadata| metadata.modified())
        .unwrap_or(UNIX_EPOCH);
    let public_run_dir = family.run_root().join(&run_id);
    let public_final_report_path = public_run_dir.join(&final_relative);
    let run_id_value = RunId::new(&run_id)?;
    let run = SafeRoot::open_existing(&absolute_run_dir)?;
    let final_report_exists = metadata_only_report_exists(&run, &final_relative);
    let marker_exists = run.direct_child_exists(FINALIZATION_MARKER)?;

    match marker_exists
        .then(|| ArtifactRunReader::open(&repository.worktree, family, &run_id_value))
    {
        None => Ok(RunArtifactSummary {
            run_id,
            run_dir: public_run_dir,
            final_report_path: public_final_report_path,
            final_report_exists,
            final_report_status: "active".to_string(),
            final_report_success: None,
            final_report_readable: false,
            final_report_corrupt: false,
            final_report_error: None,
            finalized: false,
            publishable: false,
            provenance_valid: false,
            artifact_digests_verified: false,
            finalization_error: Some(
                "artifact run is active or unfinalized; finalization marker is missing".to_string(),
            ),
            modified,
            identity,
        }),
        Some(Ok(reader)) => {
            let modified = fs::symlink_metadata(absolute_run_dir.join(&final_relative))
                .and_then(|metadata| metadata.modified())
                .unwrap_or(modified);
            let contents = reader.read(&final_relative)?;
            let (status, success, readable, corrupt, error) = parse_report(&contents);
            let marker = reader.finalization();
            Ok(RunArtifactSummary {
                run_id,
                run_dir: public_run_dir,
                final_report_path: public_final_report_path,
                final_report_exists: true,
                final_report_status: status,
                final_report_success: success,
                final_report_readable: readable,
                final_report_corrupt: corrupt,
                final_report_error: error,
                finalized: true,
                publishable: marker.publishable,
                provenance_valid: true,
                artifact_digests_verified: true,
                finalization_error: None,
                modified,
                identity,
            })
        }
        Some(Err(_)) => Ok(RunArtifactSummary {
            run_id,
            run_dir: public_run_dir,
            final_report_path: public_final_report_path,
            final_report_exists,
            final_report_status: "unverifiable_finalization".to_string(),
            final_report_success: None,
            final_report_readable: false,
            final_report_corrupt: true,
            final_report_error: None,
            finalized: false,
            publishable: false,
            provenance_valid: false,
            artifact_digests_verified: false,
            finalization_error: Some(
                "artifact finalization marker is present but verification failed".to_string(),
            ),
            modified,
            identity,
        }),
    }
}

fn metadata_only_report_exists(run: &SafeRoot, relative: &Path) -> bool {
    (|| -> Result<bool> {
        let file_name = relative
            .file_name()
            .context("artifact report path has no final file name")?;
        let mut current = run.clone();
        if let Some(parent) = relative.parent() {
            for component in parent.components() {
                let Component::Normal(name) = component else {
                    return Ok(false);
                };
                let binding = current.bind_existing_managed_direct_child_directory(name)?;
                let next = SafeRoot::open_existing(binding.path())?;
                if next.identity() != binding.identity() {
                    bail!("artifact report parent identity changed during metadata inspection");
                }
                binding.verify(&current)?;
                current = next;
            }
        }
        current.direct_child_exists(file_name)
    })()
    .unwrap_or(false)
}

fn parse_report(contents: &[u8]) -> (String, Option<bool>, bool, bool, Option<String>) {
    let value = match serde_json::from_slice::<Value>(contents) {
        Ok(value) => value,
        Err(error) => {
            return (
                "malformed".to_string(),
                None,
                false,
                true,
                Some(error.to_string()),
            )
        }
    };
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("readable")
        .to_string();
    let success = value.get("success").and_then(Value::as_bool);
    (status, success, true, false, None)
}

fn empty_prune_report<F>(
    family: ArtifactRetentionFamily,
    report_family: F,
    policy: &ArtifactRetentionPolicy,
    dry_run: bool,
) -> RunArtifactPruneReport<F> {
    RunArtifactPruneReport {
        family: report_family,
        run_root: family.run_root(),
        ordering: retention_ordering(),
        keep: policy.max_count,
        max_age_seconds: policy.max_age.map(|age| age.as_secs()),
        max_total_bytes: policy.max_total_bytes,
        unfinalized_grace_seconds: policy.unfinalized_grace.map(|grace| grace.as_secs()),
        reclaim_unverifiable: policy.reclaim_unverifiable,
        external_writers_stopped: policy.external_writers_stopped,
        dry_run,
        kept_count: 0,
        deleted_count: 0,
        refused_unfinalized_count: 0,
        delete_candidate_count: 0,
        scanned_bytes: 0,
        retained_bytes: 0,
        projected_retained_bytes: 0,
        reclaimed_bytes: 0,
        would_reclaim_bytes: 0,
        refused_bytes: 0,
        unfinalized_bytes: 0,
        compression_strategy: ArtifactCompressionStrategy::NoneRequiresWriterMigration,
        compressible_log_bytes: 0,
        compressed_bytes: 0,
        entries: Vec::new(),
    }
}

#[cfg(test)]
fn open_or_create_quarantine(root: &SafeRoot) -> Result<SafeRoot> {
    let binding = if root.direct_child_exists(QUARANTINE_DIRECTORY)? {
        root.bind_existing_direct_child_directory(QUARANTINE_DIRECTORY)?
    } else {
        root.reserve_direct_child_directory(QUARANTINE_DIRECTORY)?
    };
    SafeRoot::open_or_create(binding.path())
}

fn ensure_quarantine_empty(quarantine: &SafeRoot) -> Result<()> {
    quarantine.verify()?;
    let mut entries = fs::read_dir(quarantine.path()).with_context(|| {
        format!(
            "failed to inspect artifact quarantine {}",
            quarantine.path().display()
        )
    })?;
    if let Some(entry) = entries.next() {
        let entry = entry.context("failed to inspect artifact quarantine entry")?;
        quarantine.bind_existing_managed_direct_child_directory(entry.file_name())?;
        bail!(
            "artifact quarantine contains crash residue; refusing automatic deletion until its finalization marker and contents are inspected: {}",
            entry.path().display()
        );
    }
    quarantine.verify()
}

fn validate_artifact_relative_path(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        bail!(
            "artifact path must be a non-empty relative path: {}",
            path.display()
        );
    }
    let mut normalized = PathBuf::new();
    let mut component_count = 0usize;
    for component in path.components() {
        match component {
            Component::Normal(name) => {
                if name == FINALIZATION_MARKER || name == RUN_LOCK_FILE {
                    bail!(
                        "artifact path uses a reserved component: {}",
                        path.display()
                    );
                }
                component_count = component_count
                    .checked_add(1)
                    .context("artifact path component count overflow")?;
                normalized.push(name);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!(
                    "artifact path escapes its run directory: {}",
                    path.display()
                )
            }
        }
    }
    if normalized.as_os_str().is_empty() || component_count > MAX_ARTIFACT_PATH_COMPONENTS {
        bail!(
            "artifact path must contain 1 to {} normal components",
            MAX_ARTIFACT_PATH_COMPONENTS
        );
    }
    let text = normalized
        .to_str()
        .context("artifact paths must be valid UTF-8")?;
    if text.len() > MAX_ARTIFACT_PATH_BYTES {
        bail!(
            "artifact path exceeds its {} byte limit",
            MAX_ARTIFACT_PATH_BYTES
        );
    }
    Ok(normalized)
}

fn validate_artifact_scratch_name(path: &Path) -> Result<PathBuf> {
    let mut components = path.components();
    let Some(Component::Normal(name)) = components.next() else {
        bail!(
            "artifact scratch name must be one canonical relative component: {}",
            path.display()
        );
    };
    if components.next().is_some() {
        bail!(
            "artifact scratch name must be one canonical relative component: {}",
            path.display()
        );
    }
    let name = name
        .to_str()
        .context("artifact scratch names must be valid UTF-8")?;
    if path.as_os_str() != std::ffi::OsStr::new(name) {
        bail!(
            "artifact scratch name must be canonical without separators or redundant components: {}",
            path.display()
        );
    }
    let mut bytes = name.bytes();
    if name.len() > MAX_ARTIFACT_SCRATCH_NAME_BYTES
        || !bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!(
            "artifact scratch name must contain 1 to {} ASCII letters, digits, '.', '_' or '-', beginning with a letter or digit",
            MAX_ARTIFACT_SCRATCH_NAME_BYTES
        );
    }
    Ok(PathBuf::from(name))
}

fn artifact_path_starts_with(path: &Path, scratch_name: &Path) -> bool {
    path.starts_with(scratch_name)
}

fn is_supervisor_invocation_scratch_name(path: &Path) -> bool {
    let Some(name) = path.to_str() else {
        return false;
    };
    if matches!(name, "incoming" | "capture") {
        return true;
    }
    let Some(suffix) = name
        .strip_prefix("incoming-")
        .or_else(|| name.strip_prefix("capture-"))
    else {
        return false;
    };
    let mut components = suffix.split('-');
    if components.next() != Some("assignment") {
        return false;
    }
    let Some(assignment_index) = components.next() else {
        return false;
    };
    if !is_canonical_scratch_ordinal(assignment_index, 4) {
        return false;
    }
    match components.next() {
        Some("auditor") => components.next().is_none(),
        Some("attempt") => components.next().is_some_and(|attempt| {
            is_canonical_scratch_ordinal(attempt, 2) && components.next().is_none()
        }),
        _ => false,
    }
}

fn is_canonical_scratch_ordinal(value: &str, minimum_width: usize) -> bool {
    value.len() >= minimum_width && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn remove_artifact_scratch_tree(
    run: &SafeRoot,
    name: &std::ffi::OsStr,
    expected: &FileIdentity,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        remove_direct_child_tree(run, name, Some(expected), TreeLinkPolicy::UnlinkLinks)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (run, name, expected);
        unsupported_artifact_scratch_cleanup()
    }
}

#[cfg(any(not(target_os = "linux"), test))]
fn unsupported_artifact_scratch_cleanup() -> Result<()> {
    bail!(
        "secure artifact scratch cleanup is unsupported on this platform; refusing recursive deletion"
    )
}

fn artifact_parent_and_name<'a>(
    run: &SafeRoot,
    relative: &'a Path,
    create: bool,
) -> Result<(SafeRoot, &'a OsStr)> {
    let file_name = relative
        .file_name()
        .context("artifact path has no final file name")?;
    let mut current = run.clone();
    if let Some(parent) = relative.parent() {
        for component in parent.components() {
            let Component::Normal(name) = component else {
                continue;
            };
            let binding = if current.direct_child_exists(name)? {
                current.bind_existing_direct_child_directory(name)?
            } else if create {
                current.reserve_direct_child_directory(name)?
            } else {
                bail!("artifact parent directory is missing: {}", parent.display());
            };
            current = SafeRoot::open_or_create(binding.path())?;
        }
    }
    Ok((current, file_name))
}

fn validate_producer(producer: &str) -> Result<()> {
    if producer.is_empty()
        || producer.len() > MAX_PRODUCER_BYTES
        || !producer
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        bail!(
            "artifact producer must contain 1 to {} ASCII letters, digits, '.', '_' or '-'",
            MAX_PRODUCER_BYTES
        );
    }
    Ok(())
}

fn validate_artifact_resume_binding(binding: &ArtifactRunResumeBinding) -> Result<()> {
    if binding.version != ARTIFACT_FORMAT_VERSION {
        bail!("artifact resume binding format version is unsupported");
    }
    validate_producer(&binding.provenance.producer)?;
    validate_writer_evidence(&binding.writer_evidence)?;
    let run_id = RunId::new(&binding.run_id)?;
    if run_id.as_str() != binding.run_id {
        bail!("artifact resume binding run id is not canonical");
    }
    if let Some(revision) = &binding.provenance.source_revision {
        if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("artifact resume source revision is not a full Git object id");
        }
    }
    if binding.files.len() > MAX_ARTIFACT_FILES {
        bail!("artifact resume binding exceeds its manifest file limit");
    }
    let mut seen = BTreeSet::new();
    let mut total = 0_u64;
    for record in &binding.files {
        let path = validate_artifact_relative_path(&record.path)?;
        if path != record.path || !seen.insert(path) {
            bail!("artifact resume binding contains a duplicate or noncanonical path");
        }
        if record.bytes > MAX_ARTIFACT_FILE_BYTES || !is_canonical_lower_hex_64(&record.sha256) {
            bail!("artifact resume binding contains an invalid file record");
        }
        total = total
            .checked_add(record.bytes)
            .context("artifact resume manifest byte total overflowed")?;
        if total > MAX_ARTIFACT_TOTAL_BYTES {
            bail!("artifact resume binding exceeds its aggregate byte limit");
        }
    }
    Ok(())
}

include!("artifacts/part2.rs");

#[cfg(test)]
mod tests;
