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
}

impl ArtifactRetentionPolicy {
    pub fn count_only(max_count: usize) -> Self {
        Self {
            max_count,
            max_age: None,
            max_total_bytes: None,
            unfinalized_grace: None,
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
pub struct RunArtifactPruneReport {
    pub family: ArtifactRetentionFamily,
    pub run_root: PathBuf,
    pub ordering: &'static str,
    pub keep: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unfinalized_grace_seconds: Option<u64>,
    pub dry_run: bool,
    pub kept_count: usize,
    pub deleted_count: usize,
    pub refused_unfinalized_count: usize,
    pub delete_candidate_count: usize,
    pub scanned_bytes: u64,
    /// Bytes physically present after this invocation. In dry-run this equals
    /// `scanned_bytes`; use `projected_retained_bytes` for the planned result.
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
        let repo_handle = Repository::discover(&repository.worktree).with_context(|| {
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
            remove_artifact_scratch_tree(&self.run, scratch.name.as_os_str(), &scratch.identity)
                .with_context(|| {
                    format!(
                        "failed to safely discard artifact scratch directory {}",
                        scratch.name.display()
                    )
                })?;
            if self.run.direct_child_exists(scratch.name.as_os_str())? {
                bail!(
                    "artifact scratch source name reappeared after cleanup: {}",
                    scratch.name.display()
                );
            }
            let removed = self
                .outstanding_scratches
                .remove(&scratch.name)
                .context("artifact scratch tracking disappeared during cleanup")?;
            if removed != scratch.identity {
                bail!("artifact scratch tracking identity changed during cleanup");
            }
            Ok(())
        })();
        finish_with_artifact_lock_verification(result, self.run_lock.verify(&self.run))
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
            if !self.files.contains_key(&relative) && self.files.len() >= MAX_ARTIFACT_FILES {
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
    prune_artifacts_with_policy(repo, family.into(), policy, dry_run)
}

pub fn prune_artifacts_with_policy(
    repo: impl AsRef<Path>,
    family: ArtifactRetentionFamily,
    policy: &ArtifactRetentionPolicy,
    dry_run: bool,
) -> Result<RunArtifactPruneReport> {
    prune_artifacts_at(repo.as_ref(), family, policy, dry_run, SystemTime::now())
}

fn prune_artifacts_at(
    repo: &Path,
    family: ArtifactRetentionFamily,
    policy: &ArtifactRetentionPolicy,
    dry_run: bool,
    now: SystemTime,
) -> Result<RunArtifactPruneReport> {
    let repository = discover_artifact_repository(repo)?;
    let Some(root) = open_optional_retention_root(&repository, family)? else {
        return Ok(empty_prune_report(family, policy, dry_run));
    };
    let lock_name = if family == ArtifactRetentionFamily::Program {
        RETENTION_LOCK_FILE
    } else {
        ROOT_LOCK_FILE
    };
    let root_lock = BoundArtifactLock::acquire(&root, lock_name)?;
    root_lock.verify(&root)?;
    let result = (|| -> Result<RunArtifactPruneReport> {
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
                RetentionItemState::InvalidFinalization => {
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
                            "refusing to reclaim an artifact with a present but unverifiable finalization marker"
                                .to_string(),
                        ),
                    ));
                }
                RetentionItemState::MissingFinalization | RetentionItemState::External => {
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
                    if item.state == RetentionItemState::MissingFinalization {
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
                            ExistingExclusiveLock::Missing => {}
                            ExistingExclusiveLock::Acquired(lock) => {
                                held_unfinalized_lock = Some(lock);
                            }
                        }
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
                            Some(format!(
                                "unfinalized artifact is idle and older than its {} second grace",
                                grace.as_secs()
                            )),
                        ));
                        continue;
                    }

                    root_lock.verify(&root)?;
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
                    if item.state == RetentionItemState::MissingFinalization
                        && rebound_root.direct_child_exists(FINALIZATION_MARKER)?
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
                                "refusing to reclaim an unfinalized artifact whose finalization state changed during pruning"
                                    .to_string(),
                            ),
                        ));
                        continue;
                    }
                    let refreshed = retention_inventory(&rebound_root)?;
                    let refreshed_age = artifact_age_seconds(now, refreshed.modified);
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
                    delete_retention_item(
                        &root,
                        &root_lock,
                        &mut quarantine,
                        retention_quarantine_name(family),
                        &item,
                        held_unfinalized_lock.as_ref(),
                    )?;
                    reclaimed_bytes = reclaimed_bytes
                        .checked_add(item.bytes)
                        .context("reclaimed artifact byte total overflow")?;
                    deleted_count = deleted_count.saturating_add(1);
                    entries.push(retention_entry(
                        item,
                        refreshed_age,
                        RunArtifactPruneAction::Delete,
                        selected_by,
                        Some(format!(
                            "expired unfinalized artifact exceeded its {} second grace",
                            grace.as_secs()
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
                        &root_lock,
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

        root_lock.verify(&root)?;
        let planned_reclaimed_bytes = if dry_run {
            would_reclaim_bytes
        } else {
            reclaimed_bytes
        };
        Ok(RunArtifactPruneReport {
            family,
            run_root: family.run_root(),
            ordering: retention_ordering(),
            keep: policy.max_count,
            max_age_seconds: policy.max_age.map(|age| age.as_secs()),
            max_total_bytes: policy.max_total_bytes,
            unfinalized_grace_seconds: policy.unfinalized_grace.map(|grace| grace.as_secs()),
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
    finish_with_artifact_lock_verification(result, root_lock.verify(&root))
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
    let repo = Repository::discover(repo_path)
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
    let common_repo = Repository::open(&repository.common_dir).with_context(|| {
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
        let linked_repo = Repository::open(worktree_root.path())
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

fn empty_prune_report(
    family: ArtifactRetentionFamily,
    policy: &ArtifactRetentionPolicy,
    dry_run: bool,
) -> RunArtifactPruneReport {
    RunArtifactPruneReport {
        family,
        run_root: family.run_root(),
        ordering: retention_ordering(),
        keep: policy.max_count,
        max_age_seconds: policy.max_age.map(|age| age.as_secs()),
        max_total_bytes: policy.max_total_bytes,
        unfinalized_grace_seconds: policy.unfinalized_grace.map(|grace| grace.as_secs()),
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

fn validate_finalization(finalization: &ArtifactFinalization) -> Result<()> {
    if finalization.version != ARTIFACT_FORMAT_VERSION {
        bail!("artifact finalization format version is unsupported");
    }
    validate_producer(&finalization.provenance.producer)?;
    validate_writer_evidence(&finalization.writer_evidence)?;
    if !is_canonical_lower_hex_64(&finalization.mac_key_id)
        || finalization.mac_key_identity.file == 0
    {
        bail!("artifact finalization MAC key evidence is malformed");
    }
    if !is_canonical_lower_hex_64(&finalization.hmac_sha256) {
        bail!("artifact finalization HMAC is malformed");
    }
    let run_id = RunId::new(&finalization.run_id)?;
    if run_id.as_str() != finalization.run_id {
        bail!("artifact finalization run id is not canonical");
    }
    let final_report = validate_artifact_relative_path(&finalization.final_report)?;
    if final_report != finalization.family.final_report_relative_path() {
        bail!("artifact finalization has the wrong final report path");
    }
    if let Some(revision) = &finalization.provenance.source_revision {
        if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("artifact source revision is not a full Git object id");
        }
    }
    if finalization.files.is_empty() || finalization.files.len() > MAX_ARTIFACT_FILES {
        bail!(
            "artifact finalization must contain 1 to {} files",
            MAX_ARTIFACT_FILES
        );
    }
    let mut seen = BTreeSet::new();
    let mut total = 0u64;
    for record in &finalization.files {
        let path = validate_artifact_relative_path(&record.path)?;
        if path != record.path || !seen.insert(path) {
            bail!("artifact finalization contains a duplicate or noncanonical path");
        }
        if record.bytes > MAX_ARTIFACT_FILE_BYTES {
            bail!("artifact file record exceeds the per-file byte limit");
        }
        total = total
            .checked_add(record.bytes)
            .context("artifact manifest byte total overflow")?;
        if total > MAX_ARTIFACT_TOTAL_BYTES {
            bail!("artifact manifest exceeds its aggregate byte limit");
        }
        if !is_canonical_lower_hex_64(&record.sha256) {
            bail!("artifact file record has an invalid SHA-256 digest");
        }
    }
    if !seen.contains(&final_report) {
        bail!("artifact final report is missing from the manifest");
    }
    let expected_publishable = finalization.publish_requested
        && finalization.provenance.source_revision.is_some()
        && finalization
            .files
            .iter()
            .all(|file| file.disposition == ArtifactFileDisposition::Publishable);
    if finalization.publishable != expected_publishable {
        bail!("artifact publishability does not match its provenance/file dispositions");
    }
    Ok(())
}

fn validate_writer_evidence(evidence: &ArtifactWriterEvidence) -> Result<()> {
    const PREFIX: &str = "maco-reservation-v1-";
    if evidence.run_root_identity.file == 0
        || evidence.run_identity.file == 0
        || evidence.writer_lock_identity.file == 0
    {
        bail!("artifact writer evidence contains an invalid zero inode identity");
    }
    let suffix = evidence
        .reservation_id
        .strip_prefix(PREFIX)
        .context("artifact reservation evidence has an unsupported format")?;
    if suffix.len() != 32 || !suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("artifact reservation evidence is malformed");
    }
    Ok(())
}

fn verify_writer_evidence(
    evidence: &ArtifactWriterEvidence,
    run_root: &SafeRoot,
    run: &SafeRoot,
) -> Result<()> {
    validate_writer_evidence(evidence)?;
    run_root.verify()?;
    run.verify()?;
    if evidence.run_root_identity != *run_root.identity()
        || evidence.run_identity != *run.identity()
    {
        bail!("artifact writer evidence does not match the reserved run directories");
    }
    let observed_lock = ensure_private_regular_file(&run.path().join(RUN_LOCK_FILE))?;
    if observed_lock != evidence.writer_lock_identity {
        bail!("artifact writer lock identity does not match finalization evidence");
    }
    Ok(())
}

fn reservation_evidence_id(run_id: &str, run_identity: &FileIdentity) -> String {
    let counter = RESERVATION_COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let mut first = RandomState::new().build_hasher();
    run_id.hash(&mut first);
    run_identity.device.hash(&mut first);
    run_identity.file.hash(&mut first);
    process::id().hash(&mut first);
    counter.hash(&mut first);
    now.hash(&mut first);
    let first = first.finish();
    let mut second = RandomState::new().build_hasher();
    first.hash(&mut second);
    now.rotate_left(31).hash(&mut second);
    let second = second.finish();
    format!("maco-reservation-v1-{first:016x}{second:016x}")
}

fn finalization_checksum(finalization: &ArtifactFinalization) -> Result<String> {
    let payload = serde_json::to_vec(&(
        finalization.version,
        &finalization.repository,
        finalization.family,
        &finalization.run_id,
        &finalization.provenance,
        &finalization.writer_evidence,
        &finalization.mac_key_id,
        &finalization.mac_key_identity,
        &finalization.final_report,
        &finalization.files,
        finalization.publish_requested,
        finalization.publishable,
    ))
    .context("failed to encode artifact finalization checksum payload")?;
    Ok(stable_checksum(&payload))
}

fn verify_manifest_paths(
    records: &BTreeMap<PathBuf, ArtifactFileRecord>,
    audited: &BTreeSet<PathBuf>,
) -> Result<()> {
    let expected = records.keys().cloned().collect::<BTreeSet<_>>();
    if &expected != audited {
        bail!("artifact tree does not exactly match its in-memory manifest");
    }
    Ok(())
}

fn verify_manifest_paths_with_marker(
    records: &[ArtifactFileRecord],
    audited: &BTreeSet<PathBuf>,
) -> Result<()> {
    let expected = records
        .iter()
        .map(|record| record.path.clone())
        .collect::<BTreeSet<_>>();
    if &expected != audited {
        bail!("artifact tree does not exactly match its finalized manifest");
    }
    Ok(())
}

fn verify_manifest_contents<'a>(
    run: &SafeRoot,
    records: impl IntoIterator<Item = &'a ArtifactFileRecord>,
) -> Result<()> {
    for record in records {
        read_and_verify_record(run, record)?;
    }
    Ok(())
}

fn read_and_verify_record(run: &SafeRoot, record: &ArtifactFileRecord) -> Result<Vec<u8>> {
    let (_parent, _file_name) = artifact_parent_and_name(run, &record.path, false)?;
    ensure_private_regular_file(&run.path().join(&record.path))?;
    let contents =
        BoundedRegularReader::read_relative(run.path(), &record.path, MAX_ARTIFACT_FILE_BYTES)?;
    if u64::try_from(contents.len()).unwrap_or(u64::MAX) != record.bytes
        || sha256_hex(&contents) != record.sha256
    {
        bail!(
            "artifact file digest/length does not match its manifest: {}",
            record.path.display()
        );
    }
    Ok(contents)
}

fn audit_artifact_tree(run: &SafeRoot, require_private: bool) -> Result<BTreeSet<PathBuf>> {
    run.verify()?;
    let metadata = fs::symlink_metadata(run.path())?;
    #[cfg(unix)]
    let device = metadata.dev();
    #[cfg(not(unix))]
    let device = 0u64;
    let mut entries = 0usize;
    let mut files = BTreeSet::new();
    audit_artifact_directory(
        run.path(),
        Path::new(""),
        device,
        0,
        &mut entries,
        require_private,
        &mut files,
    )?;
    run.verify()?;
    Ok(files)
}

fn audit_artifact_directory(
    directory: &Path,
    relative: &Path,
    device: u64,
    depth: usize,
    entries: &mut usize,
    require_private: bool,
    files: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    if depth > MAX_ARTIFACT_PATH_COMPONENTS {
        bail!("artifact tree exceeds its maximum depth");
    }
    for entry in fs::read_dir(directory)
        .with_context(|| format!("failed to audit artifact directory {}", directory.display()))?
    {
        *entries = entries
            .checked_add(1)
            .context("artifact tree entry count overflow")?;
        if *entries > MAX_ARTIFACT_FILES.saturating_mul(2).saturating_add(128) {
            bail!("artifact tree exceeds its global entry budget");
        }
        let entry = entry.context("failed to inspect artifact tree entry")?;
        let name = entry.file_name();
        let child_relative = relative.join(&name);
        let metadata = fs::symlink_metadata(entry.path())?;
        ensure_same_device(&metadata, device, &entry.path())?;
        if metadata.file_type().is_symlink() {
            bail!(
                "artifact tree contains a symbolic link: {}",
                child_relative.display()
            );
        }
        if metadata.file_type().is_dir() {
            if require_private {
                ensure_private_directory(&entry.path())?;
            }
            audit_artifact_directory(
                &entry.path(),
                &child_relative,
                device,
                depth.saturating_add(1),
                entries,
                require_private,
                files,
            )?;
            continue;
        }
        if !metadata.file_type().is_file() {
            bail!(
                "artifact tree contains a special file: {}",
                child_relative.display()
            );
        }
        if child_relative == Path::new(RUN_LOCK_FILE)
            || child_relative == Path::new(FINALIZATION_MARKER)
        {
            ensure_private_regular_file(&entry.path())?;
            continue;
        }
        if require_private {
            ensure_private_regular_file(&entry.path())?;
        } else {
            ensure_regular_single_link(&entry.path())?;
        }
        validate_artifact_relative_path(&child_relative)?;
        files.insert(child_relative);
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_same_device(metadata: &fs::Metadata, device: u64, path: &Path) -> Result<()> {
    if metadata.dev() != device {
        bail!(
            "artifact tree crosses a filesystem boundary: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_same_device(_metadata: &fs::Metadata, _device: u64, path: &Path) -> Result<()> {
    bail!(
        "artifact device-boundary validation is unsupported on this platform: {}",
        path.display()
    )
}

#[cfg(unix)]
fn ensure_private_directory(path: &Path) -> Result<FileIdentity> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect private directory {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        bail!(
            "artifact directory is not a no-follow directory: {}",
            path.display()
        );
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        bail!(
            "artifact directory is not owned by the current user: {}",
            path.display()
        );
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o700 {
        bail!(
            "artifact directory is not owner-private (expected 0700, observed {:04o}): {}",
            mode,
            path.display()
        );
    }
    identity_for_path(path)
}

#[cfg(not(unix))]
fn ensure_private_directory(path: &Path) -> Result<FileIdentity> {
    bail!(
        "artifact directory ACL validation is unsupported on this platform: {}",
        path.display()
    )
}

#[cfg(unix)]
fn ensure_regular_single_link(path: &Path) -> Result<FileIdentity> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect artifact file {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        bail!(
            "artifact entry is not a regular no-follow file: {}",
            path.display()
        );
    }
    if metadata.nlink() != 1 {
        bail!(
            "artifact file must have exactly one hard link (observed {}): {}",
            metadata.nlink(),
            path.display()
        );
    }
    identity_for_path(path)
}

#[cfg(not(unix))]
fn ensure_regular_single_link(path: &Path) -> Result<FileIdentity> {
    bail!(
        "artifact regular-file validation is unsupported on this platform: {}",
        path.display()
    )
}

#[cfg(unix)]
fn ensure_private_regular_file(path: &Path) -> Result<FileIdentity> {
    let identity = ensure_regular_single_link(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.uid() != unsafe { libc::geteuid() } {
        bail!(
            "artifact file is not owned by the current user: {}",
            path.display()
        );
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o600 {
        bail!(
            "artifact file is not owner-private (expected 0600, observed {:04o}): {}",
            mode,
            path.display()
        );
    }
    Ok(identity)
}

#[cfg(not(unix))]
fn ensure_private_regular_file(path: &Path) -> Result<FileIdentity> {
    bail!(
        "artifact file ACL validation is unsupported on this platform: {}",
        path.display()
    )
}

#[cfg(unix)]
fn ensure_private_regular_file_handle(file: &File, path: &Path) -> Result<FileIdentity> {
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect opened artifact file {}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        bail!(
            "opened artifact file is not an owner-private single-link regular file: {}",
            path.display()
        );
    }
    Ok(FileIdentity {
        device: metadata.dev(),
        file: metadata.ino(),
    })
}

#[cfg(not(unix))]
fn ensure_private_regular_file_handle(_file: &File, path: &Path) -> Result<FileIdentity> {
    bail!(
        "opened artifact file ACL validation is unsupported on this platform: {}",
        path.display()
    )
}

#[cfg(unix)]
fn open_private_artifact_append_file(
    parent: &SafeRoot,
    file_name: &OsStr,
    create: bool,
) -> Result<File> {
    parent.verify()?;
    let directory = open_safe_root_handle(parent)?;
    let name = CString::new(file_name.as_bytes()).context("artifact file name contains NUL")?;
    let mut flags =
        libc::O_WRONLY | libc::O_APPEND | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
    if create {
        flags |= libc::O_CREAT | libc::O_EXCL;
    }
    let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, 0o600) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to open private artifact for append: {}",
                parent.path().join(file_name).display()
            )
        });
    }
    let file = unsafe { File::from_raw_fd(fd) };
    ensure_private_regular_file_handle(&file, &parent.path().join(file_name))?;
    parent.verify()?;
    Ok(file)
}

#[cfg(not(unix))]
fn open_private_artifact_append_file(
    _parent: &SafeRoot,
    file_name: &OsStr,
    _create: bool,
) -> Result<File> {
    bail!(
        "no-follow artifact append is unsupported on this platform: {}",
        Path::new(file_name).display()
    )
}

#[cfg(unix)]
fn filesystem_path_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().as_bytes().to_vec()
}

#[cfg(not(unix))]
fn filesystem_path_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().to_string_lossy().as_bytes().to_vec()
}

#[cfg(unix)]
fn rename_bound_directory(
    source_root: &SafeRoot,
    source_name: &OsStr,
    expected: &FileIdentity,
    destination_root: &SafeRoot,
    destination_name: &OsStr,
) -> Result<()> {
    source_root.verify()?;
    destination_root.verify()?;
    let source = open_safe_root_handle(source_root)?;
    let destination = open_safe_root_handle(destination_root)?;
    let source_name = CString::new(source_name.as_bytes()).context("source name contains NUL")?;
    let destination_name =
        CString::new(destination_name.as_bytes()).context("destination name contains NUL")?;
    let source_stat = fstatat_no_follow(source.as_raw_fd(), &source_name)?;
    if source_stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || identity_from_stat(&source_stat) != *expected
    {
        bail!("artifact source directory identity changed before quarantine");
    }
    let mut destination_stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            destination.as_raw_fd(),
            destination_name.as_ptr(),
            &mut destination_stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        bail!("artifact quarantine destination already exists");
    }
    let missing = std::io::Error::last_os_error();
    if missing.kind() != std::io::ErrorKind::NotFound {
        return Err(missing).context("failed to inspect artifact quarantine destination");
    }
    if unsafe {
        libc::renameat(
            source.as_raw_fd(),
            source_name.as_ptr(),
            destination.as_raw_fd(),
            destination_name.as_ptr(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error())
            .context("failed to atomically quarantine artifact run");
    }
    let rebound = fstatat_no_follow(destination.as_raw_fd(), &destination_name)?;
    if rebound.st_mode & libc::S_IFMT != libc::S_IFDIR || identity_from_stat(&rebound) != *expected
    {
        bail!("artifact quarantine destination does not match the inspected run inode");
    }
    source
        .sync_all()
        .context("failed to flush artifact run root")?;
    destination
        .sync_all()
        .context("failed to flush artifact quarantine")?;
    destination_root.verify()?;
    Ok(())
}

#[cfg(not(unix))]
fn rename_bound_directory(
    _source_root: &SafeRoot,
    _source_name: &std::ffi::OsStr,
    _expected: &FileIdentity,
    _destination_root: &SafeRoot,
    _destination_name: &std::ffi::OsStr,
) -> Result<()> {
    bail!("handle-relative artifact quarantine is unsupported on this platform")
}

#[cfg(unix)]
fn open_safe_root_handle(root: &SafeRoot) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root.path())
        .with_context(|| format!("failed to open safe root handle {}", root.path().display()))?;
    let metadata = file.metadata()?;
    let identity = FileIdentity {
        device: metadata.dev(),
        file: metadata.ino(),
    };
    if identity != *root.identity() {
        bail!("safe root path changed before handle-relative artifact operation");
    }
    Ok(file)
}

#[cfg(unix)]
fn fstatat_no_follow(fd: i32, name: &CStr) -> Result<libc::stat> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(fd, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to inspect artifact directory entry without following links");
    }
    Ok(stat)
}

#[cfg(unix)]
fn identity_from_stat(stat: &libc::stat) -> FileIdentity {
    FileIdentity {
        device: device_id_to_u64(stat.st_dev),
        file: unsigned_to_u64(stat.st_ino),
    }
}

fn finalization_hmac_payload(finalization: &ArtifactFinalization) -> Result<Vec<u8>> {
    serde_json::to_vec(&(
        finalization.version,
        &finalization.checksum,
        &finalization.repository,
        finalization.family,
        &finalization.run_id,
        &finalization.provenance,
        &finalization.writer_evidence,
        &finalization.mac_key_id,
        &finalization.mac_key_identity,
        &finalization.final_report,
        &finalization.files,
        finalization.publish_requested,
        finalization.publishable,
    ))
    .context("failed to encode canonical artifact HMAC payload")
}

fn finalization_hmac(
    authenticator: &RepositoryAuthenticator,
    finalization: &ArtifactFinalization,
) -> Result<String> {
    let payload = finalization_hmac_payload(finalization)?;
    Ok(authenticator
        .sign_legacy_artifact_finalization_v2(&payload)?
        .as_str()
        .to_string())
}

fn verify_finalization_hmac(
    authenticator: &RepositoryAuthenticator,
    finalization: &ArtifactFinalization,
) -> Result<()> {
    let payload = finalization_hmac_payload(finalization)?;
    let tag = AuthenticationTag::parse(finalization.hmac_sha256.clone())?;
    authenticator.verify_legacy_artifact_finalization_v2(&payload, &tag)
}

fn is_canonical_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worktree::{WorktreeCreateOptions, WorktreeManager};
    use git2::{Oid, Signature};
    use tempfile::TempDir;

    #[test]
    fn sha256_matches_standard_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_scratch_blocks_marker_and_discarded_scratch_finalizes_marker_last() {
        use std::os::unix::fs::symlink;

        let (temp, repo) = committed_repo();
        let blocked_run_id = RunId::new("scratch-live-blocked").expect("run id");
        let mut blocked = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Autopilot,
            blocked_run_id.clone(),
            "autopilot",
        )
        .expect("reserve blocked writer");
        blocked
            .write_json(
                "final-report.json",
                &serde_json::json!({"status":"done"}),
                ArtifactFileDisposition::PrivateEvidence,
            )
            .expect("write blocked report");
        let blocked_scratch = blocked
            .create_scratch_dir("incoming")
            .expect("reserve live scratch");
        fs::write(blocked_scratch.path().join("pending"), b"pending\n")
            .expect("write pending child output");
        let blocked_error = blocked
            .finalize("final-report.json", false)
            .expect_err("live scratch must block finalization");
        assert!(blocked_error.to_string().contains("outstanding scratch"));
        assert!(
            !run_dir(&repo, RunArtifactFamily::Autopilot, &blocked_run_id)
                .join(FINALIZATION_MARKER)
                .exists()
        );

        let run_id = RunId::new("scratch-discarded").expect("run id");
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Autopilot,
            run_id.clone(),
            "autopilot",
        )
        .expect("reserve writer");
        writer
            .write_json(
                "final-report.json",
                &serde_json::json!({"status":"done"}),
                ArtifactFileDisposition::PrivateEvidence,
            )
            .expect("write report");
        let scratch = writer
            .create_scratch_dir("incoming")
            .expect("reserve scratch");
        assert_eq!(mode(scratch.path()), 0o700);
        assert_eq!(
            identity_for_path(scratch.path()).expect("scratch identity"),
            *scratch.identity()
        );

        let sentinel = temp.path().join("external-sentinel");
        fs::write(&sentinel, b"keep\n").expect("write external sentinel");
        symlink(&sentinel, scratch.path().join("sentinel-link")).expect("scratch symlink");
        fs::hard_link(&sentinel, scratch.path().join("sentinel-hardlink"))
            .expect("scratch hardlink");
        let fifo = CString::new(scratch.path().join("child-fifo").as_os_str().as_bytes())
            .expect("FIFO path");
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

        let run = writer.run_dir().to_path_buf();
        writer
            .discard_scratch(&scratch)
            .expect("discard hostile child tree without following links");
        assert!(!scratch.path().exists());
        assert_eq!(fs::read(&sentinel).expect("read sentinel"), b"keep\n");
        assert!(!run.join(FINALIZATION_MARKER).exists());
        let finalization = writer
            .finalize("final-report.json", false)
            .expect("finalize after scratch discard");
        assert!(run.join(FINALIZATION_MARKER).exists());
        assert_eq!(finalization.files.len(), 1);
        assert_eq!(finalization.files[0].path, Path::new("final-report.json"));
        ArtifactRunReader::open(&repo, RunArtifactFamily::Autopilot, &run_id)
            .expect("final marker authenticates the exact post-discard manifest");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn scratch_names_manifest_overlap_and_count_are_bounded() {
        use std::os::unix::ffi::OsStringExt;

        let (_temp, repo) = committed_repo();
        let run_id = RunId::new("scratch-validation").expect("run id");
        let mut writer =
            ArtifactRunWriter::reserve(&repo, RunArtifactFamily::Inbox, run_id, "inbox")
                .expect("reserve writer");
        let invalid = [
            PathBuf::new(),
            PathBuf::from("."),
            PathBuf::from("./incoming"),
            PathBuf::from("incoming/"),
            PathBuf::from("../incoming"),
            PathBuf::from("nested/incoming"),
            PathBuf::from("/absolute"),
            PathBuf::from(".artifact.lock"),
            PathBuf::from("contains space"),
            PathBuf::from("contains/slash"),
            PathBuf::from("x".repeat(MAX_ARTIFACT_SCRATCH_NAME_BYTES + 1)),
            PathBuf::from(std::ffi::OsString::from_vec(vec![0xff])),
        ];
        for name in invalid {
            assert!(
                writer.create_scratch_dir(&name).is_err(),
                "invalid scratch name was accepted: {}",
                name.display()
            );
        }
        assert!(writer.outstanding_scratches.is_empty());

        writer
            .write_bytes(
                "manifested/first.txt",
                b"first\n",
                ArtifactFileDisposition::PrivateEvidence,
            )
            .expect("write nested manifested artifact");
        assert!(writer.create_scratch_dir("manifested").is_err());
        writer
            .write_bytes(
                "exact-name",
                b"manifested\n",
                ArtifactFileDisposition::PrivateEvidence,
            )
            .expect("write exact manifested artifact");
        assert!(writer.create_scratch_dir("exact-name").is_err());

        let scratch = writer
            .create_scratch_dir("incoming")
            .expect("create valid scratch");
        assert!(writer
            .write_bytes(
                "incoming",
                b"overlap\n",
                ArtifactFileDisposition::PrivateEvidence,
            )
            .is_err());
        assert!(writer
            .write_bytes(
                "incoming/nested.txt",
                b"overlap\n",
                ArtifactFileDisposition::PrivateEvidence,
            )
            .is_err());
        writer.discard_scratch(&scratch).expect("discard scratch");

        let mut scratches = Vec::new();
        for index in 0..MAX_ARTIFACT_SCRATCH_DIRECTORIES {
            scratches.push(
                writer
                    .create_scratch_dir(format!("scratch-{index}"))
                    .expect("scratch within limit"),
            );
        }
        let limit_error = writer
            .create_scratch_dir("one-too-many")
            .expect_err("scratch count must be bounded");
        assert!(limit_error.to_string().contains("scratch-directory limit"));
        for scratch in &scratches {
            writer
                .discard_scratch(scratch)
                .expect("discard bounded scratch");
        }
        assert!(writer.outstanding_scratches.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn scratch_capability_is_run_bound_and_rebinding_fails_closed() {
        let (_temp, repo) = committed_repo();
        let run_a = RunId::new("scratch-capability-a").expect("run id");
        let run_b = RunId::new("scratch-capability-b").expect("run id");
        let mut writer_a =
            ArtifactRunWriter::reserve(&repo, RunArtifactFamily::Consult, run_a, "consult")
                .expect("reserve writer A");
        let mut writer_b =
            ArtifactRunWriter::reserve(&repo, RunArtifactFamily::Consult, run_b, "consult")
                .expect("reserve writer B");
        let scratch = writer_a
            .create_scratch_dir("incoming")
            .expect("reserve scratch A");

        let cross_error = writer_b
            .discard_scratch(&scratch)
            .expect_err("writer B must reject writer A capability");
        assert!(cross_error
            .to_string()
            .contains("different run reservation"));
        assert!(scratch.path().exists());

        let moved = writer_a.run_dir().join("moved-original");
        fs::rename(scratch.path(), &moved).expect("move original scratch inode");
        fs::create_dir(scratch.path()).expect("create substitute scratch");
        fs::write(scratch.path().join("substitute-sentinel"), b"keep\n")
            .expect("write substitute sentinel");
        let rebind_error = writer_a
            .discard_scratch(&scratch)
            .expect_err("rebound scratch name must fail closed");
        assert!(
            rebind_error.to_string().contains("no longer identifies")
                || rebind_error.to_string().contains("identity")
        );
        assert!(scratch.path().join("substitute-sentinel").exists());
        assert!(moved.exists());
        assert_eq!(writer_a.outstanding_scratches.len(), 1);

        fs::remove_dir_all(scratch.path()).expect("remove substitute");
        fs::rename(&moved, scratch.path()).expect("restore original binding");
        writer_a
            .discard_scratch(&scratch)
            .expect("discard restored original scratch");
        assert!(writer_a.outstanding_scratches.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn scratch_cleanup_depth_budget_failure_remains_tracked_and_resumes() {
        let (_temp, repo) = committed_repo();
        let run_id = RunId::new("scratch-depth-budget").expect("run id");
        let mut writer =
            ArtifactRunWriter::reserve(&repo, RunArtifactFamily::Supervise, run_id, "supervise")
                .expect("reserve writer");
        writer
            .write_json(
                RunArtifactFamily::Supervise.final_report_relative_path(),
                &serde_json::json!({"status":"done"}),
                ArtifactFileDisposition::PrivateEvidence,
            )
            .expect("write final report");
        let scratch = writer
            .create_scratch_dir("incoming")
            .expect("reserve scratch");
        let mut nested = scratch.path().to_path_buf();
        for _ in 0..130 {
            nested.push("d");
            fs::create_dir(&nested).expect("create bounded-depth fixture");
        }

        let error = writer
            .discard_scratch(&scratch)
            .expect_err("over-depth tree must fail closed");
        assert!(format!("{error:#}").contains("maximum depth"));
        assert_eq!(writer.outstanding_scratches.len(), 1);
        assert!(!scratch.path().exists(), "source is durably quarantined");
        assert!(!writer.run_dir().join(FINALIZATION_MARKER).exists());

        let quarantine = quarantined_scratch_path(writer.run_dir(), scratch.identity())
            .expect("identity-bound scratch quarantine");
        fs::remove_dir_all(quarantine.join("d")).expect("shorten hostile tree for retry");
        writer
            .discard_scratch(&scratch)
            .expect("resume identity-bound quarantine cleanup");
        assert!(writer.outstanding_scratches.is_empty());
        writer
            .finalize(
                RunArtifactFamily::Supervise.final_report_relative_path(),
                false,
            )
            .expect("finalize after resumed cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn scratch_cleanup_refuses_mounted_descendant_when_mount_is_available() {
        let (_temp, repo) = committed_repo();
        let run_id = RunId::new("scratch-mount-boundary").expect("run id");
        let mut writer =
            ArtifactRunWriter::reserve(&repo, RunArtifactFamily::Consult, run_id, "consult")
                .expect("reserve writer");
        let scratch = writer
            .create_scratch_dir("incoming")
            .expect("reserve scratch");
        let mount_point = scratch.path().join("mounted-proc");
        fs::create_dir(&mount_point).expect("mount point");
        let source = CString::new("/proc").expect("mount source");
        let target = CString::new(mount_point.as_os_str().as_bytes()).expect("mount target");
        let mounted = unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        };
        if mounted != 0 {
            writer
                .discard_scratch(&scratch)
                .expect("discard fixture when mount privilege is unavailable");
            return;
        }

        let mut guard = ScratchMountGuard {
            run: writer.run_dir().to_path_buf(),
            scratch_identity: scratch.identity().clone(),
            mount_name: "mounted-proc".to_string(),
            active: true,
        };
        let error = writer
            .discard_scratch(&scratch)
            .expect_err("mounted descendant must fail closed");
        assert!(format!("{error:#}").contains("filesystem boundary"));
        assert_eq!(writer.outstanding_scratches.len(), 1);
        guard.unmount().expect("detach test bind mount");
        writer
            .discard_scratch(&scratch)
            .expect("resume cleanup after mounted descendant is detached");
    }

    #[test]
    fn scratch_cleanup_unsupported_platform_fallback_is_fail_closed() {
        let error = unsupported_artifact_scratch_cleanup()
            .expect_err("unsupported platforms must never use recursive path deletion");
        assert!(error.to_string().contains("unsupported on this platform"));
        assert!(error.to_string().contains("refusing recursive deletion"));
    }

    #[cfg(unix)]
    #[test]
    fn json_line_appends_remain_manifested_and_finalize() {
        let (_temp, repo) = committed_repo();
        let run_id = RunId::new("append-json-lines").expect("run id");
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            run_id.clone(),
            "supervise",
        )
        .expect("reserve writer");
        let path = Path::new("events/orchestration.jsonl");

        let first = writer
            .append_json_line(
                path,
                &serde_json::json!({"kind":"spawn","node":"worker-1"}),
                ArtifactFileDisposition::PrivateEvidence,
            )
            .expect("append first event");
        let second = writer
            .append_json_line(
                path,
                &serde_json::json!({"kind":"accept","node":"worker-1"}),
                ArtifactFileDisposition::PrivateEvidence,
            )
            .expect("append second event");
        let expected = concat!(
            "{\"kind\":\"spawn\",\"node\":\"worker-1\"}\n",
            "{\"kind\":\"accept\",\"node\":\"worker-1\"}\n"
        )
        .as_bytes();
        assert_eq!(
            fs::read(writer.run_dir().join(path)).expect("read journal"),
            expected
        );
        assert_eq!(
            first.bytes,
            u64::try_from(
                expected
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .expect("first line")
                    + 1
            )
            .expect("first line length")
        );
        assert_eq!(
            second.bytes,
            u64::try_from(expected.len()).expect("journal length")
        );
        assert_eq!(second.sha256, sha256_hex(expected));
        assert_eq!(writer.total_bytes, second.bytes);
        assert_eq!(writer.files.get(path), Some(&second));

        writer
            .write_json(
                RunArtifactFamily::Supervise.final_report_relative_path(),
                &serde_json::json!({"status":"succeeded"}),
                ArtifactFileDisposition::PrivateEvidence,
            )
            .expect("write final report");
        let finalization = writer
            .finalize(
                RunArtifactFamily::Supervise.final_report_relative_path(),
                false,
            )
            .expect("finalize appended journal");
        let finalized_record = finalization
            .files
            .iter()
            .find(|record| record.path == path)
            .expect("journal record");
        assert_eq!(finalized_record, &second);

        let reader = ArtifactRunReader::open(&repo, RunArtifactFamily::Supervise, &run_id)
            .expect("open finalized run");
        let journal = reader.read(path).expect("read finalized journal");
        let records = journal
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice::<Value>(line).expect("valid JSONL record"))
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["kind"], "spawn");
        assert_eq!(records[1]["kind"], "accept");
    }

    #[cfg(unix)]
    #[test]
    fn json_line_append_rejects_disposition_change_without_mutation() {
        let (_temp, repo) = committed_repo();
        let run_id = RunId::new("append-disposition").expect("run id");
        let mut writer =
            ArtifactRunWriter::reserve(&repo, RunArtifactFamily::Supervise, run_id, "supervise")
                .expect("reserve writer");
        let path = Path::new("events/orchestration.jsonl");
        let first = writer
            .append_json_line(
                path,
                &serde_json::json!({"kind":"spawn"}),
                ArtifactFileDisposition::PrivateEvidence,
            )
            .expect("append first event");
        let before = fs::read(writer.run_dir().join(path)).expect("read before mismatch");

        let error = writer
            .append_json_line(
                path,
                &serde_json::json!({"kind":"accept"}),
                ArtifactFileDisposition::Publishable,
            )
            .expect_err("disposition change must fail");
        assert!(error.to_string().contains("cannot change file disposition"));
        assert_eq!(
            fs::read(writer.run_dir().join(path)).expect("read after mismatch"),
            before
        );
        assert_eq!(writer.files.get(path), Some(&first));
        assert_eq!(writer.total_bytes, first.bytes);
    }

    #[cfg(unix)]
    #[test]
    fn partial_json_line_append_is_completed_before_later_append_and_finalize() {
        let (_temp, repo) = committed_repo();
        let run_id = RunId::new("append-recovery").expect("run id");
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            run_id.clone(),
            "supervise",
        )
        .expect("reserve writer");
        let path = Path::new("events/orchestration.jsonl");
        set_artifact_append_fault(ArtifactAppendFaultPoint::PartialWrite);
        let error = writer
            .append_json_line(
                path,
                &serde_json::json!({"kind":"spawn","node":"worker-1"}),
                ArtifactFileDisposition::PrivateEvidence,
            )
            .expect_err("injected partial write failure");
        assert!(error
            .to_string()
            .contains("injected partial artifact append"));
        writer
            .append_json_line(
                path,
                &serde_json::json!({"kind":"accept","node":"worker-1"}),
                ArtifactFileDisposition::PrivateEvidence,
            )
            .expect("append after recovered partial write");
        let journal = fs::read(writer.run_dir().join(path)).expect("read recovered journal");
        assert_eq!(
            journal,
            concat!(
                "{\"kind\":\"spawn\",\"node\":\"worker-1\"}\n",
                "{\"kind\":\"accept\",\"node\":\"worker-1\"}\n"
            )
            .as_bytes()
        );
        for line in journal
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            serde_json::from_slice::<Value>(line).expect("recovered JSONL line is complete");
        }
        let record = writer.files.get(path).expect("reconciled record");
        assert_eq!(record.bytes, u64::try_from(journal.len()).expect("length"));
        assert_eq!(record.sha256, sha256_hex(&journal));
        assert_eq!(writer.total_bytes, record.bytes);

        writer
            .write_json(
                RunArtifactFamily::Supervise.final_report_relative_path(),
                &serde_json::json!({"status":"succeeded"}),
                ArtifactFileDisposition::PrivateEvidence,
            )
            .expect("write final report");
        writer
            .finalize(
                RunArtifactFamily::Supervise.final_report_relative_path(),
                false,
            )
            .expect("finalize after recovered append failure");
        ArtifactRunReader::open(&repo, RunArtifactFamily::Supervise, &run_id)
            .expect("open finalized recovered run");
    }

    #[cfg(unix)]
    #[test]
    fn authenticated_resume_binding_reopens_only_the_exact_unfinalized_manifest() {
        let (_temp, repo) = committed_repo();
        let run_id = RunId::new("artifact-resume-exact").expect("run id");
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            run_id.clone(),
            "supervise",
        )
        .expect("reserve writer");
        writer
            .write_bytes(
                "evidence/completed.txt",
                b"completed once\n",
                ArtifactFileDisposition::PrivateEvidence,
            )
            .expect("write completed evidence");
        let binding = writer.resume_binding().expect("capture resume binding");
        drop(writer);

        let mut tampered = binding.clone();
        tampered.files[0].sha256 = "0".repeat(64);
        let error = match ArtifactRunWriter::reopen_unfinalized(&repo, &tampered) {
            Ok(_) => panic!("tampered manifest binding must fail closed"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("digest/length"));

        let mut resumed = ArtifactRunWriter::reopen_unfinalized(&repo, &binding)
            .expect("reopen exact authenticated binding");
        assert_eq!(
            fs::read(resumed.run_dir().join("evidence/completed.txt"))
                .expect("read completed evidence"),
            b"completed once\n"
        );
        resumed
            .write_json(
                RunArtifactFamily::Supervise.final_report_relative_path(),
                &serde_json::json!({"status":"succeeded"}),
                ArtifactFileDisposition::PrivateEvidence,
            )
            .expect("write resumed final report");
        resumed
            .finalize(
                RunArtifactFamily::Supervise.final_report_relative_path(),
                false,
            )
            .expect("finalize resumed writer");
        ArtifactRunReader::open(&repo, RunArtifactFamily::Supervise, &run_id)
            .expect("open finalized resumed run");
    }

    #[cfg(unix)]
    #[test]
    fn authenticated_resume_recovers_only_checkpoint_planned_extra_file() {
        let (_temp, repo) = committed_repo();
        let run_id = RunId::new("artifact-resume-recovery").expect("run id");
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            run_id.clone(),
            "supervise",
        )
        .expect("reserve writer");
        writer
            .write_bytes(
                "evidence/completed.txt",
                b"completed once\n",
                ArtifactFileDisposition::PrivateEvidence,
            )
            .expect("write completed evidence");
        let binding = writer.resume_binding().expect("capture resume binding");
        let report_path = RunArtifactFamily::Supervise.final_report_relative_path();
        let planned_report = b"{\n  \"status\": \"succeeded\"\n}\n";
        writer
            .write_bytes(
                &report_path,
                planned_report,
                ArtifactFileDisposition::PrivateEvidence,
            )
            .expect("simulate report write after planned checkpoint");
        drop(writer);

        let wrong = ArtifactRecoveryFile {
            relative: &report_path,
            contents: b"different\n",
            disposition: ArtifactFileDisposition::PrivateEvidence,
        };
        let error =
            match ArtifactRunWriter::reopen_unfinalized_with_recovery(&repo, &binding, &[wrong]) {
                Ok(_) => panic!("mismatched planned bytes must fail closed"),
                Err(error) => error,
            };
        assert!(error.to_string().contains("do not match"));

        let recovery = ArtifactRecoveryFile {
            relative: &report_path,
            contents: planned_report,
            disposition: ArtifactFileDisposition::PrivateEvidence,
        };
        let resumed =
            ArtifactRunWriter::reopen_unfinalized_with_recovery(&repo, &binding, &[recovery])
                .expect("recover exact checkpoint-planned report");
        resumed
            .finalize(&report_path, false)
            .expect("finalize recovered report");
        let reader = ArtifactRunReader::open(&repo, RunArtifactFamily::Supervise, &run_id)
            .expect("open recovered finalized run");
        assert_eq!(
            reader.read(&report_path).expect("read recovered report"),
            planned_report
        );
    }

    #[cfg(unix)]
    #[test]
    fn failed_append_recovery_syncs_file_and_new_parent_before_finalization() {
        for (index, fault) in [
            ArtifactAppendFaultPoint::AfterWriteBeforeFileSync,
            ArtifactAppendFaultPoint::AfterFileSyncBeforeParentSync,
        ]
        .into_iter()
        .enumerate()
        {
            let (_temp, repo) = committed_repo();
            let run_id = RunId::new(format!("append-sync-recovery-{index}")).expect("run id");
            let mut writer = ArtifactRunWriter::reserve(
                &repo,
                RunArtifactFamily::Supervise,
                run_id.clone(),
                "supervise",
            )
            .expect("reserve writer");
            let path = Path::new("events/orchestration.jsonl");
            set_artifact_append_fault(fault);
            let error = writer
                .append_json_line(
                    path,
                    &serde_json::json!({"kind":"spawn","node":"worker-1"}),
                    ArtifactFileDisposition::PrivateEvidence,
                )
                .expect_err("injected durability-boundary failure");
            assert!(error
                .to_string()
                .contains("injected artifact append failure"));
            assert!(writer.poisoned_appends.is_empty());
            let journal = fs::read(writer.run_dir().join(path)).expect("read recovered journal");
            serde_json::from_slice::<Value>(journal.strip_suffix(b"\n").expect("newline"))
                .expect("recovered journal line");

            writer
                .write_json(
                    RunArtifactFamily::Supervise.final_report_relative_path(),
                    &serde_json::json!({"status":"succeeded"}),
                    ArtifactFileDisposition::PrivateEvidence,
                )
                .expect("write final report");
            writer
                .finalize(
                    RunArtifactFamily::Supervise.final_report_relative_path(),
                    false,
                )
                .expect("finalize after durability recovery");
            ArtifactRunReader::open(&repo, RunArtifactFamily::Supervise, &run_id)
                .expect("open finalized recovered run");
        }
    }

    #[cfg(unix)]
    #[test]
    fn writer_finalizes_private_artifacts_and_public_evidence_cannot_forge_mac() {
        let (_temp, repo) = committed_repo();
        let run_id = RunId::new("secure-run").expect("run id");
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Autopilot,
            run_id.clone(),
            "autopilot",
        )
        .expect("reserve writer");
        writer
            .write_json(
                "final-report.json",
                &serde_json::json!({"status": "succeeded", "success": true}),
                ArtifactFileDisposition::Publishable,
            )
            .expect("write report");
        writer
            .write_bytes(
                "details/evidence.txt",
                b"verified\n",
                ArtifactFileDisposition::Publishable,
            )
            .expect("write evidence");
        let finalization = writer
            .finalize("final-report.json", true)
            .expect("finalize");
        assert!(finalization.publishable);

        let reader = ArtifactRunReader::open(&repo, RunArtifactFamily::Autopilot, &run_id)
            .expect("strict reader");
        assert_eq!(
            reader.read("details/evidence.txt").expect("read"),
            b"verified\n"
        );
        let summary = latest_run(&repo, RunArtifactFamily::Autopilot)
            .expect("latest")
            .run
            .expect("run");
        assert!(summary.finalized);
        assert!(summary.publishable);
        assert!(summary.provenance_valid);
        assert!(summary.artifact_digests_verified);
        assert_eq!(summary.final_report_status, "succeeded");
        assert_eq!(summary.final_report_success, Some(true));
        assert!(summary.final_report_readable);
        assert!(!summary.final_report_corrupt);

        let run = run_dir(&repo, RunArtifactFamily::Autopilot, &run_id);
        assert_eq!(mode(&run), 0o700);
        assert_eq!(mode(&run.join("final-report.json")), 0o600);
        assert_eq!(mode(&run.join(FINALIZATION_MARKER)), 0o600);
        let repository = discover_artifact_repository(&repo).expect("repository");
        let key_path = repository
            .common_dir
            .join("maco/state")
            .join(authentication_key_file_name());
        let key_lock_path = repository
            .common_dir
            .join("maco/state")
            .join(authentication_key_lock_name());
        assert_eq!(mode(&key_path), 0o600);
        assert_eq!(mode(&key_lock_path), 0o600);

        let marker_path = run.join(FINALIZATION_MARKER);
        let original_marker = fs::read(&marker_path).expect("marker");
        let mut forged: ArtifactFinalization =
            serde_json::from_slice(&original_marker).expect("marker JSON");
        forged.provenance.producer = "legacy-writer".to_string();
        forged.checksum = finalization_checksum(&forged).expect("public checksum");
        forged.hmac_sha256 = "00".repeat(32);
        fs::write(
            &marker_path,
            serde_json::to_vec_pretty(&forged).expect("forged marker"),
        )
        .expect("write public-evidence forgery");
        let marker_error = ArtifactRunReader::open(&repo, RunArtifactFamily::Autopilot, &run_id)
            .err()
            .expect("forged MAC");
        assert!(marker_error
            .to_string()
            .contains("HMAC verification failed"));

        let mut uppercase: ArtifactFinalization =
            serde_json::from_slice(&original_marker).expect("marker JSON");
        uppercase.hmac_sha256.replace_range(..1, "A");
        fs::write(
            &marker_path,
            serde_json::to_vec_pretty(&uppercase).expect("uppercase marker"),
        )
        .expect("write uppercase MAC");
        let uppercase_error = ArtifactRunReader::open(&repo, RunArtifactFamily::Autopilot, &run_id)
            .err()
            .expect("uppercase MAC");
        assert!(uppercase_error.to_string().contains("HMAC is malformed"));

        let mut oversized: ArtifactFinalization =
            serde_json::from_slice(&original_marker).expect("marker JSON");
        oversized.hmac_sha256 = "0".repeat(65);
        fs::write(
            &marker_path,
            serde_json::to_vec_pretty(&oversized).expect("oversized marker"),
        )
        .expect("write oversized MAC");
        let oversized_error = ArtifactRunReader::open(&repo, RunArtifactFamily::Autopilot, &run_id)
            .err()
            .expect("oversized MAC");
        assert!(oversized_error.to_string().contains("HMAC is malformed"));
        fs::write(&marker_path, original_marker).expect("restore marker");

        let original_key = fs::read(&key_path).expect("MAC key");
        let moved_key = key_path.with_file_name("artifact-key.original");
        fs::rename(&key_path, &moved_key).expect("move MAC key");
        let missing_error = ArtifactRunReader::open(&repo, RunArtifactFamily::Autopilot, &run_id)
            .err()
            .expect("missing key");
        assert!(missing_error.to_string().contains("MAC key is missing"));
        assert!(
            !key_path.exists(),
            "reader must never recreate a missing key"
        );
        let rekey_error = open_artifact_auth_writer(&repository)
            .err()
            .expect("rekey refusal");
        assert!(rekey_error
            .to_string()
            .contains("existing final marker is present"));
        fs::rename(&moved_key, &key_path).expect("restore MAC key");
        ArtifactRunReader::open(&repo, RunArtifactFamily::Autopilot, &run_id)
            .expect("restored key");

        fs::write(&key_path, vec![0xa5; authentication_key_length()]).expect("corrupt bound key");
        let corrupt_key_error =
            ArtifactRunReader::open(&repo, RunArtifactFamily::Autopilot, &run_id)
                .err()
                .expect("corrupt key");
        assert!(corrupt_key_error.to_string().contains("key binding"));
        fs::write(&key_path, &original_key).expect("restore bound key contents");
        ArtifactRunReader::open(&repo, RunArtifactFamily::Autopilot, &run_id)
            .expect("restored key contents");

        let moved_key = key_path.with_file_name("artifact-key.bound-original");
        fs::rename(&key_path, &moved_key).expect("move bound key");
        write_private(&key_path, &original_key);
        let rebound_key_error =
            ArtifactRunReader::open(&repo, RunArtifactFamily::Autopilot, &run_id)
                .err()
                .expect("rebound key");
        assert!(rebound_key_error.to_string().contains("key binding"));
        fs::remove_file(&key_path).expect("remove replacement key");
        fs::rename(&moved_key, &key_path).expect("restore bound key");

        let lock_path = run.join(RUN_LOCK_FILE);
        let original_lock_path = run.join("artifact-writer-lock.original");
        fs::rename(&lock_path, &original_lock_path).expect("move bound writer lock");
        fs::write(&lock_path, b"").expect("replacement lock");
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))
            .expect("replacement lock mode");
        let evidence_error = ArtifactRunReader::open(&repo, RunArtifactFamily::Autopilot, &run_id)
            .err()
            .expect("writer evidence");
        assert!(evidence_error.to_string().contains("lock identity"));
    }

    #[cfg(unix)]
    #[test]
    fn existing_marker_refuses_replaced_key_for_new_finalization() {
        let (_temp, repo) = committed_repo();
        let first_run = RunId::new("key-anchor-run").expect("run id");
        finalize_private_test_run(&repo, RunArtifactFamily::Autopilot, &first_run, "autopilot");
        let repository = discover_artifact_repository(&repo).expect("repository");
        let key_path = repository
            .common_dir
            .join("maco/state")
            .join(authentication_key_file_name());
        let original_key = key_path.with_file_name("artifact-key.pre-replacement");
        fs::rename(&key_path, &original_key).expect("move original key");
        write_private(&key_path, &vec![0xa5; authentication_key_length()]);

        let second_run = RunId::new("replacement-key-run").expect("run id");
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Autopilot,
            second_run.clone(),
            "autopilot",
        )
        .expect("reserve second writer");
        writer
            .write_json(
                "final-report.json",
                &serde_json::json!({"status":"done"}),
                ArtifactFileDisposition::PrivateEvidence,
            )
            .expect("write second report");
        let error = writer
            .finalize("final-report.json", false)
            .expect_err("replacement key must not establish a new signing epoch");
        assert!(error
            .to_string()
            .contains("does not match existing marker binding"));
        assert!(!run_dir(&repo, RunArtifactFamily::Autopilot, &second_run)
            .join(FINALIZATION_MARKER)
            .exists());
    }

    #[cfg(unix)]
    #[test]
    fn missing_common_key_scans_main_and_every_registered_linked_worktree() {
        let (temp, repo) = committed_repo();
        let linked = WorktreeManager::new(&repo)
            .create_for_test(WorktreeCreateOptions {
                agent_id: "artifact-linked".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(temp.path().join("worktrees")),
            })
            .expect("create linked worktree");
        let first_run = RunId::new("main-key-anchor").expect("run id");
        finalize_private_test_run(&repo, RunArtifactFamily::Inbox, &first_run, "inbox");
        let repository = discover_artifact_repository(&repo).expect("repository");
        let key_path = repository
            .common_dir
            .join("maco/state")
            .join(authentication_key_file_name());
        let original_key = key_path.with_file_name("artifact-key.missing-linked-test");
        fs::rename(&key_path, &original_key).expect("remove shared key");

        let linked_run = RunId::new("linked-rekey-attempt").expect("run id");
        let mut writer =
            ArtifactRunWriter::reserve(&linked.path, RunArtifactFamily::Inbox, linked_run, "inbox")
                .expect("reserve linked writer");
        writer
            .write_json(
                "final-report.json",
                &serde_json::json!({"status":"done"}),
                ArtifactFileDisposition::PrivateEvidence,
            )
            .expect("write linked report");
        let error = writer
            .finalize("final-report.json", false)
            .expect_err("marker in main worktree must prevent linked-worktree rekey");
        assert!(error
            .to_string()
            .contains("existing final marker is present"));
        assert!(!key_path.exists(), "refused rekey must not create a key");
    }

    #[cfg(unix)]
    #[test]
    fn stale_registered_worktree_refuses_first_key_creation() {
        let (temp, repo) = committed_repo();
        let linked = WorktreeManager::new(&repo)
            .create_for_test(WorktreeCreateOptions {
                agent_id: "artifact-stale".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(temp.path().join("worktrees")),
            })
            .expect("create linked worktree");
        fs::remove_dir_all(&linked.path).expect("make registration stale");
        let repository = discover_artifact_repository(&repo).expect("repository");
        let key_path = repository
            .common_dir
            .join("maco/state")
            .join(authentication_key_file_name());
        let original_key = fs::read(&key_path).expect("managed worktree registry created auth key");

        let error = open_artifact_auth_writer(&repository)
            .err()
            .expect("stale worktree registration must fail closed");
        assert!(error.to_string().contains("stale or invalid"));
        assert_eq!(
            fs::read(&key_path).expect("auth key remains present"),
            original_key
        );
    }

    #[test]
    fn first_key_marker_scan_has_a_global_entry_budget() {
        let (_temp, repo) = committed_repo();
        let repository = discover_artifact_repository(&repo).expect("repository");
        let root = open_or_create_run_root(&repository, RunArtifactFamily::Consult)
            .expect("artifact root");
        for index in 0..=MAX_RUN_ROOT_ENTRIES.saturating_mul(8) {
            fs::create_dir(root.path().join(format!("scan-budget-{index}")))
                .expect("marker-scan entry");
        }
        let key_path = repository
            .common_dir
            .join("maco/state")
            .join(authentication_key_file_name());

        let error = open_artifact_auth_writer(&repository)
            .err()
            .expect("marker scan budget must fail closed");
        assert!(error.to_string().contains("global entry budget"));
        assert!(!key_path.exists());
    }

    #[test]
    fn retention_count_age_and_size_limits_report_exact_dry_run_bytes() {
        let (_temp, repo) = committed_repo();
        for (run_id, transcript) in [
            ("retention-a", b"aaa\n".as_slice()),
            ("retention-b", b"bbbbbb\n".as_slice()),
            ("retention-c", b"ccccccccc\n".as_slice()),
        ] {
            finalize_test_run_with_log(
                &repo,
                RunArtifactFamily::Consult,
                &RunId::new(run_id).expect("run id"),
                transcript,
            );
        }
        let repository = discover_artifact_repository(&repo).expect("repository");
        let root = open_existing_run_root(&repository, RunArtifactFamily::Consult).expect("root");
        let items = retention_items(&repository, &root, ArtifactRetentionFamily::Consult)
            .expect("retention inventory");
        let scanned_bytes = items.iter().map(|item| item.bytes).sum::<u64>();
        let compressible_log_bytes = items
            .iter()
            .map(|item| item.compressible_log_bytes)
            .sum::<u64>();
        let newest_bytes = items[0].bytes;
        let newest_log = fs::read(items[0].absolute_path.join("events.jsonl"))
            .expect("newest transcript before prune");
        let policy = ArtifactRetentionPolicy {
            max_count: 2,
            max_age: None,
            max_total_bytes: Some(newest_bytes),
            unfinalized_grace: Some(Duration::from_secs(60)),
        };

        let dry = prune_artifacts_at(
            &repo,
            ArtifactRetentionFamily::Consult,
            &policy,
            true,
            SystemTime::now(),
        )
        .expect("dry-run retention");
        assert_eq!(dry.scanned_bytes, scanned_bytes);
        assert_eq!(dry.retained_bytes, scanned_bytes);
        assert_eq!(dry.reclaimed_bytes, 0);
        assert_eq!(
            dry.compression_strategy,
            ArtifactCompressionStrategy::NoneRequiresWriterMigration
        );
        assert_eq!(dry.compressible_log_bytes, compressible_log_bytes);
        assert_eq!(dry.compressed_bytes, 0);
        assert_eq!(dry.entries[0].action, RunArtifactPruneAction::Keep);
        assert!(dry.entries[1]
            .selected_by
            .contains(&ArtifactRetentionLimit::MaxTotalBytes));
        assert!(dry.entries[2]
            .selected_by
            .contains(&ArtifactRetentionLimit::MaxCount));
        let would_reclaim = dry
            .entries
            .iter()
            .filter(|entry| entry.action == RunArtifactPruneAction::WouldDelete)
            .map(|entry| entry.bytes)
            .sum::<u64>();
        assert_eq!(dry.would_reclaim_bytes, would_reclaim);
        assert_eq!(dry.projected_retained_bytes, scanned_bytes - would_reclaim);
        for item in &items {
            assert!(item.absolute_path.exists(), "dry-run removed an artifact");
        }
        assert_eq!(
            fs::read(items[0].absolute_path.join("events.jsonl")).expect("newest transcript"),
            newest_log,
            "the explicit no-compression policy must not rewrite retained logs"
        );

        let applied = prune_artifacts_at(
            &repo,
            ArtifactRetentionFamily::Consult,
            &policy,
            false,
            SystemTime::now(),
        )
        .expect("apply retention");
        assert_eq!(applied.reclaimed_bytes, dry.would_reclaim_bytes);
        assert_eq!(applied.retained_bytes, dry.projected_retained_bytes);
        assert_eq!(applied.projected_retained_bytes, applied.retained_bytes);
        assert_eq!(applied.deleted_count, 2);
        assert_eq!(
            fs::read(items[0].absolute_path.join("events.jsonl")).expect("retained transcript"),
            newest_log,
            "apply must not rewrite retained logs"
        );
    }

    #[test]
    fn max_age_reclaims_a_finalized_run_inside_the_count_limit() {
        let (_temp, repo) = committed_repo();
        let run_id = RunId::new("age-limited").expect("run id");
        finalize_private_test_run(&repo, RunArtifactFamily::Inbox, &run_id, "inbox");
        let policy = ArtifactRetentionPolicy {
            max_count: 10,
            max_age: Some(Duration::from_secs(24 * 60 * 60)),
            max_total_bytes: None,
            unfinalized_grace: Some(Duration::from_secs(7 * 24 * 60 * 60)),
        };
        let report = prune_artifacts_at(
            &repo,
            ArtifactRetentionFamily::Inbox,
            &policy,
            true,
            SystemTime::now() + Duration::from_secs(2 * 24 * 60 * 60),
        )
        .expect("age dry-run");
        assert_eq!(
            report.entries[0].action,
            RunArtifactPruneAction::WouldDelete
        );
        assert_eq!(
            report.entries[0].selected_by,
            vec![ArtifactRetentionLimit::MaxAge]
        );
        assert!(run_dir(&repo, RunArtifactFamily::Inbox, &run_id).exists());
    }

    #[test]
    fn expired_unfinalized_runs_are_reclaimed_but_fresh_and_active_runs_are_pinned() {
        let (_temp, repo) = committed_repo();
        let active_id = RunId::new("active-unfinalized").expect("run id");
        let mut active = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Autopilot,
            active_id.clone(),
            "autopilot",
        )
        .expect("active writer");
        active
            .write_bytes(
                "events.jsonl",
                b"active\n",
                ArtifactFileDisposition::PrivateEvidence,
            )
            .expect("active transcript");
        let policy = ArtifactRetentionPolicy {
            max_count: 0,
            max_age: None,
            max_total_bytes: None,
            unfinalized_grace: Some(Duration::from_secs(7 * 24 * 60 * 60)),
        };

        let fresh = prune_artifacts_at(
            &repo,
            ArtifactRetentionFamily::Autopilot,
            &policy,
            false,
            SystemTime::now(),
        )
        .expect("fresh refusal");
        assert_eq!(fresh.deleted_count, 0);
        assert_eq!(
            fresh.entries[0].action,
            RunArtifactPruneAction::RefuseUnfinalized
        );
        assert!(fresh.entries[0]
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("fresh")));

        let active_report = prune_artifacts_at(
            &repo,
            ArtifactRetentionFamily::Autopilot,
            &policy,
            false,
            SystemTime::now() + Duration::from_secs(8 * 24 * 60 * 60),
        )
        .expect("active refusal");
        assert_eq!(active_report.deleted_count, 0);
        assert!(active_report.entries[0]
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("writer lock is held")));
        drop(active);

        let expired = prune_artifacts_at(
            &repo,
            ArtifactRetentionFamily::Autopilot,
            &policy,
            false,
            SystemTime::now() + Duration::from_secs(8 * 24 * 60 * 60),
        )
        .expect("expired reclamation");
        assert_eq!(expired.deleted_count, 1);
        assert_eq!(expired.reclaimed_bytes, active_report.scanned_bytes);
        assert!(!run_dir(&repo, RunArtifactFamily::Autopilot, &active_id).exists());
    }

    #[test]
    fn program_logs_are_covered_and_dry_run_bytes_match_apply() {
        let (_temp, repo) = committed_repo();
        let maco = repo.join(".maco");
        let old = maco.join("program-a");
        let newest = maco.join("program-z");
        fs::create_dir_all(old.join("logs")).expect("old program logs");
        fs::write(old.join("logs/old.jsonl"), b"old-log\n").expect("old log");
        fs::create_dir_all(newest.join("logs")).expect("new program logs");
        fs::write(newest.join("logs/new.jsonl"), b"new-log-longer\n").expect("new log");
        fs::write(maco.join("unrelated-sentinel"), b"keep\n").expect("sentinel");
        let policy = ArtifactRetentionPolicy {
            max_count: 1,
            max_age: None,
            max_total_bytes: None,
            unfinalized_grace: Some(Duration::ZERO),
        };

        let dry = prune_artifacts_at(
            &repo,
            ArtifactRetentionFamily::Program,
            &policy,
            true,
            SystemTime::now(),
        )
        .expect("program dry-run");
        assert_eq!(dry.family, ArtifactRetentionFamily::Program);
        assert_eq!(dry.run_root, PathBuf::from(".maco"));
        assert_eq!(
            dry.scanned_bytes,
            b"old-log\n".len() as u64 + b"new-log-longer\n".len() as u64
        );
        assert_eq!(dry.compressible_log_bytes, dry.scanned_bytes);
        assert_eq!(dry.would_reclaim_bytes, b"old-log\n".len() as u64);
        assert!(old.exists());
        assert!(newest.exists());

        let applied = prune_artifacts_at(
            &repo,
            ArtifactRetentionFamily::Program,
            &policy,
            false,
            SystemTime::now(),
        )
        .expect("program apply");
        assert_eq!(applied.reclaimed_bytes, dry.would_reclaim_bytes);
        assert!(!old.exists());
        assert!(newest.exists());
        assert_eq!(
            fs::read(newest.join("logs/new.jsonl")).expect("new log"),
            b"new-log-longer\n"
        );
        assert_eq!(
            fs::read(maco.join("unrelated-sentinel")).expect("sentinel"),
            b"keep\n"
        );
    }

    #[test]
    fn legacy_direct_writer_is_visible_but_never_finalized_or_publishable() {
        let (_temp, repo) = committed_repo();
        let run_id = RunId::new("legacy-run").expect("run id");
        ensure_run_dir_available(&repo, RunArtifactFamily::Inbox, &run_id).expect("reserve");
        fs::write(
            final_report_path(&repo, RunArtifactFamily::Inbox, &run_id),
            b"{\"status\":\"succeeded\",\"success\":true}\n",
        )
        .expect("legacy report");

        let summary = latest_run(&repo, RunArtifactFamily::Inbox)
            .expect("latest")
            .run
            .expect("run");
        assert_active_unfinalized_summary(&summary, true);
        assert!(!summary.finalized);
        assert!(!summary.publishable);
        assert!(!summary.provenance_valid);
        assert!(!summary.artifact_digests_verified);
        assert!(ArtifactRunReader::open(&repo, RunArtifactFamily::Inbox, &run_id).is_err());
        let prune = prune_runs(&repo, RunArtifactFamily::Inbox, 0, false)
            .expect("legacy prune refusal report");
        assert_eq!(prune.deleted_count, 0);
        assert_eq!(prune.refused_unfinalized_count, 1);
        assert_eq!(
            prune.entries[0].action,
            RunArtifactPruneAction::RefuseUnfinalized
        );
        assert!(run_dir(&repo, RunArtifactFamily::Inbox, &run_id).exists());
    }

    #[test]
    fn marker_missing_report_bytes_are_never_parsed_or_exposed() {
        let (_temp, repo) = committed_repo();
        let secret = "marker-missing-secret-value";
        let absolute = repo.display().to_string();
        let fixtures = [
            (
                "valid-unfinalized",
                format!("{{\"status\":\"{secret}\",\"success\":true,\"path\":{absolute:?}}}\n"),
            ),
            (
                "malformed-unfinalized",
                format!("{{not-json:{secret}:{absolute}\n"),
            ),
            ("secret-unfinalized", format!("{secret}\n{absolute}\n")),
        ];

        for (run_id, contents) in fixtures {
            let run_id = RunId::new(run_id).expect("run id");
            ensure_run_dir_available(&repo, RunArtifactFamily::Inbox, &run_id).expect("reserve");
            fs::write(
                final_report_path(&repo, RunArtifactFamily::Inbox, &run_id),
                contents,
            )
            .expect("unfinalized report fixture");
        }

        let list = list_runs(&repo, RunArtifactFamily::Inbox).expect("list unfinalized runs");
        assert_eq!(list.runs.len(), 3);
        for summary in &list.runs {
            assert_active_unfinalized_summary(summary, true);
        }
        let serialized = serde_json::to_string(&list).expect("serialize public listing");
        assert!(!serialized.contains(secret));
        assert!(!serialized.contains(&absolute));
        assert!(!serialized.contains("not-json"));
    }

    #[test]
    fn metadata_only_listing_never_creates_a_missing_report_parent() {
        let (_temp, repo) = committed_repo();
        let run_id = RunId::new("missing-consult-parent").expect("run id");
        ensure_run_dir_available(&repo, RunArtifactFamily::Consult, &run_id).expect("reserve");
        let trusted = run_dir(&repo, RunArtifactFamily::Consult, &run_id).join("trusted");
        assert!(!trusted.exists());

        let summary = latest_run(&repo, RunArtifactFamily::Consult)
            .expect("metadata-only latest")
            .run
            .expect("run");
        assert_active_unfinalized_summary(&summary, false);
        assert!(
            !trusted.exists(),
            "metadata-only listing must not create a missing report parent"
        );
    }

    #[cfg(unix)]
    #[test]
    fn marker_missing_symlink_and_special_reports_are_metadata_only() {
        use std::os::unix::fs::symlink;

        let (temp, repo) = committed_repo();
        let secret = "external-final-report-secret";
        let external = temp.path().join("external-final-report.json");
        write_private(&external, secret.as_bytes());

        let symlink_id = RunId::new("unfinalized-symlink-report").expect("run id");
        ensure_run_dir_available(&repo, RunArtifactFamily::Inbox, &symlink_id).expect("reserve");
        symlink(
            &external,
            final_report_path(&repo, RunArtifactFamily::Inbox, &symlink_id),
        )
        .expect("symlink report");

        let fifo_id = RunId::new("unfinalized-fifo-report").expect("run id");
        ensure_run_dir_available(&repo, RunArtifactFamily::Inbox, &fifo_id).expect("reserve");
        let fifo_path = final_report_path(&repo, RunArtifactFamily::Inbox, &fifo_id);
        let fifo = CString::new(fifo_path.as_os_str().as_bytes()).expect("FIFO path");
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

        let directory_id = RunId::new("unfinalized-directory-report").expect("run id");
        ensure_run_dir_available(&repo, RunArtifactFamily::Inbox, &directory_id).expect("reserve");
        fs::create_dir(final_report_path(
            &repo,
            RunArtifactFamily::Inbox,
            &directory_id,
        ))
        .expect("directory report");

        let list = list_runs(&repo, RunArtifactFamily::Inbox).expect("metadata-only listing");
        assert_eq!(list.runs.len(), 3);
        for summary in &list.runs {
            assert_active_unfinalized_summary(summary, true);
        }
        let serialized = serde_json::to_string(&list).expect("serialize public listing");
        assert!(!serialized.contains(secret));
        assert!(!serialized.contains(&external.display().to_string()));
        assert!(!serialized.contains(&repo.display().to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn present_but_invalid_marker_never_falls_back_to_report_parsing() {
        let (_temp, repo) = committed_repo();
        let run_id = RunId::new("invalid-marker-valid-report").expect("run id");
        ensure_run_dir_available(&repo, RunArtifactFamily::Inbox, &run_id).expect("reserve");
        let secret = "invalid-marker-secret-value";
        let absolute = repo.display().to_string();
        write_private(
            &final_report_path(&repo, RunArtifactFamily::Inbox, &run_id),
            format!(
                "{{\"status\":\"succeeded\",\"success\":true,\"secret\":\"{secret}\",\"path\":{absolute:?}}}\n"
            )
            .as_bytes(),
        );
        write_private(
            &run_dir(&repo, RunArtifactFamily::Inbox, &run_id).join(FINALIZATION_MARKER),
            format!("{{invalid-marker:{secret}:{absolute}\n").as_bytes(),
        );

        let summary = latest_run(&repo, RunArtifactFamily::Inbox)
            .expect("latest")
            .run
            .expect("run");
        assert!(summary.final_report_exists);
        assert_eq!(summary.final_report_status, "unverifiable_finalization");
        assert_eq!(summary.final_report_success, None);
        assert!(!summary.final_report_readable);
        assert!(summary.final_report_corrupt);
        assert_eq!(summary.final_report_error, None);
        assert!(!summary.finalized);
        assert!(!summary.publishable);
        assert!(!summary.provenance_valid);
        assert!(!summary.artifact_digests_verified);
        assert_eq!(
            summary.finalization_error.as_deref(),
            Some("artifact finalization marker is present but verification failed")
        );
        let serialized = serde_json::to_string(&summary).expect("serialize public summary");
        assert!(!serialized.contains(secret));
        assert!(!serialized.contains(&absolute));
    }

    #[test]
    fn oversized_report_and_run_root_entry_budget_fail_boundedly() {
        let (_temp, repo) = committed_repo();
        let run_id = RunId::new("large-run").expect("run id");
        ensure_run_dir_available(&repo, RunArtifactFamily::Consult, &run_id).expect("reserve");
        let report = final_report_path(&repo, RunArtifactFamily::Consult, &run_id);
        let report_parent = report.parent().expect("consult report parent");
        fs::create_dir_all(report_parent).expect("consult report directory");
        #[cfg(unix)]
        fs::set_permissions(report_parent, fs::Permissions::from_mode(0o700))
            .expect("private consult report directory");
        fs::write(
            report,
            vec![b'x'; usize::try_from(MAX_ARTIFACT_FILE_BYTES).expect("limit") + 1],
        )
        .expect("oversized report");
        let summary = latest_run(&repo, RunArtifactFamily::Consult)
            .expect("latest")
            .run
            .expect("run");
        assert_active_unfinalized_summary(&summary, true);

        let root = run_root(&repo, RunArtifactFamily::Consult);
        for index in 0..MAX_RUN_ROOT_ENTRIES {
            fs::create_dir(root.join(format!("extra-{index}"))).expect("extra run");
        }
        assert!(list_runs(&repo, RunArtifactFamily::Consult)
            .expect_err("entry budget")
            .to_string()
            .contains("entry budget"));
    }

    #[cfg(unix)]
    #[test]
    fn prune_refuses_finalized_runs_tampered_with_symlink_hardlink_and_fifo() {
        use std::os::unix::fs::symlink;

        for kind in ["symlink", "hardlink", "fifo"] {
            let (temp, repo) = committed_repo();
            let run_id = RunId::new(format!("unsafe-{kind}")).expect("run id");
            let mut writer = ArtifactRunWriter::reserve(
                &repo,
                RunArtifactFamily::Inbox,
                run_id.clone(),
                "inbox",
            )
            .expect("writer");
            writer
                .write_json(
                    "final-report.json",
                    &serde_json::json!({"status":"done"}),
                    ArtifactFileDisposition::PrivateEvidence,
                )
                .expect("report");
            writer
                .finalize("final-report.json", false)
                .expect("finalize");
            let run = run_dir(&repo, RunArtifactFamily::Inbox, &run_id);
            let external = temp.path().join(format!("external-{kind}"));
            fs::write(&external, b"keep\n").expect("external");
            match kind {
                "symlink" => symlink(&external, run.join("unsafe-entry")).expect("symlink"),
                "hardlink" => fs::hard_link(&external, run.join("unsafe-entry")).expect("hardlink"),
                "fifo" => {
                    let path = CString::new(run.join("unsafe-entry").as_os_str().as_bytes())
                        .expect("FIFO path");
                    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
                }
                _ => unreachable!(),
            }
            let report = prune_runs(&repo, RunArtifactFamily::Inbox, 0, false)
                .expect("tampered run refusal");
            assert_eq!(report.deleted_count, 0);
            assert_eq!(report.refused_unfinalized_count, 1);
            assert_eq!(
                report.entries[0].action,
                RunArtifactPruneAction::RefuseUnfinalized
            );
            assert!(external.exists());
            assert!(run.exists(), "tampered run must never be deleted");
        }
    }

    #[cfg(unix)]
    #[test]
    fn prune_rejects_device_nodes_when_platform_allows_creating_one() {
        let (_temp, repo) = committed_repo();
        let run_id = RunId::new("unsafe-device").expect("run id");
        let mut writer =
            ArtifactRunWriter::reserve(&repo, RunArtifactFamily::Inbox, run_id.clone(), "inbox")
                .expect("writer");
        writer
            .write_json(
                "final-report.json",
                &serde_json::json!({"status":"done"}),
                ArtifactFileDisposition::PrivateEvidence,
            )
            .expect("report");
        writer
            .finalize("final-report.json", false)
            .expect("finalize");
        let device = run_dir(&repo, RunArtifactFamily::Inbox, &run_id).join("device");
        let path = CString::new(device.as_os_str().as_bytes()).expect("device path");
        let result =
            unsafe { libc::mknod(path.as_ptr(), libc::S_IFCHR | 0o600, libc::makedev(1, 3)) };
        if result != 0 {
            return;
        }
        let report =
            prune_runs(&repo, RunArtifactFamily::Inbox, 0, false).expect("device refusal report");
        assert_eq!(report.deleted_count, 0);
        assert_eq!(report.refused_unfinalized_count, 1);
        assert!(device.exists());
    }

    #[cfg(unix)]
    #[test]
    fn identity_bound_quarantine_refuses_aba_substitution() {
        let (_temp, repo) = committed_repo();
        let run_id = RunId::new("aba-run").expect("run id");
        ensure_run_dir_available(&repo, RunArtifactFamily::Inbox, &run_id).expect("reserve");
        let repository = discover_artifact_repository(&repo).expect("repository");
        let root = open_existing_run_root(&repository, RunArtifactFamily::Inbox).expect("root");
        let original = root
            .bind_existing_managed_direct_child_directory(run_id.as_str())
            .expect("binding");
        let original_identity = original.identity().clone();
        fs::rename(original.path(), root.path().join("moved-original")).expect("move original");
        fs::create_dir(root.path().join(run_id.as_str())).expect("substitute");
        let quarantine = open_or_create_quarantine(&root).expect("quarantine");
        let error = rename_bound_directory(
            &root,
            run_id.as_str().as_ref(),
            &original_identity,
            &quarantine,
            "quarantine-aba".as_ref(),
        )
        .expect_err("ABA substitution must fail");
        assert!(error.to_string().contains("identity changed"));
        assert!(root.path().join(run_id.as_str()).exists());
        assert!(root.path().join("moved-original").exists());
    }

    #[cfg(unix)]
    #[test]
    fn rebound_artifact_root_run_and_key_locks_fail_closed() {
        let (_temp, repo) = committed_repo();
        let run_id = RunId::new("rebound-run-lock").expect("run id");
        let mut writer =
            ArtifactRunWriter::reserve(&repo, RunArtifactFamily::Autopilot, run_id, "autopilot")
                .expect("writer");
        let run_lock_path = writer.run_lock.lock.path().to_path_buf();
        let old_run_lock = run_lock_path.with_file_name("artifact.lock.original");
        fs::rename(&run_lock_path, &old_run_lock).expect("move run lock");
        write_private(&run_lock_path, b"");
        let replacement_run_lock =
            BoundArtifactLock::acquire(&writer.run, RUN_LOCK_FILE).expect("replacement run lock");
        let run_error = writer
            .write_bytes(
                "final-report.json",
                b"{}\n",
                ArtifactFileDisposition::PrivateEvidence,
            )
            .expect_err("rebound run lock must fail");
        assert!(
            run_error.to_string().contains("lock path was rebound")
                || run_error
                    .to_string()
                    .contains("does not name its opened descriptor")
        );
        assert!(!writer.run.path().join("final-report.json").exists());
        drop(replacement_run_lock);

        let repository = discover_artifact_repository(&repo).expect("repository");
        let key_writer = open_artifact_auth_writer(&repository).expect("key writer");
        let key_lock_path = key_writer.lock_path().to_path_buf();
        let old_key_lock = key_lock_path.with_file_name("artifact-key.lock.original");
        fs::rename(&key_lock_path, &old_key_lock).expect("move key lock");
        write_private(&key_lock_path, b"");
        let replacement_key_lock = BoundStateLock::acquire(
            key_writer.authenticator().state_root(),
            authentication_key_lock_name(),
        )
        .expect("replacement key lock");
        let key_error = key_writer.verify().expect_err("rebound key lock must fail");
        assert!(
            key_error.to_string().contains("lock path was rebound")
                || key_error
                    .to_string()
                    .contains("does not name its opened descriptor")
        );
        drop(replacement_key_lock);

        let root =
            open_or_create_run_root(&repository, RunArtifactFamily::Consult).expect("consult root");
        let root_lock = BoundArtifactLock::acquire(&root, ROOT_LOCK_FILE).expect("root lock");
        let root_lock_path = root_lock.lock.path().to_path_buf();
        let old_root_lock = root_lock_path.with_file_name("runs.lock.original");
        fs::rename(&root_lock_path, &old_root_lock).expect("move root lock");
        write_private(&root_lock_path, b"");
        let replacement_root_lock =
            BoundArtifactLock::acquire(&root, ROOT_LOCK_FILE).expect("replacement root lock");
        let root_error = root_lock
            .verify(&root)
            .expect_err("rebound root lock must fail");
        assert!(
            root_error.to_string().contains("lock path was rebound")
                || root_error
                    .to_string()
                    .contains("does not name its opened descriptor")
        );
        drop(replacement_root_lock);
    }

    #[test]
    fn finalized_prune_waits_for_active_artifact_writer_lock() {
        use std::{sync::mpsc, thread, time::Duration};

        let (_temp, repo) = committed_repo();
        let run_id = RunId::new("active-lock-run").expect("run id");
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Autopilot,
            run_id.clone(),
            "autopilot",
        )
        .expect("writer");
        writer
            .write_json(
                "final-report.json",
                &serde_json::json!({"status":"done"}),
                ArtifactFileDisposition::PrivateEvidence,
            )
            .expect("report");
        writer
            .finalize("final-report.json", false)
            .expect("finalize");
        let repository = discover_artifact_repository(&repo).expect("repository");
        let root =
            open_existing_run_root(&repository, RunArtifactFamily::Autopilot).expect("run root");
        let run = root
            .bind_existing_direct_child_directory(run_id.as_str())
            .expect("run binding");
        let run = SafeRoot::open_existing(run.path()).expect("run");
        let held = BoundArtifactLock::acquire(&run, RUN_LOCK_FILE).expect("held run lock");

        let (sender, receiver) = mpsc::channel();
        let prune_repo = repo.clone();
        let worker = thread::spawn(move || {
            let result = prune_runs(&prune_repo, RunArtifactFamily::Autopilot, 0, false);
            sender.send(result).expect("send prune result");
        });
        thread::sleep(Duration::from_millis(100));
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        drop(held);
        let report = receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("prune completion")
            .expect("prune report");
        assert_eq!(report.deleted_count, 1);
        worker.join().expect("prune worker");
    }

    #[test]
    fn normal_prune_removes_run_and_leaves_empty_quarantine() {
        let (_temp, repo) = committed_repo();
        let run_id = RunId::new("prune-run").expect("run id");
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Autopilot,
            run_id.clone(),
            "autopilot",
        )
        .expect("writer");
        writer
            .write_json(
                "final-report.json",
                &serde_json::json!({"status":"done"}),
                ArtifactFileDisposition::PrivateEvidence,
            )
            .expect("report");
        writer
            .finalize("final-report.json", false)
            .expect("finalize");
        let report = prune_runs(&repo, RunArtifactFamily::Autopilot, 0, false).expect("prune");
        assert_eq!(report.deleted_count, 1);
        assert_eq!(report.refused_unfinalized_count, 0);
        assert!(!run_dir(&repo, RunArtifactFamily::Autopilot, &run_id).exists());
        let quarantine = run_root(&repo, RunArtifactFamily::Autopilot).join(QUARANTINE_DIRECTORY);
        assert_eq!(fs::read_dir(quarantine).expect("quarantine").count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn prune_refuses_run_lock_replacement_immediately_after_flock() {
        let (_temp, repo) = committed_repo();
        let run_id = RunId::new("prune-after-flock-rebind").expect("run id");
        finalize_private_test_run(&repo, RunArtifactFamily::Autopilot, &run_id, "autopilot");
        crate::safe_state::set_kernel_lock_after_flock_hook(|path| {
            if path.file_name() != Some(OsStr::new(RUN_LOCK_FILE)) {
                return false;
            }
            let original = path.with_file_name("artifact.lock.after-flock-original");
            fs::rename(path, &original).expect("move acquired writer lock");
            write_private(path, b"");
            true
        });

        let error = prune_runs(&repo, RunArtifactFamily::Autopilot, 0, false)
            .expect_err("post-flock lock replacement must abort prune");
        assert!(
            error
                .to_string()
                .contains("does not name its opened descriptor")
                || error.to_string().contains("was rebound"),
            "unexpected error: {error:#}"
        );
        assert!(run_dir(&repo, RunArtifactFamily::Autopilot, &run_id).exists());
    }

    #[cfg(target_os = "linux")]
    fn quarantined_scratch_path(run: &Path, expected: &FileIdentity) -> Option<PathBuf> {
        let entries = fs::read_dir(run).ok()?;
        for entry in entries {
            let entry = entry.ok()?;
            let metadata = fs::symlink_metadata(entry.path()).ok()?;
            if metadata.file_type().is_dir()
                && identity_for_path(entry.path()).ok().as_ref() == Some(expected)
            {
                return Some(entry.path());
            }
        }
        None
    }

    #[cfg(target_os = "linux")]
    struct ScratchMountGuard {
        run: PathBuf,
        scratch_identity: FileIdentity,
        mount_name: String,
        active: bool,
    }

    #[cfg(target_os = "linux")]
    impl ScratchMountGuard {
        fn unmount(&mut self) -> Result<()> {
            let scratch = quarantined_scratch_path(&self.run, &self.scratch_identity)
                .context("mounted scratch directory is no longer identity-bound in its run")?;
            let mount_point = scratch.join(&self.mount_name);
            let target = CString::new(mount_point.as_os_str().as_bytes())
                .context("mounted scratch path contains a NUL byte")?;
            if unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) } != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("failed to detach scratch boundary test mount");
            }
            self.active = false;
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for ScratchMountGuard {
        fn drop(&mut self) {
            if !self.active {
                return;
            }
            let Some(scratch) = quarantined_scratch_path(&self.run, &self.scratch_identity) else {
                return;
            };
            let mount_point = scratch.join(&self.mount_name);
            let Ok(target) = CString::new(mount_point.as_os_str().as_bytes()) else {
                return;
            };
            unsafe {
                libc::umount2(target.as_ptr(), libc::MNT_DETACH);
            }
        }
    }

    fn finalize_private_test_run(
        repo: &Path,
        family: RunArtifactFamily,
        run_id: &RunId,
        producer: &str,
    ) {
        let mut writer = ArtifactRunWriter::reserve(repo, family, run_id.clone(), producer)
            .expect("reserve test writer");
        writer
            .write_json(
                family.final_report_relative_path(),
                &serde_json::json!({"status":"done"}),
                ArtifactFileDisposition::PrivateEvidence,
            )
            .expect("write test report");
        writer
            .finalize(family.final_report_relative_path(), false)
            .expect("finalize test run");
    }

    fn finalize_test_run_with_log(
        repo: &Path,
        family: RunArtifactFamily,
        run_id: &RunId,
        transcript: &[u8],
    ) {
        let mut writer = ArtifactRunWriter::reserve(repo, family, run_id.clone(), family.label())
            .expect("reserve logged test writer");
        writer
            .write_bytes(
                "events.jsonl",
                transcript,
                ArtifactFileDisposition::PrivateEvidence,
            )
            .expect("write test transcript");
        writer
            .write_json(
                family.final_report_relative_path(),
                &serde_json::json!({"status":"done"}),
                ArtifactFileDisposition::PrivateEvidence,
            )
            .expect("write test report");
        writer
            .finalize(family.final_report_relative_path(), false)
            .expect("finalize logged test run");
    }

    fn committed_repo() -> (TempDir, PathBuf) {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = Repository::open(&repo_path).expect("open repo");
        let workdir = repo.workdir().expect("workdir");
        fs::write(workdir.join("README.md"), "# Test\n").expect("README");
        let mut index = repo.index().expect("index");
        index.add_path(Path::new("README.md")).expect("add");
        index.write().expect("index write");
        let tree_id = index.write_tree().expect("tree id");
        let tree = repo.find_tree(tree_id).expect("tree");
        let signature =
            Signature::now("maco test", "maco-test@example.invalid").expect("signature");
        let oid: Oid = repo
            .commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
            .expect("commit");
        assert!(!oid.is_zero());
        drop(tree);
        drop(repo);
        (temp, repo_path)
    }

    #[cfg(unix)]
    fn write_private(path: &Path, contents: &[u8]) {
        fs::write(path, contents).expect("private file");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private mode");
    }

    fn assert_active_unfinalized_summary(summary: &RunArtifactSummary, report_exists: bool) {
        assert_eq!(summary.final_report_exists, report_exists);
        assert_eq!(summary.final_report_status, "active");
        assert_eq!(summary.final_report_success, None);
        assert!(!summary.final_report_readable);
        assert!(!summary.final_report_corrupt);
        assert_eq!(summary.final_report_error, None);
        assert!(!summary.finalized);
        assert!(!summary.publishable);
        assert!(!summary.provenance_valid);
        assert!(!summary.artifact_digests_verified);
        assert_eq!(
            summary.finalization_error.as_deref(),
            Some("artifact run is active or unfinalized; finalization marker is missing")
        );
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    }
}
