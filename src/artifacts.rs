use crate::{
    orchestrator::RunId,
    safe_state::{
        identity_for_path, remove_direct_child_tree, stable_checksum, AtomicStateWriter,
        BoundedRegularReader, FileIdentity, KernelStateLock, ReservedDirectory, SafeRoot,
        TreeLinkPolicy,
    },
};
use anyhow::{bail, Context, Result};
use git2::Repository;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{hash_map::RandomState, BTreeMap, BTreeSet},
    fs,
    hash::{BuildHasher, Hash, Hasher},
    path::{Component, Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
use std::{io::Read, os::unix::fs::FileTypeExt};

#[cfg(unix)]
use std::{
    ffi::{CStr, CString, OsStr},
    fs::{File, OpenOptions},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
    },
};

const ARTIFACT_FORMAT_VERSION: u32 = 2;
const FINALIZATION_MARKER: &str = ".maco-artifact-final.json";
const RUN_LOCK_FILE: &str = ".artifact.lock";
const ROOT_LOCK_FILE: &str = ".runs.lock";
const QUARANTINE_DIRECTORY: &str = ".quarantine";
const ARTIFACT_MAC_KEY_FILE: &str = "artifact_finalization_hmac_v1.key";
const ARTIFACT_MAC_KEY_LOCK: &str = "artifact_finalization_hmac_v1.lock";
const ARTIFACT_MAC_KEY_BYTES: usize = 32;
const ARTIFACT_MAC_DOMAIN: &[u8] = b"MACO\0artifact-finalization\0hmac-sha256\0v2\0";
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
    pub family: RunArtifactFamily,
    pub run_root: PathBuf,
    pub ordering: &'static str,
    pub keep: usize,
    pub dry_run: bool,
    pub kept_count: usize,
    pub deleted_count: usize,
    pub refused_unfinalized_count: usize,
    pub delete_candidate_count: usize,
    pub entries: Vec<RunArtifactPruneEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunArtifactPruneEntry {
    pub run_id: String,
    pub run_dir: PathBuf,
    pub action: RunArtifactPruneAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
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
    total_bytes: u64,
    run_lock: BoundArtifactLock,
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

struct ArtifactMacKey {
    root: SafeRoot,
    bytes: [u8; ARTIFACT_MAC_KEY_BYTES],
    identity: FileIdentity,
    key_id: String,
}

struct ArtifactMacKeyWriter {
    key: ArtifactMacKey,
    lock: BoundArtifactLock,
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

impl ArtifactMacKey {
    fn open_existing(repository: &ArtifactRepository) -> Result<Self> {
        let state_path = repository.common_dir.join("maco").join("state");
        let root = SafeRoot::open_existing(&state_path).with_context(|| {
            format!(
                "artifact finalization key state is missing or unsafe: {}",
                state_path.display()
            )
        })?;
        ensure_private_directory(root.path())?;
        Self::load(&root)
    }

    fn load(root: &SafeRoot) -> Result<Self> {
        if !root.direct_child_exists(ARTIFACT_MAC_KEY_FILE)? {
            bail!("artifact finalization MAC key is missing");
        }
        let identity = ensure_private_regular_file(&root.path().join(ARTIFACT_MAC_KEY_FILE))?;
        let contents = BoundedRegularReader::read_direct(
            root,
            ARTIFACT_MAC_KEY_FILE,
            ARTIFACT_MAC_KEY_BYTES as u64,
        )?;
        let bytes: [u8; ARTIFACT_MAC_KEY_BYTES] =
            contents.try_into().map_err(|contents: Vec<u8>| {
                anyhow::anyhow!(
                    "artifact finalization MAC key has invalid length {} (expected {})",
                    contents.len(),
                    ARTIFACT_MAC_KEY_BYTES
                )
            })?;
        let key = Self {
            root: root.clone(),
            key_id: sha256_hex(&bytes),
            bytes,
            identity,
        };
        key.verify()?;
        Ok(key)
    }

    fn verify(&self) -> Result<()> {
        self.root.verify()?;
        let result = (|| -> Result<()> {
            let observed =
                ensure_private_regular_file(&self.root.path().join(ARTIFACT_MAC_KEY_FILE))?;
            if observed != self.identity {
                bail!("artifact finalization MAC key inode was replaced");
            }
            let contents = BoundedRegularReader::read_direct(
                &self.root,
                ARTIFACT_MAC_KEY_FILE,
                ARTIFACT_MAC_KEY_BYTES as u64,
            )?;
            if !constant_time_eq(&contents, &self.bytes) {
                bail!("artifact finalization MAC key contents changed");
            }
            Ok(())
        })();
        finish_with_artifact_lock_verification(result, self.root.verify())
    }
}

impl ArtifactMacKeyWriter {
    fn open(repository: &ArtifactRepository) -> Result<Self> {
        let state_path = repository.common_dir.join("maco").join("state");
        let existed = fs::symlink_metadata(&state_path).is_ok();
        let root = match SafeRoot::open_or_create(&state_path) {
            Ok(root) => root,
            Err(error) if existed => bail!(
                "existing artifact-key state root is not owner-private; refusing automatic permission changes: {error:#}"
            ),
            Err(error) => return Err(error).context("failed to create artifact-key state root"),
        };
        ensure_private_directory(root.path())?;
        let lock = BoundArtifactLock::acquire(&root, ARTIFACT_MAC_KEY_LOCK)?;
        lock.verify(&root)?;
        let result = (|| -> Result<ArtifactMacKey> {
            if !root.direct_child_exists(ARTIFACT_MAC_KEY_FILE)? {
                if scan_registered_finalization_markers(repository, None)? > 0 {
                    bail!(
                        "artifact finalization MAC key is missing while an existing final marker is present; refusing to generate a replacement key"
                    );
                }
                let mut bytes = [0u8; ARTIFACT_MAC_KEY_BYTES];
                fill_os_random(&mut bytes)?;
                AtomicStateWriter::scavenge_direct_temps(&root, ARTIFACT_MAC_KEY_FILE)?;
                AtomicStateWriter::write_direct_fenced(
                    &root,
                    ARTIFACT_MAC_KEY_FILE,
                    &bytes,
                    || lock.verify(&root),
                )?;
                lock.verify(&root)?;
            }
            let key = ArtifactMacKey::load(&root)?;
            key.verify()?;
            scan_registered_finalization_markers(repository, Some(&key))?;
            key.verify()?;
            Ok(key)
        })();
        let key = finish_with_artifact_lock_verification(result, lock.verify(&root))?;
        let writer = Self { key, lock };
        writer.verify()?;
        Ok(writer)
    }

    fn verify(&self) -> Result<()> {
        self.lock.verify(&self.key.root)?;
        let result = self.key.verify();
        finish_with_artifact_lock_verification(result, self.lock.verify(&self.key.root))
    }
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
                total_bytes: 0,
                run_lock,
            })
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
        let mac_key = ArtifactMacKeyWriter::open(&self.repository)?;
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
                mac_key_id: mac_key.key.key_id.clone(),
                mac_key_identity: mac_key.key.identity.clone(),
                final_report,
                files,
                publish_requested,
                publishable,
                hmac_sha256: String::new(),
            };
            verify_writer_evidence(&finalization.writer_evidence, &self.run_root, &self.run)?;
            finalization.checksum = finalization_checksum(&finalization)?;
            finalization.hmac_sha256 = finalization_hmac(&mac_key.key.bytes, &finalization)?;
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
        let mac_key = ArtifactMacKey::open_existing(&repository)?;
        mac_key.verify()?;
        if finalization.mac_key_id != mac_key.key_id
            || finalization.mac_key_identity != mac_key.identity
        {
            bail!("artifact finalization MAC key binding does not match repository state");
        }
        let expected_mac = finalization_hmac(&mac_key.bytes, &finalization)?;
        if !constant_time_eq(expected_mac.as_bytes(), finalization.hmac_sha256.as_bytes()) {
            bail!("artifact finalization HMAC verification failed");
        }
        verify_writer_evidence(&finalization.writer_evidence, &run_root, &run)?;
        let audited = audit_artifact_tree(&run, true)?;
        verify_manifest_paths_with_marker(&finalization.files, &audited)?;
        verify_manifest_contents(&run, finalization.files.iter())?;
        run.verify()?;
        run_root.verify()?;
        mac_key.verify()?;
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
    let repository = discover_artifact_repository(repo.as_ref())?;
    let Some(root) = open_optional_run_root(&repository, family)? else {
        return Ok(empty_prune_report(family, keep, dry_run));
    };
    let root_lock = BoundArtifactLock::acquire(&root, ROOT_LOCK_FILE)?;
    root_lock.verify(&root)?;
    let result = (|| -> Result<RunArtifactPruneReport> {
        let runs = sorted_run_summaries(&repository, &root, family)?;
        let mut quarantine = None;
        let mut entries = Vec::new();
        let mut kept_count = 0usize;
        let mut deleted_count = 0usize;
        let mut refused_unfinalized_count = 0usize;
        let mut delete_candidate_count = 0usize;

        for (index, run) in runs.into_iter().enumerate() {
            if index < keep {
                kept_count = kept_count.saturating_add(1);
                entries.push(RunArtifactPruneEntry {
                    run_id: run.run_id,
                    run_dir: run.run_dir,
                    action: RunArtifactPruneAction::Keep,
                    reason: None,
                });
                continue;
            }
            delete_candidate_count = delete_candidate_count.saturating_add(1);
            let run_id = RunId::new(&run.run_id)?;
            if let Err(error) = ArtifactRunReader::open(&repository.worktree, family, &run_id) {
                kept_count = kept_count.saturating_add(1);
                refused_unfinalized_count = refused_unfinalized_count.saturating_add(1);
                entries.push(RunArtifactPruneEntry {
                    run_id: run.run_id,
                    run_dir: run.run_dir,
                    action: RunArtifactPruneAction::RefuseUnfinalized,
                    reason: Some(format!(
                        "refusing to prune artifact run without a valid finalization MAC: {error:#}"
                    )),
                });
                continue;
            }
            if dry_run {
                entries.push(RunArtifactPruneEntry {
                    run_id: run.run_id,
                    run_dir: run.run_dir,
                    action: RunArtifactPruneAction::WouldDelete,
                    reason: None,
                });
                continue;
            }

            root_lock.verify(&root)?;
            let rebound = root.bind_existing_managed_direct_child_directory(&run.run_id)?;
            if rebound.identity() != &run.identity {
                bail!(
                    "artifact run identity changed before quarantine: {}",
                    run.run_id
                );
            }
            let rebound_root = SafeRoot::open_existing(rebound.path())?;
            let run_lock = BoundArtifactLock::acquire(&rebound_root, RUN_LOCK_FILE)?;
            run_lock.verify(&rebound_root)?;
            let validation = ArtifactRunReader::open(&repository.worktree, family, &run_id);
            let validation =
                finish_with_artifact_lock_verification(validation, run_lock.verify(&rebound_root));
            if let Err(error) = validation {
                kept_count = kept_count.saturating_add(1);
                refused_unfinalized_count = refused_unfinalized_count.saturating_add(1);
                entries.push(RunArtifactPruneEntry {
                    run_id: run.run_id,
                    run_dir: run.run_dir,
                    action: RunArtifactPruneAction::RefuseUnfinalized,
                    reason: Some(format!(
                        "refusing to prune artifact run that lost valid finalization while waiting for its writer lock: {error:#}"
                    )),
                });
                continue;
            }
            root_lock.verify(&root)?;
            if quarantine.is_none() {
                let created = open_or_create_quarantine(&root)?;
                ensure_quarantine_empty(&created)?;
                quarantine = Some(created);
            }
            let quarantine = quarantine
                .as_ref()
                .context("artifact quarantine unavailable")?;
            let quarantine_name = quarantine.random_direct_child_name(&run.run_id)?;
            rename_bound_directory(
                &root,
                run.run_id.as_ref(),
                &run.identity,
                quarantine,
                &quarantine_name,
            )?;
            let quarantined_run =
                SafeRoot::open_existing(quarantine.path().join(&quarantine_name))?;
            run_lock.verify(&quarantined_run)?;
            // The acquired run-lock inode is deliberately removed with the now
            // quarantined run. Its pathname identity is therefore revalidated
            // after the rename and immediately before the bounded tree deletion;
            // the root lock continues to protect the family namespace afterward.
            remove_direct_child_tree(
                quarantine,
                &quarantine_name,
                Some(&run.identity),
                TreeLinkPolicy::RejectLinksAndSpecialFiles,
            )
            .with_context(|| {
                format!(
                    "artifact run '{}' was quarantined but could not be safely deleted; inspect {}",
                    run.run_id,
                    quarantine.path().join(&quarantine_name).display()
                )
            })?;
            root_lock.verify(&root)?;
            deleted_count = deleted_count.saturating_add(1);
            entries.push(RunArtifactPruneEntry {
                run_id: run.run_id,
                run_dir: run.run_dir,
                action: RunArtifactPruneAction::Delete,
                reason: None,
            });
        }

        root_lock.verify(&root)?;
        Ok(RunArtifactPruneReport {
            family,
            run_root: family.run_root(),
            ordering: artifact_ordering(),
            keep,
            dry_run,
            kept_count,
            deleted_count,
            refused_unfinalized_count,
            delete_candidate_count,
            entries,
        })
    })();
    finish_with_artifact_lock_verification(result, root_lock.verify(&root))
}

pub fn artifact_ordering() -> &'static str {
    "newest first by final-report modification time, then run directory modification time, ties by descending run id"
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
    key: Option<&ArtifactMacKey>,
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
    key: Option<&ArtifactMacKey>,
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
    key: Option<&ArtifactMacKey>,
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
    key: &ArtifactMacKey,
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
    if finalization.mac_key_id != key.key_id || finalization.mac_key_identity != key.identity {
        bail!("artifact finalization MAC key does not match existing marker binding");
    }
    let expected_mac = finalization_hmac(&key.bytes, &finalization)?;
    if !constant_time_eq(expected_mac.as_bytes(), finalization.hmac_sha256.as_bytes()) {
        bail!("existing artifact finalization marker HMAC verification failed");
    }
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
        let name = name.context("registered linked worktree name is not valid UTF-8")?;
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

#[cfg(any(target_os = "linux", target_os = "android"))]
fn fill_os_random(bytes: &mut [u8]) -> Result<()> {
    let mut filled = 0usize;
    while filled < bytes.len() {
        let result = unsafe {
            libc::getrandom(
                bytes[filled..].as_mut_ptr().cast(),
                bytes.len().saturating_sub(filled),
                0,
            )
        };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error).context("OS getrandom failed for artifact MAC key");
        }
        let read = usize::try_from(result).context("OS random byte count overflow")?;
        if read == 0 {
            bail!("OS getrandom returned zero bytes for artifact MAC key");
        }
        filled = filled
            .checked_add(read)
            .context("OS random fill count overflow")?;
    }
    Ok(())
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn fill_os_random(bytes: &mut [u8]) -> Result<()> {
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/dev/urandom")
        .context("failed to open OS random source")?;
    if !source.metadata()?.file_type().is_char_device() {
        bail!("OS random source is not a character device");
    }
    source
        .read_exact(bytes)
        .context("failed to read artifact MAC key from OS random source")
}

#[cfg(not(unix))]
fn fill_os_random(_bytes: &mut [u8]) -> Result<()> {
    bail!("artifact MAC key generation requires a supported OS random source")
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
    let final_report_path = absolute_run_dir.join(&final_relative);
    let modified = fs::symlink_metadata(&final_report_path)
        .and_then(|metadata| metadata.modified())
        .or_else(|_| {
            fs::symlink_metadata(&absolute_run_dir).and_then(|metadata| metadata.modified())
        })
        .unwrap_or(UNIX_EPOCH);
    let public_run_dir = family.run_root().join(&run_id);
    let public_final_report_path = public_run_dir.join(&final_relative);
    let run_id_value = RunId::new(&run_id)?;
    let marker_exists = fs::symlink_metadata(absolute_run_dir.join(FINALIZATION_MARKER)).is_ok();
    let strict = if marker_exists {
        ArtifactRunReader::open(&repository.worktree, family, &run_id_value)
    } else {
        Err(anyhow::anyhow!(
            "artifact finalization marker {} is missing",
            FINALIZATION_MARKER
        ))
    };

    match strict {
        Ok(reader) => {
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
        Err(finalization_error) => {
            let (exists, status, success, readable, corrupt, error) =
                read_unfinalized_report(&absolute_run_dir, &final_relative);
            Ok(RunArtifactSummary {
                run_id,
                run_dir: public_run_dir,
                final_report_path: public_final_report_path,
                final_report_exists: exists,
                final_report_status: status,
                final_report_success: success,
                final_report_readable: readable,
                final_report_corrupt: corrupt,
                final_report_error: error,
                finalized: false,
                publishable: false,
                provenance_valid: false,
                artifact_digests_verified: false,
                finalization_error: Some(finalization_error.to_string()),
                modified,
                identity,
            })
        }
    }
}

fn read_unfinalized_report(
    run_dir: &Path,
    relative: &Path,
) -> (bool, String, Option<bool>, bool, bool, Option<String>) {
    let path = run_dir.join(relative);
    if fs::symlink_metadata(&path).is_err() {
        return (false, "missing".to_string(), None, false, false, None);
    }
    match BoundedRegularReader::read_relative(run_dir, relative, MAX_ARTIFACT_FILE_BYTES) {
        Ok(contents) => {
            let (status, success, readable, corrupt, error) = parse_report(&contents);
            (true, status, success, readable, corrupt, error)
        }
        Err(error) => (
            true,
            "read_error".to_string(),
            None,
            false,
            false,
            Some(error.to_string()),
        ),
    }
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
    family: RunArtifactFamily,
    keep: usize,
    dry_run: bool,
) -> RunArtifactPruneReport {
    RunArtifactPruneReport {
        family,
        run_root: family.run_root(),
        ordering: artifact_ordering(),
        keep,
        dry_run,
        kept_count: 0,
        deleted_count: 0,
        refused_unfinalized_count: 0,
        delete_candidate_count: 0,
        entries: Vec::new(),
    }
}

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
        device: stat.st_dev,
        file: stat.st_ino,
    }
}

fn sha256_hex(input: &[u8]) -> String {
    hex_encode(&sha256_bytes(input))
}

fn sha256_bytes(input: &[u8]) -> [u8; 32] {
    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let bit_len = u64::try_from(input.len())
        .unwrap_or(u64::MAX)
        .wrapping_mul(8);
    let mut message = input.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());
    let mut hash = INITIAL;
    for chunk in message.chunks_exact(64) {
        let mut words = [0u32; 64];
        for (index, bytes) in chunk.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = hash;
        for index in 0..64 {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(sum1)
                .wrapping_add(choice)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = sum0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        hash[0] = hash[0].wrapping_add(a);
        hash[1] = hash[1].wrapping_add(b);
        hash[2] = hash[2].wrapping_add(c);
        hash[3] = hash[3].wrapping_add(d);
        hash[4] = hash[4].wrapping_add(e);
        hash[5] = hash[5].wrapping_add(f);
        hash[6] = hash[6].wrapping_add(g);
        hash[7] = hash[7].wrapping_add(h);
    }
    let mut output = [0u8; 32];
    for (index, word) in hash.iter().enumerate() {
        let offset = index.saturating_mul(4);
        output[offset..offset + 4].copy_from_slice(&word.to_be_bytes());
    }
    output
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut padded_key = [0u8; 64];
    if key.len() > padded_key.len() {
        padded_key[..32].copy_from_slice(&sha256_bytes(key));
    } else {
        padded_key[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; 64];
    let mut outer_pad = [0x5cu8; 64];
    for index in 0..64 {
        inner_pad[index] ^= padded_key[index];
        outer_pad[index] ^= padded_key[index];
    }
    let mut inner = Vec::with_capacity(inner_pad.len().saturating_add(message.len()));
    inner.extend_from_slice(&inner_pad);
    inner.extend_from_slice(message);
    let inner_digest = sha256_bytes(&inner);
    let mut outer = Vec::with_capacity(outer_pad.len().saturating_add(inner_digest.len()));
    outer.extend_from_slice(&outer_pad);
    outer.extend_from_slice(&inner_digest);
    sha256_bytes(&outer)
}

fn finalization_hmac(
    key: &[u8; ARTIFACT_MAC_KEY_BYTES],
    finalization: &ArtifactFinalization,
) -> Result<String> {
    let canonical = serde_json::to_vec(&(
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
    .context("failed to encode canonical artifact HMAC payload")?;
    let mut domain_separated =
        Vec::with_capacity(ARTIFACT_MAC_DOMAIN.len().saturating_add(canonical.len()));
    domain_separated.extend_from_slice(ARTIFACT_MAC_DOMAIN);
    domain_separated.extend_from_slice(&canonical);
    Ok(hex_encode(&hmac_sha256(key, &domain_separated)))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
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

    #[test]
    fn hmac_sha256_matches_rfc_4231_case_one() {
        let key = [0x0bu8; 20];
        assert_eq!(
            hex_encode(&hmac_sha256(&key, b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
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

        let run = run_dir(&repo, RunArtifactFamily::Autopilot, &run_id);
        assert_eq!(mode(&run), 0o700);
        assert_eq!(mode(&run.join("final-report.json")), 0o600);
        assert_eq!(mode(&run.join(FINALIZATION_MARKER)), 0o600);
        let repository = discover_artifact_repository(&repo).expect("repository");
        let key_path = repository
            .common_dir
            .join("maco/state")
            .join(ARTIFACT_MAC_KEY_FILE);
        let key_lock_path = repository
            .common_dir
            .join("maco/state")
            .join(ARTIFACT_MAC_KEY_LOCK);
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
        let rekey_error = ArtifactMacKeyWriter::open(&repository)
            .err()
            .expect("rekey refusal");
        assert!(rekey_error
            .to_string()
            .contains("existing final marker is present"));
        fs::rename(&moved_key, &key_path).expect("restore MAC key");
        ArtifactRunReader::open(&repo, RunArtifactFamily::Autopilot, &run_id)
            .expect("restored key");

        fs::write(&key_path, [0xa5; ARTIFACT_MAC_KEY_BYTES]).expect("corrupt bound key");
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
            .join(ARTIFACT_MAC_KEY_FILE);
        let original_key = key_path.with_file_name("artifact-key.pre-replacement");
        fs::rename(&key_path, &original_key).expect("move original key");
        write_private(&key_path, &[0xa5; ARTIFACT_MAC_KEY_BYTES]);

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
            .create(WorktreeCreateOptions {
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
            .join(ARTIFACT_MAC_KEY_FILE);
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
            .create(WorktreeCreateOptions {
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
            .join(ARTIFACT_MAC_KEY_FILE);

        let error = ArtifactMacKeyWriter::open(&repository)
            .err()
            .expect("stale worktree registration must fail closed");
        assert!(error.to_string().contains("stale or invalid"));
        assert!(!key_path.exists());
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
            .join(ARTIFACT_MAC_KEY_FILE);

        let error = ArtifactMacKeyWriter::open(&repository)
            .err()
            .expect("marker scan budget must fail closed");
        assert!(error.to_string().contains("global entry budget"));
        assert!(!key_path.exists());
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
        assert_eq!(summary.final_report_status, "succeeded");
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
    fn oversized_report_and_run_root_entry_budget_fail_boundedly() {
        let (_temp, repo) = committed_repo();
        let run_id = RunId::new("large-run").expect("run id");
        ensure_run_dir_available(&repo, RunArtifactFamily::Consult, &run_id).expect("reserve");
        fs::write(
            final_report_path(&repo, RunArtifactFamily::Consult, &run_id),
            vec![b'x'; usize::try_from(MAX_ARTIFACT_FILE_BYTES).expect("limit") + 1],
        )
        .expect("oversized report");
        let summary = latest_run(&repo, RunArtifactFamily::Consult)
            .expect("latest")
            .run
            .expect("run");
        assert_eq!(summary.final_report_status, "read_error");
        assert!(!summary.final_report_readable);

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
        let key_writer = ArtifactMacKeyWriter::open(&repository).expect("key writer");
        let key_lock_path = key_writer.lock.lock.path().to_path_buf();
        let old_key_lock = key_lock_path.with_file_name("artifact-key.lock.original");
        fs::rename(&key_lock_path, &old_key_lock).expect("move key lock");
        write_private(&key_lock_path, b"");
        let replacement_key_lock =
            BoundArtifactLock::acquire(&key_writer.key.root, ARTIFACT_MAC_KEY_LOCK)
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

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    }
}
