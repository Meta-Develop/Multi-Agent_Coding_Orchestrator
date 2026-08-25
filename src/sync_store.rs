use crate::sync::{
    normalize_repo_relative_path, ClaimToken, PathClaim, SyncCoordinator, SyncSnapshot,
};
use crate::{
    artifacts::{
        repository_authenticator_key_only,
        state_auth::{sha256_hex, AuthenticationDomain, RepositoryAuthBinding},
    },
    authenticated_snapshot::{AuthenticatedSnapshot, AuthenticatedSnapshotStore, SnapshotSpec},
    live_claim::{
        claim_process_liveness, current_claim_process_identity, ClaimProcessIdentity,
        ClaimProcessLiveness,
    },
    megafile::{MegafileAssessment, MegafileStore, MegafileThresholds},
    orchestrator::RunId,
    safe_state::{stable_checksum, ExistingExclusiveLock, FileIdentity, KernelStateLock, SafeRoot},
    state_journal::JournalSpec,
    state_migration::{
        decode_checksumless_legacy_claims_state, finalize_legacy_retirement,
        prepare_legacy_retirement, LegacyAdoption, LEGACY_RETIREMENT_DOMAIN,
    },
};
use anyhow::{bail, Context, Result};
use git2::Repository;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

#[cfg(all(test, unix))]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[cfg(test)]
use crate::safe_state::{identity_for_path, AtomicStateWriter, BoundedRegularReader};

const STATE_VERSION: u32 = 2;
const MAX_SYNC_STATE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_SYNC_CLAIMS: usize = 4_096;
const MAX_SYNC_PATHS: usize = 16_384;
const MAX_AGENT_ID_BYTES: usize = 128;
const MAX_RUN_ID_BYTES: usize = 128;
const MAX_PROCESS_START_TIME_BYTES: usize = 512;
const MAX_STATE_PATH_BYTES: usize = 4_096;
const MAX_STATE_PATH_COMPONENTS: usize = 256;
const MAX_CLAIM_ID_BYTES: usize = 128;
const MAX_CLAIM_TIMING_SECONDS: u64 = 365 * 24 * 60 * 60;
const MAX_SUPERSESSION_LINEAGE_DEPTH: usize = 64;
const MAX_SUPERSESSION_RECORDS: usize = 1_024;

pub const DEFAULT_CLAIM_HEARTBEAT_INTERVAL_SECONDS: u64 = 12 * 60 * 60;
pub const DEFAULT_CLAIM_STALE_AFTER_SECONDS: u64 = 24 * 60 * 60;

#[derive(Debug, Clone)]
pub struct SyncStore {
    repo_path: PathBuf,
    state: RepositoryStateRoot,
}

/// Authenticated claims observed while holding the durable claims writer lock.
///
/// Keeping this value alive prevents cooperating claim writers from changing
/// the snapshot until the caller completes its claim-sensitive operation.
/// Callers can inspect the already authenticated claims and revalidate the
/// stable lock binding, but cannot construct or mutate the claims schema.
#[derive(Debug)]
pub(crate) struct LockedClaimsSnapshot {
    state: RepositoryStateRoot,
    lock: RepositoryStateLock,
    claims: Vec<PathClaim>,
}

impl LockedClaimsSnapshot {
    pub(crate) fn claims(&self) -> &[PathClaim] {
        &self.claims
    }

    pub(crate) fn verify(&self) -> Result<()> {
        self.state.verify(&self.lock)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExistingClaimBindingRequest {
    pub agent_id: String,
    pub token: ClaimToken,
    pub paths: Vec<PathBuf>,
}

#[derive(Debug, Error)]
pub(crate) enum ExistingClaimRevalidationError {
    #[error("existing authenticated claims state is unavailable or invalid")]
    StateUnavailable {
        #[source]
        source: anyhow::Error,
    },
    #[error("existing authenticated claims lock is busy")]
    LockBusy,
    #[error("existing authenticated claims lock is missing")]
    LockMissing,
    #[error("claim revalidation request count exceeds the {limit} entry bound")]
    RequestLimit { limit: usize },
    #[error("claim revalidation request for agent '{agent_id}' has noncanonical paths")]
    NoncanonicalPaths { agent_id: String },
    #[error(
        "claim token {token} for agent '{agent_id}' was superseded by token {successor_token}"
    )]
    Superseded {
        agent_id: String,
        token: u64,
        successor_token: u64,
    },
    #[error("claim token {token} for agent '{agent_id}' is no longer active")]
    Released { agent_id: String, token: u64 },
    #[error(
        "claim token {token} for agent '{agent_id}' was replaced by token {actual_token} owned by '{actual_owner}'"
    )]
    Replaced {
        agent_id: String,
        token: u64,
        actual_token: u64,
        actual_owner: String,
    },
    #[error("claim token {token} owner mismatch: expected '{agent_id}', found '{actual_owner}'")]
    OwnerMismatch {
        agent_id: String,
        token: u64,
        actual_owner: String,
    },
    #[error("claim token {token} path binding mismatch for agent '{agent_id}'")]
    PathsMismatch { agent_id: String, token: u64 },
    #[error("claim token {token} for agent '{agent_id}' is not live: {state:?}")]
    NotLive {
        agent_id: String,
        token: u64,
        state: ClaimLivenessState,
    },
    #[error("authenticated claims state changed while its existing-only guard was held")]
    StateChanged,
}

/// Retains the already-existing claims writer lock for one bounded batch of
/// mutation authorities. Heartbeat, sweep, takeover, and release stay
/// serialized while the guard is alive. This is the claims lock only; it must
/// not acquire `managed_worktrees.lock`.
#[must_use = "the claims guard must be retained for the protected operation"]
#[derive(Debug)]
pub(crate) struct ExistingClaimsGuard {
    repo_path: PathBuf,
    state: RepositoryStateRoot,
    lock: RepositoryStateLock,
    authenticated: AuthenticatedClaimsState,
    requests: Vec<ExistingClaimBindingRequest>,
    // Rechecks use the acquisition instant that already passed liveness.
    // Re-aging while this guard blocks heartbeats would manufacture staleness.
    validated_at_unix_seconds: u64,
}

impl ExistingClaimsGuard {
    pub(crate) fn verify(&self) -> std::result::Result<(), ExistingClaimRevalidationError> {
        let authenticated =
            read_existing_authenticated_claims(&self.repo_path, &self.state, &self.lock)
                .map_err(|source| ExistingClaimRevalidationError::StateUnavailable { source })?;
        if authenticated != self.authenticated {
            return Err(ExistingClaimRevalidationError::StateChanged);
        }
        verify_existing_claim_requests(
            &authenticated,
            &self.requests,
            self.validated_at_unix_seconds,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MegafileClaimWarning {
    pub version: u32,
    pub path: PathBuf,
    pub assessment: MegafileAssessment,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimTelemetryOutcome {
    pub claim: PathClaim,
    pub warnings: Vec<MegafileClaimWarning>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimTiming {
    pub heartbeat_interval_seconds: u64,
    pub stale_after_seconds: u64,
}

impl Default for ClaimTiming {
    fn default() -> Self {
        Self {
            heartbeat_interval_seconds: DEFAULT_CLAIM_HEARTBEAT_INTERVAL_SECONDS,
            stale_after_seconds: DEFAULT_CLAIM_STALE_AFTER_SECONDS,
        }
    }
}

impl ClaimTiming {
    pub fn new(heartbeat_interval_seconds: u64, stale_after_seconds: u64) -> Result<Self> {
        let timing = Self {
            heartbeat_interval_seconds,
            stale_after_seconds,
        };
        timing.validate()?;
        Ok(timing)
    }

    fn validate(self) -> Result<()> {
        if self.heartbeat_interval_seconds == 0
            || self.heartbeat_interval_seconds > MAX_CLAIM_TIMING_SECONDS
        {
            bail!(
                "claim heartbeat interval must be between 1 and {MAX_CLAIM_TIMING_SECONDS} seconds"
            );
        }
        if self.stale_after_seconds == 0 || self.stale_after_seconds > MAX_CLAIM_TIMING_SECONDS {
            bail!("claim stale threshold must be between 1 and {MAX_CLAIM_TIMING_SECONDS} seconds");
        }
        if self.heartbeat_interval_seconds >= self.stale_after_seconds {
            bail!("claim heartbeat interval must be shorter than its stale threshold");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimLivenessState {
    Fresh,
    HeartbeatDue,
    Stale,
    TakeoverEligible,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimLivenessReport {
    #[serde(flatten)]
    pub claim: PathClaim,
    pub claim_id: String,
    pub state: ClaimLivenessState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ambiguity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_unix_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heartbeat_unix_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heartbeat_interval_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale_after_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub takeover_eligible_since_unix_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimSupersession {
    pub prior_token: ClaimToken,
    pub prior_claim_id: String,
    pub prior_agent_id: String,
    pub successor_token: ClaimToken,
    pub successor_claim_id: String,
    pub successor_agent_id: String,
    pub path_count: usize,
    pub paths_checksum: String,
    pub superseded_at_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimSweepReport {
    pub now_unix_seconds: u64,
    pub newly_takeover_eligible: Vec<String>,
    pub claims: Vec<ClaimLivenessReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimTakeoverOutcome {
    pub superseded_claim: PathClaim,
    pub claim: PathClaim,
    pub liveness: ClaimLivenessReport,
    pub lineage: ClaimSupersession,
    pub warnings: Vec<MegafileClaimWarning>,
}

pub(crate) enum ClaimsSnapshotSpec {}

impl JournalSpec for ClaimsSnapshotSpec {
    const FORMAT_VERSION: u32 = 1;
    const NAMESPACE: &'static str = "authenticated_claims";
    const ROOT_NAME: &'static str = "authenticated-claims-state-v1";
    const ROOT_LOCK_NAME: &'static str = ".authenticated-claims.lock";
    const INSTANCE_LOCK_NAME: &'static str = ".claims-snapshot.lock";
    const HEAD_FILE_NAME: &'static str = ".head.json";
    const RECORD_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0authenticated-claims-record\0v1\0");
    const HEAD_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0authenticated-claims-head\0v1\0");
    const MAX_RECORDS: usize = 4_096;
    const MAX_RECORD_BYTES: u64 = MAX_SYNC_STATE_BYTES;
    const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
    const MAX_PHASE_BYTES: usize = 32;
    const MAX_SUBJECT_BYTES: usize = 64;
    const MAX_INSTANCE_ID_BYTES: usize = 128;
}

impl SnapshotSpec for ClaimsSnapshotSpec {
    const SNAPSHOT_FORMAT_VERSION: u32 = 1;
    const LOCATOR_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0authenticated-claims-locator\0v1\0");
}

const CLAIMS_LOGICAL_ID: &str = "claims";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedClaimsState {
    version: u32,
    snapshot_revision: u64,
    repository: RepositoryAuthBinding,
    next_token: u64,
    claims: Vec<PathClaim>,
    #[serde(default)]
    run_owners: Vec<AuthenticatedClaimRunOwner>,
    #[serde(default)]
    liveness: Vec<AuthenticatedClaimLiveness>,
    #[serde(default)]
    supersessions: Vec<AuthenticatedClaimSupersession>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedClaimRunOwner {
    token: ClaimToken,
    run_id: String,
    process: ClaimProcessIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedClaimLiveness {
    token: ClaimToken,
    claim_id: String,
    created_unix_seconds: u64,
    heartbeat_unix_seconds: u64,
    heartbeat_interval_seconds: u64,
    stale_after_seconds: u64,
    takeover_eligible_since_unix_seconds: Option<u64>,
    supersedes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedClaimSupersession {
    prior_token: ClaimToken,
    prior_claim_id: String,
    prior_agent_id: String,
    successor_token: ClaimToken,
    successor_claim_id: String,
    successor_agent_id: String,
    path_count: usize,
    paths_checksum: String,
    superseded_at_unix_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimOwnerRunState {
    Active,
    Interrupted,
    Unknown,
    Unattributed,
}

impl ClaimOwnerRunState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Interrupted => "interrupted",
            Self::Unknown => "unknown",
            Self::Unattributed => "unattributed",
        }
    }

    fn is_unattributed(&self) -> bool {
        *self == Self::Unattributed
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClaimStatusReport {
    #[serde(flatten)]
    pub claim: PathClaim,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_process_id: Option<u32>,
    #[serde(skip_serializing_if = "ClaimOwnerRunState::is_unattributed")]
    pub owner_run_state: ClaimOwnerRunState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OwnerReport {
    pub path: PathBuf,
    pub owner: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RepositoryStateBinding {
    common_dir_path_checksum: String,
    common_dir_identity: FileIdentity,
}

#[derive(Debug, Clone)]
pub(crate) struct RepositoryStateRoot {
    root: SafeRoot,
    state_path: PathBuf,
    state_file: &'static str,
    lock_file: &'static str,
    binding: RepositoryStateBinding,
}

#[derive(Debug)]
pub(crate) struct RepositoryStateLock {
    _lock: KernelStateLock,
    root_identity: FileIdentity,
    state_file: &'static str,
    lock_identity: FileIdentity,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedSyncState {
    version: u32,
    checksum: String,
    repository: RepositoryStateBinding,
    next_token: u64,
    claims: Vec<PathClaim>,
}

impl RepositoryStateRoot {
    pub(crate) fn open(
        repo: &Repository,
        state_file: &'static str,
        lock_file: &'static str,
    ) -> Result<Self> {
        let common_root = SafeRoot::open_existing(repo.commondir()).with_context(|| {
            format!(
                "Git common directory is not a safe current-user-owned directory: {}",
                repo.commondir().display()
            )
        })?;
        let binding = RepositoryStateBinding {
            common_dir_path_checksum: stable_checksum(&filesystem_path_bytes(common_root.path())),
            common_dir_identity: common_root.identity().clone(),
        };
        let state_path = common_root.path().join("maco").join("state");
        let existed = fs::symlink_metadata(&state_path).is_ok();
        let root = match SafeRoot::open_or_create(&state_path) {
            Ok(root) => root,
            Err(error) if existed => {
                bail!(
                    "existing MACO state directory is not owner-private: {}. Refusing to change legacy permissions automatically. Independently verify its ownership and contents, then migrate the directory to mode 0700 and each state/lock file to mode 0600 before retrying. Underlying error: {error:#}",
                    state_path.display()
                )
            }
            Err(error) => return Err(error).context("failed to create owner-private MACO state"),
        };
        Ok(Self {
            state_path: root.direct_child(state_file)?,
            root,
            state_file,
            lock_file,
            binding,
        })
    }

    fn open_existing(
        repo: &Repository,
        state_file: &'static str,
        lock_file: &'static str,
    ) -> Result<Self> {
        let common_root = SafeRoot::open_existing(repo.commondir()).with_context(|| {
            format!(
                "Git common directory is not a safe current-user-owned directory: {}",
                repo.commondir().display()
            )
        })?;
        let binding = RepositoryStateBinding {
            common_dir_path_checksum: stable_checksum(&filesystem_path_bytes(common_root.path())),
            common_dir_identity: common_root.identity().clone(),
        };
        let root = SafeRoot::open_existing(common_root.path().join("maco").join("state"))
            .context("existing MACO state root is absent or unsafe")?;
        Ok(Self {
            state_path: root.direct_child(state_file)?,
            root,
            state_file,
            lock_file,
            binding,
        })
    }

    pub(crate) fn state_path(&self) -> &Path {
        &self.state_path
    }

    pub(crate) fn binding(&self) -> &RepositoryStateBinding {
        &self.binding
    }

    pub(crate) fn root(&self) -> &SafeRoot {
        &self.root
    }

    pub(crate) fn verify(&self, lock: &RepositoryStateLock) -> Result<()> {
        self.verify_lock(lock)
    }

    pub(crate) fn lock(&self) -> Result<RepositoryStateLock> {
        let lock = KernelStateLock::acquire_direct(&self.root, self.lock_file)?;
        let lock_identity = lock.identity().clone();
        Ok(RepositoryStateLock {
            _lock: lock,
            root_identity: self.root.identity().clone(),
            state_file: self.state_file,
            lock_identity,
        })
    }

    fn lock_existing(
        &self,
    ) -> std::result::Result<RepositoryStateLock, ExistingClaimRevalidationError> {
        let lock = match KernelStateLock::try_acquire_existing_exclusive_direct(
            &self.root,
            self.lock_file,
        )
        .map_err(|source| ExistingClaimRevalidationError::StateUnavailable { source })?
        {
            ExistingExclusiveLock::Acquired(lock) => lock,
            ExistingExclusiveLock::Busy => return Err(ExistingClaimRevalidationError::LockBusy),
            ExistingExclusiveLock::Missing => {
                return Err(ExistingClaimRevalidationError::LockMissing)
            }
        };
        let bound = RepositoryStateLock {
            root_identity: self.root.identity().clone(),
            state_file: self.state_file,
            lock_identity: lock.identity().clone(),
            _lock: lock,
        };
        self.verify_lock(&bound)
            .map_err(|source| ExistingClaimRevalidationError::StateUnavailable { source })?;
        Ok(bound)
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn read(
        &self,
        lock: &RepositoryStateLock,
        max_bytes: u64,
    ) -> Result<Option<Vec<u8>>> {
        self.verify_lock(lock)?;
        let result = (|| -> Result<Option<Vec<u8>>> {
            if !self.root.direct_child_exists(self.state_file)? {
                return Ok(None);
            }
            let before = ensure_private_state_file(&self.state_path)?;
            let contents =
                BoundedRegularReader::read_direct(&self.root, self.state_file, max_bytes)?;
            let after = ensure_private_state_file(&self.state_path)?;
            if before != after {
                bail!(
                    "state file identity changed during protected read: {}",
                    self.state_path.display()
                );
            }
            Ok(Some(contents))
        })();
        finish_with_lock_verification(result, self.verify_lock(lock))
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn write(
        &self,
        lock: &RepositoryStateLock,
        contents: &[u8],
        max_bytes: u64,
    ) -> Result<()> {
        self.verify_lock(lock)?;
        run_repository_state_after_precheck_hook();
        let result = (|| -> Result<()> {
            if u64::try_from(contents.len()).unwrap_or(u64::MAX) > max_bytes {
                bail!(
                    "serialized state exceeds its {} byte limit: {}",
                    max_bytes,
                    self.state_path.display()
                );
            }
            if self.root.direct_child_exists(self.state_file)? {
                ensure_private_state_file(&self.state_path)?;
            }
            self.verify_lock(lock)?;
            AtomicStateWriter::scavenge_direct_temps(&self.root, self.state_file)?;
            AtomicStateWriter::write_direct_fenced(&self.root, self.state_file, contents, || {
                self.verify_lock(lock)
            })?;
            ensure_private_state_file(&self.state_path)?;
            Ok(())
        })();
        finish_with_lock_verification(result, self.verify_lock(lock))
    }

    fn verify_lock(&self, lock: &RepositoryStateLock) -> Result<()> {
        if lock.root_identity != *self.root.identity() || lock.state_file != self.state_file {
            bail!("repository state lock does not match the protected state file");
        }
        lock._lock.verify_direct_binding(&self.root)?;
        if lock._lock.identity() != &lock.lock_identity {
            bail!(
                "repository state lock identity changed unexpectedly: {}",
                lock._lock.path().display()
            );
        }
        Ok(())
    }
}

#[cfg(test)]
thread_local! {
    static REPOSITORY_STATE_AFTER_PRECHECK_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
#[allow(dead_code)]
fn set_repository_state_after_precheck_hook(hook: impl FnOnce() + 'static) {
    REPOSITORY_STATE_AFTER_PRECHECK_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
#[allow(dead_code)]
fn run_repository_state_after_precheck_hook() {
    let hook = REPOSITORY_STATE_AFTER_PRECHECK_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[allow(dead_code)]
fn finish_with_lock_verification<T>(result: Result<T>, verification: Result<()>) -> Result<T> {
    match (result, verification) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(lock_error)) => Err(lock_error),
        (Err(error), Err(lock_error)) => Err(error.context(format!(
            "operation also lost its stable lock-path binding: {lock_error:#}"
        ))),
    }
}

pub(crate) fn lock_existing_authenticated_claims(
    repo_path: &Path,
    requests: Vec<ExistingClaimBindingRequest>,
) -> std::result::Result<ExistingClaimsGuard, ExistingClaimRevalidationError> {
    if requests.is_empty() || requests.len() > MAX_SYNC_CLAIMS {
        return Err(ExistingClaimRevalidationError::RequestLimit {
            limit: MAX_SYNC_CLAIMS,
        });
    }
    let repo = crate::git_repository::discover(repo_path).map_err(|source| {
        ExistingClaimRevalidationError::StateUnavailable {
            source: source.into(),
        }
    })?;
    let state = RepositoryStateRoot::open_existing(&repo, "claims.json", "claims.lock")
        .map_err(|source| ExistingClaimRevalidationError::StateUnavailable { source })?;
    let lock = state.lock_existing()?;
    let repo_path = repo.workdir().unwrap_or_else(|| repo.path()).to_path_buf();
    let authenticated = read_existing_authenticated_claims(&repo_path, &state, &lock)
        .map_err(|source| ExistingClaimRevalidationError::StateUnavailable { source })?;
    let validated_at_unix_seconds = current_unix_seconds()
        .map_err(|source| ExistingClaimRevalidationError::StateUnavailable { source })?;
    verify_existing_claim_requests(&authenticated, &requests, validated_at_unix_seconds)?;
    Ok(ExistingClaimsGuard {
        repo_path,
        state,
        lock,
        authenticated,
        requests,
        validated_at_unix_seconds,
    })
}

fn read_existing_authenticated_claims(
    repo_path: &Path,
    state: &RepositoryStateRoot,
    lock: &RepositoryStateLock,
) -> Result<AuthenticatedClaimsState> {
    state.verify(lock)?;
    if !state
        .root
        .direct_child_exists(ClaimsSnapshotSpec::ROOT_NAME)?
    {
        bail!("authenticated claims snapshot is absent; initialization or migration is required");
    }
    let authenticator = repository_authenticator_key_only(repo_path)?;
    let snapshot = AuthenticatedSnapshotStore::<ClaimsSnapshotSpec, AuthenticatedClaimsState>::
        read_existing_current(authenticator, CLAIMS_LOGICAL_ID)?;
    validate_existing_authenticated_claims_snapshot(&snapshot)?;
    state.verify(lock)?;
    Ok(snapshot.value)
}

fn validate_existing_authenticated_claims_snapshot(
    snapshot: &AuthenticatedSnapshot<AuthenticatedClaimsState>,
) -> Result<()> {
    if snapshot.value.version != 1
        || snapshot.value.snapshot_revision != snapshot.generation
        || snapshot.value.snapshot_revision != snapshot.token
    {
        bail!("authenticated claims snapshot binding or revision is inconsistent");
    }
    validate_sync_snapshot(&SyncSnapshot {
        next_token: snapshot.value.next_token,
        claims: snapshot.value.claims.clone(),
    })?;
    validate_claim_run_owners(&snapshot.value.claims, &snapshot.value.run_owners)?;
    validate_claim_liveness(
        snapshot.value.next_token,
        &snapshot.value.claims,
        &snapshot.value.liveness,
        &snapshot.value.supersessions,
    )
}

fn verify_existing_claim_requests(
    state: &AuthenticatedClaimsState,
    requests: &[ExistingClaimBindingRequest],
    now: u64,
) -> std::result::Result<(), ExistingClaimRevalidationError> {
    ensure_supersession_time_not_future(&state.supersessions, now)
        .map_err(|source| ExistingClaimRevalidationError::StateUnavailable { source })?;
    let liveness = state
        .liveness
        .iter()
        .map(|entry| (entry.token, entry))
        .collect::<BTreeMap<_, _>>();

    for request in requests {
        let canonical = canonical_request_paths(&request.agent_id, &request.paths)?;
        let Some(claim) = state
            .claims
            .iter()
            .find(|claim| claim.token == request.token)
        else {
            if let Some(lineage) = state
                .supersessions
                .iter()
                .find(|entry| entry.prior_token == request.token)
            {
                return Err(ExistingClaimRevalidationError::Superseded {
                    agent_id: request.agent_id.clone(),
                    token: request.token.get(),
                    successor_token: lineage.successor_token.get(),
                });
            }
            if let Some(replacement) = state.claims.iter().find(|active| {
                active.paths.iter().any(|actual| {
                    canonical
                        .iter()
                        .any(|expected| claim_paths_overlap(expected, actual))
                })
            }) {
                return Err(ExistingClaimRevalidationError::Replaced {
                    agent_id: request.agent_id.clone(),
                    token: request.token.get(),
                    actual_token: replacement.token.get(),
                    actual_owner: replacement.agent_id.clone(),
                });
            }
            return Err(ExistingClaimRevalidationError::Released {
                agent_id: request.agent_id.clone(),
                token: request.token.get(),
            });
        };
        if claim.agent_id != request.agent_id {
            return Err(ExistingClaimRevalidationError::OwnerMismatch {
                agent_id: request.agent_id.clone(),
                token: request.token.get(),
                actual_owner: claim.agent_id.clone(),
            });
        }
        let mut actual = claim.paths.clone();
        actual.sort();
        if actual != canonical {
            return Err(ExistingClaimRevalidationError::PathsMismatch {
                agent_id: request.agent_id.clone(),
                token: request.token.get(),
            });
        }
        let report = claim_liveness_report(claim.clone(), liveness.get(&claim.token).copied(), now)
            .map_err(|source| ExistingClaimRevalidationError::StateUnavailable { source })?;
        if !matches!(
            report.state,
            ClaimLivenessState::Fresh | ClaimLivenessState::HeartbeatDue
        ) {
            return Err(ExistingClaimRevalidationError::NotLive {
                agent_id: request.agent_id.clone(),
                token: request.token.get(),
                state: report.state,
            });
        }
    }
    Ok(())
}

fn canonical_request_paths(
    agent_id: &str,
    paths: &[PathBuf],
) -> std::result::Result<Vec<PathBuf>, ExistingClaimRevalidationError> {
    if paths.is_empty() || paths.len() > MAX_SYNC_PATHS {
        return Err(ExistingClaimRevalidationError::NoncanonicalPaths {
            agent_id: agent_id.to_string(),
        });
    }
    let mut canonical = Vec::with_capacity(paths.len());
    for path in paths {
        let normalized = normalize_repo_relative_path(path).map_err(|_| {
            ExistingClaimRevalidationError::NoncanonicalPaths {
                agent_id: agent_id.to_string(),
            }
        })?;
        if &normalized != path {
            return Err(ExistingClaimRevalidationError::NoncanonicalPaths {
                agent_id: agent_id.to_string(),
            });
        }
        canonical.push(normalized);
    }
    canonical.sort();
    canonical.dedup();
    if canonical.len() != paths.len() {
        return Err(ExistingClaimRevalidationError::NoncanonicalPaths {
            agent_id: agent_id.to_string(),
        });
    }
    Ok(canonical)
}

fn claim_paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

impl SyncStore {
    pub fn open(repo_path: impl AsRef<Path>) -> Result<Self> {
        let repo = crate::git_repository::discover(repo_path.as_ref()).with_context(|| {
            format!(
                "failed to discover repository from {}",
                repo_path.as_ref().display()
            )
        })?;
        let store = Self {
            repo_path: repo.workdir().unwrap_or_else(|| repo.path()).to_path_buf(),
            state: RepositoryStateRoot::open(&repo, "claims.json", "claims.lock")?,
        };
        store.ensure_authenticated_initialized()?;
        Ok(store)
    }

    pub fn state_path(&self) -> &Path {
        self.state.state_path()
    }

    pub fn claim_paths<I, P>(&self, agent_id: impl AsRef<str>, paths: I) -> Result<PathClaim>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        Ok(self.claim_paths_with_telemetry(agent_id, paths)?.claim)
    }

    /// Acquires a path claim attributed to one supervise run and its exact
    /// boot-scoped holder process. Retained claims can therefore be reported as
    /// live, interrupted, or unknown without treating process death as release
    /// authority.
    pub fn claim_paths_for_run<I, P>(
        &self,
        run_id: &RunId,
        agent_id: impl AsRef<str>,
        paths: I,
    ) -> Result<PathClaim>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        Ok(self
            .claim_paths_with_telemetry_thresholds_internal(
                agent_id,
                paths,
                MegafileThresholds::provisional_bootstrap(),
                ClaimTiming::default(),
                current_unix_seconds()?,
                Some((
                    run_id.as_str().to_string(),
                    current_claim_process_identity(),
                )),
            )?
            .claim)
    }

    /// Persists the authenticated claim first, then records authoritative
    /// megafile telemetry. A telemetry failure is returned to the caller so
    /// work cannot proceed silently without its required history.
    pub fn claim_paths_with_telemetry<I, P>(
        &self,
        agent_id: impl AsRef<str>,
        paths: I,
    ) -> Result<ClaimTelemetryOutcome>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        self.claim_paths_with_telemetry_thresholds(
            agent_id,
            paths,
            MegafileThresholds::provisional_bootstrap(),
        )
    }

    /// Uses caller-supplied, validated thresholds for claim-time assessment.
    /// Threshold validation happens before the claim. For valid thresholds,
    /// the authenticated claim remains the first durable write and telemetry
    /// retains the same fail-closed recovery evidence as the default API.
    pub fn claim_paths_with_telemetry_thresholds<I, P>(
        &self,
        agent_id: impl AsRef<str>,
        paths: I,
        thresholds: MegafileThresholds,
    ) -> Result<ClaimTelemetryOutcome>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        self.claim_paths_with_telemetry_thresholds_and_timing(
            agent_id,
            paths,
            thresholds,
            ClaimTiming::default(),
        )
    }

    pub fn claim_paths_with_telemetry_thresholds_and_timing<I, P>(
        &self,
        agent_id: impl AsRef<str>,
        paths: I,
        thresholds: MegafileThresholds,
        timing: ClaimTiming,
    ) -> Result<ClaimTelemetryOutcome>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        self.claim_paths_with_telemetry_thresholds_internal(
            agent_id,
            paths,
            thresholds,
            timing,
            current_unix_seconds()?,
            None,
        )
    }

    pub fn claim_paths_with_timing<I, P>(
        &self,
        agent_id: impl AsRef<str>,
        paths: I,
        timing: ClaimTiming,
    ) -> Result<ClaimTelemetryOutcome>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        self.claim_paths_with_timing_at(agent_id, paths, timing, current_unix_seconds()?)
    }

    /// Caller-supplied time is an internal deterministic test seam. Production
    /// callers use the trusted system-clock wrapper above.
    fn claim_paths_with_timing_at<I, P>(
        &self,
        agent_id: impl AsRef<str>,
        paths: I,
        timing: ClaimTiming,
        now_unix_seconds: u64,
    ) -> Result<ClaimTelemetryOutcome>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        self.claim_paths_with_telemetry_thresholds_internal(
            agent_id,
            paths,
            MegafileThresholds::provisional_bootstrap(),
            timing,
            now_unix_seconds,
            None,
        )
    }

    fn claim_paths_with_telemetry_thresholds_internal<I, P>(
        &self,
        agent_id: impl AsRef<str>,
        paths: I,
        thresholds: MegafileThresholds,
        timing: ClaimTiming,
        now_unix_seconds: u64,
        run_owner: Option<(String, ClaimProcessIdentity)>,
    ) -> Result<ClaimTelemetryOutcome>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        thresholds
            .validate()
            .context("configured megafile claim thresholds are invalid")?;
        timing.validate()?;
        let claim =
            self.with_locked_update(|coordinator, run_owners, liveness, supersessions| {
                let active_claims = coordinator.snapshot()?;
                ensure_unambiguous_liveness(
                    &active_claims,
                    liveness,
                    supersessions,
                    now_unix_seconds,
                )?;
                let claim = coordinator.claim_paths(agent_id.as_ref(), paths)?;
                liveness.push(new_claim_liveness(&claim, timing, now_unix_seconds, None)?);
                if let Some((run_id, process)) = run_owner {
                    run_owners.push(AuthenticatedClaimRunOwner {
                        token: claim.token,
                        run_id,
                        process,
                    });
                }
                Ok(claim)
            })?;
        let assessments = (|| {
            MegafileStore::open_with_thresholds(&self.repo_path, thresholds)
                .context("megafile telemetry could not be opened")?
                .record_claim(&claim)
                .context("megafile telemetry could not be recorded")
        })()
        .with_context(|| {
            format!(
                "authenticated claim token {} remains durable for agent '{}' and paths {:?}, but its required megafile telemetry failed; do not retry the claim blindly: inspect the authenticated claim list and explicitly release token {} before retrying if rollback is intended",
                claim.token.get(),
                claim.agent_id,
                claim.paths,
                claim.token.get()
            )
        })?;
        let mut warnings = assessments
            .into_iter()
            .filter(|assessment| assessment.is_megafile)
            .map(|assessment| MegafileClaimWarning {
                version: 1,
                path: assessment.path.clone(),
                assessment,
            })
            .collect::<Vec<_>>();
        warnings.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(ClaimTelemetryOutcome { claim, warnings })
    }

    pub fn release(&self, token: ClaimToken) -> Result<PathClaim> {
        self.with_locked_update(|coordinator, _, _, _| {
            coordinator.release(token).map_err(Into::into)
        })
    }

    pub fn release_by_agent(&self, agent_id: impl AsRef<str>) -> Result<Vec<PathClaim>> {
        self.with_locked_update(|coordinator, _, _, _| {
            coordinator
                .release_by_agent(agent_id.as_ref())
                .map_err(Into::into)
        })
    }

    pub fn heartbeat(
        &self,
        token: ClaimToken,
        agent_id: impl AsRef<str>,
        timing: Option<ClaimTiming>,
    ) -> Result<ClaimLivenessReport> {
        self.heartbeat_at(token, agent_id, timing, current_unix_seconds()?)
    }

    fn heartbeat_at(
        &self,
        token: ClaimToken,
        agent_id: impl AsRef<str>,
        timing: Option<ClaimTiming>,
        now_unix_seconds: u64,
    ) -> Result<ClaimLivenessReport> {
        if let Some(timing) = timing {
            timing.validate()?;
        }
        let agent_id = agent_id.as_ref();
        self.with_locked_update(|coordinator, _, liveness, supersessions| {
            ensure_supersession_time_not_future(supersessions, now_unix_seconds)?;
            let claims = coordinator.snapshot()?;
            let claim = claims
                .iter()
                .find(|claim| claim.token == token)
                .cloned()
                .with_context(|| format!("claim token is not active: {}", token.get()))?;
            if claim.agent_id != agent_id {
                bail!(
                    "claim heartbeat agent '{}' does not exactly match owner '{}'",
                    agent_id,
                    claim.agent_id
                );
            }
            match liveness.iter_mut().find(|entry| entry.token == token) {
                Some(entry) => {
                    if entry.takeover_eligible_since_unix_seconds.is_some() {
                        bail!(
                            "claim '{}' is takeover-eligible and cannot be revived by heartbeat; release or take it over explicitly",
                            entry.claim_id
                        );
                    }
                    if now_unix_seconds < entry.heartbeat_unix_seconds {
                        bail!(
                            "claim '{}' heartbeat would move backward from {} to {}; refusing ambiguous clock state",
                            entry.claim_id,
                            entry.heartbeat_unix_seconds,
                            now_unix_seconds
                        );
                    }
                    if let Some(timing) = timing {
                        entry.heartbeat_interval_seconds = timing.heartbeat_interval_seconds;
                        entry.stale_after_seconds = timing.stale_after_seconds;
                    }
                    entry.heartbeat_unix_seconds = now_unix_seconds;
                }
                None => liveness.push(new_claim_liveness(
                    &claim,
                    timing.unwrap_or_default(),
                    now_unix_seconds,
                    None,
                )?),
            }
            let entry = liveness
                .iter()
                .find(|entry| entry.token == token)
                .context("claim heartbeat metadata disappeared during update")?;
            claim_liveness_report(claim, Some(entry), now_unix_seconds)
        })
    }

    pub fn liveness_snapshot(&self) -> Result<Vec<ClaimLivenessReport>> {
        self.liveness_snapshot_at(current_unix_seconds()?)
    }

    pub fn liveness_snapshot_at(&self, now_unix_seconds: u64) -> Result<Vec<ClaimLivenessReport>> {
        let lock = self.state.lock()?;
        let store = self.open_authenticated_store(&lock)?;
        let coordinator = SyncCoordinator::from_snapshot(SyncSnapshot {
            next_token: store.current().value.next_token,
            claims: store.current().value.claims.clone(),
        })?;
        let claims = coordinator.snapshot()?;
        let liveness = store
            .current()
            .value
            .liveness
            .iter()
            .map(|entry| (entry.token, entry))
            .collect::<BTreeMap<_, _>>();
        let reports = claims
            .into_iter()
            .map(|claim| {
                let token = claim.token;
                claim_liveness_report(claim, liveness.get(&token).copied(), now_unix_seconds)
            })
            .collect::<Result<Vec<_>>>()?;
        self.state.verify(&lock)?;
        Ok(reports)
    }

    pub fn sweep_stale(&self) -> Result<ClaimSweepReport> {
        self.sweep_stale_at(current_unix_seconds()?)
    }

    fn sweep_stale_at(&self, now_unix_seconds: u64) -> Result<ClaimSweepReport> {
        self.with_locked_update(|coordinator, _, liveness, supersessions| {
            let claims = coordinator.snapshot()?;
            ensure_unambiguous_liveness(&claims, liveness, supersessions, now_unix_seconds)?;
            let mut newly_takeover_eligible = Vec::new();
            for entry in liveness.iter_mut() {
                if now_unix_seconds - entry.heartbeat_unix_seconds >= entry.stale_after_seconds
                    && entry.takeover_eligible_since_unix_seconds.is_none()
                {
                    entry.takeover_eligible_since_unix_seconds = Some(now_unix_seconds);
                    newly_takeover_eligible.push(entry.claim_id.clone());
                }
            }
            newly_takeover_eligible.sort();
            let liveness_by_token = liveness
                .iter()
                .map(|entry| (entry.token, entry))
                .collect::<BTreeMap<_, _>>();
            let reports = claims
                .into_iter()
                .map(|claim| {
                    let token = claim.token;
                    claim_liveness_report(
                        claim,
                        liveness_by_token.get(&token).copied(),
                        now_unix_seconds,
                    )
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(ClaimSweepReport {
                now_unix_seconds,
                newly_takeover_eligible,
                claims: reports,
            })
        })
    }

    pub fn takeover(
        &self,
        prior_token: ClaimToken,
        agent_id: impl AsRef<str>,
        timing: Option<ClaimTiming>,
    ) -> Result<ClaimTakeoverOutcome> {
        self.takeover_at(prior_token, agent_id, timing, current_unix_seconds()?)
    }

    fn takeover_at(
        &self,
        prior_token: ClaimToken,
        agent_id: impl AsRef<str>,
        timing: Option<ClaimTiming>,
        now_unix_seconds: u64,
    ) -> Result<ClaimTakeoverOutcome> {
        if let Some(timing) = timing {
            timing.validate()?;
        }
        let agent_id = agent_id.as_ref();
        let mut outcome = self.with_locked_update(|coordinator, _, liveness, supersessions| {
            let claims = coordinator.snapshot()?;
            ensure_unambiguous_liveness(&claims, liveness, supersessions, now_unix_seconds)?;
            let prior_claim = claims
                .iter()
                .find(|claim| claim.token == prior_token)
                .cloned()
                .with_context(|| format!("claim token is not active: {}", prior_token.get()))?;
            let prior_liveness = liveness
                .iter()
                .find(|entry| entry.token == prior_token)
                .cloned()
                .context("active predecessor claim has ambiguous liveness metadata")?;
            let prior_report = claim_liveness_report(
                prior_claim.clone(),
                Some(&prior_liveness),
                now_unix_seconds,
            )?;
            if prior_report.state != ClaimLivenessState::TakeoverEligible {
                bail!(
                    "claim '{}' is not takeover-eligible (state: {:?})",
                    prior_liveness.claim_id,
                    prior_report.state
                );
            }
            if supersessions.len() >= MAX_SUPERSESSION_RECORDS {
                bail!(
                    "claim supersession history reached its {} record bound",
                    MAX_SUPERSESSION_RECORDS
                );
            }
            let lineage_depth =
                supersession_lineage_depth(&prior_liveness.claim_id, supersessions)?;
            if lineage_depth >= MAX_SUPERSESSION_LINEAGE_DEPTH {
                bail!(
                    "claim supersession lineage reached its {}-claim depth bound",
                    MAX_SUPERSESSION_LINEAGE_DEPTH
                );
            }
            let inherited_timing = ClaimTiming {
                heartbeat_interval_seconds: prior_liveness.heartbeat_interval_seconds,
                stale_after_seconds: prior_liveness.stale_after_seconds,
            };
            let successor_timing = timing.unwrap_or(inherited_timing);
            successor_timing.validate()?;
            let path_count = prior_claim.paths.len();
            let paths_checksum = claim_paths_checksum(&prior_claim.paths)?;

            let superseded_claim = coordinator.release(prior_token)?;
            let claim = coordinator.claim_paths(agent_id, superseded_claim.paths.clone())?;
            let successor_liveness = new_claim_liveness(
                &claim,
                successor_timing,
                now_unix_seconds,
                Some(prior_liveness.claim_id.clone()),
            )?;
            liveness.push(successor_liveness.clone());
            let authenticated_lineage = AuthenticatedClaimSupersession {
                prior_token,
                prior_claim_id: prior_liveness.claim_id,
                prior_agent_id: superseded_claim.agent_id.clone(),
                successor_token: claim.token,
                successor_claim_id: successor_liveness.claim_id.clone(),
                successor_agent_id: claim.agent_id.clone(),
                path_count,
                paths_checksum,
                superseded_at_unix_seconds: now_unix_seconds,
            };
            supersessions.push(authenticated_lineage.clone());
            let liveness_report =
                claim_liveness_report(claim.clone(), Some(&successor_liveness), now_unix_seconds)?;
            Ok(ClaimTakeoverOutcome {
                superseded_claim,
                claim,
                liveness: liveness_report,
                lineage: claim_supersession_report(authenticated_lineage),
                warnings: Vec::new(),
            })
        })?;
        let assessments = (|| {
            MegafileStore::open_with_thresholds(
                &self.repo_path,
                MegafileThresholds::provisional_bootstrap(),
            )
            .context("takeover megafile telemetry could not be opened")?
            .record_claim(&outcome.claim)
            .context("takeover megafile telemetry could not be recorded")
        })()
        .with_context(|| {
            format!(
                "takeover successor claim token {} remains durable for agent '{}' and paths {:?}, but its required megafile telemetry failed; inspect the authenticated claim list and explicitly release token {} before retrying if rollback is intended",
                outcome.claim.token.get(),
                outcome.claim.agent_id,
                outcome.claim.paths,
                outcome.claim.token.get()
            )
        })?;
        outcome.warnings = assessments
            .into_iter()
            .filter(|assessment| assessment.is_megafile)
            .map(|assessment| MegafileClaimWarning {
                version: 1,
                path: assessment.path.clone(),
                assessment,
            })
            .collect();
        outcome
            .warnings
            .sort_by(|left, right| left.path.cmp(&right.path));
        Ok(outcome)
    }

    pub fn supersession_history(&self) -> Result<Vec<ClaimSupersession>> {
        let lock = self.state.lock()?;
        let store = self.open_authenticated_store(&lock)?;
        let history = store
            .current()
            .value
            .supersessions
            .iter()
            .cloned()
            .map(claim_supersession_report)
            .collect();
        self.state.verify(&lock)?;
        Ok(history)
    }

    pub fn owner_of(&self, path: impl AsRef<Path>) -> Result<OwnerReport> {
        self.with_locked_read(|coordinator| {
            let path = normalize_repo_relative_path(path.as_ref())?;
            let owner = coordinator.owner_of(&path)?;
            Ok(OwnerReport { path, owner })
        })
    }

    pub fn snapshot(&self) -> Result<Vec<PathClaim>> {
        self.with_locked_read(|coordinator| coordinator.snapshot().map_err(Into::into))
    }

    pub fn status_snapshot(&self) -> Result<Vec<ClaimStatusReport>> {
        let (claims, run_owners) = {
            let lock = self.state.lock()?;
            let store = self.open_authenticated_store(&lock)?;
            let coordinator = SyncCoordinator::from_snapshot(SyncSnapshot {
                next_token: store.current().value.next_token,
                claims: store.current().value.claims.clone(),
            })?;
            let claims = coordinator.snapshot()?;
            let run_owners = store
                .current()
                .value
                .run_owners
                .iter()
                .cloned()
                .map(|owner| (owner.token, owner))
                .collect::<BTreeMap<_, _>>();
            self.state.verify(&lock)?;
            (claims, run_owners)
        };
        Ok(claims
            .into_iter()
            .map(|claim| {
                let token = claim.token;
                claim_status_report(claim, run_owners.get(&token))
            })
            .collect())
    }

    /// Opens and authenticates the canonical claims schema, then retains its
    /// durable writer lock for a caller that must make a claim-sensitive
    /// decision and complete another operation at the same linearization
    /// boundary.
    pub(crate) fn lock_authenticated_snapshot(&self) -> Result<LockedClaimsSnapshot> {
        let lock = self.state.lock()?;
        let claims = finish_with_lock_verification(
            (|| {
                let store = self.open_authenticated_store(&lock)?;
                let coordinator = SyncCoordinator::from_snapshot(SyncSnapshot {
                    next_token: store.current().value.next_token,
                    claims: store.current().value.claims.clone(),
                })?;
                coordinator.snapshot().map_err(Into::into)
            })(),
            self.state.verify(&lock),
        )?;
        Ok(LockedClaimsSnapshot {
            state: self.state.clone(),
            lock,
            claims,
        })
    }

    fn with_locked_update<T>(
        &self,
        operation: impl FnOnce(
            &SyncCoordinator,
            &mut Vec<AuthenticatedClaimRunOwner>,
            &mut Vec<AuthenticatedClaimLiveness>,
            &mut Vec<AuthenticatedClaimSupersession>,
        ) -> Result<T>,
    ) -> Result<T> {
        let lock = self.state.lock()?;
        let mut store = self.open_authenticated_store(&lock)?;
        let coordinator = SyncCoordinator::from_snapshot(SyncSnapshot {
            next_token: store.current().value.next_token,
            claims: store.current().value.claims.clone(),
        })?;
        let mut run_owners = store.current().value.run_owners.clone();
        let mut liveness = store.current().value.liveness.clone();
        let mut supersessions = store.current().value.supersessions.clone();
        let output = operation(
            &coordinator,
            &mut run_owners,
            &mut liveness,
            &mut supersessions,
        )?;
        let snapshot = coordinator.to_snapshot()?;
        validate_sync_snapshot(&snapshot)?;
        let active_tokens = snapshot
            .claims
            .iter()
            .map(|claim| claim.token)
            .collect::<BTreeSet<_>>();
        run_owners.retain(|owner| active_tokens.contains(&owner.token));
        liveness.retain(|entry| active_tokens.contains(&entry.token));
        run_owners.sort_by_key(|owner| owner.token);
        liveness.sort_by_key(|entry| entry.token);
        supersessions.sort_by_key(|entry| entry.successor_token);
        validate_claim_run_owners(&snapshot.claims, &run_owners)?;
        validate_claim_liveness(
            snapshot.next_token,
            &snapshot.claims,
            &liveness,
            &supersessions,
        )?;
        if snapshot.next_token == store.current().value.next_token
            && snapshot.claims == store.current().value.claims
            && run_owners == store.current().value.run_owners
            && liveness == store.current().value.liveness
            && supersessions == store.current().value.supersessions
        {
            self.state.verify_lock(&lock)?;
            return Ok(output);
        }
        let revision = store
            .current()
            .value
            .snapshot_revision
            .checked_add(1)
            .context("authenticated claims snapshot revision exhausted")?;
        let value = AuthenticatedClaimsState {
            version: 1,
            snapshot_revision: revision,
            repository: store.current().value.repository.clone(),
            next_token: snapshot.next_token,
            claims: snapshot.claims,
            run_owners,
            liveness,
            supersessions,
        };
        if revision % 4_096 == 0 {
            let authenticator = repository_authenticator_key_only(&self.repo_path)?;
            store = store.rollover(authenticator, revision, value)?;
        } else {
            store.commit(revision, value)?;
        }
        self.validate_authenticated_store(&store)?;
        self.ensure_legacy_retirement(&store, &lock)?;
        self.state.verify_lock(&lock)?;
        Ok(output)
    }

    fn with_locked_read<T>(
        &self,
        operation: impl FnOnce(&SyncCoordinator) -> Result<T>,
    ) -> Result<T> {
        let lock = self.state.lock()?;
        let store = self.open_authenticated_store(&lock)?;
        let coordinator = SyncCoordinator::from_snapshot(SyncSnapshot {
            next_token: store.current().value.next_token,
            claims: store.current().value.claims.clone(),
        })?;
        operation(&coordinator)
    }

    fn ensure_authenticated_initialized(&self) -> Result<()> {
        let lock = self.state.lock()?;
        let root_exists = self
            .state
            .root
            .direct_child_exists(ClaimsSnapshotSpec::ROOT_NAME)?;
        if root_exists {
            let authenticator = repository_authenticator_key_only(&self.repo_path)?;
            let initialized = AuthenticatedSnapshotStore::<
                ClaimsSnapshotSpec,
                AuthenticatedClaimsState,
            >::initialized(&authenticator, CLAIMS_LOGICAL_ID)?;
            if initialized {
                let store = AuthenticatedSnapshotStore::<
                    ClaimsSnapshotSpec,
                    AuthenticatedClaimsState,
                >::open_instance(authenticator, CLAIMS_LOGICAL_ID)?;
                self.validate_authenticated_store(&store)?;
                self.ensure_legacy_retirement(&store, &lock)?;
                return self.state.verify_lock(&lock);
            }
        }
        let preparation = prepare_legacy_retirement::<ClaimsSnapshotSpec>(
            &self.repo_path,
            "claims",
            "claims.json",
            LEGACY_RETIREMENT_DOMAIN,
            &|| self.state.verify_lock(&lock),
        )?;
        let (adoption, writer) = preparation.into_parts();
        let binding = writer.authenticator().binding().clone();
        let initial = match adoption {
            LegacyAdoption::Missing => AuthenticatedClaimsState {
                version: 1,
                snapshot_revision: 1,
                repository: binding,
                next_token: 1,
                claims: Vec::new(),
                run_owners: Vec::new(),
                liveness: Vec::new(),
                supersessions: Vec::new(),
            },
            LegacyAdoption::Present(bytes) => {
                let snapshot = match serde_json::from_slice::<PersistedSyncState>(&bytes) {
                    Ok(legacy) => {
                        if legacy.version != STATE_VERSION
                            || legacy.repository != *self.state.binding()
                            || legacy.checksum != sync_state_checksum(&legacy)?
                        {
                            bail!(
                                "signed legacy claims state failed repository/checksum validation"
                            );
                        }
                        SyncSnapshot {
                            next_token: legacy.next_token,
                            claims: legacy.claims,
                        }
                    }
                    Err(_) => {
                        let legacy = decode_checksumless_legacy_claims_state(&bytes)
                            .context("signed operator-attested claims-v1 state is malformed")?;
                        SyncSnapshot {
                            next_token: legacy.next_token,
                            claims: legacy.claims,
                        }
                    }
                };
                validate_sync_snapshot(&snapshot)?;
                AuthenticatedClaimsState {
                    version: 1,
                    snapshot_revision: 1,
                    repository: binding,
                    next_token: snapshot.next_token,
                    claims: snapshot.claims,
                    run_owners: Vec::new(),
                    liveness: Vec::new(),
                    supersessions: Vec::new(),
                }
            }
        };
        let store =
            AuthenticatedSnapshotStore::<ClaimsSnapshotSpec, AuthenticatedClaimsState>::create(
                writer.into_authenticator()?,
                CLAIMS_LOGICAL_ID,
                1,
                initial,
            )?;
        self.validate_authenticated_store(&store)?;
        self.ensure_legacy_retirement(&store, &lock)?;
        self.state.verify_lock(&lock)
    }

    fn open_authenticated_store(
        &self,
        lock: &RepositoryStateLock,
    ) -> Result<AuthenticatedSnapshotStore<ClaimsSnapshotSpec, AuthenticatedClaimsState>> {
        self.state.verify_lock(lock)?;
        let authenticator = repository_authenticator_key_only(&self.repo_path)?;
        let store = AuthenticatedSnapshotStore::open_instance(authenticator, CLAIMS_LOGICAL_ID)?;
        self.validate_authenticated_store(&store)?;
        self.ensure_legacy_retirement(&store, lock)?;
        self.state.verify_lock(lock)?;
        Ok(store)
    }

    fn validate_authenticated_store(
        &self,
        store: &AuthenticatedSnapshotStore<ClaimsSnapshotSpec, AuthenticatedClaimsState>,
    ) -> Result<()> {
        let snapshot = store.current();
        if snapshot.value.version != 1
            || snapshot.value.snapshot_revision != snapshot.generation
            || snapshot.value.snapshot_revision != snapshot.token
            || snapshot.value.repository != store.identity().repository
        {
            bail!("authenticated claims snapshot binding or revision is inconsistent");
        }
        validate_sync_snapshot(&SyncSnapshot {
            next_token: snapshot.value.next_token,
            claims: snapshot.value.claims.clone(),
        })?;
        validate_claim_run_owners(&snapshot.value.claims, &snapshot.value.run_owners).and_then(
            |()| {
                validate_claim_liveness(
                    snapshot.value.next_token,
                    &snapshot.value.claims,
                    &snapshot.value.liveness,
                    &snapshot.value.supersessions,
                )
            },
        )
    }

    fn ensure_legacy_retirement(
        &self,
        store: &AuthenticatedSnapshotStore<ClaimsSnapshotSpec, AuthenticatedClaimsState>,
        lock: &RepositoryStateLock,
    ) -> Result<()> {
        finalize_legacy_retirement::<ClaimsSnapshotSpec>(
            &self.repo_path,
            "claims",
            "claims.json",
            LEGACY_RETIREMENT_DOMAIN,
            store.identity(),
            store.current().generation,
            &|| self.state.verify_lock(lock),
        )
    }

    #[cfg(test)]
    fn load_snapshot(&self, lock: &RepositoryStateLock) -> Result<SyncSnapshot> {
        let store = self.open_authenticated_store(lock)?;
        Ok(SyncSnapshot {
            next_token: store.current().value.next_token,
            claims: store.current().value.claims.clone(),
        })
    }

    #[cfg(test)]
    fn save_snapshot(&self, lock: &RepositoryStateLock, snapshot: SyncSnapshot) -> Result<()> {
        self.state.verify_lock(lock)?;
        validate_sync_snapshot(&snapshot)?;
        let mut store = self.open_authenticated_store(lock)?;
        let revision = store
            .current()
            .value
            .snapshot_revision
            .checked_add(1)
            .context("authenticated claims test revision exhausted")?;
        let value = AuthenticatedClaimsState {
            version: 1,
            snapshot_revision: revision,
            repository: store.current().value.repository.clone(),
            next_token: snapshot.next_token,
            claims: snapshot.claims,
            run_owners: Vec::new(),
            liveness: Vec::new(),
            supersessions: Vec::new(),
        };
        store.commit(revision, value)?;
        self.state.verify_lock(lock)
    }
}

fn sync_state_checksum(state: &PersistedSyncState) -> Result<String> {
    let payload = serde_json::to_vec(&(
        state.version,
        &state.repository,
        state.next_token,
        &state.claims,
    ))
    .context("failed to encode sync state checksum payload")?;
    Ok(stable_checksum(&payload))
}

fn claim_status_report(
    claim: PathClaim,
    run_owner: Option<&AuthenticatedClaimRunOwner>,
) -> ClaimStatusReport {
    let owner_run_state = match run_owner.map(|owner| claim_process_liveness(&owner.process)) {
        Some(ClaimProcessLiveness::Live) => ClaimOwnerRunState::Active,
        Some(ClaimProcessLiveness::Interrupted) => ClaimOwnerRunState::Interrupted,
        Some(ClaimProcessLiveness::Unknown) => ClaimOwnerRunState::Unknown,
        None => ClaimOwnerRunState::Unattributed,
    };
    ClaimStatusReport {
        claim,
        owner_run_id: run_owner.map(|owner| owner.run_id.clone()),
        owner_process_id: run_owner.map(|owner| owner.process.pid),
        owner_run_state,
    }
}

fn current_unix_seconds() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")
        .map(|duration| duration.as_secs())
}

fn canonical_claim_id(token: ClaimToken) -> String {
    format!("claim-{:020}", token.get())
}

fn new_claim_liveness(
    claim: &PathClaim,
    timing: ClaimTiming,
    now_unix_seconds: u64,
    supersedes: Option<String>,
) -> Result<AuthenticatedClaimLiveness> {
    timing.validate()?;
    if supersedes
        .as_ref()
        .is_some_and(|claim_id| validate_claim_id(claim_id).is_err())
    {
        bail!("superseded claim id is invalid");
    }
    Ok(AuthenticatedClaimLiveness {
        token: claim.token,
        claim_id: canonical_claim_id(claim.token),
        created_unix_seconds: now_unix_seconds,
        heartbeat_unix_seconds: now_unix_seconds,
        heartbeat_interval_seconds: timing.heartbeat_interval_seconds,
        stale_after_seconds: timing.stale_after_seconds,
        takeover_eligible_since_unix_seconds: None,
        supersedes,
    })
}

fn claim_liveness_report(
    claim: PathClaim,
    liveness: Option<&AuthenticatedClaimLiveness>,
    now_unix_seconds: u64,
) -> Result<ClaimLivenessReport> {
    let Some(liveness) = liveness else {
        return Ok(ClaimLivenessReport {
            claim_id: canonical_claim_id(claim.token),
            claim,
            state: ClaimLivenessState::Unknown,
            ambiguity: Some(
                "authenticated claim predates liveness metadata; exact-owner heartbeat or explicit release is required"
                    .to_string(),
            ),
            created_unix_seconds: None,
            heartbeat_unix_seconds: None,
            heartbeat_interval_seconds: None,
            stale_after_seconds: None,
            takeover_eligible_since_unix_seconds: None,
            supersedes: None,
        });
    };
    if liveness.token != claim.token {
        bail!("claim liveness metadata token does not match its claim");
    }
    let mut report = ClaimLivenessReport {
        claim_id: liveness.claim_id.clone(),
        claim,
        state: ClaimLivenessState::Unknown,
        ambiguity: None,
        created_unix_seconds: Some(liveness.created_unix_seconds),
        heartbeat_unix_seconds: Some(liveness.heartbeat_unix_seconds),
        heartbeat_interval_seconds: Some(liveness.heartbeat_interval_seconds),
        stale_after_seconds: Some(liveness.stale_after_seconds),
        takeover_eligible_since_unix_seconds: liveness.takeover_eligible_since_unix_seconds,
        supersedes: liveness.supersedes.clone(),
    };
    if now_unix_seconds < liveness.heartbeat_unix_seconds {
        report.ambiguity = Some(format!(
            "observed time {now_unix_seconds} precedes heartbeat {}",
            liveness.heartbeat_unix_seconds
        ));
        return Ok(report);
    }
    if let Some(eligible_since) = liveness.takeover_eligible_since_unix_seconds {
        if now_unix_seconds < eligible_since {
            report.ambiguity = Some(format!(
                "observed time {now_unix_seconds} precedes takeover eligibility {eligible_since}"
            ));
            return Ok(report);
        }
        report.state = ClaimLivenessState::TakeoverEligible;
        return Ok(report);
    }
    let age = now_unix_seconds - liveness.heartbeat_unix_seconds;
    report.state = if age >= liveness.stale_after_seconds {
        ClaimLivenessState::Stale
    } else if age >= liveness.heartbeat_interval_seconds {
        ClaimLivenessState::HeartbeatDue
    } else {
        ClaimLivenessState::Fresh
    };
    Ok(report)
}

fn ensure_unambiguous_liveness(
    claims: &[PathClaim],
    liveness: &[AuthenticatedClaimLiveness],
    supersessions: &[AuthenticatedClaimSupersession],
    now_unix_seconds: u64,
) -> Result<()> {
    ensure_supersession_time_not_future(supersessions, now_unix_seconds)?;
    let liveness = liveness
        .iter()
        .map(|entry| (entry.token, entry))
        .collect::<BTreeMap<_, _>>();
    for claim in claims {
        let report = claim_liveness_report(
            claim.clone(),
            liveness.get(&claim.token).copied(),
            now_unix_seconds,
        )?;
        if report.state == ClaimLivenessState::Unknown {
            bail!(
                "claim '{}' has ambiguous liveness: {}",
                report.claim_id,
                report.ambiguity.as_deref().unwrap_or("unknown reason")
            );
        }
    }
    Ok(())
}

fn ensure_supersession_time_not_future(
    supersessions: &[AuthenticatedClaimSupersession],
    now_unix_seconds: u64,
) -> Result<()> {
    if let Some(future) = supersessions
        .iter()
        .find(|entry| entry.superseded_at_unix_seconds > now_unix_seconds)
    {
        bail!(
            "claim supersession '{}' has future timestamp {}; observed time is {}; refusing ambiguous clock state",
            future.successor_claim_id,
            future.superseded_at_unix_seconds,
            now_unix_seconds
        );
    }
    Ok(())
}

fn claim_paths_checksum(paths: &[PathBuf]) -> Result<String> {
    let payload = serde_json::to_vec(paths).context("failed to encode canonical claim paths")?;
    Ok(sha256_hex(&payload))
}

fn claim_supersession_report(value: AuthenticatedClaimSupersession) -> ClaimSupersession {
    ClaimSupersession {
        prior_token: value.prior_token,
        prior_claim_id: value.prior_claim_id,
        prior_agent_id: value.prior_agent_id,
        successor_token: value.successor_token,
        successor_claim_id: value.successor_claim_id,
        successor_agent_id: value.successor_agent_id,
        path_count: value.path_count,
        paths_checksum: value.paths_checksum,
        superseded_at_unix_seconds: value.superseded_at_unix_seconds,
    }
}

fn validate_claim_id(claim_id: &str) -> Result<()> {
    if claim_id.is_empty() || claim_id.len() > MAX_CLAIM_ID_BYTES {
        bail!("claim id must be between 1 and {MAX_CLAIM_ID_BYTES} bytes");
    }
    if !claim_id
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        bail!("claim id contains unsupported characters");
    }
    Ok(())
}

fn validate_lineage_agent_id(agent_id: &str) -> Result<()> {
    if agent_id.is_empty() || agent_id.len() > MAX_AGENT_ID_BYTES {
        bail!("claim lineage agent id has an invalid length");
    }
    if !agent_id
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        bail!("claim lineage agent id contains unsupported characters");
    }
    Ok(())
}

fn supersession_lineage_depth(
    claim_id: &str,
    supersessions: &[AuthenticatedClaimSupersession],
) -> Result<usize> {
    let by_successor = supersessions
        .iter()
        .map(|entry| (entry.successor_claim_id.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let mut seen = BTreeSet::new();
    let mut current = claim_id;
    let mut depth = 0usize;
    while let Some(entry) = by_successor.get(current) {
        if !seen.insert(current.to_string()) {
            bail!("claim supersession lineage contains a cycle");
        }
        depth = depth
            .checked_add(1)
            .context("claim supersession lineage depth overflow")?;
        if depth > MAX_SUPERSESSION_LINEAGE_DEPTH {
            bail!(
                "claim supersession lineage exceeds its {}-claim depth bound",
                MAX_SUPERSESSION_LINEAGE_DEPTH
            );
        }
        current = &entry.prior_claim_id;
    }
    Ok(depth)
}

fn validate_claim_run_owners(
    claims: &[PathClaim],
    run_owners: &[AuthenticatedClaimRunOwner],
) -> Result<()> {
    if run_owners.len() > claims.len() {
        bail!("authenticated claim run-owner count exceeds active claim count");
    }
    let active_tokens = claims
        .iter()
        .map(|claim| claim.token)
        .collect::<BTreeSet<_>>();
    let mut seen_tokens = BTreeSet::new();
    for owner in run_owners {
        if !active_tokens.contains(&owner.token) {
            bail!(
                "authenticated run owner references inactive claim token {}",
                owner.token.get()
            );
        }
        if !seen_tokens.insert(owner.token) {
            bail!(
                "authenticated claim token {} has duplicate run owners",
                owner.token.get()
            );
        }
        if owner.run_id.len() > MAX_RUN_ID_BYTES {
            bail!("authenticated claim run id exceeds {MAX_RUN_ID_BYTES} bytes");
        }
        RunId::new(&owner.run_id).context("authenticated claim run id is invalid")?;
        if owner.process.pid == 0 {
            bail!("authenticated claim run owner contains PID 0");
        }
        if owner
            .process
            .process_start_time
            .as_ref()
            .is_some_and(|value| {
                value.is_empty()
                    || value.len() > MAX_PROCESS_START_TIME_BYTES
                    || value.chars().any(char::is_control)
            })
        {
            bail!("authenticated claim process start-time identity is invalid");
        }
    }
    Ok(())
}

fn validate_claim_liveness(
    next_token: u64,
    claims: &[PathClaim],
    liveness: &[AuthenticatedClaimLiveness],
    supersessions: &[AuthenticatedClaimSupersession],
) -> Result<()> {
    if liveness.len() > claims.len() {
        bail!("authenticated claim liveness count exceeds active claim count");
    }
    if supersessions.len() > MAX_SUPERSESSION_RECORDS {
        bail!(
            "authenticated claim supersession history exceeds its {} record bound",
            MAX_SUPERSESSION_RECORDS
        );
    }
    let active_claims = claims
        .iter()
        .map(|claim| (claim.token, claim))
        .collect::<BTreeMap<_, _>>();
    let mut active_liveness = BTreeMap::new();
    for entry in liveness {
        if !active_claims.contains_key(&entry.token) {
            bail!(
                "authenticated liveness references inactive claim token {}",
                entry.token.get()
            );
        }
        if active_liveness.insert(entry.token, entry).is_some() {
            bail!(
                "authenticated claim token {} has duplicate liveness metadata",
                entry.token.get()
            );
        }
        validate_claim_id(&entry.claim_id)?;
        if entry.claim_id != canonical_claim_id(entry.token) {
            bail!("authenticated claim id is not canonical for its token");
        }
        ClaimTiming::new(entry.heartbeat_interval_seconds, entry.stale_after_seconds)?;
        if entry.created_unix_seconds > entry.heartbeat_unix_seconds {
            bail!("authenticated claim heartbeat predates claim creation");
        }
        if let Some(eligible) = entry.takeover_eligible_since_unix_seconds {
            let eligible_age = eligible
                .checked_sub(entry.heartbeat_unix_seconds)
                .context("authenticated claim eligibility predates its last heartbeat")?;
            if eligible_age < entry.stale_after_seconds {
                bail!("authenticated claim eligibility was recorded before the stale threshold");
            }
        }
        if let Some(supersedes) = &entry.supersedes {
            validate_claim_id(supersedes)?;
            if supersedes == &entry.claim_id {
                bail!("authenticated claim cannot supersede itself");
            }
        }
    }

    let mut by_prior = BTreeMap::new();
    let mut by_successor = BTreeMap::new();
    for entry in supersessions {
        if entry.prior_token.get() == 0 || entry.successor_token.get() == 0 {
            bail!("authenticated claim supersession contains token zero");
        }
        if entry.successor_token <= entry.prior_token {
            bail!("authenticated claim supersession tokens are not monotonic");
        }
        if entry.prior_token.get() >= next_token || entry.successor_token.get() >= next_token {
            bail!("authenticated claim supersession token reaches or exceeds next_token");
        }
        if active_claims.contains_key(&entry.prior_token) {
            bail!("authenticated supersession predecessor remains active");
        }
        validate_claim_id(&entry.prior_claim_id)?;
        validate_claim_id(&entry.successor_claim_id)?;
        if entry.prior_claim_id != canonical_claim_id(entry.prior_token)
            || entry.successor_claim_id != canonical_claim_id(entry.successor_token)
        {
            bail!("authenticated claim supersession contains a noncanonical claim id");
        }
        validate_lineage_agent_id(&entry.prior_agent_id)?;
        validate_lineage_agent_id(&entry.successor_agent_id)?;
        if entry.path_count == 0 || entry.path_count > MAX_SYNC_PATHS {
            bail!("authenticated claim supersession path count is out of bounds");
        }
        if entry.paths_checksum.len() != 64
            || !entry
                .paths_checksum
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            bail!("authenticated claim supersession path checksum is invalid");
        }
        if by_prior.insert(entry.prior_token, entry).is_some() {
            bail!("authenticated claim was superseded more than once");
        }
        if by_successor.insert(entry.successor_token, entry).is_some() {
            bail!("authenticated claim successor has more than one predecessor");
        }
    }

    for entry in supersessions {
        if let Some(previous) = by_successor.get(&entry.prior_token) {
            if previous.superseded_at_unix_seconds > entry.superseded_at_unix_seconds {
                bail!("authenticated claim supersession time moved backward");
            }
            if previous.successor_claim_id != entry.prior_claim_id
                || previous.successor_agent_id != entry.prior_agent_id
                || previous.path_count != entry.path_count
                || previous.paths_checksum != entry.paths_checksum
            {
                bail!("authenticated claim supersession lineage changed owner or scope");
            }
        }
        supersession_lineage_depth(&entry.successor_claim_id, supersessions)?;
        if active_claims.contains_key(&entry.successor_token)
            && !active_liveness.contains_key(&entry.successor_token)
        {
            bail!("active successor claim is missing its audited liveness metadata");
        }
    }

    for (token, entry) in &active_liveness {
        let lineage = by_successor.get(token).copied();
        match (&entry.supersedes, lineage) {
            (None, None) => {}
            (Some(prior), Some(lineage)) if prior == &lineage.prior_claim_id => {
                let claim = active_claims
                    .get(token)
                    .context("active liveness lost its claim during validation")?;
                if claim.agent_id != lineage.successor_agent_id
                    || claim.paths.len() != lineage.path_count
                    || claim_paths_checksum(&claim.paths)? != lineage.paths_checksum
                    || entry.created_unix_seconds != lineage.superseded_at_unix_seconds
                {
                    bail!("active successor claim no longer matches its audited lineage");
                }
            }
            _ => bail!("active successor claim lineage metadata is inconsistent"),
        }
    }
    Ok(())
}

fn validate_sync_snapshot(snapshot: &SyncSnapshot) -> Result<()> {
    if snapshot.next_token == 0 {
        bail!("sync state next_token must be nonzero");
    }
    if snapshot.claims.len() > MAX_SYNC_CLAIMS {
        bail!(
            "sync state exceeds its claim budget of {} records",
            MAX_SYNC_CLAIMS
        );
    }
    let mut path_count = 0usize;
    let mut max_token = 0u64;
    for claim in &snapshot.claims {
        max_token = max_token.max(claim.token.get());
        if claim.agent_id.len() > MAX_AGENT_ID_BYTES {
            bail!("sync state agent id exceeds {MAX_AGENT_ID_BYTES} bytes");
        }
        path_count = path_count
            .checked_add(claim.paths.len())
            .context("sync state path count overflow")?;
        if path_count > MAX_SYNC_PATHS {
            bail!(
                "sync state exceeds its aggregate path budget of {}",
                MAX_SYNC_PATHS
            );
        }
        for path in &claim.paths {
            validate_state_path(path)?;
        }
    }
    if snapshot.next_token <= max_token {
        bail!("sync state next_token must be greater than every active claim token");
    }
    Ok(())
}

pub(crate) fn validate_state_path(path: &Path) -> Result<()> {
    let bytes = path_bytes(path);
    if bytes == 0 || bytes > MAX_STATE_PATH_BYTES {
        bail!(
            "persisted path length must be between 1 and {} bytes",
            MAX_STATE_PATH_BYTES
        );
    }
    if path.components().count() > MAX_STATE_PATH_COMPONENTS {
        bail!(
            "persisted path exceeds its {} component budget",
            MAX_STATE_PATH_COMPONENTS
        );
    }
    normalize_repo_relative_path(path).with_context(|| {
        format!(
            "persisted path is not repository-relative: {}",
            path.display()
        )
    })?;
    Ok(())
}

#[cfg(unix)]
fn path_bytes(path: &Path) -> usize {
    path.as_os_str().as_bytes().len()
}

#[cfg(not(unix))]
fn path_bytes(path: &Path) -> usize {
    path.as_os_str().to_string_lossy().len()
}

#[cfg(unix)]
fn filesystem_path_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().as_bytes().to_vec()
}

#[cfg(not(unix))]
fn filesystem_path_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().to_string_lossy().as_bytes().to_vec()
}

#[cfg(all(test, unix))]
#[allow(dead_code)]
fn ensure_private_state_file(path: &Path) -> Result<FileIdentity> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect private state file {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        bail!(
            "state file is not a regular no-follow file: {}",
            path.display()
        );
    }
    if metadata.nlink() != 1 {
        bail!(
            "state file must have exactly one hard link (observed {}): {}",
            metadata.nlink(),
            path.display()
        );
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        bail!(
            "state file is not owned by the current user: {}",
            path.display()
        );
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o600 {
        bail!(
            "state file has unsafe mode {:04o}; independently verify ownership and contents, then migrate it to mode 0600: {}",
            mode,
            path.display()
        );
    }
    identity_for_path(path)
}

#[cfg(all(test, not(unix)))]
#[allow(dead_code)]
fn ensure_private_state_file(path: &Path) -> Result<FileIdentity> {
    bail!(
        "private state-file ownership and ACL validation is unsupported on this platform: {}",
        path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        artifacts::state_auth::authentication_key_file_name,
        megafile::{
            set_record_claim_fault, FileSizeSample, MegafileStore, MegafileThresholdCalibration,
            MAX_CLAIM_TELEMETRY_TARGETS,
        },
        state_migration::{
            migrate_repository_state_with_options, set_legacy_retirement_fault,
            LegacyRetirementFaultPoint, StateMigrationOptions,
        },
        worktree::WorktreeManager,
    };
    use git2::{Oid, Repository, Signature};
    #[cfg(unix)]
    use std::{
        env,
        ffi::OsString,
        io,
        process::{Child, Command, ExitStatus, Stdio},
        time::{Duration, Instant},
    };
    use tempfile::TempDir;

    const ISSUE33_CLAIMS_V1: &[u8] =
        include_bytes!("../tests/fixtures/issue33/agent-files-claims-v1.json");
    const ISSUE33_CLAIMS_V1_SHA256: &str =
        "58076fb067d6bbc560926628b8930075d0674eae025b945619f0890000995291";

    #[cfg(unix)]
    const WATCHDOG_COMPLETION_RECEIPT: &[u8] = b"sync-store-test-complete-v1\n";
    #[cfg(unix)]
    const WATCHDOG_RECEIPT_PATH_ENV: &str = "MACO_SYNC_STORE_TEST_RECEIPT_PATH";
    #[cfg(unix)]
    const WATCHDOG_FORCE_STALL_ENV: &str = "MACO_SYNC_STORE_TEST_FORCE_STALL";
    #[cfg(unix)]
    const WATCHDOG_STALL_READY_PATH_ENV: &str = "MACO_SYNC_STORE_TEST_STALL_READY_PATH";
    #[cfg(unix)]
    const WATCHDOG_POLL_INTERVAL: Duration = Duration::from_millis(10);

    #[cfg(unix)]
    #[derive(Debug, Eq, PartialEq)]
    enum CompletionReceipt {
        Confirmed,
        Missing,
        Invalid,
    }

    #[cfg(unix)]
    #[derive(Debug)]
    enum ExactTestOutcome {
        Completed {
            status: ExitStatus,
            receipt: CompletionReceipt,
        },
        TimedOut {
            pid: u32,
            status: ExitStatus,
        },
    }

    #[cfg(unix)]
    struct KillOnDropChild {
        child: Child,
        reaped: bool,
    }

    #[cfg(unix)]
    impl KillOnDropChild {
        fn spawn(command: &mut Command) -> io::Result<Self> {
            Ok(Self {
                child: command.spawn()?,
                reaped: false,
            })
        }

        fn id(&self) -> u32 {
            self.child.id()
        }

        fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
            let status = self.child.try_wait()?;
            self.reaped = status.is_some();
            Ok(status)
        }

        fn kill_and_reap(&mut self) -> io::Result<ExitStatus> {
            let kill_result = self.child.kill();
            let wait_result = self.child.wait();
            if wait_result.is_ok() {
                self.reaped = true;
            }
            match (kill_result, wait_result) {
                (_, Ok(status)) => Ok(status),
                (Ok(()), Err(error)) => Err(error),
                (Err(kill_error), Err(wait_error)) => Err(io::Error::new(
                    wait_error.kind(),
                    format!(
                        "failed to kill watched child ({kill_error}) and failed to reap it ({wait_error})"
                    ),
                )),
            }
        }
    }

    #[cfg(unix)]
    impl Drop for KillOnDropChild {
        fn drop(&mut self) {
            if self.reaped {
                return;
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    #[cfg(unix)]
    fn completion_receipt(path: &Path) -> io::Result<CompletionReceipt> {
        match fs::read(path) {
            Ok(contents) if contents == WATCHDOG_COMPLETION_RECEIPT => {
                Ok(CompletionReceipt::Confirmed)
            }
            Ok(_) => Ok(CompletionReceipt::Invalid),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(CompletionReceipt::Missing),
            Err(error) => Err(error),
        }
    }

    #[cfg(unix)]
    fn write_completion_receipt_if_requested() {
        if let Some(path) = env::var_os(WATCHDOG_RECEIPT_PATH_ENV) {
            fs::write(PathBuf::from(path), WATCHDOG_COMPLETION_RECEIPT)
                .expect("write sync-store child completion receipt");
        }
    }

    #[cfg(unix)]
    fn run_exact_current_test_with_watchdog(
        test_name: &str,
        timeout: Duration,
        child_environment: &[(&str, OsString)],
        receipt_path: &Path,
    ) -> io::Result<ExactTestOutcome> {
        if receipt_path.try_exists()? {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "sync-store child receipt path must start absent",
            ));
        }
        let mut command = Command::new(env::current_exe()?);
        command
            .arg("--exact")
            .arg(test_name)
            .arg("--nocapture")
            .arg("--test-threads=1")
            .envs(child_environment.iter().map(|(name, value)| (*name, value)))
            .env(WATCHDOG_RECEIPT_PATH_ENV, receipt_path)
            .stdin(Stdio::null());
        let mut child = KillOnDropChild::spawn(&mut command)?;
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "sync-store child watchdog duration overflowed",
            )
        })?;

        loop {
            let now = Instant::now();
            if now >= deadline {
                let pid = child.id();
                let status = child.kill_and_reap()?;
                return Ok(ExactTestOutcome::TimedOut { pid, status });
            }
            if let Some(status) = child.try_wait()? {
                return Ok(ExactTestOutcome::Completed {
                    status,
                    receipt: completion_receipt(receipt_path)?,
                });
            }
            std::thread::sleep(WATCHDOG_POLL_INTERVAL.min(deadline.duration_since(now)));
        }
    }

    #[cfg(unix)]
    #[test]
    fn watchdog_forced_stall_child() {
        if env::var_os(WATCHDOG_FORCE_STALL_ENV).is_some() {
            let ready_path = env::var_os(WATCHDOG_STALL_READY_PATH_ENV)
                .expect("forced-stall child requires a ready-marker path");
            fs::write(ready_path, b"stalled\n").expect("publish forced-stall readiness");
            loop {
                std::thread::park();
            }
        }
        write_completion_receipt_if_requested();
    }

    #[cfg(unix)]
    #[test]
    fn exact_test_watchdog_times_out_and_reaps_stalled_child() {
        const CHILD_TEST: &str = "sync_store::tests::watchdog_forced_stall_child";
        let temp = TempDir::new().expect("watchdog tempdir");
        let receipt_path = temp.path().join("completion-receipt");
        let ready_path = temp.path().join("stall-ready");
        let timeout = Duration::from_secs(1);
        let child_environment = [
            (WATCHDOG_FORCE_STALL_ENV, OsString::from("1")),
            (
                WATCHDOG_STALL_READY_PATH_ENV,
                ready_path.as_os_str().to_owned(),
            ),
        ];

        let started = Instant::now();
        let outcome = run_exact_current_test_with_watchdog(
            CHILD_TEST,
            timeout,
            &child_environment,
            &receipt_path,
        )
        .expect("watch forced-stall child");
        let elapsed = started.elapsed();

        let (pid, status) = match outcome {
            ExactTestOutcome::TimedOut { pid, status } => (pid, status),
            ExactTestOutcome::Completed { status, receipt } => {
                panic!("forced-stall child completed: status={status}, receipt={receipt:?}")
            }
        };
        assert!(!status.success(), "killed child reported success: {status}");
        assert_eq!(
            fs::read(&ready_path).expect("read forced-stall readiness"),
            b"stalled\n"
        );
        assert_eq!(
            completion_receipt(&receipt_path).expect("inspect absent completion receipt"),
            CompletionReceipt::Missing
        );
        assert!(elapsed >= timeout, "watchdog returned before its deadline");
        assert!(
            elapsed < timeout + Duration::from_secs(5),
            "watchdog exceeded its short containment bound: {elapsed:?}"
        );

        let mut wait_status = 0;
        // SAFETY: `pid` came from our child, and the status pointer is valid for this call.
        let child_pid = libc::pid_t::try_from(pid).expect("child PID fits pid_t");
        let wait_result = unsafe { libc::waitpid(child_pid, &mut wait_status, libc::WNOHANG) };
        let wait_error = io::Error::last_os_error();
        assert_eq!(
            wait_result, -1,
            "child remained waitable after watchdog reap"
        );
        assert_eq!(
            wait_error.raw_os_error(),
            Some(libc::ECHILD),
            "watchdog did not fully reap child {pid}: {wait_error}"
        );
    }

    #[cfg(target_os = "linux")]
    struct SleepChild(Child);

    #[cfg(target_os = "linux")]
    impl SleepChild {
        fn spawn() -> Self {
            Self(
                Command::new("sleep")
                    .arg("60")
                    .spawn()
                    .expect("spawn claim holder process"),
            )
        }

        fn identity(&self) -> ClaimProcessIdentity {
            ClaimProcessIdentity {
                pid: self.0.id(),
                process_start_time: Some(
                    crate::agent_lifecycle::process_start_time(self.0.id())
                        .expect("read claim holder process identity"),
                ),
            }
        }

        fn terminate(&mut self) {
            self.0.kill().expect("terminate claim holder process");
            self.0.wait().expect("reap claim holder process");
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for SleepChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn test_timing() -> ClaimTiming {
        ClaimTiming::new(10, 20).expect("valid test timing")
    }

    #[test]
    fn issue_84_stale_claim_is_rejected_by_existing_only_gate() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let store = SyncStore::open(&repo_path).expect("open claims");
        let claim = store
            .claim_paths_with_timing_at("owner", ["src"], test_timing(), 100)
            .expect("timed claim")
            .claim;
        let error = lock_existing_authenticated_claims(
            &repo_path,
            vec![ExistingClaimBindingRequest {
                agent_id: claim.agent_id.clone(),
                token: claim.token,
                paths: claim.paths.clone(),
            }],
        )
        .expect_err("stale claim must stop the harness");
        assert!(error.to_string().contains("not live"));
    }

    #[test]
    fn issue_84_takeover_lineage_rejects_superseded_token() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let store = SyncStore::open(&repo_path).expect("open claims");
        let prior = store
            .claim_paths_with_timing_at("owner", ["src"], test_timing(), 100)
            .expect("timed claim")
            .claim;
        store
            .sweep_stale_at(120)
            .expect("persist takeover eligibility");
        store
            .takeover_at(prior.token, "successor", None, 121)
            .expect("takeover");
        let error = lock_existing_authenticated_claims(
            &repo_path,
            vec![ExistingClaimBindingRequest {
                agent_id: prior.agent_id.clone(),
                token: prior.token,
                paths: prior.paths.clone(),
            }],
        )
        .expect_err("superseded predecessor must stop the harness");
        assert!(error.to_string().contains("superseded"));
    }

    fn authenticated_claims_state(store: &SyncStore) -> AuthenticatedClaimsState {
        let lock = store.state.lock().expect("claims lock");
        store
            .open_authenticated_store(&lock)
            .expect("authenticated claims")
            .current()
            .value
            .clone()
    }

    fn commit_unvalidated_authenticated_state(
        store: &SyncStore,
        mutate: impl FnOnce(&mut AuthenticatedClaimsState),
    ) {
        let lock = store.state.lock().expect("claims lock");
        let mut authenticated = store
            .open_authenticated_store(&lock)
            .expect("authenticated claims");
        let revision = authenticated
            .current()
            .value
            .snapshot_revision
            .checked_add(1)
            .expect("test revision");
        let mut value = authenticated.current().value.clone();
        value.snapshot_revision = revision;
        mutate(&mut value);
        authenticated
            .commit(revision, value)
            .expect("commit signed malformed test state");
    }

    #[test]
    fn claim_timing_rejects_zero_equal_reversed_and_over_bound_values() {
        assert!(ClaimTiming::new(0, 2).is_err());
        assert!(ClaimTiming::new(1, 0).is_err());
        assert!(ClaimTiming::new(2, 2).is_err());
        assert!(ClaimTiming::new(3, 2).is_err());
        assert!(
            ClaimTiming::new(MAX_CLAIM_TIMING_SECONDS + 1, MAX_CLAIM_TIMING_SECONDS + 1).is_err()
        );
        assert!(ClaimTiming::new(1, MAX_CLAIM_TIMING_SECONDS + 1).is_err());
    }

    #[test]
    fn liveness_defaults_and_exact_stale_boundary_are_deterministic() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let store = SyncStore::open(&repo_path).expect("open claims");
        let claim = store
            .claim_paths_with_timing_at("owner", ["src"], test_timing(), 100)
            .expect("timed claim")
            .claim;

        assert_eq!(
            store.liveness_snapshot_at(109).expect("fresh")[0].state,
            ClaimLivenessState::Fresh
        );
        assert_eq!(
            store.liveness_snapshot_at(110).expect("due")[0].state,
            ClaimLivenessState::HeartbeatDue
        );
        assert_eq!(
            store.liveness_snapshot_at(119).expect("still due")[0].state,
            ClaimLivenessState::HeartbeatDue
        );
        assert_eq!(
            store
                .liveness_snapshot_at(120)
                .expect("exact stale boundary")[0]
                .state,
            ClaimLivenessState::Stale
        );
        assert_eq!(
            store.owner_of("src/lib.rs").expect("owner").owner,
            Some("owner".to_string())
        );
        assert_eq!(claim.token.get(), 1);
    }

    #[test]
    fn heartbeat_before_sweep_refreshes_but_eligibility_is_sticky_after_sweep() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let store = SyncStore::open(&repo_path).expect("open claims");
        let claim = store
            .claim_paths_with_timing_at("owner", ["src"], test_timing(), 100)
            .expect("timed claim")
            .claim;

        let refreshed = store
            .heartbeat_at(claim.token, "owner", None, 119)
            .expect("heartbeat before sweep");
        assert_eq!(refreshed.state, ClaimLivenessState::Fresh);
        assert!(store
            .sweep_stale_at(138)
            .expect("not yet stale")
            .newly_takeover_eligible
            .is_empty());
        let swept = store.sweep_stale_at(139).expect("exact stale sweep");
        assert_eq!(
            swept.newly_takeover_eligible,
            vec![canonical_claim_id(claim.token)]
        );
        assert_eq!(swept.claims[0].state, ClaimLivenessState::TakeoverEligible);
        assert_eq!(
            store.owner_of("src/lib.rs").expect("owner remains").owner,
            Some("owner".to_string())
        );

        let late = store
            .heartbeat_at(claim.token, "owner", None, 140)
            .expect_err("sticky eligibility rejects late heartbeat");
        assert!(late.to_string().contains("cannot be revived"));
        assert_eq!(
            store.liveness_snapshot_at(140).expect("still eligible")[0].state,
            ClaimLivenessState::TakeoverEligible
        );
    }

    #[test]
    fn no_op_sweep_does_not_advance_authenticated_revision() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let store = SyncStore::open(&repo_path).expect("open claims");
        store
            .claim_paths_with_timing_at("owner", ["src"], test_timing(), 100)
            .expect("timed claim");
        let before_fresh_sweep = authenticated_claims_state(&store).snapshot_revision;
        assert!(store
            .sweep_stale_at(119)
            .expect("fresh no-op sweep")
            .newly_takeover_eligible
            .is_empty());
        assert_eq!(
            authenticated_claims_state(&store).snapshot_revision,
            before_fresh_sweep
        );

        store.sweep_stale_at(120).expect("eligibility commit");
        let before_repeat = authenticated_claims_state(&store).snapshot_revision;
        assert!(store
            .sweep_stale_at(121)
            .expect("eligible no-op sweep")
            .newly_takeover_eligible
            .is_empty());
        assert_eq!(
            authenticated_claims_state(&store).snapshot_revision,
            before_repeat
        );
    }

    #[test]
    fn takeover_is_atomic_and_preserves_auditable_lineage() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let store = SyncStore::open(&repo_path).expect("open claims");
        let prior = store
            .claim_paths_with_timing_at("owner", ["src", "README.md"], test_timing(), 100)
            .expect("timed claim")
            .claim;
        store.sweep_stale_at(120).expect("mark eligible");

        let outcome = store
            .takeover_at(prior.token, "successor", None, 121)
            .expect("take over stale claim");

        assert_eq!(outcome.superseded_claim, prior);
        assert_eq!(outcome.claim.token.get(), 2);
        assert_eq!(outcome.claim.agent_id, "successor");
        assert_eq!(outcome.claim.paths, prior.paths);
        assert_eq!(outcome.liveness.state, ClaimLivenessState::Fresh);
        assert_eq!(
            outcome.liveness.supersedes.as_deref(),
            Some(canonical_claim_id(prior.token).as_str())
        );
        assert_eq!(outcome.lineage.prior_agent_id, "owner");
        assert_eq!(outcome.lineage.successor_agent_id, "successor");
        assert_eq!(outcome.lineage.path_count, prior.paths.len());
        assert_eq!(
            store.owner_of("src/lib.rs").expect("successor owner").owner,
            Some("successor".to_string())
        );
        let state = authenticated_claims_state(&store);
        assert_eq!(state.claims, vec![outcome.claim]);
        assert_eq!(state.supersessions.len(), 1);
    }

    #[test]
    fn takeover_telemetry_failure_reports_durable_successor_and_lineage() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let store = SyncStore::open(&repo_path).expect("open claims");
        let prior = store
            .claim_paths_with_timing_at("owner", ["src"], test_timing(), 100)
            .expect("timed claim")
            .claim;
        store.sweep_stale_at(120).expect("mark eligible");
        set_record_claim_fault();

        let error = store
            .takeover_at(prior.token, "successor", None, 121)
            .expect_err("takeover telemetry fault");
        let message = format!("{error:#}");
        assert!(message.contains("successor claim token 2 remains durable"));
        assert!(message.contains("explicitly release token 2"));
        let state = authenticated_claims_state(&store);
        assert_eq!(state.claims.len(), 1);
        assert_eq!(state.claims[0].token.get(), 2);
        assert_eq!(state.claims[0].agent_id, "successor");
        assert_eq!(state.supersessions.len(), 1);
    }

    #[test]
    fn legacy_claim_is_readable_but_blocks_mutation_until_exact_owner_heartbeat() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let store = SyncStore::open(&repo_path).expect("open claims");
        let legacy_claim = PathClaim {
            token: ClaimToken::from_u64(1),
            agent_id: "legacy-owner".to_string(),
            paths: vec![PathBuf::from("src")],
        };
        let lock = store.state.lock().expect("claims lock");
        store
            .save_snapshot(
                &lock,
                SyncSnapshot {
                    next_token: 2,
                    claims: vec![legacy_claim.clone()],
                },
            )
            .expect("save legacy-shaped authenticated snapshot");
        drop(lock);

        let report = store.liveness_snapshot_at(100).expect("legacy liveness");
        assert_eq!(report[0].claim, legacy_claim);
        assert_eq!(report[0].state, ClaimLivenessState::Unknown);
        assert!(store
            .claim_paths_with_timing_at("other", ["README.md"], test_timing(), 100)
            .expect_err("ambiguous legacy state blocks ordinary claim")
            .to_string()
            .contains("ambiguous liveness"));
        assert!(store
            .sweep_stale_at(100)
            .expect_err("ambiguous legacy state blocks sweep")
            .to_string()
            .contains("ambiguous liveness"));
        assert!(store
            .takeover_at(legacy_claim.token, "other", None, 100)
            .expect_err("ambiguous legacy state blocks takeover")
            .to_string()
            .contains("ambiguous liveness"));
        assert!(store
            .heartbeat_at(legacy_claim.token, "not-owner", None, 100)
            .expect_err("wrong owner cannot initialize")
            .to_string()
            .contains("does not exactly match"));

        let initialized = store
            .heartbeat_at(legacy_claim.token, "legacy-owner", Some(test_timing()), 100)
            .expect("exact owner initializes legacy metadata");
        assert_eq!(initialized.state, ClaimLivenessState::Fresh);
        store
            .claim_paths_with_timing_at("other", ["README.md"], test_timing(), 101)
            .expect("unambiguous state permits disjoint claim");
    }

    #[test]
    fn future_heartbeat_and_clock_rollback_fail_closed_without_mutation() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let store = SyncStore::open(&repo_path).expect("open claims");
        let claim = store
            .claim_paths_with_timing_at("owner", ["src"], test_timing(), 200)
            .expect("future claim")
            .claim;
        let before = authenticated_claims_state(&store);

        let report = store.liveness_snapshot_at(199).expect("future report");
        assert_eq!(report[0].state, ClaimLivenessState::Unknown);
        assert!(report[0]
            .ambiguity
            .as_deref()
            .is_some_and(|message| message.contains("precedes heartbeat")));
        assert!(store
            .heartbeat_at(claim.token, "owner", None, 199)
            .expect_err("rollback heartbeat")
            .to_string()
            .contains("move backward"));
        assert!(store
            .sweep_stale_at(199)
            .expect_err("future state blocks sweep")
            .to_string()
            .contains("ambiguous liveness"));
        assert_eq!(authenticated_claims_state(&store), before);
    }

    #[test]
    fn concurrent_takeovers_commit_exactly_one_successor() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let store = SyncStore::open(&repo_path).expect("open claims");
        let prior = store
            .claim_paths_with_timing_at("owner", ["src"], test_timing(), 100)
            .expect("timed claim")
            .claim;
        store.sweep_stale_at(120).expect("mark eligible");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut workers = Vec::new();
        for agent in ["contender-b", "contender-a"] {
            let worker_store = store.clone();
            let worker_barrier = barrier.clone();
            workers.push(std::thread::spawn(move || {
                worker_barrier.wait();
                worker_store.takeover_at(prior.token, agent, None, 121)
            }));
        }
        barrier.wait();
        let outcomes = workers
            .into_iter()
            .map(|worker| worker.join().expect("takeover worker"))
            .collect::<Vec<_>>();

        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert_eq!(
            outcomes.iter().filter(|outcome| outcome.is_err()).count(),
            1
        );
        let state = authenticated_claims_state(&store);
        assert_eq!(state.claims.len(), 1);
        assert_eq!(state.claims[0].token.get(), 2);
        assert_eq!(state.supersessions.len(), 1);
        assert_eq!(state.supersessions[0].prior_token, prior.token);
        assert_eq!(
            state.supersessions[0].successor_token,
            state.claims[0].token
        );
    }

    #[test]
    fn authenticated_schema_accepts_missing_legacy_sidecars_and_rejects_unknown_fields() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let store = SyncStore::open(&repo_path).expect("open claims");
        store
            .claim_paths_with_timing_at("owner", ["src"], test_timing(), 100)
            .expect("timed claim");
        let value = authenticated_claims_state(&store);
        let encoded = serde_json::to_value(&value).expect("authenticated value");
        let mut unknown_liveness = encoded.clone();
        unknown_liveness["liveness"][0]["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<AuthenticatedClaimsState>(unknown_liveness).is_err());

        let mut legacy = encoded;
        let object = legacy.as_object_mut().expect("object");
        object.remove("liveness");
        object.remove("supersessions");
        let decoded: AuthenticatedClaimsState =
            serde_json::from_value(legacy.clone()).expect("legacy defaults");
        assert!(decoded.liveness.is_empty());
        assert!(decoded.supersessions.is_empty());

        legacy
            .as_object_mut()
            .expect("object")
            .insert("unexpected".to_string(), serde_json::json!(true));
        assert!(serde_json::from_value::<AuthenticatedClaimsState>(legacy).is_err());
    }

    #[test]
    fn signed_duplicate_liveness_and_malformed_lineage_fail_on_open() {
        let duplicate_temp = TempDir::new().expect("duplicate tempdir");
        let duplicate_repo = duplicate_temp.path().join("repo");
        WorktreeManager::init_repository(&duplicate_repo, "main").expect("init duplicate repo");
        let duplicate_store = SyncStore::open(&duplicate_repo).expect("open duplicate claims");
        duplicate_store
            .claim_paths_with_timing_at("owner", ["src"], test_timing(), 100)
            .expect("timed duplicate claim");
        duplicate_store
            .claim_paths_with_timing_at("other", ["tests"], test_timing(), 100)
            .expect("second timed duplicate claim");
        commit_unvalidated_authenticated_state(&duplicate_store, |state| {
            state.liveness[1] = state.liveness[0].clone();
        });
        let duplicate_error = SyncStore::open(&duplicate_repo)
            .expect_err("signed duplicate liveness must fail closed");
        assert!(format!("{duplicate_error:#}").contains("duplicate liveness metadata"));

        let lineage_temp = TempDir::new().expect("lineage tempdir");
        let lineage_repo = lineage_temp.path().join("repo");
        WorktreeManager::init_repository(&lineage_repo, "main").expect("init lineage repo");
        let lineage_store = SyncStore::open(&lineage_repo).expect("open lineage claims");
        let active = lineage_store
            .claim_paths_with_timing_at("owner", ["src"], test_timing(), 100)
            .expect("timed lineage claim")
            .claim;
        commit_unvalidated_authenticated_state(&lineage_store, |state| {
            state.next_token = 3;
            state.supersessions.push(AuthenticatedClaimSupersession {
                prior_token: active.token,
                prior_claim_id: canonical_claim_id(active.token),
                prior_agent_id: active.agent_id.clone(),
                successor_token: ClaimToken::from_u64(2),
                successor_claim_id: canonical_claim_id(ClaimToken::from_u64(2)),
                successor_agent_id: "successor".to_string(),
                path_count: active.paths.len(),
                paths_checksum: claim_paths_checksum(&active.paths).expect("path checksum"),
                superseded_at_unix_seconds: 120,
            });
        });
        let lineage_error =
            SyncStore::open(&lineage_repo).expect_err("active predecessor must fail closed");
        assert!(format!("{lineage_error:#}").contains("predecessor remains active"));
    }

    #[test]
    fn validator_rejects_early_eligibility_and_successor_time_mismatch() {
        let claim = PathClaim {
            token: ClaimToken::from_u64(1),
            agent_id: "owner".to_string(),
            paths: vec![PathBuf::from("src")],
        };
        let mut early =
            new_claim_liveness(&claim, test_timing(), 100, None).expect("claim liveness");
        early.takeover_eligible_since_unix_seconds = Some(119);
        assert!(
            validate_claim_liveness(2, std::slice::from_ref(&claim), &[early], &[])
                .expect_err("early eligibility")
                .to_string()
                .contains("before the stale threshold")
        );

        let successor = PathClaim {
            token: ClaimToken::from_u64(2),
            agent_id: "successor".to_string(),
            paths: claim.paths.clone(),
        };
        let prior_id = canonical_claim_id(claim.token);
        let successor_liveness =
            new_claim_liveness(&successor, test_timing(), 121, Some(prior_id.clone()))
                .expect("successor liveness");
        let history = AuthenticatedClaimSupersession {
            prior_token: claim.token,
            prior_claim_id: prior_id,
            prior_agent_id: claim.agent_id,
            successor_token: successor.token,
            successor_claim_id: canonical_claim_id(successor.token),
            successor_agent_id: successor.agent_id.clone(),
            path_count: successor.paths.len(),
            paths_checksum: claim_paths_checksum(&successor.paths).expect("path checksum"),
            superseded_at_unix_seconds: 120,
        };
        assert!(validate_claim_liveness(
            3,
            std::slice::from_ref(&successor),
            &[successor_liveness],
            std::slice::from_ref(&history),
        )
        .expect_err("successor time mismatch")
        .to_string()
        .contains("audited lineage"));
        assert!(
            ensure_supersession_time_not_future(std::slice::from_ref(&history), 119)
                .expect_err("future lineage time")
                .to_string()
                .contains("ambiguous clock state")
        );
        assert!(validate_claim_liveness(2, &[], &[], &[history])
            .expect_err("historical token reuse guard")
            .to_string()
            .contains("reaches or exceeds next_token"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn run_owned_status_distinguishes_live_holder_from_leftover_after_process_exit() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let store = SyncStore::open(&repo_path).expect("open claims");
        let mut holder = SleepChild::spawn();
        let process = holder.identity();
        let claim = store
            .claim_paths_with_telemetry_thresholds_internal(
                "interrupted-assignment",
                ["README.md"],
                MegafileThresholds::provisional_bootstrap(),
                ClaimTiming::default(),
                current_unix_seconds().expect("current time"),
                Some(("interrupted-run".to_string(), process)),
            )
            .expect("record run-owned claim")
            .claim;

        let live = store.status_snapshot().expect("status while holder lives");
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].claim, claim);
        assert_eq!(live[0].owner_run_id.as_deref(), Some("interrupted-run"));
        assert_eq!(live[0].owner_run_state, ClaimOwnerRunState::Active);

        holder.terminate();

        let leftover = store.status_snapshot().expect("status after holder exit");
        assert_eq!(leftover.len(), 1);
        assert_eq!(leftover[0].claim, claim);
        assert_eq!(leftover[0].owner_run_state, ClaimOwnerRunState::Interrupted);
        assert_eq!(
            serde_json::to_value(&leftover[0]).expect("serialize leftover claim status")
                ["owner_run_state"],
            "interrupted"
        );
        assert_eq!(
            store.snapshot().expect("retained claim remains active"),
            vec![claim]
        );
    }

    #[cfg(unix)]
    #[test]
    fn locked_authenticated_snapshot_excludes_a_concurrent_claim_writer_until_drop() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let store = SyncStore::open(&repo_path).expect("open claims");
        let boundary = store
            .lock_authenticated_snapshot()
            .expect("lock authenticated claims snapshot");
        assert!(boundary.claims().is_empty());
        boundary.verify().expect("verify claims boundary");

        let lock_error =
            KernelStateLock::try_acquire_exclusive_direct(boundary.state.root(), "claims.lock")
                .expect_err("claims boundary must exclude another writer lock");
        assert!(lock_error.to_string().contains("already held"));

        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (start_tx, start_rx) = std::sync::mpsc::channel();
        let writer = store.clone();
        let writer_thread = std::thread::spawn(move || {
            ready_tx.send(()).expect("signal ready");
            start_rx.recv().expect("receive start");
            writer.with_locked_update(|coordinator, _, _, _| {
                coordinator
                    .claim_paths("neutral-arbiter", ["src"])
                    .map_err(Into::into)
            })
        });
        ready_rx.recv().expect("writer ready");
        start_tx.send(()).expect("start writer");
        drop(boundary);

        let claim = writer_thread
            .join()
            .expect("join writer")
            .expect("claim after boundary release");
        assert_eq!(claim.agent_id, "neutral-arbiter");
        assert_eq!(
            store.snapshot().expect("snapshot after writer"),
            vec![claim]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn claims_wrapper_recovers_nine_metadata_residues_before_inventory() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        drop(SyncStore::open(&repo_path).expect("initialize claims wrapper"));
        let root_path = repo_path
            .join(".git/maco/state")
            .join(ClaimsSnapshotSpec::ROOT_NAME);
        let root = SafeRoot::open_existing(&root_path).expect("claims snapshot root");
        let durable_entries = fs::read_dir(&root_path).expect("durable root").count();
        let logical_hash = sha256_hex(CLAIMS_LOGICAL_ID.as_bytes());
        let targets = [
            format!(".snapshot-locator-{logical_hash}.json"),
            format!(".snapshot-init-{logical_hash}.json"),
            format!(".snapshot-rollover-{logical_hash}.json"),
        ];
        for target in &targets {
            for _ in 0..3 {
                AtomicStateWriter::write_direct_fenced(&root, target, b"partial", || {
                    bail!("injected claims metadata crash")
                })
                .expect_err("leave claims residue");
            }
        }
        assert_eq!(
            fs::read_dir(&root_path)
                .expect("durable root plus residues")
                .count(),
            durable_entries + 9
        );

        let reopened =
            SyncStore::open(&repo_path).expect("claims wrapper scavenges before inventory");

        assert!(reopened.snapshot().expect("claims snapshot").is_empty());
        assert_eq!(
            fs::read_dir(root_path).expect("recovered root").count(),
            durable_entries
        );
    }

    #[test]
    fn retirement_faults_recover_without_an_empty_or_split_brain_window() {
        for fault in [
            LegacyRetirementFaultPoint::Sidecar,
            LegacyRetirementFaultPoint::Intent,
            LegacyRetirementFaultPoint::PendingTombstone,
            LegacyRetirementFaultPoint::ActiveTombstone,
        ] {
            let temp = TempDir::new().expect("tempdir");
            let repo_path = temp.path().join("repo");
            WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
            set_legacy_retirement_fault(fault);
            let error = SyncStore::open(&repo_path).expect_err("fault must interrupt retirement");
            assert!(error
                .to_string()
                .contains("injected legacy retirement fault"));

            let legacy_path = repo_path.join(".git/maco/state/claims.json");
            if matches!(
                fault,
                LegacyRetirementFaultPoint::PendingTombstone
                    | LegacyRetirementFaultPoint::ActiveTombstone
            ) {
                let value: serde_json::Value = serde_json::from_slice(
                    &fs::read(&legacy_path).expect("pending or active tombstone"),
                )
                .expect("tombstone JSON");
                assert_eq!(
                    value.get("version").and_then(serde_json::Value::as_u64),
                    Some(3)
                );
                assert!(serde_json::from_value::<PersistedSyncState>(value).is_err());
            }

            let store = SyncStore::open(&repo_path).expect("forward recover retirement");
            assert!(store.snapshot().expect("snapshot").is_empty());
            let consumer_root =
                repo_path.join(format!(".git/maco/state/{}", ClaimsSnapshotSpec::ROOT_NAME));
            assert!(!consumer_root.join(".legacy-retirement.sidecar").exists());
            assert!(!consumer_root
                .join(".legacy-retirement.intent.json")
                .exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn unmanifested_legacy_claims_refuse_before_auth_bootstrap() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let state_root = repo_path.join(".git/maco/state");
        fs::create_dir_all(&state_root).expect("state root");
        fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700)).expect("state mode");
        fs::write(state_root.join("claims.json"), b"{\"version\":2}\n")
            .expect("unmanifested legacy");
        fs::set_permissions(
            state_root.join("claims.json"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("legacy mode");

        let error = SyncStore::open(&repo_path).expect_err("migration evidence is mandatory");
        assert!(error.to_string().contains("signed migration manifest"));
        assert!(!state_root.join(authentication_key_file_name()).exists());
        assert!(!state_root.join("repository_auth_epoch_v1").exists());
        assert!(!state_root.join(ClaimsSnapshotSpec::ROOT_NAME).exists());
    }

    #[cfg(unix)]
    #[test]
    fn manifest_bound_operator_attested_claims_v1_is_adopted_exactly_once() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repository = crate::git_repository::open(&repo_path).expect("repository");
        let state_root = SafeRoot::open_or_create(repository.commondir().join("maco/state"))
            .expect("state root");
        AtomicStateWriter::write_direct(&state_root, "claims.json", ISSUE33_CLAIMS_V1)
            .expect("literal claims-v1");
        let options = StateMigrationOptions {
            acknowledge_unauthenticated_claims_v1: true,
            expected_claims_v1_sha256: Some(ISSUE33_CLAIMS_V1_SHA256.to_string()),
        };
        migrate_repository_state_with_options(&repo_path, true, &options)
            .expect("signed operator-attested migration");

        let store = SyncStore::open(&repo_path).expect("manifest-bound claims-v1 adoption");
        let lock = store.state.lock().expect("claims lock");
        let snapshot = store.load_snapshot(&lock).expect("authenticated snapshot");
        assert_eq!(snapshot.next_token, 67);
        assert_eq!(
            snapshot
                .claims
                .iter()
                .map(|claim| claim.token.get())
                .collect::<Vec<_>>(),
            vec![20, 44, 66]
        );
        drop(lock);
        assert_eq!(
            store.owner_of(".maco").expect("fixture owner").owner,
            Some("o1-worktree-cleanup".to_string())
        );

        let tombstone: serde_json::Value = serde_json::from_slice(
            &fs::read(state_root.path().join("claims.json")).expect("active tombstone"),
        )
        .expect("tombstone JSON");
        assert_eq!(tombstone["version"], 3);
        let reopened = SyncStore::open(&repo_path).expect("authenticated reopen");
        assert_eq!(
            reopened.snapshot().expect("reopened claims"),
            snapshot.claims
        );
    }

    #[cfg(unix)]
    #[test]
    fn unauthenticated_version_three_tombstone_cannot_bootstrap_authentication_state() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let state_root = repo_path.join(".git/maco/state");
        fs::create_dir_all(&state_root).expect("state root");
        fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700)).expect("state mode");
        fs::write(state_root.join("claims.json"), b"{\"version\":3}\n")
            .expect("forged version-three marker");
        fs::set_permissions(
            state_root.join("claims.json"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("marker mode");

        let error = SyncStore::open(&repo_path).expect_err("unsigned marker must fail closed");
        let chain = format!("{error:#}");
        assert!(
            chain.contains("key") || chain.contains("authentication"),
            "unexpected error: {chain}"
        );
        assert!(!state_root.join(authentication_key_file_name()).exists());
        assert!(!state_root.join("repository_auth_epoch_v1").exists());
        assert!(!state_root.join(ClaimsSnapshotSpec::ROOT_NAME).exists());
    }

    #[test]
    fn active_retirement_rejects_generation_and_identity_rollback() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let store = SyncStore::open(&repo_path).expect("open store");
        store
            .claim_paths("agent-a", ["README.md"])
            .expect("advance snapshot");
        let lock = store.state.lock().expect("claims lock");
        let authenticated = store
            .open_authenticated_store(&lock)
            .expect("authenticated claims");
        let generation = authenticated.current().generation;
        assert!(generation > 1);
        let mut foreign_identity = authenticated.identity().clone();
        foreign_identity.journal_id = "0".repeat(64);

        let rollback = finalize_legacy_retirement::<ClaimsSnapshotSpec>(
            &repo_path,
            "claims",
            "claims.json",
            LEGACY_RETIREMENT_DOMAIN,
            &foreign_identity,
            generation - 1,
            &|| store.state.verify_lock(&lock),
        )
        .expect_err("generation rollback must fail regardless of identity");
        assert!(rollback.to_string().contains("generation rolled back"));

        let identity_swap = finalize_legacy_retirement::<ClaimsSnapshotSpec>(
            &repo_path,
            "claims",
            "claims.json",
            LEGACY_RETIREMENT_DOMAIN,
            &foreign_identity,
            generation,
            &|| store.state.verify_lock(&lock),
        )
        .expect_err("same-generation identity swap must fail");
        assert!(identity_swap
            .to_string()
            .contains("identity changed without increasing"));
    }

    #[cfg(unix)]
    #[test]
    fn retirement_write_fence_rejects_rebound_legacy_lock_path() {
        use std::cell::Cell;

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("repo");
        let state =
            RepositoryStateRoot::open(&repo, "claims.json", "claims.lock").expect("state root");
        let lock = state.lock().expect("claims lock");
        let lock_path = lock._lock.path().to_path_buf();
        let moved = lock_path.with_file_name("claims.lock.retirement-original");
        let calls = Cell::new(0_u32);
        let fence = || {
            let call = calls.get();
            calls.set(call + 1);
            if call == 1 {
                fs::rename(&lock_path, &moved).expect("move lock pathname");
                fs::write(&lock_path, b"").expect("replacement lock");
                fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))
                    .expect("replacement mode");
            }
            state.verify_lock(&lock)
        };
        let error = match prepare_legacy_retirement::<ClaimsSnapshotSpec>(
            &repo_path,
            "claims",
            "claims.json",
            LEGACY_RETIREMENT_DOMAIN,
            &fence,
        ) {
            Ok(_) => panic!("rebound legacy lock must fence retirement publication"),
            Err(error) => error,
        };
        let message = format!("{error:#}");
        assert!(
            message.contains("lock path") || message.contains("opened descriptor"),
            "unexpected error: {error:#}"
        );
        assert!(!state.state_path().exists());
    }

    #[test]
    fn claim_persists_and_blocks_overlapping_paths() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");

        let store = SyncStore::open(&repo_path).expect("open store");
        let claim = store
            .claim_paths("agent-a", ["src/../README.md"])
            .expect("claim readme");

        assert_eq!(claim.token.get(), 1);
        assert_eq!(claim.paths, vec![PathBuf::from("README.md")]);
        assert!(store.state_path().exists());

        let reopened = SyncStore::open(&repo_path).expect("reopen store");
        let claims = reopened.snapshot().expect("snapshot");
        assert_eq!(claims, vec![claim]);

        let error = reopened
            .claim_paths("agent-b", ["README.md"])
            .expect_err("overlap should fail");
        assert!(error.to_string().contains("already claimed by agent-a"));
        let assessment = MegafileStore::open_existing(&repo_path)
            .expect("query telemetry")
            .expect("initialized telemetry")
            .assess_path("README.md")
            .expect("assess path")
            .expect("recorded claim");
        assert_eq!(assessment.claims_in_window, 1);
    }

    #[test]
    fn post_claim_telemetry_failure_reports_durable_recovery_evidence() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let store = SyncStore::open(&repo_path).expect("open store");
        let thresholds = MegafileThresholds {
            calibration: MegafileThresholdCalibration::Configured,
            file_bytes: 1,
            ..MegafileThresholds::provisional_bootstrap()
        };
        set_record_claim_fault();

        let error = store
            .claim_paths_with_telemetry_thresholds("agent-a", ["src/lib.rs"], thresholds)
            .expect_err("telemetry fault must fail closed");
        let message = format!("{error:#}");

        assert!(message.contains("claim token 1 remains durable"));
        assert!(message.contains("explicitly release token 1"));
        let claims = store.snapshot().expect("durable claim evidence");
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].token.get(), 1);
        assert_eq!(claims[0].paths, vec![PathBuf::from("src/lib.rs")]);
        assert!(MegafileStore::open_existing(&repo_path)
            .expect("query telemetry")
            .expect("initialized telemetry")
            .assess_path("src/lib.rs")
            .expect("assessment")
            .is_none());
    }

    #[test]
    fn oversized_directory_expansion_fails_closed_after_durable_claim() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        fs::create_dir_all(repo_path.join("root")).expect("create claimed directory");
        let telemetry = MegafileStore::open(&repo_path).expect("open telemetry");
        telemetry
            .record_file_samples(
                (0..=MAX_CLAIM_TELEMETRY_TARGETS).map(|index| FileSizeSample {
                    path: PathBuf::from(format!("root/file-{index:04}.rs")),
                    bytes: 1,
                    lines: 1,
                }),
            )
            .expect("seed pathological authenticated file subjects");
        let before = telemetry.report().expect("telemetry before broad claim");
        let store = SyncStore::open(&repo_path).expect("open claims");

        let error = store
            .claim_paths_with_telemetry("root-agent", ["root"])
            .expect_err("oversized expansion must fail closed");
        let message = format!("{error:#}");
        assert!(message.contains(&format!(
            "megafile claim telemetry expansion exceeds its {}-target limit",
            MAX_CLAIM_TELEMETRY_TARGETS
        )));
        assert!(message.contains("claim token 1 remains durable"));
        assert!(message.contains("explicitly release token 1"));

        let claims = store.snapshot().expect("durable broad claim");
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].token.get(), 1);
        assert_eq!(claims[0].paths, vec![PathBuf::from("root")]);
        let after = MegafileStore::open_existing(&repo_path)
            .expect("query telemetry")
            .expect("initialized telemetry")
            .report()
            .expect("telemetry after broad claim");
        assert_eq!(after.next_record_sequence, before.next_record_sequence);
        assert_eq!(after.retained_records, before.retained_records);
        assert!(after.records.iter().all(|record| !matches!(
            record.kind,
            crate::megafile::MegafileRecordKind::Claim { .. }
        )));
    }

    #[test]
    fn ambiguous_missing_path_fails_closed_after_durable_claim() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let telemetry = MegafileStore::open(&repo_path).expect("open telemetry");
        telemetry
            .record_file_samples([
                FileSizeSample {
                    path: PathBuf::from("missing"),
                    bytes: 1,
                    lines: 1,
                },
                FileSizeSample {
                    path: PathBuf::from("missing/child.rs"),
                    bytes: 1,
                    lines: 1,
                },
            ])
            .expect("seed ambiguous missing-path evidence");
        let before = telemetry
            .report()
            .expect("telemetry before ambiguous claim");
        let store = SyncStore::open(&repo_path).expect("open claims");

        let error = store
            .claim_paths_with_telemetry("ambiguous-agent", ["missing"])
            .expect_err("ambiguous missing path must fail closed");
        let message = format!("{error:#}");
        assert!(message.contains(
            "authenticated megafile telemetry contains both an exact file subject and descendant file subjects"
        ));
        assert!(message.contains("claim token 1 remains durable"));
        assert!(message.contains("explicitly release token 1"));

        let claims = store.snapshot().expect("durable ambiguous claim");
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].paths, vec![PathBuf::from("missing")]);
        let after = MegafileStore::open_existing(&repo_path)
            .expect("query telemetry")
            .expect("initialized telemetry")
            .report()
            .expect("telemetry after ambiguous claim");
        assert_eq!(after.next_record_sequence, before.next_record_sequence);
        assert_eq!(after.retained_records, before.retained_records);
    }

    #[test]
    fn repository_root_claim_is_rejected_without_telemetry_mutation() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let telemetry = MegafileStore::open(&repo_path).expect("open telemetry");
        telemetry
            .record_file_samples([FileSizeSample {
                path: PathBuf::from("src/lib.rs"),
                bytes: 1,
                lines: 1,
            }])
            .expect("seed telemetry");
        let before = telemetry.report().expect("telemetry before root claim");
        let store = SyncStore::open(&repo_path).expect("open claims");

        let error = store
            .claim_paths_with_telemetry("root-agent", ["."])
            .expect_err("repository root claim must be rejected");

        assert!(error.to_string().contains("path cannot be empty"));
        assert!(store
            .snapshot()
            .expect("claims after rejected root")
            .is_empty());
        let after = MegafileStore::open_existing(&repo_path)
            .expect("query telemetry")
            .expect("initialized telemetry")
            .report()
            .expect("telemetry after rejected root claim");
        assert_eq!(after.next_record_sequence, before.next_record_sequence);
        assert_eq!(after.retained_records, before.retained_records);
    }

    #[test]
    fn claim_time_warning_contains_typed_authenticated_assessment() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let store = SyncStore::open(&repo_path).expect("open store");
        let mut final_outcome = None;

        for index in 0..MegafileThresholds::default().claim_count {
            let outcome = store
                .claim_paths_with_telemetry(format!("agent-{index}"), ["src/hotspot.rs"])
                .expect("claim with telemetry");
            store.release(outcome.claim.token).expect("release claim");
            final_outcome = Some(outcome);
        }

        let outcome = final_outcome.expect("final outcome");
        assert_eq!(outcome.warnings.len(), 1);
        assert_eq!(outcome.warnings[0].version, 1);
        assert_eq!(outcome.warnings[0].path, PathBuf::from("src/hotspot.rs"));
        assert!(outcome.warnings[0].assessment.is_megafile);
        assert!(outcome.warnings[0]
            .assessment
            .signals
            .iter()
            .any(|signal| matches!(signal, crate::megafile::MegafileSignal::ClaimCount { .. })));
    }

    #[test]
    fn configured_threshold_changes_claim_time_warning_without_changing_defaults() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        MegafileStore::open(&repo_path)
            .expect("open telemetry")
            .record_file_samples([
                FileSizeSample {
                    path: PathBuf::from("src/default.rs"),
                    bytes: 128,
                    lines: 4,
                },
                FileSizeSample {
                    path: PathBuf::from("src/configured.rs"),
                    bytes: 128,
                    lines: 4,
                },
            ])
            .expect("record samples");
        let store = SyncStore::open(&repo_path).expect("open claims");

        let default = store
            .claim_paths_with_telemetry("default-agent", ["src/default.rs"])
            .expect("default claim");
        assert!(default.warnings.is_empty());

        let configured_thresholds = MegafileThresholds {
            calibration: MegafileThresholdCalibration::Configured,
            file_bytes: 64,
            ..MegafileThresholds::provisional_bootstrap()
        };
        let configured = store
            .claim_paths_with_telemetry_thresholds(
                "configured-agent",
                ["src/configured.rs"],
                configured_thresholds,
            )
            .expect("configured claim");

        assert_eq!(configured.warnings.len(), 1);
        assert!(configured.warnings[0]
            .assessment
            .signals
            .iter()
            .any(|signal| matches!(
                signal,
                crate::megafile::MegafileSignal::FileBytes {
                    observed: 128,
                    threshold: 64
                }
            )));
    }

    #[test]
    fn invalid_configured_threshold_is_rejected_before_claim_persistence() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let store = SyncStore::open(&repo_path).expect("open claims");
        let mut thresholds = MegafileThresholds::provisional_bootstrap();
        thresholds.calibration = MegafileThresholdCalibration::Configured;
        thresholds.file_bytes = 0;

        let error = store
            .claim_paths_with_telemetry_thresholds("agent-a", ["src/lib.rs"], thresholds)
            .expect_err("invalid thresholds must fail before claim");

        assert!(error
            .to_string()
            .contains("configured megafile claim thresholds are invalid"));
        assert!(store.snapshot().expect("claim snapshot").is_empty());
        assert!(MegafileStore::open_existing(&repo_path)
            .expect("query telemetry")
            .is_none());
    }

    #[test]
    fn release_by_token_updates_persisted_state() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");

        let store = SyncStore::open(&repo_path).expect("open store");
        let claim = store
            .claim_paths("agent-a", ["src/lib.rs"])
            .expect("claim file");
        let released = store.release(claim.token).expect("release");

        assert_eq!(released, claim);

        let reopened = SyncStore::open(&repo_path).expect("reopen store");
        assert_eq!(
            reopened.snapshot().expect("snapshot"),
            Vec::<PathClaim>::new()
        );

        let next = reopened
            .claim_paths("agent-b", ["src/lib.rs"])
            .expect("claim again");
        assert_eq!(next.token.get(), 2);
    }

    #[test]
    fn release_by_agent_removes_only_that_agents_claims() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");

        let store = SyncStore::open(&repo_path).expect("open store");
        store
            .claim_paths("agent-a", ["src/lib.rs"])
            .expect("claim lib");
        store
            .claim_paths("agent-a", ["README.md"])
            .expect("claim readme");
        let other = store
            .claim_paths("agent-b", ["Cargo.toml"])
            .expect("claim cargo");

        let released = store.release_by_agent("agent-a").expect("release agent");

        assert_eq!(released.len(), 2);
        assert_eq!(store.snapshot().expect("snapshot"), vec![other]);
    }

    #[test]
    fn owner_reports_parent_claims_with_normalized_path() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");

        let store = SyncStore::open(&repo_path).expect("open store");
        store.claim_paths("agent-a", ["src"]).expect("claim src");

        let report = store.owner_of("src/generated/../lib.rs").expect("owner");

        assert_eq!(report.path, PathBuf::from("src/lib.rs"));
        assert_eq!(report.owner, Some("agent-a".to_string()));
    }

    #[test]
    fn linked_worktrees_share_sync_state() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("commit");
        let worktree = WorktreeManager::new(&repo_path)
            .create_for_test(crate::worktree::WorktreeCreateOptions {
                agent_id: "agent-a".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");

        let worktree_store = SyncStore::open(&worktree.path).expect("open worktree store");
        worktree_store
            .claim_paths("agent-a", ["README.md"])
            .expect("claim from worktree");
        let main_store = SyncStore::open(&repo_path).expect("open main store");

        assert_eq!(
            main_store.owner_of("README.md").expect("owner").owner,
            Some("agent-a".to_string())
        );
    }

    #[test]
    fn stable_kernel_lock_is_private_and_keeps_its_inode() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let store = SyncStore::open(&repo_path).expect("open store");
        let lock_path = store
            .state_path()
            .parent()
            .expect("state parent")
            .join("claims.lock");

        assert_eq!(store.snapshot().expect("snapshot"), Vec::<PathClaim>::new());
        let first = identity_for_path(&lock_path).expect("first lock identity");
        assert_eq!(
            store.snapshot().expect("second snapshot"),
            Vec::<PathClaim>::new()
        );
        assert_eq!(
            identity_for_path(&lock_path).expect("second lock identity"),
            first
        );
        #[cfg(unix)]
        assert_eq!(
            fs::symlink_metadata(&lock_path)
                .expect("lock metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn legacy_public_state_directory_fails_closed_without_chmod() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let state_root = repo_path.join(".git/maco/state");
        fs::create_dir_all(&state_root).expect("legacy state root");
        fs::set_permissions(&state_root, fs::Permissions::from_mode(0o755)).expect("legacy mode");

        let error = SyncStore::open(&repo_path).expect_err("legacy mode must fail closed");
        let message = error.to_string();
        assert!(message.contains("Independently verify its ownership and contents"));
        assert!(message.contains("0700"));
        assert!(message.contains("0600"));
        assert_eq!(
            fs::symlink_metadata(&state_root)
                .expect("state metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
    }

    #[cfg(unix)]
    #[test]
    fn retired_legacy_filename_is_not_decodable_as_v2_state() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let store = SyncStore::open(&repo_path).expect("open store");
        let tombstone = fs::read(store.state_path()).expect("retirement tombstone");
        let value: serde_json::Value = serde_json::from_slice(&tombstone).expect("tombstone JSON");
        assert_eq!(value["version"], 3);
        assert!(serde_json::from_slice::<PersistedSyncState>(&tombstone).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn checksum_tamper_and_unsafe_file_types_are_rejected() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let store = SyncStore::open(&repo_path).expect("open store");
        store
            .claim_paths("agent-a", ["README.md"])
            .expect("initial claim");
        let mut state: serde_json::Value =
            serde_json::from_slice(&fs::read(store.state_path()).expect("state"))
                .expect("parse state");
        state["snapshot_generation"] = serde_json::json!(999);
        fs::write(
            store.state_path(),
            serde_json::to_vec_pretty(&state).expect("tampered JSON"),
        )
        .expect("tamper state");
        let error = store.snapshot().expect_err("HMAC tamper");
        assert!(format!("{error:#}").contains("authentication tag"));

        fs::remove_file(store.state_path()).expect("remove tampered state");
        let external = temp.path().join("external-state");
        fs::write(&external, b"{}\n").expect("external state");
        fs::set_permissions(&external, fs::Permissions::from_mode(0o600)).expect("mode");
        symlink(&external, store.state_path()).expect("state symlink");
        assert!(store
            .snapshot()
            .expect_err("symlink state")
            .to_string()
            .contains("regular"));

        fs::remove_file(store.state_path()).expect("remove symlink");
        fs::hard_link(&external, store.state_path()).expect("hardlink state");
        assert!(store
            .snapshot()
            .expect_err("hard-linked state")
            .to_string()
            .contains("exactly one hard link"));

        fs::remove_file(store.state_path()).expect("remove hardlink");
        let path =
            std::ffi::CString::new(store.state_path().as_os_str().as_bytes()).expect("FIFO path");
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        assert!(store
            .snapshot()
            .expect_err("FIFO state")
            .to_string()
            .contains("regular"));
    }

    #[test]
    fn concurrent_claims_are_serialized_without_lost_updates() {
        #[cfg(unix)]
        if env::var_os(WATCHDOG_RECEIPT_PATH_ENV).is_none() {
            const CHILD_TEST: &str =
                "sync_store::tests::concurrent_claims_are_serialized_without_lost_updates";
            const CHILD_TIMEOUT: Duration = Duration::from_secs(120);
            let temp = TempDir::new().expect("concurrent claims watchdog tempdir");
            let receipt_path = temp.path().join("completion-receipt");
            let outcome =
                run_exact_current_test_with_watchdog(CHILD_TEST, CHILD_TIMEOUT, &[], &receipt_path)
                    .expect("run concurrent claims child under watchdog");
            match outcome {
                ExactTestOutcome::Completed { status, receipt } => {
                    assert!(
                        status.success() && receipt == CompletionReceipt::Confirmed,
                        "{CHILD_TEST} completed without exact success evidence: status={status}, receipt={receipt:?}"
                    );
                }
                ExactTestOutcome::TimedOut { pid, status } => {
                    panic!(
                        "{CHILD_TEST} exceeded its {CHILD_TIMEOUT:?} bound; killed and reaped PID {pid} with status {status}"
                    );
                }
            }
            return;
        }

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let store = SyncStore::open(&repo_path).expect("open store");
        let mut workers = Vec::new();
        for index in 0..16usize {
            let store = store.clone();
            workers.push(std::thread::spawn(move || {
                store.claim_paths(
                    format!("agent-{index}"),
                    [format!("generated/path-{index}")],
                )
            }));
        }
        let outcomes = workers
            .into_iter()
            .enumerate()
            .map(|(index, worker)| (index, worker.join()))
            .collect::<Vec<_>>();
        let failures = outcomes
            .into_iter()
            .filter_map(|(index, outcome)| match outcome {
                Ok(Ok(_)) => None,
                Ok(Err(error)) => Some(format!("worker {index} claim failed: {error:#}")),
                Err(_) => Some(format!("worker {index} panicked")),
            })
            .collect::<Vec<_>>();
        assert!(
            failures.is_empty(),
            "concurrent claim workers failed after all joins:\n{}",
            failures.join("\n")
        );

        let claims = store.snapshot().expect("snapshot");
        assert_eq!(claims.len(), 16);
        #[cfg(unix)]
        write_completion_receipt_if_requested();
    }

    #[test]
    fn state_record_budget_is_enforced_before_coordinator_materialization() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let store = SyncStore::open(&repo_path).expect("open store");
        let claims = (0..=MAX_SYNC_CLAIMS)
            .map(|index| PathClaim {
                token: ClaimToken::from_u64(u64::try_from(index).expect("index") + 1),
                agent_id: format!("agent-{index}"),
                paths: vec![PathBuf::from(format!("path-{index}"))],
            })
            .collect::<Vec<_>>();
        let snapshot = SyncSnapshot {
            next_token: u64::try_from(MAX_SYNC_CLAIMS).expect("count") + 2,
            claims,
        };
        let lock = store.state.lock().expect("claims lock");
        assert!(store
            .save_snapshot(&lock, snapshot)
            .expect_err("record budget")
            .to_string()
            .contains("claim budget"));
    }

    #[cfg(unix)]
    #[test]
    fn repository_binding_supports_non_utf8_common_directory_paths() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join(OsString::from_vec(b"repo-\x80".to_vec()));
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let store = SyncStore::open(&repo_path).expect("open store");
        store
            .claim_paths("agent-a", ["README.md"])
            .expect("persist claim");

        let lock = store.state.lock().expect("claims lock");
        let authenticated = store
            .open_authenticated_store(&lock)
            .expect("authenticated claims");
        assert_eq!(
            authenticated.current().value.repository,
            authenticated.identity().repository
        );
        drop(authenticated);
        drop(lock);
        assert_eq!(store.snapshot().expect("snapshot").len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn rebound_lock_path_cannot_commit_a_stale_snapshot_or_lose_newer_update() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let store = SyncStore::open(&repo_path).expect("open store");
        store
            .claim_paths("agent-a", ["first"])
            .expect("initial claim");

        let stale_lock = store.state.lock().expect("first lock");
        let stale_snapshot = store.load_snapshot(&stale_lock).expect("stale snapshot");
        let lock_path = stale_lock._lock.path().to_path_buf();
        let moved_lock = lock_path.with_file_name("claims.lock.rebound-original");
        fs::rename(&lock_path, &moved_lock).expect("move locked inode");
        fs::write(&lock_path, b"").expect("replacement lock");
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))
            .expect("replacement mode");

        store
            .claim_paths("agent-b", ["second"])
            .expect("new lock-domain writer");
        let error = store
            .save_snapshot(&stale_lock, stale_snapshot)
            .expect_err("stale writer must fail closed");
        assert!(
            error.to_string().contains("lock path was rebound")
                || error
                    .to_string()
                    .contains("does not name its opened descriptor"),
            "unexpected error: {error:#}"
        );
        drop(stale_lock);

        let claims = store.snapshot().expect("final snapshot");
        assert_eq!(claims.len(), 2);
        assert!(claims.iter().any(|claim| claim.agent_id == "agent-a"));
        assert!(claims.iter().any(|claim| claim.agent_id == "agent-b"));
    }

    #[cfg(unix)]
    #[test]
    fn lock_rebind_after_write_precheck_cannot_overwrite_newer_snapshot() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let store = SyncStore::open(&repo_path).expect("open store");
        store
            .claim_paths("agent-a", ["first"])
            .expect("initial claim");

        let stale_lock = store.state.lock().expect("stale lock");
        let lock_path = stale_lock._lock.path().to_path_buf();
        let moved_lock = lock_path.with_file_name("claims.lock.precheck-original");
        fs::rename(&lock_path, &moved_lock).expect("move stale lock inode");
        fs::write(&lock_path, b"").expect("create replacement lock inode");
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))
            .expect("replacement mode");
        let error = match store.open_authenticated_store(&stale_lock) {
            Ok(_) => panic!("stale lock must fail before authenticated state access"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("lock path")
                || error.to_string().contains("opened descriptor"),
            "unexpected error: {error:#}"
        );
        drop(stale_lock);

        assert_eq!(store.snapshot().expect("final snapshot").len(), 1);
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
}
