use crate::sync::{
    normalize_repo_relative_path, ClaimToken, PathClaim, SyncCoordinator, SyncSnapshot,
};
use crate::{
    artifacts::{
        repository_authenticator_key_only,
        state_auth::{AuthenticationDomain, RepositoryAuthBinding},
    },
    authenticated_snapshot::{AuthenticatedSnapshotStore, SnapshotSpec},
    live_claim::{
        claim_process_liveness, current_claim_process_identity, ClaimProcessIdentity,
        ClaimProcessLiveness,
    },
    megafile::{MegafileAssessment, MegafileStore, MegafileThresholds},
    orchestrator::RunId,
    safe_state::{stable_checksum, FileIdentity, KernelStateLock, SafeRoot},
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
};

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
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedClaimRunOwner {
    token: ClaimToken,
    run_id: String,
    process: ClaimProcessIdentity,
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

impl SyncStore {
    pub fn open(repo_path: impl AsRef<Path>) -> Result<Self> {
        let repo = Repository::discover(repo_path.as_ref()).with_context(|| {
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
                Some((
                    run_id.as_str().to_string(),
                    current_claim_process_identity(),
                )),
            )?
            .claim)
    }

    #[cfg(test)]
    pub(crate) fn claim_paths_for_run_with_process<I, P>(
        &self,
        run_id: &RunId,
        agent_id: impl AsRef<str>,
        paths: I,
        process: ClaimProcessIdentity,
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
                Some((run_id.as_str().to_string(), process)),
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
        self.claim_paths_with_telemetry_thresholds_internal(agent_id, paths, thresholds, None)
    }

    fn claim_paths_with_telemetry_thresholds_internal<I, P>(
        &self,
        agent_id: impl AsRef<str>,
        paths: I,
        thresholds: MegafileThresholds,
        run_owner: Option<(String, ClaimProcessIdentity)>,
    ) -> Result<ClaimTelemetryOutcome>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        thresholds
            .validate()
            .context("configured megafile claim thresholds are invalid")?;
        let claim = self.with_locked_update_and_run_owners(
            |coordinator| {
                coordinator
                    .claim_paths(agent_id.as_ref(), paths)
                    .map_err(Into::into)
            },
            |claim, run_owners| {
                if let Some((run_id, process)) = run_owner {
                    run_owners.push(AuthenticatedClaimRunOwner {
                        token: claim.token,
                        run_id,
                        process,
                    });
                }
                Ok(())
            },
        )?;
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
        self.with_locked_update(|coordinator| coordinator.release(token).map_err(Into::into))
    }

    pub fn release_by_agent(&self, agent_id: impl AsRef<str>) -> Result<Vec<PathClaim>> {
        self.with_locked_update(|coordinator| {
            coordinator
                .release_by_agent(agent_id.as_ref())
                .map_err(Into::into)
        })
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
        operation: impl FnOnce(&SyncCoordinator) -> Result<T>,
    ) -> Result<T> {
        self.with_locked_update_and_run_owners(operation, |_, _| Ok(()))
    }

    fn with_locked_update_and_run_owners<T>(
        &self,
        operation: impl FnOnce(&SyncCoordinator) -> Result<T>,
        update_run_owners: impl FnOnce(&T, &mut Vec<AuthenticatedClaimRunOwner>) -> Result<()>,
    ) -> Result<T> {
        let lock = self.state.lock()?;
        let mut store = self.open_authenticated_store(&lock)?;
        let coordinator = SyncCoordinator::from_snapshot(SyncSnapshot {
            next_token: store.current().value.next_token,
            claims: store.current().value.claims.clone(),
        })?;
        let mut run_owners = store.current().value.run_owners.clone();
        let output = operation(&coordinator)?;
        let snapshot = coordinator.to_snapshot()?;
        validate_sync_snapshot(&snapshot)?;
        let active_tokens = snapshot
            .claims
            .iter()
            .map(|claim| claim.token)
            .collect::<BTreeSet<_>>();
        run_owners.retain(|owner| active_tokens.contains(&owner.token));
        update_run_owners(&output, &mut run_owners)?;
        run_owners.sort_by_key(|owner| owner.token);
        validate_claim_run_owners(&snapshot.claims, &run_owners)?;
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
        validate_claim_run_owners(&snapshot.value.claims, &snapshot.value.run_owners)
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
    for claim in &snapshot.claims {
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
        artifacts::state_auth::{authentication_key_file_name, sha256_hex},
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
    #[cfg(target_os = "linux")]
    use std::process::{Child, Command};
    use tempfile::TempDir;

    const ISSUE33_CLAIMS_V1: &[u8] =
        include_bytes!("../tests/fixtures/issue33/agent-files-claims-v1.json");
    const ISSUE33_CLAIMS_V1_SHA256: &str =
        "85ca48c7b658a3f28b4d3758268a41319b86f9b9bef78637bda7069cc2b83111";

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
            writer.with_locked_update(|coordinator| {
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
        let repository = Repository::open(&repo_path).expect("repository");
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
        let repo = Repository::open(&repo_path).expect("repo");
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
        let repo = Repository::open(&repo_path).expect("open repo");
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
        for worker in workers {
            worker.join().expect("worker thread").expect("claim");
        }

        let claims = store.snapshot().expect("snapshot");
        assert_eq!(claims.len(), 16);
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
