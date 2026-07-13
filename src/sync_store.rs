use crate::sync::{
    normalize_repo_relative_path, ClaimToken, PathClaim, SyncCoordinator, SyncSnapshot,
};
use crate::{
    artifacts::{
        repository_authenticator_key_only,
        state_auth::{AuthenticationDomain, RepositoryAuthBinding},
    },
    authenticated_snapshot::{AuthenticatedSnapshotStore, SnapshotSpec},
    safe_state::{stable_checksum, FileIdentity, KernelStateLock, SafeRoot},
    state_journal::JournalSpec,
    state_migration::{
        finalize_legacy_retirement, prepare_legacy_retirement, LegacyAdoption,
        LEGACY_RETIREMENT_DOMAIN,
    },
};
use anyhow::{bail, Context, Result};
use git2::Repository;
use serde::{Deserialize, Serialize};
use std::{
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
const MAX_STATE_PATH_BYTES: usize = 4_096;
const MAX_STATE_PATH_COMPONENTS: usize = 256;

#[derive(Debug, Clone)]
pub struct SyncStore {
    repo_path: PathBuf,
    state: RepositoryStateRoot,
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

#[cfg(test)]
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
        self.with_locked_update(|coordinator| {
            coordinator
                .claim_paths(agent_id.as_ref(), paths)
                .map_err(Into::into)
        })
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

    fn with_locked_update<T>(
        &self,
        operation: impl FnOnce(&SyncCoordinator) -> Result<T>,
    ) -> Result<T> {
        let lock = self.state.lock()?;
        let mut store = self.open_authenticated_store(&lock)?;
        let coordinator = SyncCoordinator::from_snapshot(SyncSnapshot {
            next_token: store.current().value.next_token,
            claims: store.current().value.claims.clone(),
        })?;
        let output = operation(&coordinator)?;
        let snapshot = coordinator.to_snapshot()?;
        validate_sync_snapshot(&snapshot)?;
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
            },
            LegacyAdoption::Present(bytes) => {
                let legacy: PersistedSyncState = serde_json::from_slice(&bytes)
                    .context("signed legacy claims state is malformed")?;
                if legacy.version != STATE_VERSION
                    || legacy.repository != *self.state.binding()
                    || legacy.checksum != sync_state_checksum(&legacy)?
                {
                    bail!("signed legacy claims state failed repository/checksum validation");
                }
                let snapshot = SyncSnapshot {
                    next_token: legacy.next_token,
                    claims: legacy.claims,
                };
                validate_sync_snapshot(&snapshot)?;
                AuthenticatedClaimsState {
                    version: 1,
                    snapshot_revision: 1,
                    repository: binding,
                    next_token: snapshot.next_token,
                    claims: snapshot.claims,
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
        })
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
        state_migration::{set_legacy_retirement_fault, LegacyRetirementFaultPoint},
        worktree::WorktreeManager,
    };
    use git2::{Oid, Repository, Signature};
    use tempfile::TempDir;

    #[cfg(target_os = "linux")]
    #[test]
    fn claims_wrapper_recovers_nine_residues_beyond_a_full_snapshot_root() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        drop(SyncStore::open(&repo_path).expect("initialize claims wrapper"));
        let root_path = repo_path
            .join(".git/maco/state")
            .join(ClaimsSnapshotSpec::ROOT_NAME);
        let root = SafeRoot::open_existing(&root_path).expect("claims snapshot root");
        let durable_entries = fs::read_dir(&root_path).expect("durable root").count();
        for index in durable_entries..ClaimsSnapshotSpec::MAX_ROOT_ENTRIES {
            let filler = root_path.join(format!("capacity-filler-{index:03}"));
            fs::write(&filler, b"").expect("capacity filler");
            fs::set_permissions(&filler, fs::Permissions::from_mode(0o600))
                .expect("private filler");
        }
        assert_eq!(
            fs::read_dir(&root_path).expect("full root").count(),
            ClaimsSnapshotSpec::MAX_ROOT_ENTRIES
        );
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
                .expect("full root plus residues")
                .count(),
            ClaimsSnapshotSpec::MAX_ROOT_ENTRIES + 9
        );

        let reopened =
            SyncStore::open(&repo_path).expect("claims wrapper scavenges before inventory");

        assert!(reopened.snapshot().expect("claims snapshot").is_empty());
        assert_eq!(
            fs::read_dir(root_path)
                .expect("recovered full root")
                .count(),
            ClaimsSnapshotSpec::MAX_ROOT_ENTRIES
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
            .create(crate::worktree::WorktreeCreateOptions {
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
