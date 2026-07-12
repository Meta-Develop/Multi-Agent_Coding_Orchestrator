use crate::safe_state::{
    identity_for_path, stable_checksum, AtomicStateWriter, BoundedRegularReader, FileIdentity,
    KernelStateLock, SafeRoot,
};
use crate::sync::{
    normalize_repo_relative_path, ClaimToken, PathClaim, SyncCoordinator, SyncSnapshot,
};
use anyhow::{bail, Context, Result};
use git2::Repository;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::{
    ffi::OsStrExt,
    fs::{MetadataExt, PermissionsExt},
};

const STATE_VERSION: u32 = 2;
const LEGACY_STATE_VERSION: u32 = 1;
const MAX_SYNC_STATE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_SYNC_CLAIMS: usize = 4_096;
const MAX_SYNC_PATHS: usize = 16_384;
const MAX_AGENT_ID_BYTES: usize = 128;
const MAX_STATE_PATH_BYTES: usize = 4_096;
const MAX_STATE_PATH_COMPONENTS: usize = 256;

#[derive(Debug, Clone)]
pub struct SyncStore {
    state: RepositoryStateRoot,
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyPersistedSyncState {
    version: u32,
    next_token: u64,
    claims: Vec<PathClaim>,
}

impl PersistedSyncState {
    fn from_snapshot(repository: RepositoryStateBinding, snapshot: SyncSnapshot) -> Result<Self> {
        validate_sync_snapshot(&snapshot)?;
        let mut state = Self {
            version: STATE_VERSION,
            checksum: String::new(),
            repository,
            next_token: snapshot.next_token,
            claims: snapshot.claims,
        };
        state.checksum = sync_state_checksum(&state)?;
        Ok(state)
    }
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

    pub(crate) fn lock(&self) -> Result<RepositoryStateLock> {
        let lock = KernelStateLock::acquire_direct(&self.root, self.lock_file)?;
        let lock_identity = ensure_private_state_file(lock.path())?;
        Ok(RepositoryStateLock {
            _lock: lock,
            root_identity: self.root.identity().clone(),
            state_file: self.state_file,
            lock_identity,
        })
    }

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

    pub(crate) fn write(
        &self,
        lock: &RepositoryStateLock,
        contents: &[u8],
        max_bytes: u64,
    ) -> Result<()> {
        self.verify_lock(lock)?;
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
            AtomicStateWriter::scavenge_direct_temps(&self.root, self.state_file)?;
            AtomicStateWriter::write_direct(&self.root, self.state_file, contents)?;
            ensure_private_state_file(&self.state_path)?;
            Ok(())
        })();
        finish_with_lock_verification(result, self.verify_lock(lock))
    }

    fn verify_lock(&self, lock: &RepositoryStateLock) -> Result<()> {
        if lock.root_identity != *self.root.identity() || lock.state_file != self.state_file {
            bail!("repository state lock does not match the protected state file");
        }
        self.root.verify()?;
        let observed = ensure_private_state_file(lock._lock.path())?;
        if observed != lock.lock_identity {
            bail!(
                "repository state lock path was rebound while its original inode remained locked: {}",
                lock._lock.path().display()
            );
        }
        Ok(())
    }
}

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
        Ok(Self {
            state: RepositoryStateRoot::open(&repo, "claims.json", "claims.lock")?,
        })
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
        let coordinator = self.load_coordinator(&lock)?;
        let output = operation(&coordinator)?;
        self.save_snapshot(&lock, coordinator.to_snapshot()?)?;
        Ok(output)
    }

    fn with_locked_read<T>(
        &self,
        operation: impl FnOnce(&SyncCoordinator) -> Result<T>,
    ) -> Result<T> {
        let lock = self.state.lock()?;
        let coordinator = self.load_coordinator(&lock)?;
        operation(&coordinator)
    }

    fn load_coordinator(&self, lock: &RepositoryStateLock) -> Result<SyncCoordinator> {
        let snapshot = self.load_snapshot(lock)?;
        SyncCoordinator::from_snapshot(snapshot).map_err(Into::into)
    }

    fn load_snapshot(&self, lock: &RepositoryStateLock) -> Result<SyncSnapshot> {
        let Some(contents) = self.state.read(lock, MAX_SYNC_STATE_BYTES)? else {
            return Ok(SyncSnapshot::default());
        };
        let version = serde_json::from_slice::<serde_json::Value>(&contents)
            .with_context(|| format!("failed to parse sync state {}", self.state_path().display()))?
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .context("sync state is missing an integer version")?;
        let version = u32::try_from(version).context("sync state version does not fit in u32")?;
        if version == LEGACY_STATE_VERSION {
            let legacy: LegacyPersistedSyncState =
                serde_json::from_slice(&contents).with_context(|| {
                    format!(
                        "failed to parse legacy sync state {}",
                        self.state_path().display()
                    )
                })?;
            if legacy.version != LEGACY_STATE_VERSION {
                bail!("legacy sync state changed versions while it was being parsed");
            }
            let snapshot = SyncSnapshot {
                next_token: legacy.next_token,
                claims: legacy.claims,
            };
            validate_sync_snapshot(&snapshot)?;
            SyncCoordinator::from_snapshot(snapshot.clone())
                .context("legacy sync state failed structural validation")?;
            self.save_snapshot(lock, snapshot.clone()).context(
                "failed to migrate private legacy sync state to repository-bound version 2",
            )?;
            return Ok(snapshot);
        }
        if version != STATE_VERSION {
            bail!(
                "unsupported sync state version {} in {}",
                version,
                self.state_path().display()
            );
        }
        let state: PersistedSyncState = serde_json::from_slice(&contents).with_context(|| {
            format!("failed to parse sync state {}", self.state_path().display())
        })?;
        if state.repository != *self.state.binding() {
            bail!("sync state repository/common-directory binding does not match this repository");
        }
        let expected_checksum = sync_state_checksum(&state)?;
        if state.checksum != expected_checksum {
            bail!(
                "sync state checksum mismatch in {}; refusing to use corrupted state",
                self.state_path().display()
            );
        }
        let snapshot = SyncSnapshot {
            next_token: state.next_token,
            claims: state.claims,
        };
        validate_sync_snapshot(&snapshot)?;
        Ok(snapshot)
    }

    fn save_snapshot(&self, lock: &RepositoryStateLock, snapshot: SyncSnapshot) -> Result<()> {
        let state = PersistedSyncState::from_snapshot(self.state.binding().clone(), snapshot)?;
        let mut contents = serde_json::to_vec_pretty(&state)
            .context("failed to serialize repository-bound sync state")?;
        contents.push(b'\n');
        self.state.write(lock, &contents, MAX_SYNC_STATE_BYTES)
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

#[cfg(unix)]
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

#[cfg(not(unix))]
fn ensure_private_state_file(path: &Path) -> Result<FileIdentity> {
    bail!(
        "private state-file ownership and ACL validation is unsupported on this platform: {}",
        path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worktree::WorktreeManager;
    use git2::{Oid, Repository, Signature};
    use tempfile::TempDir;

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
    fn private_legacy_v1_state_is_migrated_and_repository_bound() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let store = SyncStore::open(&repo_path).expect("open store");
        let legacy = serde_json::json!({
            "version": LEGACY_STATE_VERSION,
            "next_token": 2,
            "claims": [{
                "token": 1,
                "agent_id": "agent-a",
                "paths": ["README.md"]
            }]
        });
        fs::write(
            store.state_path(),
            serde_json::to_vec_pretty(&legacy).expect("legacy JSON"),
        )
        .expect("write legacy");
        fs::set_permissions(store.state_path(), fs::Permissions::from_mode(0o600))
            .expect("private state");

        assert_eq!(store.snapshot().expect("migrate").len(), 1);
        let migrated = fs::read(store.state_path()).expect("read migrated");
        let state: PersistedSyncState = serde_json::from_slice(&migrated).expect("parse migrated");
        assert_eq!(state.version, STATE_VERSION);
        assert_eq!(state.repository, *store.state.binding());
        assert_eq!(
            state.checksum,
            sync_state_checksum(&state).expect("checksum")
        );
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
        state["next_token"] = serde_json::json!(999);
        fs::write(
            store.state_path(),
            serde_json::to_vec_pretty(&state).expect("tampered JSON"),
        )
        .expect("tamper state");
        assert!(store
            .snapshot()
            .expect_err("checksum tamper")
            .to_string()
            .contains("checksum mismatch"));

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
        let state: PersistedSyncState =
            serde_json::from_slice(&fs::read(store.state_path()).expect("state"))
                .expect("parse state");
        assert_eq!(
            state.checksum,
            sync_state_checksum(&state).expect("checksum")
        );
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
        let mut state = PersistedSyncState {
            version: STATE_VERSION,
            checksum: String::new(),
            repository: store.state.binding().clone(),
            next_token: u64::try_from(MAX_SYNC_CLAIMS).expect("count") + 2,
            claims,
        };
        state.checksum = sync_state_checksum(&state).expect("checksum");
        let bytes = serde_json::to_vec(&state).expect("state JSON");
        assert!(u64::try_from(bytes.len()).expect("length") < MAX_SYNC_STATE_BYTES);
        fs::write(store.state_path(), bytes).expect("write oversized records");
        #[cfg(unix)]
        fs::set_permissions(store.state_path(), fs::Permissions::from_mode(0o600))
            .expect("private mode");

        assert!(store
            .snapshot()
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

        let bytes = fs::read(store.state_path()).expect("state bytes");
        let state: PersistedSyncState = serde_json::from_slice(&bytes).expect("state JSON");
        assert_eq!(state.repository, *store.state.binding());
        assert!(state
            .repository
            .common_dir_path_checksum
            .starts_with("maco-v1-"));
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
        assert!(error.to_string().contains("lock path was rebound"));
        drop(stale_lock);

        let claims = store.snapshot().expect("final snapshot");
        assert_eq!(claims.len(), 2);
        assert!(claims.iter().any(|claim| claim.agent_id == "agent-a"));
        assert!(claims.iter().any(|claim| claim.agent_id == "agent-b"));
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
