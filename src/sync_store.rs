use crate::sync::{
    normalize_repo_relative_path, ClaimToken, PathClaim, SyncCoordinator, SyncSnapshot,
};
use anyhow::{bail, Context, Result};
use git2::Repository;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
    process::{self, Command},
    thread,
    time::Duration,
};

const STATE_VERSION: u32 = 1;

#[derive(Debug, Clone)]
pub struct SyncStore {
    state_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OwnerReport {
    pub path: PathBuf,
    pub owner: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct PersistedSyncState {
    version: u32,
    next_token: u64,
    claims: Vec<PathClaim>,
}

impl From<SyncSnapshot> for PersistedSyncState {
    fn from(snapshot: SyncSnapshot) -> Self {
        Self {
            version: STATE_VERSION,
            next_token: snapshot.next_token,
            claims: snapshot.claims,
        }
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
            state_path: repo
                .commondir()
                .join("maco")
                .join("state")
                .join("claims.json"),
        })
    }

    pub fn state_path(&self) -> &Path {
        &self.state_path
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
        let _lock = StateLock::acquire(&self.state_path)?;
        let coordinator = self.load_coordinator()?;
        let output = operation(&coordinator)?;
        self.save_snapshot(coordinator.to_snapshot()?)?;
        Ok(output)
    }

    fn with_locked_read<T>(
        &self,
        operation: impl FnOnce(&SyncCoordinator) -> Result<T>,
    ) -> Result<T> {
        let _lock = StateLock::acquire(&self.state_path)?;
        let coordinator = self.load_coordinator()?;
        operation(&coordinator)
    }

    fn load_coordinator(&self) -> Result<SyncCoordinator> {
        let snapshot = self.load_snapshot()?;
        SyncCoordinator::from_snapshot(snapshot).map_err(Into::into)
    }

    fn load_snapshot(&self) -> Result<SyncSnapshot> {
        let contents = match fs::read_to_string(&self.state_path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(SyncSnapshot::default()),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to read sync state {}", self.state_path.display())
                })
            }
        };

        let state: PersistedSyncState = serde_json::from_str(&contents)
            .with_context(|| format!("failed to parse sync state {}", self.state_path.display()))?;
        if state.version != STATE_VERSION {
            bail!(
                "unsupported sync state version {} in {}",
                state.version,
                self.state_path.display()
            );
        }

        Ok(SyncSnapshot {
            next_token: state.next_token,
            claims: state.claims,
        })
    }

    fn save_snapshot(&self, snapshot: SyncSnapshot) -> Result<()> {
        let parent = self
            .state_path
            .parent()
            .context("sync state path must have a parent directory")?;
        fs::create_dir_all(parent).with_context(|| {
            format!("failed to create sync state directory {}", parent.display())
        })?;

        let state = PersistedSyncState::from(snapshot);
        let temp_path = temp_state_path(&self.state_path);
        let result = write_state_file(&temp_path, &self.state_path, &state);
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        result
    }
}

fn write_state_file(temp_path: &Path, state_path: &Path, state: &PersistedSyncState) -> Result<()> {
    let mut file = File::create(temp_path)
        .with_context(|| format!("failed to create temporary state {}", temp_path.display()))?;
    serde_json::to_writer_pretty(&mut file, state)
        .with_context(|| format!("failed to write temporary state {}", temp_path.display()))?;
    file.write_all(b"\n")
        .with_context(|| format!("failed to finish temporary state {}", temp_path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to flush temporary state {}", temp_path.display()))?;
    drop(file);

    fs::rename(temp_path, state_path).with_context(|| {
        format!(
            "failed to replace sync state {} with {}",
            state_path.display(),
            temp_path.display()
        )
    })
}

fn temp_state_path(state_path: &Path) -> PathBuf {
    let file_name = state_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("claims.json");
    state_path.with_file_name(format!(".{file_name}.{}.tmp", process::id()))
}

struct StateLock {
    path: PathBuf,
}

impl StateLock {
    fn acquire(state_path: &Path) -> Result<Self> {
        let parent = state_path
            .parent()
            .context("sync state path must have a parent directory")?;
        fs::create_dir_all(parent).with_context(|| {
            format!("failed to create sync state directory {}", parent.display())
        })?;

        let path = parent.join("claims.lock");
        let mut attempts = 0;
        let mut file = loop {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => break file,
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                    if remove_stale_lock(&path)? {
                        continue;
                    }
                    attempts += 1;
                    if attempts >= 50 {
                        bail!(
                            "sync state is locked at {}; another maco sync command may be running",
                            path.display()
                        );
                    }
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("failed to create sync lock {}", path.display()))
                }
            }
        };

        let result = (|| -> Result<()> {
            writeln!(file, "pid={}", process::id())
                .with_context(|| format!("failed to write sync lock {}", path.display()))?;
            file.sync_all()
                .with_context(|| format!("failed to flush sync lock {}", path.display()))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&path);
        }
        result?;

        Ok(Self { path })
    }
}

impl Drop for StateLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn remove_stale_lock(path: &Path) -> Result<bool> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(true),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect sync lock {}", path.display()))
        }
    };
    let Some(pid) = parse_lock_pid(&contents) else {
        return Ok(false);
    };
    if process_is_running(pid) {
        return Ok(false);
    }

    fs::remove_file(path)
        .with_context(|| format!("failed to remove stale sync lock {}", path.display()))?;
    Ok(true)
}

fn parse_lock_pid(contents: &str) -> Option<u32> {
    contents
        .lines()
        .find_map(|line| line.strip_prefix("pid="))
        .and_then(|pid| pid.trim().parse().ok())
}

#[cfg(target_family = "unix")]
fn process_is_running(pid: u32) -> bool {
    if Path::new("/proc").exists() {
        return Path::new("/proc").join(pid.to_string()).exists();
    }

    Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .status()
        .map(|status| status.success())
        .unwrap_or(true)
}

#[cfg(not(target_family = "unix"))]
fn process_is_running(_pid: u32) -> bool {
    true
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
    fn stale_lock_file_is_removed() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let store = SyncStore::open(&repo_path).expect("open store");
        let lock_path = store
            .state_path()
            .parent()
            .expect("state parent")
            .join("claims.lock");
        fs::create_dir_all(lock_path.parent().expect("lock parent")).expect("state dir");
        fs::write(&lock_path, "pid=4294967295\n").expect("write stale lock");

        assert_eq!(store.snapshot().expect("snapshot"), Vec::<PathClaim>::new());
        assert!(!lock_path.exists());
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
