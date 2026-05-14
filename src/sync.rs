use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ClaimToken(u64);

impl ClaimToken {
    pub fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PathClaim {
    pub token: ClaimToken,
    pub agent_id: String,
    pub paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Default)]
pub struct SyncCoordinator {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Debug)]
struct Inner {
    next_token: u64,
    claims: BTreeMap<PathBuf, ClaimEntry>,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            next_token: 1,
            claims: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClaimEntry {
    token: ClaimToken,
    agent_id: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SyncError {
    #[error("agent id cannot be empty")]
    EmptyAgentId,
    #[error("agent id may only contain ASCII letters, digits, '.', '_' and '-'")]
    InvalidAgentId,
    #[error("claim must include at least one path")]
    EmptyClaim,
    #[error("path cannot be empty")]
    EmptyPath,
    #[error("path must be repository-relative: {path}")]
    AbsolutePath { path: PathBuf },
    #[error("path cannot escape repository: {path}")]
    EscapingPath { path: PathBuf },
    #[error("path is already claimed by {owner}: {path}")]
    Conflict { path: PathBuf, owner: String },
    #[error("claim token is not active: {0}")]
    UnknownToken(u64),
    #[error("sync coordinator lock is poisoned")]
    Poisoned,
}

pub type Result<T> = std::result::Result<T, SyncError>;

impl SyncCoordinator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn claim_paths<I, P>(&self, agent_id: impl AsRef<str>, paths: I) -> Result<PathClaim>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let agent_id = normalize_agent_id(agent_id.as_ref())?;
        let paths = normalize_claim_paths(paths)?;
        let mut inner = self.lock_inner()?;

        for requested in &paths {
            if let Some((path, entry)) = find_conflict(&inner.claims, requested) {
                return Err(SyncError::Conflict {
                    path,
                    owner: entry.agent_id.clone(),
                });
            }
        }

        let token = ClaimToken(inner.next_token);
        inner.next_token += 1;
        for path in &paths {
            inner.claims.insert(
                path.clone(),
                ClaimEntry {
                    token,
                    agent_id: agent_id.clone(),
                },
            );
        }

        Ok(PathClaim {
            token,
            agent_id,
            paths,
        })
    }

    pub fn release(&self, token: ClaimToken) -> Result<PathClaim> {
        let mut inner = self.lock_inner()?;
        let released =
            claim_for_token(&inner.claims, token).ok_or(SyncError::UnknownToken(token.get()))?;
        inner.claims.retain(|_, entry| entry.token != token);
        Ok(released)
    }

    pub fn release_by_agent(&self, agent_id: impl AsRef<str>) -> Result<Vec<PathClaim>> {
        let agent_id = normalize_agent_id(agent_id.as_ref())?;
        let mut inner = self.lock_inner()?;
        let mut tokens = BTreeSet::new();

        for entry in inner.claims.values() {
            if entry.agent_id == agent_id {
                tokens.insert(entry.token);
            }
        }

        let released = tokens
            .iter()
            .filter_map(|token| claim_for_token(&inner.claims, *token))
            .collect();
        inner.claims.retain(|_, entry| entry.agent_id != agent_id);
        Ok(released)
    }

    pub fn owner_of(&self, path: impl AsRef<Path>) -> Result<Option<String>> {
        let path = normalize_repo_path(path.as_ref())?;
        let inner = self.lock_inner()?;

        Ok(inner
            .claims
            .iter()
            .find(|(claimed, _)| path_is_covered_by_claim(&path, claimed))
            .map(|(_, entry)| entry.agent_id.clone()))
    }

    pub fn can_write(&self, agent_id: impl AsRef<str>, path: impl AsRef<Path>) -> Result<bool> {
        let agent_id = normalize_agent_id(agent_id.as_ref())?;
        let path = normalize_repo_path(path.as_ref())?;
        let inner = self.lock_inner()?;

        Ok(inner.claims.iter().any(|(claimed, entry)| {
            entry.agent_id == agent_id && path_is_covered_by_claim(&path, claimed)
        }))
    }

    pub fn snapshot(&self) -> Result<Vec<PathClaim>> {
        let inner = self.lock_inner()?;
        Ok(group_claims(&inner.claims).into_values().collect())
    }

    fn lock_inner(&self) -> Result<MutexGuard<'_, Inner>> {
        self.inner.lock().map_err(|_| SyncError::Poisoned)
    }
}

fn normalize_agent_id(agent_id: &str) -> Result<String> {
    let trimmed = agent_id.trim();
    if trimmed.is_empty() {
        return Err(SyncError::EmptyAgentId);
    }
    if matches!(trimmed, "." | "..") {
        return Err(SyncError::InvalidAgentId);
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(SyncError::InvalidAgentId);
    }

    Ok(trimmed.to_string())
}

fn normalize_claim_paths<I, P>(paths: I) -> Result<Vec<PathBuf>>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    let paths = paths
        .into_iter()
        .map(|path| normalize_repo_path(path.as_ref()))
        .collect::<Result<BTreeSet<_>>>()?;

    if paths.is_empty() {
        return Err(SyncError::EmptyClaim);
    }

    Ok(collapse_covered_paths(paths))
}

fn normalize_repo_path(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(SyncError::EmptyPath);
    }

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(segment) => normalized.push(segment),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(SyncError::EscapingPath {
                    path: path.to_path_buf(),
                });
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(SyncError::AbsolutePath {
                    path: path.to_path_buf(),
                });
            }
        }
    }

    if normalized.as_os_str().is_empty() {
        return Err(SyncError::EmptyPath);
    }

    Ok(normalized)
}

fn collapse_covered_paths(paths: BTreeSet<PathBuf>) -> Vec<PathBuf> {
    let mut collapsed: Vec<PathBuf> = Vec::new();
    for path in paths {
        if collapsed.iter().any(|existing| path.starts_with(existing)) {
            continue;
        }
        collapsed.retain(|existing| !existing.starts_with(&path));
        collapsed.push(path);
    }

    collapsed
}

fn find_conflict(
    claims: &BTreeMap<PathBuf, ClaimEntry>,
    requested: &Path,
) -> Option<(PathBuf, ClaimEntry)> {
    claims.iter().find_map(|(claimed, entry)| {
        if paths_overlap(claimed, requested) {
            Some((claimed.clone(), entry.clone()))
        } else {
            None
        }
    })
}

fn paths_overlap(a: &Path, b: &Path) -> bool {
    a == b || a.starts_with(b) || b.starts_with(a)
}

fn path_is_covered_by_claim(path: &Path, claim: &Path) -> bool {
    path == claim || path.starts_with(claim)
}

fn claim_for_token(claims: &BTreeMap<PathBuf, ClaimEntry>, token: ClaimToken) -> Option<PathClaim> {
    group_claims(claims).remove(&token)
}

fn group_claims(claims: &BTreeMap<PathBuf, ClaimEntry>) -> BTreeMap<ClaimToken, PathClaim> {
    let mut grouped: BTreeMap<ClaimToken, PathClaim> = BTreeMap::new();
    for (path, entry) in claims {
        grouped
            .entry(entry.token)
            .and_modify(|claim| claim.paths.push(path.clone()))
            .or_insert_with(|| PathClaim {
                token: entry.token,
                agent_id: entry.agent_id.clone(),
                paths: vec![path.clone()],
            });
    }

    grouped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grants_exclusive_claims_for_disjoint_paths() {
        let coordinator = SyncCoordinator::new();

        let src = coordinator
            .claim_paths("agent-a", ["src/lib.rs"])
            .expect("claim src");
        let docs = coordinator
            .claim_paths("agent-b", ["README.md"])
            .expect("claim docs");

        assert_eq!(src.token.get(), 1);
        assert_eq!(docs.token.get(), 2);
        assert_eq!(
            coordinator.owner_of("src/lib.rs").expect("owner"),
            Some("agent-a".to_string())
        );
        assert!(coordinator
            .can_write("agent-b", "README.md")
            .expect("write"));
        assert!(!coordinator
            .can_write("agent-b", "src/lib.rs")
            .expect("write"));
    }

    #[test]
    fn rejects_overlapping_claims_between_agents() {
        let coordinator = SyncCoordinator::new();
        coordinator
            .claim_paths("agent-a", ["src"])
            .expect("claim src");

        let error = coordinator
            .claim_paths("agent-b", ["src/worktree.rs"])
            .expect_err("overlap should fail");

        assert_eq!(
            error,
            SyncError::Conflict {
                path: PathBuf::from("src"),
                owner: "agent-a".to_string()
            }
        );
    }

    #[test]
    fn releases_claims_by_token() {
        let coordinator = SyncCoordinator::new();
        let claim = coordinator
            .claim_paths("agent-a", ["src/lib.rs", "src/main.rs"])
            .expect("claim files");

        let released = coordinator.release(claim.token).expect("release");

        assert_eq!(released, claim);
        assert_eq!(coordinator.owner_of("src/lib.rs").expect("owner"), None);
        coordinator
            .claim_paths("agent-b", ["src"])
            .expect("claim released path");
    }

    #[test]
    fn releases_all_claims_for_agent() {
        let coordinator = SyncCoordinator::new();
        coordinator
            .claim_paths("agent-a", ["src/lib.rs"])
            .expect("claim lib");
        coordinator
            .claim_paths("agent-a", ["README.md"])
            .expect("claim readme");
        coordinator
            .claim_paths("agent-b", ["Cargo.toml"])
            .expect("claim cargo");

        let released = coordinator
            .release_by_agent("agent-a")
            .expect("release agent");

        assert_eq!(released.len(), 2);
        assert_eq!(coordinator.owner_of("src/lib.rs").expect("owner"), None);
        assert_eq!(
            coordinator.owner_of("Cargo.toml").expect("owner"),
            Some("agent-b".to_string())
        );
    }

    #[test]
    fn rejects_unsafe_paths() {
        let coordinator = SyncCoordinator::new();

        assert!(matches!(
            coordinator.claim_paths("agent-a", ["../src"]),
            Err(SyncError::EscapingPath { .. })
        ));
        assert!(matches!(
            coordinator.claim_paths("agent-a", ["/tmp/repo"]),
            Err(SyncError::AbsolutePath { .. })
        ));
        assert!(matches!(
            coordinator.claim_paths("agent-a", ["."]),
            Err(SyncError::EmptyPath)
        ));
    }

    #[test]
    fn collapses_parent_and_child_paths_in_single_claim() {
        let coordinator = SyncCoordinator::new();

        let claim = coordinator
            .claim_paths("agent-a", ["src/worktree.rs", "src"])
            .expect("claim paths");

        assert_eq!(claim.paths, vec![PathBuf::from("src")]);
        assert!(coordinator
            .can_write("agent-a", "src/worktree.rs")
            .expect("write"));
    }

    #[test]
    fn reports_unknown_token_on_double_release() {
        let coordinator = SyncCoordinator::new();
        let claim = coordinator
            .claim_paths("agent-a", ["src/lib.rs"])
            .expect("claim lib");

        coordinator.release(claim.token).expect("release");
        let error = coordinator
            .release(claim.token)
            .expect_err("second release should fail");

        assert_eq!(error, SyncError::UnknownToken(claim.token.get()));
    }

    #[test]
    fn snapshot_is_sorted_by_claim_token() {
        let coordinator = SyncCoordinator::new();
        let first = coordinator
            .claim_paths("agent-a", ["src/lib.rs"])
            .expect("first claim");
        let second = coordinator
            .claim_paths("agent-b", ["README.md"])
            .expect("second claim");

        assert_eq!(
            coordinator.snapshot().expect("snapshot"),
            vec![first, second]
        );
    }
}
