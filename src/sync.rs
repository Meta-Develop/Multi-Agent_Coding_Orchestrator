use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(transparent)]
pub struct ClaimToken(u64);

impl ClaimToken {
    pub fn from_u64(value: u64) -> Self {
        Self(value)
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PathClaim {
    pub token: ClaimToken,
    pub agent_id: String,
    pub paths: Vec<PathBuf>,
}

/// Authenticated storage data, never a deserializable dispatch capability.
/// Retained after release so an exact frozen turn/Worker grant cannot be replayed.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SubordinateClaimBinding {
    pub child_token: ClaimToken,
    pub parent_token: ClaimToken,
    pub source_digest: String,
    pub worker_id: String,
    pub paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct SyncSnapshot {
    pub next_token: u64,
    pub claims: Vec<PathClaim>,
}

impl Default for SyncSnapshot {
    fn default() -> Self {
        Self {
            next_token: 1,
            claims: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SyncCoordinator {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Debug)]
struct Inner {
    next_token: u64,
    claims: BTreeMap<PathBuf, ClaimEntry>,
    subordinate_claims: BTreeMap<ClaimToken, PathClaim>,
    subordinate_bindings: Vec<SubordinateClaimBinding>,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            next_token: 1,
            claims: BTreeMap::new(),
            subordinate_claims: BTreeMap::new(),
            subordinate_bindings: Vec::new(),
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
    #[error("claim token cannot be zero")]
    InvalidToken,
    #[error("claim token appears more than once: {0}")]
    DuplicateToken(u64),
    #[error("claim token space is exhausted")]
    TokenExhausted,
    #[error("sync coordinator lock is poisoned")]
    Poisoned,
    #[error("subordinate claim does not match its retained parent, scope or frozen reservation")]
    InvalidSubordinateClaim,
    #[error("subordinate Worker reservation was already consumed")]
    SubordinateReplay,
    #[error("parent claim still has active subordinate Workers")]
    ActiveSubordinates,
}

pub type Result<T> = std::result::Result<T, SyncError>;

impl SyncCoordinator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_snapshot(snapshot: SyncSnapshot) -> Result<Self> {
        let mut inner = Inner::default();
        let mut seen_tokens = BTreeSet::new();
        let mut max_token = 0;

        for claim in snapshot.claims {
            let token = claim.token;
            if token.get() == 0 {
                return Err(SyncError::InvalidToken);
            }
            if !seen_tokens.insert(token) {
                return Err(SyncError::DuplicateToken(token.get()));
            }

            let agent_id = normalize_agent_id(&claim.agent_id)?;
            let paths = normalize_claim_paths(claim.paths)?;
            insert_claim(&mut inner.claims, token, agent_id, paths)?;
            max_token = max_token.max(token.get());
        }

        inner.next_token = snapshot.next_token.max(max_token.saturating_add(1)).max(1);

        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    pub(crate) fn from_snapshot_with_subordinates(
        mut snapshot: SyncSnapshot,
        bindings: Vec<SubordinateClaimBinding>,
    ) -> Result<Self> {
        let mut child_tokens = BTreeSet::new();
        let mut sources = BTreeSet::new();
        for binding in &bindings {
            if binding.child_token.get() == 0
                || binding.parent_token.get() == 0
                || binding.child_token == binding.parent_token
                || binding.child_token.get() >= snapshot.next_token
                || binding.parent_token.get() >= snapshot.next_token
                || !child_tokens.insert(binding.child_token)
                || !sources.insert((
                    binding.parent_token,
                    &binding.source_digest,
                    &binding.worker_id,
                ))
                || normalize_agent_id(&binding.worker_id)? != binding.worker_id
                || normalize_claim_paths(&binding.paths)? != binding.paths
                || !valid_source_digest(&binding.source_digest)
            {
                return Err(SyncError::InvalidSubordinateClaim);
            }
        }
        let mut children = Vec::new();
        snapshot.claims.retain(|claim| {
            if child_tokens.contains(&claim.token) {
                children.push(claim.clone());
                false
            } else {
                true
            }
        });
        let coordinator = Self::from_snapshot(snapshot)?;
        {
            let mut inner = coordinator.lock_inner()?;
            for child in children {
                let binding = bindings
                    .iter()
                    .find(|binding| binding.child_token == child.token)
                    .ok_or(SyncError::InvalidSubordinateClaim)?;
                let parent = claim_for_token(&inner.claims, binding.parent_token)
                    .ok_or(SyncError::InvalidSubordinateClaim)?;
                validate_subordinate_scope(&inner, &parent, &child.agent_id, &child.paths)?;
                if child.agent_id != binding.worker_id
                    || child.paths != binding.paths
                    || normalize_claim_paths(&child.paths)? != child.paths
                    || inner
                        .subordinate_claims
                        .insert(child.token, child)
                        .is_some()
                {
                    return Err(SyncError::InvalidSubordinateClaim);
                }
            }
            inner.subordinate_bindings = bindings;
        }
        Ok(coordinator)
    }

    pub(crate) fn claim_subordinate_paths(
        &self,
        parent: &PathClaim,
        worker_id: &str,
        paths: &[PathBuf],
        source_digest: &str,
    ) -> Result<PathClaim> {
        let mut inner = self.lock_inner()?;
        if claim_for_token(&inner.claims, parent.token).as_ref() != Some(parent)
            || normalize_claim_paths(paths)? != paths
            || !valid_source_digest(source_digest)
        {
            return Err(SyncError::InvalidSubordinateClaim);
        }
        if inner.subordinate_bindings.iter().any(|binding| {
            binding.parent_token == parent.token
                && binding.source_digest == source_digest
                && binding.worker_id == worker_id
        }) {
            return Err(SyncError::SubordinateReplay);
        }
        validate_subordinate_scope(&inner, parent, worker_id, paths)?;
        let token = ClaimToken(inner.next_token);
        inner.next_token = inner
            .next_token
            .checked_add(1)
            .ok_or(SyncError::TokenExhausted)?;
        let claim = PathClaim {
            token,
            agent_id: worker_id.to_string(),
            paths: paths.to_vec(),
        };
        inner.subordinate_claims.insert(token, claim.clone());
        inner.subordinate_bindings.push(SubordinateClaimBinding {
            child_token: token,
            parent_token: parent.token,
            source_digest: source_digest.to_string(),
            worker_id: worker_id.to_string(),
            paths: paths.to_vec(),
        });
        Ok(claim)
    }

    pub(crate) fn subordinate_bindings(&self) -> Result<Vec<SubordinateClaimBinding>> {
        Ok(self.lock_inner()?.subordinate_bindings.clone())
    }

    pub fn claim_paths<I, P>(&self, agent_id: impl AsRef<str>, paths: I) -> Result<PathClaim>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let agent_id = normalize_agent_id(agent_id.as_ref())?;
        let paths = normalize_claim_paths(paths)?;
        let mut inner = self.lock_inner()?;

        let token = ClaimToken(inner.next_token);
        inner.next_token = inner
            .next_token
            .checked_add(1)
            .ok_or(SyncError::TokenExhausted)?;
        insert_claim(&mut inner.claims, token, agent_id.clone(), paths.clone())?;

        Ok(PathClaim {
            token,
            agent_id,
            paths,
        })
    }

    pub fn release(&self, token: ClaimToken) -> Result<PathClaim> {
        let mut inner = self.lock_inner()?;
        if inner.subordinate_bindings.iter().any(|binding| {
            binding.parent_token == token
                && inner.subordinate_claims.contains_key(&binding.child_token)
        }) {
            return Err(SyncError::ActiveSubordinates);
        }
        if let Some(child) = inner.subordinate_claims.remove(&token) {
            return Ok(child);
        }
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

        if inner.subordinate_bindings.iter().any(|binding| {
            tokens.contains(&binding.parent_token)
                && inner.subordinate_claims.contains_key(&binding.child_token)
        }) {
            return Err(SyncError::ActiveSubordinates);
        }
        tokens.extend(
            inner
                .subordinate_claims
                .values()
                .filter(|claim| claim.agent_id == agent_id)
                .map(|claim| claim.token),
        );

        let released = tokens
            .iter()
            .filter_map(|token| {
                inner
                    .subordinate_claims
                    .get(token)
                    .cloned()
                    .or_else(|| claim_for_token(&inner.claims, *token))
            })
            .collect();
        inner.claims.retain(|_, entry| entry.agent_id != agent_id);
        inner
            .subordinate_claims
            .retain(|_, claim| claim.agent_id != agent_id);
        Ok(released)
    }

    pub fn owner_of(&self, path: impl AsRef<Path>) -> Result<Option<String>> {
        let path = normalize_repo_path(path.as_ref())?;
        let inner = self.lock_inner()?;

        if let Some(child) = inner.subordinate_claims.values().find(|claim| {
            claim
                .paths
                .iter()
                .any(|scope| path_is_covered_by_claim(&path, scope))
        }) {
            return Ok(Some(child.agent_id.clone()));
        }

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

        if let Some(child) = inner
            .subordinate_claims
            .values()
            .find(|claim| claim.paths.iter().any(|scope| paths_overlap(&path, scope)))
        {
            return Ok(child.agent_id == agent_id
                && child
                    .paths
                    .iter()
                    .any(|scope| path_is_covered_by_claim(&path, scope)));
        }

        Ok(inner.claims.iter().any(|(claimed, entry)| {
            entry.agent_id == agent_id && path_is_covered_by_claim(&path, claimed)
        }))
    }

    pub fn snapshot(&self) -> Result<Vec<PathClaim>> {
        let inner = self.lock_inner()?;
        Ok(all_claims(&inner))
    }

    pub fn to_snapshot(&self) -> Result<SyncSnapshot> {
        let inner = self.lock_inner()?;
        Ok(SyncSnapshot {
            next_token: inner.next_token,
            claims: all_claims(&inner),
        })
    }

    fn lock_inner(&self) -> Result<MutexGuard<'_, Inner>> {
        self.inner.lock().map_err(|_| SyncError::Poisoned)
    }
}

fn all_claims(inner: &Inner) -> Vec<PathClaim> {
    let mut claims = group_claims(&inner.claims);
    claims.extend(
        inner
            .subordinate_claims
            .iter()
            .map(|(token, claim)| (*token, claim.clone())),
    );
    claims.into_values().collect()
}

fn valid_source_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_subordinate_scope(
    inner: &Inner,
    parent: &PathClaim,
    worker_id: &str,
    paths: &[PathBuf],
) -> Result<()> {
    if normalize_agent_id(worker_id)? != worker_id
        || worker_id == parent.agent_id
        || paths.is_empty()
        || normalize_claim_paths(paths)? != paths
        || paths
            .iter()
            .any(|path| !parent.paths.iter().any(|scope| path.starts_with(scope)))
        || parent
            .paths
            .iter()
            .all(|scope| paths.iter().any(|path| scope.starts_with(path)))
        || inner.subordinate_claims.values().any(|claim| {
            claim.agent_id == worker_id
                || claim
                    .paths
                    .iter()
                    .any(|scope| paths.iter().any(|path| paths_overlap(scope, path)))
        })
        || inner
            .claims
            .values()
            .any(|entry| entry.agent_id == worker_id)
    {
        return Err(SyncError::InvalidSubordinateClaim);
    }
    Ok(())
}

pub fn normalize_repo_relative_path(path: impl AsRef<Path>) -> Result<PathBuf> {
    normalize_repo_path(path.as_ref())
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
                if !normalized.pop() {
                    return Err(SyncError::EscapingPath {
                        path: path.to_path_buf(),
                    });
                }
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

fn insert_claim(
    claims: &mut BTreeMap<PathBuf, ClaimEntry>,
    token: ClaimToken,
    agent_id: String,
    paths: Vec<PathBuf>,
) -> Result<()> {
    for requested in &paths {
        if let Some((path, entry)) = find_conflict(claims, requested) {
            return Err(SyncError::Conflict {
                path,
                owner: entry.agent_id,
            });
        }
    }

    for path in paths {
        claims.insert(
            path,
            ClaimEntry {
                token,
                agent_id: agent_id.clone(),
            },
        );
    }

    Ok(())
}

pub(crate) fn paths_overlap(a: &Path, b: &Path) -> bool {
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
    fn normalizes_non_escaping_parent_segments() {
        let coordinator = SyncCoordinator::new();

        let claim = coordinator
            .claim_paths("agent-a", ["src/../README.md"])
            .expect("claim normalized path");

        assert_eq!(claim.paths, vec![PathBuf::from("README.md")]);
        assert_eq!(
            coordinator.owner_of("README.md").expect("owner"),
            Some("agent-a".to_string())
        );
    }

    #[test]
    fn rejects_parent_segments_that_escape_repository() {
        let coordinator = SyncCoordinator::new();

        assert!(matches!(
            coordinator.claim_paths("agent-a", ["src/../../README.md"]),
            Err(SyncError::EscapingPath { .. })
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

    #[test]
    fn persisted_path_claim_rejects_unknown_fields() {
        let value = serde_json::json!({
            "token": 1,
            "agent_id": "agent-a",
            "paths": ["src"],
            "unexpected": true,
        });

        assert!(serde_json::from_value::<PathClaim>(value).is_err());
    }

    #[test]
    fn subordinate_claims_retain_union_and_disjoint_authority_then_refuse_replay() {
        let coordinator = SyncCoordinator::new();
        let parent = coordinator.claim_paths("parent", ["src"]).unwrap();
        let digest = "a".repeat(64);
        let first = coordinator
            .claim_subordinate_paths(&parent, "first", &["src/a.rs".into()], &digest)
            .unwrap();
        let second = coordinator
            .claim_subordinate_paths(&parent, "second", &["src/b.rs".into()], &digest)
            .unwrap();
        assert!(coordinator.snapshot().unwrap().contains(&parent));
        assert!(coordinator.can_write("first", "src/a.rs").unwrap());
        assert!(!coordinator.can_write("first", "src/b.rs").unwrap());
        assert!(!coordinator.can_write("parent", "src/a.rs").unwrap());
        assert_eq!(
            coordinator.release(parent.token).unwrap_err(),
            SyncError::ActiveSubordinates
        );
        assert!(coordinator.claim_paths("outside", ["src/c.rs"]).is_err());
        coordinator.release(first.token).unwrap();
        assert_eq!(
            coordinator
                .claim_subordinate_paths(&parent, "first", &["src/a.rs".into()], &digest)
                .unwrap_err(),
            SyncError::SubordinateReplay
        );
        coordinator.release(second.token).unwrap();
        assert!(coordinator.can_write("parent", "src/a.rs").unwrap());
        coordinator.release(parent.token).unwrap();
        let restored = SyncCoordinator::from_snapshot_with_subordinates(
            coordinator.to_snapshot().unwrap(),
            coordinator.subordinate_bindings().unwrap(),
        )
        .unwrap();
        assert!(restored.snapshot().unwrap().is_empty());
    }

    #[test]
    fn subordinate_scope_and_forged_or_duplicate_snapshot_links_fail_closed() {
        let coordinator = SyncCoordinator::new();
        let parent = coordinator.claim_paths("parent", ["src"]).unwrap();
        let digest = "a".repeat(64);
        for paths in [
            vec![PathBuf::from("src")],
            vec![PathBuf::from("outside.rs")],
            vec![PathBuf::from("src/../outside.rs")],
        ] {
            assert!(coordinator
                .claim_subordinate_paths(&parent, "worker", &paths, &digest)
                .is_err());
        }
        coordinator
            .claim_subordinate_paths(&parent, "worker", &["src/a.rs".into()], &digest)
            .unwrap();
        assert!(coordinator
            .claim_subordinate_paths(&parent, "other", &["src/a.rs".into()], &digest)
            .is_err());
        let snapshot = coordinator.to_snapshot().unwrap();
        assert!(SyncCoordinator::from_snapshot(snapshot.clone()).is_err());
        let bindings = coordinator.subordinate_bindings().unwrap();
        let restored =
            SyncCoordinator::from_snapshot_with_subordinates(snapshot.clone(), bindings.clone())
                .unwrap();
        assert_eq!(
            restored.snapshot().unwrap(),
            coordinator.snapshot().unwrap()
        );
        let mut forged = bindings.clone();
        forged[0].worker_id = "outside".into();
        assert!(
            SyncCoordinator::from_snapshot_with_subordinates(snapshot.clone(), forged).is_err()
        );
        let mut widened = bindings.clone();
        widened[0].paths = vec!["src".into()];
        assert!(
            SyncCoordinator::from_snapshot_with_subordinates(snapshot.clone(), widened).is_err()
        );
        let mut duplicated = bindings.clone();
        duplicated.push(bindings[0].clone());
        assert!(
            SyncCoordinator::from_snapshot_with_subordinates(snapshot.clone(), duplicated).is_err()
        );
        assert!(SyncCoordinator::from_snapshot_with_subordinates(snapshot, Vec::new()).is_err());
    }
}
