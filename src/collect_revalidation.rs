use crate::{
    sync::ClaimToken,
    sync_store::{
        lock_existing_authenticated_claims, ExistingClaimBindingRequest,
        ExistingClaimRevalidationError, ExistingClaimsGuard,
    },
    worktree::{WorktreeManager, WorktreeRecord},
};
use git2::Oid;
use std::path::{Path, PathBuf};
use thiserror::Error;

const MAX_REVALIDATION_REQUESTS: usize = 4_096;

#[derive(Debug, Clone)]
pub(crate) struct RevalidationRequest {
    pub repo_path: PathBuf,
    pub agent_id: String,
    pub claim_token: ClaimToken,
    pub claimed_paths: Vec<PathBuf>,
    pub expected_worktree: WorktreeRecord,
    pub expected_head_oid: Oid,
}

#[derive(Debug, Error)]
pub(crate) enum RevalidationError {
    #[error(transparent)]
    Claims(#[from] ExistingClaimRevalidationError),
    #[error("worker revalidation request count must be between 1 and {limit}")]
    RequestLimit { limit: usize },
    #[error("worker revalidation request set contains duplicate agent '{agent_id}'")]
    DuplicateAgent { agent_id: String },
    #[error("managed worktree for agent '{agent_id}' is unavailable or invalid: {source}")]
    WorktreeUnavailable {
        agent_id: String,
        #[source]
        source: anyhow::Error,
    },
    #[error(
        "agent '{agent_id}' worktree path no longer matches the claimed binding ({expected} vs {actual})"
    )]
    WorktreePathMismatch {
        agent_id: String,
        expected: PathBuf,
        actual: PathBuf,
    },
    #[error("agent '{agent_id}' worktree branch is '{actual}', expected '{expected}'")]
    WrongBranch {
        agent_id: String,
        expected: String,
        actual: String,
    },
    #[error("agent '{agent_id}' worktree HEAD is detached")]
    DetachedHead { agent_id: String },
    #[error("agent '{agent_id}' worktree HEAD/ref OID mismatch")]
    OidMismatch { agent_id: String },
}

/// Claims-only revalidation guard plus a snapshot worktree/HEAD check.
///
/// The guard holds the authenticated claims writer lock so release, heartbeat,
/// sweep, and takeover cannot race the protected mutation. It does **not** hold
/// `managed_worktrees.lock`; worktree identity is re-read on each verify so an
/// unrelated writer can still acquire kernel worktree state.
#[must_use = "the revalidation guard must outlive the protected operation"]
#[derive(Debug)]
pub(crate) struct RevalidationGuard {
    claims: ExistingClaimsGuard,
    requests: Vec<RevalidationRequest>,
    verification: std::sync::Mutex<()>,
}

impl RevalidationGuard {
    pub(crate) fn verify(&self) -> Result<(), RevalidationError> {
        let _serial = self
            .verification
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.claims.verify()?;
        for request in &self.requests {
            verify_worktree_snapshot(request)?;
        }
        Ok(())
    }
}

pub(crate) fn revalidate_existing_worker_batch(
    repo: &Path,
    requests: Vec<RevalidationRequest>,
) -> Result<RevalidationGuard, RevalidationError> {
    validate_request_agents(&requests)?;
    let claims = lock_existing_authenticated_claims(repo, claim_bindings(&requests))?;
    for request in &requests {
        verify_worktree_snapshot(request)?;
    }
    let guard = RevalidationGuard {
        claims,
        requests,
        verification: std::sync::Mutex::new(()),
    };
    guard.verify()?;
    Ok(guard)
}

pub(crate) fn revalidate_claimed_worker(
    repo: &Path,
    agent_id: &str,
    claim_token: ClaimToken,
    claimed_paths: &[PathBuf],
    expected_worktree: &WorktreeRecord,
) -> Result<RevalidationGuard, RevalidationError> {
    let expected_head_oid = current_head(&expected_worktree.path).map_err(|source| {
        RevalidationError::WorktreeUnavailable {
            agent_id: agent_id.to_string(),
            source,
        }
    })?;
    let repo_path = primary_repository_path(repo).map_err(|source| {
        RevalidationError::WorktreeUnavailable {
            agent_id: agent_id.to_string(),
            source,
        }
    })?;
    revalidate_existing_worker_batch(
        &repo_path,
        vec![RevalidationRequest {
            repo_path: repo_path.clone(),
            agent_id: agent_id.to_string(),
            claim_token,
            claimed_paths: claimed_paths.to_vec(),
            expected_worktree: expected_worktree.clone(),
            expected_head_oid,
        }],
    )
}

fn primary_repository_path(path: &Path) -> anyhow::Result<PathBuf> {
    let repo = crate::git_repository::discover(path)?;
    let common = repo.commondir();
    if common.file_name() == Some(std::ffi::OsStr::new(".git")) {
        if let Some(parent) = common.parent() {
            return Ok(parent.to_path_buf());
        }
    }
    Ok(repo.workdir().unwrap_or(common).to_path_buf())
}

fn validate_request_agents(requests: &[RevalidationRequest]) -> Result<(), RevalidationError> {
    if requests.is_empty() || requests.len() > MAX_REVALIDATION_REQUESTS {
        return Err(RevalidationError::RequestLimit {
            limit: MAX_REVALIDATION_REQUESTS,
        });
    }
    let mut seen = std::collections::BTreeSet::new();
    for request in requests {
        if !seen.insert(request.agent_id.as_str()) {
            return Err(RevalidationError::DuplicateAgent {
                agent_id: request.agent_id.clone(),
            });
        }
    }
    Ok(())
}

fn claim_bindings(requests: &[RevalidationRequest]) -> Vec<ExistingClaimBindingRequest> {
    requests
        .iter()
        .map(|request| ExistingClaimBindingRequest {
            agent_id: request.agent_id.clone(),
            token: request.claim_token,
            paths: request.claimed_paths.clone(),
        })
        .collect()
}

fn verify_worktree_snapshot(request: &RevalidationRequest) -> Result<(), RevalidationError> {
    let manager = WorktreeManager::new(&request.repo_path);
    let verified = manager
        .get_managed_verified(&request.agent_id)
        .map_err(|source| RevalidationError::WorktreeUnavailable {
            agent_id: request.agent_id.clone(),
            source,
        })?;
    if verified.path != request.expected_worktree.path {
        return Err(RevalidationError::WorktreePathMismatch {
            agent_id: request.agent_id.clone(),
            expected: request.expected_worktree.path.clone(),
            actual: verified.path,
        });
    }
    if verified.branch != request.expected_worktree.branch {
        return Err(RevalidationError::WrongBranch {
            agent_id: request.agent_id.clone(),
            expected: request.expected_worktree.branch.clone(),
            actual: verified.branch,
        });
    }
    verify_head_and_branch(
        &request.agent_id,
        &request.expected_worktree.path,
        &request.expected_worktree.branch,
        request.expected_head_oid,
    )
}

fn verify_head_and_branch(
    agent_id: &str,
    worktree_path: &Path,
    expected_branch: &str,
    expected_head_oid: Oid,
) -> Result<(), RevalidationError> {
    let repo = crate::git_repository::open(worktree_path).map_err(|source| {
        RevalidationError::WorktreeUnavailable {
            agent_id: agent_id.to_string(),
            source: source.into(),
        }
    })?;
    if repo.head_detached().unwrap_or(true) {
        return Err(RevalidationError::DetachedHead {
            agent_id: agent_id.to_string(),
        });
    }
    let head = repo.head().map_err(|source| RevalidationError::WorktreeUnavailable {
        agent_id: agent_id.to_string(),
        source: source.into(),
    })?;
    let actual_branch = head
        .shorthand()
        .ok()
        .map(str::to_string)
        .or_else(|| {
            head.name().ok().and_then(|name| {
                name.strip_prefix("refs/heads/")
                    .map(str::to_string)
                    .or_else(|| Some(name.to_string()))
            })
        })
        .unwrap_or_default();
    if actual_branch != expected_branch {
        return Err(RevalidationError::WrongBranch {
            agent_id: agent_id.to_string(),
            expected: expected_branch.to_string(),
            actual: actual_branch,
        });
    }
    let oid = head
        .peel_to_commit()
        .map_err(|source| RevalidationError::WorktreeUnavailable {
            agent_id: agent_id.to_string(),
            source: source.into(),
        })?
        .id();
    if oid != expected_head_oid {
        return Err(RevalidationError::OidMismatch {
            agent_id: agent_id.to_string(),
        });
    }
    Ok(())
}

fn current_head(path: &Path) -> anyhow::Result<Oid> {
    let repo = crate::git_repository::open(path)?;
    let oid = repo.head()?.peel_to_commit()?.id();
    Ok(oid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        sync_store::{ClaimTiming, SyncStore},
        worktree::{WorktreeCreateOptions, WorktreeManager},
    };
    use anyhow::{Context, Result};
    use git2::Signature;
    use std::{fs, time::Duration};
    use tempfile::TempDir;

    struct Fixture {
        _temp: TempDir,
        repo_path: PathBuf,
        manager: WorktreeManager,
        store: SyncStore,
        claim: crate::sync::PathClaim,
        worktree: WorktreeRecord,
        head: Oid,
    }

    impl Fixture {
        fn new() -> Result<Self> {
            let temp = TempDir::new()?;
            let repo_path = temp.path().join("repo");
            WorktreeManager::init_repository(&repo_path, "main")?;
            let repo = crate::git_repository::open(&repo_path)?;
            commit_file(&repo, "README.md", "base\n")?;
            let store = SyncStore::open(&repo_path)?;
            let claim = store.claim_paths("agent-a", ["README.md"])?;
            let manager = WorktreeManager::new(&repo_path);
            let worktree = manager.create_for_test(WorktreeCreateOptions {
                agent_id: "agent-a".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })?;
            let head = current_head(&worktree.path)?;
            Ok(Self {
                _temp: temp,
                repo_path,
                manager,
                store,
                claim,
                worktree,
                head,
            })
        }

        fn request(&self) -> RevalidationRequest {
            RevalidationRequest {
                repo_path: self.repo_path.clone(),
                agent_id: "agent-a".to_string(),
                claim_token: self.claim.token,
                claimed_paths: self.claim.paths.clone(),
                expected_worktree: self.worktree.clone(),
                expected_head_oid: self.head,
            }
        }

        fn guard(&self) -> Result<RevalidationGuard> {
            Ok(revalidate_existing_worker_batch(
                &self.repo_path,
                vec![self.request()],
            )?)
        }
    }

    #[test]
    fn issue_84_exact_live_claim_head_and_held_exclusive_lease_validate() -> Result<()> {
        let fixture = Fixture::new()?;
        let _lease = fixture.manager.acquire_write_execution_lease("agent-a")?;
        let guard = fixture.guard()?;
        guard.verify()?;
        Ok(())
    }

    #[test]
    fn issue_84_parallel_literal_preflight_verification_is_serialized() -> Result<()> {
        let fixture = Fixture::new()?;
        let guard = fixture.guard()?;
        std::thread::scope(|scope| {
            let handles = (0..8)
                .map(|_| scope.spawn(|| guard.verify()))
                .collect::<Vec<_>>();
            for handle in handles {
                handle
                    .join()
                    .map_err(|_| anyhow::anyhow!("parallel verifier panicked"))??;
            }
            Ok::<(), anyhow::Error>(())
        })?;
        Ok(())
    }

    #[test]
    fn issue_84_existing_only_guard_preserves_all_state_file_bytes() -> Result<()> {
        let fixture = Fixture::new()?;
        let state_root = crate::git_repository::open(&fixture.repo_path)?
            .commondir()
            .join("maco/state");
        let before = recursive_regular_bytes(&state_root)?;
        let guard = fixture.guard()?;
        guard.verify()?;
        drop(guard);
        let after = recursive_regular_bytes(&state_root)?;
        assert_eq!(after, before);
        Ok(())
    }

    #[test]
    fn issue_84_guard_lifetime_blocks_claim_release() -> Result<()> {
        let fixture = Fixture::new()?;
        let guard = fixture.guard()?;
        let store = fixture.store.clone();
        let token = fixture.claim.token;
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let release = std::thread::spawn(move || {
            let result = store.release(token).map(|claim| claim.token);
            let _ = sender.send(result);
        });
        assert!(receiver.recv_timeout(Duration::from_millis(150)).is_err());
        guard.verify()?;
        drop(guard);
        assert_eq!(
            receiver
                .recv_timeout(Duration::from_secs(5))
                .context("release did not complete after revalidation guard dropped")??,
            token
        );
        release
            .join()
            .map_err(|_| anyhow::anyhow!("release thread panicked"))?;
        Ok(())
    }

    #[test]
    fn issue_84_release_and_reclaim_by_same_owner_rejects_old_token() -> Result<()> {
        let fixture = Fixture::new()?;
        fixture.store.release(fixture.claim.token)?;
        let replacement = fixture.store.claim_paths("agent-a", ["README.md"])?;
        assert_ne!(replacement.token, fixture.claim.token);
        let error = revalidate_existing_worker_batch(&fixture.repo_path, vec![fixture.request()])
            .expect_err("old authenticated token must not alias the replacement");
        assert!(
            error.to_string().contains("superseded")
                || error.to_string().contains("released")
                || error.to_string().contains("replaced"),
            "unexpected error: {error}"
        );
        Ok(())
    }

    #[test]
    fn issue_84_same_branch_name_with_head_and_ref_drift_fails_guard() -> Result<()> {
        let fixture = Fixture::new()?;
        let guard = fixture.guard()?;
        let repo = crate::git_repository::open(&fixture.worktree.path)?;
        let changed = commit_file(&repo, "README.md", "changed\n")?;
        assert_ne!(changed, fixture.head);
        let error = guard.verify().expect_err("HEAD/ref drift must fail closed");
        assert!(
            error.to_string().contains("OID mismatch"),
            "unexpected error: {error}"
        );
        Ok(())
    }

    #[test]
    fn issue_84_detached_and_wrong_branch_heads_fail_closed() -> Result<()> {
        let fixture = Fixture::new()?;
        let guard = fixture.guard()?;
        let repo = crate::git_repository::open(&fixture.worktree.path)?;
        repo.set_head_detached(fixture.head)?;
        let detached = guard
            .verify()
            .expect_err("detached HEAD must fail")
            .to_string();
        assert!(
            detached.contains("detached")
                || detached.contains("unavailable")
                || detached.contains("invalid")
                || detached.contains("branch"),
            "unexpected detached-head error: {detached}"
        );
        drop(guard);

        repo.reference("refs/heads/wrong", fixture.head, true, "test")?;
        repo.set_head("refs/heads/wrong")?;
        let error = revalidate_existing_worker_batch(&fixture.repo_path, vec![fixture.request()])
            .expect_err("wrong symbolic branch must fail");
        assert!(
            matches!(
                error,
                RevalidationError::WrongBranch { .. }
                    | RevalidationError::WorktreeUnavailable { .. }
            ),
            "unexpected error: {error:?}"
        );
        Ok(())
    }

    #[test]
    fn issue_84_replaced_worktree_path_identity_is_detected() -> Result<()> {
        let fixture = Fixture::new()?;
        let guard = fixture.guard()?;
        let original = fixture.worktree.path.clone();
        let moved = original.with_extension("replaced-original");
        fs::rename(&original, &moved)?;
        fs::create_dir(&original)?;
        let error = guard.verify().expect_err("replaced path must fail closed");
        assert!(
            error.to_string().contains("unavailable")
                || error.to_string().contains("invalid")
                || error.to_string().contains("worktree")
                || error.to_string().contains("repository"),
            "unexpected error: {error}"
        );
        Ok(())
    }

    #[test]
    fn issue_84_absent_existing_state_fails_without_creating_claim_state() -> Result<()> {
        let temp = TempDir::new()?;
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main")?;
        let repo = crate::git_repository::open(&repo_path)?;
        commit_file(&repo, "README.md", "base\n")?;
        let state_root = repo.commondir().join("maco/state");
        assert!(!state_root.exists());
        let dummy = WorktreeRecord {
            name: "agent-a".to_string(),
            path: repo_path.clone(),
            branch: "main".to_string(),
        };
        let error = revalidate_existing_worker_batch(
            &repo_path,
            vec![RevalidationRequest {
                repo_path: repo_path.clone(),
                agent_id: "agent-a".to_string(),
                claim_token: crate::sync::ClaimToken::from_u64(1),
                claimed_paths: vec![PathBuf::from("README.md")],
                expected_worktree: dummy,
                expected_head_oid: current_head(&repo_path)?,
            }],
        )
        .expect_err("missing claims state must fail closed");
        assert!(
            !state_root.exists(),
            "existing-only revalidation must not bootstrap claims state"
        );
        assert!(
            error.to_string().contains("unavailable")
                || error.to_string().contains("absent")
                || error.to_string().contains("missing"),
            "unexpected error: {error}"
        );
        Ok(())
    }

    #[test]
    fn issue_84_unrelated_writer_acquires_managed_worktrees_lock_while_guard_is_held() -> Result<()>
    {
        let fixture = Fixture::new()?;
        let guard = fixture.guard()?;
        let manager = WorktreeManager::new(&fixture.repo_path);
        let started = std::time::Instant::now();
        manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-b".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .context("unrelated writer during revalidation")?;
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "managed_worktrees.lock must not be held across revalidation"
        );
        guard.verify()?;
        Ok(())
    }

    #[test]
    fn issue_84_stale_claim_fails_before_worktree_mutation() -> Result<()> {
        let fixture = Fixture::new()?;
        let stale = fixture.store.claim_paths_with_timing(
            "agent-stale",
            ["src"],
            ClaimTiming::new(1, 2).expect("timing"),
        )?;
        std::thread::sleep(Duration::from_secs(3));
        fixture.store.sweep_stale()?;
        let error = revalidate_existing_worker_batch(
            &fixture.repo_path,
            vec![RevalidationRequest {
                repo_path: fixture.repo_path.clone(),
                agent_id: "agent-stale".to_string(),
                claim_token: stale.claim.token,
                claimed_paths: stale.claim.paths.clone(),
                expected_worktree: fixture.worktree.clone(),
                expected_head_oid: fixture.head,
            }],
        )
        .expect_err("stale claim must fail closed");
        assert!(
            error.to_string().contains("not live"),
            "unexpected error: {error}"
        );
        Ok(())
    }

    fn commit_file(repo: &git2::Repository, path: &str, contents: &str) -> Result<Oid> {
        fs::write(repo.workdir().context("workdir")?.join(path), contents)?;
        let mut index = repo.index()?;
        index.add_path(Path::new(path))?;
        index.write()?;
        let tree_id = index.write_tree()?;
        let tree = repo.find_tree(tree_id)?;
        let signature = Signature::now("maco", "maco@example.com")?;
        let parents = match repo.head() {
            Ok(head) => vec![head.peel_to_commit()?],
            Err(_) => Vec::new(),
        };
        let parent_refs = parents.iter().collect::<Vec<_>>();
        Ok(repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            "test",
            &tree,
            &parent_refs,
        )?)
    }

    fn recursive_regular_bytes(root: &Path) -> Result<std::collections::BTreeMap<PathBuf, Vec<u8>>> {
        fn visit(
            root: &Path,
            current: &Path,
            output: &mut std::collections::BTreeMap<PathBuf, Vec<u8>>,
        ) -> Result<()> {
            for entry in fs::read_dir(current)? {
                let entry = entry?;
                let path = entry.path();
                let relative = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
                if entry.file_type()?.is_dir() {
                    visit(root, &path, output)?;
                } else if entry.file_type()?.is_file() {
                    output.insert(relative, fs::read(path)?);
                }
            }
            Ok(())
        }
        let mut output = std::collections::BTreeMap::new();
        if root.exists() {
            visit(root, root, &mut output)?;
        }
        Ok(output)
    }
}
