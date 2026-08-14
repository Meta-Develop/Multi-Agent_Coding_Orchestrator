use crate::{
    sync::{ClaimToken, PathClaim},
    sync_store::{LockedClaimsSnapshot, SyncStore},
    worktree::{WorktreeManager, WorktreeRecord},
};
use anyhow::Context;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Orchestrator-independent inputs for the worker collection boundary.
#[derive(Debug, Clone, Copy)]
pub struct CollectRevalidationRequest<'a> {
    pub agent_id: &'a str,
    pub claim_token: ClaimToken,
    pub claimed_paths: &'a [PathBuf],
    pub expected_worktree: &'a WorktreeRecord,
    pub expected_branch: &'a str,
}

/// Keeps the authenticated claim writer lock held across result collection.
#[must_use = "the guard must remain alive until result collection finishes"]
#[derive(Debug)]
pub struct CollectRevalidationGuard {
    claims: LockedClaimsSnapshot,
    agent_id: String,
}

impl CollectRevalidationGuard {
    /// Rechecks the authenticated claim lock binding before releasing the guard.
    pub fn verify(&self) -> Result<(), CollectRevalidationError> {
        self.claims
            .verify()
            .map_err(|source| CollectRevalidationError::ClaimStateUnavailable {
                agent_id: self.agent_id.clone(),
                source,
            })
    }
}

#[derive(Debug, Error)]
pub enum CollectRevalidationError {
    #[error("claim binding check failed for agent '{agent_id}': authenticated claim state is unavailable")]
    ClaimStateUnavailable {
        agent_id: String,
        #[source]
        source: anyhow::Error,
    },
    #[error(
        "claim binding broke for agent '{agent_id}': claim token {claim_token} on {claimed_paths:?} is no longer held"
    )]
    ClaimReleased {
        agent_id: String,
        claim_token: u64,
        claimed_paths: Vec<PathBuf>,
    },
    #[error(
        "claim ownership binding broke for agent '{agent_id}': path '{path}' is now held by agent '{actual_owner}' with token {actual_token}"
    )]
    ClaimTakenOver {
        agent_id: String,
        path: PathBuf,
        actual_owner: String,
        actual_token: u64,
    },
    #[error(
        "claim identity binding broke for agent '{agent_id}': expected token {expected_token}, found replacement token {actual_token}"
    )]
    ClaimSuperseded {
        agent_id: String,
        expected_token: u64,
        actual_token: u64,
    },
    #[error(
        "claim ownership binding broke for agent '{agent_id}': token {claim_token} is held by agent '{actual_owner}'"
    )]
    ClaimOwnerMismatch {
        agent_id: String,
        claim_token: u64,
        actual_owner: String,
    },
    #[error(
        "claim path binding broke for agent '{agent_id}' and token {claim_token}: expected {expected_paths:?}, found {actual_paths:?}"
    )]
    ClaimPathsMismatch {
        agent_id: String,
        claim_token: u64,
        expected_paths: Vec<PathBuf>,
        actual_paths: Vec<PathBuf>,
    },
    #[error(
        "worktree identity binding broke for agent '{agent_id}': expected {expected:?}, found {actual:?}"
    )]
    WorktreeIdentityMismatch {
        agent_id: String,
        expected: Box<WorktreeRecord>,
        actual: Box<WorktreeRecord>,
    },
    #[error(
        "worktree identity binding broke for agent '{agent_id}': expected managed worktree {expected:?} is unavailable"
    )]
    WorktreeBindingUnavailable {
        agent_id: String,
        expected: WorktreeRecord,
        #[source]
        source: anyhow::Error,
    },
    #[error("branch binding check failed for agent '{agent_id}' at {path}: HEAD is unreadable")]
    BranchInspectionFailed {
        agent_id: String,
        path: PathBuf,
        #[source]
        source: anyhow::Error,
    },
    #[error(
        "branch binding broke for agent '{agent_id}': expected HEAD on '{expected_branch}', found {actual_branch:?}"
    )]
    BranchMismatch {
        agent_id: String,
        expected_branch: String,
        actual_branch: Option<String>,
    },
}

/// Revalidates the claim, managed worktree identity, and symbolic HEAD branch.
///
/// The returned guard retains the authenticated claims writer lock. Callers
/// must keep it alive until immutable result collection has completed.
pub fn revalidate_for_collection(
    store: &SyncStore,
    manager: &WorktreeManager,
    request: CollectRevalidationRequest<'_>,
) -> Result<CollectRevalidationGuard, CollectRevalidationError> {
    let claims = store.lock_authenticated_snapshot().map_err(|source| {
        CollectRevalidationError::ClaimStateUnavailable {
            agent_id: request.agent_id.to_string(),
            source,
        }
    })?;
    verify_claim_binding(claims.claims(), request)?;

    let head_branch = inspect_head_branch(&request.expected_worktree.path);
    let actual_worktree = match manager.get_managed_verified(request.agent_id) {
        Ok(actual) => actual,
        Err(source) => {
            if let Ok(actual_branch) = &head_branch {
                if actual_branch.as_deref() != Some(request.expected_branch) {
                    return Err(CollectRevalidationError::BranchMismatch {
                        agent_id: request.agent_id.to_string(),
                        expected_branch: request.expected_branch.to_string(),
                        actual_branch: actual_branch.clone(),
                    });
                }
            }
            return Err(CollectRevalidationError::WorktreeBindingUnavailable {
                agent_id: request.agent_id.to_string(),
                expected: request.expected_worktree.clone(),
                source,
            });
        }
    };
    if actual_worktree != *request.expected_worktree
        || actual_worktree.name != request.agent_id
        || actual_worktree.branch != request.expected_branch
    {
        return Err(CollectRevalidationError::WorktreeIdentityMismatch {
            agent_id: request.agent_id.to_string(),
            expected: Box::new(request.expected_worktree.clone()),
            actual: Box::new(actual_worktree),
        });
    }

    let actual_branch =
        head_branch.map_err(|source| CollectRevalidationError::BranchInspectionFailed {
            agent_id: request.agent_id.to_string(),
            path: request.expected_worktree.path.clone(),
            source,
        })?;
    if actual_branch.as_deref() != Some(request.expected_branch) {
        return Err(CollectRevalidationError::BranchMismatch {
            agent_id: request.agent_id.to_string(),
            expected_branch: request.expected_branch.to_string(),
            actual_branch,
        });
    }

    let guard = CollectRevalidationGuard {
        claims,
        agent_id: request.agent_id.to_string(),
    };
    guard.verify()?;
    Ok(guard)
}

fn verify_claim_binding(
    claims: &[PathClaim],
    request: CollectRevalidationRequest<'_>,
) -> Result<(), CollectRevalidationError> {
    if let Some(active) = claims
        .iter()
        .find(|claim| claim.token == request.claim_token)
    {
        if active.agent_id != request.agent_id {
            return Err(CollectRevalidationError::ClaimOwnerMismatch {
                agent_id: request.agent_id.to_string(),
                claim_token: request.claim_token.get(),
                actual_owner: active.agent_id.clone(),
            });
        }
        if !same_paths(&active.paths, request.claimed_paths) {
            return Err(CollectRevalidationError::ClaimPathsMismatch {
                agent_id: request.agent_id.to_string(),
                claim_token: request.claim_token.get(),
                expected_paths: request.claimed_paths.to_vec(),
                actual_paths: active.paths.clone(),
            });
        }
        return Ok(());
    }

    if let Some((active, path)) = claims.iter().find_map(|claim| {
        request.claimed_paths.iter().find_map(|expected| {
            claim
                .paths
                .iter()
                .any(|actual| paths_overlap(expected, actual))
                .then_some((claim, expected.clone()))
        })
    }) {
        if active.agent_id == request.agent_id {
            return Err(CollectRevalidationError::ClaimSuperseded {
                agent_id: request.agent_id.to_string(),
                expected_token: request.claim_token.get(),
                actual_token: active.token.get(),
            });
        }
        return Err(CollectRevalidationError::ClaimTakenOver {
            agent_id: request.agent_id.to_string(),
            path,
            actual_owner: active.agent_id.clone(),
            actual_token: active.token.get(),
        });
    }

    Err(CollectRevalidationError::ClaimReleased {
        agent_id: request.agent_id.to_string(),
        claim_token: request.claim_token.get(),
        claimed_paths: request.claimed_paths.to_vec(),
    })
}

fn same_paths(left: &[PathBuf], right: &[PathBuf]) -> bool {
    let mut left = left.to_vec();
    let mut right = right.to_vec();
    left.sort();
    right.sort();
    left == right
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn inspect_head_branch(path: &Path) -> anyhow::Result<Option<String>> {
    let repository = crate::git_repository::open(path)
        .with_context(|| format!("failed to open worktree {}", path.display()))?;
    let head = repository
        .head()
        .context("failed to inspect worktree HEAD")?;
    if !head.is_branch() {
        return Ok(None);
    }
    let name = head
        .name()
        .context("worktree HEAD branch name is not valid UTF-8")?;
    Ok(name.strip_prefix("refs/heads/").map(ToOwned::to_owned))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worktree::WorktreeCreateOptions;
    use git2::{Repository, Signature};
    use std::fs;
    use tempfile::TempDir;

    const AGENT_ID: &str = "collect-agent";
    const CLAIMED_PATH: &str = "src/lib.rs";

    struct Fixture {
        _temp: TempDir,
        manager: WorktreeManager,
        store: SyncStore,
        record: WorktreeRecord,
        claim: PathClaim,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().expect("create fixture directory");
            let repo_path = temp.path().join("repo");
            WorktreeManager::init_repository(&repo_path, "main")
                .expect("initialize fixture repository");
            let repository = Repository::open(&repo_path).expect("open fixture repository");
            fs::write(repo_path.join("README.md"), "fixture\n")
                .expect("write fixture repository content");
            commit_all(&repository);
            let manager = WorktreeManager::new(&repo_path);
            let record = manager
                .create_for_test(WorktreeCreateOptions {
                    agent_id: AGENT_ID.to_string(),
                    branch: None,
                    base: None,
                    worktree_root: None,
                })
                .expect("create managed fixture worktree");
            let store = SyncStore::open(&repo_path).expect("open fixture claims store");
            let claim = store
                .claim_paths(AGENT_ID, [CLAIMED_PATH])
                .expect("claim fixture path");
            Self {
                _temp: temp,
                manager,
                store,
                record,
                claim,
            }
        }

        fn request(&self) -> CollectRevalidationRequest<'_> {
            CollectRevalidationRequest {
                agent_id: AGENT_ID,
                claim_token: self.claim.token,
                claimed_paths: &self.claim.paths,
                expected_worktree: &self.record,
                expected_branch: &self.record.branch,
            }
        }
    }

    fn commit_all(repository: &Repository) {
        let mut index = repository.index().expect("open fixture index");
        index
            .add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)
            .expect("stage fixture content");
        index.write().expect("write fixture index");
        let tree_id = index.write_tree().expect("write fixture tree");
        let tree = repository.find_tree(tree_id).expect("find fixture tree");
        let signature = Signature::now("maco test", "maco-test@example.invalid")
            .expect("create fixture signature");
        repository
            .commit(
                Some("HEAD"),
                &signature,
                &signature,
                "initial fixture",
                &tree,
                &[],
            )
            .expect("commit fixture content");
    }

    #[test]
    fn collect_revalidation_accepts_matching_claim_worktree_and_branch() {
        let fixture = Fixture::new();
        let guard = revalidate_for_collection(&fixture.store, &fixture.manager, fixture.request())
            .expect("matching bindings pass");
        guard.verify().expect("claim boundary remains valid");
    }

    #[test]
    fn collect_revalidation_rejects_released_claim() {
        let fixture = Fixture::new();
        fixture
            .store
            .release(fixture.claim.token)
            .expect("release fixture claim");

        let error = revalidate_for_collection(&fixture.store, &fixture.manager, fixture.request())
            .expect_err("released claim must fail closed");
        assert!(matches!(
            error,
            CollectRevalidationError::ClaimReleased { .. }
        ));
    }

    #[test]
    fn collect_revalidation_rejects_claim_taken_over_by_another_agent() {
        let fixture = Fixture::new();
        fixture
            .store
            .release(fixture.claim.token)
            .expect("release fixture claim");
        fixture
            .store
            .claim_paths("replacement-agent", [CLAIMED_PATH])
            .expect("replace fixture claim");

        let error = revalidate_for_collection(&fixture.store, &fixture.manager, fixture.request())
            .expect_err("claim takeover must fail closed");
        assert!(matches!(
            error,
            CollectRevalidationError::ClaimTakenOver {
                actual_owner,
                ..
            } if actual_owner == "replacement-agent"
        ));
    }

    #[test]
    fn collect_revalidation_rejects_unregistered_worktree() {
        let fixture = Fixture::new();
        fixture
            .store
            .release(fixture.claim.token)
            .expect("release claim before fixture removal");
        fixture
            .manager
            .remove(AGENT_ID, true, true)
            .expect("remove managed fixture worktree");
        let replacement_claim = fixture
            .store
            .claim_paths(AGENT_ID, [CLAIMED_PATH])
            .expect("restore live claim after fixture removal");
        let request = CollectRevalidationRequest {
            agent_id: AGENT_ID,
            claim_token: replacement_claim.token,
            claimed_paths: &replacement_claim.paths,
            expected_worktree: &fixture.record,
            expected_branch: &fixture.record.branch,
        };

        let error = revalidate_for_collection(&fixture.store, &fixture.manager, request)
            .expect_err("unregistered worktree must fail closed");
        assert!(matches!(
            error,
            CollectRevalidationError::WorktreeBindingUnavailable { .. }
        ));
    }

    #[test]
    fn collect_revalidation_rejects_switched_branch() {
        let fixture = Fixture::new();
        let repository = Repository::open(&fixture.record.path).expect("open fixture worktree");
        let commit = repository
            .head()
            .and_then(|head| head.peel_to_commit())
            .expect("resolve fixture commit");
        repository
            .branch("switched-branch", &commit, false)
            .expect("create replacement branch");
        repository
            .set_head("refs/heads/switched-branch")
            .expect("switch fixture HEAD");

        let error = revalidate_for_collection(&fixture.store, &fixture.manager, fixture.request())
            .expect_err("switched branch must fail closed");
        assert!(matches!(
            error,
            CollectRevalidationError::BranchMismatch {
                actual_branch: Some(actual),
                ..
            } if actual == "switched-branch"
        ));
    }
}
