use crate::{
    sync::ClaimToken,
    sync_store::{
        lock_existing_authenticated_claims, ExistingClaimBindingRequest,
        ExistingClaimRevalidationError, ExistingClaimsGuard,
    },
    worktree::{
        ExistingManagedWorktreeGuard, ExistingWorktreeBindingRequest,
        ExistingWorktreeHeadExpectation, ExistingWorktreeRevalidationError,
        ManagedWorktreeWriteLease, WorktreeManager, WorktreeRecord,
    },
};
use git2::Oid;
use std::path::{Path, PathBuf};
use thiserror::Error;

const MAX_REVALIDATION_REQUESTS: usize = 4_096;

#[derive(Debug, Clone)]
pub(crate) struct RevalidationRequest<'a> {
    pub agent_id: String,
    pub claim_token: ClaimToken,
    pub claimed_paths: Vec<PathBuf>,
    pub write_lease: &'a ManagedWorktreeWriteLease,
    pub expected_worktree: WorktreeRecord,
    pub expected_head_oid: Oid,
    pub expected_ref_oid: Oid,
}

#[derive(Debug, Clone)]
pub(crate) struct RevalidationHeadExpectation {
    pub agent_id: String,
    pub head_oid: Oid,
    pub ref_oid: Oid,
}

#[derive(Debug, Error)]
pub(crate) enum RevalidationError {
    #[error(transparent)]
    Claims(#[from] ExistingClaimRevalidationError),
    #[error(transparent)]
    Worktree(#[from] ExistingWorktreeRevalidationError),
    #[error("worker revalidation request count must be between 1 and {limit}")]
    RequestLimit { limit: usize },
    #[error("worker revalidation request set contains duplicate agent '{agent_id}'")]
    DuplicateAgent { agent_id: String },
}

#[derive(Debug)]
struct GuardBinding<'a> {
    agent_id: String,
    lease: &'a ManagedWorktreeWriteLease,
}

/// One linearized claim/worktree authority for a bounded worker batch.
///
/// Lock order is always authenticated claims first, then the authenticated
/// managed-worktree registry. Keeping the value alive prevents cooperating
/// release/takeover/reclaim and worktree lifecycle changes until the guarded
/// command, collection, application, and artifact publication are complete.
#[must_use = "the revalidation guard must outlive the protected operation"]
#[derive(Debug)]
pub(crate) struct RevalidationGuard<'a> {
    claims: ExistingClaimsGuard,
    worktrees: ExistingManagedWorktreeGuard<'a>,
    bindings: Vec<GuardBinding<'a>>,
    verification: std::sync::Mutex<()>,
}

impl RevalidationGuard<'_> {
    pub(crate) fn verify(&self) -> Result<(), RevalidationError> {
        let _serial = self
            .verification
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.claims.verify()?;
        self.worktrees.verify()?;
        Ok(())
    }

    pub(crate) fn verify_with_heads(
        &self,
        expectations: &[RevalidationHeadExpectation],
    ) -> Result<(), RevalidationError> {
        let _serial = self
            .verification
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.claims.verify()?;
        let worktree_expectations = expectations
            .iter()
            .map(|expectation| ExistingWorktreeHeadExpectation {
                agent_id: expectation.agent_id.clone(),
                head_oid: expectation.head_oid,
                ref_oid: expectation.ref_oid,
            })
            .collect::<Vec<_>>();
        self.worktrees.verify_with_heads(&worktree_expectations)?;
        Ok(())
    }

    pub(crate) fn write_lease(&self, agent_id: &str) -> Option<&ManagedWorktreeWriteLease> {
        self.bindings
            .iter()
            .find(|binding| binding.agent_id == agent_id)
            .map(|binding| binding.lease)
    }
}

pub(crate) fn revalidate_existing_worker_batch<'a>(
    repo_path: &Path,
    manager: &WorktreeManager,
    requests: Vec<RevalidationRequest<'a>>,
) -> Result<RevalidationGuard<'a>, RevalidationError> {
    revalidate_existing_worker_batch_with_additional_worktrees(
        repo_path,
        manager,
        requests,
        Vec::new(),
    )
}

pub(crate) fn revalidate_existing_worker_batch_with_additional_worktrees<'a>(
    repo_path: &Path,
    manager: &WorktreeManager,
    requests: Vec<RevalidationRequest<'a>>,
    additional_worktrees: Vec<ExistingWorktreeBindingRequest<'a>>,
) -> Result<RevalidationGuard<'a>, RevalidationError> {
    if requests.is_empty() || requests.len() > MAX_REVALIDATION_REQUESTS {
        return Err(RevalidationError::RequestLimit {
            limit: MAX_REVALIDATION_REQUESTS,
        });
    }
    let mut agents = std::collections::BTreeSet::new();
    for request in &requests {
        if !agents.insert(request.agent_id.clone()) {
            return Err(RevalidationError::DuplicateAgent {
                agent_id: request.agent_id.clone(),
            });
        }
    }

    let claim_requests = requests
        .iter()
        .map(|request| ExistingClaimBindingRequest {
            agent_id: request.agent_id.clone(),
            token: request.claim_token,
            paths: request.claimed_paths.clone(),
        })
        .collect::<Vec<_>>();
    let claims = lock_existing_authenticated_claims(repo_path, claim_requests)?;
    if requests
        .len()
        .checked_add(additional_worktrees.len())
        .is_none_or(|count| count > MAX_REVALIDATION_REQUESTS)
    {
        return Err(RevalidationError::RequestLimit {
            limit: MAX_REVALIDATION_REQUESTS,
        });
    }
    let mut worktree_requests = requests
        .iter()
        .map(|request| ExistingWorktreeBindingRequest {
            agent_id: request.agent_id.clone(),
            lease: request.write_lease,
            expected_record: request.expected_worktree.clone(),
            expected_head_oid: request.expected_head_oid,
            expected_ref_oid: request.expected_ref_oid,
        })
        .collect::<Vec<_>>();
    for request in &additional_worktrees {
        if !agents.insert(request.agent_id.clone()) {
            return Err(RevalidationError::DuplicateAgent {
                agent_id: request.agent_id.clone(),
            });
        }
    }
    worktree_requests.extend(additional_worktrees);
    let worktrees = manager.revalidate_existing_write_leases(worktree_requests)?;
    let bindings = requests
        .into_iter()
        .map(|request| GuardBinding {
            agent_id: request.agent_id,
            lease: request.write_lease,
        })
        .collect();
    Ok(RevalidationGuard {
        claims,
        worktrees,
        bindings,
        verification: std::sync::Mutex::new(()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        sync_store::SyncStore,
        worktree::{WorktreeCreateOptions, WorktreeManager},
    };
    use anyhow::{Context, Result};
    use git2::{Oid, Signature};
    use std::{collections::BTreeMap, fs, path::Path, sync::mpsc, time::Duration};
    use tempfile::TempDir;

    struct Fixture {
        _temp: TempDir,
        repo_path: PathBuf,
        manager: WorktreeManager,
        store: SyncStore,
        claim: crate::sync::PathClaim,
        lease: ManagedWorktreeWriteLease,
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
            manager.create_for_test(WorktreeCreateOptions {
                agent_id: "agent-a".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })?;
            let lease = manager.acquire_write_execution_lease("agent-a")?;
            let head = current_head(lease.path())?;
            Ok(Self {
                _temp: temp,
                repo_path,
                manager,
                store,
                claim,
                lease,
                head,
            })
        }

        fn request(&self) -> RevalidationRequest<'_> {
            RevalidationRequest {
                agent_id: "agent-a".to_string(),
                claim_token: self.claim.token,
                claimed_paths: self.claim.paths.clone(),
                write_lease: &self.lease,
                expected_worktree: self.lease.record().clone(),
                expected_head_oid: self.head,
                expected_ref_oid: self.head,
            }
        }

        fn guard(&self) -> Result<RevalidationGuard<'_>> {
            Ok(revalidate_existing_worker_batch(
                &self.repo_path,
                &self.manager,
                vec![self.request()],
            )?)
        }
    }

    #[test]
    fn issue_84_exact_live_claim_head_and_held_exclusive_lease_validate() -> Result<()> {
        let fixture = Fixture::new()?;
        let guard = fixture.guard()?;
        guard.verify()?;
        assert_eq!(
            guard
                .write_lease("agent-a")
                .map(ManagedWorktreeWriteLease::record),
            Some(fixture.lease.record())
        );
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
    fn issue_84_guard_lifetime_blocks_release_through_artifact_publication() -> Result<()> {
        let fixture = Fixture::new()?;
        let guard = fixture.guard()?;
        let store = fixture.store.clone();
        let token = fixture.claim.token;
        let (sender, receiver) = mpsc::sync_channel(1);
        let release = std::thread::spawn(move || {
            let result = store.release(token).map(|claim| claim.token);
            let _ = sender.send(result);
        });
        assert!(receiver.recv_timeout(Duration::from_millis(150)).is_err());
        let artifact = fixture._temp.path().join("published-artifact");
        fs::write(&artifact, b"candidate-bound\n")?;
        assert_eq!(fs::read(&artifact)?, b"candidate-bound\n");
        guard.verify()?;
        drop(guard);
        assert_eq!(
            receiver
                .recv_timeout(Duration::from_secs(5))
                .context("release did not complete after publication guard dropped")??,
            token
        );
        release
            .join()
            .map_err(|_| anyhow::anyhow!("release thread panicked"))?;
        Ok(())
    }

    #[test]
    fn issue_84_release_and_reclaim_by_same_owner_rejects_old_token() -> Result<()> {
        let mut fixture = Fixture::new()?;
        fixture.store.release(fixture.claim.token)?;
        let replacement = fixture.store.claim_paths("agent-a", ["README.md"])?;
        assert_ne!(replacement.token, fixture.claim.token);
        let error = revalidate_existing_worker_batch(
            &fixture.repo_path,
            &fixture.manager,
            vec![fixture.request()],
        )
        .expect_err("old authenticated token must not alias the replacement");
        assert!(
            error.to_string().contains("superseded")
                || error.to_string().contains("released")
                || error.to_string().contains("replaced"),
            "unexpected error: {error}"
        );
        fixture.claim = replacement;
        Ok(())
    }

    #[test]
    fn issue_84_same_branch_name_with_head_and_ref_drift_fails_guard() -> Result<()> {
        let fixture = Fixture::new()?;
        let guard = fixture.guard()?;
        let repo = crate::git_repository::open(fixture.lease.path())?;
        let changed = commit_file(&repo, "README.md", "changed\n")?;
        assert_ne!(changed, fixture.head);
        let error = guard.verify().expect_err("HEAD/ref drift must fail closed");
        assert!(error.to_string().contains("OID mismatch"));
        Ok(())
    }

    #[test]
    fn issue_84_detached_and_wrong_branch_heads_fail_closed() -> Result<()> {
        let fixture = Fixture::new()?;
        let guard = fixture.guard()?;
        let repo = crate::git_repository::open(fixture.lease.path())?;
        repo.set_head_detached(fixture.head)?;
        assert!(guard
            .verify()
            .expect_err("detached HEAD must fail")
            .to_string()
            .contains("detached"));
        drop(guard);

        let expected_ref = format!("refs/heads/{}", fixture.lease.record().branch);
        repo.reference("refs/heads/wrong", fixture.head, true, "test")?;
        repo.set_head("refs/heads/wrong")?;
        let error = revalidate_existing_worker_batch(
            &fixture.repo_path,
            &fixture.manager,
            vec![fixture.request()],
        )
        .expect_err("wrong symbolic branch must fail before collection");
        assert!(error.to_string().contains("wrong branch"));
        repo.set_head(&expected_ref)?;
        Ok(())
    }

    #[test]
    fn issue_84_replaced_worktree_path_identity_is_detected_while_guard_is_held() -> Result<()> {
        let fixture = Fixture::new()?;
        let guard = fixture.guard()?;
        let original = fixture.lease.path().to_path_buf();
        let moved = original.with_extension("replaced-original");
        fs::rename(&original, &moved)?;
        fs::create_dir(&original)?;
        let error = guard.verify().expect_err("replaced path must fail closed");
        assert!(
            error.to_string().contains("binding")
                || error.to_string().contains("repository")
                || error.to_string().contains("worktree"),
            "unexpected error: {error}"
        );
        Ok(())
    }

    #[test]
    fn issue_84_absent_existing_state_fails_without_creating_claim_state() -> Result<()> {
        let fixture = Fixture::new()?;
        let claim_root = crate::git_repository::open(&fixture.repo_path)?
            .commondir()
            .join("maco/state/authenticated-claims-state-v1");
        assert!(claim_root.exists());
        fs::remove_dir_all(&claim_root)?;
        let error = revalidate_existing_worker_batch(
            &fixture.repo_path,
            &fixture.manager,
            vec![fixture.request()],
        )
        .expect_err("missing authenticated state cannot initialize itself");
        assert!(error.to_string().contains("unavailable"));
        assert!(!claim_root.exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn issue_84_transitional_residue_failure_preserves_exact_physical_inventory() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let fixture = Fixture::new()?;
        let state_root = crate::git_repository::open(&fixture.repo_path)?
            .commondir()
            .join("maco/state");
        let consumer_root = state_root.join("authenticated-claims-state-v1");
        let residue = consumer_root.join(".legacy-retirement.sidecar");
        fs::write(&residue, b"unfinished-recovery-evidence")?;
        fs::set_permissions(&residue, fs::Permissions::from_mode(0o600))?;
        let before = recursive_physical_inventory(&state_root)?;
        let error = revalidate_existing_worker_batch(
            &fixture.repo_path,
            &fixture.manager,
            vec![fixture.request()],
        )
        .expect_err("visible recovery residue must stop existing-only access");
        assert!(error.to_string().contains("unavailable"));
        let after = recursive_physical_inventory(&state_root)?;
        assert_eq!(after, before);
        Ok(())
    }

    fn current_head(path: &Path) -> Result<Oid> {
        crate::git_repository::open(path)?
            .head()?
            .target()
            .context("HEAD must resolve directly")
    }

    fn commit_file(repo: &git2::Repository, path: &str, contents: &str) -> Result<Oid> {
        let workdir = repo
            .workdir()
            .context("test repository must have a workdir")?;
        fs::write(workdir.join(path), contents)?;
        let mut index = repo.index()?;
        index.add_path(Path::new(path))?;
        index.write()?;
        let tree_id = index.write_tree()?;
        let tree = repo.find_tree(tree_id)?;
        let signature = Signature::now("maco test", "maco-test@example.invalid")?;
        let parents = repo
            .head()
            .ok()
            .and_then(|head| head.target())
            .map(|oid| repo.find_commit(oid))
            .transpose()?;
        match parents.as_ref() {
            Some(parent) => Ok(repo.commit(
                Some("HEAD"),
                &signature,
                &signature,
                "test commit",
                &tree,
                &[parent],
            )?),
            None => Ok(repo.commit(
                Some("HEAD"),
                &signature,
                &signature,
                "test commit",
                &tree,
                &[],
            )?),
        }
    }

    fn recursive_regular_bytes(root: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>> {
        fn visit(
            root: &Path,
            current: &Path,
            output: &mut BTreeMap<PathBuf, Vec<u8>>,
        ) -> Result<()> {
            for entry in fs::read_dir(current)? {
                let entry = entry?;
                let file_type = entry.file_type()?;
                let path = entry.path();
                if file_type.is_dir() {
                    visit(root, &path, output)?;
                } else if file_type.is_file() {
                    output.insert(path.strip_prefix(root)?.to_path_buf(), fs::read(path)?);
                }
            }
            Ok(())
        }
        let mut output = BTreeMap::new();
        visit(root, root, &mut output)?;
        Ok(output)
    }

    #[cfg(unix)]
    fn recursive_physical_inventory(
        root: &Path,
    ) -> Result<BTreeMap<PathBuf, (u32, u64, u64, Vec<u8>)>> {
        use std::os::unix::fs::MetadataExt;

        fn visit(
            root: &Path,
            current: &Path,
            output: &mut BTreeMap<PathBuf, (u32, u64, u64, Vec<u8>)>,
        ) -> Result<()> {
            for entry in fs::read_dir(current)? {
                let entry = entry?;
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path)?;
                let bytes = if metadata.file_type().is_file() {
                    fs::read(&path)?
                } else {
                    Vec::new()
                };
                output.insert(
                    path.strip_prefix(root)?.to_path_buf(),
                    (metadata.mode(), metadata.dev(), metadata.ino(), bytes),
                );
                if metadata.file_type().is_dir() {
                    visit(root, &path, output)?;
                }
            }
            Ok(())
        }
        let mut output = BTreeMap::new();
        visit(root, root, &mut output)?;
        Ok(output)
    }
}
