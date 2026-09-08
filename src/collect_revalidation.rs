use crate::{
    sync::ClaimToken,
    sync_store::{
        lock_existing_authenticated_claims, persist_exact_owner_heartbeat_under_held_lock,
        snapshot_lock_busy, ExistingClaimBindingRequest, ExistingClaimRevalidationError,
        ExistingClaimsGuard, HeldClaimsPersist,
    },
    worktree::{WorktreeManager, WorktreeRecord},
};
use git2::Oid;
use std::{
    path::{Path, PathBuf},
    sync::{mpsc, Arc, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
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
    #[error("guard-owned heartbeat already started")]
    HeartbeatAlreadyStarted,
    #[error("guard-owned heartbeat missing liveness for agent '{agent_id}' token {token}")]
    HeartbeatMissingLiveness { agent_id: String, token: u64 },
    #[error("guard-owned heartbeat interval must be at least 1 second")]
    HeartbeatInvalidInterval,
    #[error("guard-owned heartbeat persist failed: {source}")]
    HeartbeatPersist {
        #[source]
        source: anyhow::Error,
    },
    #[error("guard-owned heartbeat worker panicked")]
    HeartbeatJoinPanic,
}

struct HeartbeatWorker {
    stop_tx: mpsc::Sender<()>,
    join: JoinHandle<Result<(), RevalidationError>>,
}

impl std::fmt::Debug for HeartbeatWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeartbeatWorker").finish_non_exhaustive()
    }
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
    verification: Mutex<()>,
    heartbeat: Mutex<Option<HeartbeatWorker>>,
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

    pub(crate) fn start_guard_owned_heartbeat(&self) -> Result<(), RevalidationError> {
        let mut slot = self
            .heartbeat
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if slot.is_some() {
            return Err(RevalidationError::HeartbeatAlreadyStarted);
        }
        let persist = self.claims.persist_handle();
        let interval = heartbeat_interval_seconds(&persist)?;
        let (stop_tx, stop_rx) = mpsc::channel();
        let join = thread::Builder::new()
            .name("maco-guard-heartbeat".to_string())
            .spawn(move || run_guard_owned_heartbeat(persist, stop_rx, interval))
            .map_err(|source| RevalidationError::HeartbeatPersist {
                source: anyhow::Error::from(source)
                    .context("failed to spawn guard-owned heartbeat worker"),
            })?;
        *slot = Some(HeartbeatWorker { stop_tx, join });
        Ok(())
    }

    pub(crate) fn stop_guard_owned_heartbeat(&self) -> Result<(), RevalidationError> {
        let worker = {
            let mut slot = self
                .heartbeat
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            slot.take()
        };
        let Some(worker) = worker else {
            return Ok(());
        };
        let _ = worker.stop_tx.send(());
        match worker.join.join() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(RevalidationError::HeartbeatJoinPanic),
        }
    }
}

impl Drop for RevalidationGuard {
    fn drop(&mut self) {
        let _ = self.stop_guard_owned_heartbeat();
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
        verification: Mutex::new(()),
        heartbeat: Mutex::new(None),
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
    let repo_path =
        primary_repository_path(repo).map_err(|source| RevalidationError::WorktreeUnavailable {
            agent_id: agent_id.to_string(),
            source,
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
    let head = repo
        .head()
        .map_err(|source| RevalidationError::WorktreeUnavailable {
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

fn missing_liveness(agent_id: String, token: u64) -> RevalidationError {
    RevalidationError::HeartbeatMissingLiveness { agent_id, token }
}

fn heartbeat_interval_seconds(
    persist: &Mutex<HeldClaimsPersist>,
) -> Result<u64, RevalidationError> {
    let held = persist
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let interval = held
        .min_heartbeat_interval_seconds()
        .map_err(|(agent_id, token)| missing_liveness(agent_id, token))?;
    if interval == 0 {
        return Err(RevalidationError::HeartbeatInvalidInterval);
    }
    Ok(interval)
}

fn due_unix_seconds(persist: &HeldClaimsPersist, interval: u64) -> Result<u64, RevalidationError> {
    persist
        .next_due_unix_seconds(interval)
        .map_err(|(agent_id, token)| missing_liveness(agent_id, token))
}

fn current_unix_seconds() -> Result<u64, RevalidationError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|source| RevalidationError::HeartbeatPersist {
            source: anyhow::Error::from(source).context("system clock is before the Unix epoch"),
        })
}

fn run_guard_owned_heartbeat(
    persist: Arc<Mutex<HeldClaimsPersist>>,
    stop_rx: mpsc::Receiver<()>,
    interval: u64,
) -> Result<(), RevalidationError> {
    loop {
        let due = {
            let held = persist
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            due_unix_seconds(&held, interval)?
        };
        let now = current_unix_seconds()?;
        let wait = Duration::from_secs(due.saturating_sub(now));
        match stop_rx.recv_timeout(wait) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        loop {
            match stop_rx.try_recv() {
                Ok(()) | Err(mpsc::TryRecvError::Disconnected) => return Ok(()),
                Err(mpsc::TryRecvError::Empty) => {}
            }
            let now = current_unix_seconds()?;
            match persist_exact_owner_heartbeat_under_held_lock(&persist, now) {
                Ok(()) => break,
                Err(error) if snapshot_lock_busy(&error) => {
                    match stop_rx.recv_timeout(Duration::from_millis(50)) {
                        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    }
                }
                Err(error) => {
                    return Err(RevalidationError::HeartbeatPersist { source: error });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        sync_store::{
            peek_liveness_without_claims_lock, persist_exact_owner_heartbeat_under_held_lock,
            queue_heartbeat_persist_fault, ClaimTiming, HeartbeatPersistFault, SyncStore,
        },
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
            Self::new_with_timing(ClaimTiming::default())
        }

        fn new_with_timing(timing: ClaimTiming) -> Result<Self> {
            let temp = TempDir::new()?;
            let repo_path = temp.path().join("repo");
            WorktreeManager::init_repository(&repo_path, "main")?;
            let repo = crate::git_repository::open(&repo_path)?;
            commit_file(&repo, "README.md", "base\n")?;
            let store = SyncStore::open(&repo_path)?;
            let claim = store
                .claim_paths_with_timing("agent-a", ["README.md"], timing)?
                .claim;
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

    fn heartbeat_row_for_agent(
        repo_path: &Path,
        agent_id: &str,
    ) -> Result<crate::sync_store::PeekedClaimLiveness> {
        peek_liveness_without_claims_lock(repo_path)?
            .into_iter()
            .find(|row| row.agent_id == agent_id)
            .context("missing peeked liveness row")
    }

    #[test]
    fn revalidation_guard_stays_sync_with_heartbeat_join_behind_mutex() {
        fn assert_sync<T: Sync>() {}
        fn assert_send<T: Send>() {}
        assert_sync::<RevalidationGuard>();
        assert_send::<HeldClaimsPersist>();
        assert_send::<RevalidationGuard>();
    }

    #[test]
    fn guard_owned_heartbeat_second_start_fails_and_stop_is_safe_twice() -> Result<()> {
        let fixture = Fixture::new()?;
        let guard = fixture.guard()?;
        guard.start_guard_owned_heartbeat()?;
        let error = guard
            .start_guard_owned_heartbeat()
            .expect_err("second start must fail");
        assert!(
            matches!(error, RevalidationError::HeartbeatAlreadyStarted),
            "unexpected second-start error: {error}"
        );
        guard.stop_guard_owned_heartbeat()?;
        guard.stop_guard_owned_heartbeat()?;
        Ok(())
    }

    #[test]
    fn guard_owned_heartbeat_absent_lets_claim_go_stale_after_hold() -> Result<()> {
        let fixture = Fixture::new_with_timing(ClaimTiming::new(1, 3)?)?;
        let guard = fixture.guard()?;
        std::thread::scope(|scope| {
            scope.spawn(|| std::thread::sleep(Duration::from_secs(4)));
        });
        drop(guard);
        let report = fixture.store.sweep_stale()?;
        assert!(
            report
                .newly_takeover_eligible
                .iter()
                .any(|claim_id| claim_id == &format!("claim-{:020}", fixture.claim.token.get())),
            "no-start hold must make the claim takeover-eligible, got {:?}",
            report.newly_takeover_eligible
        );
        Ok(())
    }

    #[test]
    fn guard_owned_heartbeat_verify_ok_after_ticks_and_no_tick_without_start() -> Result<()> {
        let fixture = Fixture::new_with_timing(ClaimTiming::new(1, 3)?)?;
        let before = heartbeat_row_for_agent(&fixture.repo_path, "agent-a")?;
        let guard = fixture.guard()?;
        std::thread::sleep(Duration::from_secs(2));
        let without_start = heartbeat_row_for_agent(&fixture.repo_path, "agent-a")?;
        assert_eq!(
            without_start.heartbeat_unix_seconds, before.heartbeat_unix_seconds,
            "timestamps must not advance from this unit without start"
        );
        guard.start_guard_owned_heartbeat()?;
        let deadline = std::time::Instant::now() + Duration::from_secs(8);
        loop {
            let row = heartbeat_row_for_agent(&fixture.repo_path, "agent-a")?;
            if row.heartbeat_unix_seconds > before.heartbeat_unix_seconds {
                break;
            }
            if std::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "worker did not advance heartbeat_unix_seconds (before={}, after={})",
                    before.heartbeat_unix_seconds,
                    row.heartbeat_unix_seconds
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        guard.verify()?;
        guard.stop_guard_owned_heartbeat()?;
        Ok(())
    }

    #[test]
    fn guard_owned_heartbeat_busy_retry_does_not_kill_worker() -> Result<()> {
        let fixture = Fixture::new_with_timing(ClaimTiming::new(1, 3)?)?;
        let before = heartbeat_row_for_agent(&fixture.repo_path, "agent-a")?;
        queue_heartbeat_persist_fault(&fixture.repo_path, HeartbeatPersistFault::Busy);
        queue_heartbeat_persist_fault(&fixture.repo_path, HeartbeatPersistFault::Busy);
        let guard = fixture.guard()?;
        guard.start_guard_owned_heartbeat()?;
        let deadline = std::time::Instant::now() + Duration::from_secs(8);
        loop {
            let row = heartbeat_row_for_agent(&fixture.repo_path, "agent-a")?;
            if row.heartbeat_unix_seconds > before.heartbeat_unix_seconds {
                break;
            }
            if std::time::Instant::now() >= deadline {
                anyhow::bail!("busy retry worker never persisted a heartbeat");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        guard.stop_guard_owned_heartbeat()?;
        Ok(())
    }

    #[test]
    fn guard_owned_heartbeat_stop_surfaces_persist_error() -> Result<()> {
        let fixture = Fixture::new_with_timing(ClaimTiming::new(1, 3)?)?;
        queue_heartbeat_persist_fault(
            &fixture.repo_path,
            HeartbeatPersistFault::Fatal("injected exact-owner persist failure"),
        );
        let guard = fixture.guard()?;
        guard.start_guard_owned_heartbeat()?;
        std::thread::sleep(Duration::from_secs(2));
        let error = guard
            .stop_guard_owned_heartbeat()
            .expect_err("persist failure must fail stop");
        let message = error.to_string();
        assert!(
            message.contains("injected exact-owner persist failure"),
            "unexpected persist error: {error}"
        );
        Ok(())
    }

    #[test]
    fn persist_exact_owner_heartbeat_under_held_lock_advances_and_preserves_identity() -> Result<()>
    {
        let fixture = Fixture::new_with_timing(ClaimTiming::new(1, 3)?)?;
        let before = heartbeat_row_for_agent(&fixture.repo_path, "agent-a")?;
        let guard = fixture.guard()?;
        std::thread::sleep(Duration::from_secs(1));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("unix time")
            .as_secs();
        persist_exact_owner_heartbeat_under_held_lock(&guard.claims.persist_handle(), now)?;
        let after = heartbeat_row_for_agent(&fixture.repo_path, "agent-a")?;
        assert!(
            after.heartbeat_unix_seconds > before.heartbeat_unix_seconds,
            "held-lock persist must advance heartbeat_unix_seconds"
        );
        assert_eq!(after.token, fixture.claim.token);
        assert_eq!(after.agent_id, "agent-a");
        assert_eq!(after.paths, fixture.claim.paths);
        assert_eq!(after.heartbeat_interval_seconds, 1);
        assert_eq!(after.stale_after_seconds, 3);
        assert!(after.takeover_eligible_since_unix_seconds.is_none());
        assert_eq!(after.run_owner_count, 0);
        guard.verify()?;
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

    fn recursive_regular_bytes(
        root: &Path,
    ) -> Result<std::collections::BTreeMap<PathBuf, Vec<u8>>> {
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
