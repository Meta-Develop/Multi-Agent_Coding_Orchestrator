//! One-shot endpoint ownership transfer, not Worker execution or parent quiescence.
//!
//! A turn is supplied by the supervisor before attachment. Its in-memory identity cannot
//! be reconstructed from a child report, journal replay, or even matching numeric labels.
//! Generation allocation/reconciliation remains the caller's existing responsibility.
//! No constructor here authorizes a fresh generation after an uncertain/recovered turn.

use super::*;
use crate::{
    artifacts::repository_authenticator_key_only,
    messaging::transport::{AssignmentMessagingLaunch, AssignmentMessagingServer},
    process_runner::ProcessCancellation,
    supervise::messaging_bridge::worker_request_ipc::{
        start_assignment_messaging_with_worker_inbox, WorkerRequestIpc,
    },
    sync::PathClaim,
    sync_store::{lock_existing_authenticated_claims, ExistingClaimBindingRequest, SyncStore},
    worktree::{ManagedWorktreeWriteLease, WorktreeManager},
};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

/// Borrow the parent's existing resources; this never acquires a worktree or claim.
/// These inputs come from supervisor preflight, not from deserialized request fields.
pub(in crate::supervise) struct WorkerInboxResources<'a> {
    pub repo: &'a Path,
    pub parent: &'a OrchestratorAssignment,
    pub lease: &'a ManagedWorktreeWriteLease,
    pub claim: &'a PathClaim,
    pub claims: &'a SyncStore,
}

impl WorkerInboxResources<'_> {
    fn verify(&self, binding: &WorkerRequestBinding) -> Result<RepositoryAuthBinding> {
        let expected = WorkerRequestBinding::new(
            &binding.state_instance,
            &RunId::new(&binding.run)?,
            self.parent,
            binding.attempt,
            &binding.generation,
        )?;
        if expected != *binding
            || self.lease.record().name != binding.parent
            || self.claim.agent_id != binding.parent
            || self.claim.paths != self.parent.assigned_paths
        {
            bail!("frozen inbox parent or resource binding differs from authored turn");
        }
        let auth = repository_authenticator_key_only(self.repo)?;
        // Do not allow a same-token/same-path claim from another repository's store.
        if self.claims.state_path() != auth.state_root().path().join("claims.json") {
            bail!("frozen inbox claims store belongs to another repository");
        }
        WorktreeManager::new(self.repo)
            .verify_write_execution_lease(&binding.parent, self.lease)?;
        if !self.claims.status_snapshot()?.iter().any(|held| {
            held.claim == *self.claim && held.owner_run_id.as_deref() == Some(&binding.run)
        }) {
            bail!("frozen inbox exact parent claim is no longer held by this run");
        }
        // Existing-only liveness/authentication check, including released/superseded claims.
        let guard = lock_existing_authenticated_claims(
            self.repo,
            vec![ExistingClaimBindingRequest {
                agent_id: self.claim.agent_id.clone(),
                token: self.claim.token,
                paths: self.claim.paths.clone(),
            }],
        )?;
        guard.verify()?;
        auth.verify()?;
        Ok(auth.binding().clone())
    }
}

/// Non-cloneable, non-serializable supervisor turn identity. At most one endpoint
/// may use it, even if starting that endpoint fails. Numeric turn is evidence only.
pub(in crate::supervise) struct WorkerInboxTurn<'a> {
    binding: WorkerRequestBinding,
    turn: u64,
    resources: WorkerInboxResources<'a>,
    repository: RepositoryAuthBinding,
    attached: AtomicBool,
}

impl<'a> WorkerInboxTurn<'a> {
    pub(in crate::supervise) fn new(
        binding: WorkerRequestBinding,
        turn: u64,
        resources: WorkerInboxResources<'a>,
    ) -> Result<Self> {
        if turn == 0 {
            bail!("frozen inbox requires a nonzero supervisor turn");
        }
        let repository = resources.verify(&binding)?;
        Ok(Self {
            binding,
            turn,
            resources,
            repository,
            attached: AtomicBool::new(false),
        })
    }

    fn verify(&self) -> Result<()> {
        if self.resources.verify(&self.binding)? != self.repository {
            bail!("frozen inbox repository authority changed");
        }
        Ok(())
    }
}

/// Owns both endpoint and inbox. No API hands out the service Arc or live inbox.
/// Dropping without freezing still joins; reopening afterward remains quarantined.
pub(in crate::supervise) struct WorkerInboxEndpoint<'a> {
    server: AssignmentMessagingServer,
    service: Arc<WorkerRequestIpc>,
    turn: &'a WorkerInboxTurn<'a>,
    run_directory: PathBuf,
}

impl<'a> WorkerInboxEndpoint<'a> {
    /// Requires an empty fresh journal: existing requests cannot be relabeled as
    /// submissions from this turn, even if their live handle was retained.
    pub(in crate::supervise) fn start(
        run_directory: &Path,
        turn: &'a WorkerInboxTurn<'a>,
        inbox: WorkerRequestInbox<RepositoryAuthenticator>,
        cancellation: ProcessCancellation,
    ) -> Result<Self> {
        let service = WorkerRequestIpc::new(inbox, turn.binding.clone(), cancellation);
        Self::start_service(run_directory, turn, service)
    }

    fn start_service(
        run_directory: &Path,
        turn: &'a WorkerInboxTurn<'a>,
        service: WorkerRequestIpc,
    ) -> Result<Self> {
        turn.verify()?;
        service.verify_fresh_binding(&turn.binding, &turn.repository)?;
        if turn.attached.swap(true, Ordering::AcqRel) {
            bail!("supervisor inbox turn has already been attached");
        }
        let service = Arc::new(service);
        let server = start_assignment_messaging_with_worker_inbox(
            run_directory,
            &turn.binding.run,
            &turn.binding.parent,
            Arc::clone(&service),
        )?;
        Ok(Self {
            server,
            service,
            turn,
            run_directory: run_directory.to_path_buf(),
        })
    }

    pub(in crate::supervise) fn launch(&self) -> AssignmentMessagingLaunch {
        self.server.launch()
    }

    /// Joins all endpoint handlers before reading the journal. Cancellation may
    /// discard a reply after append; exactly the committed records are retained.
    /// This proves endpoint shutdown only, never parent/descendant process quiescence.
    pub(in crate::supervise) fn shutdown(self) -> Result<FrozenWorkerInbox<'a>> {
        let Self {
            server,
            service,
            turn,
            run_directory,
        } = self;
        drop(server);
        let service = Arc::try_unwrap(service)
            .map_err(|_| anyhow::anyhow!("joined endpoint still has a shared inbox owner"))?;
        let inbox = service.into_inbox()?;
        turn.verify()?;
        verify_session(&run_directory, turn)?;
        inbox.verify_ipc_binding(&turn.binding, &turn.repository)?;
        if inbox.requires_reconciliation {
            bail!("recovered inbox cannot become a frozen authenticated turn");
        }
        let records = inbox.requests()?;
        if records
            .iter()
            .any(|r| r.status != WorkerRequestStatus::Queued)
        {
            bail!(
                "frozen turn requires only queued requests; prior reservations need reconciliation"
            );
        }
        let watermark = WorkerInboxWatermark {
            journal_instance: inbox.store.header().broker_instance_id.clone(),
            last_sequence: inbox.store.events().len() - 1,
            journal_digest: inbox.journal_digest.clone(),
        };
        Ok(FrozenWorkerInbox {
            inbox,
            turn,
            run_directory,
            records,
            watermark,
        })
    }
}

/// Local live-handle watermark, not an independent crash-recovery high-water mark.
#[derive(Debug, PartialEq, Eq)]
pub(in crate::supervise) struct WorkerInboxWatermark {
    pub journal_instance: String,
    pub last_sequence: usize,
    pub journal_digest: String,
}

/// Neither Clone nor Deserialize. Keeps the exclusive journal lock and borrows
/// the original turn's held worktree lease. It cannot be reopened or unfrozen.
pub(in crate::supervise) struct FrozenWorkerInbox<'a> {
    inbox: WorkerRequestInbox<RepositoryAuthenticator>,
    turn: &'a WorkerInboxTurn<'a>,
    run_directory: PathBuf,
    records: Vec<WorkerRequestRecord>,
    watermark: WorkerInboxWatermark,
}

pub(in crate::supervise) struct FrozenWorkerInboxView<'a> {
    pub binding: &'a WorkerRequestBinding,
    pub turn: u64,
    pub requests: &'a [WorkerRequestRecord],
    pub watermark: &'a WorkerInboxWatermark,
}

impl FrozenWorkerInbox<'_> {
    /// Read-only authenticated evidence. A later consumer still needs parent
    /// quiescence, current cancellation/budget/admission checks and durable reservation.
    pub(in crate::supervise) fn view(
        &self,
        current: &WorkerInboxTurn<'_>,
    ) -> Result<FrozenWorkerInboxView<'_>> {
        if !std::ptr::eq(self.turn, current) {
            bail!("frozen inbox belongs to a foreign state instance, generation or turn owner");
        }
        current.verify()?;
        verify_session(&self.run_directory, current)?;
        self.inbox
            .verify_ipc_binding(&current.binding, &current.repository)?;
        if self.inbox.journal_digest != self.watermark.journal_digest
            || self.inbox.store.header().broker_instance_id != self.watermark.journal_instance
            || self.inbox.store.events().len() - 1 != self.watermark.last_sequence
        {
            bail!("frozen inbox watermark changed");
        }
        Ok(FrozenWorkerInboxView {
            binding: &self.turn.binding,
            turn: current.turn,
            requests: &self.records,
            watermark: &self.watermark,
        })
    }
}

fn verify_session(directory: &Path, turn: &WorkerInboxTurn<'_>) -> Result<()> {
    crate::supervise::messaging_bridge::with_supervisor_messaging_session(directory, |factory| {
        turn.binding.verify_session(factory, &turn.binding.parent)
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
