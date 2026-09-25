//! Opt-in submit/status transport for a supervisor-held inbox. No launch authority.
//!
//! The caller supplies the frozen authored parent, current attempt/generation and an
//! already-opened inbox. It must persist/reuse that generation, reconcile recovery,
//! and cancel/drop the endpoint at attempt end. There is no automatic fresh/recover
//! fallback here. Ordinary assignment endpoints do not gain Worker request access.

use super::{
    persistence::PersistentMessagingBinding,
    worker_requests::{WorkerRequestBinding, WorkerRequestInbox},
    *,
};
use crate::{artifacts::state_auth::RepositoryAuthenticator, process_runner::ProcessCancellation};

/// Owned by the endpoint, retaining the inbox's exclusive journal handle for its
/// whole lifetime. Child input can neither attach a journal nor choose its binding.
pub(in crate::supervise) struct WorkerRequestIpc {
    inbox: Mutex<WorkerRequestInbox<RepositoryAuthenticator>>,
    expected: WorkerRequestBinding,
    cancellation: ProcessCancellation,
    #[cfg(test)]
    pub(super) submit_observer: Option<Box<dyn Fn(SubmitBoundary) -> Result<()> + Send + Sync>>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SubmitBoundary {
    BeforeAdmission,
    BeforeAppend,
    AfterAppend,
}

impl SupervisorMessagingSessionFactory {
    /// `parent` and attempt identity must come from the current supervisor context,
    /// never from an IPC request or a child report. This grants enqueueing only.
    #[allow(dead_code)] // Staged supervisor caller; no scheduler wiring in this leaf.
    pub(in crate::supervise) fn worker_request_binding(
        &self,
        run_id: &RunId,
        parent: &OrchestratorAssignment,
        attempt: usize,
        generation: &str,
    ) -> Result<WorkerRequestBinding> {
        self.ensure_authenticated_run_id(run_id.as_str())?;
        let persistent = self
            .persistent
            .as_ref()
            .context("worker IPC requires a persistent messaging session")?;
        let expected = WorkerRequestBinding::new(
            persistent.state_instance_id(),
            run_id,
            parent,
            attempt,
            generation,
        )?;
        expected.verify_session(self, &parent.id)?;
        Ok(expected)
    }
}

impl WorkerRequestIpc {
    #[allow(dead_code)] // Staged frozen owner transfer, not a scheduler entry point.
    pub(super) fn verify_fresh_binding(
        &self,
        expected: &WorkerRequestBinding,
        repository: &crate::artifacts::state_auth::RepositoryAuthBinding,
    ) -> Result<()> {
        let inbox = self
            .inbox
            .lock()
            .map_err(|_| anyhow::anyhow!("worker inbox lock is poisoned"))?;
        if &self.expected != expected
            || inbox.requires_reconciliation()
            || !inbox.requests()?.is_empty()
        {
            bail!("frozen turn requires a fresh empty inbox with the exact supervisor binding");
        }
        inbox.verify_ipc_binding(expected, repository)
    }

    /// Supply the current supervisor binding and combined attempt/run cancellation.
    /// The endpoint revalidates this binding on attachment and every inbox operation.
    #[allow(dead_code)] // Staged supervisor caller; no scheduler wiring in this leaf.
    pub(in crate::supervise) fn new(
        inbox: WorkerRequestInbox<RepositoryAuthenticator>,
        expected: WorkerRequestBinding,
        cancellation: ProcessCancellation,
    ) -> Self {
        Self {
            inbox: Mutex::new(inbox),
            expected,
            cancellation,
            #[cfg(test)]
            submit_observer: None,
        }
    }

    /// A trusted caller may retain an Arc while the endpoint runs, then use
    /// Arc::try_unwrap after dropping the endpoint to recover this same live handle.
    /// This is ownership transfer only, never quiescence or launch evidence.
    #[allow(dead_code)] // Staged supervisor caller; no scheduler wiring in this leaf.
    pub(in crate::supervise) fn into_inbox(
        self,
    ) -> Result<WorkerRequestInbox<RepositoryAuthenticator>> {
        self.inbox
            .into_inner()
            .map_err(|_| anyhow::anyhow!("worker inbox lock is poisoned"))
    }

    fn session<'a>(
        &self,
        factory: &'a SupervisorMessagingSessionFactory,
        task_id: &str,
    ) -> Result<&'a PersistentMessagingBinding> {
        if self.cancellation.is_cancelled() {
            bail!("Worker request attempt is cancelled or revoked");
        }
        self.expected.verify_session(factory, task_id)?;
        factory
            .persistent
            .as_ref()
            .context("persistent Worker request session is absent")
    }

    pub(super) fn verify(
        &self,
        factory: &SupervisorMessagingSessionFactory,
        task_id: &str,
    ) -> Result<()> {
        let inbox = self
            .inbox
            .lock()
            .map_err(|_| anyhow::anyhow!("worker inbox lock is poisoned"))?;
        let session = self.session(factory, task_id)?;
        inbox.verify_ipc_binding(&self.expected, session.repository_binding())
    }

    pub(super) fn submit(
        &self,
        factory: &SupervisorMessagingSessionFactory,
        task_id: &str,
        request_id: &str,
        worker_id: &str,
    ) -> Result<Value> {
        let mut inbox = self
            .inbox
            .lock()
            .map_err(|_| anyhow::anyhow!("worker inbox lock is poisoned"))?;
        #[cfg(test)]
        if let Some(observer) = &self.submit_observer {
            observer(SubmitBoundary::BeforeAdmission)?;
        }
        let session = self.session(factory, task_id)?;
        inbox.verify_ipc_binding(&self.expected, session.repository_binding())?;
        #[cfg(test)]
        if let Some(observer) = &self.submit_observer {
            observer(SubmitBoundary::BeforeAppend)?;
        }
        let record = inbox.submit(request_id, worker_id)?;
        #[cfg(test)]
        if let Some(observer) = &self.submit_observer {
            observer(SubmitBoundary::AfterAppend)?;
        }
        serialize_messaging_result(&record)
    }

    pub(super) fn status(
        &self,
        factory: &SupervisorMessagingSessionFactory,
        task_id: &str,
        request_id: &str,
    ) -> Result<Value> {
        let inbox = self
            .inbox
            .lock()
            .map_err(|_| anyhow::anyhow!("worker inbox lock is poisoned"))?;
        let session = self.session(factory, task_id)?;
        inbox.verify_ipc_binding(&self.expected, session.repository_binding())?;
        // A recovered queued record is inspectable, but explicitly quarantined.
        Ok(json!({
            "record": inbox.status(request_id)?,
            "requires_reconciliation": inbox.requires_reconciliation(),
        }))
    }
}

/// Explicit opt-in; existing launch sites keep the ordinary messaging-only endpoint.
#[allow(dead_code)] // Staged supervisor caller; existing launch sites remain unchanged.
pub(in crate::supervise) fn start_assignment_messaging_with_worker_inbox(
    run_directory: &Path,
    run_id: &str,
    task_id: &str,
    inbox: std::sync::Arc<WorkerRequestIpc>,
) -> Result<AssignmentMessagingServer> {
    super::start_assignment_messaging_inner(run_directory, run_id, task_id, Some(inbox))
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
