//! Durable inbox core: no launch authority or automatic execution/retry.
//!
//! The supervisor supplies the current binding and frozen authored parent. Never construct
//! them from child JSON. Callers must revoke access when the attempt ends and revalidate
//! current authority before consuming queued work. An exclusive journal handle belongs to
//! one attempt owner; reopening conservatively fences every unresolved reservation.
//! A journal and its tail anchor can both be restored to an older valid snapshot. Without
//! an independent high-water mark they cannot prove that queued work was never reserved.
//! Every recovered handle therefore requires external reconciliation: queued records remain
//! inspectable, but neither submissions (including retries) nor reservations are admitted. This core deliberately
//! provides no reconciliation/unseal API; do not use a new generation to bypass this fence.
//! A new generation requires supervisor authorization after reconciling the parent's
//! checkpoint and proving shared-worktree quiescence. Another file under the same rollbackable
//! state root would not establish monotonicity either.
//!
//! Before executing any reserved work, the caller must prove shared-worktree quiescence:
//! the parent and all previous workers/process trees using that worktree must have stopped,
//! and no other attempt may still be writing it. Inbox status, a completed report, or successful
//! recovery is not proof of quiescence or permission to reuse the parent's resources.
//!
//! Private state-transition messages reuse MessagingStore's authenticated chain, tail anchor,
//! bounded replay and exclusive lock. They are never sent through the messaging broker.
#![allow(dead_code)] // Reservation/execution and recovery reconciliation remain staged.

use std::{
    borrow::Borrow,
    collections::{BTreeMap, BTreeSet},
};

use super::persistence::{MESSAGING_ROOT_LOCK, MESSAGING_STATE_NAMESPACE};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    artifacts::state_auth::{
        random_identifier, sha256_hex, AuthenticationDomain, BoundStateLock, RepositoryAuthBinding,
        RepositoryAuthenticator,
    },
    hierarchy_ledger::RoleCategory,
    messaging::{
        envelope::{MessageAddress, MessageEnvelope},
        store::{MessagingStore, StoreEvent, StoreIntegrityKey},
        MessageId, MessagingLimits,
    },
    orchestrator::RunId,
    safe_state::{BoundedRegularReader, SafeRoot},
    supervise::{AgentRole, AssignmentPhase, OrchestratorAssignment},
};

const MAX_ID_BYTES: usize = 128;
const MAX_WORKERS: usize = 256;
const DOMAIN: AuthenticationDomain = AuthenticationDomain::new(b"MACO\0worker-request-inbox\0v1\0");

pub(in crate::supervise) mod frozen;

/// Server-owned identity, deliberately not deserializable. Generation must be persisted by
/// the supervisor and reused on recovery, never regenerated to evade an existing inbox.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(in crate::supervise) struct WorkerRequestBinding {
    state_instance: String,
    run: String,
    parent: String,
    attempt: usize,
    generation: String,
    workers: BTreeSet<String>,
}

impl WorkerRequestBinding {
    pub(super) fn verify_session(
        &self,
        factory: &super::SupervisorMessagingSessionFactory,
        task_id: &str,
    ) -> Result<()> {
        factory.ensure_authenticated_run_id(&self.run)?;
        let persistent = factory
            .persistent
            .as_ref()
            .context("worker IPC requires a persistent messaging session")?;
        if task_id != self.parent
            || self.state_instance != persistent.state_instance_id()
            || factory.hierarchy.effective_categories.get(task_id)
                != Some(&RoleCategory::DelegatingCoordinator)
            || self.workers.iter().any(|worker| {
                factory.hierarchy.effective_categories.get(worker)
                    != Some(&RoleCategory::NonDelegatingTerminalWorker)
            })
        {
            bail!("worker inbox endpoint differs from authenticated messaging authority");
        }
        Ok(())
    }

    fn identity(&self) -> Result<String> {
        let identity = serde_json::to_vec(&(
            &self.state_instance,
            &self.run,
            &self.parent,
            self.attempt,
            &self.generation,
        ))?;
        Ok(format!("worker-inbox-{}", sha256_hex(&identity)))
    }

    pub(in crate::supervise) fn new(
        state_instance: &str,
        run: &RunId,
        parent: &OrchestratorAssignment,
        attempt: usize,
        generation: &str,
    ) -> Result<Self> {
        for id in [state_instance, run.as_str(), parent.id.as_str(), generation] {
            MessageId::new(id)?;
        }
        if attempt == 0
            || parent.role != AgentRole::ChildOrchestrator
            || parent.phase != AssignmentPhase::Execution
            || parent.effective_role_category()
                != crate::supervise::role_authority::RoleCategory::DelegatingCoordinator
            || parent.worker_assignments.is_empty()
            || parent.worker_assignments.len() > MAX_WORKERS
        {
            bail!("worker inbox requires an authored execution coordinator and bounded workers");
        }
        let mut workers = BTreeSet::new();
        for worker in &parent.worker_assignments {
            MessageId::new(worker.id.clone())?;
            if worker.role != AgentRole::Worker
                || worker.effective_role_category()
                    != crate::supervise::role_authority::RoleCategory::NonDelegatingTerminalWorker
                || worker.id == parent.id
                || !workers.insert(worker.id.clone())
            {
                bail!("worker inbox requires unique exact authored terminal Worker IDs");
            }
        }
        Ok(Self {
            state_instance: state_instance.into(),
            run: run.as_str().into(),
            parent: parent.id.clone(),
            attempt,
            generation: generation.into(),
            workers,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::supervise) enum WorkerRequestStatus {
    Queued,
    Reserved,
    Completed,
    Failed,
    RecoveryRequired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::supervise) struct WorkerRequestRecord {
    pub(in crate::supervise) request_id: String,
    pub(in crate::supervise) worker_id: String,
    pub(in crate::supervise) status: WorkerRequestStatus,
}

/// May borrow the authenticator in a scoped caller or own it in an IPC service.
/// Moving the owner preserves the exclusive journal lock; no key is cloned.
pub(in crate::supervise) struct WorkerRequestInbox<A: Borrow<RepositoryAuthenticator>> {
    authenticator: A,
    binding: WorkerRequestBinding,
    store: MessagingStore,
    records: BTreeMap<String, WorkerRequestRecord>,
    poisoned: bool,
    file_name: String,
    journal_digest: String,
    root: SafeRoot,
    requires_reconciliation: bool,
}

impl<A: Borrow<RepositoryAuthenticator>> WorkerRequestInbox<A> {
    /// Fresh creation only. Existing or partially created state is never overwritten.
    pub(in crate::supervise) fn create(
        authenticator: A,
        binding: WorkerRequestBinding,
    ) -> Result<Self> {
        Self::load(authenticator, binding, false)
    }

    /// Missing, corrupt or differently bound state is an error, never a fresh inbox.
    /// Recovery preserves queued records for inspection only, not for automatic resumption.
    pub(in crate::supervise) fn recover(
        authenticator: A,
        binding: WorkerRequestBinding,
    ) -> Result<Self> {
        let mut inbox = Self::load(authenticator, binding, true)?;
        let reserved: Vec<_> = inbox
            .records
            .values()
            .filter(|record| record.status == WorkerRequestStatus::Reserved)
            .map(|record| record.request_id.clone())
            .collect();
        for id in reserved {
            inbox.transition(&id, WorkerRequestStatus::RecoveryRequired)?;
        }
        Ok(inbox)
    }

    fn load(authenticator: A, binding: WorkerRequestBinding, recover: bool) -> Result<Self> {
        let auth = authenticator.borrow();
        auth.verify()?;
        let (root, root_lock) = inbox_root(auth, !recover)?;
        let payload = serde_json::to_vec(&binding)?;
        let identity = binding.identity()?;
        let tag = auth.sign(DOMAIN, &payload)?;
        let mut key = [0_u8; 32];
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&tag.as_str()[index * 2..index * 2 + 2], 16)?;
        }
        let authority =
            BTreeMap::from([(binding.parent.clone(), RoleCategory::DelegatingCoordinator)]);
        let file_name = format!("{identity}.jsonl");
        let path = root.direct_child(&file_name)?;
        let store = if recover {
            MessagingStore::open(
                path,
                &identity,
                &authority,
                &limits(),
                StoreIntegrityKey::new(key),
            )?
        } else {
            MessagingStore::create(
                path,
                format!("{identity}-{}", random_identifier()?),
                authority,
                limits(),
                StoreIntegrityKey::new(key),
            )?
        };
        let mut records = BTreeMap::new();
        for event in store.events().iter().skip(1) {
            let StoreEvent::MessageSent { envelope } = event else {
                bail!("unexpected worker inbox journal event");
            };
            if envelope.sender_id != binding.parent
                || envelope.address
                    != (MessageAddress::Direct {
                        recipient_id: binding.parent.clone(),
                    })
            {
                bail!("worker inbox transition has a foreign identity");
            }
            let record: WorkerRequestRecord = serde_json::from_value(envelope.payload.clone())?;
            validate_record(&binding, &records, &record)?;
            records.insert(record.request_id.clone(), record);
        }
        let journal_digest = journal_digest(&root, &file_name)?;
        root_lock.verify(auth.state_root())?;
        Ok(Self {
            authenticator,
            binding,
            store,
            records,
            poisoned: false,
            file_name,
            journal_digest,
            root,
            requires_reconciliation: recover,
        })
    }

    /// Compare the entire supervisor-owned binding before attaching or servicing IPC.
    pub(super) fn verify_ipc_binding(
        &self,
        expected: &WorkerRequestBinding,
        repository: &RepositoryAuthBinding,
    ) -> Result<()> {
        self.verify()?;
        self.authenticator
            .borrow()
            .verify_repository_binding(repository)?;
        if &self.binding != expected {
            bail!("worker inbox differs from current supervisor attempt binding");
        }
        Ok(())
    }

    pub(in crate::supervise) fn submit(
        &mut self,
        request_id: &str,
        worker_id: &str,
    ) -> Result<WorkerRequestRecord> {
        self.verify()?;
        if self.requires_reconciliation {
            bail!("recovered worker inbox requires external reconciliation before submissions");
        }
        validate_id(request_id)?;
        if !self.binding.workers.contains(worker_id) {
            bail!("Worker ID is not authored under this parent");
        }
        if let Some(existing) = self.records.get(request_id) {
            if existing.worker_id != worker_id {
                bail!("request ID already binds another Worker");
            }
            return Ok(existing.clone());
        }
        self.append(WorkerRequestRecord {
            request_id: request_id.into(),
            worker_id: worker_id.into(),
            status: WorkerRequestStatus::Queued,
        })
    }

    /// Snapshot under the exclusive handle; does not confer permission to execute.
    pub(in crate::supervise) fn status(&self, request_id: &str) -> Result<WorkerRequestRecord> {
        self.verify()?;
        validate_id(request_id)?;
        self.records
            .get(request_id)
            .cloned()
            .context("unknown worker request")
    }

    pub(in crate::supervise) fn requires_reconciliation(&self) -> bool {
        self.requires_reconciliation
    }

    /// Current records in durable submission order for a later supervisor-owned consumer.
    pub(in crate::supervise) fn requests(&self) -> Result<Vec<WorkerRequestRecord>> {
        self.verify()?;
        let mut ordered = Vec::with_capacity(self.records.len());
        for event in self.store.events().iter().skip(1) {
            if let StoreEvent::MessageSent { envelope } = event {
                let record: WorkerRequestRecord = serde_json::from_value(envelope.payload.clone())?;
                if record.status == WorkerRequestStatus::Queued {
                    ordered.push(self.records[&record.request_id].clone());
                }
            }
        }
        Ok(ordered)
    }

    /// Reservation must be durably acknowledged before any future consumer launches work.
    /// Completed/failed are supervisor outcomes, never child-authored attestations.
    pub(in crate::supervise) fn transition(
        &mut self,
        request_id: &str,
        status: WorkerRequestStatus,
    ) -> Result<WorkerRequestRecord> {
        let mut record = self.status(request_id)?;
        if self.requires_reconciliation && status == WorkerRequestStatus::Reserved {
            bail!("recovered worker inbox requires external reconciliation before reservation");
        }
        if record.status == status && status != WorkerRequestStatus::Reserved {
            return Ok(record);
        }
        record.status = status;
        self.append(record)
    }

    fn verify(&self) -> Result<()> {
        if self.poisoned {
            bail!("worker inbox requires recovery after an uncertain append");
        }
        self.authenticator.borrow().verify()?;
        self.root.verify()?;
        if journal_digest(&self.root, &self.file_name)? != self.journal_digest {
            bail!("worker inbox journal changed outside its exclusive owner");
        }
        Ok(())
    }

    fn append(&mut self, record: WorkerRequestRecord) -> Result<WorkerRequestRecord> {
        self.verify()?;
        validate_record(&self.binding, &self.records, &record)?;
        let sequence = self.store.events().len() as u64;
        let envelope = MessageEnvelope::new(
            MessageId::new(format!(
                "{}-{sequence:020}",
                self.store.header().broker_instance_id
            ))?,
            MessageAddress::Direct {
                recipient_id: self.binding.parent.clone(),
            },
            self.binding.parent.clone(),
            RoleCategory::DelegatingCoordinator,
            sequence,
            serde_json::to_value(&record)?,
            BTreeSet::from([self.binding.parent.clone()]),
            &limits(),
        )?;
        // Even an ambiguous I/O error must not allow a same-handle retry to launch twice.
        self.poisoned = true;
        self.store.append(StoreEvent::MessageSent { envelope })?;
        self.journal_digest = journal_digest(&self.root, &self.file_name)?;
        self.records
            .insert(record.request_id.clone(), record.clone());
        self.poisoned = false;
        Ok(record)
    }
}

fn inbox_root(
    authenticator: &RepositoryAuthenticator,
    create: bool,
) -> Result<(SafeRoot, BoundStateLock)> {
    let state_root = authenticator.state_root();
    let lock = BoundStateLock::acquire(state_root, MESSAGING_ROOT_LOCK)?;
    let path = state_root.direct_child(MESSAGING_STATE_NAMESPACE)?;
    let root = if create {
        SafeRoot::open_or_create(path)?
    } else {
        SafeRoot::open_existing(path)?
    };
    lock.verify(state_root)?;
    root.verify()?;
    Ok((root, lock))
}

fn journal_digest(root: &SafeRoot, name: &str) -> Result<String> {
    let journal = BoundedRegularReader::read_direct(root, name, limits().max_journal_bytes as u64)?;
    let anchor = BoundedRegularReader::read_direct(root, format!("{name}.tail-anchor"), 4096)?;
    Ok(format!("{}:{}", sha256_hex(&journal), sha256_hex(&anchor)))
}

fn validate_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > MAX_ID_BYTES
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        || id == "."
        || id == ".."
    {
        bail!("worker inbox identifier must be 1..=128 canonical ASCII bytes");
    }
    Ok(())
}

fn validate_record(
    binding: &WorkerRequestBinding,
    records: &BTreeMap<String, WorkerRequestRecord>,
    next: &WorkerRequestRecord,
) -> Result<()> {
    validate_id(&next.request_id)?;
    if !binding.workers.contains(&next.worker_id) {
        bail!("Worker ID is not authored under this parent");
    }
    if let Some(previous) = records.get(&next.request_id) {
        use WorkerRequestStatus::*;
        if previous.worker_id != next.worker_id
            || !matches!(
                (previous.status, next.status),
                (Queued, Reserved) | (Reserved, Completed | Failed | RecoveryRequired)
            )
        {
            bail!("invalid worker request transition");
        }
    } else if next.status != WorkerRequestStatus::Queued
        || records
            .values()
            .any(|record| record.worker_id == next.worker_id)
        || records.len() >= binding.workers.len()
    {
        bail!("duplicate Worker or invalid initial request");
    }
    Ok(())
}

fn limits() -> MessagingLimits {
    MessagingLimits {
        max_credentials: 1,
        max_messages: MAX_WORKERS * 3,
        max_channels: 1,
        max_members_per_channel: 1,
        max_publishers_per_channel: 1,
        max_payload_bytes: 1024,
        max_identifier_bytes: 256,
        max_journal_records: MAX_WORKERS * 3 + 1,
        max_journal_bytes: 2 * 1024 * 1024,
        max_delivery_attempts: 1,
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::artifacts::repository_auth_writer;
    use serde_json::json;

    fn parent() -> OrchestratorAssignment {
        serde_json::from_value(json!({
            "id":"parent", "phase":"execution", "role":"child_orchestrator",
            "worker_assignments":[{"id":"worker", "role":"worker"},
                                  {"id":"other", "role":"worker"}]
        }))
        .unwrap()
    }

    fn binding() -> WorkerRequestBinding {
        WorkerRequestBinding::new(
            "instance",
            &RunId::new("run").unwrap(),
            &parent(),
            1,
            "generation",
        )
        .unwrap()
    }

    fn fixture() -> Result<(tempfile::TempDir, RepositoryAuthenticator)> {
        let temp = tempfile::tempdir()?;
        git2::Repository::init(temp.path())?;
        let auth = repository_auth_writer(temp.path())?.into_authenticator()?;
        Ok((temp, auth))
    }

    fn path(auth: &RepositoryAuthenticator, binding: &WorkerRequestBinding) -> std::path::PathBuf {
        auth.state_root()
            .path()
            .join(MESSAGING_STATE_NAMESPACE)
            .join(format!("{}.jsonl", binding.identity().unwrap()))
    }

    #[test]
    fn retries_and_terminal_results_survive_reopen_without_duplicate_work() -> Result<()> {
        let (_temp, auth) = fixture()?;
        let mut inbox = WorkerRequestInbox::create(&auth, binding())?;
        let queued = inbox.submit("request", "worker")?;
        let count = inbox.store.events().len();
        assert_eq!(inbox.submit("request", "worker")?, queued);
        assert_eq!(inbox.store.events().len(), count);
        assert!(inbox.submit("request", "other").is_err());
        assert!(inbox.submit("another-request", "worker").is_err());
        assert!(inbox
            .transition("request", WorkerRequestStatus::Completed)
            .is_err());
        inbox.transition("request", WorkerRequestStatus::Reserved)?;
        assert!(inbox
            .transition("request", WorkerRequestStatus::Reserved)
            .is_err());
        inbox.transition("request", WorkerRequestStatus::Completed)?;
        inbox.submit("second", "other")?;
        inbox.transition("second", WorkerRequestStatus::Reserved)?;
        inbox.transition("second", WorkerRequestStatus::Failed)?;
        drop(inbox);
        let mut reopened = WorkerRequestInbox::recover(&auth, binding())?;
        assert_eq!(
            reopened.status("request")?.status,
            WorkerRequestStatus::Completed
        );
        assert_eq!(
            reopened.status("second")?.status,
            WorkerRequestStatus::Failed
        );
        assert!(reopened.submit("request", "worker").is_err());
        assert!(reopened.submit("second", "other").is_err());
        assert!(reopened
            .transition("request", WorkerRequestStatus::Reserved)
            .is_err());
        assert!(reopened
            .transition("second", WorkerRequestStatus::Queued)
            .is_err());
        Ok(())
    }

    #[test]
    fn recovered_reservations_are_fenced_and_queued_work_is_inspection_only() -> Result<()> {
        let (_temp, auth) = fixture()?;
        let mut inbox = WorkerRequestInbox::create(&auth, binding())?;
        inbox.submit("uncertain", "worker")?;
        inbox.transition("uncertain", WorkerRequestStatus::Reserved)?;
        inbox.submit("pending", "other")?;
        drop(inbox);
        let mut inbox = WorkerRequestInbox::recover(&auth, binding())?;
        assert!(inbox.requires_reconciliation());
        assert_eq!(
            inbox.status("uncertain")?.status,
            WorkerRequestStatus::RecoveryRequired
        );
        assert_eq!(inbox.status("pending")?.status, WorkerRequestStatus::Queued);
        assert!(inbox
            .transition("pending", WorkerRequestStatus::Reserved)
            .is_err());
        assert_eq!(
            inbox
                .requests()?
                .iter()
                .map(|record| record.request_id.as_str())
                .collect::<Vec<_>>(),
            ["uncertain", "pending"]
        );
        for status in [
            WorkerRequestStatus::Queued,
            WorkerRequestStatus::Reserved,
            WorkerRequestStatus::Completed,
            WorkerRequestStatus::Failed,
        ] {
            assert!(inbox.transition("uncertain", status).is_err());
        }
        drop(inbox);
        let inbox = WorkerRequestInbox::recover(&auth, binding())?;
        assert_eq!(
            inbox.status("uncertain")?.status,
            WorkerRequestStatus::RecoveryRequired
        );
        Ok(())
    }

    #[test]
    fn malformed_requests_and_foreign_workers_append_nothing() -> Result<()> {
        let (_temp, auth) = fixture()?;
        let mut inbox = WorkerRequestInbox::create(&auth, binding())?;
        let before = std::fs::read(path(&auth, &binding()))?;
        for id in [
            "",
            ".",
            "..",
            "a/b",
            " a",
            "a\n",
            &"x".repeat(MAX_ID_BYTES + 1),
        ] {
            assert!(inbox.submit(id, "worker").is_err());
        }
        for worker in ["parent", "foreign", "Worker", "worker "] {
            assert!(inbox.submit("request", worker).is_err());
        }
        assert!(inbox
            .transition("missing", WorkerRequestStatus::Reserved)
            .is_err());
        assert_eq!(std::fs::read(path(&auth, &binding()))?, before);
        inbox.submit(&"x".repeat(MAX_ID_BYTES), "worker")?;
        Ok(())
    }

    #[test]
    fn binding_refuses_non_execution_non_coordinator_and_non_unique_workers() {
        for mutation in 0..7 {
            let mut parent = parent();
            match mutation {
                0 => parent.phase = AssignmentPhase::Planning,
                1 => parent.role = AgentRole::Worker,
                2 => parent.worker_assignments[0].role = AgentRole::Auditor,
                3 => parent
                    .worker_assignments
                    .push(parent.worker_assignments[0].clone()),
                4 => parent.worker_assignments[0].id = parent.id.clone(),
                5 => parent.worker_assignments.clear(),
                _ => {
                    parent.role_category = Some(
                        crate::supervise::role_authority::RoleCategory::NonDelegatingTerminalWorker,
                    )
                }
            }
            assert!(WorkerRequestBinding::new(
                "instance",
                &RunId::new("run").unwrap(),
                &parent,
                1,
                "generation"
            )
            .is_err());
        }
        assert!(WorkerRequestBinding::new(
            "instance",
            &RunId::new("run").unwrap(),
            &parent(),
            0,
            "generation"
        )
        .is_err());
    }

    #[test]
    fn creation_recovery_and_locking_do_not_adopt_missing_or_existing_state() -> Result<()> {
        let (_temp, auth) = fixture()?;
        assert!(WorkerRequestInbox::recover(&auth, binding()).is_err());
        let inbox = WorkerRequestInbox::create(&auth, binding())?;
        assert!(WorkerRequestInbox::create(&auth, binding()).is_err());
        assert!(WorkerRequestInbox::recover(&auth, binding()).is_err());
        drop(inbox);
        assert!(WorkerRequestInbox::create(&auth, binding()).is_err());
        WorkerRequestInbox::recover(&auth, binding())?;
        Ok(())
    }

    #[test]
    fn each_server_identity_component_changes_recovery_binding() -> Result<()> {
        let (_temp, auth) = fixture()?;
        drop(WorkerRequestInbox::create(&auth, binding())?);
        for component in 0..6 {
            let mut changed = binding();
            match component {
                0 => changed.state_instance.push('x'),
                1 => changed.run.push('x'),
                2 => changed.parent.push('x'),
                3 => changed.attempt += 1,
                4 => changed.generation.push('x'),
                _ => {
                    changed.workers.insert("foreign".into());
                }
            }
            if component == 5 {
                assert!(WorkerRequestInbox::create(&auth, changed.clone()).is_err());
            }
            assert!(WorkerRequestInbox::recover(&auth, changed).is_err());
        }
        Ok(())
    }

    #[test]
    fn corruption_and_partial_or_complete_tail_truncation_fail_closed() -> Result<()> {
        for attack in 0..3 {
            let (_temp, auth) = fixture()?;
            let mut inbox = WorkerRequestInbox::create(&auth, binding())?;
            inbox.submit("request", "worker")?;
            let queued_len = std::fs::metadata(path(&auth, &binding()))?.len() as usize;
            inbox.transition("request", WorkerRequestStatus::Reserved)?;
            drop(inbox);
            let file = path(&auth, &binding());
            let mut bytes = std::fs::read(&file)?;
            match attack {
                0 => {
                    let index = bytes.iter().position(|b| *b == b'q').unwrap();
                    bytes[index] = b'z';
                }
                1 => {
                    bytes.pop();
                }
                _ => bytes.truncate(queued_len),
            }
            std::fs::write(&file, &bytes)?;
            assert!(WorkerRequestInbox::recover(&auth, binding()).is_err());
            assert_eq!(std::fs::read(file)?, bytes);
        }
        Ok(())
    }

    #[test]
    fn authenticated_but_illegal_transition_is_rejected_during_replay() -> Result<()> {
        let (_temp, auth) = fixture()?;
        let mut inbox = WorkerRequestInbox::create(&auth, binding())?;
        let envelope = MessageEnvelope::new(
            MessageId::new(format!(
                "{}-{:020}",
                inbox.store.header().broker_instance_id,
                1
            ))?,
            MessageAddress::Direct {
                recipient_id: "parent".into(),
            },
            "parent",
            RoleCategory::DelegatingCoordinator,
            1,
            json!({"request_id":"request", "worker_id":"worker", "status":"completed"}),
            BTreeSet::from(["parent".into()]),
            &limits(),
        )?;
        inbox.store.append(StoreEvent::MessageSent { envelope })?;
        drop(inbox);
        assert!(WorkerRequestInbox::recover(&auth, binding()).is_err());
        Ok(())
    }

    #[test]
    fn live_tamper_refuses_cached_retry_status_and_reservation() -> Result<()> {
        let (_temp, auth) = fixture()?;
        let mut inbox = WorkerRequestInbox::create(&auth, binding())?;
        inbox.submit("request", "worker")?;
        let file = path(&auth, &binding());
        let mut bytes = std::fs::read(&file)?;
        bytes.pop();
        std::fs::write(&file, bytes)?;
        assert!(inbox.status("request").is_err());
        assert!(inbox.submit("request", "worker").is_err());
        assert!(inbox
            .transition("request", WorkerRequestStatus::Reserved)
            .is_err());
        Ok(())
    }

    #[test]
    fn same_generation_two_file_rollback_cannot_admit_another_reservation() -> Result<()> {
        // Both a queued snapshot and a snapshot predating submission can hide a launch.
        // Cover rollback after reservation as well as after a completed execution.
        for snapshot_has_request in [false, true] {
            for complete in [false, true] {
                let (_temp, auth) = fixture()?;
                let mut inbox = WorkerRequestInbox::create(&auth, binding())?;
                assert!(!inbox.requires_reconciliation());
                if snapshot_has_request {
                    inbox.submit("request", "worker")?;
                }
                let journal = path(&auth, &binding());
                let anchor = journal.with_file_name(format!(
                    "{}.tail-anchor",
                    journal.file_name().unwrap().to_string_lossy(),
                ));
                let saved_journal = std::fs::read(&journal)?;
                let saved_anchor = std::fs::read(&anchor)?;
                if !snapshot_has_request {
                    inbox.submit("request", "worker")?;
                }
                inbox.transition("request", WorkerRequestStatus::Reserved)?;
                if complete {
                    inbox.transition("request", WorkerRequestStatus::Completed)?;
                }
                drop(inbox);
                std::fs::write(&journal, saved_journal)?;
                std::fs::write(&anchor, saved_anchor)?;

                // Restoring authenticated bytes remains readable, but must not restore
                // execution eligibility. Reopening again cannot remove the fence either.
                for _ in 0..2 {
                    let mut recovered = WorkerRequestInbox::recover(&auth, binding())?;
                    assert!(recovered.requires_reconciliation());
                    if snapshot_has_request {
                        assert_eq!(
                            recovered.status("request")?.status,
                            WorkerRequestStatus::Queued
                        );
                        assert!(recovered
                            .transition("request", WorkerRequestStatus::Reserved)
                            .unwrap_err()
                            .to_string()
                            .contains("requires external reconciliation"));
                    }
                    assert!(recovered
                        .submit("request", "worker")
                        .unwrap_err()
                        .to_string()
                        .contains("requires external reconciliation"));
                    assert!(recovered
                        .submit("new-request", "other")
                        .unwrap_err()
                        .to_string()
                        .contains("requires external reconciliation"));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn copied_journal_and_anchor_cannot_cross_attempt_generation() -> Result<()> {
        let (_temp, auth) = fixture()?;
        let mut inbox = WorkerRequestInbox::create(&auth, binding())?;
        inbox.submit("request", "worker")?;
        drop(inbox);
        let mut changed = binding();
        changed.generation = "different-generation".into();
        let source = path(&auth, &binding());
        let destination = path(&auth, &changed);
        for suffix in ["", ".tail-anchor"] {
            std::fs::copy(
                format!("{}{suffix}", source.display()),
                format!("{}{suffix}", destination.display()),
            )?;
        }
        assert!(WorkerRequestInbox::recover(&auth, changed).is_err());
        Ok(())
    }

    #[test]
    fn symlinked_journal_is_not_adopted() -> Result<()> {
        let (_temp, auth) = fixture()?;
        let (root, lock) = inbox_root(&auth, true)?;
        drop(lock);
        let target = root.path().join("foreign.jsonl");
        std::fs::write(&target, b"preserve")?;
        std::os::unix::fs::symlink(&target, path(&auth, &binding()))?;
        assert!(WorkerRequestInbox::create(&auth, binding()).is_err());
        assert!(WorkerRequestInbox::recover(&auth, binding()).is_err());
        assert_eq!(std::fs::read(target)?, b"preserve");
        Ok(())
    }

    #[test]
    fn existing_inbox_prevents_replacement_key_bootstrap() -> Result<()> {
        let (temp, auth) = fixture()?;
        drop(WorkerRequestInbox::create(&auth, binding())?);
        let key = auth
            .state_root()
            .direct_child(crate::artifacts::state_auth::authentication_key_file_name())?;
        drop(auth);
        std::fs::remove_file(key)?;
        assert!(repository_auth_writer(temp.path()).is_err());
        Ok(())
    }
}
