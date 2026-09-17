//! Private supervisor bridge for one run's authenticated messaging session.
//!
//! The supervisor opens this session before assignment dispatch and keeps every presented
//! capability process-local. Child IPC/CLI transport deliberately remains outside this bridge;
//! later transport wiring can borrow the already-admitted capability instead of creating a new
//! identity.

mod persistence;

#[cfg(test)]
use super::ArtifactFileDisposition;
use super::{
    role_authority::RoleCategory as AssignmentRoleCategory, ArtifactRunWriter,
    OrchestratorAssignment, SupervisorPlan, SupervisorPlanMetadata, WorkerAssignment,
};
#[cfg(test)]
use crate::artifacts::state_auth::random_identifier;
use crate::{
    hierarchy_ledger::{HierarchyLedgerSnapshot, RoleCategory},
    messaging::{
        transport::{serialize_messaging_result, string_array_to_set, AssignmentMessagingServer},
        AcknowledgementOutcome, CredentialRegistry, MessageId, MessagingBroker, MessagingError,
        MessagingLimits, PresentedCredential,
    },
    orchestrator::RunId,
    safe_state::SafeRoot,
};
use anyhow::{bail, Context, Result};
use persistence::PersistentMessagingBinding;
use serde::Deserialize;
use serde_json::{json, Value};
#[cfg(test)]
use std::fs;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::{Component, Path, PathBuf},
    sync::{Mutex, OnceLock},
};

const SUPERVISOR_MESSAGING_STORE_NAME: &str = "messaging.jsonl";
const SUPERVISOR_MESSAGING_ANCHOR_NAME: &str = "messaging.jsonl.tail-anchor";

pub(super) const MESSAGING_SESSION_DESCRIPTOR_NAME: &str =
    PersistentMessagingBinding::DESCRIPTOR_NAME;

/// One assignment identity that the supervisor has already admitted for launch.
///
/// The category is checked against the validated hierarchy snapshot. It never supplies broker
/// authority itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct LaunchedMessagingIdentity {
    agent_id: String,
    role_category: RoleCategory,
}

impl LaunchedMessagingIdentity {
    pub(super) fn new(agent_id: impl Into<String>, role_category: RoleCategory) -> Self {
        Self {
            agent_id: agent_id.into(),
            role_category,
        }
    }

    pub(super) fn from_orchestrator(assignment: &OrchestratorAssignment) -> Self {
        Self::new(
            assignment.id.clone(),
            hierarchy_role_category(assignment.effective_role_category()),
        )
    }

    pub(super) fn from_worker(assignment: &WorkerAssignment) -> Self {
        Self::new(
            assignment.id.clone(),
            hierarchy_role_category(assignment.effective_role_category()),
        )
    }
}

const fn hierarchy_role_category(category: AssignmentRoleCategory) -> RoleCategory {
    match category {
        AssignmentRoleCategory::DelegatingCoordinator => RoleCategory::DelegatingCoordinator,
        AssignmentRoleCategory::NonDelegatingTerminalWorker => {
            RoleCategory::NonDelegatingTerminalWorker
        }
        AssignmentRoleCategory::ReadOnlyResearcher => RoleCategory::ReadOnlyResearcher,
        AssignmentRoleCategory::ReadOnlyReviewAuditor => RoleCategory::ReadOnlyReviewAuditor,
    }
}

/// Memory-resident credentials plus the authority and path binding for one supervisor run.
///
/// A single factory may create the broker and later reopen it after the previous handle has been
/// dropped. Production sessions bind a [`PersistentMessagingBinding`] so a fresh process can
/// re-derive credentials; legacy memory-only factories still refuse recovery when credentials are
/// gone.
pub(super) struct SupervisorMessagingSessionFactory {
    artifact_root: SafeRoot,
    store_path: PathBuf,
    hierarchy: HierarchyLedgerSnapshot,
    limits: MessagingLimits,
    registry: CredentialRegistry,
    capabilities: BTreeMap<String, PresentedCredential>,
    persistent: Option<PersistentMessagingBinding>,
}

impl SupervisorMessagingSessionFactory {
    #[cfg(test)]
    pub(super) fn new(
        run_artifact_directory: impl AsRef<Path>,
        hierarchy: &HierarchyLedgerSnapshot,
        launched_identities: &[LaunchedMessagingIdentity],
    ) -> Result<Self> {
        Self::new_with_secret_generator(
            run_artifact_directory.as_ref(),
            hierarchy,
            launched_identities,
            |_| random_identifier().context("failed to generate supervisor messaging credential"),
        )
    }

    #[cfg(test)]
    fn new_with_secret_generator<F>(
        run_artifact_directory: &Path,
        hierarchy: &HierarchyLedgerSnapshot,
        launched_identities: &[LaunchedMessagingIdentity],
        mut generate_secret: F,
    ) -> Result<Self>
    where
        F: FnMut(&str) -> Result<String>,
    {
        validate_absolute_run_artifact_directory(run_artifact_directory)?;
        validate_launched_identities(hierarchy, launched_identities)?;

        let artifact_root = SafeRoot::open_existing(run_artifact_directory).with_context(|| {
            format!(
                "supervisor messaging store is not a safe existing directory: {}",
                run_artifact_directory.display()
            )
        })?;
        let store_path = artifact_root
            .direct_child(SUPERVISOR_MESSAGING_STORE_NAME)
            .context("failed to bind supervisor messaging store beneath run artifact directory")?;

        let limits = MessagingLimits::default();
        let mut registry = CredentialRegistry::from_limits(&limits)
            .context("failed to initialize supervisor messaging credential registry")?;
        let mut capabilities = BTreeMap::new();
        for identity in launched_identities {
            let secret = generate_secret(&identity.agent_id).with_context(|| {
                format!(
                    "failed to generate supervisor messaging credential for {:?}",
                    identity.agent_id
                )
            })?;
            let capability = registry
                .register(identity.agent_id.clone(), secret)
                .with_context(|| {
                    format!(
                        "failed to register supervisor messaging identity {:?}",
                        identity.agent_id
                    )
                })?;
            capabilities.insert(identity.agent_id.clone(), capability);
        }

        Ok(Self {
            artifact_root,
            store_path,
            hierarchy: hierarchy.clone(),
            limits,
            registry,
            capabilities,
            persistent: None,
        })
    }

    fn from_persistent_binding(
        run_artifact_directory: &Path,
        binding: PersistentMessagingBinding,
    ) -> Result<Self> {
        validate_absolute_run_artifact_directory(run_artifact_directory)?;
        let hierarchy = binding.hierarchy();
        let launched_identities = binding.identities();
        validate_launched_identities(hierarchy, launched_identities)?;

        let artifact_root = SafeRoot::open_existing(run_artifact_directory).with_context(|| {
            format!(
                "supervisor messaging store is not a safe existing directory: {}",
                run_artifact_directory.display()
            )
        })?;
        let store_path = binding
            .store_path()
            .context("failed to bind durable supervisor messaging store path")?;

        let limits = binding.limits().clone();
        let mut registry = CredentialRegistry::from_limits(&limits)
            .context("failed to initialize supervisor messaging credential registry")?;
        let mut capabilities = BTreeMap::new();
        for identity in launched_identities {
            let secret = binding
                .credential_for(&identity.agent_id)
                .with_context(|| {
                    format!(
                        "failed to derive supervisor messaging credential for {:?}",
                        identity.agent_id
                    )
                })?;
            let capability = registry
                .register(identity.agent_id.clone(), secret)
                .with_context(|| {
                    format!(
                        "failed to register supervisor messaging identity {:?}",
                        identity.agent_id
                    )
                })?;
            capabilities.insert(identity.agent_id.clone(), capability);
        }

        Ok(Self {
            artifact_root,
            store_path,
            hierarchy: hierarchy.clone(),
            limits,
            registry,
            capabilities,
            persistent: Some(binding),
        })
    }

    fn verify_run_and_binding(&self) -> Result<()> {
        self.artifact_root
            .verify()
            .context("supervisor messaging artifact directory changed before broker open")?;
        if let Some(binding) = &self.persistent {
            binding
                .verify()
                .context("supervisor messaging durable binding failed verification")?;
        }
        Ok(())
    }

    fn create_initial_persistent_broker(&self) -> Result<MessagingBroker> {
        let binding = self
            .persistent
            .as_ref()
            .context("persistent supervisor messaging session is not bound")?;
        binding.verify()?;
        self.verify_run_and_binding()?;
        let broker = MessagingBroker::create(
            &self.store_path,
            self.registry.clone(),
            &self.hierarchy,
            self.limits.clone(),
        )
        .context("failed to create durable supervisor messaging broker")?;
        self.artifact_root
            .verify()
            .context("supervisor messaging artifact directory changed after broker creation")?;
        binding.verify()?;
        Ok(broker)
    }

    fn open_existing_broker(&self) -> Result<MessagingBroker> {
        self.verify_run_and_binding()?;
        let broker = if self.persistent.is_some() {
            MessagingBroker::open(
                &self.store_path,
                self.registry.clone(),
                &self.hierarchy,
                self.limits.clone(),
            )
            .context("failed to open durable supervisor messaging broker")?
        } else {
            MessagingBroker::open_or_create(
                &self.store_path,
                self.registry.clone(),
                &self.hierarchy,
                self.limits.clone(),
            )
            .context("failed to open supervisor messaging broker")?
        };
        self.artifact_root
            .verify()
            .context("supervisor messaging artifact directory changed during broker open")?;
        if let Some(binding) = &self.persistent {
            binding.verify()?;
        }
        Ok(broker)
    }

    /// Opens the run's authenticated broker, creating its durable journal on first use.
    pub(super) fn open_or_create(&self) -> Result<MessagingBroker> {
        self.open_existing_broker()
    }

    /// Returns one launched agent's own process-local presentation capability.
    ///
    /// The returned value is neither serializable nor secret-revealing under `Debug`.
    pub(crate) fn capability_for(&self, agent_id: &str) -> Result<PresentedCredential> {
        self.capabilities
            .get(agent_id)
            .cloned()
            .with_context(|| format!("supervisor messaging identity {agent_id:?} was not launched"))
    }

    /// Binds a caller-supplied run id to this factory's authenticated artifact root.
    pub(crate) fn ensure_authenticated_run_id(&self, run_id: &str) -> Result<()> {
        self.verify_run_and_binding()?;
        let validated = RunId::new(run_id)
            .context("assignment messaging run id is not a valid supervisor run identifier")?;
        let authenticated_leaf = self
            .artifact_root
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .context("supervisor messaging artifact root has no directory name")?;
        if authenticated_leaf != validated.as_str() {
            bail!(
                "assignment messaging run id {:?} does not match the authenticated supervisor run binding {:?}",
                validated.as_str(),
                authenticated_leaf
            );
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn durable_store_path(&self) -> &Path {
        &self.store_path
    }

    /// Legacy unit-fixture path that manifests live broker bytes into the run artifact manifest.
    #[cfg(test)]
    fn legacy_create_manifested_store(&self, writer: &mut ArtifactRunWriter) -> Result<()> {
        if self.persistent.is_some() {
            bail!("legacy manifested store creation is incompatible with durable bindings");
        }
        if self
            .artifact_root
            .direct_child_exists(SUPERVISOR_MESSAGING_STORE_NAME)?
            || self
                .artifact_root
                .direct_child_exists(SUPERVISOR_MESSAGING_ANCHOR_NAME)?
        {
            bail!(
                "supervisor messaging store or tail anchor already exists before initial session admission"
            );
        }

        drop(self.open_or_create()?);
        self.artifact_root
            .verify()
            .context("supervisor messaging artifact directory changed after broker creation")?;
        let anchor_path = self
            .artifact_root
            .direct_child(SUPERVISOR_MESSAGING_ANCHOR_NAME)
            .context("failed to bind supervisor messaging tail anchor")?;
        for (label, path) in [("store", &self.store_path), ("tail anchor", &anchor_path)] {
            let metadata = fs::symlink_metadata(path)
                .with_context(|| format!("failed to inspect newly created messaging {label}"))?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                bail!("newly created supervisor messaging {label} is not a regular file");
            }
        }
        let contents = fs::read(&self.store_path)
            .context("failed to read newly created supervisor messaging store")?;
        let anchor_contents = fs::read(&anchor_path)
            .context("failed to read newly created supervisor messaging tail anchor")?;
        fs::remove_file(&self.store_path)
            .context("failed to transfer supervisor messaging store into artifact authority")?;
        fs::remove_file(&anchor_path).context(
            "failed to transfer supervisor messaging tail anchor into artifact authority",
        )?;
        writer
            .write_bytes(
                Path::new(SUPERVISOR_MESSAGING_STORE_NAME),
                &contents,
                ArtifactFileDisposition::PrivateEvidence,
            )
            .context("failed to manifest supervisor messaging store")?;
        writer
            .write_bytes(
                Path::new(SUPERVISOR_MESSAGING_ANCHOR_NAME),
                &anchor_contents,
                ArtifactFileDisposition::PrivateEvidence,
            )
            .context("failed to manifest supervisor messaging tail anchor")?;
        drop(
            self.open_or_create()
                .context("failed to verify manifested supervisor messaging store")?,
        );
        Ok(())
    }
}

fn reopen_registered_session(run_directory: &Path) -> Result<()> {
    let sessions = run_sessions()
        .lock()
        .map_err(|_| anyhow::anyhow!("supervisor messaging session registry is poisoned"))?;
    let factory = sessions
        .get(run_directory)
        .context("supervisor messaging session is not initialized")?;
    drop(factory.open_or_create()?);
    Ok(())
}

fn run_sessions() -> &'static Mutex<BTreeMap<PathBuf, SupervisorMessagingSessionFactory>> {
    static RUN_SESSIONS: OnceLock<Mutex<BTreeMap<PathBuf, SupervisorMessagingSessionFactory>>> =
        OnceLock::new();
    RUN_SESSIONS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn legacy_artifact_messaging_exists(run_directory: &Path) -> Result<bool> {
    let store = run_directory.join(SUPERVISOR_MESSAGING_STORE_NAME);
    let anchor = run_directory.join(SUPERVISOR_MESSAGING_ANCHOR_NAME);
    Ok(store
        .try_exists()
        .context("failed to inspect legacy supervisor messaging store")?
        || anchor
            .try_exists()
            .context("failed to inspect legacy supervisor messaging tail anchor")?)
}

fn authenticated_descriptor_present(run_directory: &Path) -> Result<bool> {
    run_directory
        .join(MESSAGING_SESSION_DESCRIPTOR_NAME)
        .try_exists()
        .context("failed to inspect supervisor messaging session descriptor")
}

fn legacy_credentials_unavailable_message(store: &Path) -> String {
    format!(
        "supervisor messaging journal {} cannot be resumed because its memory-resident credentials are unavailable; refusing to grant replacement identities",
        store.display()
    )
}

/// Establishes exactly one process-local identity set for an authenticated supervisor run.
///
/// This is called from scheduler evidence initialization after plan normalization and before the
/// first dispatch-capable scheduler action. Durable sessions restore their authenticated authority;
/// legacy journals still require their original memory-resident credentials.
pub(super) fn initialize_supervisor_messaging_session(
    writer: &mut ArtifactRunWriter,
    plan: &SupervisorPlan,
    metadata: &SupervisorPlanMetadata,
) -> Result<()> {
    if plan.assignments.is_empty() {
        return Ok(());
    }
    let run_directory = writer.run_dir().to_path_buf();
    let (hierarchy, identities) = admitted_messaging_authority(plan, metadata)?;

    let resume_existing = {
        let mut sessions = run_sessions()
            .lock()
            .map_err(|_| anyhow::anyhow!("supervisor messaging session registry is poisoned"))?;
        sessions.retain(|directory, _| {
            directory.is_dir()
                && !directory
                    .join(super::ARTIFACT_FINALIZATION_MARKER)
                    .is_file()
        });
        if let Some(existing) = sessions.get(&run_directory) {
            existing.revalidate_authority(&hierarchy, &identities)?;
            true
        } else {
            false
        }
    };
    if resume_existing {
        return reopen_registered_session(&run_directory);
    }

    if legacy_artifact_messaging_exists(&run_directory)? {
        bail!(
            "supervisor messaging journal exists but its memory-resident credentials are unavailable; refusing to grant replacement identities"
        );
    }

    let (binding, newly_created) =
        PersistentMessagingBinding::prepare(writer, &hierarchy, &identities)
            .context("supervisor messaging durable session preparation failed")?;
    let factory =
        SupervisorMessagingSessionFactory::from_persistent_binding(&run_directory, binding)
            .context("supervisor messaging pre-launch admission failed")?;
    if newly_created {
        drop(
            factory
                .create_initial_persistent_broker()
                .context("supervisor messaging pre-launch journal creation failed")?,
        );
    } else {
        drop(
            factory
                .open_existing_broker()
                .context("supervisor messaging pre-launch journal open failed")?,
        );
    }

    let mut sessions = run_sessions()
        .lock()
        .map_err(|_| anyhow::anyhow!("supervisor messaging session registry is poisoned"))?;
    sessions.insert(run_directory, factory);
    Ok(())
}

/// Authenticates and replays an existing durable session, retaining legacy credential refusals.
pub(super) fn recover_supervisor_messaging_session(run_directory: &Path) -> Result<()> {
    let already_registered = {
        let sessions = run_sessions()
            .lock()
            .map_err(|_| anyhow::anyhow!("supervisor messaging session registry is poisoned"))?;
        sessions.contains_key(run_directory)
    };
    if already_registered {
        return reopen_registered_session(run_directory);
    }

    let has_legacy = legacy_artifact_messaging_exists(run_directory)?;
    let has_descriptor = authenticated_descriptor_present(run_directory)?;
    if !has_legacy && !has_descriptor {
        return Ok(());
    }

    if has_descriptor {
        let binding = PersistentMessagingBinding::open(run_directory)
            .context("failed to authenticate supervisor messaging session descriptor")?;
        let factory =
            SupervisorMessagingSessionFactory::from_persistent_binding(run_directory, binding)?;
        drop(
            factory
                .open_existing_broker()
                .context("failed to recover durable supervisor messaging journal")?,
        );
        let mut sessions = run_sessions()
            .lock()
            .map_err(|_| anyhow::anyhow!("supervisor messaging session registry is poisoned"))?;
        sessions.insert(run_directory.to_path_buf(), factory);
        return Ok(());
    }

    let store = run_directory.join(SUPERVISOR_MESSAGING_STORE_NAME);
    bail!(legacy_credentials_unavailable_message(&store));
}

#[cfg(test)]
pub(super) fn forget_supervisor_messaging_session_for_test(run_directory: &Path) -> Result<()> {
    let mut sessions = run_sessions()
        .lock()
        .map_err(|_| anyhow::anyhow!("supervisor messaging session registry is poisoned"))?;
    sessions
        .remove(run_directory)
        .context("supervisor messaging test session is not initialized")?;
    Ok(())
}

#[cfg(test)]
pub(super) fn legacy_initialize_supervisor_messaging_session_for_test(
    writer: &mut ArtifactRunWriter,
    plan: &SupervisorPlan,
    metadata: &SupervisorPlanMetadata,
) -> Result<()> {
    if plan.assignments.is_empty() {
        return Ok(());
    }
    let run_directory = writer.run_dir().to_path_buf();
    let (hierarchy, identities) = admitted_messaging_authority(plan, metadata)?;
    let mut sessions = run_sessions()
        .lock()
        .map_err(|_| anyhow::anyhow!("supervisor messaging session registry is poisoned"))?;
    if sessions.contains_key(&run_directory) {
        bail!("legacy messaging test session is already initialized");
    }
    if authenticated_descriptor_present(&run_directory)? {
        bail!("legacy messaging test fixture cannot share a durable descriptor");
    }
    let factory = SupervisorMessagingSessionFactory::new(&run_directory, &hierarchy, &identities)
        .context("legacy supervisor messaging pre-launch admission failed")?;
    factory
        .legacy_create_manifested_store(writer)
        .context("legacy supervisor messaging pre-launch journal creation failed")?;
    sessions.insert(run_directory, factory);
    Ok(())
}

pub(crate) fn with_supervisor_messaging_session<T>(
    run_directory: &Path,
    operation: impl FnOnce(&SupervisorMessagingSessionFactory) -> Result<T>,
) -> Result<T> {
    let sessions = run_sessions()
        .lock()
        .map_err(|_| anyhow::anyhow!("supervisor messaging session registry is poisoned"))?;
    let factory = sessions
        .get(run_directory)
        .context("supervisor messaging session is not initialized")?;
    operation(factory)
}

/// Starts loopback assignment messaging for one already-admitted `task_id`.
pub(super) fn start_assignment_messaging(
    run_directory: &Path,
    run_id: &str,
    task_id: &str,
) -> Result<AssignmentMessagingServer> {
    recover_supervisor_messaging_session(run_directory)?;
    let bound_run_id = with_supervisor_messaging_session(run_directory, |factory| {
        factory.ensure_authenticated_run_id(run_id)?;
        factory
            .capability_for(task_id)
            .map(|_| ())
            .with_context(|| {
                format!(
                    "assignment messaging transport cannot bind to non-admitted task {:?}",
                    task_id
                )
            })?;
        RunId::new(run_id).map(|validated| validated.as_str().to_string())
    })?;
    let run_directory = run_directory.to_path_buf();
    let handler_task_id = task_id.to_string();
    AssignmentMessagingServer::start(&bound_run_id, task_id, move |request| {
        dispatch_assignment_messaging_operation(&run_directory, &handler_task_id, request)
    })
}

#[derive(Debug, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum AssignmentMessagingOperation {
    SendDirect {
        recipient_id: String,
        payload: Value,
    },
    CreateChannel {
        channel_id: String,
        members: Vec<String>,
        publishers: Vec<String>,
    },
    PublishChannel {
        channel_id: String,
        payload: Value,
    },
    ReceiveNext {},
    ReceiveNextFromChannel {
        channel_id: String,
    },
    Acknowledge {
        message_id: String,
    },
}

fn dispatch_assignment_messaging_operation(
    run_directory: &Path,
    task_id: &str,
    request: Value,
) -> Result<Value> {
    let operation: AssignmentMessagingOperation = serde_json::from_value(request)
        .context("assignment messaging operation is ill-typed or contains unknown fields")?;
    with_supervisor_messaging_session(run_directory, |factory| {
        let credential = factory.capability_for(task_id)?;
        let mut broker = factory.open_or_create()?;
        match operation {
            AssignmentMessagingOperation::SendDirect {
                recipient_id,
                payload,
            } => {
                let envelope = broker
                    .send_direct(&credential, recipient_id, payload)
                    .map_err(messaging_error)?;
                serialize_messaging_result(&envelope)
                    .context("failed to serialize send_direct result")
            }
            AssignmentMessagingOperation::CreateChannel {
                channel_id,
                members,
                publishers,
            } => {
                let members = string_array_to_set(members);
                let publishers = string_array_to_set(publishers);
                let channel = broker
                    .create_channel(&credential, channel_id, members, publishers)
                    .map_err(messaging_error)?;
                serialize_messaging_result(&channel)
                    .context("failed to serialize create_channel result")
            }
            AssignmentMessagingOperation::PublishChannel {
                channel_id,
                payload,
            } => {
                let envelope = broker
                    .publish_channel(&credential, channel_id, payload)
                    .map_err(messaging_error)?;
                serialize_messaging_result(&envelope)
                    .context("failed to serialize publish_channel result")
            }
            AssignmentMessagingOperation::ReceiveNext {} => {
                let envelope = broker.receive_next(&credential).map_err(messaging_error)?;
                match envelope {
                    Some(envelope) => serialize_messaging_result(&envelope)
                        .context("failed to serialize receive_next result"),
                    None => Ok(Value::Null),
                }
            }
            AssignmentMessagingOperation::ReceiveNextFromChannel { channel_id } => {
                let envelope = broker
                    .receive_next_from_channel(&credential, channel_id)
                    .map_err(messaging_error)?;
                match envelope {
                    Some(envelope) => serialize_messaging_result(&envelope)
                        .context("failed to serialize receive_next_from_channel result"),
                    None => Ok(Value::Null),
                }
            }
            AssignmentMessagingOperation::Acknowledge { message_id } => {
                let message_id = MessageId::new(message_id).map_err(|error| {
                    anyhow::anyhow!("acknowledge message_id is invalid: {error}")
                })?;
                let outcome = broker
                    .acknowledge(&credential, &message_id)
                    .map_err(messaging_error)?;
                serialize_acknowledgement_outcome(outcome)
            }
        }
    })
}

fn serialize_acknowledgement_outcome(outcome: AcknowledgementOutcome) -> Result<Value> {
    let label = match outcome {
        AcknowledgementOutcome::Acknowledged => "acknowledged",
        AcknowledgementOutcome::AlreadyAcknowledged => "already_acknowledged",
    };
    Ok(json!(label))
}

fn messaging_error(error: MessagingError) -> anyhow::Error {
    anyhow::Error::new(error)
}

fn admitted_messaging_authority(
    plan: &SupervisorPlan,
    metadata: &SupervisorPlanMetadata,
) -> Result<(HierarchyLedgerSnapshot, Vec<LaunchedMessagingIdentity>)> {
    // The scheduler treats an absent supplied schedule as the validated flat-plan schedule. Keep
    // messaging admission on that same authority path: an explicit schedule must match exactly,
    // while absence never invents identities beyond the already-normalized plan.
    let schedule = (!metadata.assignment_schedule.is_empty())
        .then_some(metadata.assignment_schedule.as_slice());
    if schedule.is_some_and(|schedule| schedule.len() != plan.assignments.len()) {
        bail!("validated assignment schedule does not cover every messaging identity owner");
    }

    let mut hierarchy = HierarchyLedgerSnapshot::default();
    let mut identities = Vec::new();
    for (index, assignment) in plan.assignments.iter().enumerate() {
        if let Some(entry) = schedule.and_then(|schedule| schedule.get(index)) {
            if entry.flattened_index != index {
                bail!(
                    "validated assignment schedule entry {:?} has unexpected flattened index {}",
                    entry.assignment_id,
                    entry.flattened_index
                );
            }
            if entry.assignment_id != assignment.id {
                bail!(
                    "validated assignment schedule identity {:?} does not match plan identity {:?}",
                    entry.assignment_id,
                    assignment.id
                );
            }
        }
        insert_admitted_identity(
            &mut hierarchy,
            &mut identities,
            LaunchedMessagingIdentity::from_orchestrator(assignment),
        )?;
        for worker in &assignment.worker_assignments {
            insert_admitted_identity(
                &mut hierarchy,
                &mut identities,
                LaunchedMessagingIdentity::from_worker(worker),
            )?;
        }
    }
    validate_launched_identities(&hierarchy, &identities)?;
    Ok((hierarchy, identities))
}

fn insert_admitted_identity(
    hierarchy: &mut HierarchyLedgerSnapshot,
    identities: &mut Vec<LaunchedMessagingIdentity>,
    identity: LaunchedMessagingIdentity,
) -> Result<()> {
    if hierarchy
        .effective_categories
        .insert(identity.agent_id.clone(), identity.role_category)
        .is_some()
    {
        bail!(
            "validated supervisor plan contains duplicate messaging identity {:?}",
            identity.agent_id
        );
    }
    identities.push(identity);
    Ok(())
}

impl SupervisorMessagingSessionFactory {
    fn revalidate_authority(
        &self,
        hierarchy: &HierarchyLedgerSnapshot,
        identities: &[LaunchedMessagingIdentity],
    ) -> Result<()> {
        if let Some(binding) = &self.persistent {
            binding.verify_authority(hierarchy, identities)?;
            return Ok(());
        }
        self.validate_session_authority(hierarchy, identities)
    }

    fn validate_session_authority(
        &self,
        hierarchy: &HierarchyLedgerSnapshot,
        identities: &[LaunchedMessagingIdentity],
    ) -> Result<()> {
        validate_launched_identities(hierarchy, identities)?;
        if self.hierarchy.effective_categories != hierarchy.effective_categories
            || self.capabilities.len() != identities.len()
            || identities
                .iter()
                .any(|identity| !self.capabilities.contains_key(&identity.agent_id))
        {
            bail!(
                "supervisor messaging resume authority differs from the originally admitted identity set"
            );
        }
        Ok(())
    }
}

impl fmt::Debug for SupervisorMessagingSessionFactory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SupervisorMessagingSessionFactory")
            .field("artifact_root", &self.artifact_root.path())
            .field("store_path", &self.store_path)
            .field("persistent", &self.persistent.is_some())
            .field(
                "capability_principals",
                &self.capabilities.keys().collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

fn validate_absolute_run_artifact_directory(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!(
            "supervisor messaging run artifact directory must be absolute: {}",
            path.display()
        );
    }
    for component in path.components() {
        match component {
            Component::ParentDir => bail!(
                "supervisor messaging run artifact directory must not contain a path escape: {}",
                path.display()
            ),
            Component::CurDir => bail!(
                "supervisor messaging run artifact directory must be lexically normalized: {}",
                path.display()
            ),
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {}
        }
    }
    Ok(())
}

fn validate_launched_identities(
    hierarchy: &HierarchyLedgerSnapshot,
    launched_identities: &[LaunchedMessagingIdentity],
) -> Result<()> {
    if launched_identities.is_empty() {
        bail!("supervisor messaging session requires at least one launched identity");
    }

    let mut unique = BTreeSet::new();
    for identity in launched_identities {
        if !unique.insert(identity.agent_id.as_str()) {
            bail!(
                "duplicate supervisor messaging identity {:?}",
                identity.agent_id
            );
        }
        let ledger_category = hierarchy
            .effective_categories
            .get(&identity.agent_id)
            .with_context(|| {
                format!(
                    "supervisor messaging identity {:?} is absent from the validated hierarchy ledger",
                    identity.agent_id
                )
            })?;
        if *ledger_category != identity.role_category {
            bail!(
                "supervisor messaging identity {:?} declared role {}, but the validated hierarchy ledger binds role {}",
                identity.agent_id,
                identity.role_category.as_str(),
                ledger_category.as_str()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{cell::Cell, fs};

    const COORDINATOR_SECRET: &str = "coordinator-secret-known-only-to-this-test";
    const WORKER_SECRET: &str = "worker-secret-known-only-to-this-test";

    fn hierarchy() -> HierarchyLedgerSnapshot {
        let mut hierarchy = HierarchyLedgerSnapshot::default();
        hierarchy.effective_categories.insert(
            "coordinator".to_string(),
            RoleCategory::DelegatingCoordinator,
        );
        hierarchy.effective_categories.insert(
            "worker".to_string(),
            RoleCategory::NonDelegatingTerminalWorker,
        );
        hierarchy
            .effective_categories
            .insert("researcher".to_string(), RoleCategory::ReadOnlyResearcher);
        hierarchy
    }

    fn launched_identities() -> Vec<LaunchedMessagingIdentity> {
        vec![
            LaunchedMessagingIdentity::new("coordinator", RoleCategory::DelegatingCoordinator),
            LaunchedMessagingIdentity::new("worker", RoleCategory::NonDelegatingTerminalWorker),
        ]
    }

    fn factory_with_known_secrets(directory: &Path) -> Result<SupervisorMessagingSessionFactory> {
        let mut secrets = [COORDINATOR_SECRET, WORKER_SECRET].into_iter();
        SupervisorMessagingSessionFactory::new_with_secret_generator(
            directory,
            &hierarchy(),
            &launched_identities(),
            |_| {
                secrets
                    .next()
                    .map(str::to_string)
                    .context("test secret generator was exhausted")
            },
        )
    }

    #[test]
    fn ledger_snapshot_is_the_only_broker_authority_binding() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let factory = factory_with_known_secrets(temporary.path())?;
        let coordinator = factory.capability_for("coordinator")?;
        let mut broker = factory.open_or_create()?;

        let envelope = broker.send_direct(&coordinator, "worker", json!({"task": "bounded"}))?;
        assert_eq!(envelope.sender_role, RoleCategory::DelegatingCoordinator);
        drop(broker);

        let durable = fs::read_to_string(temporary.path().join(SUPERVISOR_MESSAGING_STORE_NAME))?;
        assert!(durable.contains("researcher"));
        assert!(durable.contains("read_only_researcher"));
        assert!(factory.capability_for("researcher").is_err());
        Ok(())
    }

    #[test]
    fn each_launched_agent_receives_one_unique_memory_only_handle() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let factory = factory_with_known_secrets(temporary.path())?;

        let coordinator = factory.capability_for("coordinator")?;
        let worker = factory.capability_for("worker")?;
        assert_eq!(coordinator.agent_id(), "coordinator");
        assert_eq!(worker.agent_id(), "worker");
        assert_ne!(coordinator, worker);
        assert_eq!(factory.capabilities.len(), 2);
        assert_eq!(factory.registry.len(), 2);
        assert_eq!(factory.capability_for("worker")?, worker);
        Ok(())
    }

    #[test]
    fn one_factory_can_resume_the_same_durable_store() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let factory = factory_with_known_secrets(temporary.path())?;
        let coordinator = factory.capability_for("coordinator")?;
        let worker = factory.capability_for("worker")?;

        let (broker_instance_id, sent) = {
            let mut broker = factory.open_or_create()?;
            let broker_instance_id = broker.broker_instance_id().to_string();
            let sent = broker.send_direct(&coordinator, "worker", "resume-safe message")?;
            (broker_instance_id, sent)
        };
        let mut resumed = factory.open_or_create()?;
        assert_eq!(resumed.broker_instance_id(), broker_instance_id);
        assert_eq!(
            resumed
                .receive_next(&worker)?
                .context("resumed broker did not replay pending message")?
                .id,
            sent.id
        );
        Ok(())
    }

    #[test]
    fn unknown_duplicate_and_role_disagreeing_identities_are_refused_before_secrets() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let hierarchy = hierarchy();

        for identities in [
            vec![LaunchedMessagingIdentity::new(
                "unknown",
                RoleCategory::NonDelegatingTerminalWorker,
            )],
            vec![
                LaunchedMessagingIdentity::new("worker", RoleCategory::NonDelegatingTerminalWorker),
                LaunchedMessagingIdentity::new("worker", RoleCategory::NonDelegatingTerminalWorker),
            ],
            vec![LaunchedMessagingIdentity::new(
                "worker",
                RoleCategory::DelegatingCoordinator,
            )],
        ] {
            let calls = Cell::new(0);
            let error = SupervisorMessagingSessionFactory::new_with_secret_generator(
                temporary.path(),
                &hierarchy,
                &identities,
                |_| {
                    calls.set(calls.get() + 1);
                    Ok("must-not-be-generated".to_string())
                },
            )
            .expect_err("invalid launched identity must be refused");
            assert_eq!(calls.get(), 0, "credential generation preceded {error:#}");
        }
    }

    #[test]
    fn durable_and_debug_surfaces_contain_no_credential_secrets() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let factory = factory_with_known_secrets(temporary.path())?;
        let coordinator = factory.capability_for("coordinator")?;
        let worker = factory.capability_for("worker")?;
        let broker = factory.open_or_create()?;
        drop(broker);

        let debug = format!("{factory:?} {coordinator:?} {worker:?}");
        for secret in [COORDINATOR_SECRET, WORKER_SECRET] {
            assert!(!debug.contains(secret));
            for entry in fs::read_dir(temporary.path())? {
                let bytes = fs::read(entry?.path())?;
                assert!(!bytes
                    .windows(secret.len())
                    .any(|window| window == secret.as_bytes()));
            }
        }
        assert!(debug.contains("[REDACTED]"));
        Ok(())
    }

    #[test]
    fn start_assignment_messaging_rejects_authenticated_run_id_mismatch() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let run_directory = temporary.path().to_path_buf();
        let factory = factory_with_known_secrets(&run_directory)?;
        let authenticated_run_id = run_directory
            .file_name()
            .and_then(|name| name.to_str())
            .context("run directory must have a UTF-8 leaf name")?;
        {
            let mut sessions = run_sessions().lock().map_err(|_| {
                anyhow::anyhow!("supervisor messaging session registry is poisoned")
            })?;
            sessions.insert(run_directory.clone(), factory);
        }
        let mismatch = start_assignment_messaging(&run_directory, "not-that-run", "coordinator")
            .expect_err("mismatched run id must be refused before transport bind");
        assert!(mismatch
            .to_string()
            .contains("authenticated supervisor run binding"));
        let server =
            start_assignment_messaging(&run_directory, authenticated_run_id, "coordinator")?;
        drop(server);
        Ok(())
    }

    #[test]
    fn dispatch_rejects_unknown_operation_fields_before_broker_mutation() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let run_directory = temporary.path().to_path_buf();
        let factory = factory_with_known_secrets(&run_directory)?;
        {
            let mut sessions = run_sessions().lock().map_err(|_| {
                anyhow::anyhow!("supervisor messaging session registry is poisoned")
            })?;
            sessions.insert(run_directory.clone(), factory);
        }
        let error = dispatch_assignment_messaging_operation(
            &run_directory,
            "coordinator",
            json!({"operation": "receive_next", "task_id": "stolen"}),
        )
        .expect_err("unknown operation fields must be refused");
        assert!(error
            .to_string()
            .contains("ill-typed or contains unknown fields"));
        Ok(())
    }

    #[test]
    fn unsafe_store_directories_and_path_escape_are_refused() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let file = temporary.path().join("not-a-directory");
        fs::write(&file, b"not a directory")?;
        assert!(SupervisorMessagingSessionFactory::new(
            &file,
            &hierarchy(),
            &launched_identities()
        )
        .is_err());

        let escaped = temporary.path().join("inside").join("..").join("outside");
        let error =
            SupervisorMessagingSessionFactory::new(&escaped, &hierarchy(), &launched_identities())
                .expect_err("parent-directory escape must be refused");
        assert!(format!("{error:#}").contains("path escape"));

        let directory_store_root = temporary.path().join("directory-store-root");
        fs::create_dir(&directory_store_root)?;
        fs::create_dir(directory_store_root.join(SUPERVISOR_MESSAGING_STORE_NAME))?;
        let directory_store = SupervisorMessagingSessionFactory::new(
            &directory_store_root,
            &hierarchy(),
            &launched_identities(),
        )?;
        assert!(directory_store.open_or_create().is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let real = temporary.path().join("real-directory");
            let alias = temporary.path().join("symlink-directory");
            fs::create_dir(&real)?;
            symlink(&real, &alias)?;
            assert!(SupervisorMessagingSessionFactory::new(
                &alias,
                &hierarchy(),
                &launched_identities()
            )
            .is_err());

            let symlink_store_root = temporary.path().join("symlink-store-root");
            let outside_store = temporary.path().join("outside-store.jsonl");
            fs::create_dir(&symlink_store_root)?;
            fs::write(&outside_store, b"outside")?;
            symlink(
                &outside_store,
                symlink_store_root.join(SUPERVISOR_MESSAGING_STORE_NAME),
            )?;
            let symlink_store = SupervisorMessagingSessionFactory::new(
                &symlink_store_root,
                &hierarchy(),
                &launched_identities(),
            )?;
            assert!(symlink_store.open_or_create().is_err());
        }
        Ok(())
    }
}
