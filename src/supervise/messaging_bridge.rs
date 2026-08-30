//! Private supervisor bridge for one run's authenticated messaging session.
//!
//! This first issue #333 slice deliberately stops before launch or IPC wiring. The factory keeps
//! every presented capability in memory, binds the durable broker to ledger authority, and can
//! reopen the same store while the per-run factory remains alive.

use super::{
    role_authority::RoleCategory as AssignmentRoleCategory, OrchestratorAssignment,
    WorkerAssignment,
};
use crate::{
    artifacts::state_auth::random_identifier,
    hierarchy_ledger::{HierarchyLedgerSnapshot, RoleCategory},
    messaging::{CredentialRegistry, MessagingBroker, MessagingLimits, PresentedCredential},
    safe_state::SafeRoot,
};
use anyhow::{bail, Context, Result};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::{Component, Path, PathBuf},
};

const SUPERVISOR_MESSAGING_STORE_NAME: &str = "messaging.jsonl";

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
/// dropped. A new factory intentionally receives fresh credentials and therefore cannot silently
/// take over an existing authenticated store.
pub(super) struct SupervisorMessagingSessionFactory {
    artifact_root: SafeRoot,
    store_path: PathBuf,
    hierarchy: HierarchyLedgerSnapshot,
    limits: MessagingLimits,
    registry: CredentialRegistry,
    capabilities: BTreeMap<String, PresentedCredential>,
}

impl SupervisorMessagingSessionFactory {
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
        })
    }

    /// Opens the run's authenticated broker, creating its durable journal on first use.
    pub(super) fn open_or_create(&self) -> Result<MessagingBroker> {
        self.artifact_root
            .verify()
            .context("supervisor messaging artifact directory changed before broker open")?;
        let broker = MessagingBroker::open_or_create(
            &self.store_path,
            self.registry.clone(),
            &self.hierarchy,
            self.limits.clone(),
        )
        .context("failed to open supervisor messaging broker")?;
        self.artifact_root
            .verify()
            .context("supervisor messaging artifact directory changed during broker open")?;
        Ok(broker)
    }

    /// Returns one launched agent's own process-local presentation capability.
    ///
    /// The returned value is neither serializable nor secret-revealing under `Debug`.
    pub(super) fn capability_for(&self, agent_id: &str) -> Result<PresentedCredential> {
        self.capabilities
            .get(agent_id)
            .cloned()
            .with_context(|| format!("supervisor messaging identity {agent_id:?} was not launched"))
    }
}

impl fmt::Debug for SupervisorMessagingSessionFactory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SupervisorMessagingSessionFactory")
            .field("artifact_root", &self.artifact_root.path())
            .field("store_path", &self.store_path)
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
