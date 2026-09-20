//! Repository-authenticated snapshot persistence for [`DecisionRegistry`].
//!
//! The in-memory registry remains the coordination substrate. This store is the
//! repository-bound seam that writes and reloads its validated
//! [`DecisionRegistrySnapshot`] through the shared authenticated snapshot
//! journal. Persist fails closed when overlapping-scope records still need
//! reconciliation. First-key consumer registration is a separate compile-time
//! wiring step outside this module.

use crate::{
    artifacts::{
        repository_auth_writer, repository_authenticator_key_only,
        state_auth::{
            validate_repository_binding, AuthenticationDomain, BoundStateLock,
            RepositoryAuthBinding, RepositoryAuthenticator,
        },
    },
    authenticated_snapshot::{AuthenticatedSnapshot, AuthenticatedSnapshotStore, SnapshotSpec},
    decision_claim::{detect_decision_contradictions, DecisionRegistry, DecisionRegistrySnapshot},
    safe_state::SafeRoot,
    state_journal::JournalSpec,
};
use anyhow::{bail, Context, Result};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

/// Direct child of Git-common `maco/state` reserved for decision-registry snapshots.
pub const DECISION_STORE_STATE_NAMESPACE: &str = "authenticated-decision-registry-v1";

const DECISION_STORE_LOGICAL_ID: &str = "decision-registry";
pub(crate) const DECISION_STORE_ROOT_LOCK: &str = ".authenticated-decision-registry.lock";
pub(crate) const DECISION_STORE_OPERATION_LOCK: &str = "decision-registry-operation-v1.lock";
const DECISION_STORE_STATE_VERSION: u32 = 1;
const MAX_DECISION_REGISTRY_CLAIMS: usize = 4_096;
const MAX_DECISION_REGISTRY_RECORDS: usize = 4_096;
const MAX_DECISION_STATE_BYTES: u64 = 512 * 1024;
const MAX_DECISION_SNAPSHOT_RECORD_BYTES: u64 = 768 * 1024;
const MAX_DECISION_JOURNAL_BYTES: u64 = 96 * 1024 * 1024;
const SNAPSHOT_ROLLOVER_INTERVAL: u64 = 128;

enum DecisionRegistrySnapshotSpec {}

impl JournalSpec for DecisionRegistrySnapshotSpec {
    const FORMAT_VERSION: u32 = 1;
    const NAMESPACE: &'static str = "authenticated_decision_registry";
    const ROOT_NAME: &'static str = DECISION_STORE_STATE_NAMESPACE;
    const ROOT_LOCK_NAME: &'static str = DECISION_STORE_ROOT_LOCK;
    const INSTANCE_LOCK_NAME: &'static str = ".decision-registry-snapshot.lock";
    const HEAD_FILE_NAME: &'static str = ".head.json";
    const RECORD_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0authenticated-decision-registry-record\0v1\0");
    const HEAD_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0authenticated-decision-registry-head\0v1\0");
    const MAX_RECORDS: usize = 128;
    const MAX_RECORD_BYTES: u64 = MAX_DECISION_SNAPSHOT_RECORD_BYTES;
    const MAX_TOTAL_BYTES: u64 = MAX_DECISION_JOURNAL_BYTES;
    const MAX_PHASE_BYTES: usize = 32;
    const MAX_SUBJECT_BYTES: usize = 64;
    const MAX_INSTANCE_ID_BYTES: usize = 128;
}

impl SnapshotSpec for DecisionRegistrySnapshotSpec {
    const SNAPSHOT_FORMAT_VERSION: u32 = 1;
    const LOCATOR_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0authenticated-decision-registry-locator\0v1\0");
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedDecisionRegistryState {
    version: u32,
    snapshot_revision: u64,
    repository: RepositoryAuthBinding,
    registry: DecisionRegistrySnapshot,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedDecisionRegistryStateWire {
    version: u32,
    snapshot_revision: u64,
    repository: RepositoryAuthBinding,
    registry: DecisionRegistrySnapshot,
}

impl<'de> Deserialize<'de> for AuthenticatedDecisionRegistryState {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AuthenticatedDecisionRegistryStateWire::deserialize(deserializer)?;
        let state = Self {
            version: wire.version,
            snapshot_revision: wire.snapshot_revision,
            repository: wire.repository,
            registry: wire.registry,
        };
        validate_state_structure(&state).map_err(D::Error::custom)?;
        Ok(state)
    }
}

/// Repository-authenticated decision-registry store rooted in the Git common
/// directory, shared by the primary and linked worktrees.
#[derive(Debug, Clone)]
pub struct DecisionStore {
    repo_path: PathBuf,
}

impl DecisionStore {
    /// Opens or creates the authenticated decision-registry snapshot.
    pub fn open(repo_path: impl AsRef<Path>) -> Result<Self> {
        let store = Self {
            repo_path: discover_repository_path(repo_path.as_ref())?,
        };
        store.ensure_initialized()?;
        Ok(store)
    }

    /// Opens an existing snapshot without creating a key, namespace, lock, or
    /// recovery write. Malformed or over-bounds authenticated state fails
    /// closed before a handle is returned.
    pub fn open_existing(repo_path: impl AsRef<Path>) -> Result<Option<Self>> {
        let repo = crate::git_repository::discover(repo_path.as_ref()).with_context(|| {
            format!(
                "failed to discover repository from {}",
                repo_path.as_ref().display()
            )
        })?;
        let state_path = repo.commondir().join("maco").join("state");
        match fs::symlink_metadata(&state_path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect repository state root {}",
                        state_path.display()
                    )
                });
            }
        }
        let common_root = SafeRoot::open_existing(repo.commondir())
            .context("Git common directory is not safely reachable for decision-registry query")?;
        let state_root = SafeRoot::open_existing(&state_path)
            .context("repository state root is unsafe for decision-registry query")?;
        if !state_root.direct_child_exists(DECISION_STORE_STATE_NAMESPACE)? {
            return Ok(None);
        }
        common_root.verify()?;
        state_root.verify()?;
        let store = Self {
            repo_path: repo
                .workdir()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| repo.path().to_path_buf()),
        };
        store.read_state()?;
        Ok(Some(store))
    }

    /// Reloads the in-memory registry from the authenticated snapshot.
    pub fn load_registry(&self) -> Result<DecisionRegistry> {
        let state = self.read_state()?;
        DecisionRegistry::from_snapshot(state.registry)
            .context("authenticated decision registry snapshot is invalid")
    }

    /// Persists a registry snapshot. Overlapping-scope records with different
    /// resolutions are refused so contradictions cannot become durable.
    pub fn persist_registry(&self, registry: &DecisionRegistry) -> Result<()> {
        let report = registry
            .reconciliation_report()
            .context("failed to inspect decision registry reconciliation state")?;
        if report.reconciliation_needed {
            bail!(
                "decision registry persist refused because reconciliation_needed is true; overlapping-scope records require reconciliation"
            );
        }
        let snapshot = registry
            .snapshot()
            .context("failed to snapshot decision registry")?;
        if detect_decision_contradictions(&snapshot.records).reconciliation_needed {
            bail!(
                "decision registry persist refused because reconciliation_needed is true; overlapping-scope records require reconciliation"
            );
        }

        let authenticator = repository_authenticator_key_only(&self.repo_path)?;
        let state_root = authenticator.state_root().clone();
        let operation_lock = BoundStateLock::acquire(&state_root, DECISION_STORE_OPERATION_LOCK)?;
        let result = (|| {
            let mut store = self.open_store_with_authenticator(authenticator)?;
            let mut value = store.current().value.clone();
            value.registry = snapshot;
            let revision = value
                .snapshot_revision
                .checked_add(1)
                .context("decision-registry snapshot revision exhausted")?;
            value.snapshot_revision = revision;
            validate_state_structure(&value)?;

            if revision % SNAPSHOT_ROLLOVER_INTERVAL == 0 {
                let rollover_authenticator = repository_authenticator_key_only(&self.repo_path)?;
                store = store.rollover(rollover_authenticator, revision, value)?;
            } else {
                store.commit(revision, value)?;
            }
            self.validate_store(&store)
        })();
        finish_operation(result, operation_lock.verify(&state_root))
    }

    fn ensure_initialized(&self) -> Result<()> {
        let writer = repository_auth_writer(&self.repo_path)?;
        let authenticator = writer.into_authenticator()?;
        let state_root = authenticator.state_root().clone();
        let operation_lock = BoundStateLock::acquire(&state_root, DECISION_STORE_OPERATION_LOCK)?;
        let result = (|| {
            if AuthenticatedSnapshotStore::<
                DecisionRegistrySnapshotSpec,
                AuthenticatedDecisionRegistryState,
            >::initialized(&authenticator, DECISION_STORE_LOGICAL_ID)?
            {
                let store =
                    AuthenticatedSnapshotStore::<
                        DecisionRegistrySnapshotSpec,
                        AuthenticatedDecisionRegistryState,
                    >::open_instance(authenticator, DECISION_STORE_LOGICAL_ID)?;
                return self.validate_store(&store);
            }
            let initial = AuthenticatedDecisionRegistryState {
                version: DECISION_STORE_STATE_VERSION,
                snapshot_revision: 1,
                repository: authenticator.binding().clone(),
                registry: DecisionRegistrySnapshot::default(),
            };
            validate_state_structure(&initial)?;
            let store = AuthenticatedSnapshotStore::<
                DecisionRegistrySnapshotSpec,
                AuthenticatedDecisionRegistryState,
            >::create(authenticator, DECISION_STORE_LOGICAL_ID, 1, initial)?;
            self.validate_store(&store)
        })();
        finish_operation(result, operation_lock.verify(&state_root))
    }

    fn open_store_with_authenticator(
        &self,
        authenticator: RepositoryAuthenticator,
    ) -> Result<
        AuthenticatedSnapshotStore<
            DecisionRegistrySnapshotSpec,
            AuthenticatedDecisionRegistryState,
        >,
    > {
        let store =
            AuthenticatedSnapshotStore::open_instance(authenticator, DECISION_STORE_LOGICAL_ID)?;
        self.validate_store(&store)?;
        Ok(store)
    }

    fn read_state(&self) -> Result<AuthenticatedDecisionRegistryState> {
        let authenticator = repository_authenticator_key_only(&self.repo_path)?;
        let repository = authenticator.binding().clone();
        let snapshot = AuthenticatedSnapshotStore::<
            DecisionRegistrySnapshotSpec,
            AuthenticatedDecisionRegistryState,
        >::read_existing_current(authenticator, DECISION_STORE_LOGICAL_ID)?;
        validate_authenticated_snapshot(&snapshot, &repository)?;
        Ok(snapshot.value)
    }

    fn validate_store(
        &self,
        store: &AuthenticatedSnapshotStore<
            DecisionRegistrySnapshotSpec,
            AuthenticatedDecisionRegistryState,
        >,
    ) -> Result<()> {
        validate_authenticated_snapshot(store.current(), &store.identity().repository)
    }
}

fn validate_authenticated_snapshot(
    snapshot: &AuthenticatedSnapshot<AuthenticatedDecisionRegistryState>,
    repository: &RepositoryAuthBinding,
) -> Result<()> {
    if snapshot.value.version != DECISION_STORE_STATE_VERSION
        || snapshot.value.snapshot_revision != snapshot.generation
        || snapshot.value.snapshot_revision != snapshot.token
        || &snapshot.value.repository != repository
    {
        bail!("authenticated decision-registry snapshot binding or revision is inconsistent");
    }
    validate_state_structure(&snapshot.value)
}

fn validate_state_structure(state: &AuthenticatedDecisionRegistryState) -> Result<()> {
    if state.version != DECISION_STORE_STATE_VERSION || state.snapshot_revision == 0 {
        bail!("authenticated decision-registry state has an invalid version or revision");
    }
    validate_repository_binding(&state.repository)?;
    if state.registry.claims.len() > MAX_DECISION_REGISTRY_CLAIMS {
        bail!(
            "authenticated decision-registry state exceeds its {} claim bound",
            MAX_DECISION_REGISTRY_CLAIMS
        );
    }
    if state.registry.records.len() > MAX_DECISION_REGISTRY_RECORDS {
        bail!(
            "authenticated decision-registry state exceeds its {} record bound",
            MAX_DECISION_REGISTRY_RECORDS
        );
    }
    DecisionRegistry::from_snapshot(state.registry.clone())
        .context("authenticated decision registry snapshot is invalid")?;
    let encoded = serde_json::to_vec(state)
        .context("failed to size authenticated decision-registry state")?;
    if u64::try_from(encoded.len()).unwrap_or(u64::MAX) > MAX_DECISION_STATE_BYTES {
        bail!(
            "authenticated decision-registry state exceeds its {} byte bound",
            MAX_DECISION_STATE_BYTES
        );
    }
    Ok(())
}

fn discover_repository_path(repo_path: &Path) -> Result<PathBuf> {
    let repository = crate::git_repository::discover(repo_path)
        .with_context(|| format!("failed to discover repository from {}", repo_path.display()))?;
    Ok(repository
        .workdir()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| repository.path().to_path_buf()))
}

fn finish_operation<T>(result: Result<T>, verification: Result<()>) -> Result<T> {
    match (result, verification) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(lock_error)) => Err(lock_error),
        (Err(error), Err(lock_error)) => Err(error.context(format!(
            "decision-registry operation also lost its stable lock-path binding: {lock_error:#}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision_claim::{DecisionRecord, DecisionScope};
    use git2::Repository;

    fn repository() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().expect("temporary repository");
        Repository::init(temp.path()).expect("initialize repository");
        let path = temp.path().to_path_buf();
        (temp, path)
    }

    fn scope(modules: &[&str], symbols: &[&str], topics: &[&str]) -> DecisionScope {
        DecisionScope::new(
            modules.iter().map(|value| (*value).to_string()),
            symbols.iter().map(|value| (*value).to_string()),
            topics.iter().map(|value| (*value).to_string()),
        )
        .expect("valid test scope")
    }

    fn record(
        question_key: &str,
        resolution: &str,
        assignment: &str,
        scope: DecisionScope,
    ) -> DecisionRecord {
        DecisionRecord::new(question_key, resolution, assignment, scope)
            .expect("valid test decision record")
    }

    /// Reuses the overlapping-scope different-resolution case from decision_claim tests.
    fn contradictory_registry() -> DecisionRegistry {
        DecisionRegistry::from_snapshot(DecisionRegistrySnapshot {
            claims: Vec::new(),
            records: vec![
                record(
                    "api.transport",
                    "Use HTTP",
                    "planner-a",
                    scope(&["api"], &["client::send"], &["public-contract"]),
                ),
                record(
                    "api.protocol",
                    "Use a local socket",
                    "planner-b",
                    scope(
                        &["api"],
                        &["client::send", "server::receive"],
                        &["public-contract"],
                    ),
                ),
            ],
        })
        .expect("contradictory registry is representable in memory")
    }

    #[cfg(unix)]
    #[test]
    fn persist_round_trips_open_and_resolved_claim() {
        let (_temp, repo) = repository();
        let store = DecisionStore::open(&repo).expect("open decision store");
        let registry = DecisionRegistry::new();
        registry
            .claim_open(
                "api.transport",
                "Which transport should the API use?",
                "planner-a",
            )
            .expect("open claim");
        registry
            .resolve_claim(
                "api.transport",
                "planner-a",
                "Use HTTP",
                scope(&["api"], &[], &[]),
            )
            .expect("resolve claim");

        store
            .persist_registry(&registry)
            .expect("persist reconciled registry");

        let reopened = DecisionStore::open(&repo).expect("reopen decision store");
        let loaded = reopened.load_registry().expect("load persisted registry");
        assert_eq!(
            loaded.snapshot().expect("loaded snapshot"),
            registry.snapshot().expect("source snapshot")
        );
    }

    #[test]
    fn persist_refuses_overlapping_scope_different_resolution_records() {
        let registry = contradictory_registry();
        assert!(
            registry
                .reconciliation_report()
                .expect("reconciliation report")
                .reconciliation_needed
        );

        // The reconciliation gate runs before repository authentication, so a
        // contradictory registry is refused without opening durable state.
        let store = DecisionStore {
            repo_path: PathBuf::from("decision-registry-unbound"),
        };
        let error = store
            .persist_registry(&registry)
            .expect_err("contradictory registry must not persist");
        assert!(
            format!("{error:#}").contains("reconciliation_needed"),
            "persist error should name the fail-closed reconciliation gate: {error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn persist_refuse_leaves_initialized_store_empty() {
        let (_temp, repo) = repository();
        let store = DecisionStore::open(&repo).expect("open decision store");
        store
            .persist_registry(&contradictory_registry())
            .expect_err("contradictory registry must not persist");
        let loaded = store
            .load_registry()
            .expect("store remains readable after refused persist");
        assert_eq!(
            loaded.snapshot().expect("empty snapshot"),
            DecisionRegistrySnapshot::default()
        );
    }

    #[test]
    fn open_existing_without_store_returns_none_and_creates_nothing() {
        let (_temp, repo) = repository();
        let maco_root = repo.join(".git").join("maco");
        let state_root = maco_root.join("state");

        assert!(DecisionStore::open_existing(&repo)
            .expect("read-only query")
            .is_none());
        assert!(
            !maco_root.exists(),
            "open_existing must not create Git-common maco state"
        );
        assert!(
            !state_root.exists(),
            "open_existing must not create the authenticated state root"
        );
        assert!(
            !state_root.join(DECISION_STORE_STATE_NAMESPACE).exists(),
            "open_existing must not create the decision-registry namespace"
        );
    }
}
