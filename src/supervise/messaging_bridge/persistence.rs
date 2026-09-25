//! Repository-authenticated durable binding for one supervisor messaging session.
//!
//! The signed session descriptor lives in the run artifact manifest. Live broker
//! journals are rooted under the `supervisor-messaging-v1` authenticated state
//! namespace, bound to repository epoch, run path+identity, and frozen hierarchy
//! authority. Derived agent credentials never leave process memory.

use super::LaunchedMessagingIdentity;
use crate::{
    artifacts::{
        discover_repo_root, repository_auth_writer, repository_authenticator_key_only,
        state_auth::{
            sha256_hex, validate_repository_binding, AuthenticationDomain, AuthenticationTag,
            BoundStateLock, RepositoryAuthBinding, RepositoryAuthenticator, MAX_AUTH_PAYLOAD_BYTES,
        },
        ArtifactFileDisposition, ArtifactRunWriter,
    },
    hierarchy_ledger::{
        GateOwnershipRecord, HierarchyLedgerSnapshot, RoleCategory, RoleTransitionRecord,
        SupervisionEdgeRecord,
    },
    messaging::MessagingLimits,
    safe_state::{BoundedRegularReader, FileIdentity, SafeRoot},
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

/// Direct child of Git-common `maco/state` reserved for supervisor messaging stores.
pub(crate) const MESSAGING_STATE_NAMESPACE: &str = "supervisor-messaging-v1";
pub(crate) const MESSAGING_ROOT_LOCK: &str = ".supervisor-messaging.lock";

const MESSAGING_INSTANCE_LOCK: &str = ".supervisor-messaging-run.lock";
const MESSAGING_STORE_NAME: &str = "messaging.jsonl";
const DESCRIPTOR_FORMAT_VERSION: u32 = 1;

const DESCRIPTOR_DOMAIN: AuthenticationDomain =
    AuthenticationDomain::new(b"MACO\0supervisor-messaging-session-descriptor\0v1\0");
const STATE_INSTANCE_DOMAIN: AuthenticationDomain =
    AuthenticationDomain::new(b"MACO\0supervisor-messaging-state-instance\0v1\0");
const CREDENTIAL_DERIVATION_DOMAIN: AuthenticationDomain =
    AuthenticationDomain::new(b"MACO\0supervisor-messaging-agent-credential\0v1\0");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HierarchyWire {
    edges: BTreeMap<String, SupervisionEdgeRecord>,
    effective_categories: BTreeMap<String, RoleCategory>,
    gate_owners: BTreeMap<String, GateOwnershipRecord>,
    gate_history: Vec<GateOwnershipRecord>,
    role_transitions: Vec<RoleTransitionRecord>,
}

type CanonicalIdentityWire = BTreeMap<String, RoleCategory>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MessagingSessionDescriptorBody {
    version: u32,
    repository: RepositoryAuthBinding,
    run_directory_identity: FileIdentity,
    run_directory_path_sha256: String,
    state_instance_id: String,
    state_directory_identity: FileIdentity,
    hierarchy: HierarchyWire,
    identities: CanonicalIdentityWire,
    limits: MessagingLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MessagingSessionDescriptorFile {
    version: u32,
    repository: RepositoryAuthBinding,
    run_directory_identity: FileIdentity,
    run_directory_path_sha256: String,
    state_instance_id: String,
    state_directory_identity: FileIdentity,
    hierarchy: HierarchyWire,
    identities: CanonicalIdentityWire,
    limits: MessagingLimits,
    mac: AuthenticationTag,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateInstanceBindingPayload {
    version: u32,
    repository: RepositoryAuthBinding,
    run_directory_identity: FileIdentity,
    run_directory_path_sha256: String,
}

pub(super) struct PersistentMessagingBinding {
    authenticator: RepositoryAuthenticator,
    run_directory: SafeRoot,
    state_instance: SafeRoot,
    frozen_descriptor_bytes: Vec<u8>,
    on_disk_descriptor_bytes: Vec<u8>,
    descriptor_mac: AuthenticationTag,
    body: MessagingSessionDescriptorBody,
    hierarchy: HierarchyLedgerSnapshot,
    identities: Vec<LaunchedMessagingIdentity>,
}

impl PersistentMessagingBinding {
    pub(super) const DESCRIPTOR_NAME: &str = "messaging-session.json";

    pub(super) fn prepare(
        writer: &mut ArtifactRunWriter,
        hierarchy: &HierarchyLedgerSnapshot,
        identities: &[LaunchedMessagingIdentity],
    ) -> Result<(Self, bool)> {
        super::validate_launched_identities(hierarchy, identities)?;
        let repo = discover_repo_root(writer.run_dir())?;
        let run_directory = SafeRoot::open_existing(writer.run_dir()).with_context(|| {
            format!(
                "supervisor messaging run artifact directory is not safe: {}",
                writer.run_dir().display()
            )
        })?;
        run_directory.verify()?;

        if run_directory.direct_child_exists(Self::DESCRIPTOR_NAME)? {
            let binding = Self::open_existing_authenticated(
                &repo,
                &run_directory,
                hierarchy,
                identities,
                true,
            )?;
            return Ok((binding, false));
        }

        let authenticator = repository_auth_writer(&repo)?
            .into_authenticator()
            .context(
            "failed to establish repository authentication for new supervisor messaging session",
        )?;
        let state_instance_id = derive_state_instance_id(&authenticator, &run_directory)?;
        let (state_instance, _root_lock) =
            reserve_fresh_state_instance(&authenticator, &state_instance_id)?;
        let body = build_descriptor_body(
            &authenticator,
            &run_directory,
            &state_instance,
            &state_instance_id,
            hierarchy,
            identities,
        )?;
        let (descriptor_file, frozen_descriptor_bytes, descriptor_mac) =
            sign_descriptor(&authenticator, &body)?;
        let on_disk_descriptor_bytes = encode_descriptor_manifest(&descriptor_file)?;
        writer
            .write_bytes(
                Path::new(Self::DESCRIPTOR_NAME),
                &on_disk_descriptor_bytes,
                ArtifactFileDisposition::PrivateEvidence,
            )
            .with_context(|| {
                format!(
                    "failed to manifest supervisor messaging session descriptor {}",
                    Self::DESCRIPTOR_NAME
                )
            })?;
        let hierarchy_snapshot = hierarchy_from_wire(&body.hierarchy);
        let admitted = identities_from_wire(&body.identities);
        let binding = Self {
            authenticator,
            run_directory,
            state_instance,
            frozen_descriptor_bytes,
            on_disk_descriptor_bytes,
            descriptor_mac,
            body,
            hierarchy: hierarchy_snapshot,
            identities: admitted,
        };
        binding.verify_authority(hierarchy, identities)?;
        binding.verify()?;
        Ok((binding, true))
    }

    pub(super) fn open(run_directory: &Path) -> Result<Self> {
        let repo = discover_repo_root(run_directory)?;
        let run_root = SafeRoot::open_existing(run_directory).with_context(|| {
            format!(
                "supervisor messaging run artifact directory is not safe: {}",
                run_directory.display()
            )
        })?;
        run_root.verify()?;
        Self::open_existing_authenticated(
            &repo,
            &run_root,
            &HierarchyLedgerSnapshot::default(),
            &[],
            false,
        )
    }

    pub(super) fn state_instance_id(&self) -> &str {
        &self.body.state_instance_id
    }

    pub(super) fn repository_binding(&self) -> &RepositoryAuthBinding {
        &self.body.repository
    }

    pub(super) fn hierarchy(&self) -> &HierarchyLedgerSnapshot {
        &self.hierarchy
    }

    pub(super) fn identities(&self) -> &[LaunchedMessagingIdentity] {
        &self.identities
    }

    pub(super) fn limits(&self) -> &MessagingLimits {
        &self.body.limits
    }

    pub(super) fn verify_authority(
        &self,
        hierarchy: &HierarchyLedgerSnapshot,
        identities: &[LaunchedMessagingIdentity],
    ) -> Result<()> {
        super::validate_launched_identities(hierarchy, identities)?;
        if hierarchy_wire(hierarchy) != self.body.hierarchy {
            bail!(
                "supervisor messaging resume authority differs from the authenticated hierarchy snapshot"
            );
        }
        if canonical_identity_wire(identities) != self.body.identities {
            bail!(
                "supervisor messaging resume authority differs from the authenticated identity set"
            );
        }
        Ok(())
    }

    pub(super) fn credential_for(&self, agent_id: &str) -> Result<String> {
        self.verify()?;
        if !self.body.identities.contains_key(agent_id) {
            bail!(
                "supervisor messaging identity {:?} was not admitted in the authenticated session descriptor",
                agent_id
            );
        }
        let payload = credential_derivation_payload(&self.frozen_descriptor_bytes, agent_id)?;
        let tag = self
            .authenticator
            .sign(CREDENTIAL_DERIVATION_DOMAIN, &payload)
            .context("failed to derive supervisor messaging credential")?;
        Ok(tag.as_str().to_string())
    }

    pub(super) fn store_path(&self) -> Result<PathBuf> {
        self.verify()?;
        self.state_instance
            .direct_child(MESSAGING_STORE_NAME)
            .context("failed to bind supervisor messaging durable store path")
    }

    pub(super) fn verify(&self) -> Result<()> {
        self.authenticator.verify_epoch()?;
        self.authenticator
            .verify_repository_binding(&self.body.repository)?;
        self.run_directory.verify()?;
        self.state_instance.verify()?;
        verify_run_directory_binding(&self.run_directory, &self.body)?;
        if self.state_instance.identity() != &self.body.state_directory_identity {
            bail!("supervisor messaging authenticated state directory identity changed");
        }
        let on_disk = read_descriptor_bytes_from_run(&self.run_directory)?;
        if on_disk != self.on_disk_descriptor_bytes {
            bail!("supervisor messaging session descriptor changed on disk");
        }
        let (body, frozen_descriptor_bytes, descriptor_mac) = parse_descriptor_bytes(&on_disk)?;
        if body != self.body
            || frozen_descriptor_bytes != self.frozen_descriptor_bytes
            || descriptor_mac != self.descriptor_mac
        {
            bail!("supervisor messaging session descriptor no longer matches its frozen binding");
        }
        verify_descriptor_mac(
            &self.authenticator,
            &self.frozen_descriptor_bytes,
            &self.body,
            &self.descriptor_mac,
        )?;
        Ok(())
    }

    fn open_existing_authenticated(
        repo: &Path,
        run_directory: &SafeRoot,
        hierarchy: &HierarchyLedgerSnapshot,
        identities: &[LaunchedMessagingIdentity],
        enforce_admission: bool,
    ) -> Result<Self> {
        let authenticator = repository_authenticator_key_only(repo).context(
            "failed to open repository authentication for supervisor messaging descriptor",
        )?;
        let on_disk_descriptor_bytes = read_descriptor_bytes_from_run(run_directory)?;
        let (body, frozen_descriptor_bytes, descriptor_mac) =
            parse_descriptor_bytes(&on_disk_descriptor_bytes)?;
        verify_run_directory_binding(run_directory, &body)?;
        authenticator.verify_repository_binding(&body.repository)?;
        verify_descriptor_mac(
            &authenticator,
            &frozen_descriptor_bytes,
            &body,
            &descriptor_mac,
        )?;
        authenticator.verify_epoch()?;
        let state_instance = open_bound_state_instance(&authenticator, &body)?;
        let hierarchy_snapshot = hierarchy_from_wire(&body.hierarchy);
        let admitted = identities_from_wire(&body.identities);
        let binding = Self {
            authenticator,
            run_directory: run_directory.clone(),
            state_instance,
            frozen_descriptor_bytes,
            on_disk_descriptor_bytes,
            descriptor_mac,
            body,
            hierarchy: hierarchy_snapshot,
            identities: admitted,
        };
        if enforce_admission {
            binding.verify_authority(hierarchy, identities)?;
        }
        binding.verify()?;
        Ok(binding)
    }
}

fn hierarchy_wire(hierarchy: &HierarchyLedgerSnapshot) -> HierarchyWire {
    HierarchyWire {
        edges: hierarchy.edges.clone(),
        effective_categories: hierarchy.effective_categories.clone(),
        gate_owners: hierarchy.gate_owners.clone(),
        gate_history: hierarchy.gate_history.clone(),
        role_transitions: hierarchy.role_transitions.clone(),
    }
}

fn hierarchy_from_wire(wire: &HierarchyWire) -> HierarchyLedgerSnapshot {
    HierarchyLedgerSnapshot {
        edges: wire.edges.clone(),
        effective_categories: wire.effective_categories.clone(),
        gate_owners: wire.gate_owners.clone(),
        gate_history: wire.gate_history.clone(),
        role_transitions: wire.role_transitions.clone(),
    }
}

fn canonical_identity_wire(identities: &[LaunchedMessagingIdentity]) -> CanonicalIdentityWire {
    identities
        .iter()
        .map(|identity| (identity.agent_id.clone(), identity.role_category))
        .collect()
}

fn identities_from_wire(identities: &CanonicalIdentityWire) -> Vec<LaunchedMessagingIdentity> {
    identities
        .iter()
        .map(|(agent_id, role_category)| {
            LaunchedMessagingIdentity::new(agent_id.clone(), *role_category)
        })
        .collect()
}

fn run_directory_path_sha256(path: &Path) -> String {
    sha256_hex(&filesystem_path_bytes(path))
}

#[cfg(unix)]
fn filesystem_path_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes().to_vec()
}

#[cfg(windows)]
fn filesystem_path_bytes(path: &Path) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect()
}

#[cfg(not(any(unix, windows)))]
fn filesystem_path_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().to_string_lossy().as_bytes().to_vec()
}

fn verify_run_directory_binding(
    run_directory: &SafeRoot,
    body: &MessagingSessionDescriptorBody,
) -> Result<()> {
    if run_directory.identity() != &body.run_directory_identity {
        bail!("supervisor messaging session descriptor binds a different run directory identity");
    }
    if run_directory_path_sha256(run_directory.path()) != body.run_directory_path_sha256 {
        bail!("supervisor messaging session descriptor binds a different run directory path");
    }
    Ok(())
}

fn build_descriptor_body(
    authenticator: &RepositoryAuthenticator,
    run_directory: &SafeRoot,
    state_instance: &SafeRoot,
    state_instance_id: &str,
    hierarchy: &HierarchyLedgerSnapshot,
    identities: &[LaunchedMessagingIdentity],
) -> Result<MessagingSessionDescriptorBody> {
    let limits = MessagingLimits::default();
    limits
        .validate()
        .map_err(|error| anyhow::anyhow!("supervisor messaging limits are invalid: {error}"))?;
    Ok(MessagingSessionDescriptorBody {
        version: DESCRIPTOR_FORMAT_VERSION,
        repository: authenticator.binding().clone(),
        run_directory_identity: run_directory.identity().clone(),
        run_directory_path_sha256: run_directory_path_sha256(run_directory.path()),
        state_instance_id: state_instance_id.to_string(),
        state_directory_identity: state_instance.identity().clone(),
        hierarchy: hierarchy_wire(hierarchy),
        identities: canonical_identity_wire(identities),
        limits,
    })
}

fn sign_descriptor(
    authenticator: &RepositoryAuthenticator,
    body: &MessagingSessionDescriptorBody,
) -> Result<(MessagingSessionDescriptorFile, Vec<u8>, AuthenticationTag)> {
    let frozen_descriptor_bytes = descriptor_mac_payload(body)?;
    let mac = authenticator
        .sign(DESCRIPTOR_DOMAIN, &frozen_descriptor_bytes)
        .context("failed to sign supervisor messaging session descriptor")?;
    let descriptor_file = MessagingSessionDescriptorFile {
        version: body.version,
        repository: body.repository.clone(),
        run_directory_identity: body.run_directory_identity.clone(),
        run_directory_path_sha256: body.run_directory_path_sha256.clone(),
        state_instance_id: body.state_instance_id.clone(),
        state_directory_identity: body.state_directory_identity.clone(),
        hierarchy: body.hierarchy.clone(),
        identities: body.identities.clone(),
        limits: body.limits.clone(),
        mac: mac.clone(),
    };
    encode_descriptor_manifest(&descriptor_file)?;
    Ok((descriptor_file, frozen_descriptor_bytes, mac))
}

fn encode_descriptor_manifest(file: &MessagingSessionDescriptorFile) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(file)
        .context("failed to encode supervisor messaging descriptor")?;
    bytes.push(b'\n');
    if bytes.len() > MAX_AUTH_PAYLOAD_BYTES {
        bail!("supervisor messaging session descriptor exceeds its byte bound");
    }
    Ok(bytes)
}

fn descriptor_mac_payload(body: &MessagingSessionDescriptorBody) -> Result<Vec<u8>> {
    let bytes =
        serde_json::to_vec(body).context("failed to encode supervisor messaging descriptor")?;
    if bytes.len() > MAX_AUTH_PAYLOAD_BYTES {
        bail!("supervisor messaging session descriptor body exceeds its byte bound");
    }
    Ok(bytes)
}

fn verify_descriptor_mac(
    authenticator: &RepositoryAuthenticator,
    frozen_descriptor_bytes: &[u8],
    body: &MessagingSessionDescriptorBody,
    mac: &AuthenticationTag,
) -> Result<()> {
    if frozen_descriptor_bytes != descriptor_mac_payload(body)? {
        bail!("supervisor messaging session descriptor bytes are not frozen canonical form");
    }
    authenticator.verify_tag(DESCRIPTOR_DOMAIN, frozen_descriptor_bytes, mac)?;
    validate_descriptor_body(body)?;
    Ok(())
}

fn validate_descriptor_body(body: &MessagingSessionDescriptorBody) -> Result<()> {
    validate_repository_binding(&body.repository)?;
    if body.version != DESCRIPTOR_FORMAT_VERSION
        || body.run_directory_identity.file == 0
        || body.state_directory_identity.file == 0
        || !is_canonical_lower_hex_64(&body.run_directory_path_sha256)
    {
        bail!("supervisor messaging session descriptor is malformed or unsupported");
    }
    validate_state_instance_id(&body.state_instance_id)?;
    body.limits.validate().map_err(|error| {
        anyhow::anyhow!("supervisor messaging descriptor limits are invalid: {error}")
    })?;
    if body.identities.is_empty() {
        bail!("supervisor messaging session descriptor requires at least one admitted identity");
    }
    Ok(())
}

fn is_canonical_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn read_descriptor_bytes_from_run(run_directory: &SafeRoot) -> Result<Vec<u8>> {
    BoundedRegularReader::read_direct(
        run_directory,
        PersistentMessagingBinding::DESCRIPTOR_NAME,
        u64::try_from(MAX_AUTH_PAYLOAD_BYTES).unwrap_or(u64::MAX),
    )
    .with_context(|| {
        format!(
            "failed to read supervisor messaging session descriptor {}",
            PersistentMessagingBinding::DESCRIPTOR_NAME
        )
    })
}

fn parse_descriptor_bytes(
    bytes: &[u8],
) -> Result<(MessagingSessionDescriptorBody, Vec<u8>, AuthenticationTag)> {
    if bytes.len() > MAX_AUTH_PAYLOAD_BYTES {
        bail!("supervisor messaging session descriptor exceeds its byte bound");
    }
    let file: MessagingSessionDescriptorFile = serde_json::from_slice(bytes)
        .context("supervisor messaging session descriptor is malformed")?;
    let canonical = encode_descriptor_manifest(&file)?;
    if canonical != bytes {
        bail!("supervisor messaging session descriptor is not in canonical on-disk encoding");
    }
    let body = MessagingSessionDescriptorBody {
        version: file.version,
        repository: file.repository,
        run_directory_identity: file.run_directory_identity,
        run_directory_path_sha256: file.run_directory_path_sha256,
        state_instance_id: file.state_instance_id,
        state_directory_identity: file.state_directory_identity,
        hierarchy: file.hierarchy,
        identities: file.identities,
        limits: file.limits,
    };
    let frozen_descriptor_bytes = descriptor_mac_payload(&body)?;
    validate_descriptor_body(&body)?;
    Ok((body, frozen_descriptor_bytes, file.mac))
}

fn credential_derivation_payload(
    frozen_descriptor_bytes: &[u8],
    agent_id: &str,
) -> Result<Vec<u8>> {
    let digest = sha256_hex(frozen_descriptor_bytes);
    serde_json::to_vec(&(digest, agent_id))
        .context("failed to encode supervisor messaging credential derivation payload")
}

fn derive_state_instance_id(
    authenticator: &RepositoryAuthenticator,
    run_directory: &SafeRoot,
) -> Result<String> {
    let payload = serde_json::to_vec(&StateInstanceBindingPayload {
        version: DESCRIPTOR_FORMAT_VERSION,
        repository: authenticator.binding().clone(),
        run_directory_identity: run_directory.identity().clone(),
        run_directory_path_sha256: run_directory_path_sha256(run_directory.path()),
    })
    .context("failed to encode supervisor messaging state-instance binding")?;
    if payload.len() > MAX_AUTH_PAYLOAD_BYTES {
        bail!("supervisor messaging state-instance binding exceeds its byte bound");
    }
    let tag = authenticator
        .sign(STATE_INSTANCE_DOMAIN, &payload)
        .context("failed to derive supervisor messaging state-instance identifier")?;
    Ok(tag.as_str().to_string())
}

fn validate_state_instance_id(state_instance_id: &str) -> Result<()> {
    AuthenticationTag::parse(state_instance_id).context(
        "supervisor messaging state-instance identifier is not canonical lowercase SHA-256 hex",
    )?;
    Ok(())
}

fn open_or_create_messaging_root(
    authenticator: &RepositoryAuthenticator,
) -> Result<(SafeRoot, BoundStateLock)> {
    authenticator.verify_epoch()?;
    let state_root = authenticator.state_root();
    let root_lock = BoundStateLock::acquire(state_root, MESSAGING_ROOT_LOCK)?;
    root_lock.verify(state_root)?;
    let path = state_root.path().join(MESSAGING_STATE_NAMESPACE);
    let root = SafeRoot::open_or_create(&path).with_context(|| {
        format!(
            "failed to open owner-private supervisor messaging state root {}",
            path.display()
        )
    })?;
    root_lock.verify(state_root)?;
    root.verify()?;
    Ok((root, root_lock))
}

/// Reserves an empty authenticated state directory before the signed descriptor is
/// committed. A crash between reservation and manifest write can leave an unadmitted
/// orphan directory; a later `prepare` on the same run refuses that existing state
/// instead of silently adopting it. Production call order commits the descriptor before
/// any broker admission, so no child transport exists for orphans.
fn reserve_fresh_state_instance(
    authenticator: &RepositoryAuthenticator,
    state_instance_id: &str,
) -> Result<(SafeRoot, BoundStateLock)> {
    validate_state_instance_id(state_instance_id)?;
    let (messaging_root, root_lock) = open_or_create_messaging_root(authenticator)?;
    if messaging_root.direct_child_exists(state_instance_id)? {
        bail!(
            "supervisor messaging authenticated state instance already exists; refusing to adopt an existing journal directory"
        );
    }
    let reserved = messaging_root
        .reserve_direct_child_directory(state_instance_id)
        .with_context(|| {
            format!(
                "failed to reserve supervisor messaging state instance {}",
                state_instance_id
            )
        })?;
    reserved.verify(&messaging_root)?;
    let state_instance = SafeRoot::open_existing(reserved.path())?;
    let _instance_lock =
        BoundStateLock::try_acquire_exclusive(&state_instance, MESSAGING_INSTANCE_LOCK)
            .with_context(|| "supervisor messaging state instance is already active elsewhere")?;
    ensure_empty_fresh_instance(&state_instance)?;
    root_lock.verify(authenticator.state_root())?;
    Ok((state_instance, root_lock))
}

fn open_bound_state_instance(
    authenticator: &RepositoryAuthenticator,
    body: &MessagingSessionDescriptorBody,
) -> Result<SafeRoot> {
    validate_state_instance_id(&body.state_instance_id)?;
    let messaging_root = open_existing_messaging_root(authenticator)?;
    if !messaging_root.direct_child_exists(&body.state_instance_id)? {
        bail!(
            "supervisor messaging authenticated state is missing for an existing session descriptor"
        );
    }
    let reserved = messaging_root
        .bind_existing_direct_child_directory(&body.state_instance_id)
        .with_context(|| {
            "supervisor messaging authenticated state directory is missing or unsafe"
        })?;
    let state_instance = SafeRoot::open_existing(reserved.path())?;
    if state_instance.identity() != &body.state_directory_identity {
        bail!("supervisor messaging authenticated state directory identity changed");
    }
    Ok(state_instance)
}

fn open_existing_messaging_root(authenticator: &RepositoryAuthenticator) -> Result<SafeRoot> {
    authenticator.verify()?;
    let path = authenticator
        .state_root()
        .path()
        .join(MESSAGING_STATE_NAMESPACE);
    let root = SafeRoot::open_existing(&path).with_context(|| {
        format!(
            "supervisor messaging authenticated state root is missing or unsafe: {}",
            path.display()
        )
    })?;
    root.verify()?;
    Ok(root)
}

fn ensure_empty_fresh_instance(state_instance: &SafeRoot) -> Result<()> {
    state_instance.verify()?;
    if state_instance.direct_child_exists(MESSAGING_STORE_NAME)? {
        bail!(
            "supervisor messaging state directory already contains a journal; refusing silent adoption"
        );
    }
    if state_instance.direct_child_exists(format!("{}.tail-anchor", MESSAGING_STORE_NAME))? {
        bail!(
            "supervisor messaging state directory already contains journal residue; refusing silent adoption"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        artifacts::{
            repository_auth_writer,
            state_auth::{
                authentication_key_file_name, authentication_key_length, AuthenticationTag,
            },
            RunArtifactFamily,
        },
        hierarchy_ledger::{RoleTransitionDecision, RoleTransitionEvidenceRecord},
        orchestration_event::OrchestrationRole,
        orchestrator::RunId,
    };
    use git2::Repository;
    use serde_json::json;
    use tempfile::TempDir;

    fn auth_repo() -> (TempDir, PathBuf) {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        Repository::init(&repo_path).expect("init repo");
        repository_auth_writer(&repo_path)
            .expect("create auth")
            .into_authenticator()
            .expect("release key writer");
        (temp, repo_path)
    }

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
    }

    fn launched_identities() -> Vec<LaunchedMessagingIdentity> {
        vec![
            LaunchedMessagingIdentity::new("coordinator", RoleCategory::DelegatingCoordinator),
            LaunchedMessagingIdentity::new("worker", RoleCategory::NonDelegatingTerminalWorker),
        ]
    }

    fn populated_hierarchy() -> Result<HierarchyLedgerSnapshot> {
        let edge = SupervisionEdgeRecord::new(
            "worker",
            "coordinator",
            OrchestrationRole::Worker,
            "worker",
            vec!["src/main.rs".to_string()],
            "assignment:worker",
        )?;
        let assign = GateOwnershipRecord::assign(
            "task-1",
            "coordinator",
            OrchestrationRole::Supervisor,
            "supervisor",
            "initial_gate",
        )?;
        let transfer = GateOwnershipRecord::transfer(
            "task-1",
            "worker",
            OrchestrationRole::Worker,
            "worker",
            "coordinator",
            "handoff_gate",
        )?;
        let transition = RoleTransitionRecord {
            agent_id: "worker".to_string(),
            from_category: RoleCategory::ReadOnlyResearcher,
            to_category: RoleCategory::NonDelegatingTerminalWorker,
            requester_agent_id: "coordinator".to_string(),
            judge_agent_id: "auditor".to_string(),
            evidence: RoleTransitionEvidenceRecord {
                acceptance_grade: true,
                recorded: true,
                uncertain: false,
            },
            decision: RoleTransitionDecision::Granted,
            reason: "promotion_with_evidence".to_string(),
        };
        transition.validate()?;
        let mut hierarchy = HierarchyLedgerSnapshot::default();
        hierarchy.edges.insert(edge.child_agent_id.clone(), edge);
        hierarchy.effective_categories.insert(
            "coordinator".to_string(),
            RoleCategory::DelegatingCoordinator,
        );
        hierarchy.effective_categories.insert(
            "worker".to_string(),
            RoleCategory::NonDelegatingTerminalWorker,
        );
        hierarchy
            .gate_owners
            .insert(transfer.task_id.clone(), transfer.clone());
        hierarchy.gate_history.push(assign);
        hierarchy.gate_history.push(transfer);
        hierarchy.role_transitions.push(transition);
        Ok(hierarchy)
    }

    fn reserve_writer(repo: &Path, run_id: &str) -> (ArtifactRunWriter, PathBuf) {
        let run_id = RunId::new(run_id).expect("valid run id");
        let writer = ArtifactRunWriter::reserve(
            repo,
            RunArtifactFamily::Supervise,
            run_id,
            "persistence-test",
        )
        .expect("reserve artifact run");
        let run_directory = writer.run_dir().to_path_buf();
        (writer, run_directory)
    }

    #[test]
    fn credentials_are_deterministic_across_prepare_and_open() -> Result<()> {
        let (_temp, repo_path) = auth_repo();
        let hierarchy = hierarchy();
        let identities = launched_identities();
        let (mut writer, run_directory) =
            reserve_writer(&repo_path, "messaging-persist-deterministic");
        let (binding, created) =
            PersistentMessagingBinding::prepare(&mut writer, &hierarchy, &identities)?;
        assert!(created);
        let coordinator_prepare = binding.credential_for("coordinator")?;
        let worker_prepare = binding.credential_for("worker")?;
        drop(binding);

        let reopened = PersistentMessagingBinding::open(&run_directory)?;
        assert_eq!(reopened.credential_for("coordinator")?, coordinator_prepare);
        assert_eq!(reopened.credential_for("worker")?, worker_prepare);
        Ok(())
    }

    #[test]
    fn credentials_differ_across_runs_and_agents() -> Result<()> {
        let (_temp, repo_path) = auth_repo();
        let hierarchy = hierarchy();
        let identities = launched_identities();
        let (mut writer_a, _) = reserve_writer(&repo_path, "messaging-persist-run-a");
        let (binding_a, _) =
            PersistentMessagingBinding::prepare(&mut writer_a, &hierarchy, &identities)?;
        let (mut writer_b, _) = reserve_writer(&repo_path, "messaging-persist-run-b");
        let (binding_b, _) =
            PersistentMessagingBinding::prepare(&mut writer_b, &hierarchy, &identities)?;
        assert_ne!(
            binding_a.credential_for("coordinator")?,
            binding_b.credential_for("coordinator")?
        );
        assert_ne!(
            binding_a.credential_for("coordinator")?,
            binding_a.credential_for("worker")?
        );
        Ok(())
    }

    #[test]
    fn tampered_descriptor_is_refused_on_fresh_open() -> Result<()> {
        let (_temp, repo_path) = auth_repo();
        let hierarchy = hierarchy();
        let identities = launched_identities();
        let (mut writer, run_directory) =
            reserve_writer(&repo_path, "messaging-persist-tamper-open");
        PersistentMessagingBinding::prepare(&mut writer, &hierarchy, &identities)?;
        let path = run_directory.join(PersistentMessagingBinding::DESCRIPTOR_NAME);
        let mut bytes = std::fs::read(&path)?;
        bytes.push(b' ');
        std::fs::write(&path, bytes)?;
        assert!(PersistentMessagingBinding::open(&run_directory).is_err());
        Ok(())
    }

    #[test]
    fn tampered_descriptor_is_refused_by_existing_binding() -> Result<()> {
        let (_temp, repo_path) = auth_repo();
        let hierarchy = hierarchy();
        let identities = launched_identities();
        let (mut writer, run_directory) =
            reserve_writer(&repo_path, "messaging-persist-tamper-bound");
        let (binding, _) =
            PersistentMessagingBinding::prepare(&mut writer, &hierarchy, &identities)?;
        let path = run_directory.join(PersistentMessagingBinding::DESCRIPTOR_NAME);
        let mut bytes = std::fs::read(&path)?;
        bytes.push(b' ');
        std::fs::write(&path, bytes)?;
        assert!(binding.verify().is_err());
        assert!(binding.credential_for("coordinator").is_err());
        Ok(())
    }

    #[test]
    fn full_hierarchy_round_trips_through_prepare_and_open() -> Result<()> {
        let hierarchy = populated_hierarchy()?;
        let identities = launched_identities();
        let (_temp, repo_path) = auth_repo();
        let (mut writer, run_directory) =
            reserve_writer(&repo_path, "messaging-persist-full-hierarchy");
        let (binding, created) =
            PersistentMessagingBinding::prepare(&mut writer, &hierarchy, &identities)?;
        assert!(created);
        assert_eq!(*binding.hierarchy(), hierarchy);
        let reopened = PersistentMessagingBinding::open(&run_directory)?;
        assert_eq!(*reopened.hierarchy(), hierarchy);

        let mut changed_history = hierarchy.clone();
        let extra_transition = RoleTransitionRecord {
            agent_id: "coordinator".to_string(),
            from_category: RoleCategory::DelegatingCoordinator,
            to_category: RoleCategory::ReadOnlyResearcher,
            requester_agent_id: "worker".to_string(),
            judge_agent_id: "auditor".to_string(),
            evidence: RoleTransitionEvidenceRecord::default(),
            decision: RoleTransitionDecision::Refused,
            reason: "post_admission_history_mutation".to_string(),
        };
        extra_transition.validate()?;
        changed_history.role_transitions.push(extra_transition);
        assert!(reopened
            .verify_authority(&changed_history, &identities)
            .is_err());
        Ok(())
    }

    #[test]
    fn changed_hierarchy_authority_is_refused_on_prepare() -> Result<()> {
        let (_temp, repo_path) = auth_repo();
        let hierarchy = hierarchy();
        let identities = launched_identities();
        let (mut writer, _) = reserve_writer(&repo_path, "messaging-persist-hierarchy");
        PersistentMessagingBinding::prepare(&mut writer, &hierarchy, &identities)?;
        let mut changed = hierarchy.clone();
        changed
            .effective_categories
            .insert("intruder".to_string(), RoleCategory::ReadOnlyResearcher);
        let error = PersistentMessagingBinding::prepare(&mut writer, &changed, &identities)
            .err()
            .expect("changed hierarchy must be refused");
        assert!(error
            .to_string()
            .contains("authenticated hierarchy snapshot"));
        Ok(())
    }

    #[test]
    fn wrong_run_directory_descriptor_is_refused() -> Result<()> {
        let (_temp, repo_path) = auth_repo();
        let hierarchy = hierarchy();
        let identities = launched_identities();
        let (mut writer_a, run_directory_a) =
            reserve_writer(&repo_path, "messaging-persist-run-expected");
        PersistentMessagingBinding::prepare(&mut writer_a, &hierarchy, &identities)?;
        let (mut writer_b, run_directory_b) =
            reserve_writer(&repo_path, "messaging-persist-run-wrong");
        std::fs::copy(
            run_directory_a.join(PersistentMessagingBinding::DESCRIPTOR_NAME),
            run_directory_b.join(PersistentMessagingBinding::DESCRIPTOR_NAME),
        )?;
        assert!(PersistentMessagingBinding::open(&run_directory_b).is_err());
        assert!(
            PersistentMessagingBinding::prepare(&mut writer_b, &hierarchy, &identities).is_err()
        );
        Ok(())
    }

    #[test]
    fn renamed_run_directory_with_same_inode_is_refused() -> Result<()> {
        let (temp, repo_path) = auth_repo();
        let hierarchy = hierarchy();
        let identities = launched_identities();
        let (mut writer, run_directory) = reserve_writer(&repo_path, "messaging-persist-rename");
        let (binding, _) =
            PersistentMessagingBinding::prepare(&mut writer, &hierarchy, &identities)?;
        let renamed = temp.path().join("messaging-run-renamed");
        std::fs::rename(&run_directory, &renamed)?;
        assert!(PersistentMessagingBinding::open(&renamed).is_err());
        assert!(binding.verify().is_err());
        Ok(())
    }

    #[test]
    fn missing_authenticated_state_is_refused_for_existing_descriptor() -> Result<()> {
        let (_temp, repo_path) = auth_repo();
        let hierarchy = hierarchy();
        let identities = launched_identities();
        let (mut writer, run_directory) =
            reserve_writer(&repo_path, "messaging-persist-missing-state");
        let (binding, _) =
            PersistentMessagingBinding::prepare(&mut writer, &hierarchy, &identities)?;
        let state_dir = binding
            .store_path()?
            .parent()
            .expect("state parent")
            .to_path_buf();
        drop(binding);
        std::fs::remove_dir_all(state_dir)?;
        assert!(PersistentMessagingBinding::open(&run_directory).is_err());
        Ok(())
    }

    #[test]
    fn unsigned_descriptor_file_is_refused() -> Result<()> {
        let (_temp, repo_path) = auth_repo();
        let hierarchy = hierarchy();
        let identities = launched_identities();
        let (mut writer, run_directory) = reserve_writer(&repo_path, "messaging-persist-unsigned");
        PersistentMessagingBinding::prepare(&mut writer, &hierarchy, &identities)?;
        let path = run_directory.join(PersistentMessagingBinding::DESCRIPTOR_NAME);
        let value = json!({
            "version": 1,
            "repository": {},
            "run_directory_identity": {"device": 0, "file": 0},
            "run_directory_path_sha256": "0".repeat(64),
            "state_instance_id": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "state_directory_identity": {"device": 0, "file": 0},
            "hierarchy": {
                "edges": {},
                "effective_categories": {},
                "gate_owners": {},
                "gate_history": [],
                "role_transitions": []
            },
            "identities": {},
            "limits": MessagingLimits::default(),
            "mac": AuthenticationTag::zero().as_str()
        });
        std::fs::write(path, serde_json::to_vec(&value)?)?;
        assert!(PersistentMessagingBinding::open(&run_directory).is_err());
        Ok(())
    }

    #[test]
    fn replaced_repository_authentication_key_is_refused() -> Result<()> {
        let (_temp, repo_path) = auth_repo();
        let hierarchy = hierarchy();
        let identities = launched_identities();
        let (mut writer, run_directory) =
            reserve_writer(&repo_path, "messaging-persist-replaced-key");
        let (binding, _) =
            PersistentMessagingBinding::prepare(&mut writer, &hierarchy, &identities)?;
        let repo = crate::git_repository::discover(&repo_path).expect("discover repo");
        let key_path = repo
            .commondir()
            .join("maco")
            .join("state")
            .join(authentication_key_file_name());
        std::fs::write(key_path, vec![0_u8; authentication_key_length()])?;
        assert!(binding.verify().is_err());
        assert!(PersistentMessagingBinding::open(&run_directory).is_err());
        Ok(())
    }

    #[test]
    fn preexisting_unadmitted_state_is_refused_without_descriptor() -> Result<()> {
        let (_temp, repo_path) = auth_repo();
        let hierarchy = hierarchy();
        let identities = launched_identities();
        let (mut writer, run_directory) =
            reserve_writer(&repo_path, "messaging-persist-orphan-state");
        let repo = discover_repo_root(writer.run_dir())?;
        let authenticator = repository_auth_writer(&repo)?
            .into_authenticator()
            .expect("authenticator");
        let run_root = SafeRoot::open_existing(writer.run_dir())?;
        let state_instance_id = derive_state_instance_id(&authenticator, &run_root)?;
        let (_state_instance, root_lock) =
            reserve_fresh_state_instance(&authenticator, &state_instance_id)?;
        assert!(
            !run_directory
                .join(PersistentMessagingBinding::DESCRIPTOR_NAME)
                .exists(),
            "orphan reservation must not create a session descriptor"
        );
        let git = crate::git_repository::discover(&repo_path).expect("discover repo");
        let orphan_journal = git
            .commondir()
            .join("maco")
            .join("state")
            .join(MESSAGING_STATE_NAMESPACE)
            .join(&state_instance_id)
            .join(MESSAGING_STORE_NAME);
        assert!(!orphan_journal.exists());
        drop(root_lock);
        assert!(PersistentMessagingBinding::prepare(&mut writer, &hierarchy, &identities).is_err());
        Ok(())
    }

    #[test]
    fn missing_repository_key_refuses_when_messaging_namespace_exists() -> Result<()> {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        Repository::init(&repo_path).expect("init repo");
        let repo = crate::git_repository::discover(&repo_path).expect("discover repo");
        let common = repo.commondir();
        let state_root = common.join("maco").join("state");
        std::fs::create_dir_all(state_root.join(MESSAGING_STATE_NAMESPACE))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&state_root, std::fs::Permissions::from_mode(0o700))?;
            std::fs::set_permissions(
                state_root.join(MESSAGING_STATE_NAMESPACE),
                std::fs::Permissions::from_mode(0o700),
            )?;
        }
        assert!(repository_auth_writer(&repo_path).is_err());
        Ok(())
    }
}
