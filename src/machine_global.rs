//! Claims and recoverable retention for explicitly declared machine-global roots.
//!
//! Absolute host paths enter this module only through a strict, reviewable configuration file.
//! Persisted claims, operation reports, and gate denials use [`DeclaredPathCoordinate`] instead.

use crate::{
    artifacts::state_auth::{random_identifier, sha256_hex},
    gate_denial::{CorrectionCorrelationId, GateDenial},
    protected_path::{DeclaredPathCoordinate, ProtectedPathSpec, SandboxDenialRetryability},
    safe_state::{
        identity_for_path, quarantine_direct_child_directory,
        quarantined_direct_child_cleanup_name, remove_quarantined_direct_child_tree,
        restore_quarantined_direct_child_directory, stable_checksum, AtomicStateWriter,
        BoundedRegularReader, FileIdentity, KernelStateLock, SafeRoot, TreeLinkPolicy,
    },
    worktree::normalize_agent_id,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs,
    path::{Component, Path, PathBuf},
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};

const CONFIG_VERSION: u32 = 1;
const STATE_VERSION: u32 = 1;
const CONFIG_MAX_BYTES: u64 = 1024 * 1024;
const STATE_MAX_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ROOTS: usize = 128;
const MAX_PROTECTED_PATHS_PER_ROOT: usize = 4096;
const MAX_TARGETS_PER_OPERATION: usize = 4096;
const MAX_ACTIVE_CLAIMS: usize = 65_536;
const MAX_RETENTION_OPERATIONS: usize = 65_536;
const MAX_GRACE_SECONDS: u64 = 31 * 24 * 60 * 60;
const STATE_FILE: &str = "machine-global-state-v1.json";
const LOCK_FILE: &str = "machine-global-state-v1.lock";

/// Strict configuration for the shared claim and retention domain.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MachineGlobalConfig {
    pub version: u32,
    pub state_root: PathBuf,
    pub roots: Vec<DeclaredGlobalRootConfig>,
}

/// One reviewed machine-global root and its shared protected-path policy.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredGlobalRootConfig {
    pub id: String,
    pub path: PathBuf,
    pub protected_paths: Vec<ProtectedPathSpec>,
    pub quarantine_grace_seconds: u64,
}

/// Explicit caller binding for one cooperative machine-global retention path.
///
/// This is deliberately configuration-bound rather than inferred from an
/// absolute target. Callers that cannot supply this binding must either refuse
/// destructive work or identify their operation as a known bypass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineGlobalRetentionBinding {
    pub config: PathBuf,
    pub root_id: String,
    pub owner: String,
    pub correction_correlation_id: String,
}

/// Returns the exact no-follow content and inode binding used to retain a
/// machine-global configuration across a generated follow-up round.
pub(crate) fn machine_global_config_content_binding(
    path: &Path,
) -> Result<(String, FileIdentity)> {
    let config_path = require_exact_canonical_regular_file(path)
        .context("machine-global config path is not exact and canonical")?;
    let before = identity_for_path(&config_path)?;
    let bytes = BoundedRegularReader::read_tree_no_follow_validated(
        &config_path,
        CONFIG_MAX_BYTES,
        validate_machine_global_config_metadata,
    )?;
    let after = identity_for_path(&config_path)?;
    if before != after {
        bail!("machine-global config identity changed while binding its contents");
    }
    Ok((sha256_hex(&bytes), after))
}

/// A gate operation either completed or was refused through the typed Issue 29 envelope.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "outcome", content = "value", rename_all = "snake_case")]
pub enum GateOutcome<T> {
    Allowed(T),
    Denied(GateDenial),
}

/// Opaque durable token for one machine-global claim.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(transparent)]
pub struct MachineGlobalClaimToken(String);

impl MachineGlobalClaimToken {
    pub fn new(value: impl AsRef<str>) -> Result<Self> {
        validate_bearer_token(value.as_ref(), "machine-global claim token")?;
        Ok(Self(value.as_ref().to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for MachineGlobalClaimToken {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::new(value)
    }
}

/// Public, auditable identity for one retention operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(transparent)]
pub struct RetentionOperationId(u64);

impl RetentionOperationId {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            bail!("retention operation id must be nonzero");
        }
        Ok(Self(value))
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

impl FromStr for RetentionOperationId {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::new(
            value
                .parse::<u64>()
                .context("retention operation id must be an unsigned integer")?,
        )
    }
}

/// Secret bearer capability required only for irreversible purge.
///
/// Restore deliberately uses the public audit id so a crash after the durable rename but before
/// command output cannot strand recoverable data. Restore still performs the complete current
/// claim, protected-path, reservation, identity, and no-replace preflight.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(transparent)]
pub struct RetentionOperationToken(String);

impl RetentionOperationToken {
    pub fn new(value: impl AsRef<str>) -> Result<Self> {
        validate_bearer_token(value.as_ref(), "retention operation token")?;
        Ok(Self(value.as_ref().to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for RetentionOperationToken {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::new(value)
    }
}

/// Public claim state. It contains no configured absolute host path.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MachineGlobalClaim {
    pub token: MachineGlobalClaimToken,
    pub owner: String,
    pub targets: Vec<DeclaredPathCoordinate>,
}

/// Redacted claim view used by status and ownership queries.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MachineGlobalClaimSummary {
    pub owner: String,
    pub targets: Vec<DeclaredPathCoordinate>,
}

/// A target supplied to destructive preflight.
///
/// Undeclared absolute paths exist only transiently to construct a typed denial. They are never
/// admitted to state or converted into a declared coordinate.
#[derive(Debug, Clone)]
pub enum DestructiveTargetInput {
    Declared(DeclaredPathCoordinate),
    UndeclaredAbsolute(PathBuf),
}

/// Durable phase of a recoverable retention target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionTargetState {
    Planned,
    Quarantined,
    Restored,
    Purged,
}

/// Public retention target state. `quarantine_name` is a sibling basename, never an absolute path.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionTarget {
    pub coordinate: DeclaredPathCoordinate,
    pub quarantine_name: String,
    pub cleanup_name: String,
    pub identity: FileIdentity,
    pub state: RetentionTargetState,
}

/// Auditable, recoverable retention operation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionOperation {
    pub id: RetentionOperationId,
    pub token: RetentionOperationToken,
    pub owner: String,
    pub created_at_epoch_seconds: u64,
    pub purge_after_epoch_seconds: u64,
    pub targets: Vec<RetentionTarget>,
}

/// Redacted retention view. The bearer operation token is replaced by a non-authorizing digest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionOperationSummary {
    pub id: RetentionOperationId,
    pub owner: String,
    pub created_at_epoch_seconds: u64,
    pub purge_after_epoch_seconds: u64,
    pub targets: Vec<RetentionTarget>,
}

/// Privacy-safe snapshot of the complete shared state.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MachineGlobalStatus {
    pub claims: Vec<MachineGlobalClaimSummary>,
    pub retention_operations: Vec<RetentionOperationSummary>,
}

#[derive(Debug)]
struct ValidatedRoot {
    safe: SafeRoot,
    mount_id: u64,
    protected_paths: Vec<ProtectedPathSpec>,
    quarantine_grace_seconds: u64,
}

#[derive(Debug, Clone)]
struct PhysicalRootBinding {
    label: String,
    path: PathBuf,
    identity: FileIdentity,
    mount_id: u64,
}

/// Shared store. Independent repositories coordinate when they open the same configured state root.
#[derive(Debug)]
pub struct MachineGlobalStore {
    state_root: SafeRoot,
    state_root_mount_id: u64,
    roots: BTreeMap<String, ValidatedRoot>,
    config_fingerprint: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StatePayload {
    config_fingerprint: String,
    root_identities: BTreeMap<String, FileIdentity>,
    next_operation_id: u64,
    claims: BTreeMap<MachineGlobalClaimToken, MachineGlobalClaim>,
    retention_operations: BTreeMap<RetentionOperationId, RetentionOperation>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StateEnvelope {
    version: u32,
    checksum: String,
    payload: StatePayload,
}

impl StatePayload {
    fn empty(config_fingerprint: String, roots: &BTreeMap<String, ValidatedRoot>) -> StatePayload {
        Self {
            config_fingerprint,
            root_identities: roots
                .iter()
                .map(|(id, root)| (id.clone(), root.safe.identity().clone()))
                .collect(),
            next_operation_id: 1,
            claims: BTreeMap::new(),
            retention_operations: BTreeMap::new(),
        }
    }
}

impl MachineGlobalStore {
    /// Opens a bounded, no-follow JSON config and validates every absolute spelling and root.
    pub fn open_config(path: impl AsRef<Path>) -> Result<Self> {
        let config_path = require_exact_canonical_regular_file(path.as_ref())
            .context("machine-global config path is not exact and canonical")?;
        let bytes = BoundedRegularReader::read_tree_no_follow_validated(
            &config_path,
            CONFIG_MAX_BYTES,
            validate_machine_global_config_metadata,
        )
        .with_context(|| {
            format!(
                "failed to read machine-global config {}",
                config_path.display()
            )
        })?;
        let config: MachineGlobalConfig =
            serde_json::from_slice(&bytes).context("machine-global config is invalid JSON")?;
        if config.version != CONFIG_VERSION {
            bail!(
                "unsupported machine-global config version {}",
                config.version
            );
        }
        if config.roots.is_empty() || config.roots.len() > MAX_ROOTS {
            bail!("machine-global config must declare between 1 and {MAX_ROOTS} roots");
        }

        let state_root_path = require_exact_canonical_directory(&config.state_root)
            .context("machine-global state_root is not an exact canonical directory")?;
        let state_root = SafeRoot::open_or_create(&state_root_path)
            .context("machine-global state_root must be owner-private")?;
        let state_root_mount_id = state_root
            .linux_mount_id()
            .context("machine-global state_root mount identity is unavailable")?;

        let mut roots = BTreeMap::new();
        let mut physical_bindings = vec![PhysicalRootBinding {
            label: "state_root".to_string(),
            path: state_root_path,
            identity: state_root.identity().clone(),
            mount_id: state_root_mount_id,
        }];
        for configured in &config.roots {
            let canonical =
                require_exact_canonical_directory(&configured.path).with_context(|| {
                    format!(
                        "declared machine-global root {} is not exact and canonical",
                        configured.id
                    )
                })?;
            let safe = SafeRoot::open_existing(&canonical).with_context(|| {
                format!("declared machine-global root {} is unsafe", configured.id)
            })?;
            let mount_id = safe.linux_mount_id().with_context(|| {
                format!(
                    "declared machine-global root {} mount identity is unavailable",
                    configured.id
                )
            })?;
            if configured.quarantine_grace_seconds == 0
                || configured.quarantine_grace_seconds > MAX_GRACE_SECONDS
            {
                bail!(
                    "root {} quarantine grace must be between 1 and {MAX_GRACE_SECONDS} seconds",
                    configured.id
                );
            }
            if configured.protected_paths.len() > MAX_PROTECTED_PATHS_PER_ROOT {
                bail!("root {} exceeds the protected-path limit", configured.id);
            }
            for protected in &configured.protected_paths {
                protected.validate().with_context(|| {
                    format!("root {} contains an invalid protected path", configured.id)
                })?;
                if protected.coordinate().root_id() != configured.id {
                    bail!(
                        "protected path root id {} does not match enclosing root {}",
                        protected.coordinate().root_id(),
                        configured.id
                    );
                }
            }
            let id_probe = DeclaredPathCoordinate::new(&configured.id, "__config_validation__")
                .with_context(|| format!("declared root id {} is invalid", configured.id))?;
            if id_probe.root_id() != configured.id {
                bail!("declared root id is not canonical");
            }
            if roots
                .insert(
                    configured.id.clone(),
                    ValidatedRoot {
                        mount_id,
                        safe,
                        protected_paths: configured.protected_paths.clone(),
                        quarantine_grace_seconds: configured.quarantine_grace_seconds,
                    },
                )
                .is_some()
            {
                bail!("duplicate declared root id {}", configured.id);
            }
            let root = roots
                .get(&configured.id)
                .context("inserted declared root disappeared")?;
            physical_bindings.push(PhysicalRootBinding {
                label: format!("declared root {}", configured.id),
                path: canonical,
                identity: root.safe.identity().clone(),
                mount_id,
            });
        }
        validate_configured_physical_bindings(&physical_bindings)?;

        let config_fingerprint = stable_checksum(&bytes);
        Ok(Self {
            state_root,
            state_root_mount_id,
            roots,
            config_fingerprint,
        })
    }

    /// Resolves one already-existing directory beneath a reviewed root into the
    /// privacy-safe coordinate used by claims and destructive preflight.
    ///
    /// Callers must still supply the exact config and reviewed root id. This
    /// helper does not discover configs or reinterpret arbitrary absolute paths.
    pub fn coordinate_for_existing_directory(
        &self,
        root_id: impl AsRef<str>,
        path: impl AsRef<Path>,
    ) -> Result<DeclaredPathCoordinate> {
        let root_id = root_id.as_ref();
        let root = self
            .roots
            .get(root_id)
            .with_context(|| format!("undeclared machine-global root {root_id}"))?;
        root.safe.verify_linux_mount_id(root.mount_id)?;

        let path = path.as_ref();
        if !path.is_absolute() {
            bail!("machine-global directory path must be absolute");
        }
        let canonical =
            fs::canonicalize(path).context("failed to canonicalize machine-global directory")?;
        if canonical != path {
            bail!("machine-global directory path is not exact and canonical");
        }
        let relative = path.strip_prefix(root.safe.path()).with_context(|| {
            format!("machine-global directory is outside reviewed root {root_id}")
        })?;
        let coordinate = DeclaredPathCoordinate::new(root_id, relative)
            .context("machine-global directory is the root itself or has an invalid coordinate")?;
        self.validate_coordinate(&coordinate, true)?;
        root.safe.verify_linux_mount_id(root.mount_id)?;
        Ok(coordinate)
    }

    /// Acquires all declared targets atomically against the shared cross-repository state.
    pub fn claim(
        &self,
        owner: impl AsRef<str>,
        correction_correlation_id: impl AsRef<str>,
        targets: Vec<DeclaredPathCoordinate>,
    ) -> Result<GateOutcome<MachineGlobalClaim>> {
        let owner =
            validate_owner_and_correlation(owner.as_ref(), correction_correlation_id.as_ref())?;
        let targets = self.validate_declared_target_set(targets, false)?;
        let lock = self.acquire_lock()?;
        let mut state = self.load_state(&lock)?;
        for claim in state.claims.values() {
            if let Some(conflict) = first_intersection(&targets, &claim.targets) {
                let denial = GateDenial::from_machine_global_claim_conflict(
                    correction_correlation_id,
                    &owner,
                    conflict,
                )
                .context("failed to construct machine-global claim denial")?;
                return Ok(GateOutcome::Denied(denial));
            }
        }
        for reservation in state
            .retention_operations
            .values()
            .flat_map(operation_reserved_coordinates)
        {
            if targets.iter().any(|target| target.intersects(&reservation)) {
                let denial = GateDenial::from_machine_global_claim_conflict(
                    correction_correlation_id,
                    &owner,
                    &reservation,
                )
                .context("failed to construct retention-reservation claim denial")?;
                return Ok(GateOutcome::Denied(denial));
            }
        }
        if state.claims.len() >= MAX_ACTIVE_CLAIMS {
            bail!("machine-global active-claim limit reached");
        }
        let token = MachineGlobalClaimToken::new(random_identifier()?)?;
        let claim = MachineGlobalClaim {
            token: token.clone(),
            owner,
            targets,
        };
        if state.claims.insert(token, claim.clone()).is_some() {
            bail!("claim token unexpectedly replaced durable state");
        }
        self.write_state(&lock, &state)?;
        Ok(GateOutcome::Allowed(claim))
    }

    /// Releases a claim token. Missing tokens are accepted idempotently.
    pub fn release(&self, owner: impl AsRef<str>, token: MachineGlobalClaimToken) -> Result<bool> {
        let owner =
            normalize_agent_id(owner.as_ref()).context("machine-global owner is invalid")?;
        let lock = self.acquire_lock()?;
        let mut state = self.load_state(&lock)?;
        if let Some(claim) = state.claims.get(&token) {
            if claim.owner != owner {
                bail!("claim token is owned by a different agent");
            }
        }
        let removed = state.claims.remove(&token).is_some();
        if removed {
            self.write_state(&lock, &state)?;
        }
        Ok(removed)
    }

    /// Returns all claims intersecting one declared coordinate.
    pub fn owner(&self, target: &DeclaredPathCoordinate) -> Result<Vec<MachineGlobalClaimSummary>> {
        self.validate_coordinate(target, false)?;
        let lock = self.acquire_lock()?;
        let state = self.load_state(&lock)?;
        Ok(state
            .claims
            .values()
            .filter(|claim| {
                claim
                    .targets
                    .iter()
                    .any(|claimed| claimed.intersects(target))
            })
            .map(claim_summary)
            .collect())
    }

    /// Returns a complete privacy-safe status snapshot.
    pub fn status(&self) -> Result<MachineGlobalStatus> {
        let lock = self.acquire_lock()?;
        let state = self.load_state(&lock)?;
        Ok(MachineGlobalStatus {
            claims: state.claims.values().map(claim_summary).collect(),
            retention_operations: state
                .retention_operations
                .values()
                .map(retention_summary)
                .collect(),
        })
    }

    /// Checks the complete declared target set before performing the first quarantine rename.
    pub fn quarantine(
        &self,
        owner: impl AsRef<str>,
        correction_correlation_id: impl AsRef<str>,
        targets: Vec<DestructiveTargetInput>,
    ) -> Result<GateOutcome<RetentionOperation>> {
        self.quarantine_at(
            owner,
            correction_correlation_id,
            targets,
            trusted_now_epoch_seconds()?,
        )
    }

    fn quarantine_at(
        &self,
        owner: impl AsRef<str>,
        correction_correlation_id: impl AsRef<str>,
        targets: Vec<DestructiveTargetInput>,
        now_epoch_seconds: u64,
    ) -> Result<GateOutcome<RetentionOperation>> {
        let owner =
            validate_owner_and_correlation(owner.as_ref(), correction_correlation_id.as_ref())?;
        if targets.is_empty() || targets.len() > MAX_TARGETS_PER_OPERATION {
            bail!(
                "retention target set must contain between 1 and {MAX_TARGETS_PER_OPERATION} paths"
            );
        }
        let mut declared = Vec::with_capacity(targets.len());
        for target in targets {
            match target {
                DestructiveTargetInput::Declared(coordinate) => declared.push(coordinate),
                DestructiveTargetInput::UndeclaredAbsolute(path) => {
                    let denial = GateDenial::from_undeclared_destructive_target(
                        correction_correlation_id,
                        &owner,
                        &path,
                    )
                    .context("failed to construct undeclared-target denial")?;
                    return Ok(GateOutcome::Denied(denial));
                }
            }
        }
        let declared = self.validate_declared_target_set(declared, true)?;
        let lock = self.acquire_lock()?;
        let mut state = self.load_state(&lock)?;

        if state.retention_operations.len() >= MAX_RETENTION_OPERATIONS {
            bail!("machine-global retention-operation limit reached");
        }

        let operation_id = RetentionOperationId::new(state.next_operation_id)?;
        let mut purge_after = now_epoch_seconds;
        let mut operation_targets = Vec::with_capacity(declared.len());
        let mut prepared_targets = Vec::with_capacity(declared.len());
        for coordinate in declared {
            let prepared = self.prepare_existing_directory(&coordinate)?;
            let grace = self
                .roots
                .get(coordinate.root_id())
                .context("validated root disappeared")?
                .quarantine_grace_seconds;
            purge_after = purge_after.max(
                now_epoch_seconds
                    .checked_add(grace)
                    .context("quarantine grace timestamp overflow")?,
            );
            let quarantine_name = quarantine_name(operation_id, &coordinate);
            let cleanup_name =
                quarantined_direct_child_cleanup_name(&quarantine_name, &prepared.identity)?
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("derived cleanup name is not valid UTF-8"))?;
            prepared
                .parent
                .ensure_direct_child_absent(&quarantine_name)
                .context("quarantine destination is unavailable")?;
            prepared
                .parent
                .ensure_direct_child_absent(&cleanup_name)
                .context("quarantine cleanup destination is unavailable")?;
            operation_targets.push(RetentionTarget {
                quarantine_name,
                cleanup_name,
                coordinate,
                identity: prepared.identity.clone(),
                state: RetentionTargetState::Planned,
            });
            prepared_targets.push(prepared);
        }
        let mut operation = RetentionOperation {
            id: operation_id,
            token: RetentionOperationToken::new(random_identifier()?)?,
            owner,
            created_at_epoch_seconds: now_epoch_seconds,
            purge_after_epoch_seconds: purge_after,
            targets: operation_targets,
        };
        let mutation_coordinates = operation_mutation_coordinates(&operation)?;
        validate_disjoint_coordinates(
            &mutation_coordinates,
            "retention source and quarantine coordinate",
        )?;
        if let Some(denial) = self.destructive_intersection_denial(
            &state,
            &operation.owner,
            correction_correlation_id.as_ref(),
            &mutation_coordinates,
            None,
        )? {
            return Ok(GateOutcome::Denied(denial));
        }
        let allocated = RetentionOperationId::new(take_next_id(&mut state.next_operation_id)?)?;
        if allocated != operation_id {
            bail!("retention operation allocation changed during locked preflight");
        }
        if state
            .retention_operations
            .insert(operation_id, operation.clone())
            .is_some()
        {
            bail!("retention operation id unexpectedly replaced durable state");
        }
        self.write_state(&lock, &state)?;

        run_after_retention_preflight_hook();
        for (index, prepared) in prepared_targets.iter().enumerate() {
            let target = operation
                .targets
                .get(index)
                .context("retention target index disappeared")?
                .clone();
            prepared.parent.verify_linux_mount_id(prepared.mount_id)?;
            quarantine_direct_child_directory(
                &prepared.parent,
                &prepared.child,
                &target.quarantine_name,
                &target.identity,
            )
            .with_context(|| {
                format!(
                    "failed closed while quarantining {}:{}",
                    target.coordinate.root_id(),
                    target.coordinate.relative().display()
                )
            })?;
            if let Some(record) = operation.targets.get_mut(index) {
                record.state = RetentionTargetState::Quarantined;
            }
            state
                .retention_operations
                .insert(operation_id, operation.clone());
            self.write_state(&lock, &state)?;
        }
        Ok(GateOutcome::Allowed(operation))
    }

    /// Restores every non-purged target to its original coordinate using no-replace renames.
    pub fn restore(
        &self,
        owner: impl AsRef<str>,
        correction_correlation_id: impl AsRef<str>,
        operation_id: RetentionOperationId,
    ) -> Result<GateOutcome<RetentionOperation>> {
        let owner =
            validate_owner_and_correlation(owner.as_ref(), correction_correlation_id.as_ref())?;
        let lock = self.acquire_lock()?;
        let mut state = self.load_state(&lock)?;
        let mut operation = state
            .retention_operations
            .get(&operation_id)
            .cloned()
            .context("unknown retention operation")?;
        if operation.owner != owner {
            bail!("retention operation is owned by a different agent");
        }
        if operation
            .targets
            .iter()
            .any(|target| target.state == RetentionTargetState::Purged)
        {
            bail!("purged retention operation cannot be restored");
        }
        let mutation_coordinates = operation_mutation_coordinates(&operation)?;
        if let Some(denial) = self.destructive_intersection_denial(
            &state,
            &owner,
            correction_correlation_id.as_ref(),
            &mutation_coordinates,
            Some(operation_id),
        )? {
            return Ok(GateOutcome::Denied(denial));
        }
        let accesses = self.bind_operation_parents(&operation)?;
        run_before_recovery_mutation_hook();
        for (index, access) in accesses.iter().enumerate() {
            let target = operation
                .targets
                .get(index)
                .context("retention target index disappeared")?
                .clone();
            if target.state == RetentionTargetState::Restored {
                continue;
            }
            access.parent.verify_linux_mount_id(access.mount_id)?;
            restore_quarantined_direct_child_directory(
                &access.parent,
                &access.child,
                &target.quarantine_name,
                &target.identity,
            )
            .with_context(|| {
                format!(
                    "failed closed while restoring {}:{}",
                    target.coordinate.root_id(),
                    target.coordinate.relative().display()
                )
            })?;
            if let Some(record) = operation.targets.get_mut(index) {
                record.state = RetentionTargetState::Restored;
            }
            state
                .retention_operations
                .insert(operation_id, operation.clone());
            self.write_state(&lock, &state)?;
        }
        Ok(GateOutcome::Allowed(operation))
    }

    /// Permanently removes quarantined trees only after grace and a fresh full preflight.
    pub fn purge(
        &self,
        owner: impl AsRef<str>,
        correction_correlation_id: impl AsRef<str>,
        operation_id: RetentionOperationId,
        operation_token: &RetentionOperationToken,
    ) -> Result<GateOutcome<RetentionOperation>> {
        self.purge_at(
            owner,
            correction_correlation_id,
            operation_id,
            operation_token,
            trusted_now_epoch_seconds()?,
        )
    }

    fn purge_at(
        &self,
        owner: impl AsRef<str>,
        correction_correlation_id: impl AsRef<str>,
        operation_id: RetentionOperationId,
        operation_token: &RetentionOperationToken,
        now_epoch_seconds: u64,
    ) -> Result<GateOutcome<RetentionOperation>> {
        let owner =
            validate_owner_and_correlation(owner.as_ref(), correction_correlation_id.as_ref())?;
        let lock = self.acquire_lock()?;
        let mut state = self.load_state(&lock)?;
        let mut operation = state
            .retention_operations
            .get(&operation_id)
            .cloned()
            .context("unknown retention operation")?;
        if operation.owner != owner {
            bail!("retention operation is owned by a different agent");
        }
        if operation.token != *operation_token {
            bail!("retention operation token does not match");
        }
        if now_epoch_seconds < operation.purge_after_epoch_seconds {
            bail!(
                "retention grace has not elapsed; purge becomes eligible at {}",
                operation.purge_after_epoch_seconds
            );
        }
        if operation.targets.iter().any(|target| {
            !matches!(
                target.state,
                RetentionTargetState::Quarantined | RetentionTargetState::Purged
            )
        }) {
            bail!("retention operation is not fully quarantined; refusing purge");
        }
        let coordinates = operation_mutation_coordinates(&operation)?;
        if let Some(denial) = self.destructive_intersection_denial(
            &state,
            &owner,
            correction_correlation_id.as_ref(),
            &coordinates,
            Some(operation_id),
        )? {
            return Ok(GateOutcome::Denied(denial));
        }
        let accesses = self.bind_operation_parents(&operation)?;
        run_before_recovery_mutation_hook();
        for (index, access) in accesses.iter().enumerate() {
            let target = operation
                .targets
                .get(index)
                .context("retention target index disappeared")?
                .clone();
            if target.state == RetentionTargetState::Purged {
                continue;
            }
            access.parent.verify_linux_mount_id(access.mount_id)?;
            remove_quarantined_direct_child_tree(
                &access.parent,
                &target.quarantine_name,
                &target.identity,
                TreeLinkPolicy::RejectLinksAndSpecialFiles,
            )
            .with_context(|| {
                format!(
                    "failed closed while purging quarantine for {}:{}",
                    target.coordinate.root_id(),
                    target.coordinate.relative().display()
                )
            })?;
            if let Some(record) = operation.targets.get_mut(index) {
                record.state = RetentionTargetState::Purged;
            }
            state
                .retention_operations
                .insert(operation_id, operation.clone());
            self.write_state(&lock, &state)?;
        }
        Ok(GateOutcome::Allowed(operation))
    }

    fn acquire_lock(&self) -> Result<KernelStateLock> {
        self.state_root
            .verify_linux_mount_id(self.state_root_mount_id)?;
        let lock = KernelStateLock::acquire_direct(&self.state_root, LOCK_FILE)
            .context("failed to acquire machine-global kernel state lock")?;
        self.state_root
            .verify_linux_mount_id(self.state_root_mount_id)?;
        Ok(lock)
    }

    fn load_state(&self, lock: &KernelStateLock) -> Result<StatePayload> {
        lock.verify_direct_binding(&self.state_root)?;
        self.state_root
            .verify_linux_mount_id(self.state_root_mount_id)?;
        if !self.state_root.direct_child_exists(STATE_FILE)? {
            return Ok(StatePayload::empty(
                self.config_fingerprint.clone(),
                &self.roots,
            ));
        }
        let bytes =
            BoundedRegularReader::read_direct(&self.state_root, STATE_FILE, STATE_MAX_BYTES)?;
        let envelope: StateEnvelope =
            serde_json::from_slice(&bytes).context("machine-global state is invalid JSON")?;
        if envelope.version != STATE_VERSION {
            bail!("unsupported machine-global state version");
        }
        let payload_bytes = serde_json::to_vec(&envelope.payload)
            .context("failed to canonicalize state payload")?;
        if stable_checksum(&payload_bytes) != envelope.checksum {
            bail!("machine-global state checksum mismatch");
        }
        if envelope.payload.config_fingerprint != self.config_fingerprint {
            bail!("machine-global config changed; refusing to reinterpret durable state");
        }
        validate_loaded_state(
            &envelope.payload,
            &self.state_root,
            self.state_root_mount_id,
            &self.roots,
        )?;
        lock.verify_direct_binding(&self.state_root)?;
        Ok(envelope.payload)
    }

    fn write_state(&self, lock: &KernelStateLock, state: &StatePayload) -> Result<()> {
        validate_loaded_state(
            state,
            &self.state_root,
            self.state_root_mount_id,
            &self.roots,
        )?;
        lock.verify_direct_binding(&self.state_root)?;
        let payload_bytes =
            serde_json::to_vec(state).context("failed to serialize machine-global state")?;
        let envelope = StateEnvelope {
            version: STATE_VERSION,
            checksum: stable_checksum(&payload_bytes),
            payload: state.clone(),
        };
        let bytes =
            serde_json::to_vec_pretty(&envelope).context("failed to serialize state envelope")?;
        if bytes.len() as u64 > STATE_MAX_BYTES {
            bail!("machine-global state exceeds bounded size");
        }
        AtomicStateWriter::write_direct_fenced(&self.state_root, STATE_FILE, &bytes, || {
            lock.verify_direct_binding(&self.state_root)
        })
    }

    fn validate_declared_target_set(
        &self,
        mut targets: Vec<DeclaredPathCoordinate>,
        destructive: bool,
    ) -> Result<Vec<DeclaredPathCoordinate>> {
        if targets.is_empty() || targets.len() > MAX_TARGETS_PER_OPERATION {
            bail!("target set must contain between 1 and {MAX_TARGETS_PER_OPERATION} coordinates");
        }
        targets.sort();
        for target in &targets {
            self.validate_coordinate(target, destructive)?;
        }
        for pair in targets.windows(2) {
            if pair[0].intersects(&pair[1]) {
                bail!("target set contains duplicate or intersecting coordinates");
            }
        }
        Ok(targets)
    }

    fn validate_coordinate(
        &self,
        coordinate: &DeclaredPathCoordinate,
        require_existing_directory: bool,
    ) -> Result<()> {
        coordinate
            .validate()
            .context("invalid declared coordinate")?;
        let root = self
            .roots
            .get(coordinate.root_id())
            .with_context(|| format!("undeclared machine-global root {}", coordinate.root_id()))?;
        root.safe.verify_linux_mount_id(root.mount_id)?;
        let parent = self.open_coordinate_parent(coordinate)?;
        let child = coordinate_basename(coordinate)?;
        let absolute = parent.direct_child(child)?;
        let initial_mount = parent.direct_child_linux_mount_id(child)?;
        match fs::symlink_metadata(&absolute) {
            Ok(metadata) => {
                let observed_mount =
                    initial_mount.context("existing declared coordinate has no mount identity")?;
                require_same_mount(root.mount_id, observed_mount, "declared coordinate leaf")?;
                if metadata.file_type().is_symlink() {
                    bail!(
                        "declared coordinate resolves through a symbolic link: {}:{}",
                        coordinate.root_id(),
                        coordinate.relative().display()
                    );
                }
                if require_existing_directory && !metadata.is_dir() {
                    bail!("destructive retention targets must be existing directories");
                }
                let canonical = fs::canonicalize(&absolute).with_context(|| {
                    format!(
                        "failed to canonicalize declared coordinate {}",
                        absolute.display()
                    )
                })?;
                if canonical != absolute {
                    bail!("declared coordinate is not canonically spelled");
                }
                let rebound_mount = parent
                    .direct_child_linux_mount_id(child)?
                    .context("declared coordinate disappeared during mount validation")?;
                require_same_mount(
                    root.mount_id,
                    rebound_mount,
                    "rebound declared coordinate leaf",
                )?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if initial_mount.is_some() || parent.direct_child_linux_mount_id(child)?.is_some() {
                    bail!("declared coordinate appeared or disappeared during mount validation");
                }
                if require_existing_directory {
                    bail!("destructive retention target does not exist");
                }
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect declared coordinate {}",
                        absolute.display()
                    )
                });
            }
        }
        Ok(())
    }

    fn prepare_existing_directory(
        &self,
        coordinate: &DeclaredPathCoordinate,
    ) -> Result<PreparedTarget> {
        self.validate_coordinate(coordinate, true)?;
        let parent = self.open_coordinate_parent(coordinate)?;
        let child = coordinate_basename(coordinate)?;
        let absolute = parent.direct_child(child)?;
        let identity = identity_for_path(&absolute)?;
        let mount_id = self
            .roots
            .get(coordinate.root_id())
            .context("validated root disappeared")?
            .mount_id;
        Ok(PreparedTarget {
            parent,
            child: child.to_os_string(),
            identity,
            mount_id,
        })
    }

    fn bind_operation_parents(
        &self,
        operation: &RetentionOperation,
    ) -> Result<Vec<PreparedAccess>> {
        operation
            .targets
            .iter()
            .map(|target| {
                let parent = self.open_coordinate_parent(&target.coordinate)?;
                let child = coordinate_basename(&target.coordinate)?.to_os_string();
                let mount_id = self
                    .roots
                    .get(target.coordinate.root_id())
                    .context("validated root disappeared")?
                    .mount_id;
                Ok(PreparedAccess {
                    parent,
                    child,
                    mount_id,
                })
            })
            .collect()
    }

    fn open_coordinate_parent(&self, coordinate: &DeclaredPathCoordinate) -> Result<SafeRoot> {
        let root = self
            .roots
            .get(coordinate.root_id())
            .with_context(|| format!("undeclared machine-global root {}", coordinate.root_id()))?;
        let parent_relative = coordinate
            .relative()
            .parent()
            .context("declared coordinate must contain a basename")?;
        root.safe.verify_linux_mount_id(root.mount_id)?;
        if parent_relative.as_os_str().is_empty() {
            root.safe.verify_linux_mount_id(root.mount_id)?;
            return Ok(root.safe.clone());
        }
        let parent =
            SafeRoot::open_existing(root.safe.path().join(parent_relative)).with_context(|| {
                format!(
                    "declared coordinate parent is unsafe or non-canonical: {}:{}",
                    coordinate.root_id(),
                    parent_relative.display()
                )
            })?;
        root.safe.verify_linux_mount_id(root.mount_id)?;
        parent
            .verify_linux_mount_id(root.mount_id)
            .with_context(|| {
                format!(
                    "declared coordinate parent crosses root mount {}:{}",
                    coordinate.root_id(),
                    parent_relative.display()
                )
            })?;
        Ok(parent)
    }

    fn destructive_intersection_denial(
        &self,
        state: &StatePayload,
        owner: &str,
        correlation: &str,
        targets: &[DeclaredPathCoordinate],
        skip_operation: Option<RetentionOperationId>,
    ) -> Result<Option<GateDenial>> {
        for target in targets {
            for claim in state.claims.values() {
                if let Some(active) = claim
                    .targets
                    .iter()
                    .find(|active| active.intersects(target))
                {
                    return GateDenial::from_destructive_active_claim_intersection(
                        correlation,
                        owner,
                        target.clone(),
                        active.clone(),
                    )
                    .context("failed to construct active-claim intersection denial")
                    .map(Some);
                }
            }
            for reservation in state
                .retention_operations
                .values()
                .filter(|operation| Some(operation.id) != skip_operation)
                .flat_map(operation_reserved_coordinates)
            {
                if reservation.intersects(target) {
                    let protected = ProtectedPathSpec::new(
                        reservation,
                        SandboxDenialRetryability::NotRetryable,
                    );
                    return GateDenial::from_protected_path_intersection(
                        correlation,
                        owner,
                        target.clone(),
                        protected,
                    )
                    .context("failed to construct retention-reservation denial")
                    .map(Some);
                }
            }
            let root = self
                .roots
                .get(target.root_id())
                .context("validated root disappeared")?;
            if let Some(protected) = root
                .protected_paths
                .iter()
                .find(|protected| protected.intersects(target))
            {
                return GateDenial::from_protected_path_intersection(
                    correlation,
                    owner,
                    target.clone(),
                    protected.clone(),
                )
                .context("failed to construct protected-path intersection denial")
                .map(Some);
            }
        }
        Ok(None)
    }
}

#[derive(Debug)]
struct PreparedTarget {
    parent: SafeRoot,
    child: OsString,
    identity: FileIdentity,
    mount_id: u64,
}

#[derive(Debug)]
struct PreparedAccess {
    parent: SafeRoot,
    child: OsString,
    mount_id: u64,
}

fn validate_owner_and_correlation(owner: &str, correlation: &str) -> Result<String> {
    let owner = normalize_agent_id(owner).context("machine-global owner is invalid")?;
    CorrectionCorrelationId::new(correlation).context("correction correlation id is invalid")?;
    Ok(owner)
}

fn validate_loaded_state(
    state: &StatePayload,
    state_root: &SafeRoot,
    state_root_mount_id: u64,
    roots: &BTreeMap<String, ValidatedRoot>,
) -> Result<()> {
    state_root.verify_linux_mount_id(state_root_mount_id)?;
    if state.root_identities.len() != roots.len() {
        bail!("durable declared-root binding set does not match configuration");
    }
    for (id, root) in roots {
        root.safe.verify_linux_mount_id(root.mount_id)?;
        if state.root_identities.get(id) != Some(root.safe.identity()) {
            bail!("declared root identity changed for {id}");
        }
    }
    if state.next_operation_id == 0 {
        bail!("machine-global operation counter must be nonzero");
    }
    if state.claims.len() > MAX_ACTIVE_CLAIMS
        || state.retention_operations.len() > MAX_RETENTION_OPERATIONS
    {
        bail!("machine-global state exceeds collection bounds");
    }
    let mut claims_seen = Vec::new();
    for (token, claim) in &state.claims {
        validate_bearer_token(token.as_str(), "durable claim token")?;
        if *token != claim.token {
            bail!("machine-global claim key/token mismatch");
        }
        normalize_agent_id(&claim.owner).context("durable claim owner is invalid")?;
        if claim.targets.is_empty() || claim.targets.len() > MAX_TARGETS_PER_OPERATION {
            bail!("durable claim target set is out of bounds");
        }
        validate_sorted_disjoint(&claim.targets, "durable claim")?;
        for target in &claim.targets {
            target
                .validate()
                .context("durable claim coordinate is invalid")?;
            if !roots.contains_key(target.root_id()) {
                bail!("durable claim names an undeclared root");
            }
            if claims_seen
                .iter()
                .any(|seen: &DeclaredPathCoordinate| seen.intersects(target))
            {
                bail!("durable active claims intersect");
            }
            claims_seen.push(target.clone());
        }
    }
    let mut maximum_operation_id = 0_u64;
    let mut reservations = Vec::new();
    for (id, operation) in &state.retention_operations {
        if id.get() == 0 {
            bail!("retention operation map contains a zero id");
        }
        maximum_operation_id = maximum_operation_id.max(id.get());
        if *id != operation.id {
            bail!("retention operation key/id mismatch");
        }
        validate_bearer_token(
            operation.token.as_str(),
            "durable retention operation token",
        )?;
        normalize_agent_id(&operation.owner).context("retention owner is invalid")?;
        if operation.targets.is_empty() || operation.targets.len() > MAX_TARGETS_PER_OPERATION {
            bail!("durable retention target set is out of bounds");
        }
        validate_retention_phases(&operation.targets)?;
        let mut expected_purge_after = operation.created_at_epoch_seconds;
        let mut original_coordinates = Vec::with_capacity(operation.targets.len());
        for target in &operation.targets {
            target
                .coordinate
                .validate()
                .context("durable retention coordinate is invalid")?;
            let root = roots
                .get(target.coordinate.root_id())
                .context("durable retention target names an undeclared root")?;
            expected_purge_after = expected_purge_after.max(
                operation
                    .created_at_epoch_seconds
                    .checked_add(root.quarantine_grace_seconds)
                    .context("durable retention grace timestamp overflow")?,
            );
            validate_quarantine_name(&target.quarantine_name)?;
            if target.quarantine_name != quarantine_name(operation.id, &target.coordinate) {
                bail!("durable quarantine name does not match its operation and coordinate");
            }
            validate_cleanup_name(&target.cleanup_name)?;
            let expected_cleanup =
                quarantined_direct_child_cleanup_name(&target.quarantine_name, &target.identity)?
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("derived cleanup name is not valid UTF-8"))?;
            if target.cleanup_name != expected_cleanup {
                bail!("durable cleanup name does not match its quarantine and identity");
            }
            original_coordinates.push(target.coordinate.clone());
        }
        validate_sorted_disjoint(&original_coordinates, "durable retention operation")?;
        if operation.purge_after_epoch_seconds != expected_purge_after {
            bail!("retention operation has an invalid configured grace window");
        }
        let mutation_coordinates = operation_mutation_coordinates(operation)?;
        validate_disjoint_coordinates(
            &mutation_coordinates,
            "durable retention mutation coordinate",
        )?;
        for coordinate in operation_reserved_coordinates(operation) {
            if claims_seen
                .iter()
                .any(|claim| claim.intersects(&coordinate))
            {
                bail!("durable retention reservation intersects an active claim");
            }
            if reservations
                .iter()
                .any(|reserved: &DeclaredPathCoordinate| reserved.intersects(&coordinate))
            {
                bail!("durable retention reservations intersect");
            }
            reservations.push(coordinate);
        }
    }
    if state.next_operation_id <= maximum_operation_id {
        bail!("next retention operation id does not advance beyond durable operations");
    }
    Ok(())
}

fn validate_sorted_disjoint(coordinates: &[DeclaredPathCoordinate], label: &str) -> Result<()> {
    for pair in coordinates.windows(2) {
        if pair[0] >= pair[1] {
            bail!("{label} coordinates are not strictly sorted");
        }
        if pair[0].intersects(&pair[1]) {
            bail!("{label} coordinates intersect");
        }
    }
    Ok(())
}

fn validate_disjoint_coordinates(
    coordinates: &[DeclaredPathCoordinate],
    label: &str,
) -> Result<()> {
    for (index, left) in coordinates.iter().enumerate() {
        if coordinates
            .iter()
            .skip(index.saturating_add(1))
            .any(|right| left.intersects(right))
        {
            bail!("{label} set intersects");
        }
    }
    Ok(())
}

fn validate_retention_phases(targets: &[RetentionTarget]) -> Result<()> {
    let contains_purged = targets
        .iter()
        .any(|target| target.state == RetentionTargetState::Purged);
    let contains_restored = targets
        .iter()
        .any(|target| target.state == RetentionTargetState::Restored);
    if contains_purged && contains_restored {
        bail!("durable retention operation mixes purged and restored phases");
    }

    let rank = |state| {
        if contains_purged {
            match state {
                RetentionTargetState::Purged => Some(0_u8),
                RetentionTargetState::Quarantined => Some(1),
                RetentionTargetState::Planned | RetentionTargetState::Restored => None,
            }
        } else if contains_restored {
            match state {
                RetentionTargetState::Restored => Some(0),
                RetentionTargetState::Quarantined => Some(1),
                RetentionTargetState::Planned => Some(2),
                RetentionTargetState::Purged => None,
            }
        } else {
            match state {
                RetentionTargetState::Quarantined => Some(0),
                RetentionTargetState::Planned => Some(1),
                RetentionTargetState::Restored | RetentionTargetState::Purged => None,
            }
        }
    };
    let mut previous = 0_u8;
    for (index, target) in targets.iter().enumerate() {
        let current =
            rank(target.state).context("durable retention operation has an impossible phase")?;
        if index > 0 && current < previous {
            bail!("durable retention phases are not a valid resumable prefix");
        }
        previous = current;
    }
    Ok(())
}

fn take_next_id(next: &mut u64) -> Result<u64> {
    let current = *next;
    if current == 0 {
        bail!("durable identifier counter is invalid");
    }
    *next = current
        .checked_add(1)
        .context("durable identifier exhausted")?;
    Ok(current)
}

fn first_intersection<'a>(
    left: &'a [DeclaredPathCoordinate],
    right: &'a [DeclaredPathCoordinate],
) -> Option<&'a DeclaredPathCoordinate> {
    left.iter()
        .find(|candidate| right.iter().any(|other| candidate.intersects(other)))
}

fn claim_summary(claim: &MachineGlobalClaim) -> MachineGlobalClaimSummary {
    MachineGlobalClaimSummary {
        owner: claim.owner.clone(),
        targets: claim.targets.clone(),
    }
}

fn retention_summary(operation: &RetentionOperation) -> RetentionOperationSummary {
    RetentionOperationSummary {
        id: operation.id,
        owner: operation.owner.clone(),
        created_at_epoch_seconds: operation.created_at_epoch_seconds,
        purge_after_epoch_seconds: operation.purge_after_epoch_seconds,
        targets: operation.targets.clone(),
    }
}

fn operation_mutation_coordinates(
    operation: &RetentionOperation,
) -> Result<Vec<DeclaredPathCoordinate>> {
    let mut coordinates = Vec::with_capacity(operation.targets.len().saturating_mul(3));
    for target in &operation.targets {
        if matches!(
            target.state,
            RetentionTargetState::Restored | RetentionTargetState::Purged
        ) {
            continue;
        }
        coordinates.push(target.coordinate.clone());
        coordinates.push(quarantine_coordinate(target)?);
        coordinates.push(cleanup_coordinate(target)?);
    }
    Ok(coordinates)
}

fn operation_reserved_coordinates(
    operation: &RetentionOperation,
) -> impl Iterator<Item = DeclaredPathCoordinate> + '_ {
    operation.targets.iter().flat_map(|target| {
        if matches!(
            target.state,
            RetentionTargetState::Restored | RetentionTargetState::Purged
        ) {
            return Vec::new().into_iter();
        }
        let mut coordinates = vec![target.coordinate.clone()];
        if let Ok(quarantine) = quarantine_coordinate(target) {
            coordinates.push(quarantine);
        }
        if let Ok(cleanup) = cleanup_coordinate(target) {
            coordinates.push(cleanup);
        }
        coordinates.into_iter()
    })
}

fn quarantine_coordinate(target: &RetentionTarget) -> Result<DeclaredPathCoordinate> {
    let parent = target
        .coordinate
        .relative()
        .parent()
        .context("retention coordinate must contain a basename")?;
    DeclaredPathCoordinate::new(
        target.coordinate.root_id(),
        parent.join(&target.quarantine_name),
    )
    .context("derived quarantine coordinate is invalid")
}

fn cleanup_coordinate(target: &RetentionTarget) -> Result<DeclaredPathCoordinate> {
    let parent = target
        .coordinate
        .relative()
        .parent()
        .context("retention coordinate must contain a basename")?;
    DeclaredPathCoordinate::new(
        target.coordinate.root_id(),
        parent.join(&target.cleanup_name),
    )
    .context("derived cleanup coordinate is invalid")
}

fn coordinate_basename(coordinate: &DeclaredPathCoordinate) -> Result<&OsStr> {
    coordinate
        .relative()
        .file_name()
        .context("declared coordinate must contain a basename")
}

fn quarantine_name(
    operation_id: RetentionOperationId,
    coordinate: &DeclaredPathCoordinate,
) -> String {
    let fingerprint = stable_checksum(coordinate.relative().to_string_lossy().as_bytes());
    format!(
        ".maco-quarantine-v1-{:016x}-{}",
        operation_id.get(),
        fingerprint
    )
}

fn validate_bearer_token(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} must be 64 lowercase hexadecimal characters");
    }
    Ok(())
}

fn validate_quarantine_name(name: &str) -> Result<()> {
    if !name.starts_with(".maco-quarantine-v1-")
        || name.is_empty()
        || name.len() > 240
        || Path::new(name).components().count() != 1
    {
        bail!("durable quarantine sibling name is invalid");
    }
    Ok(())
}

fn validate_cleanup_name(name: &str) -> Result<()> {
    if !name.starts_with(".maco-delete-v2-")
        || name.is_empty()
        || name.len() > 240
        || Path::new(name).components().count() != 1
    {
        bail!("durable quarantine cleanup sibling name is invalid");
    }
    Ok(())
}

fn require_exact_canonical_directory(path: &Path) -> Result<PathBuf> {
    let canonical = require_exact_canonical_path(path)?;
    if !fs::symlink_metadata(&canonical)
        .with_context(|| format!("failed to inspect directory {}", canonical.display()))?
        .is_dir()
    {
        bail!("configured path is not a directory");
    }
    Ok(canonical)
}

fn require_exact_canonical_regular_file(path: &Path) -> Result<PathBuf> {
    let canonical = require_exact_canonical_path(path)?;
    let metadata = fs::symlink_metadata(&canonical)
        .with_context(|| format!("failed to inspect config {}", canonical.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("configured path is not a regular file");
    }
    #[cfg(unix)]
    {
        if metadata.uid() != unsafe { libc::geteuid() } {
            bail!("machine-global config must be owned by the current user");
        }
        if metadata.nlink() != 1 {
            bail!("machine-global config must have exactly one hard link");
        }
        if metadata.mode() & 0o022 != 0 {
            bail!("machine-global config must not be group- or world-writable");
        }
    }
    Ok(canonical)
}

#[cfg(unix)]
fn validate_machine_global_config_metadata(metadata: &fs::Metadata) -> Result<()> {
    if metadata.uid() != unsafe { libc::geteuid() } {
        bail!("machine-global config must be owned by the current user");
    }
    if metadata.nlink() != 1 {
        bail!("machine-global config must have exactly one hard link");
    }
    if metadata.mode() & 0o022 != 0 {
        bail!("machine-global config must not be group- or world-writable");
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_machine_global_config_metadata(_metadata: &fs::Metadata) -> Result<()> {
    bail!("machine-global config metadata policy is unsupported on this platform")
}

fn require_exact_canonical_path(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        bail!("path must be absolute");
    }
    if path
        .components()
        .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        bail!("path contains non-canonical lexical components");
    }
    let canonical = fs::canonicalize(path)
        .with_context(|| format!("failed to canonicalize directory {}", path.display()))?;
    #[cfg(unix)]
    let spelling_matches = canonical.as_os_str().as_bytes() == path.as_os_str().as_bytes();
    #[cfg(not(unix))]
    let spelling_matches = canonical == path;
    if !spelling_matches {
        bail!(
            "configured spelling {} differs from canonical path {}",
            path.display(),
            canonical.display()
        );
    }
    Ok(canonical)
}

fn paths_intersect(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn validate_configured_physical_bindings(bindings: &[PhysicalRootBinding]) -> Result<()> {
    for (index, left) in bindings.iter().enumerate() {
        for right in bindings.iter().skip(index.saturating_add(1)) {
            if paths_intersect(&left.path, &right.path) {
                bail!(
                    "{} and {} overlap by canonical path components",
                    left.label,
                    right.label
                );
            }
            if left.identity == right.identity {
                bail!(
                    "{} and {} resolve to the same filesystem object",
                    left.label,
                    right.label
                );
            }
            if left.mount_id == right.mount_id {
                if left.identity.device != right.identity.device {
                    bail!(
                        "{} and {} report one mount id with inconsistent devices",
                        left.label,
                        right.label
                    );
                }
            } else if left.identity.device == right.identity.device {
                bail!(
                    "{} and {} are ambiguous aliases on different mounts of device {}",
                    left.label,
                    right.label,
                    left.identity.device
                );
            }
        }
    }
    Ok(())
}

fn require_same_mount(expected: u64, observed: u64, label: &str) -> Result<()> {
    if expected != observed {
        bail!("{label} crosses the configured mount (expected {expected}, observed {observed})");
    }
    Ok(())
}

fn trusted_now_epoch_seconds() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs())
}

#[cfg(test)]
thread_local! {
    static AFTER_RETENTION_PREFLIGHT_HOOK:
        std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
    static BEFORE_RECOVERY_MUTATION_HOOK:
        std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
}

#[cfg(test)]
fn set_after_retention_preflight_hook(hook: impl FnOnce() + 'static) {
    AFTER_RETENTION_PREFLIGHT_HOOK.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(hook));
    });
}

#[cfg(test)]
fn set_before_recovery_mutation_hook(hook: impl FnOnce() + 'static) {
    BEFORE_RECOVERY_MUTATION_HOOK.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(hook));
    });
}

fn run_after_retention_preflight_hook() {
    #[cfg(test)]
    AFTER_RETENTION_PREFLIGHT_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

fn run_before_recovery_mutation_hook() {
    #[cfg(test)]
    BEFORE_RECOVERY_MUTATION_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::gate_denial::{DestructiveTargetDenial, GateDenialReason};
    use std::{
        os::unix::{fs::symlink, fs::PermissionsExt},
        sync::mpsc,
        thread,
    };
    use tempfile::TempDir;

    struct Fixture {
        _temp: TempDir,
        state_root: PathBuf,
        external_root: PathBuf,
        config_path: PathBuf,
    }

    impl Fixture {
        fn new(protected_relative: &[&str], grace_seconds: u64) -> Self {
            let temp = TempDir::new().expect("tempdir");
            let state_root = temp.path().join("machine-state");
            let external_root = temp.path().join("external-root");
            fs::create_dir(&state_root).expect("state root");
            fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700))
                .expect("private state root");
            fs::create_dir(&external_root).expect("external root");
            let config_path = temp.path().join("machine-global.json");
            let protected_paths = protected_relative
                .iter()
                .map(|relative| {
                    ProtectedPathSpec::new(
                        coordinate(relative),
                        SandboxDenialRetryability::NotRetryable,
                    )
                })
                .collect();
            write_config(
                &config_path,
                &state_root,
                &external_root,
                protected_paths,
                grace_seconds,
            );
            Self {
                _temp: temp,
                state_root,
                external_root,
                config_path,
            }
        }

        fn store(&self) -> MachineGlobalStore {
            MachineGlobalStore::open_config(&self.config_path).expect("open store")
        }

        fn directory(&self, relative: &str) -> PathBuf {
            let path = self.external_root.join(relative);
            fs::create_dir_all(&path).expect("target directory");
            path
        }
    }

    fn coordinate(relative: &str) -> DeclaredPathCoordinate {
        DeclaredPathCoordinate::new("external", relative).expect("coordinate")
    }

    fn declared(relative: &str) -> DestructiveTargetInput {
        DestructiveTargetInput::Declared(coordinate(relative))
    }

    fn write_config(
        config_path: &Path,
        state_root: &Path,
        external_root: &Path,
        protected_paths: Vec<ProtectedPathSpec>,
        grace_seconds: u64,
    ) {
        let config = MachineGlobalConfig {
            version: CONFIG_VERSION,
            state_root: state_root.to_path_buf(),
            roots: vec![DeclaredGlobalRootConfig {
                id: "external".to_string(),
                path: external_root.to_path_buf(),
                protected_paths,
                quarantine_grace_seconds: grace_seconds,
            }],
        };
        fs::write(
            config_path,
            serde_json::to_vec_pretty(&config).expect("config json"),
        )
        .expect("write config");
    }

    fn allowed_claim(outcome: GateOutcome<MachineGlobalClaim>) -> MachineGlobalClaim {
        match outcome {
            GateOutcome::Allowed(claim) => claim,
            GateOutcome::Denied(denial) => panic!("unexpected denial: {denial:?}"),
        }
    }

    fn allowed_operation(outcome: GateOutcome<RetentionOperation>) -> RetentionOperation {
        match outcome {
            GateOutcome::Allowed(operation) => operation,
            GateOutcome::Denied(denial) => panic!("unexpected denial: {denial:?}"),
        }
    }

    #[test]
    fn durable_repair_claim_blocks_later_reclaimer_across_independent_stores() {
        let fixture = Fixture::new(&[], 60);
        let session = fixture.directory("sessions/current");
        fs::write(session.join("irrecoverable"), "keep").expect("valuable data");
        let config_for_repair = fixture.config_path.clone();
        let config_for_reclaimer = fixture.config_path.clone();
        let (claimed_tx, claimed_rx) = mpsc::channel();
        let repair = thread::spawn(move || {
            let store = MachineGlobalStore::open_config(config_for_repair).expect("repair store");
            let claim = allowed_claim(
                store
                    .claim(
                        "repair-agent",
                        "repair-correlation",
                        vec![coordinate("sessions")],
                    )
                    .expect("repair claim"),
            );
            claimed_tx.send(()).expect("signal claim");
            claim
        });
        let reclaim = thread::spawn(move || {
            claimed_rx.recv().expect("wait for repair claim");
            let store =
                MachineGlobalStore::open_config(config_for_reclaimer).expect("reclaimer store");
            store
                .quarantine_at(
                    "reclaim-agent",
                    "reclaim-correlation",
                    vec![declared("sessions/current")],
                    100,
                )
                .expect("typed reclaim outcome")
        });

        let claim = repair.join().expect("repair thread");
        let outcome = reclaim.join().expect("reclaim thread");
        let GateOutcome::Denied(denial) = outcome else {
            panic!("reclaimer must be denied by the concurrent repair claim");
        };
        assert!(serde_json::to_string(&denial)
            .expect("denial json")
            .contains("active_claim_intersection"));
        assert_eq!(
            fs::read_to_string(session.join("irrecoverable")).expect("data survives"),
            "keep"
        );
        fixture
            .store()
            .release("repair-agent", claim.token)
            .expect("release");
    }

    #[test]
    fn concurrent_repair_mutation_survives_reclaim_attempt_during_live_claim() {
        let fixture = Fixture::new(&[], 60);
        let session = fixture.directory("sessions/current");
        let repair_data = session.join("irrecoverable");
        fs::write(&repair_data, "damaged").expect("damaged data");
        let config_for_repair = fixture.config_path.clone();
        let config_for_reclaimer = fixture.config_path.clone();
        let repair_data_for_thread = repair_data.clone();
        let (repair_inside_tx, repair_inside_rx) = mpsc::channel();
        let (reclaim_attempted_tx, reclaim_attempted_rx) = mpsc::channel();

        let repair = thread::spawn(move || {
            let store = MachineGlobalStore::open_config(config_for_repair).expect("repair store");
            let claim = allowed_claim(
                store
                    .claim(
                        "repair-agent",
                        "repair-correlation",
                        vec![coordinate("sessions")],
                    )
                    .expect("repair claim"),
            );
            fs::write(&repair_data_for_thread, "repair-in-progress")
                .expect("start repair mutation");
            repair_inside_tx
                .send(())
                .expect("signal protected repair section");
            reclaim_attempted_rx
                .recv()
                .expect("wait for reclaim attempt");
            assert_eq!(
                fs::read_to_string(&repair_data_for_thread).expect("repair data survives"),
                "repair-in-progress"
            );
            fs::write(&repair_data_for_thread, "repaired").expect("finish repair mutation");
            assert_eq!(
                fs::read_to_string(&repair_data_for_thread).expect("completed repair survives"),
                "repaired"
            );
            store
                .release("repair-agent", claim.token)
                .expect("release repair claim");
        });

        let reclaim = thread::spawn(move || {
            repair_inside_rx
                .recv()
                .expect("wait for protected repair section");
            let outcome = MachineGlobalStore::open_config(config_for_reclaimer).and_then(|store| {
                store.quarantine_at(
                    "reclaim-agent",
                    "reclaim-correlation",
                    vec![declared("sessions/current")],
                    100,
                )
            });
            reclaim_attempted_tx
                .send(())
                .expect("acknowledge reclaim attempt");
            outcome.expect("typed reclaim outcome")
        });

        let outcome = reclaim.join().expect("reclaim thread");
        repair.join().expect("repair thread");
        let GateOutcome::Denied(denial) = outcome else {
            panic!("reclaimer must be denied while the repair mutation is protected");
        };
        let GateDenialReason::DestructiveTarget { denial } = denial.reason else {
            panic!("reclaimer must receive a destructive-target denial");
        };
        let DestructiveTargetDenial::ActiveClaimIntersection {
            target,
            active_claim,
        } = *denial
        else {
            panic!("reclaimer must receive an active-claim intersection denial");
        };
        assert_eq!(target, coordinate("sessions/current"));
        assert_eq!(active_claim, coordinate("sessions"));
        assert_eq!(
            fs::read_to_string(repair_data).expect("repaired data survives"),
            "repaired"
        );
    }

    #[test]
    fn destructive_full_preflight_reports_claim_and_protected_intersections_before_any_rename() {
        let fixture = Fixture::new(&["protected"], 60);
        let allowed = fixture.directory("allowed");
        let claimed = fixture.directory("claimed");
        let protected = fixture.directory("protected");
        let store = fixture.store();
        let _claim = allowed_claim(
            store
                .claim(
                    "repair-agent",
                    "claim-correlation",
                    vec![coordinate("claimed")],
                )
                .expect("claim"),
        );

        let protected_outcome = store
            .quarantine_at(
                "cleanup-agent",
                "protected-correlation",
                vec![declared("allowed"), declared("protected")],
                100,
            )
            .expect("protected outcome");
        let GateOutcome::Denied(protected_denial) = protected_outcome else {
            panic!("protected target must be denied");
        };
        assert!(serde_json::to_string(&protected_denial)
            .expect("protected denial json")
            .contains("protected_path_intersection"));
        assert!(allowed.exists());
        assert!(protected.exists());

        let claim_outcome = store
            .quarantine_at(
                "cleanup-agent",
                "claim-correlation-2",
                vec![declared("allowed"), declared("claimed")],
                100,
            )
            .expect("claim outcome");
        let GateOutcome::Denied(claim_denial) = claim_outcome else {
            panic!("claimed target must be denied");
        };
        assert!(serde_json::to_string(&claim_denial)
            .expect("claim denial json")
            .contains("active_claim_intersection"));
        assert!(allowed.exists());
        assert!(claimed.exists());
    }

    #[test]
    fn quarantine_destination_claim_and_protection_are_preflighted() {
        let source_coordinate = coordinate("victim");
        let operation_id = RetentionOperationId::new(1).expect("operation id");
        let quarantine = quarantine_name(operation_id, &source_coordinate);
        let fixture = Fixture::new(&[&quarantine], 60);
        let victim = fixture.directory("victim");
        let protected_outcome = fixture
            .store()
            .quarantine_at(
                "cleanup-agent",
                "destination-protected",
                vec![declared("victim")],
                100,
            )
            .expect("protected destination outcome");
        assert!(matches!(protected_outcome, GateOutcome::Denied(_)));
        assert!(victim.exists());

        let unprotected = Fixture::new(&[], 60);
        let victim = unprotected.directory("victim");
        let store = unprotected.store();
        let _claim = allowed_claim(
            store
                .claim(
                    "repair-agent",
                    "destination-claim",
                    vec![coordinate(&quarantine)],
                )
                .expect("destination claim"),
        );
        let claim_outcome = store
            .quarantine_at(
                "cleanup-agent",
                "destination-claim-denial",
                vec![declared("victim")],
                100,
            )
            .expect("claimed destination outcome");
        assert!(matches!(claim_outcome, GateOutcome::Denied(_)));
        assert!(victim.exists());

        let cleanup_protected = Fixture::new(&[], 60);
        let victim = cleanup_protected.directory("victim");
        let identity = identity_for_path(&victim).expect("victim identity");
        let cleanup = quarantined_direct_child_cleanup_name(&quarantine, &identity)
            .expect("cleanup name")
            .into_string()
            .expect("utf8 cleanup name");
        write_config(
            &cleanup_protected.config_path,
            &cleanup_protected.state_root,
            &cleanup_protected.external_root,
            vec![ProtectedPathSpec::new(
                coordinate(&cleanup),
                SandboxDenialRetryability::NotRetryable,
            )],
            60,
        );
        let cleanup_outcome = cleanup_protected
            .store()
            .quarantine_at(
                "cleanup-agent",
                "cleanup-protected",
                vec![declared("victim")],
                100,
            )
            .expect("cleanup protected outcome");
        assert!(matches!(cleanup_outcome, GateOutcome::Denied(_)));
        assert!(victim.exists());
    }

    #[test]
    fn active_retention_reserves_source_quarantine_and_cleanup_coordinates() {
        let fixture = Fixture::new(&[], 60);
        fixture.directory("victim");
        let store = fixture.store();
        let operation = allowed_operation(
            store
                .quarantine_at(
                    "cleanup-agent",
                    "reserve-operation",
                    vec![declared("victim")],
                    100,
                )
                .expect("quarantine"),
        );

        let source_claim = store
            .claim(
                "repair-agent",
                "reserved-source",
                vec![coordinate("victim")],
            )
            .expect("source claim outcome");
        assert!(matches!(source_claim, GateOutcome::Denied(_)));
        for (index, reserved) in [
            operation.targets[0].quarantine_name.as_str(),
            operation.targets[0].cleanup_name.as_str(),
        ]
        .into_iter()
        .enumerate()
        {
            let claim = store
                .claim(
                    "repair-agent",
                    format!("reserved-coordinate-{index}"),
                    vec![coordinate(reserved)],
                )
                .expect("reserved claim outcome");
            assert!(matches!(claim, GateOutcome::Denied(_)));
        }

        let nested_cleanup = store
            .quarantine_at(
                "other-cleanup",
                "reserved-quarantine-cleanup",
                vec![declared(&operation.targets[0].quarantine_name)],
                101,
            )
            .expect("reservation cleanup denial");
        assert!(matches!(nested_cleanup, GateOutcome::Denied(_)));
    }

    #[test]
    fn undeclared_absolute_and_component_prefix_paths_do_not_widen_declared_roots() {
        let fixture = Fixture::new(&[], 60);
        let state = fixture.directory("state");
        let statefoo = fixture.directory("statefoo");
        let outside = fixture._temp.path().join("external-root-old");
        fs::create_dir(&outside).expect("outside directory");
        let store = fixture.store();

        let outside_outcome = store
            .quarantine_at(
                "cleanup-agent",
                "outside-target",
                vec![DestructiveTargetInput::UndeclaredAbsolute(outside.clone())],
                100,
            )
            .expect("outside denial");
        let GateOutcome::Denied(denial) = outside_outcome else {
            panic!("outside target must be denied");
        };
        let denial_json = serde_json::to_string(&denial).expect("outside denial json");
        assert!(denial_json.contains("undeclared_target"));
        assert!(!denial_json.contains(outside.to_str().expect("utf8 outside")));
        assert!(outside.exists());

        let first = allowed_claim(
            store
                .claim("first-agent", "prefix-first", vec![coordinate("state")])
                .expect("first claim"),
        );
        let second = allowed_claim(
            store
                .claim(
                    "second-agent",
                    "prefix-second",
                    vec![coordinate("statefoo")],
                )
                .expect("component-distinct claim"),
        );
        assert!(state.exists());
        assert!(statefoo.exists());
        store
            .release("first-agent", first.token)
            .expect("release first");
        store
            .release("second-agent", second.token)
            .expect("release second");
        assert!(DeclaredPathCoordinate::new("external", &outside).is_err());
    }

    #[test]
    fn config_spelling_symlink_and_permissions_fail_closed() {
        let fixture = Fixture::new(&[], 60);
        let noncanonical_config = PathBuf::from(format!(
            "{}/./machine-global.json",
            fixture._temp.path().display()
        ));
        assert!(MachineGlobalStore::open_config(noncanonical_config).is_err());
        let repeated_separator = PathBuf::from(format!(
            "{}//machine-global.json",
            fixture._temp.path().display()
        ));
        assert!(MachineGlobalStore::open_config(repeated_separator).is_err());
        let trailing_separator = PathBuf::from(format!(
            "{}/machine-global.json/",
            fixture._temp.path().display()
        ));
        assert!(MachineGlobalStore::open_config(trailing_separator).is_err());

        let config_link = fixture._temp.path().join("config-link.json");
        symlink(&fixture.config_path, &config_link).expect("config symlink");
        assert!(MachineGlobalStore::open_config(config_link).is_err());

        let config_hardlink = fixture._temp.path().join("config-hardlink.json");
        fs::hard_link(&fixture.config_path, &config_hardlink).expect("config hard link");
        assert!(MachineGlobalStore::open_config(&fixture.config_path).is_err());
        fs::remove_file(config_hardlink).expect("remove config hard link");

        fs::set_permissions(&fixture.config_path, fs::Permissions::from_mode(0o666))
            .expect("writable config");
        assert!(MachineGlobalStore::open_config(&fixture.config_path).is_err());
        fs::set_permissions(&fixture.config_path, fs::Permissions::from_mode(0o644))
            .expect("restore config mode");

        let root_alias = fixture._temp.path().join("root-alias");
        symlink(&fixture.external_root, &root_alias).expect("root symlink");
        let alias_config = fixture._temp.path().join("alias.json");
        write_config(
            &alias_config,
            &fixture.state_root,
            &root_alias,
            Vec::new(),
            60,
        );
        assert!(MachineGlobalStore::open_config(alias_config).is_err());

        let dotted_config = fixture._temp.path().join("dotted.json");
        write_config(
            &dotted_config,
            &fixture.state_root,
            &fixture.external_root.join("."),
            Vec::new(),
            60,
        );
        assert!(MachineGlobalStore::open_config(dotted_config).is_err());
    }

    #[test]
    fn configured_physical_binding_policy_rejects_mount_alias_ambiguity() {
        let binding =
            |label: &str, path: &str, device: u64, file: u64, mount_id: u64| PhysicalRootBinding {
                label: label.to_string(),
                path: PathBuf::from(path),
                identity: FileIdentity { device, file },
                mount_id,
            };
        assert!(validate_configured_physical_bindings(&[
            binding("state", "/state", 1, 10, 7),
            binding("root", "/root", 1, 11, 7),
            binding("other-device", "/other", 2, 12, 8),
        ])
        .is_ok());
        assert!(validate_configured_physical_bindings(&[
            binding("left", "/left", 1, 10, 7),
            binding("duplicate inode", "/alias", 1, 10, 8),
        ])
        .is_err());
        assert!(validate_configured_physical_bindings(&[
            binding("left", "/left", 1, 10, 7),
            binding("same device bind", "/alias", 1, 11, 8),
        ])
        .is_err());
        assert!(validate_configured_physical_bindings(&[
            binding("root", "/root", 1, 10, 7),
            binding("nested", "/root/nested", 1, 11, 7),
        ])
        .is_err());
    }

    #[test]
    fn runtime_mount_mismatches_fail_closed() {
        let fixture = Fixture::new(&[], 60);
        fixture.directory("victim");
        let mut store = fixture.store();
        let configured_state_mount = store.state_root_mount_id;
        store.state_root_mount_id = configured_state_mount.saturating_add(1);
        assert!(store.acquire_lock().is_err());
        store.state_root_mount_id = configured_state_mount;

        let configured = store.roots.get_mut("external").expect("configured root");
        configured.mount_id = configured.mount_id.saturating_add(1);
        assert!(store
            .claim(
                "repair-agent",
                "fabricated-mount-crossing",
                vec![coordinate("victim")],
            )
            .is_err());
        assert!(require_same_mount(7, 8, "fabricated nested leaf").is_err());
    }

    #[test]
    fn traversal_noncanonical_and_symlink_targets_fail_closed() {
        let fixture = Fixture::new(&[], 60);
        let outside = fixture._temp.path().join("outside");
        fs::create_dir(&outside).expect("outside");
        fs::write(outside.join("valuable"), "keep").expect("outside data");
        symlink(&outside, fixture.external_root.join("linked")).expect("target symlink");
        fs::create_dir(fixture.external_root.join("nested")).expect("nested");
        symlink(
            &outside,
            fixture.external_root.join("nested").join("linked-parent"),
        )
        .expect("parent symlink");
        let store = fixture.store();

        assert!(DeclaredPathCoordinate::new("external", "../outside").is_err());
        assert!(DeclaredPathCoordinate::new("external", "nested/./child").is_err());
        assert!(store
            .claim("repair-agent", "leaf-symlink", vec![coordinate("linked")],)
            .is_err());
        assert!(store
            .claim(
                "repair-agent",
                "parent-symlink",
                vec![coordinate("nested/linked-parent/child")],
            )
            .is_err());
        assert_eq!(
            fs::read_to_string(outside.join("valuable")).expect("outside survives"),
            "keep"
        );
    }

    #[test]
    fn quarantine_restore_grace_and_token_gates_are_recoverable_and_auditable() {
        let fixture = Fixture::new(&[], 30);
        let victim = fixture.directory("victim");
        fs::write(victim.join("valuable"), "keep").expect("valuable");
        let store = fixture.store();

        let operation = allowed_operation(
            store
                .quarantine_at(
                    "cleanup-agent",
                    "quarantine-one",
                    vec![declared("victim")],
                    100,
                )
                .expect("quarantine"),
        );
        assert!(!victim.exists());
        assert!(store
            .purge_at(
                "cleanup-agent",
                "too-early",
                operation.id,
                &operation.token,
                129,
            )
            .is_err());
        let restored = allowed_operation(
            store
                .restore("cleanup-agent", "restore-one", operation.id)
                .expect("restore"),
        );
        assert_eq!(restored.targets[0].state, RetentionTargetState::Restored);
        assert_eq!(
            fs::read_to_string(victim.join("valuable")).expect("restored data"),
            "keep"
        );

        let second = allowed_operation(
            store
                .quarantine_at(
                    "cleanup-agent",
                    "quarantine-two",
                    vec![declared("victim")],
                    200,
                )
                .expect("second quarantine"),
        );
        let wrong_token =
            RetentionOperationToken::new("0".repeat(64)).expect("syntactically valid wrong token");
        assert!(store
            .purge_at("cleanup-agent", "wrong-token", second.id, &wrong_token, 230,)
            .is_err());
        let purged = allowed_operation(
            store
                .purge_at("cleanup-agent", "purge-two", second.id, &second.token, 230)
                .expect("purge"),
        );
        assert_eq!(purged.targets[0].state, RetentionTargetState::Purged);
        assert!(!victim.exists());
        let status_json = serde_json::to_string(&store.status().expect("status")).expect("json");
        assert!(status_json.contains(&format!("\"id\":{}", second.id.get())));
        assert!(!status_json.contains(second.token.as_str()));
    }

    #[test]
    fn unavailable_quarantine_destination_refuses_without_moving_source() {
        let fixture = Fixture::new(&[], 60);
        let victim = fixture.directory("victim");
        fs::write(victim.join("valuable"), "keep").expect("valuable");
        let operation_id = RetentionOperationId::new(1).expect("operation id");
        let quarantine = quarantine_name(operation_id, &coordinate("victim"));
        fs::create_dir(fixture.external_root.join(&quarantine)).expect("occupied destination");

        let error = fixture
            .store()
            .quarantine_at(
                "cleanup-agent",
                "occupied-destination",
                vec![declared("victim")],
                100,
            )
            .expect_err("occupied destination must fail closed");
        assert!(error.to_string().contains("destination"));
        assert_eq!(
            fs::read_to_string(victim.join("valuable")).expect("source survives"),
            "keep"
        );
    }

    #[test]
    fn post_preflight_target_replacement_is_refused_without_quarantine_mutation() {
        let fixture = Fixture::new(&[], 60);
        let victim = fixture.directory("victim");
        fs::write(victim.join("valuable"), "original").expect("valuable");
        let displaced = fixture.external_root.join("displaced");
        let victim_for_hook = victim.clone();
        let displaced_for_hook = displaced.clone();
        set_after_retention_preflight_hook(move || {
            fs::rename(&victim_for_hook, &displaced_for_hook).expect("displace original");
            fs::create_dir(&victim_for_hook).expect("replacement");
            fs::write(victim_for_hook.join("valuable"), "replacement").expect("replacement data");
        });

        let error = fixture
            .store()
            .quarantine_at(
                "cleanup-agent",
                "target-replacement",
                vec![declared("victim")],
                100,
            )
            .expect_err("identity replacement must fail");
        assert!(error.to_string().contains("quarantining"));
        assert_eq!(
            fs::read_to_string(victim.join("valuable")).expect("replacement remains"),
            "replacement"
        );
        assert_eq!(
            fs::read_to_string(displaced.join("valuable")).expect("original remains"),
            "original"
        );
    }

    #[test]
    fn post_preflight_root_replacement_is_refused_without_outside_mutation() {
        let fixture = Fixture::new(&[], 60);
        let victim = fixture.directory("victim");
        fs::write(victim.join("valuable"), "original").expect("valuable");
        let displaced_root = fixture._temp.path().join("displaced-root");
        let root_for_hook = fixture.external_root.clone();
        let displaced_for_hook = displaced_root.clone();
        set_after_retention_preflight_hook(move || {
            fs::rename(&root_for_hook, &displaced_for_hook).expect("displace root");
            fs::create_dir(&root_for_hook).expect("replacement root");
            fs::create_dir(root_for_hook.join("victim")).expect("replacement victim");
            fs::write(root_for_hook.join("victim/valuable"), "replacement")
                .expect("replacement data");
        });

        fixture
            .store()
            .quarantine_at(
                "cleanup-agent",
                "root-replacement",
                vec![declared("victim")],
                100,
            )
            .expect_err("root replacement must fail");
        assert_eq!(
            fs::read_to_string(displaced_root.join("victim/valuable"))
                .expect("original outside survives"),
            "original"
        );
        assert_eq!(
            fs::read_to_string(victim.join("valuable")).expect("replacement survives"),
            "replacement"
        );
    }

    #[test]
    fn planned_record_restores_after_post_rename_crash_state() {
        let fixture = Fixture::new(&[], 60);
        let victim = fixture.directory("victim");
        fs::write(victim.join("valuable"), "keep").expect("valuable");
        let store = fixture.store();
        let operation = allowed_operation(
            store
                .quarantine_at(
                    "cleanup-agent",
                    "crash-quarantine",
                    vec![declared("victim")],
                    100,
                )
                .expect("quarantine"),
        );
        let lock = store.acquire_lock().expect("state lock");
        let mut state = store.load_state(&lock).expect("state");
        let record = state
            .retention_operations
            .get_mut(&operation.id)
            .expect("operation record");
        record.targets[0].state = RetentionTargetState::Planned;
        store.write_state(&lock, &state).expect("write crash state");
        drop(lock);

        let restored = allowed_operation(
            store
                .restore("cleanup-agent", "crash-restore", operation.id)
                .expect("restore planned"),
        );
        assert_eq!(restored.targets[0].state, RetentionTargetState::Restored);
        assert_eq!(
            fs::read_to_string(victim.join("valuable")).expect("restored data"),
            "keep"
        );
    }

    #[test]
    fn restore_and_purge_recheck_live_protection_before_mutation() {
        let fixture = Fixture::new(&[], 20);
        fixture.directory("victim");
        let mut store = fixture.store();
        let operation = allowed_operation(
            store
                .quarantine_at(
                    "cleanup-agent",
                    "protect-before-restore",
                    vec![declared("victim")],
                    100,
                )
                .expect("quarantine"),
        );
        let lock = store.acquire_lock().expect("state lock");
        let mut active_claim_state = store.load_state(&lock).expect("state");
        drop(lock);
        let fabricated_token =
            MachineGlobalClaimToken::new(random_identifier().expect("random token"))
                .expect("claim token");
        active_claim_state.claims.insert(
            fabricated_token.clone(),
            MachineGlobalClaim {
                token: fabricated_token,
                owner: "repair-agent".to_string(),
                targets: vec![coordinate("victim")],
            },
        );
        let active_claim_denial = store
            .destructive_intersection_denial(
                &active_claim_state,
                "cleanup-agent",
                "restore-claim-recheck",
                &operation_mutation_coordinates(&operation).expect("mutation coordinates"),
                Some(operation.id),
            )
            .expect("active claim preflight");
        assert!(serde_json::to_string(&active_claim_denial)
            .expect("active claim denial json")
            .contains("active_claim_intersection"));
        store
            .roots
            .get_mut("external")
            .expect("root")
            .protected_paths
            .push(ProtectedPathSpec::new(
                coordinate("victim"),
                SandboxDenialRetryability::NotRetryable,
            ));
        let restore = store
            .restore("cleanup-agent", "restore-recheck", operation.id)
            .expect("restore outcome");
        assert!(matches!(restore, GateOutcome::Denied(_)));
        assert!(!fixture.external_root.join("victim").exists());
        assert!(fixture
            .external_root
            .join(&operation.targets[0].quarantine_name)
            .exists());

        let purge_fixture = Fixture::new(&[], 20);
        purge_fixture.directory("victim");
        let mut purge_store = purge_fixture.store();
        let purge_operation = allowed_operation(
            purge_store
                .quarantine_at(
                    "cleanup-agent",
                    "protect-before-purge",
                    vec![declared("victim")],
                    100,
                )
                .expect("quarantine"),
        );
        purge_store
            .roots
            .get_mut("external")
            .expect("root")
            .protected_paths
            .push(ProtectedPathSpec::new(
                coordinate(&purge_operation.targets[0].cleanup_name),
                SandboxDenialRetryability::NotRetryable,
            ));
        let purge = purge_store
            .purge_at(
                "cleanup-agent",
                "purge-recheck",
                purge_operation.id,
                &purge_operation.token,
                120,
            )
            .expect("purge outcome");
        assert!(matches!(purge, GateOutcome::Denied(_)));
        assert!(purge_fixture
            .external_root
            .join(&purge_operation.targets[0].quarantine_name)
            .exists());
    }

    #[test]
    fn recovery_parent_replacement_hooks_refuse_restore_and_purge() {
        let restore_fixture = Fixture::new(&[], 20);
        restore_fixture.directory("victim");
        let restore_store = restore_fixture.store();
        let restore_operation = allowed_operation(
            restore_store
                .quarantine_at(
                    "cleanup-agent",
                    "restore-hook-quarantine",
                    vec![declared("victim")],
                    100,
                )
                .expect("quarantine"),
        );
        let displaced_restore_root = restore_fixture._temp.path().join("restore-displaced");
        let restore_root = restore_fixture.external_root.clone();
        let restore_displaced = displaced_restore_root.clone();
        set_before_recovery_mutation_hook(move || {
            fs::rename(&restore_root, &restore_displaced).expect("displace restore root");
            fs::create_dir(&restore_root).expect("replacement restore root");
            fs::create_dir(restore_root.join("victim")).expect("replacement restore victim");
        });
        assert!(restore_store
            .restore(
                "cleanup-agent",
                "restore-parent-replacement",
                restore_operation.id,
            )
            .is_err());
        assert!(displaced_restore_root
            .join(&restore_operation.targets[0].quarantine_name)
            .exists());
        assert!(restore_fixture.external_root.join("victim").exists());

        let purge_fixture = Fixture::new(&[], 20);
        purge_fixture.directory("victim");
        let purge_store = purge_fixture.store();
        let purge_operation = allowed_operation(
            purge_store
                .quarantine_at(
                    "cleanup-agent",
                    "purge-hook-quarantine",
                    vec![declared("victim")],
                    100,
                )
                .expect("quarantine"),
        );
        let displaced_purge_root = purge_fixture._temp.path().join("purge-displaced");
        let purge_root = purge_fixture.external_root.clone();
        let purge_displaced = displaced_purge_root.clone();
        set_before_recovery_mutation_hook(move || {
            fs::rename(&purge_root, &purge_displaced).expect("displace purge root");
            fs::create_dir(&purge_root).expect("replacement purge root");
            fs::create_dir(purge_root.join("victim")).expect("replacement purge victim");
        });
        assert!(purge_store
            .purge_at(
                "cleanup-agent",
                "purge-parent-replacement",
                purge_operation.id,
                &purge_operation.token,
                120,
            )
            .is_err());
        assert!(displaced_purge_root
            .join(&purge_operation.targets[0].quarantine_name)
            .exists());
        assert!(purge_fixture.external_root.join("victim").exists());
    }

    #[test]
    fn impossible_mixed_retention_phases_are_rejected() {
        let fixture = Fixture::new(&[], 20);
        fixture.directory("first");
        fixture.directory("second");
        let operation = allowed_operation(
            fixture
                .store()
                .quarantine_at(
                    "cleanup-agent",
                    "phase-fixture",
                    vec![declared("first"), declared("second")],
                    100,
                )
                .expect("quarantine"),
        );
        let mut invalid = operation.targets.clone();
        invalid[0].state = RetentionTargetState::Planned;
        invalid[1].state = RetentionTargetState::Quarantined;
        assert!(validate_retention_phases(&invalid).is_err());
        invalid[0].state = RetentionTargetState::Restored;
        invalid[1].state = RetentionTargetState::Purged;
        assert!(validate_retention_phases(&invalid).is_err());
    }
}
