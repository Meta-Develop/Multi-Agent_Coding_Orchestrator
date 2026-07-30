//! Claims and recoverable retention for explicitly declared machine-global roots.
//!
//! Absolute host paths enter this module only through a strict, reviewable configuration file.
//! Persisted claims, operation reports, and gate denials use [`DeclaredPathCoordinate`] instead.

use crate::{
    gate_denial::{CorrectionCorrelationId, GateDenial},
    protected_path::{DeclaredPathCoordinate, ProtectedPathSpec},
    safe_state::{
        identity_for_path, quarantine_direct_child_directory, remove_quarantined_direct_child_tree,
        restore_quarantined_direct_child_directory, stable_checksum, AtomicStateWriter,
        BoundedRegularReader, FileIdentity, KernelStateLock, SafeRoot, TreeLinkPolicy,
    },
    worktree::normalize_agent_id,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs,
    path::{Component, Path, PathBuf},
    str::FromStr,
};

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

/// A gate operation either completed or was refused through the typed Issue 29 envelope.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "outcome", content = "value", rename_all = "snake_case")]
pub enum GateOutcome<T> {
    Allowed(T),
    Denied(GateDenial),
}

/// Opaque durable token for one machine-global claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(transparent)]
pub struct MachineGlobalClaimToken(u64);

impl MachineGlobalClaimToken {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            bail!("machine-global claim token must be nonzero");
        }
        Ok(Self(value))
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

impl FromStr for MachineGlobalClaimToken {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::new(
            value
                .parse::<u64>()
                .context("machine-global claim token must be an unsigned integer")?,
        )
    }
}

/// Opaque durable identity for one retention operation.
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

/// Public claim state. It contains no configured absolute host path.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MachineGlobalClaim {
    pub token: MachineGlobalClaimToken,
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
    pub identity: FileIdentity,
    pub state: RetentionTargetState,
}

/// Auditable, recoverable retention operation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionOperation {
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
    pub claims: Vec<MachineGlobalClaim>,
    pub retention_operations: Vec<RetentionOperation>,
}

#[derive(Debug)]
struct ValidatedRoot {
    safe: SafeRoot,
    protected_paths: Vec<ProtectedPathSpec>,
    quarantine_grace_seconds: u64,
}

/// Shared store. Independent repositories coordinate when they open the same configured state root.
#[derive(Debug)]
pub struct MachineGlobalStore {
    state_root: SafeRoot,
    roots: BTreeMap<String, ValidatedRoot>,
    config_fingerprint: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StatePayload {
    config_fingerprint: String,
    next_claim_token: u64,
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
    fn empty(config_fingerprint: String) -> Self {
        Self {
            config_fingerprint,
            next_claim_token: 1,
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
        let bytes = BoundedRegularReader::read_tree_no_follow(&config_path, CONFIG_MAX_BYTES)
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

        let mut roots = BTreeMap::new();
        let mut canonical_paths = Vec::new();
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
                        safe,
                        protected_paths: configured.protected_paths.clone(),
                        quarantine_grace_seconds: configured.quarantine_grace_seconds,
                    },
                )
                .is_some()
            {
                bail!("duplicate declared root id {}", configured.id);
            }
            canonical_paths.push((configured.id.clone(), canonical));
        }
        for (index, (left_id, left)) in canonical_paths.iter().enumerate() {
            if paths_intersect(left, &state_root_path) {
                bail!("declared root {left_id} intersects machine-global state_root");
            }
            for (right_id, right) in canonical_paths.iter().skip(index.saturating_add(1)) {
                if paths_intersect(left, right) {
                    bail!("declared roots {left_id} and {right_id} overlap");
                }
            }
        }

        let config_fingerprint = stable_checksum(&bytes);
        Ok(Self {
            state_root,
            roots,
            config_fingerprint,
        })
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
        if state.claims.len() >= MAX_ACTIVE_CLAIMS {
            bail!("machine-global active-claim limit reached");
        }
        let token = MachineGlobalClaimToken::new(take_next_id(&mut state.next_claim_token)?)?;
        let claim = MachineGlobalClaim {
            token,
            owner,
            targets,
        };
        state.claims.insert(token, claim.clone());
        self.write_state(&lock, &state)?;
        Ok(GateOutcome::Allowed(claim))
    }

    /// Releases a claim token. Missing tokens are accepted idempotently.
    pub fn release(&self, token: MachineGlobalClaimToken) -> Result<bool> {
        let lock = self.acquire_lock()?;
        let mut state = self.load_state(&lock)?;
        let removed = state.claims.remove(&token).is_some();
        if removed {
            self.write_state(&lock, &state)?;
        }
        Ok(removed)
    }

    /// Returns all claims intersecting one declared coordinate.
    pub fn owner(&self, target: &DeclaredPathCoordinate) -> Result<Vec<MachineGlobalClaim>> {
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
            .cloned()
            .collect())
    }

    /// Returns a complete privacy-safe status snapshot.
    pub fn status(&self) -> Result<MachineGlobalStatus> {
        let lock = self.acquire_lock()?;
        let state = self.load_state(&lock)?;
        Ok(MachineGlobalStatus {
            claims: state.claims.into_values().collect(),
            retention_operations: state.retention_operations.into_values().collect(),
        })
    }

    /// Checks the complete declared target set before performing the first quarantine rename.
    pub fn quarantine(
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

        if let Some(denial) = self.destructive_intersection_denial(
            &state,
            &owner,
            correction_correlation_id.as_ref(),
            &declared,
        )? {
            return Ok(GateOutcome::Denied(denial));
        }
        if state.retention_operations.len() >= MAX_RETENTION_OPERATIONS {
            bail!("machine-global retention-operation limit reached");
        }

        let operation_id = RetentionOperationId::new(take_next_id(&mut state.next_operation_id)?)?;
        let mut purge_after = now_epoch_seconds;
        let mut operation_targets = Vec::with_capacity(declared.len());
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
            operation_targets.push(RetentionTarget {
                quarantine_name: quarantine_name(operation_id, &coordinate),
                coordinate,
                identity: prepared.identity,
                state: RetentionTargetState::Planned,
            });
        }
        let mut operation = RetentionOperation {
            id: operation_id,
            owner,
            created_at_epoch_seconds: now_epoch_seconds,
            purge_after_epoch_seconds: purge_after,
            targets: operation_targets,
        };
        state
            .retention_operations
            .insert(operation_id, operation.clone());
        self.write_state(&lock, &state)?;

        run_after_retention_preflight_hook();
        for index in 0..operation.targets.len() {
            let target = operation
                .targets
                .get(index)
                .context("retention target index disappeared")?
                .clone();
            let parent = self.open_coordinate_parent(&target.coordinate)?;
            let child = coordinate_basename(&target.coordinate)?;
            quarantine_direct_child_directory(
                &parent,
                child,
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
    pub fn restore(&self, operation_id: RetentionOperationId) -> Result<RetentionOperation> {
        let lock = self.acquire_lock()?;
        let mut state = self.load_state(&lock)?;
        let mut operation = state
            .retention_operations
            .get(&operation_id)
            .cloned()
            .context("unknown retention operation")?;
        if operation
            .targets
            .iter()
            .any(|target| target.state == RetentionTargetState::Purged)
        {
            bail!("purged retention operation cannot be restored");
        }
        for index in 0..operation.targets.len() {
            let target = operation
                .targets
                .get(index)
                .context("retention target index disappeared")?
                .clone();
            if target.state == RetentionTargetState::Restored {
                continue;
            }
            let parent = self.open_coordinate_parent(&target.coordinate)?;
            let child = coordinate_basename(&target.coordinate)?;
            restore_quarantined_direct_child_directory(
                &parent,
                child,
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
        Ok(operation)
    }

    /// Permanently removes quarantined trees only after grace and a fresh full preflight.
    pub fn purge(
        &self,
        owner: impl AsRef<str>,
        correction_correlation_id: impl AsRef<str>,
        operation_id: RetentionOperationId,
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
        let coordinates = operation
            .targets
            .iter()
            .filter(|target| target.state != RetentionTargetState::Purged)
            .map(|target| target.coordinate.clone())
            .collect::<Vec<_>>();
        if let Some(denial) = self.destructive_intersection_denial(
            &state,
            &owner,
            correction_correlation_id.as_ref(),
            &coordinates,
        )? {
            return Ok(GateOutcome::Denied(denial));
        }
        for index in 0..operation.targets.len() {
            let target = operation
                .targets
                .get(index)
                .context("retention target index disappeared")?
                .clone();
            if target.state == RetentionTargetState::Purged {
                continue;
            }
            let parent = self.open_coordinate_parent(&target.coordinate)?;
            remove_quarantined_direct_child_tree(
                &parent,
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
        KernelStateLock::acquire_direct(&self.state_root, LOCK_FILE)
            .context("failed to acquire machine-global kernel state lock")
    }

    fn load_state(&self, lock: &KernelStateLock) -> Result<StatePayload> {
        lock.verify_direct_binding(&self.state_root)?;
        self.state_root.verify()?;
        if !self.state_root.direct_child_exists(STATE_FILE)? {
            return Ok(StatePayload::empty(self.config_fingerprint.clone()));
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
        validate_loaded_state(&envelope.payload)?;
        lock.verify_direct_binding(&self.state_root)?;
        Ok(envelope.payload)
    }

    fn write_state(&self, lock: &KernelStateLock, state: &StatePayload) -> Result<()> {
        validate_loaded_state(state)?;
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
        root.safe.verify()?;
        let parent = self.open_coordinate_parent(coordinate)?;
        let child = coordinate_basename(coordinate)?;
        let absolute = parent.direct_child(child)?;
        match fs::symlink_metadata(&absolute) {
            Ok(metadata) => {
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
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
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
        Ok(PreparedTarget { identity })
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
        if parent_relative.as_os_str().is_empty() {
            root.safe.verify()?;
            return Ok(root.safe.clone());
        }
        SafeRoot::open_existing(root.safe.path().join(parent_relative)).with_context(|| {
            format!(
                "declared coordinate parent is unsafe or non-canonical: {}:{}",
                coordinate.root_id(),
                parent_relative.display()
            )
        })
    }

    fn destructive_intersection_denial(
        &self,
        state: &StatePayload,
        owner: &str,
        correlation: &str,
        targets: &[DeclaredPathCoordinate],
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
    identity: FileIdentity,
}

fn validate_owner_and_correlation(owner: &str, correlation: &str) -> Result<String> {
    let owner = normalize_agent_id(owner).context("machine-global owner is invalid")?;
    CorrectionCorrelationId::new(correlation).context("correction correlation id is invalid")?;
    Ok(owner)
}

fn validate_loaded_state(state: &StatePayload) -> Result<()> {
    if state.next_claim_token == 0 || state.next_operation_id == 0 {
        bail!("machine-global state counters must be nonzero");
    }
    if state.claims.len() > MAX_ACTIVE_CLAIMS
        || state.retention_operations.len() > MAX_RETENTION_OPERATIONS
    {
        bail!("machine-global state exceeds collection bounds");
    }
    for (token, claim) in &state.claims {
        if *token != claim.token {
            bail!("machine-global claim key/token mismatch");
        }
        normalize_agent_id(&claim.owner).context("durable claim owner is invalid")?;
        if claim.targets.is_empty() || claim.targets.len() > MAX_TARGETS_PER_OPERATION {
            bail!("durable claim target set is out of bounds");
        }
        for target in &claim.targets {
            target
                .validate()
                .context("durable claim coordinate is invalid")?;
        }
    }
    for (id, operation) in &state.retention_operations {
        if *id != operation.id {
            bail!("retention operation key/id mismatch");
        }
        normalize_agent_id(&operation.owner).context("retention owner is invalid")?;
        if operation.targets.is_empty() || operation.targets.len() > MAX_TARGETS_PER_OPERATION {
            bail!("durable retention target set is out of bounds");
        }
        if operation.purge_after_epoch_seconds <= operation.created_at_epoch_seconds {
            bail!("retention operation has an invalid grace window");
        }
        for target in &operation.targets {
            target
                .coordinate
                .validate()
                .context("durable retention coordinate is invalid")?;
            validate_quarantine_name(&target.quarantine_name)?;
        }
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
    Ok(canonical)
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
    if canonical != path {
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

#[cfg(test)]
thread_local! {
    static AFTER_RETENTION_PREFLIGHT_HOOK:
        std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
}

#[cfg(test)]
fn set_after_retention_preflight_hook(hook: impl FnOnce() + 'static) {
    AFTER_RETENTION_PREFLIGHT_HOOK.with(|slot| {
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
