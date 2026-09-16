//! Explicit operator selection of remote GitHub CAS coordination (#410).
//!
//! Does not enable remote mode by itself and does not wire [`crate::sync_store::SyncStore`].
//! Production shared-effect admission still requires a parent-supplied
//! [`super::coordination_journal::EffectReconciliationVerifier`] for legacy opaque effects.
//! [`service_from_stored`] injects [`super::coordination_provider::ParentPublicationProviderVerifier`]
//! as the bound publication live verifier.

use super::coordination_admission::{
    worktree_has_planned_coordination_pending_intents, CoordinationAdmissionService,
};
use super::coordination_github::{
    CoordinationGithubAdapterConfig, CoordinationGithubAdapterOpenInput, CoordinationGithubRunner,
    CoordinationGithubTransport, ProductionCoordinationGithubRunner,
};
use super::coordination_provider::ParentPublicationProviderVerifier;
use super::forge_transport::{
    ForgeActor, ForgeItem, ForgeItemKind, ForgeRepository, ProviderObjectId, ProviderObjectKind,
};
use super::stable_json_digest;
use crate::{
    artifacts::{
        discover_repo_root, repository_auth_writer, repository_authenticator_key_only,
        state_auth::{
            sha256_hex, AuthenticationDomain, RepositoryAuthBinding, RepositoryAuthenticator,
        },
    },
    authenticated_snapshot::{AuthenticatedSnapshot, AuthenticatedSnapshotStore, SnapshotSpec},
    git_repository,
    safe_state::{BoundedRegularReader, SafeRoot},
    state_journal::JournalSpec,
    sync::{normalize_repo_relative_path, PathClaim},
    sync_store::{ClaimTiming, ClaimsSnapshotSpec, RepositoryStateLock, RepositoryStateRoot},
};
use anyhow::{bail, Context, Result};
use git2::Repository;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

const OPERATOR_INPUT_SCHEMA_VERSION: u32 = 1;
const MAX_OPERATOR_COORDINATION_CONFIG_BYTES: u64 = 64 * 1024;
const COORDINATION_MODE_LOGICAL_ID: &str = "coordination-mode";
const CLAIMS_LOGICAL_ID: &str = "claims";
const STATE_FILE: &str = "coordination-mode.json";
const STATE_LOCK: &str = "coordination-mode.lock";

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ClaimsProbeSnapshot {
    claims: Vec<PathClaim>,
}

pub(crate) type ProductionCoordinationService =
    CoordinationAdmissionService<CoordinationGithubTransport<ProductionCoordinationGithubRunner>>;

pub(crate) enum CoordinationModeSnapshotSpec {}

impl JournalSpec for CoordinationModeSnapshotSpec {
    const FORMAT_VERSION: u32 = 1;
    const NAMESPACE: &'static str = "authenticated_coordination_mode";
    const ROOT_NAME: &'static str = "authenticated-coordination-mode-v1";
    const ROOT_LOCK_NAME: &'static str = ".authenticated-coordination-mode.lock";
    const INSTANCE_LOCK_NAME: &'static str = ".coordination-mode-snapshot.lock";
    const HEAD_FILE_NAME: &'static str = ".head.json";
    const RECORD_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0authenticated-coordination-mode-record\0v1\0");
    const HEAD_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0authenticated-coordination-mode-head\0v1\0");
    const MAX_RECORDS: usize = 256;
    const MAX_RECORD_BYTES: u64 = 256 * 1024;
    const MAX_TOTAL_BYTES: u64 = 8 * 1024 * 1024;
    const MAX_PHASE_BYTES: usize = 32;
    const MAX_SUBJECT_BYTES: usize = 64;
    const MAX_INSTANCE_ID_BYTES: usize = 128;
}

impl SnapshotSpec for CoordinationModeSnapshotSpec {
    const SNAPSHOT_FORMAT_VERSION: u32 = 1;
    const LOCATOR_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0authenticated-coordination-mode-locator\0v1\0");
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredCoordinationSelection {
    operator_config_path: String,
    operator_input_sha256: String,
    selection_digest: String,
    repository_selector: String,
    anchor_item: ForgeItem,
    journal_ref: String,
    anchor_commit_oid: String,
    pointer_filename: String,
    trusted_actors: Vec<ForgeActor>,
    timing: ClaimTiming,
    approved_actor: ForgeActor,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedCoordinationModeState {
    version: u32,
    snapshot_revision: u64,
    repository: RepositoryAuthBinding,
    selection: Option<StoredCoordinationSelection>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperatorCoordinationModeInput {
    schema_version: u32,
    repository_selector: String,
    repository_provider_node_id: ProviderObjectId,
    anchor_issue_number: u64,
    anchor_issue_provider_node_id: ProviderObjectId,
    anchor_item_revision: String,
    journal_ref: String,
    anchor_commit_oid: String,
    pointer_filename: String,
    trusted_actors: Vec<ForgeActor>,
    claim_timing: ClaimTiming,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteCoordinationConfigureReport {
    pub configured: bool,
    pub idempotent: bool,
    pub selection_digest: String,
    pub repository_selector: String,
    pub anchor_issue_number: u64,
    pub journal_ref: String,
    pub anchor_commit_oid: String,
    pub claim_timing: ClaimTiming,
    pub operator_config_path: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteCoordinationStatusReport {
    pub selected: bool,
    pub selection_digest: Option<String>,
    pub repository_selector: Option<String>,
    pub anchor_issue_number: Option<u64>,
    pub journal_ref: Option<String>,
    pub anchor_commit_oid: Option<String>,
    pub claim_timing: Option<ClaimTiming>,
    pub operator_config_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteCoordinationDisableReport {
    pub disabled: bool,
    pub was_selected: bool,
}

fn require_supported_operator_config_platform() -> Result<()> {
    #[cfg(not(unix))]
    bail!(
        "remote coordination operator config requires Unix component-wise repository path confinement; native Windows is unsupported"
    );
    #[cfg(unix)]
    Ok(())
}

fn repo_workdir(repo_path: &Path) -> Result<PathBuf> {
    let repo = git_repository::discover(repo_path)?;
    Ok(repo.workdir().unwrap_or_else(|| repo.path()).to_path_buf())
}

fn open_mode_state(repo: &Repository) -> Result<RepositoryStateRoot> {
    RepositoryStateRoot::open(repo, STATE_FILE, STATE_LOCK)
}

fn read_operator_config(repo: &Path, relative_path: &Path) -> Result<Vec<u8>> {
    require_supported_operator_config_platform()?;
    let repo_root = discover_repo_root(repo)?;
    let relative_path = normalize_repo_relative_path(relative_path)
        .context("coordination operator config path must be repository-relative")?;
    BoundedRegularReader::read_relative(
        &repo_root,
        &relative_path,
        MAX_OPERATOR_COORDINATION_CONFIG_BYTES,
    )
    .with_context(|| {
        format!(
            "failed to read bounded coordination operator config {}",
            relative_path.display()
        )
    })
}

fn parse_operator_input(bytes: &[u8]) -> Result<OperatorCoordinationModeInput> {
    let input: OperatorCoordinationModeInput = serde_json::from_slice(bytes)
        .context("coordination operator config is not valid strict JSON")?;
    if input.schema_version != OPERATOR_INPUT_SCHEMA_VERSION {
        bail!(
            "unsupported coordination operator config schema version {}",
            input.schema_version
        );
    }
    if input.trusted_actors.is_empty() {
        bail!("coordination operator config requires a non-empty trusted actor allowlist");
    }
    ClaimTiming::new(
        input.claim_timing.heartbeat_interval_seconds,
        input.claim_timing.stale_after_seconds,
    )?;
    Ok(input)
}

fn forge_item_from_operator(input: &OperatorCoordinationModeInput) -> Result<ForgeItem> {
    require_object_kind(
        &input.repository_provider_node_id,
        ProviderObjectKind::Repository,
        "repository provider node id",
    )?;
    require_object_kind(
        &input.anchor_issue_provider_node_id,
        ProviderObjectKind::Item,
        "anchor issue provider node id",
    )?;
    let repository = ForgeRepository::new(
        "github",
        input.repository_selector.as_str(),
        input.repository_provider_node_id.clone(),
    )?;
    ForgeItem::new(
        repository,
        ForgeItemKind::Issue,
        input.anchor_issue_number,
        input.anchor_issue_provider_node_id.clone(),
        input.anchor_item_revision.as_str(),
        None,
        None,
    )
}

fn require_object_kind(id: &ProviderObjectId, kind: ProviderObjectKind, label: &str) -> Result<()> {
    if id.kind() != kind {
        bail!("{label} must be a {kind:?} provider object id");
    }
    if id.provider_id() != "github" {
        bail!("{label} must belong to the github forge provider");
    }
    Ok(())
}

#[derive(Debug)]
struct CoordinationModeSelectionDigestInput<'a> {
    repository_selector: &'a str,
    anchor_item: &'a ForgeItem,
    journal_ref: &'a str,
    anchor_commit_oid: &'a str,
    pointer_filename: &'a str,
    trusted_actors: &'a [ForgeActor],
    timing: ClaimTiming,
    approved_actor: &'a ForgeActor,
}

fn selection_digest(input: &CoordinationModeSelectionDigestInput<'_>) -> Result<String> {
    stable_json_digest(&(
        "maco_coordination_mode_selection_v1",
        input.repository_selector,
        input.anchor_item.provider_item_id(),
        input.anchor_item.revision(),
        input.journal_ref,
        input.anchor_commit_oid,
        input.pointer_filename,
        input.trusted_actors,
        input.timing,
        input.approved_actor.provider_actor_id(),
    ))
}

fn stored_selection(
    operator_config_path: String,
    operator_input_sha256: String,
    input: &OperatorCoordinationModeInput,
    anchor_item: &ForgeItem,
    adapter: &CoordinationGithubAdapterConfig,
) -> Result<StoredCoordinationSelection> {
    let timing = ClaimTiming::new(
        input.claim_timing.heartbeat_interval_seconds,
        input.claim_timing.stale_after_seconds,
    )?;
    let digest = selection_digest(&CoordinationModeSelectionDigestInput {
        repository_selector: &input.repository_selector,
        anchor_item,
        journal_ref: &input.journal_ref,
        anchor_commit_oid: &input.anchor_commit_oid,
        pointer_filename: &input.pointer_filename,
        trusted_actors: &input.trusted_actors,
        timing,
        approved_actor: adapter.approved_actor(),
    })?;
    Ok(StoredCoordinationSelection {
        operator_config_path,
        operator_input_sha256,
        selection_digest: digest,
        repository_selector: input.repository_selector.clone(),
        anchor_item: anchor_item.clone(),
        journal_ref: input.journal_ref.clone(),
        anchor_commit_oid: input.anchor_commit_oid.clone(),
        pointer_filename: input.pointer_filename.clone(),
        trusted_actors: input.trusted_actors.clone(),
        timing,
        approved_actor: adapter.approved_actor().clone(),
    })
}

fn adapter_from_stored(
    worktree: &Path,
    stored: &StoredCoordinationSelection,
    runner: &impl CoordinationGithubRunner,
) -> Result<CoordinationGithubAdapterConfig> {
    CoordinationGithubAdapterConfig::try_new(
        CoordinationGithubAdapterOpenInput {
            worktree: worktree.to_path_buf(),
            repository_selector: stored.repository_selector.clone(),
            anchor_item: stored.anchor_item.clone(),
            journal_ref: stored.journal_ref.clone(),
            anchor_commit_oid: stored.anchor_commit_oid.clone(),
            pointer_path: Some(stored.pointer_filename.clone()),
            trusted_actors: stored.trusted_actors.clone(),
            timing: stored.timing,
        },
        runner,
    )
}

fn service_from_stored<R: CoordinationGithubRunner>(
    worktree: &Path,
    stored: &StoredCoordinationSelection,
    runner: R,
) -> Result<CoordinationAdmissionService<CoordinationGithubTransport<R>>> {
    let config = adapter_from_stored(worktree, stored, &runner)?;
    let publication_live_verifier: Option<
        Arc<dyn super::coordination_effect::PublicationEffectLiveVerifier + Send + Sync>,
    > = Some(Arc::new(ParentPublicationProviderVerifier::new(
        worktree.to_path_buf(),
    )));
    let service =
        CoordinationAdmissionService::from_github(config, runner, None, publication_live_verifier);
    service.remote_authority_snapshot()?;
    Ok(service)
}

fn repository_common_root(repo_path: &Path) -> Result<SafeRoot> {
    let repo = git_repository::discover(repo_path)?;
    SafeRoot::open_existing(repo.commondir()).with_context(|| {
        format!(
            "Git common directory is not a safe current-user-owned directory: {}",
            repo.commondir().display()
        )
    })
}

fn open_existing_maco_root(common_root: &SafeRoot) -> Result<SafeRoot> {
    let maco = common_root
        .bind_existing_managed_direct_child_directory("maco")
        .context("MACO state parent directory is unsafe")?;
    SafeRoot::open_existing(maco.path()).context("MACO state parent binding is unsafe")
}

fn optional_read_only_authenticator(repo_path: &Path) -> Result<Option<RepositoryAuthenticator>> {
    let common_root = repository_common_root(repo_path)?;
    if !common_root.direct_child_exists("maco")? {
        return Ok(None);
    }
    let maco_root = open_existing_maco_root(&common_root)?;
    if !maco_root.direct_child_exists("state")? {
        return Ok(None);
    }
    Ok(Some(repository_authenticator_key_only(repo_path)?))
}

fn active_local_sync_claim_count(repo_path: &Path) -> Result<Option<usize>> {
    let common_root = repository_common_root(repo_path)?;
    if !common_root.direct_child_exists("maco")? {
        return Ok(None);
    }
    let _maco_root = open_existing_maco_root(&common_root)?;
    let repo = git_repository::discover(repo_path)?;
    let state = RepositoryStateRoot::open_existing(&repo, "claims.json", "claims.lock")?;
    if !state
        .root()
        .direct_child_exists(ClaimsSnapshotSpec::ROOT_NAME)?
    {
        return Ok(Some(0));
    }
    let authenticator = repository_authenticator_key_only(repo_path)?;
    if !AuthenticatedSnapshotStore::<ClaimsSnapshotSpec, ClaimsProbeSnapshot>::initialized(
        &authenticator,
        CLAIMS_LOGICAL_ID,
    )? {
        return Ok(Some(0));
    }
    let snapshot = AuthenticatedSnapshotStore::<ClaimsSnapshotSpec, ClaimsProbeSnapshot>::read_existing_current(
        authenticator,
        CLAIMS_LOGICAL_ID,
    )?;
    Ok(Some(snapshot.value.claims.len()))
}

fn local_sync_has_active_claims(repo: &Path) -> Result<bool> {
    Ok(matches!(active_local_sync_claim_count(repo)?, Some(count) if count > 0))
}

fn refuse_selection_change<R: CoordinationGithubRunner + Clone>(
    repo: &Path,
    worktree: &Path,
    stored: &StoredCoordinationSelection,
    runner: &R,
) -> Result<()> {
    if local_sync_has_active_claims(repo)? {
        bail!("remote coordination selection cannot change while local sync claims are active");
    }
    if worktree_has_planned_coordination_pending_intents(worktree)? {
        bail!(
            "remote coordination selection cannot change while a local coordination operation is pending"
        );
    }
    let service = service_from_stored(worktree, stored, runner.clone())?;
    let authority = service.remote_authority_snapshot()?;
    if !authority.active_owners().is_empty() {
        bail!(
            "remote coordination selection cannot change while remote authority has active owners"
        );
    }
    if !authority.pending_reservations().is_empty() {
        bail!(
            "remote coordination selection cannot change while remote authority has pending effect reservations"
        );
    }
    Ok(())
}

fn validate_stored_selection(selection: &StoredCoordinationSelection) -> Result<()> {
    let recomputed = selection_digest(&CoordinationModeSelectionDigestInput {
        repository_selector: &selection.repository_selector,
        anchor_item: &selection.anchor_item,
        journal_ref: &selection.journal_ref,
        anchor_commit_oid: &selection.anchor_commit_oid,
        pointer_filename: &selection.pointer_filename,
        trusted_actors: &selection.trusted_actors,
        timing: selection.timing,
        approved_actor: &selection.approved_actor,
    })?;
    if recomputed != selection.selection_digest {
        bail!("authenticated coordination mode selection digest does not match stored fields");
    }
    Ok(())
}

fn validate_authenticated_state(
    snapshot: &AuthenticatedSnapshot<AuthenticatedCoordinationModeState>,
) -> Result<()> {
    if snapshot.value.version != 1
        || snapshot.value.snapshot_revision != snapshot.generation
        || snapshot.value.snapshot_revision != snapshot.token
    {
        bail!("authenticated coordination mode snapshot binding or revision is inconsistent");
    }
    if let Some(selection) = snapshot.value.selection.as_ref() {
        validate_stored_selection(selection)?;
    }
    Ok(())
}

fn read_authenticated_state(
    repo_path: &Path,
) -> Result<Option<AuthenticatedCoordinationModeState>> {
    let Some(authenticator) = optional_read_only_authenticator(repo_path)? else {
        return Ok(None);
    };
    if !AuthenticatedSnapshotStore::<
        CoordinationModeSnapshotSpec,
        AuthenticatedCoordinationModeState,
    >::initialized(&authenticator, COORDINATION_MODE_LOGICAL_ID)?
    {
        return Ok(None);
    }
    let snapshot = AuthenticatedSnapshotStore::<
        CoordinationModeSnapshotSpec,
        AuthenticatedCoordinationModeState,
    >::read_existing_current(authenticator, COORDINATION_MODE_LOGICAL_ID)?;
    validate_authenticated_state(&snapshot)?;
    Ok(Some(snapshot.value))
}

fn status_from_selection(
    selection: &StoredCoordinationSelection,
) -> RemoteCoordinationStatusReport {
    RemoteCoordinationStatusReport {
        selected: true,
        selection_digest: Some(selection.selection_digest.clone()),
        repository_selector: Some(selection.repository_selector.clone()),
        anchor_issue_number: Some(selection.anchor_item.number()),
        journal_ref: Some(selection.journal_ref.clone()),
        anchor_commit_oid: Some(selection.anchor_commit_oid.clone()),
        claim_timing: Some(selection.timing),
        operator_config_path: Some(selection.operator_config_path.clone()),
    }
}

pub(crate) fn remote_coordination_status(repo: &Path) -> Result<RemoteCoordinationStatusReport> {
    let state = read_authenticated_state(repo)?;
    Ok(match state.and_then(|state| state.selection) {
        Some(selection) => status_from_selection(&selection),
        None => RemoteCoordinationStatusReport {
            selected: false,
            selection_digest: None,
            repository_selector: None,
            anchor_issue_number: None,
            journal_ref: None,
            anchor_commit_oid: None,
            claim_timing: None,
            operator_config_path: None,
        },
    })
}

pub(crate) fn load_selected_remote_service(
    repo: &Path,
) -> Result<Option<Arc<ProductionCoordinationService>>> {
    load_selected_remote_service_with_runner(repo, ProductionCoordinationGithubRunner)
}

pub(crate) fn load_selected_remote_service_with_runner<R: CoordinationGithubRunner>(
    repo: &Path,
    runner: R,
) -> Result<Option<Arc<CoordinationAdmissionService<CoordinationGithubTransport<R>>>>> {
    let worktree = repo_workdir(repo)?;
    let state = read_authenticated_state(repo)?;
    let Some(state) = state else {
        return Ok(None);
    };
    let Some(stored) = state.selection else {
        return Ok(None);
    };
    let service = service_from_stored(&worktree, &stored, runner)?;
    Ok(Some(Arc::new(service)))
}

fn ensure_mode_snapshot_store(
    repo_path: &Path,
    state: &RepositoryStateRoot,
    lock: &RepositoryStateLock,
) -> Result<
    AuthenticatedSnapshotStore<CoordinationModeSnapshotSpec, AuthenticatedCoordinationModeState>,
> {
    state.verify(lock)?;
    let authenticator = repository_auth_writer(repo_path)?
        .into_authenticator()
        .context("coordination mode authenticated write")?;
    if AuthenticatedSnapshotStore::<CoordinationModeSnapshotSpec, AuthenticatedCoordinationModeState>::initialized(
        &authenticator,
        COORDINATION_MODE_LOGICAL_ID,
    )? {
        let store = AuthenticatedSnapshotStore::open_instance(authenticator, COORDINATION_MODE_LOGICAL_ID)?;
        validate_authenticated_state(store.current())?;
        state.verify(lock)?;
        return Ok(store);
    }
    let writer = repository_auth_writer(repo_path)?;
    let binding = writer.authenticator().binding().clone();
    let initial = AuthenticatedCoordinationModeState {
        version: 1,
        snapshot_revision: 1,
        repository: binding,
        selection: None,
    };
    let store = AuthenticatedSnapshotStore::create(
        writer.into_authenticator()?,
        COORDINATION_MODE_LOGICAL_ID,
        1,
        initial,
    )?;
    validate_authenticated_state(store.current())?;
    state.verify(lock)?;
    Ok(store)
}

pub(crate) fn configure_remote_coordination_with_runner<R: CoordinationGithubRunner + Clone>(
    repo: &Path,
    operator_config_path: &Path,
    runner: R,
) -> Result<RemoteCoordinationConfigureReport> {
    require_supported_operator_config_platform()?;
    let relative_path = normalize_repo_relative_path(operator_config_path)
        .context("coordination operator config path must be repository-relative")?;
    let raw = read_operator_config(repo, &relative_path)?;
    let operator_input_sha256 = sha256_hex(&raw);
    let input = parse_operator_input(&raw)?;
    let anchor_item = forge_item_from_operator(&input)?;
    let worktree = repo_workdir(repo)?;
    let adapter = CoordinationGithubAdapterConfig::try_new(
        CoordinationGithubAdapterOpenInput {
            worktree: worktree.to_path_buf(),
            repository_selector: input.repository_selector.clone(),
            anchor_item: anchor_item.clone(),
            journal_ref: input.journal_ref.clone(),
            anchor_commit_oid: input.anchor_commit_oid.clone(),
            pointer_path: Some(input.pointer_filename.clone()),
            trusted_actors: input.trusted_actors.clone(),
            timing: ClaimTiming::new(
                input.claim_timing.heartbeat_interval_seconds,
                input.claim_timing.stale_after_seconds,
            )?,
        },
        &runner,
    )?;
    let stored = stored_selection(
        relative_path.display().to_string(),
        operator_input_sha256,
        &input,
        &anchor_item,
        &adapter,
    )?;

    let git_repo = git_repository::discover(repo)?;
    let state = open_mode_state(&git_repo)?;
    let lock = state.lock()?;
    let mut store = ensure_mode_snapshot_store(repo, &state, &lock)?;
    if store.current().value.repository != *store.authenticator().binding() {
        bail!("authenticated coordination mode repository binding is inconsistent");
    }
    if let Some(existing) = store.current().value.selection.clone() {
        if existing.selection_digest == stored.selection_digest {
            state.verify(&lock)?;
            return Ok(RemoteCoordinationConfigureReport {
                configured: true,
                idempotent: true,
                selection_digest: stored.selection_digest,
                repository_selector: stored.repository_selector,
                anchor_issue_number: stored.anchor_item.number(),
                journal_ref: stored.journal_ref,
                anchor_commit_oid: stored.anchor_commit_oid,
                claim_timing: stored.timing,
                operator_config_path: stored.operator_config_path,
            });
        }
        refuse_selection_change(repo, &worktree, &existing, &runner)?;
    }
    let next_token = store
        .current()
        .token
        .checked_add(1)
        .context("authenticated coordination mode snapshot token overflowed")?;
    let next = AuthenticatedCoordinationModeState {
        version: 1,
        snapshot_revision: next_token,
        repository: store.current().value.repository.clone(),
        selection: Some(stored.clone()),
    };
    store.commit(next_token, next)?;
    state.verify(&lock)?;
    Ok(RemoteCoordinationConfigureReport {
        configured: true,
        idempotent: false,
        selection_digest: stored.selection_digest,
        repository_selector: stored.repository_selector,
        anchor_issue_number: stored.anchor_item.number(),
        journal_ref: stored.journal_ref,
        anchor_commit_oid: stored.anchor_commit_oid,
        claim_timing: stored.timing,
        operator_config_path: stored.operator_config_path,
    })
}

pub(crate) fn configure_remote_coordination(
    repo: &Path,
    operator_config_path: &Path,
) -> Result<RemoteCoordinationConfigureReport> {
    configure_remote_coordination_with_runner(
        repo,
        operator_config_path,
        ProductionCoordinationGithubRunner,
    )
}

pub(crate) fn disable_remote_coordination_with_runner<R: CoordinationGithubRunner + Clone>(
    repo: &Path,
    runner: R,
) -> Result<RemoteCoordinationDisableReport> {
    let worktree = repo_workdir(repo)?;
    let git_repo = git_repository::discover(repo)?;
    let state = open_mode_state(&git_repo)?;
    let lock = state.lock()?;
    let mut store = ensure_mode_snapshot_store(repo, &state, &lock)?;
    let existing = store.current().value.selection.clone();
    let Some(existing) = existing else {
        state.verify(&lock)?;
        return Ok(RemoteCoordinationDisableReport {
            disabled: true,
            was_selected: false,
        });
    };
    refuse_selection_change(repo, &worktree, &existing, &runner)?;
    let next_token = store
        .current()
        .token
        .checked_add(1)
        .context("authenticated coordination mode snapshot token overflowed")?;
    let next = AuthenticatedCoordinationModeState {
        version: 1,
        snapshot_revision: next_token,
        repository: store.current().value.repository.clone(),
        selection: None,
    };
    store.commit(next_token, next)?;
    state.verify(&lock)?;
    Ok(RemoteCoordinationDisableReport {
        disabled: true,
        was_selected: true,
    })
}

pub(crate) fn disable_remote_coordination(repo: &Path) -> Result<RemoteCoordinationDisableReport> {
    disable_remote_coordination_with_runner(repo, ProductionCoordinationGithubRunner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::publication::coordination_github::CoordinationGithubOperation;
    use crate::worktree::WorktreeManager;
    use git2::Repository;
    use std::{
        collections::VecDeque,
        fs,
        sync::{Arc, Mutex},
    };
    use tempfile::TempDir;

    const ANCHOR_OID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    struct ScriptedRunner {
        responses: Arc<Mutex<VecDeque<String>>>,
    }

    impl Clone for ScriptedRunner {
        fn clone(&self) -> Self {
            Self {
                responses: Arc::clone(&self.responses),
            }
        }
    }

    impl ScriptedRunner {
        fn new(responses: impl IntoIterator<Item = String>) -> Self {
            Self {
                responses: Arc::new(Mutex::new(responses.into_iter().collect())),
            }
        }
    }

    impl CoordinationGithubRunner for ScriptedRunner {
        fn run(
            &self,
            _config: &CoordinationGithubAdapterConfig,
            label: &str,
            operation: CoordinationGithubOperation,
        ) -> Result<String> {
            let response = self
                .responses
                .lock()
                .expect("responses")
                .pop_front()
                .with_context(|| format!("scripted coordination response missing for {label:?}"))?;
            match operation {
                CoordinationGithubOperation::JournalRefHead { .. } => {
                    let value: serde_json::Value =
                        serde_json::from_str(&response).with_context(|| {
                            format!("JournalRefHead fixture for {label} was not JSON: {response}")
                        })?;
                    if value
                        .get("object")
                        .and_then(|object| object.get("sha"))
                        .is_none()
                    {
                        bail!(
                            "JournalRefHead fixture for {label} must include object.sha, got {response}"
                        );
                    }
                }
                CoordinationGithubOperation::AnchorItemComments { .. } => {
                    serde_json::from_str::<serde_json::Value>(&response).with_context(|| {
                        format!("AnchorItemComments fixture for {label} was not JSON: {response}")
                    })?;
                }
                _ => {}
            }
            Ok(response)
        }
    }

    fn github_node_stable_id(raw: &str) -> String {
        format!("node:sha256:{}", sha256_hex(raw.as_bytes()))
    }

    fn sample_operator_json(extra_field: Option<(&str, &str)>) -> String {
        let mut value = serde_json::json!({
            "schema_version": 1,
            "repository_selector": "github.com/meta-develop/maco",
            "repository_provider_node_id": {
                "provider_id": "github",
                "kind": "repository",
                "stable_id": github_node_stable_id("R_repo")
            },
            "anchor_issue_number": 89,
            "anchor_issue_provider_node_id": {
                "provider_id": "github",
                "kind": "item",
                "stable_id": github_node_stable_id("I_issue")
            },
            "anchor_item_revision": "revision:1",
            "journal_ref": "refs/heads/maco/coordination/journal",
            "anchor_commit_oid": ANCHOR_OID,
            "pointer_filename": "maco-coordination.json",
            "trusted_actors": [{
                "provider_id": "github",
                "provider_actor_id": {
                    "provider_id": "github",
                    "kind": "actor",
                    "stable_id": github_node_stable_id("A_trusted")
                },
                "canonical_handle": "trusted-a",
                "reported_kind": "human"
            }],
            "claim_timing": {
                "heartbeat_interval_seconds": 10,
                "stale_after_seconds": 30
            }
        });
        if let Some((key, val)) = extra_field {
            value
                .as_object_mut()
                .expect("object")
                .insert(key.to_string(), serde_json::Value::String(val.to_string()));
        }
        value.to_string()
    }

    fn identity_responses() -> [String; 3] {
        [
            serde_json::json!({"node_id":"R_repo","full_name":"meta-develop/maco"}).to_string(),
            serde_json::json!({
                "node_id":"I_issue","number":89,
                "url":"https://api.github.com/repos/meta-develop/maco/issues/89",
                "html_url":"https://github.com/meta-develop/maco/issues/89",
                "updated_at":"2026-08-16T00:00:00Z","pull_request":null
            })
            .to_string(),
            serde_json::json!({"node_id":"A_trusted","login":"trusted-a","type":"User"})
                .to_string(),
        ]
    }

    fn protected_branch_json(enforce_admins: bool) -> String {
        serde_json::json!({
            "enforce_admins": { "enabled": enforce_admins },
            "allow_force_pushes": { "enabled": false },
            "allow_deletions": { "enabled": false }
        })
        .to_string()
    }

    fn configure_responses(enforce_admins: bool) -> Vec<String> {
        identity_responses()
            .into_iter()
            .chain(std::iter::once(protected_branch_json(enforce_admins)))
            .collect()
    }

    fn authority_load_responses() -> Vec<String> {
        vec![
            serde_json::json!({"object":{"sha":ANCHOR_OID}}).to_string(),
            "[]".to_string(),
        ]
    }

    /// Load after configure: `try_new` (repo, issue, actor, protection) then authority
    /// (`JournalRefHead`, empty `AnchorItemComments` page).
    fn load_responses() -> Vec<String> {
        configure_responses(true)
            .into_iter()
            .chain(authority_load_responses())
            .chain(authority_load_responses())
            .collect()
    }

    fn init_repo() -> TempDir {
        let temp = TempDir::new().expect("tempdir");
        WorktreeManager::init_repository(temp.path(), "main").expect("init repo");
        temp
    }

    #[test]
    fn load_selected_remote_service_defaults_to_none() {
        let temp = init_repo();
        let state_root = temp.path().join(".git").join("maco").join("state");
        assert!(
            !state_root.exists(),
            "fixture must start without repository authentication state"
        );
        let loaded = load_selected_remote_service(temp.path()).expect("load");
        assert!(loaded.is_none());
        assert!(
            !state_root.exists(),
            "read-only selection load must not bootstrap repository authentication state"
        );
    }

    #[test]
    fn passive_load_errors_on_partial_repository_authentication() {
        let temp = init_repo();
        let state_root = temp.path().join(".git").join("maco").join("state");
        fs::create_dir_all(&state_root).expect("partial auth tree");
        let message = match load_selected_remote_service(temp.path()) {
            Err(error) => format!("{error:#}"),
            Ok(_) => panic!("partial auth must refuse load"),
        };
        assert!(message.contains("repository authentication MAC key is missing"));
    }

    #[cfg(unix)]
    #[test]
    fn passive_load_errors_on_unsafe_maco_symlink_without_bootstrap() {
        let temp = init_repo();
        let outside = tempfile::tempdir().expect("outside");
        fs::write(outside.path().join("probe.txt"), b"x").expect("outside file");
        std::os::unix::fs::symlink(outside.path(), temp.path().join(".git/maco")).expect("symlink");
        let state_root = temp.path().join(".git").join("maco").join("state");
        let message = match load_selected_remote_service(temp.path()) {
            Err(error) => format!("{error:#}"),
            Ok(_) => panic!("unsafe maco must refuse load"),
        };
        assert!(
            message.contains("unsafe") || message.contains("MACO state parent"),
            "unexpected error: {message}"
        );
        assert!(
            !state_root.exists(),
            "unsafe maco entry must not be treated as absent or bootstrap auth state"
        );
    }

    #[test]
    fn disable_errors_when_local_claims_snapshot_is_corrupt() {
        let temp = init_repo();
        fs::write(
            temp.path().join("coordination.json"),
            sample_operator_json(None),
        )
        .expect("write config");
        configure_remote_coordination_with_runner(
            temp.path(),
            Path::new("coordination.json"),
            ScriptedRunner::new(configure_responses(true)),
        )
        .expect("configure");
        let sim = crate::sync_store::remote_coordination::test_support::SimTransport::new(
            temp.path().to_path_buf(),
        );
        let store =
            crate::sync_store::remote_coordination::test_support::open_sync_with_sim_remote(
                temp.path(),
                sim,
            )
            .expect("sync");
        store
            .claim_paths_with_timing("agent-a", ["README.md"], ClaimTiming::default())
            .expect("claim");
        let locator = format!(
            ".snapshot-locator-{}.json",
            sha256_hex(CLAIMS_LOGICAL_ID.as_bytes())
        );
        let locator_path = temp
            .path()
            .join(".git")
            .join("maco")
            .join("state")
            .join("authenticated-claims-state-v1")
            .join(locator);
        fs::write(&locator_path, b"not-authenticated-locator").expect("corrupt locator");
        let error = disable_remote_coordination_with_runner(
            temp.path(),
            ScriptedRunner::new(load_responses()),
        )
        .expect_err("corrupt claims snapshot");
        let message = format!("{error:#}");
        assert!(!message.contains("local sync claims are active"));
        assert!(
            message.contains("inventory")
                || message.contains("snapshot")
                || message.contains("authenticated")
                || message.contains("locator")
        );
    }

    #[test]
    fn passive_load_errors_after_repository_authentication_key_removed() {
        let temp = init_repo();
        fs::write(
            temp.path().join("coordination.json"),
            sample_operator_json(None),
        )
        .expect("write config");
        configure_remote_coordination_with_runner(
            temp.path(),
            Path::new("coordination.json"),
            ScriptedRunner::new(configure_responses(true)),
        )
        .expect("configure");
        let key_path = temp
            .path()
            .join(".git")
            .join("maco")
            .join("state")
            .join("artifact_finalization_hmac_v1.key");
        fs::remove_file(&key_path).expect("remove auth key");
        let message = match load_selected_remote_service(temp.path()) {
            Err(error) => format!("{error:#}"),
            Ok(_) => panic!("corrupt auth must refuse load"),
        };
        assert!(message.contains("repository authentication MAC key is missing"));
    }

    #[test]
    fn operator_input_rejects_unknown_fields() {
        let temp = init_repo();
        fs::write(
            temp.path().join("coordination.json"),
            sample_operator_json(Some(("unexpected", "value"))),
        )
        .expect("write config");
        let error = configure_remote_coordination_with_runner(
            temp.path(),
            Path::new("coordination.json"),
            ScriptedRunner::new([]),
        )
        .expect_err("unknown field");
        let message = format!("{error:#}");
        assert!(message.contains("unknown field"));
    }

    #[cfg(unix)]
    #[test]
    fn operator_input_rejects_symlink_escape() {
        let temp = init_repo();
        let outside = tempfile::tempdir().expect("outside");
        fs::write(outside.path().join("secret.json"), b"{}").expect("secret");
        std::os::unix::fs::symlink(
            outside.path().join("secret.json"),
            temp.path().join("link.json"),
        )
        .expect("symlink");
        let error = read_operator_config(temp.path(), Path::new("link.json")).expect_err("symlink");
        assert!(error.to_string().contains("coordination operator config"));
    }

    #[test]
    fn configure_refuses_unverifiable_branch_protection() {
        let temp = init_repo();
        fs::write(
            temp.path().join("coordination.json"),
            sample_operator_json(None),
        )
        .expect("write config");
        let runner = ScriptedRunner::new(configure_responses(false));
        let error = configure_remote_coordination_with_runner(
            temp.path(),
            Path::new("coordination.json"),
            runner,
        )
        .expect_err("admin bypass");
        assert!(error.to_string().contains("enforce admins"));
    }

    #[test]
    fn configure_and_load_use_frozen_snapshot_not_edited_source_file() {
        let temp = init_repo();
        let path = temp.path().join("coordination.json");
        fs::write(&path, sample_operator_json(None)).expect("write config");
        let runner = ScriptedRunner::new(configure_responses(true));
        configure_remote_coordination_with_runner(
            temp.path(),
            Path::new("coordination.json"),
            runner,
        )
        .expect("configure");

        fs::write(
            &path,
            sample_operator_json(Some(("repository_selector", "github.com/other/repo"))),
        )
        .expect("edit source");

        let load_runner = ScriptedRunner::new(load_responses());
        let service =
            load_selected_remote_service_with_runner(temp.path(), load_runner).expect("load");
        let service = service.expect("selected");
        assert_eq!(
            service
                .remote_authority_snapshot()
                .expect("authority")
                .journal_head_oid(),
            ANCHOR_OID
        );
        let status = remote_coordination_status(temp.path()).expect("status");
        assert_eq!(
            status.repository_selector.as_deref(),
            Some("github.com/meta-develop/maco")
        );
    }

    #[test]
    fn disable_refuses_while_local_claim_active() {
        let temp = init_repo();
        fs::write(
            temp.path().join("coordination.json"),
            sample_operator_json(None),
        )
        .expect("write config");
        configure_remote_coordination_with_runner(
            temp.path(),
            Path::new("coordination.json"),
            ScriptedRunner::new(configure_responses(true)),
        )
        .expect("configure");
        let sim = crate::sync_store::remote_coordination::test_support::SimTransport::new(
            temp.path().to_path_buf(),
        );
        let store =
            crate::sync_store::remote_coordination::test_support::open_sync_with_sim_remote(
                temp.path(),
                sim,
            )
            .expect("sync");
        store
            .claim_paths_with_timing("agent-a", ["README.md"], ClaimTiming::default())
            .expect("claim");
        let error = disable_remote_coordination_with_runner(
            temp.path(),
            ScriptedRunner::new(load_responses()),
        )
        .expect_err("active claim");
        assert!(error.to_string().contains("local sync claims"));
    }

    #[test]
    fn configure_rejects_authenticated_identity_mismatch() {
        let temp = init_repo();
        let mut json: serde_json::Value =
            serde_json::from_str(&sample_operator_json(None)).expect("json");
        json["repository_provider_node_id"]["stable_id"] =
            serde_json::Value::String("R_wrong".into());
        fs::write(temp.path().join("coordination.json"), json.to_string()).expect("write config");
        let error = configure_remote_coordination_with_runner(
            temp.path(),
            Path::new("coordination.json"),
            ScriptedRunner::new(configure_responses(true)),
        )
        .expect_err("identity mismatch");
        assert!(error
            .to_string()
            .contains("authenticated repository identity"));
    }

    #[test]
    fn tampered_authenticated_selection_refuses_load() {
        let temp = init_repo();
        fs::write(
            temp.path().join("coordination.json"),
            sample_operator_json(None),
        )
        .expect("write config");
        configure_remote_coordination_with_runner(
            temp.path(),
            Path::new("coordination.json"),
            ScriptedRunner::new(configure_responses(true)),
        )
        .expect("configure");
        let repo = Repository::open(temp.path()).expect("open");
        let state = open_mode_state(&repo).expect("state");
        let lock = state.lock().expect("lock");
        let mut store = ensure_mode_snapshot_store(temp.path(), &state, &lock).expect("store");
        let next_token = store.current().token.checked_add(1).expect("token");
        let mut tampered = store.current().value.clone();
        tampered.snapshot_revision = next_token;
        tampered.selection.as_mut().expect("selection").journal_ref =
            "refs/heads/tampered".to_string();
        store.commit(next_token, tampered).expect("commit tampered");
        drop(store);
        drop(lock);
        let message =
            match load_selected_remote_service_with_runner(temp.path(), ScriptedRunner::new([])) {
                Err(error) => format!("{error:#}"),
                Ok(_) => panic!("tampered selection must refuse load"),
            };
        assert!(
            message.contains("selection digest does not match stored fields"),
            "unexpected refusal chain: {message}"
        );
    }
}
