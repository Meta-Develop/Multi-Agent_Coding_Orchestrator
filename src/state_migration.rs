//! Explicit, offline migration of legacy repository state into an authenticated
//! generation-one manifest.
//!
//! The migration is deliberately opt-in. Dry-run performs bounded no-follow
//! validation and takes every existing legacy kernel lock without modifying
//! the repository. Apply holds those locks for its full lifecycle, hardens the
//! legacy state tree, and publishes a signed immutable manifest. A private
//! transaction outside the state root makes the chmod-to-manifest crash window
//! forward recoverable.

use crate::{
    artifacts::{
        repository_auth_writer, repository_authenticator_key_only,
        state_auth::{
            authenticated_state_consumers, sha256_hex, AuthenticationDomain, AuthenticationTag,
            BoundStateLock, RepositoryAuthBinding, RepositoryAuthWriter, RepositoryAuthenticator,
        },
    },
    authenticated_snapshot::{AuthenticatedSnapshotStore, SnapshotSpec},
    safe_state::{
        identity_for_path, stable_checksum, AtomicStateWriter, BoundedRegularReader,
        DirectChildType, FileIdentity, KernelStateLock, ReservedDirectory, SafeRoot,
    },
    semantic_coord::{
        validate_legacy_semantic_payload, ResolvedSemanticSymbol, SemanticIntent,
        SemanticIntentToken, SemanticSnapshotSpec,
    },
    state_journal::{AuthenticatedStateJournal, JournalIdentity, JournalSpec},
    sync::{PathClaim, SyncCoordinator, SyncSnapshot},
    sync_store::{validate_state_path, ClaimsSnapshotSpec},
    worktree::ManagedSnapshotSpec,
};
use anyhow::{bail, Context, Result};
#[cfg(test)]
use git2::Repository;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::{
    ffi::{OsStrExt, OsStringExt},
    fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    io::AsRawFd,
};

const MIGRATION_VERSION: u32 = 1;
const MANIFEST_INSTANCE_ID: &str = "legacy-state-v1";
const MANIFEST_ROOT_NAME: &str = "state-migration-manifests-v1";
const TRANSACTION_ROOT_NAME: &str = "maco-state-migration-v1";
const TRANSACTION_FILE: &str = "transaction.json";
const RECEIPT_FILE: &str = "receipt.json";
const TRANSACTION_LOCK: &str = "migration.lock";
const MAX_LEGACY_STATE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_TRANSACTION_BYTES: u64 = 2 * 1024 * 1024;
const MAX_STATE_ENTRIES: usize = 4_096;
const AUTH_KEY_FILE: &str = "artifact_finalization_hmac_v1.key";
const AUTH_KEY_LOCK: &str = "artifact_finalization_hmac_v1.lock";
const AUTH_EPOCH_FILE: &str = "repository_auth_epoch_v1";
const LEGACY_STORES: [(&str, &str); 3] = [
    ("claims", "claims.json"),
    ("semantic_intents", "semantic_intents.json"),
    ("managed_worktrees", "managed_worktrees.json"),
];
const LEGACY_LOCKS: [&str; 3] = [
    "claims.lock",
    "semantic_intents.lock",
    "managed_worktrees.lock",
];
pub(crate) const LEGACY_PUBLICATION_TRANSACTIONS_DIR: &str = "publication-transactions";

pub(crate) enum StateMigrationManifestSpec {}

impl JournalSpec for StateMigrationManifestSpec {
    const FORMAT_VERSION: u32 = 1;
    const NAMESPACE: &'static str = "state_migration_manifest";
    const ROOT_NAME: &'static str = MANIFEST_ROOT_NAME;
    const ROOT_LOCK_NAME: &'static str = ".state-migrations.lock";
    const INSTANCE_LOCK_NAME: &'static str = ".state-migration.lock";
    const HEAD_FILE_NAME: &'static str = ".head.json";
    const RECORD_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0state-migration-record\0v1\0");
    const HEAD_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0state-migration-head\0v1\0");
    const MAX_RECORDS: usize = 16;
    const MAX_RECORD_BYTES: u64 = 8 * 1024 * 1024;
    const MAX_TOTAL_BYTES: u64 = 16 * 1024 * 1024;
    const MAX_PHASE_BYTES: usize = 64;
    const MAX_SUBJECT_BYTES: usize = 128;
    const MAX_INSTANCE_ID_BYTES: usize = 128;
}

impl SnapshotSpec for StateMigrationManifestSpec {
    const SNAPSHOT_FORMAT_VERSION: u32 = 1;
    const LOCATOR_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0state-migration-locator\0v1\0");
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StateMigrationMode {
    DryRun,
    Apply,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StateMigrationStatus {
    Ready,
    Applied,
    AlreadyApplied,
    NoLegacyState,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LegacyStateEntry {
    pub store: String,
    pub file: String,
    pub present: bool,
    pub size: u64,
    pub sha256: Option<String>,
    pub legacy_checksum: Option<String>,
    pub file_identity: Option<FileIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<LegacyStateProvenance>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LegacyStateProvenance {
    OperatorAttestedUnauthenticatedImport,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StateMigrationManifest {
    pub version: u32,
    pub repository: RepositoryAuthBinding,
    pub entries: Vec<LegacyStateEntry>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub inventoried_directories: BTreeMap<String, FileIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StateMigrationReport {
    pub version: u32,
    pub mode: StateMigrationMode,
    pub status: StateMigrationStatus,
    pub legacy_state_root: String,
    pub transaction_phase: Option<MigrationPhase>,
    pub entries: Vec<LegacyStateEntry>,
    pub hardened: bool,
    pub manifest_generation: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct StateMigrationOptions {
    pub acknowledge_unauthenticated_claims_v1: bool,
    pub expected_claims_v1_sha256: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) enum LegacyAdoption {
    Missing,
    Present(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum LegacyRetirementPhase {
    Pending,
    Active,
}

const RETIREMENT_INTENT_FILE: &str = ".legacy-retirement.intent.json";
const RETIREMENT_SIDECAR_FILE: &str = ".legacy-retirement.sidecar";
pub(crate) const LEGACY_RETIREMENT_DOMAIN: AuthenticationDomain =
    AuthenticationDomain::new(b"MACO\0legacy-state-retirement\0v1\0");

pub(crate) fn is_legacy_retirement_metadata_name(name: &str) -> bool {
    matches!(name, RETIREMENT_INTENT_FILE | RETIREMENT_SIDECAR_FILE)
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LegacyRetirementFaultPoint {
    Sidecar,
    Intent,
    PendingTombstone,
    ActiveTombstone,
}

#[cfg(test)]
thread_local! {
    static LEGACY_RETIREMENT_FAULT: std::cell::Cell<Option<LegacyRetirementFaultPoint>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn set_legacy_retirement_fault(point: LegacyRetirementFaultPoint) {
    LEGACY_RETIREMENT_FAULT.with(|slot| slot.set(Some(point)));
}

#[cfg(test)]
fn run_legacy_retirement_fault(point: LegacyRetirementFaultPoint) -> Result<()> {
    let triggered = LEGACY_RETIREMENT_FAULT.with(|slot| {
        if slot.get() == Some(point) {
            slot.set(None);
            true
        } else {
            false
        }
    });
    if triggered {
        bail!("injected legacy retirement fault after {point:?}");
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyRetirementDescriptor {
    original_present: bool,
    original_identity: Option<FileIdentity>,
    original_sha256: Option<String>,
    sidecar_file: String,
    sidecar_identity: FileIdentity,
    sidecar_size: u64,
    sidecar_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyRetirementIntent {
    version: u32,
    consumer: String,
    file: String,
    repository: RepositoryAuthBinding,
    descriptor: LegacyRetirementDescriptor,
    mac: AuthenticationTag,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyRetirementTombstone {
    version: u32,
    phase: LegacyRetirementPhase,
    consumer: String,
    file: String,
    repository: RepositoryAuthBinding,
    descriptor: LegacyRetirementDescriptor,
    snapshot_identity: Option<JournalIdentity>,
    snapshot_generation: Option<u64>,
    mac: AuthenticationTag,
}

pub(crate) struct LegacyRetirementPreparation {
    adoption: LegacyAdoption,
    writer: RepositoryAuthWriter,
}

impl LegacyRetirementPreparation {
    pub(crate) fn into_parts(self) -> (LegacyAdoption, RepositoryAuthWriter) {
        (self.adoption, self.writer)
    }
}

/// Starts or resumes the legacy-retirement transaction before a consumer
/// publishes its first authenticated snapshot. The trusted legacy bytes are
/// copied into the consumer root and bound by a signed intent before the
/// legacy filename becomes a version-3 pending tombstone. Consequently a
/// crash leaves either the untouched legacy state, or a state that old
/// version-2 writers reject and new code can recover from the signed sidecar.
pub(crate) fn prepare_legacy_retirement<S: SnapshotSpec>(
    repo_path: &Path,
    consumer: &str,
    file_name: &str,
    domain: AuthenticationDomain,
    legacy_fence: &impl Fn() -> Result<()>,
) -> Result<LegacyRetirementPreparation> {
    legacy_fence()?;
    let repository = crate::git_repository::discover(repo_path)?;
    let common_root = SafeRoot::open_existing(repository.commondir())?;
    let state_root = SafeRoot::open_existing(common_root.path().join("maco/state"))?;
    if state_root.direct_child_exists(file_name)? {
        let bytes =
            BoundedRegularReader::read_direct(&state_root, file_name, MAX_LEGACY_STATE_BYTES)?;
        if serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|value| value.get("version").and_then(serde_json::Value::as_u64))
            == Some(3)
        {
            // A version marker is attacker-controlled until its MAC has been
            // checked with an already-established repository key. Never let
            // this recovery branch bootstrap a key, epoch, or consumer root.
            let existing_authenticator = repository_authenticator_key_only(repo_path)?;
            let tombstone = verify_retirement_tombstone(
                &existing_authenticator,
                consumer,
                file_name,
                domain,
                &bytes,
            )?;
            existing_authenticator.verify_epoch()?;
            if tombstone.phase != LegacyRetirementPhase::Pending
                || tombstone.snapshot_identity.is_some()
                || tombstone.snapshot_generation.is_some()
            {
                bail!("legacy retirement is already active but no authenticated snapshot locator was found");
            }
            let writer = repository_auth_writer(repo_path)?;
            if writer.authenticator().binding() != existing_authenticator.binding() {
                bail!(
                    "legacy retirement authentication binding changed after tombstone verification"
                );
            }
            let consumer_root =
                AuthenticatedStateJournal::<S>::existing_root(writer.authenticator())
                    .context("pending legacy retirement consumer root is missing")?;
            let root_lock = BoundStateLock::acquire(&consumer_root, S::ROOT_LOCK_NAME)?;
            let intent = read_and_verify_retirement_intent(
                writer.authenticator(),
                &consumer_root,
                consumer,
                file_name,
                domain,
            )?;
            if intent.descriptor != tombstone.descriptor {
                bail!("legacy retirement pending tombstone does not match its signed intent");
            }
            let adoption = read_retirement_sidecar(&consumer_root, &intent.descriptor)?;
            root_lock.verify(&consumer_root)?;
            legacy_fence()?;
            return Ok(LegacyRetirementPreparation { adoption, writer });
        }
    }
    // This manifest preflight deliberately precedes the first auth writer so
    // untrusted legacy state cannot cause a key, epoch, or consumer root.
    let adoption = authenticated_legacy_adoption(repo_path, consumer, file_name)?;
    let original_identity = match &adoption {
        LegacyAdoption::Missing => None,
        LegacyAdoption::Present(_) => Some(identity_for_path(state_root.direct_child(file_name)?)?),
    };
    let writer = repository_auth_writer(repo_path)?;
    let consumer_root = open_consumer_retirement_root::<S>(writer.authenticator())?;
    let root_lock = BoundStateLock::acquire(&consumer_root, S::ROOT_LOCK_NAME)?;
    if consumer_root.direct_child_exists(RETIREMENT_INTENT_FILE)? {
        let intent = read_and_verify_retirement_intent(
            writer.authenticator(),
            &consumer_root,
            consumer,
            file_name,
            domain,
        )?;
        validate_retirement_descriptor_against_adoption(
            &intent.descriptor,
            &adoption,
            original_identity.as_ref(),
        )?;
        let recovered = read_retirement_sidecar(&consumer_root, &intent.descriptor)?;
        let tombstone = pending_retirement_tombstone(
            writer.authenticator(),
            consumer,
            file_name,
            domain,
            intent.descriptor,
        )?;
        write_pretty_fenced(&state_root, file_name, &tombstone, || {
            legacy_fence()?;
            root_lock.verify(&consumer_root)
        })?;
        #[cfg(test)]
        run_legacy_retirement_fault(LegacyRetirementFaultPoint::PendingTombstone)?;
        root_lock.verify(&consumer_root)?;
        legacy_fence()?;
        return Ok(LegacyRetirementPreparation {
            adoption: recovered,
            writer,
        });
    }
    if consumer_root.direct_child_exists(RETIREMENT_SIDECAR_FILE)? {
        let bytes = BoundedRegularReader::read_direct(
            &consumer_root,
            RETIREMENT_SIDECAR_FILE,
            MAX_LEGACY_STATE_BYTES,
        )?;
        let expected = match &adoption {
            LegacyAdoption::Missing => &[][..],
            LegacyAdoption::Present(bytes) => bytes.as_slice(),
        };
        if bytes != expected {
            bail!("unsigned legacy retirement sidecar does not match current trusted legacy state");
        }
        fs::remove_file(consumer_root.direct_child(RETIREMENT_SIDECAR_FILE)?)?;
        File::open(consumer_root.path())?.sync_all()?;
        legacy_fence()?;
    }
    let sidecar_bytes = match &adoption {
        LegacyAdoption::Missing => Vec::new(),
        LegacyAdoption::Present(bytes) => bytes.clone(),
    };
    AtomicStateWriter::scavenge_direct_temps(&consumer_root, RETIREMENT_SIDECAR_FILE)?;
    AtomicStateWriter::write_direct_fenced(
        &consumer_root,
        RETIREMENT_SIDECAR_FILE,
        &sidecar_bytes,
        || {
            legacy_fence()?;
            root_lock.verify(&consumer_root)
        },
    )?;
    #[cfg(test)]
    run_legacy_retirement_fault(LegacyRetirementFaultPoint::Sidecar)?;
    let descriptor = LegacyRetirementDescriptor {
        original_present: matches!(adoption, LegacyAdoption::Present(_)),
        original_identity,
        original_sha256: match &adoption {
            LegacyAdoption::Missing => None,
            LegacyAdoption::Present(bytes) => Some(sha256_hex(bytes)),
        },
        sidecar_file: RETIREMENT_SIDECAR_FILE.to_string(),
        sidecar_identity: identity_for_path(consumer_root.direct_child(RETIREMENT_SIDECAR_FILE)?)?,
        sidecar_size: u64::try_from(sidecar_bytes.len()).unwrap_or(u64::MAX),
        sidecar_sha256: sha256_hex(&sidecar_bytes),
    };
    let mut intent = LegacyRetirementIntent {
        version: 1,
        consumer: consumer.to_string(),
        file: file_name.to_string(),
        repository: writer.authenticator().binding().clone(),
        descriptor: descriptor.clone(),
        mac: AuthenticationTag::zero(),
    };
    intent.mac = writer
        .authenticator()
        .sign(domain, &legacy_retirement_intent_payload(&intent)?)?;
    write_pretty_fenced(&consumer_root, RETIREMENT_INTENT_FILE, &intent, || {
        legacy_fence()?;
        root_lock.verify(&consumer_root)
    })?;
    #[cfg(test)]
    run_legacy_retirement_fault(LegacyRetirementFaultPoint::Intent)?;
    let tombstone = pending_retirement_tombstone(
        writer.authenticator(),
        consumer,
        file_name,
        domain,
        descriptor,
    )?;
    write_pretty_fenced(&state_root, file_name, &tombstone, || {
        legacy_fence()?;
        root_lock.verify(&consumer_root)
    })?;
    #[cfg(test)]
    run_legacy_retirement_fault(LegacyRetirementFaultPoint::PendingTombstone)?;
    root_lock.verify(&consumer_root)?;
    legacy_fence()?;
    Ok(LegacyRetirementPreparation { adoption, writer })
}

pub(crate) fn finalize_legacy_retirement<S: SnapshotSpec>(
    repo_path: &Path,
    consumer: &str,
    file_name: &str,
    domain: AuthenticationDomain,
    snapshot_identity: &JournalIdentity,
    snapshot_generation: u64,
    legacy_fence: &impl Fn() -> Result<()>,
) -> Result<()> {
    legacy_fence()?;
    let repository = crate::git_repository::discover(repo_path)?;
    let common_root = SafeRoot::open_existing(repository.commondir())?;
    let state_root = SafeRoot::open_existing(common_root.path().join("maco/state"))?;
    let bytes = BoundedRegularReader::read_direct(&state_root, file_name, MAX_LEGACY_STATE_BYTES)?;
    let authenticator = repository_authenticator_key_only(repo_path)?;
    authenticator.verify_repository_binding(&snapshot_identity.repository)?;
    let prior = verify_retirement_tombstone(&authenticator, consumer, file_name, domain, &bytes)?;
    if prior.phase == LegacyRetirementPhase::Active {
        if prior.snapshot_identity.as_ref() == Some(snapshot_identity)
            && prior.snapshot_generation == Some(snapshot_generation)
        {
            cleanup_retirement_sidecar::<S>(
                &authenticator,
                consumer,
                file_name,
                domain,
                &prior.descriptor,
                legacy_fence,
            )?;
            return Ok(());
        }
        let prior_generation = prior
            .snapshot_generation
            .context("active legacy retirement tombstone has no generation")?;
        if snapshot_generation < prior_generation {
            bail!("authenticated snapshot generation rolled back behind its legacy tombstone");
        }
        if snapshot_generation == prior_generation
            && prior.snapshot_identity.as_ref() != Some(snapshot_identity)
        {
            bail!("authenticated snapshot identity changed without increasing its generation");
        }
    } else {
        let consumer_root = open_consumer_retirement_root::<S>(&authenticator)?;
        let intent = read_and_verify_retirement_intent(
            &authenticator,
            &consumer_root,
            consumer,
            file_name,
            domain,
        )?;
        if intent.descriptor != prior.descriptor {
            bail!("legacy retirement pending tombstone does not match its signed intent");
        }
        let _ = read_retirement_sidecar(&consumer_root, &intent.descriptor)?;
    }
    let mut tombstone = LegacyRetirementTombstone {
        phase: LegacyRetirementPhase::Active,
        snapshot_identity: Some(snapshot_identity.clone()),
        snapshot_generation: Some(snapshot_generation),
        mac: AuthenticationTag::zero(),
        ..prior
    };
    tombstone.mac = authenticator.sign(domain, &legacy_retirement_payload(&tombstone)?)?;
    write_pretty_fenced(&state_root, file_name, &tombstone, || {
        legacy_fence()?;
        authenticator.verify_epoch()
    })?;
    #[cfg(test)]
    run_legacy_retirement_fault(LegacyRetirementFaultPoint::ActiveTombstone)?;
    cleanup_retirement_sidecar::<S>(
        &authenticator,
        consumer,
        file_name,
        domain,
        &tombstone.descriptor,
        legacy_fence,
    )
}

fn pending_retirement_tombstone(
    authenticator: &crate::artifacts::state_auth::RepositoryAuthenticator,
    consumer: &str,
    file_name: &str,
    domain: AuthenticationDomain,
    descriptor: LegacyRetirementDescriptor,
) -> Result<LegacyRetirementTombstone> {
    let mut tombstone = LegacyRetirementTombstone {
        version: 3,
        phase: LegacyRetirementPhase::Pending,
        consumer: consumer.to_string(),
        file: file_name.to_string(),
        repository: authenticator.binding().clone(),
        descriptor,
        snapshot_identity: None,
        snapshot_generation: None,
        mac: AuthenticationTag::zero(),
    };
    tombstone.mac = authenticator.sign(domain, &legacy_retirement_payload(&tombstone)?)?;
    Ok(tombstone)
}

fn validate_retirement_descriptor_against_adoption(
    descriptor: &LegacyRetirementDescriptor,
    adoption: &LegacyAdoption,
    identity: Option<&FileIdentity>,
) -> Result<()> {
    match adoption {
        LegacyAdoption::Missing => {
            if descriptor.original_present
                || descriptor.original_identity.is_some()
                || descriptor.original_sha256.is_some()
            {
                bail!("signed retirement intent does not match missing legacy state");
            }
        }
        LegacyAdoption::Present(bytes) => {
            let digest = sha256_hex(bytes);
            if !descriptor.original_present
                || descriptor.original_identity.as_ref() != identity
                || descriptor.original_sha256.as_deref() != Some(digest.as_str())
            {
                bail!("signed retirement intent no longer matches trusted legacy state");
            }
        }
    }
    Ok(())
}

fn verify_retirement_tombstone(
    authenticator: &crate::artifacts::state_auth::RepositoryAuthenticator,
    consumer: &str,
    file_name: &str,
    domain: AuthenticationDomain,
    bytes: &[u8],
) -> Result<LegacyRetirementTombstone> {
    let tombstone: LegacyRetirementTombstone =
        serde_json::from_slice(bytes).context("legacy retirement tombstone is malformed")?;
    if tombstone.version != 3 || tombstone.consumer != consumer || tombstone.file != file_name {
        bail!("legacy retirement tombstone belongs to a different consumer");
    }
    authenticator.verify_repository_binding(&tombstone.repository)?;
    authenticator.verify_tag(
        domain,
        &legacy_retirement_payload(&tombstone)?,
        &tombstone.mac,
    )?;
    match tombstone.phase {
        LegacyRetirementPhase::Pending
            if tombstone.snapshot_identity.is_none() && tombstone.snapshot_generation.is_none() => {
        }
        LegacyRetirementPhase::Active
            if tombstone.snapshot_identity.is_some() && tombstone.snapshot_generation.is_some() => {
        }
        _ => bail!("legacy retirement tombstone phase fields are inconsistent"),
    }
    Ok(tombstone)
}

fn legacy_retirement_payload(tombstone: &LegacyRetirementTombstone) -> Result<Vec<u8>> {
    serde_json::to_vec(&(
        tombstone.version,
        &tombstone.phase,
        &tombstone.consumer,
        &tombstone.file,
        &tombstone.repository,
        &tombstone.descriptor,
        &tombstone.snapshot_identity,
        &tombstone.snapshot_generation,
    ))
    .context("failed to encode legacy retirement tombstone")
}

fn legacy_retirement_intent_payload(intent: &LegacyRetirementIntent) -> Result<Vec<u8>> {
    serde_json::to_vec(&(
        intent.version,
        &intent.consumer,
        &intent.file,
        &intent.repository,
        &intent.descriptor,
    ))
    .context("failed to encode legacy retirement intent")
}

fn open_consumer_retirement_root<S: SnapshotSpec>(
    authenticator: &crate::artifacts::state_auth::RepositoryAuthenticator,
) -> Result<SafeRoot> {
    authenticator.verify_epoch()?;
    SafeRoot::open_or_create(authenticator.state_root().path().join(S::ROOT_NAME))
        .context("failed to open authenticated consumer retirement root")
}

fn read_and_verify_retirement_intent(
    authenticator: &crate::artifacts::state_auth::RepositoryAuthenticator,
    root: &SafeRoot,
    consumer: &str,
    file_name: &str,
    domain: AuthenticationDomain,
) -> Result<LegacyRetirementIntent> {
    let bytes =
        BoundedRegularReader::read_direct(root, RETIREMENT_INTENT_FILE, MAX_LEGACY_STATE_BYTES)?;
    let intent: LegacyRetirementIntent =
        serde_json::from_slice(&bytes).context("legacy retirement intent is malformed")?;
    if intent.version != 1 || intent.consumer != consumer || intent.file != file_name {
        bail!("legacy retirement intent belongs to a different consumer");
    }
    authenticator.verify_repository_binding(&intent.repository)?;
    authenticator.verify_tag(
        domain,
        &legacy_retirement_intent_payload(&intent)?,
        &intent.mac,
    )?;
    Ok(intent)
}

fn read_retirement_sidecar(
    root: &SafeRoot,
    descriptor: &LegacyRetirementDescriptor,
) -> Result<LegacyAdoption> {
    if descriptor.sidecar_file != RETIREMENT_SIDECAR_FILE {
        bail!("legacy retirement sidecar name is not canonical");
    }
    let identity = identity_for_path(root.direct_child(RETIREMENT_SIDECAR_FILE)?)?;
    let bytes =
        BoundedRegularReader::read_direct(root, RETIREMENT_SIDECAR_FILE, MAX_LEGACY_STATE_BYTES)?;
    if identity != descriptor.sidecar_identity
        || u64::try_from(bytes.len()).unwrap_or(u64::MAX) != descriptor.sidecar_size
        || sha256_hex(&bytes) != descriptor.sidecar_sha256
    {
        bail!("legacy retirement sidecar no longer matches its signed descriptor");
    }
    if descriptor.original_present {
        let digest = sha256_hex(&bytes);
        if descriptor.original_sha256.as_deref() != Some(digest.as_str()) {
            bail!("legacy retirement sidecar does not match the original digest");
        }
        Ok(LegacyAdoption::Present(bytes))
    } else if !bytes.is_empty()
        || descriptor.original_identity.is_some()
        || descriptor.original_sha256.is_some()
    {
        bail!("signed missing legacy retirement descriptor is inconsistent");
    } else {
        Ok(LegacyAdoption::Missing)
    }
}

fn cleanup_retirement_sidecar<S: SnapshotSpec>(
    authenticator: &crate::artifacts::state_auth::RepositoryAuthenticator,
    consumer: &str,
    file_name: &str,
    domain: AuthenticationDomain,
    descriptor: &LegacyRetirementDescriptor,
    legacy_fence: &impl Fn() -> Result<()>,
) -> Result<()> {
    legacy_fence()?;
    let root = open_consumer_retirement_root::<S>(authenticator)?;
    let root_lock = BoundStateLock::acquire(&root, S::ROOT_LOCK_NAME)?;
    let intent_identity = if root.direct_child_exists(RETIREMENT_INTENT_FILE)? {
        let before = identity_for_path(root.direct_child(RETIREMENT_INTENT_FILE)?)?;
        let intent =
            read_and_verify_retirement_intent(authenticator, &root, consumer, file_name, domain)?;
        if &intent.descriptor != descriptor {
            bail!("legacy retirement cleanup intent does not match the active tombstone");
        }
        let after = identity_for_path(root.direct_child(RETIREMENT_INTENT_FILE)?)?;
        if before != after {
            bail!("legacy retirement cleanup intent identity changed during verification");
        }
        Some(before)
    } else {
        None
    };
    for (name, expected) in [
        (RETIREMENT_SIDECAR_FILE, Some(&descriptor.sidecar_identity)),
        (RETIREMENT_INTENT_FILE, intent_identity.as_ref()),
    ] {
        if root.direct_child_exists(name)? {
            if let Some(expected) = expected {
                if identity_for_path(root.direct_child(name)?)? != *expected {
                    bail!("legacy retirement cleanup file identity changed");
                }
            }
            fs::remove_file(root.direct_child(name)?)?;
            File::open(root.path())?.sync_all()?;
            legacy_fence()?;
        }
    }
    root_lock.verify(&root)?;
    legacy_fence()
}

fn write_pretty_fenced<T: Serialize>(
    root: &SafeRoot,
    name: &str,
    value: &T,
    verify: impl Fn() -> Result<()>,
) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    AtomicStateWriter::scavenge_direct_temps(root, name)?;
    AtomicStateWriter::write_direct_fenced(root, name, &bytes, verify)
}

/// True when a completed signed migration inventoried the leftover
/// `publication-transactions` directory and that same directory inode is
/// still present. Publication treats that as retirement: the plaintext
/// journals stay on disk as evidence and no longer block authenticated
/// external effects.
pub(crate) fn legacy_publication_journals_are_retired(repo_path: &Path) -> Result<bool> {
    let repository = crate::git_repository::discover(repo_path)?;
    let common_root = match SafeRoot::open_existing(repository.commondir()) {
        Ok(root) => root,
        Err(_) => return Ok(false),
    };
    let state_path = common_root.path().join("maco/state");
    let state_root = match SafeRoot::open_existing(&state_path) {
        Ok(root) => root,
        Err(_) => return Ok(false),
    };
    if !manifest_exists(&state_root)? {
        return Ok(false);
    }
    if !state_root.direct_child_exists(LEGACY_PUBLICATION_TRANSACTIONS_DIR)? {
        return Ok(false);
    }
    let authenticator = repository_authenticator_key_only(repo_path)?;
    authenticator.verify_epoch()?;
    let store = AuthenticatedSnapshotStore::<
        StateMigrationManifestSpec,
        StateMigrationManifest,
    >::open_instance(authenticator, MANIFEST_INSTANCE_ID)?;
    let manifest = &store.current().value;
    if manifest.repository != store.identity().repository {
        bail!("signed migration manifest repository binding is inconsistent");
    }
    let Some(expected) = manifest
        .inventoried_directories
        .get(LEGACY_PUBLICATION_TRANSACTIONS_DIR)
    else {
        return Ok(false);
    };
    let path = state_root.direct_child(LEGACY_PUBLICATION_TRANSACTIONS_DIR)?;
    let metadata = fs::symlink_metadata(&path)?;
    validate_owned_directory(&metadata, &path)?;
    Ok(&identity_for_path(&path)? == expected)
}

/// Returns legacy bytes only when the signed migration manifest binds the
/// exact repository, inode, size, digest, store name, and file name. A legacy
/// file without that evidence is never treated as trusted first-use state.
pub(crate) fn authenticated_legacy_adoption(
    repo_path: &Path,
    store_name: &str,
    file_name: &str,
) -> Result<LegacyAdoption> {
    let repository = crate::git_repository::discover(repo_path)?;
    let common_root = SafeRoot::open_existing(repository.commondir())?;
    let state_path = common_root.path().join("maco/state");
    let state_root = match SafeRoot::open_existing(&state_path) {
        Ok(root) => root,
        Err(error) if fs::symlink_metadata(&state_path).is_err() => {
            let _ = error;
            return Ok(LegacyAdoption::Missing);
        }
        Err(error) => return Err(error),
    };
    let legacy_exists = state_root.direct_child_exists(file_name)?;
    if !state_root.direct_child_exists(MANIFEST_ROOT_NAME)? {
        if legacy_exists {
            bail!(
                "legacy {file_name} has no signed migration manifest; run `maco state migrate --repo <repo> --apply` offline before retrying"
            );
        }
        return Ok(LegacyAdoption::Missing);
    }
    let authenticator = repository_authenticator_key_only(repo_path)?;
    authenticator.verify_epoch()?;
    let manifest_store = AuthenticatedSnapshotStore::<
        StateMigrationManifestSpec,
        StateMigrationManifest,
    >::open_instance(authenticator, MANIFEST_INSTANCE_ID)?;
    let manifest = &manifest_store.current().value;
    if manifest.repository != manifest_store.identity().repository {
        bail!("signed migration manifest repository binding is inconsistent");
    }
    let entry = manifest
        .entries
        .iter()
        .find(|entry| entry.store == store_name && entry.file == file_name)
        .context("signed migration manifest has no entry for this state consumer")?;
    if !entry.present {
        if legacy_exists {
            bail!("legacy state exists despite a signed missing migration entry");
        }
        return Ok(LegacyAdoption::Missing);
    }
    if !legacy_exists {
        bail!("signed migration entry refers to a missing legacy state file");
    }
    let bytes = BoundedRegularReader::read_direct(&state_root, file_name, MAX_LEGACY_STATE_BYTES)?;
    let identity = identity_for_path(state_root.direct_child(file_name)?)?;
    let digest = sha256_hex(&bytes);
    if entry.file_identity.as_ref() != Some(&identity)
        || entry.size != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
        || entry.sha256.as_deref() != Some(digest.as_str())
    {
        bail!("legacy state no longer matches its signed migration manifest entry");
    }
    match entry.provenance {
        Some(LegacyStateProvenance::OperatorAttestedUnauthenticatedImport) => {
            if store_name != "claims"
                || file_name != "claims.json"
                || entry.legacy_checksum.is_some()
            {
                bail!("signed operator-attested legacy provenance is inconsistent");
            }
            decode_checksumless_legacy_claims_state(&bytes)
                .context("signed checksum-less claims-v1 state is malformed")?;
        }
        None if store_name == "claims"
            && file_name == "claims.json"
            && decode_checksumless_legacy_claims_state(&bytes).is_ok() =>
        {
            bail!(
                "signed checksum-less claims-v1 state lacks its operator-attested unauthenticated-import provenance"
            );
        }
        None => {}
    }
    Ok(LegacyAdoption::Present(bytes))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MigrationPhase {
    Planned,
    PermissionsHardened,
    ManifestPublished,
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MigrationTransaction {
    version: u32,
    phase: MigrationPhase,
    common_dir_identity: FileIdentity,
    state_root_identity: FileIdentity,
    original_state_mode: u32,
    original_file_modes: BTreeMap<String, u32>,
    created_locks: Vec<String>,
    entries: Vec<LegacyStateEntry>,
    checksum: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MigrationReceipt {
    version: u32,
    manifest_generation: u64,
    manifest_token: u64,
    manifest_sha256: String,
    entries: Vec<LegacyStateEntry>,
}

#[derive(Debug)]
struct LoadedMigrationTransaction {
    value: MigrationTransaction,
    root_identity: FileIdentity,
    root: SafeRoot,
    root_binding: ReservedDirectory,
}

struct MigrationTransactionBoundary<'a> {
    root: &'a SafeRoot,
    binding: &'a ReservedDirectory,
    lock: &'a KernelStateLock,
    expected: &'a MigrationTransaction,
    identity: &'a FileIdentity,
}

#[derive(Debug)]
struct LegacyPreflight {
    common_dir: PathBuf,
    common_dir_identity: FileIdentity,
    common_root: SafeRoot,
    state_root: SafeRoot,
    original_state_mode: u32,
    original_file_modes: BTreeMap<String, u32>,
    entries: Vec<LegacyStateEntry>,
    retired_tombstones: BTreeMap<String, (FileIdentity, String)>,
    inventoried_directories: BTreeMap<String, FileIdentity>,
    root_entries: BTreeMap<String, FileIdentity>,
    existing_lock_names: Vec<String>,
    expected_bindings: ExpectedLegacyBindings,
}

/// Validates or applies the offline migration. `apply == false` is guaranteed
/// not to create, chmod, rewrite, or remove repository state.
pub(crate) fn migrate_repository_state(
    repo_path: impl AsRef<Path>,
    apply: bool,
) -> Result<StateMigrationReport> {
    migrate_repository_state_with_options(repo_path, apply, &StateMigrationOptions::default())
}

pub(crate) fn migrate_repository_state_with_options(
    repo_path: impl AsRef<Path>,
    apply: bool,
    options: &StateMigrationOptions,
) -> Result<StateMigrationReport> {
    validate_migration_options(options)?;
    let repo_path = repo_path.as_ref();
    let repository = crate::git_repository::discover(repo_path).with_context(|| {
        format!(
            "failed to discover repository for state migration from {}",
            repo_path.display()
        )
    })?;
    let common_dir = repository.commondir().to_path_buf();
    let state_path = common_dir.join("maco/state");
    if fs::symlink_metadata(&state_path).is_err() {
        return Ok(StateMigrationReport {
            version: MIGRATION_VERSION,
            mode: migration_mode(apply),
            status: StateMigrationStatus::NoLegacyState,
            legacy_state_root: ".git/maco/state".to_string(),
            transaction_phase: None,
            entries: missing_manifest_entries(),
            hardened: false,
            manifest_generation: None,
        });
    }

    let preflight = preflight_legacy_state(repo_path, &common_dir, &state_path, options)?;
    let mut locks = acquire_existing_locks(&preflight)?;
    let transaction = load_transaction_if_present(&preflight)?;
    if let Some(transaction) = &transaction {
        validate_transaction(&transaction.value, &preflight)?;
    }
    run_migration_after_preflight_hook();
    verify_preflight_repository_binding(&preflight)?;

    if manifest_exists(&preflight.state_root)? {
        let report =
            verify_existing_manifest(repo_path, apply, &preflight, &locks, transaction.as_ref())?;
        return Ok(report);
    }

    if !apply {
        return Ok(StateMigrationReport {
            version: MIGRATION_VERSION,
            mode: StateMigrationMode::DryRun,
            status: StateMigrationStatus::Ready,
            legacy_state_root: ".git/maco/state".to_string(),
            transaction_phase: transaction.as_ref().map(|loaded| loaded.value.phase),
            entries: preflight.entries.clone(),
            hardened: state_is_hardened(&preflight, &locks)?,
            manifest_generation: None,
        });
    }

    let (transaction_root, transaction_binding, existing_transaction) = match transaction {
        Some(loaded) => {
            verify_transaction_root_binding(
                &preflight,
                &loaded.root,
                &loaded.root_binding,
                &loaded.root_identity,
            )?;
            (loaded.root, loaded.root_binding, Some(loaded.value))
        }
        None => {
            verify_preflight_repository_binding(&preflight)?;
            let root =
                SafeRoot::open_or_create(preflight.common_root.path().join(TRANSACTION_ROOT_NAME))
                    .context("failed to open owner-private state migration transaction root")?;
            let binding = preflight
                .common_root
                .bind_existing_direct_child_directory(TRANSACTION_ROOT_NAME)
                .context("failed to bind the new migration transaction root")?;
            let identity = root.identity().clone();
            verify_transaction_root_binding(&preflight, &root, &binding, &identity)?;
            (root, binding, None)
        }
    };
    let transaction_lock = KernelStateLock::acquire_direct(&transaction_root, TRANSACTION_LOCK)?;
    transaction_lock.verify_direct_binding(&transaction_root)?;

    create_and_acquire_missing_legacy_locks(&preflight, &mut locks)?;
    revalidate_preflight(&preflight)?;

    apply_migration(
        repo_path,
        &preflight,
        &transaction_root,
        &transaction_binding,
        existing_transaction,
        locks,
        transaction_lock,
    )
}

fn validate_migration_options(options: &StateMigrationOptions) -> Result<()> {
    match (
        options.acknowledge_unauthenticated_claims_v1,
        options.expected_claims_v1_sha256.as_deref(),
    ) {
        (false, None) => Ok(()),
        (false, Some(_)) => {
            bail!(
                "expected claims-v1 SHA-256 requires explicit unauthenticated claims-v1 acknowledgement"
            )
        }
        (true, None) => {
            bail!("unauthenticated claims-v1 acknowledgement requires an expected SHA-256")
        }
        (true, Some(expected)) if is_lowercase_sha256(expected) => Ok(()),
        (true, Some(_)) => {
            bail!("expected claims-v1 SHA-256 must be exactly 64 lowercase hexadecimal characters")
        }
    }
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn migration_mode(apply: bool) -> StateMigrationMode {
    if apply {
        StateMigrationMode::Apply
    } else {
        StateMigrationMode::DryRun
    }
}

#[cfg(test)]
thread_local! {
    static MIGRATION_AFTER_PREFLIGHT_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn set_migration_after_preflight_hook(hook: impl FnOnce() + 'static) {
    MIGRATION_AFTER_PREFLIGHT_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_migration_after_preflight_hook() {
    let hook = MIGRATION_AFTER_PREFLIGHT_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(not(test))]
fn run_migration_after_preflight_hook() {}

#[cfg(test)]
type MigrationAfterChildBindHook = Option<(String, Box<dyn FnOnce()>)>;

#[cfg(test)]
thread_local! {
    static MIGRATION_AFTER_CHILD_BIND_HOOK: std::cell::RefCell<MigrationAfterChildBindHook> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn set_migration_after_child_bind_hook(name: &str, hook: impl FnOnce() + 'static) {
    MIGRATION_AFTER_CHILD_BIND_HOOK.with(|slot| {
        *slot.borrow_mut() = Some((name.to_string(), Box::new(hook)));
    });
}

#[cfg(test)]
fn run_migration_after_child_bind_hook(name: &str) {
    let hook = MIGRATION_AFTER_CHILD_BIND_HOOK.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.as_ref().is_some_and(|(expected, _)| expected == name) {
            slot.take().map(|(_, hook)| hook)
        } else {
            None
        }
    });
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(not(test))]
fn run_migration_after_child_bind_hook(_name: &str) {}

#[cfg(test)]
type MigrationBeforeFinalVerificationHook = Option<Box<dyn FnOnce()>>;

#[cfg(test)]
thread_local! {
    static MIGRATION_BEFORE_FINAL_VERIFICATION_HOOK: std::cell::RefCell<MigrationBeforeFinalVerificationHook> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn set_migration_before_final_verification_hook(hook: impl FnOnce() + 'static) {
    MIGRATION_BEFORE_FINAL_VERIFICATION_HOOK.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(hook));
    });
}

#[cfg(test)]
fn run_migration_before_final_verification_hook() {
    let hook = MIGRATION_BEFORE_FINAL_VERIFICATION_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(not(test))]
fn run_migration_before_final_verification_hook() {}

fn preflight_legacy_state(
    repo_path: &Path,
    common_dir: &Path,
    state_path: &Path,
    options: &StateMigrationOptions,
) -> Result<LegacyPreflight> {
    let common_root = SafeRoot::open_existing(common_dir)
        .context("Git common directory is unsafe for state migration")?;
    let state_root = SafeRoot::open_existing(state_path)
        .context("legacy state root is not a current-user-owned no-follow directory")?;
    let state_metadata = fs::symlink_metadata(state_root.path())?;
    validate_owned_directory(&state_metadata, state_root.path())?;

    let mut original_file_modes = BTreeMap::new();
    let mut existing_lock_names = Vec::new();
    let mut observed_files = BTreeSet::new();
    let mut inventoried_directories = BTreeMap::new();
    let mut root_entries = BTreeMap::new();
    for name in state_root.direct_child_names_bounded(MAX_STATE_ENTRIES)? {
        let name = name
            .into_string()
            .map_err(|_| anyhow::anyhow!("legacy state entry name is not UTF-8"))?;
        let path = state_root.direct_child(&name)?;
        let metadata = fs::symlink_metadata(&path)?;
        let identity = identity_for_path(&path)?;
        if root_entries.insert(name.clone(), identity.clone()).is_some() {
            bail!("legacy state root contains a duplicate entry name");
        }
        if metadata.file_type().is_dir() {
            if !is_known_state_directory(&name) {
                bail!("unexpected directory in legacy state root: {name}");
            }
            validate_owned_directory(&metadata, &path)?;
            if is_known_legacy_directory(&name)
                && inventoried_directories
                    .insert(name.clone(), identity)
                    .is_some()
            {
                bail!("legacy state root contains a duplicate inventoried directory");
            }
            continue;
        }
        if !is_known_state_file(&name) {
            bail!("unexpected file in legacy state root: {name}");
        }
        validate_owned_regular_file(&metadata, &path, file_bound(&name))?;
        let mode = file_mode(&metadata);
        original_file_modes.insert(name.clone(), mode);
        observed_files.insert(name.clone());
        if is_known_lock_name(&name) {
            existing_lock_names.push(name);
        }
    }
    state_root.verify()?;
    common_root.verify()?;

    let managed_repository = if observed_files.contains("managed_worktrees.json") {
        let primary_workdir = common_root
            .path()
            .file_name()
            .is_some_and(|name| name == ".git")
            .then(|| common_root.path().parent())
            .flatten()
            .context(
                "managed worktree registry migration requires an embedded primary .git directory",
            )?;
        let primary_root = SafeRoot::open_existing(primary_workdir)
            .context("primary repository workdir is unsafe for managed state migration")?;
        Some(ManagedRepositoryBindingWire {
            common_dir: encode_persisted_path_wire(common_root.path())?,
            common_dir_identity: common_root.identity().clone(),
            repository_workdir: encode_persisted_path_wire(primary_root.path())?,
            repository_workdir_identity: primary_root.identity().clone(),
        })
    } else {
        None
    };
    let expected_bindings = ExpectedLegacyBindings {
        repository_state: LegacyRepositoryBinding {
            common_dir_path_checksum: stable_checksum(&filesystem_path_bytes(common_root.path())),
            common_dir_identity: common_root.identity().clone(),
        },
        managed_repository,
    };

    let mut entries = Vec::with_capacity(LEGACY_STORES.len());
    let mut retired_tombstones = BTreeMap::new();
    for (store, file_name) in LEGACY_STORES {
        if observed_files.contains(file_name) {
            let bytes =
                BoundedRegularReader::read_direct(&state_root, file_name, MAX_LEGACY_STATE_BYTES)?;
            if serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .and_then(|value| value.get("version").and_then(serde_json::Value::as_u64))
                == Some(3)
            {
                retired_tombstones.insert(
                    file_name.to_string(),
                    (
                        identity_for_path(state_root.direct_child(file_name)?)?,
                        sha256_hex(&bytes),
                    ),
                );
                entries.push(retired_manifest_entry(repo_path, store, file_name, &bytes)?);
                continue;
            }
            let validation = validate_legacy_state(file_name, &bytes, &expected_bindings, options)?;
            entries.push(LegacyStateEntry {
                store: store.to_string(),
                file: file_name.to_string(),
                present: true,
                size: u64::try_from(bytes.len()).context("legacy state size overflowed")?,
                sha256: Some(sha256_hex(&bytes)),
                legacy_checksum: validation.legacy_checksum,
                file_identity: Some(identity_for_path(state_root.direct_child(file_name)?)?),
                provenance: validation.provenance,
            });
        } else {
            entries.push(missing_manifest_entry(store, file_name));
        }
    }

    existing_lock_names.sort();
    Ok(LegacyPreflight {
        common_dir: common_dir.to_path_buf(),
        common_dir_identity: common_root.identity().clone(),
        common_root,
        state_root,
        original_state_mode: file_mode(&state_metadata),
        original_file_modes,
        entries,
        retired_tombstones,
        inventoried_directories,
        root_entries,
        existing_lock_names,
        expected_bindings,
    })
}

fn verify_preflight_repository_binding(preflight: &LegacyPreflight) -> Result<()> {
    preflight.common_root.verify()?;
    preflight.state_root.verify()?;
    if preflight.common_root.identity() != &preflight.common_dir_identity
        || preflight.common_root.path() != preflight.common_dir
    {
        bail!("migration Git common-directory capability changed after preflight");
    }

    let maco_binding = preflight
        .common_root
        .bind_existing_managed_direct_child_directory("maco")
        .context("migration state parent is no longer bound to the Git common directory")?;
    let maco_root = SafeRoot::open_existing(maco_binding.path())?;
    if maco_root.identity() != maco_binding.identity() {
        bail!("migration state parent binding changed while it was opened");
    }
    let state_binding = maco_root
        .bind_existing_managed_direct_child_directory("state")
        .context("migration state root is no longer bound to its state parent")?;
    if state_binding.identity() != preflight.state_root.identity()
        || state_binding.path() != preflight.state_root.path()
    {
        bail!("migration state root is no longer associated with the preflight repository");
    }
    state_binding.verify(&maco_root)?;
    maco_root.verify()?;
    maco_binding.verify(&preflight.common_root)?;
    preflight.state_root.verify()?;
    preflight.common_root.verify()
}

fn verify_migration_authenticator_binding(
    preflight: &LegacyPreflight,
    authenticator: &RepositoryAuthenticator,
) -> Result<()> {
    verify_preflight_repository_binding(preflight)?;
    authenticator.verify()?;
    if authenticator.binding().common_dir_identity != preflight.common_dir_identity
        || authenticator.state_root().identity() != preflight.state_root.identity()
    {
        bail!("migration authentication writer is bound to a different repository state root");
    }
    verify_preflight_repository_binding(preflight)
}

fn missing_manifest_entries() -> Vec<LegacyStateEntry> {
    LEGACY_STORES
        .iter()
        .map(|(store, file)| missing_manifest_entry(store, file))
        .collect()
}

fn retired_manifest_entry(
    repo_path: &Path,
    store_name: &str,
    file_name: &str,
    bytes: &[u8],
) -> Result<LegacyStateEntry> {
    let manifest_authenticator = repository_authenticator_key_only(repo_path)?;
    let manifest_store = AuthenticatedSnapshotStore::<
        StateMigrationManifestSpec,
        StateMigrationManifest,
    >::open_instance(manifest_authenticator, MANIFEST_INSTANCE_ID)?;
    let entry = manifest_store
        .current()
        .value
        .entries
        .iter()
        .find(|entry| entry.store == store_name && entry.file == file_name)
        .cloned()
        .context("signed migration manifest has no retired consumer entry")?;
    verify_retired_tombstone_binding(repo_path, store_name, file_name, bytes, &entry)?;
    Ok(entry)
}

fn verify_retired_tombstone_binding(
    repo_path: &Path,
    store_name: &str,
    file_name: &str,
    bytes: &[u8],
    entry: &LegacyStateEntry,
) -> Result<()> {
    let authenticator = repository_authenticator_key_only(repo_path)?;
    let tombstone = verify_retirement_tombstone(
        &authenticator,
        store_name,
        file_name,
        LEGACY_RETIREMENT_DOMAIN,
        bytes,
    )?;
    if tombstone.phase != LegacyRetirementPhase::Active {
        bail!("state migration inspection found a pending legacy retirement; reopen the owning consumer to recover it first");
    }
    let identity = tombstone
        .snapshot_identity
        .as_ref()
        .context("active retirement tombstone has no snapshot identity")?;
    let generation = tombstone
        .snapshot_generation
        .context("active retirement tombstone has no snapshot generation")?;
    match store_name {
        "claims" => AuthenticatedSnapshotStore::<ClaimsSnapshotSpec, serde_json::Value>::verify_locator_anchor(
            &authenticator,
            "claims",
            identity,
            generation,
        )?,
        "semantic_intents" => AuthenticatedSnapshotStore::<
            SemanticSnapshotSpec,
            serde_json::Value,
        >::verify_locator_anchor(
            &authenticator, "semantic-intents", identity, generation
        )?,
        "managed_worktrees" => AuthenticatedSnapshotStore::<
            ManagedSnapshotSpec,
            serde_json::Value,
        >::verify_locator_anchor(
            &authenticator, "managed-worktrees", identity, generation
        )?,
        _ => bail!("unknown legacy retirement consumer"),
    }
    if entry.present {
        if !tombstone.descriptor.original_present
            || tombstone.descriptor.original_identity != entry.file_identity
            || tombstone.descriptor.original_sha256 != entry.sha256
            || tombstone.descriptor.sidecar_size != entry.size
            || tombstone.descriptor.sidecar_sha256 != entry.sha256.clone().unwrap_or_default()
        {
            bail!("active retirement tombstone does not match the original signed migration entry");
        }
    } else if tombstone.descriptor.original_present
        || tombstone.descriptor.original_identity.is_some()
        || tombstone.descriptor.original_sha256.is_some()
        || tombstone.descriptor.sidecar_size != 0
        || tombstone.descriptor.sidecar_sha256 != sha256_hex(&[])
    {
        bail!("active retirement tombstone does not match the signed missing migration entry");
    }
    Ok(())
}

fn missing_manifest_entry(store: &str, file: &str) -> LegacyStateEntry {
    LegacyStateEntry {
        store: store.to_string(),
        file: file.to_string(),
        present: false,
        size: 0,
        sha256: None,
        legacy_checksum: None,
        file_identity: None,
        provenance: None,
    }
}

fn is_known_authenticated_directory(name: &str) -> bool {
    authenticated_state_consumers()
        .iter()
        .any(|source| source.root_name == name)
}

fn is_known_legacy_directory(name: &str) -> bool {
    name == LEGACY_PUBLICATION_TRANSACTIONS_DIR
}

fn is_known_state_directory(name: &str) -> bool {
    is_known_authenticated_directory(name) || is_known_legacy_directory(name)
}

fn is_known_state_file(name: &str) -> bool {
    LEGACY_STORES.iter().any(|(_, file)| *file == name)
        || is_known_lock_name(name)
        || matches!(name, AUTH_KEY_FILE | AUTH_EPOCH_FILE)
}

fn is_known_lock_name(name: &str) -> bool {
    LEGACY_LOCKS.contains(&name)
        || matches!(name, AUTH_KEY_LOCK | "repository-mutation.lock")
        || authenticated_state_consumers()
            .iter()
            .any(|source| source.state_root_lock_names.contains(&name))
        || name
            .strip_prefix("managed-worktree-")
            .and_then(|tail| tail.strip_suffix(".execution.lock"))
            .is_some_and(is_canonical_lock_component)
}

fn is_canonical_lock_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn file_bound(name: &str) -> u64 {
    if name.ends_with(".json") {
        MAX_LEGACY_STATE_BYTES
    } else if matches!(name, AUTH_KEY_FILE | AUTH_EPOCH_FILE) {
        32
    } else {
        0
    }
}

#[cfg(unix)]
fn validate_owned_directory(metadata: &fs::Metadata, path: &Path) -> Result<()> {
    let attributes = OwnedDirectoryAttributes::from_metadata(metadata);
    if !attributes.are_safe_for(unsafe { libc::geteuid() }) {
        bail!(
            "state migration directory is not a current-user-owned, non-writable no-follow directory: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OwnedDirectoryAttributes {
    is_symlink: bool,
    is_directory: bool,
    owner: u32,
    hard_link_count: u64,
    mode: u32,
}

#[cfg(unix)]
impl OwnedDirectoryAttributes {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            is_symlink: metadata.file_type().is_symlink(),
            is_directory: metadata.file_type().is_dir(),
            owner: metadata.uid(),
            hard_link_count: metadata.nlink(),
            mode: metadata.permissions().mode() & 0o777,
        }
    }

    fn are_safe_for(self, expected_owner: u32) -> bool {
        !self.is_symlink
            && self.is_directory
            && self.owner == expected_owner
            && self.hard_link_count != 0
            && self.mode & 0o022 == 0
    }
}

#[cfg(not(unix))]
fn validate_owned_directory(_metadata: &fs::Metadata, path: &Path) -> Result<()> {
    bail!(
        "state migration directory ACL validation is unsupported: {}",
        path.display()
    )
}

#[cfg(unix)]
fn validate_owned_regular_file(metadata: &fs::Metadata, path: &Path, max_bytes: u64) -> Result<()> {
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.len() > max_bytes
    {
        bail!(
            "legacy state entry is not a bounded current-user-owned single-link regular file: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_owned_regular_file(
    _metadata: &fs::Metadata,
    path: &Path,
    _max_bytes: u64,
) -> Result<()> {
    bail!(
        "legacy state file ACL validation is unsupported: {}",
        path.display()
    )
}

#[cfg(unix)]
fn file_mode(metadata: &fs::Metadata) -> u32 {
    metadata.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn file_mode(_metadata: &fs::Metadata) -> u32 {
    0
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyRepositoryBinding {
    common_dir_path_checksum: String,
    common_dir_identity: FileIdentity,
}

#[derive(Debug, Clone)]
struct ExpectedLegacyBindings {
    repository_state: LegacyRepositoryBinding,
    managed_repository: Option<ManagedRepositoryBindingWire>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyClaimsState {
    version: u32,
    checksum: String,
    repository: LegacyRepositoryBinding,
    next_token: u64,
    claims: Vec<PathClaim>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacySemanticState {
    version: u32,
    checksum: String,
    repository: LegacyRepositoryBinding,
    next_token: u64,
    intents: Vec<SemanticIntent>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChecksumlessLegacyClaimsStateWire {
    version: u32,
    next_token: u64,
    claims: Vec<ChecksumlessLegacyPathClaimWire>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChecksumlessLegacyPathClaimWire {
    token: u64,
    agent_id: String,
    paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChecksumlessLegacyClaimsState {
    pub(crate) next_token: u64,
    pub(crate) claims: Vec<PathClaim>,
}

const MAX_LEGACY_SYNC_CLAIMS: usize = 4_096;
const MAX_LEGACY_SYNC_PATHS: usize = 16_384;
const MAX_LEGACY_AGENT_ID_BYTES: usize = 128;

pub(crate) fn decode_checksumless_legacy_claims_state(
    bytes: &[u8],
) -> Result<ChecksumlessLegacyClaimsState> {
    let wire: ChecksumlessLegacyClaimsStateWire = serde_json::from_slice(bytes)
        .context("failed to decode strict checksum-less claims-v1 state")?;
    if wire.version != 1 {
        bail!("checksum-less claims state is not supported version 1");
    }
    if wire.next_token == 0 {
        bail!("checksum-less claims state next_token must be nonzero");
    }
    if wire.claims.len() > MAX_LEGACY_SYNC_CLAIMS {
        bail!(
            "checksum-less claims state exceeds its claim budget of {} records",
            MAX_LEGACY_SYNC_CLAIMS
        );
    }

    let mut path_count = 0usize;
    let claims = wire
        .claims
        .into_iter()
        .map(|claim| {
            if claim.agent_id.len() > MAX_LEGACY_AGENT_ID_BYTES {
                bail!(
                    "checksum-less claims state agent id exceeds {} bytes",
                    MAX_LEGACY_AGENT_ID_BYTES
                );
            }
            path_count = path_count
                .checked_add(claim.paths.len())
                .context("checksum-less claims state path count overflow")?;
            if path_count > MAX_LEGACY_SYNC_PATHS {
                bail!(
                    "checksum-less claims state exceeds its aggregate path budget of {}",
                    MAX_LEGACY_SYNC_PATHS
                );
            }
            for path in &claim.paths {
                validate_state_path(path)?;
            }
            Ok(PathClaim {
                token: crate::sync::ClaimToken::from_u64(claim.token),
                agent_id: claim.agent_id,
                paths: claim.paths,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let snapshot = SyncSnapshot {
        next_token: wire.next_token,
        claims,
    };
    let canonical = SyncCoordinator::from_snapshot(snapshot.clone())
        .context("checksum-less claims-v1 state failed structural claim validation")?
        .to_snapshot()
        .context("failed to canonicalize checksum-less claims-v1 state")?;
    if canonical != snapshot {
        bail!("checksum-less claims-v1 state is not in the canonical pinned-writer form");
    }
    Ok(ChecksumlessLegacyClaimsState {
        next_token: snapshot.next_token,
        claims: snapshot.claims,
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChecksumlessLegacySemanticStateWire {
    version: u32,
    next_token: u64,
    intents: Vec<ChecksumlessLegacySemanticIntentWire>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChecksumlessLegacySemanticIntentWire {
    token: u64,
    agent_id: String,
    paths: Vec<PathBuf>,
    symbols: Vec<ChecksumlessLegacyResolvedSymbolWire>,
    modules: Vec<String>,
    impacted_files: Vec<PathBuf>,
    task_digest: Option<String>,
    task_excerpt: Option<String>,
    notes: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChecksumlessLegacyResolvedSymbolWire {
    id: String,
    qualified_path: String,
    name: String,
    kind: String,
    file: PathBuf,
}

#[derive(Debug)]
pub(crate) struct ChecksumlessLegacySemanticState {
    pub(crate) next_token: u64,
    pub(crate) intents: Vec<SemanticIntent>,
}

pub(crate) fn decode_checksumless_legacy_semantic_state(
    bytes: &[u8],
) -> Result<ChecksumlessLegacySemanticState> {
    let wire: ChecksumlessLegacySemanticStateWire = serde_json::from_slice(bytes)
        .context("failed to decode strict checksum-less semantic intent state")?;
    if wire.version != 1 {
        bail!("checksum-less semantic intent state is not supported version 1");
    }
    let intents = wire
        .intents
        .into_iter()
        .map(|intent| SemanticIntent {
            token: SemanticIntentToken::from_u64(intent.token),
            agent_id: intent.agent_id,
            paths: intent.paths,
            symbols: intent
                .symbols
                .into_iter()
                .map(|symbol| ResolvedSemanticSymbol {
                    id: symbol.id,
                    qualified_path: symbol.qualified_path,
                    name: symbol.name,
                    kind: symbol.kind,
                    file: symbol.file,
                })
                .collect(),
            modules: intent.modules,
            impacted_files: intent.impacted_files,
            task_digest: intent.task_digest,
            task_excerpt: intent.task_excerpt,
            notes: intent.notes,
            warnings: intent.warnings,
        })
        .collect::<Vec<_>>();
    validate_legacy_semantic_payload(wire.next_token, &intents)?;
    Ok(ChecksumlessLegacySemanticState {
        next_token: wire.next_token,
        intents,
    })
}

#[derive(Debug)]
struct LegacyStateValidation {
    legacy_checksum: Option<String>,
    provenance: Option<LegacyStateProvenance>,
}

fn validate_legacy_state(
    file_name: &str,
    bytes: &[u8],
    expected: &ExpectedLegacyBindings,
    options: &StateMigrationOptions,
) -> Result<LegacyStateValidation> {
    match file_name {
        "claims.json" => match serde_json::from_slice::<LegacyClaimsState>(bytes) {
            Ok(state) => {
                if state.version != 2 || state.next_token == 0 {
                    bail!("claims state is not supported checksummed version 2");
                }
                if state.repository != expected.repository_state {
                    bail!(
                        "claims state repository binding does not match the migration repository"
                    );
                }
                let payload = serde_json::to_vec(&(
                    state.version,
                    &state.repository,
                    state.next_token,
                    &state.claims,
                ))?;
                Ok(LegacyStateValidation {
                    legacy_checksum: Some(verify_legacy_checksum(
                        &state.checksum,
                        &payload,
                        file_name,
                    )?),
                    provenance: None,
                })
            }
            Err(_) => {
                decode_checksumless_legacy_claims_state(bytes)?;
                let observed_sha256 = sha256_hex(bytes);
                if !options.acknowledge_unauthenticated_claims_v1 {
                    bail!(
                        "checksum-less claims-v1 is unauthenticated; after independently verifying its provenance and exact bytes, retry with `--acknowledge-unauthenticated-claims-v1 --expected-claims-v1-sha256 {observed_sha256}`"
                    );
                }
                let expected_sha256 = options
                    .expected_claims_v1_sha256
                    .as_deref()
                    .context("validated claims-v1 acknowledgement lost its expected SHA-256")?;
                if expected_sha256 != observed_sha256 {
                    bail!(
                        "checksum-less claims-v1 SHA-256 mismatch: expected {expected_sha256}, observed {observed_sha256}"
                    );
                }
                Ok(LegacyStateValidation {
                    legacy_checksum: None,
                    provenance: Some(LegacyStateProvenance::OperatorAttestedUnauthenticatedImport),
                })
            }
        },
        "semantic_intents.json" => match serde_json::from_slice::<LegacySemanticState>(bytes) {
            Ok(state) => {
                if state.version != 2 || state.next_token == 0 {
                    bail!("semantic intent state is not supported checksummed version 2");
                }
                if state.repository != expected.repository_state {
                    bail!(
                            "semantic intent state repository binding does not match the migration repository"
                        );
                }
                validate_legacy_semantic_payload(state.next_token, &state.intents)?;
                let payload = serde_json::to_vec(&(
                    state.version,
                    &state.repository,
                    state.next_token,
                    &state.intents,
                ))?;
                Ok(LegacyStateValidation {
                    legacy_checksum: Some(verify_legacy_checksum(
                        &state.checksum,
                        &payload,
                        file_name,
                    )?),
                    provenance: None,
                })
            }
            Err(_) => {
                let state = decode_checksumless_legacy_semantic_state(bytes)?;
                let payload = serde_json::to_vec(&(1_u32, state.next_token, &state.intents))?;
                Ok(LegacyStateValidation {
                    legacy_checksum: Some(stable_checksum(&payload)),
                    provenance: None,
                })
            }
        },
        "managed_worktrees.json" => Ok(LegacyStateValidation {
            legacy_checksum: Some(validate_managed_worktree_checksum(
                bytes,
                expected
                    .managed_repository
                    .as_ref()
                    .context("managed worktree migration binding is unavailable")?,
            )?),
            provenance: None,
        }),
        _ => bail!("unsupported legacy state file: {file_name}"),
    }
}

fn verify_legacy_checksum(checksum: &str, payload: &[u8], file_name: &str) -> Result<String> {
    let expected = stable_checksum(payload);
    if checksum != expected {
        bail!("legacy state checksum mismatch in {file_name}");
    }
    Ok(expected)
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedPathWire {
    platform: String,
    encoding: String,
    data: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagedRepositoryBindingWire {
    common_dir: PersistedPathWire,
    common_dir_identity: FileIdentity,
    repository_workdir: PersistedPathWire,
    repository_workdir_identity: FileIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagedWorktreeBindingWire {
    name: String,
    root: PersistedPathWire,
    root_identity: FileIdentity,
    path: PersistedPathWire,
    path_identity: FileIdentity,
    metadata_dir: PersistedPathWire,
    metadata_dir_identity: FileIdentity,
    worktree_git_file_identity: FileIdentity,
    metadata_gitdir_file_identity: FileIdentity,
    metadata_head_file_identity: FileIdentity,
    branch: String,
    branch_created_by_maco: bool,
    base_oid: String,
    created_branch_oid: String,
    #[serde(default, skip_serializing_if = "is_false")]
    creation_lock_pending: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ManagedWorktreeOperationKindWire {
    Create,
    Remove,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ManagedWorktreeOperationPhaseWire {
    CreateIntent,
    CreatePrepared,
    CreateStaged,
    CreateObserved,
    RemovePrepared,
    WorktreeQuarantined,
    MetadataQuarantined,
    WorktreeDeleted,
    MetadataDeleted,
    BranchDeleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ManagedBranchOwnershipWire {
    Unknown,
    Preexisting,
    CreatedByMaco,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StagedWorktreeMetadataWire {
    metadata_dir: PersistedPathWire,
    metadata_dir_identity: FileIdentity,
    worktree_git_file_identity: FileIdentity,
    metadata_gitdir_file_identity: FileIdentity,
    metadata_head_file_identity: FileIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagedWorktreeOperationWire {
    kind: ManagedWorktreeOperationKindWire,
    phase: ManagedWorktreeOperationPhaseWire,
    name: String,
    root: PersistedPathWire,
    root_identity: FileIdentity,
    path: PersistedPathWire,
    prepared_path_identity: Option<FileIdentity>,
    #[serde(default)]
    staging_root: Option<PersistedPathWire>,
    staging_root_identity: Option<FileIdentity>,
    #[serde(default)]
    staging_path: Option<PersistedPathWire>,
    staged_path_identity: Option<FileIdentity>,
    staged_metadata: Option<StagedWorktreeMetadataWire>,
    branch: String,
    base_oid: String,
    branch_preexisting_oid: Option<String>,
    branch_ownership: ManagedBranchOwnershipWire,
    owned_branch_oid: Option<String>,
    binding: Option<ManagedWorktreeBindingWire>,
    delete_branch: bool,
    force: bool,
    expected_branch_oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    worktree_quarantine_path: Option<PersistedPathWire>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    worktree_quarantine_identity: Option<FileIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    metadata_quarantine_path: Option<PersistedPathWire>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    metadata_quarantine_identity: Option<FileIdentity>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagedWorktreeRegistryWire {
    version: u32,
    checksum: String,
    repository: ManagedRepositoryBindingWire,
    records: BTreeMap<String, ManagedWorktreeBindingWire>,
    operations: BTreeMap<String, ManagedWorktreeOperationWire>,
}

fn validate_managed_worktree_checksum(
    bytes: &[u8],
    expected_repository: &ManagedRepositoryBindingWire,
) -> Result<String> {
    let registry: ManagedWorktreeRegistryWire = serde_json::from_slice(bytes)
        .context("failed to decode checksummed managed worktree registry")?;
    if registry.version != 2 {
        bail!("managed worktree registry is not supported checksummed version 2");
    }
    if &registry.repository != expected_repository {
        bail!(
            "managed worktree registry repository binding does not match the migration repository"
        );
    }
    validate_managed_repository(&registry.repository)?;
    if registry.records.len() > 4_096 || registry.operations.len() > 4_096 {
        bail!("managed worktree registry exceeds its bounded record count");
    }
    if !registry.operations.is_empty() {
        bail!(
            "legacy managed worktree registry contains unauthenticated pending operations; refuse migration and complete or manually recover them with the originating trusted binary before retrying"
        );
    }
    for (name, binding) in &registry.records {
        if name != &binding.name || !is_canonical_lock_component(name) {
            bail!("managed worktree registry has a noncanonical record name");
        }
        validate_managed_binding(binding)?;
    }
    for (name, operation) in &registry.operations {
        if name != &operation.name || !is_canonical_lock_component(name) {
            bail!("managed worktree registry has a noncanonical operation name");
        }
        validate_managed_operation(operation)?;
    }
    let payload = serde_json::to_vec(&(
        registry.version,
        &registry.repository,
        &registry.records,
        &registry.operations,
    ))?;
    verify_legacy_checksum(&registry.checksum, &payload, "managed_worktrees.json")
}

fn validate_managed_repository(repository: &ManagedRepositoryBindingWire) -> Result<()> {
    decode_persisted_path_wire(&repository.common_dir)?;
    decode_persisted_path_wire(&repository.repository_workdir)?;
    validate_file_identity(&repository.common_dir_identity)?;
    validate_file_identity(&repository.repository_workdir_identity)
}

fn validate_managed_binding(binding: &ManagedWorktreeBindingWire) -> Result<()> {
    if !is_canonical_lock_component(&binding.name)
        || binding.branch.is_empty()
        || binding.branch.len() > 1_024
        || !valid_oid(&binding.base_oid)
        || !valid_oid(&binding.created_branch_oid)
    {
        bail!("managed worktree binding has malformed names, branch, or object ids");
    }
    for path in [&binding.root, &binding.path, &binding.metadata_dir] {
        decode_persisted_path_wire(path)?;
    }
    for identity in [
        &binding.root_identity,
        &binding.path_identity,
        &binding.metadata_dir_identity,
        &binding.worktree_git_file_identity,
        &binding.metadata_gitdir_file_identity,
        &binding.metadata_head_file_identity,
    ] {
        validate_file_identity(identity)?;
    }
    Ok(())
}

fn validate_managed_operation(operation: &ManagedWorktreeOperationWire) -> Result<()> {
    if !is_canonical_lock_component(&operation.name)
        || operation.branch.is_empty()
        || operation.branch.len() > 1_024
        || !valid_oid(&operation.base_oid)
        || !valid_optional_oid(operation.branch_preexisting_oid.as_deref())
        || !valid_optional_oid(operation.owned_branch_oid.as_deref())
        || !valid_optional_oid(operation.expected_branch_oid.as_deref())
    {
        bail!("managed worktree operation has malformed names, branch, or object ids");
    }
    for path in [&operation.root, &operation.path] {
        decode_persisted_path_wire(path)?;
    }
    for path in [
        operation.staging_root.as_ref(),
        operation.staging_path.as_ref(),
        operation.worktree_quarantine_path.as_ref(),
        operation.metadata_quarantine_path.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        decode_persisted_path_wire(path)?;
    }
    validate_file_identity(&operation.root_identity)?;
    for identity in [
        operation.prepared_path_identity.as_ref(),
        operation.staging_root_identity.as_ref(),
        operation.staged_path_identity.as_ref(),
        operation.worktree_quarantine_identity.as_ref(),
        operation.metadata_quarantine_identity.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        validate_file_identity(identity)?;
    }
    if let Some(staged) = &operation.staged_metadata {
        decode_persisted_path_wire(&staged.metadata_dir)?;
        for identity in [
            &staged.metadata_dir_identity,
            &staged.worktree_git_file_identity,
            &staged.metadata_gitdir_file_identity,
            &staged.metadata_head_file_identity,
        ] {
            validate_file_identity(identity)?;
        }
    }
    if let Some(binding) = &operation.binding {
        validate_managed_binding(binding)?;
    }
    validate_managed_operation_phase(operation)?;
    Ok(())
}

fn validate_managed_operation_phase(operation: &ManagedWorktreeOperationWire) -> Result<()> {
    let create_phase = matches!(
        operation.phase,
        ManagedWorktreeOperationPhaseWire::CreateIntent
            | ManagedWorktreeOperationPhaseWire::CreatePrepared
            | ManagedWorktreeOperationPhaseWire::CreateStaged
            | ManagedWorktreeOperationPhaseWire::CreateObserved
    );
    let remove_phase = !create_phase;
    if (operation.kind == ManagedWorktreeOperationKindWire::Create) != create_phase
        || (operation.kind == ManagedWorktreeOperationKindWire::Remove) != remove_phase
    {
        bail!("managed worktree operation kind does not match its phase family");
    }
    if create_phase {
        if operation.staging_root.is_none()
            || operation.staging_path.is_none()
            || operation.delete_branch
            || operation.force
            || operation.expected_branch_oid.is_some()
            || operation.worktree_quarantine_path.is_some()
            || operation.worktree_quarantine_identity.is_some()
            || operation.metadata_quarantine_path.is_some()
            || operation.metadata_quarantine_identity.is_some()
        {
            bail!("managed create operation has impossible removal or staging fields");
        }
        let prepared = !matches!(
            operation.phase,
            ManagedWorktreeOperationPhaseWire::CreateIntent
        );
        let staged = matches!(
            operation.phase,
            ManagedWorktreeOperationPhaseWire::CreateStaged
                | ManagedWorktreeOperationPhaseWire::CreateObserved
        );
        let observed = matches!(
            operation.phase,
            ManagedWorktreeOperationPhaseWire::CreateObserved
        );
        if operation.prepared_path_identity.is_some() != prepared
            || operation.staging_root_identity.is_some() != prepared
            || operation.staged_path_identity.is_some() != staged
            || operation.staged_metadata.is_some() != staged
            || operation.binding.is_some() != observed
        {
            bail!("managed create operation fields do not match its durable phase");
        }
        return Ok(());
    }

    if operation.staging_root.is_some()
        || operation.staging_root_identity.is_some()
        || operation.staging_path.is_some()
        || operation.staged_path_identity.is_some()
        || operation.staged_metadata.is_some()
        || operation.prepared_path_identity.is_none()
        || operation.binding.is_none()
        || operation.expected_branch_oid.is_none()
        || operation.worktree_quarantine_path.is_none()
        || operation.metadata_quarantine_path.is_none()
    {
        bail!("managed remove operation is missing required binding or quarantine fields");
    }
    let after_worktree_quarantine = !matches!(
        operation.phase,
        ManagedWorktreeOperationPhaseWire::RemovePrepared
    );
    let after_metadata_quarantine = matches!(
        operation.phase,
        ManagedWorktreeOperationPhaseWire::MetadataQuarantined
            | ManagedWorktreeOperationPhaseWire::WorktreeDeleted
            | ManagedWorktreeOperationPhaseWire::MetadataDeleted
            | ManagedWorktreeOperationPhaseWire::BranchDeleted
    );
    if operation.worktree_quarantine_identity.is_some() != after_worktree_quarantine
        || operation.metadata_quarantine_identity.is_some() != after_metadata_quarantine
    {
        bail!("managed remove operation quarantine identities do not match its phase");
    }
    Ok(())
}

fn validate_file_identity(identity: &FileIdentity) -> Result<()> {
    if identity.file == 0 {
        bail!("managed worktree registry contains an invalid filesystem identity");
    }
    Ok(())
}

fn valid_oid(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_optional_oid(value: Option<&str>) -> bool {
    value.is_none_or(valid_oid)
}

fn decode_persisted_path_wire(path: &PersistedPathWire) -> Result<PathBuf> {
    if path.platform != std::env::consts::OS
        || path.encoding != "unix-bytes-hex-v1"
        || path.data.is_empty()
        || !path.data.len().is_multiple_of(2)
        || path.data.len() > 128 * 1024
        || !path
            .data
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("managed worktree registry contains a malformed persisted path");
    }
    #[cfg(unix)]
    {
        let mut bytes = Vec::with_capacity(path.data.len() / 2);
        for pair in path.data.as_bytes().chunks_exact(2) {
            let digit = |byte| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                _ => None,
            };
            bytes.push(
                digit(pair[0])
                    .and_then(|high| digit(pair[1]).map(|low| (high << 4) | low))
                    .context("managed worktree path hex is malformed")?,
            );
        }
        if bytes.contains(&0) {
            bail!("managed worktree path contains a NUL byte");
        }
        let decoded = PathBuf::from(std::ffi::OsString::from_vec(bytes));
        if !decoded.is_absolute()
            || decoded.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            })
        {
            bail!("managed worktree path is not absolute and lexically canonical");
        }
        let mut normalized = PathBuf::new();
        for component in decoded.components() {
            match component {
                std::path::Component::RootDir => normalized.push(std::path::MAIN_SEPARATOR_STR),
                std::path::Component::Normal(value) => normalized.push(value),
                std::path::Component::Prefix(_) => normalized.push(component.as_os_str()),
                std::path::Component::CurDir | std::path::Component::ParentDir => {
                    bail!("managed worktree path is not lexically canonical")
                }
            }
        }
        if normalized.as_os_str() != decoded.as_os_str() {
            bail!("managed worktree path contains repeated or trailing separators");
        }
        Ok(decoded)
    }
    #[cfg(not(unix))]
    bail!("managed worktree path decoding is unsupported on this platform")
}

fn encode_persisted_path_wire(path: &Path) -> Result<PersistedPathWire> {
    #[cfg(unix)]
    {
        let bytes = path.as_os_str().as_bytes();
        if bytes.is_empty() || bytes.len() > 64 * 1024 || bytes.contains(&0) {
            bail!("managed worktree path exceeds its canonical bound");
        }
        let mut data = String::with_capacity(bytes.len() * 2);
        use std::fmt::Write as _;
        for byte in bytes {
            write!(&mut data, "{byte:02x}")?;
        }
        let wire = PersistedPathWire {
            platform: std::env::consts::OS.to_string(),
            encoding: "unix-bytes-hex-v1".to_string(),
            data,
        };
        decode_persisted_path_wire(&wire)?;
        Ok(wire)
    }
    #[cfg(not(unix))]
    bail!("managed worktree path encoding is unsupported on this platform")
}

#[cfg(unix)]
fn filesystem_path_bytes(path: &Path) -> Vec<u8> {
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

#[derive(Debug)]
struct MigrationHeldLock {
    name: String,
    file: File,
    identity: FileIdentity,
    created: bool,
}

impl MigrationHeldLock {
    fn open_existing(root: &SafeRoot, name: &str) -> Result<Self> {
        let path = root.direct_child(name)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options
            .open(&path)
            .with_context(|| format!("failed to open legacy state lock {name}"))?;
        let metadata = file.metadata()?;
        validate_owned_regular_file(&metadata, &path, 0)?;
        try_exclusive_flock(&file, &path)?;
        let lock = Self {
            name: name.to_string(),
            identity: identity_for_path(&path)?,
            file,
            created: false,
        };
        lock.verify(root)?;
        Ok(lock)
    }

    fn create(root: &SafeRoot, name: &str) -> Result<Self> {
        let path = root.direct_child(name)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options
            .open(&path)
            .with_context(|| format!("failed to create missing legacy state lock {name}"))?;
        file.sync_all()?;
        try_exclusive_flock(&file, &path)?;
        let lock = Self {
            name: name.to_string(),
            identity: identity_for_path(&path)?,
            file,
            created: true,
        };
        lock.verify(root)?;
        root.sync_directory_fenced()?;
        Ok(lock)
    }

    fn verify(&self, root: &SafeRoot) -> Result<()> {
        root.verify()?;
        let path = root.direct_child(&self.name)?;
        let metadata = self.file.metadata()?;
        validate_owned_regular_file(&metadata, &path, 0)?;
        if identity_for_path(path)? != self.identity {
            bail!(
                "legacy state lock path was rebound while held: {}",
                self.name
            );
        }
        Ok(())
    }
}

impl Drop for MigrationHeldLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[cfg(unix)]
fn try_exclusive_flock(file: &File, path: &Path) -> Result<()> {
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = std::io::Error::last_os_error();
        bail!(
            "legacy state lock is active; migration requires an offline repository: {} ({error})",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn try_exclusive_flock(_file: &File, path: &Path) -> Result<()> {
    bail!(
        "nonblocking state lock validation is unsupported: {}",
        path.display()
    )
}

fn acquire_existing_locks(preflight: &LegacyPreflight) -> Result<Vec<MigrationHeldLock>> {
    let mut locks = Vec::with_capacity(preflight.existing_lock_names.len());
    for name in &preflight.existing_lock_names {
        locks.push(MigrationHeldLock::open_existing(
            &preflight.state_root,
            name,
        )?);
    }
    revalidate_preflight(preflight)?;
    Ok(locks)
}

fn create_and_acquire_missing_legacy_locks(
    preflight: &LegacyPreflight,
    locks: &mut Vec<MigrationHeldLock>,
) -> Result<()> {
    let held = locks
        .iter()
        .map(|lock| lock.name.as_str())
        .collect::<BTreeSet<_>>();
    let missing = LEGACY_LOCKS
        .iter()
        .filter(|name| !held.contains(**name))
        .copied()
        .collect::<Vec<_>>();
    for name in missing {
        locks.push(MigrationHeldLock::create(&preflight.state_root, name)?);
    }
    for lock in locks.iter() {
        lock.verify(&preflight.state_root)?;
    }
    Ok(())
}

fn revalidate_preflight(preflight: &LegacyPreflight) -> Result<()> {
    preflight.state_root.verify()?;
    for entry in &preflight.entries {
        let path = preflight.state_root.direct_child(&entry.file)?;
        if let Some((identity, digest)) = preflight.retired_tombstones.get(&entry.file) {
            let bytes = BoundedRegularReader::read_direct(
                &preflight.state_root,
                &entry.file,
                MAX_LEGACY_STATE_BYTES,
            )?;
            if &identity_for_path(path)? != identity || &sha256_hex(&bytes) != digest {
                bail!(
                    "retired legacy tombstone changed during migration preflight: {}",
                    entry.file
                );
            }
            continue;
        }
        if !entry.present {
            if fs::symlink_metadata(path).is_ok() {
                bail!(
                    "legacy state appeared during migration preflight: {}",
                    entry.file
                );
            }
            continue;
        }
        let bytes = BoundedRegularReader::read_direct(
            &preflight.state_root,
            &entry.file,
            MAX_LEGACY_STATE_BYTES,
        )?;
        if Some(sha256_hex(&bytes)) != entry.sha256
            || Some(identity_for_path(path)?) != entry.file_identity
        {
            bail!(
                "legacy state changed during migration preflight: {}",
                entry.file
            );
        }
        revalidate_legacy_state(entry, &bytes, &preflight.expected_bindings)?;
    }
    for (name, identity) in &preflight.inventoried_directories {
        let path = preflight.state_root.direct_child(name)?;
        let metadata = fs::symlink_metadata(&path).with_context(|| {
            format!("inventoried legacy directory disappeared during migration preflight: {name}")
        })?;
        validate_owned_directory(&metadata, &path)?;
        if &identity_for_path(&path)? != identity {
            bail!("inventoried legacy directory changed during migration preflight: {name}");
        }
    }
    preflight.state_root.verify()
}

fn revalidate_legacy_state(
    entry: &LegacyStateEntry,
    bytes: &[u8],
    expected: &ExpectedLegacyBindings,
) -> Result<()> {
    if entry.provenance == Some(LegacyStateProvenance::OperatorAttestedUnauthenticatedImport) {
        if entry.store != "claims" || entry.file != "claims.json" || entry.legacy_checksum.is_some()
        {
            bail!("operator-attested unauthenticated-import provenance is inconsistent");
        }
        decode_checksumless_legacy_claims_state(bytes)?;
        return Ok(());
    }
    let validation = validate_legacy_state(
        &entry.file,
        bytes,
        expected,
        &StateMigrationOptions::default(),
    )?;
    if validation.legacy_checksum != entry.legacy_checksum
        || validation.provenance != entry.provenance
    {
        bail!("legacy state validation classification changed after preflight");
    }
    Ok(())
}

fn manifest_exists(state_root: &SafeRoot) -> Result<bool> {
    if !state_root.direct_child_exists(MANIFEST_ROOT_NAME)? {
        return Ok(false);
    }
    let manifest_root = SafeRoot::open_existing(state_root.direct_child(MANIFEST_ROOT_NAME)?)?;
    let has_entries = !manifest_root
        .direct_child_names_bounded(MAX_STATE_ENTRIES)?
        .is_empty();
    manifest_root.verify()?;
    state_root.verify()?;
    Ok(has_entries)
}

fn load_transaction_if_present(
    preflight: &LegacyPreflight,
) -> Result<Option<LoadedMigrationTransaction>> {
    verify_preflight_repository_binding(preflight)?;
    if !preflight
        .common_root
        .direct_child_exists(TRANSACTION_ROOT_NAME)?
    {
        return Ok(None);
    }
    let root_binding = preflight
        .common_root
        .bind_existing_direct_child_directory(TRANSACTION_ROOT_NAME)
        .context("failed to bind migration transaction root to the Git common directory")?;
    let root_path = root_binding.path();
    let metadata = fs::symlink_metadata(root_path)?;
    validate_owned_directory(&metadata, root_path)?;
    if file_mode(&metadata) != 0o700 {
        bail!("migration transaction root is not owner-private mode 0700");
    }
    let root = SafeRoot::open_existing(root_path)?;
    if root.identity() != root_binding.identity() {
        bail!("migration transaction root changed while opening its capability");
    }
    for name in root.direct_child_names_bounded(3)? {
        if !matches!(
            name.to_str(),
            Some(TRANSACTION_FILE | RECEIPT_FILE | TRANSACTION_LOCK)
        ) {
            bail!("unexpected entry in migration transaction root");
        }
    }
    if !root.direct_child_exists(TRANSACTION_FILE)? {
        return Ok(None);
    }
    let bytes = BoundedRegularReader::read_direct(&root, TRANSACTION_FILE, MAX_TRANSACTION_BYTES)?;
    let transaction: MigrationTransaction =
        serde_json::from_slice(&bytes).context("failed to decode migration transaction")?;
    let expected = transaction_checksum(&transaction)?;
    if transaction.checksum != expected {
        bail!("migration transaction checksum mismatch");
    }
    root_binding.verify(&preflight.common_root)?;
    root.verify()?;
    Ok(Some(LoadedMigrationTransaction {
        value: transaction,
        root_identity: root.identity().clone(),
        root,
        root_binding,
    }))
}

fn verify_transaction_root_binding(
    preflight: &LegacyPreflight,
    root: &SafeRoot,
    binding: &ReservedDirectory,
    expected_identity: &FileIdentity,
) -> Result<()> {
    verify_preflight_repository_binding(preflight)?;
    binding.verify(&preflight.common_root)?;
    root.verify()?;
    if binding.path() != preflight.common_root.path().join(TRANSACTION_ROOT_NAME)
        || binding.identity() != expected_identity
        || root.identity() != expected_identity
        || root.path() != binding.path()
    {
        bail!("migration transaction root is no longer bound to the preflight common directory");
    }
    binding.verify(&preflight.common_root)?;
    verify_preflight_repository_binding(preflight)
}

fn validate_transaction(
    transaction: &MigrationTransaction,
    preflight: &LegacyPreflight,
) -> Result<()> {
    if transaction.version != MIGRATION_VERSION
        || transaction.common_dir_identity != preflight.common_dir_identity
        || transaction.state_root_identity != *preflight.state_root.identity()
        || transaction.entries != preflight.entries
    {
        bail!("migration transaction does not match the current repository state");
    }
    Ok(())
}

fn transaction_checksum(transaction: &MigrationTransaction) -> Result<String> {
    let payload = serde_json::to_vec(&(
        transaction.version,
        transaction.phase,
        &transaction.common_dir_identity,
        &transaction.state_root_identity,
        transaction.original_state_mode,
        &transaction.original_file_modes,
        &transaction.created_locks,
        &transaction.entries,
    ))?;
    Ok(stable_checksum(&payload))
}

fn write_transaction(
    root: &SafeRoot,
    lock: &KernelStateLock,
    transaction: &mut MigrationTransaction,
) -> Result<()> {
    transaction.checksum.clear();
    transaction.checksum = transaction_checksum(transaction)?;
    let mut bytes = serde_json::to_vec_pretty(transaction)?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_TRANSACTION_BYTES {
        bail!("migration transaction exceeds its size bound");
    }
    AtomicStateWriter::scavenge_direct_temps(root, TRANSACTION_FILE)?;
    AtomicStateWriter::write_direct_fenced(root, TRANSACTION_FILE, &bytes, || {
        lock.verify_direct_binding(root)
    })
}

fn apply_migration(
    repo_path: &Path,
    preflight: &LegacyPreflight,
    transaction_root: &SafeRoot,
    transaction_binding: &ReservedDirectory,
    existing_transaction: Option<MigrationTransaction>,
    mut locks: Vec<MigrationHeldLock>,
    transaction_lock: KernelStateLock,
) -> Result<StateMigrationReport> {
    let mut transaction = existing_transaction.unwrap_or_else(|| MigrationTransaction {
        version: MIGRATION_VERSION,
        phase: MigrationPhase::Planned,
        common_dir_identity: preflight.common_dir_identity.clone(),
        state_root_identity: preflight.state_root.identity().clone(),
        original_state_mode: preflight.original_state_mode,
        original_file_modes: preflight.original_file_modes.clone(),
        created_locks: Vec::new(),
        entries: preflight.entries.clone(),
        checksum: String::new(),
    });
    for lock in &locks {
        if lock.created && !transaction.created_locks.contains(&lock.name) {
            transaction.created_locks.push(lock.name.clone());
        }
    }
    transaction.created_locks.sort();
    transaction.created_locks.dedup();
    write_transaction(transaction_root, &transaction_lock, &mut transaction)?;

    if transaction.phase == MigrationPhase::Planned {
        if let Err(error) = harden_state(preflight, &locks) {
            return rollback_error(
                error,
                preflight,
                transaction_root,
                &transaction_lock,
                &transaction,
                &locks,
            );
        }
        transaction.phase = MigrationPhase::PermissionsHardened;
        if let Err(error) = write_transaction(transaction_root, &transaction_lock, &mut transaction)
        {
            return rollback_error(
                error,
                preflight,
                transaction_root,
                &transaction_lock,
                &transaction,
                &locks,
            );
        }
    } else {
        ensure_hardened_state(preflight, &locks)?;
    }

    if let Some(action) = take_migration_fault(MigrationFaultPoint::AfterPermissions) {
        let error = anyhow::anyhow!("injected state migration fault after permission hardening");
        if action == MigrationFaultAction::Crash {
            return Err(error.context("migration transaction remains forward-recoverable"));
        }
        return rollback_error(
            error,
            preflight,
            transaction_root,
            &transaction_lock,
            &transaction,
            &locks,
        );
    }

    // These pre-existing locks have already been proven idle. Release their
    // descriptors before the canonical key and manifest writers reacquire the
    // same inodes. Every other consumer lock remains held until return.
    for writer_lock in [AUTH_KEY_LOCK, StateMigrationManifestSpec::ROOT_LOCK_NAME] {
        if let Some(index) = locks.iter().position(|lock| lock.name == writer_lock) {
            locks.remove(index);
        }
    }
    verify_preflight_repository_binding(preflight)?;
    let key_preexisted = preflight.state_root.direct_child_exists(AUTH_KEY_FILE)?;
    let writer = match repository_auth_writer(repo_path) {
        Ok(writer) => writer,
        Err(error) => {
            let key_now_exists = preflight.state_root.direct_child_exists(AUTH_KEY_FILE)?;
            if key_now_exists && !key_preexisted {
                return Err(error.context(
                    "authentication bootstrap crossed its durable key boundary; rerun apply to recover forward",
                ));
            }
            return rollback_error(
                error,
                preflight,
                transaction_root,
                &transaction_lock,
                &transaction,
                &locks,
            );
        }
    };
    verify_migration_authenticator_binding(preflight, writer.authenticator())?;
    let binding = writer.authenticator().binding().clone();
    let manifest = StateMigrationManifest {
        version: MIGRATION_VERSION,
        repository: binding,
        entries: preflight.entries.clone(),
        inventoried_directories: preflight.inventoried_directories.clone(),
    };
    let authenticator = writer.into_authenticator()?;
    verify_migration_authenticator_binding(preflight, &authenticator)?;
    revalidate_exact_state_root_inventory(preflight, &locks, true, false)?;
    revalidate_preflight(preflight)?;
    verify_preflight_repository_binding(preflight)?;
    let store = match AuthenticatedSnapshotStore::<
        StateMigrationManifestSpec,
        StateMigrationManifest,
    >::create(authenticator, MANIFEST_INSTANCE_ID, 1, manifest.clone())
    {
        Ok(store) => store,
        Err(error) => {
            return Err(error.context(
                "authentication state is durable; migration remains forward-recoverable",
            ));
        }
    };
    verify_preflight_repository_binding(preflight)?;
    transaction.phase = MigrationPhase::ManifestPublished;
    write_transaction(transaction_root, &transaction_lock, &mut transaction)?;

    if take_migration_fault(MigrationFaultPoint::AfterManifest) == Some(MigrationFaultAction::Crash)
    {
        return Err(anyhow::anyhow!(
            "injected state migration crash after signed manifest publication; rerun apply"
        ));
    }

    let snapshot = store.current();
    write_receipt(
        transaction_root,
        &transaction_lock,
        &manifest,
        snapshot.generation,
        snapshot.token,
    )?;
    transaction.phase = MigrationPhase::Completed;
    write_transaction(transaction_root, &transaction_lock, &mut transaction)?;
    run_migration_before_final_verification_hook();
    let transaction_boundary = MigrationTransactionBoundary {
        root: transaction_root,
        binding: transaction_binding,
        lock: &transaction_lock,
        expected: &transaction,
        identity: transaction_root.identity(),
    };
    verify_completed_migration_boundaries(
        repo_path,
        preflight,
        &locks,
        &transaction_boundary,
        &store,
    )?;

    Ok(StateMigrationReport {
        version: MIGRATION_VERSION,
        mode: StateMigrationMode::Apply,
        status: StateMigrationStatus::Applied,
        legacy_state_root: ".git/maco/state".to_string(),
        transaction_phase: Some(MigrationPhase::Completed),
        entries: preflight.entries.clone(),
        hardened: true,
        manifest_generation: Some(snapshot.generation),
    })
}

fn verify_completed_migration_boundaries(
    repo_path: &Path,
    preflight: &LegacyPreflight,
    locks: &[MigrationHeldLock],
    transaction: &MigrationTransactionBoundary<'_>,
    store: &AuthenticatedSnapshotStore<StateMigrationManifestSpec, StateMigrationManifest>,
) -> Result<()> {
    if transaction.expected.phase != MigrationPhase::Completed {
        bail!("final migration verification requires a completed transaction");
    }
    verify_transaction_root_binding(
        preflight,
        transaction.root,
        transaction.binding,
        transaction.identity,
    )?;
    transaction.lock.verify_direct_binding(transaction.root)?;
    verify_all_legacy_locks(preflight, locks)?;
    verify_migration_authenticator_binding(preflight, store.authenticator())?;
    let snapshot = store.current();
    AuthenticatedSnapshotStore::<StateMigrationManifestSpec, StateMigrationManifest>::verify_locator_anchor(
        store.authenticator(),
        MANIFEST_INSTANCE_ID,
        store.identity(),
        snapshot.generation,
    )?;
    revalidate_exact_state_root_inventory(preflight, locks, true, true)?;
    revalidate_preflight(preflight)?;
    revalidate_retired_tombstones(repo_path, preflight, Some(&snapshot.value))?;
    let observed = load_transaction_if_present(preflight)?
        .context("completed migration transaction disappeared before return")?;
    if &observed.root_identity != transaction.identity || &observed.value != transaction.expected {
        bail!("completed migration transaction changed before return");
    }
    verify_migration_receipt(
        transaction.root,
        &snapshot.value,
        snapshot.generation,
        snapshot.token,
    )?;
    transaction.lock.verify_direct_binding(transaction.root)?;
    verify_transaction_root_binding(
        preflight,
        transaction.root,
        transaction.binding,
        transaction.identity,
    )?;
    verify_migration_authenticator_binding(preflight, store.authenticator())
}

fn verify_existing_manifest(
    repo_path: &Path,
    apply: bool,
    preflight: &LegacyPreflight,
    locks: &[MigrationHeldLock],
    transaction: Option<&LoadedMigrationTransaction>,
) -> Result<StateMigrationReport> {
    let transaction =
        transaction.context("signed migration manifest is missing its durable transaction")?;
    verify_all_legacy_locks(preflight, locks)?;
    let transaction_root = &transaction.root;
    verify_transaction_root_binding(
        preflight,
        transaction_root,
        &transaction.root_binding,
        &transaction.root_identity,
    )?;
    let transaction_lock =
        KernelStateLock::acquire_existing_direct(transaction_root, TRANSACTION_LOCK)?;
    let initial_transaction_boundary = MigrationTransactionBoundary {
        root: transaction_root,
        binding: &transaction.root_binding,
        lock: &transaction_lock,
        expected: &transaction.value,
        identity: &transaction.root_identity,
    };
    verify_existing_manifest_boundaries(
        repo_path,
        preflight,
        locks,
        &initial_transaction_boundary,
        None,
        None,
    )?;

    let authenticator = repository_authenticator_key_only(repo_path)?;
    authenticator.verify_epoch()?;
    let store = AuthenticatedSnapshotStore::<StateMigrationManifestSpec, StateMigrationManifest>::open_instance(
        authenticator,
        MANIFEST_INSTANCE_ID,
    )?;
    let snapshot = store.current();
    if snapshot.generation != 1
        || snapshot.token != 1
        || snapshot.value.version != MIGRATION_VERSION
        || snapshot.value.repository != store.identity().repository
        || snapshot.value.entries != preflight.entries
        || snapshot.value.inventoried_directories != preflight.inventoried_directories
    {
        bail!("signed state migration manifest does not match the current legacy state");
    }

    let mut durable_transaction = transaction.value.clone();
    let mut phase = Some(durable_transaction.phase);
    if apply && phase != Some(MigrationPhase::Completed) {
        verify_existing_manifest_boundaries(
            repo_path,
            preflight,
            locks,
            &initial_transaction_boundary,
            Some(&snapshot.value),
            Some(&store),
        )?;
        write_receipt(
            transaction_root,
            &transaction_lock,
            &snapshot.value,
            snapshot.generation,
            snapshot.token,
        )?;
        durable_transaction.phase = MigrationPhase::Completed;
        write_transaction(
            transaction_root,
            &transaction_lock,
            &mut durable_transaction,
        )?;
        phase = Some(MigrationPhase::Completed);
    }

    let durable_transaction_boundary = MigrationTransactionBoundary {
        root: transaction_root,
        binding: &transaction.root_binding,
        lock: &transaction_lock,
        expected: &durable_transaction,
        identity: &transaction.root_identity,
    };
    verify_existing_manifest_boundaries(
        repo_path,
        preflight,
        locks,
        &durable_transaction_boundary,
        Some(&snapshot.value),
        Some(&store),
    )?;
    if phase == Some(MigrationPhase::Completed) {
        verify_migration_receipt(
            transaction_root,
            &snapshot.value,
            snapshot.generation,
            snapshot.token,
        )?;
    }
    let hardened = state_is_hardened(preflight, locks)?;
    verify_existing_manifest_boundaries(
        repo_path,
        preflight,
        locks,
        &durable_transaction_boundary,
        Some(&snapshot.value),
        Some(&store),
    )?;

    Ok(StateMigrationReport {
        version: MIGRATION_VERSION,
        mode: migration_mode(apply),
        status: StateMigrationStatus::AlreadyApplied,
        legacy_state_root: ".git/maco/state".to_string(),
        transaction_phase: phase,
        entries: preflight.entries.clone(),
        hardened,
        manifest_generation: Some(snapshot.generation),
    })
}

fn verify_all_legacy_locks(preflight: &LegacyPreflight, locks: &[MigrationHeldLock]) -> Result<()> {
    let held = locks
        .iter()
        .map(|lock| lock.name.as_str())
        .collect::<BTreeSet<_>>();
    if !LEGACY_LOCKS.iter().all(|name| held.contains(name)) {
        bail!("signed migration verification does not hold every legacy consumer lock");
    }
    for lock in locks {
        lock.verify(&preflight.state_root)?;
    }
    Ok(())
}

fn verify_existing_manifest_boundaries(
    repo_path: &Path,
    preflight: &LegacyPreflight,
    locks: &[MigrationHeldLock],
    transaction: &MigrationTransactionBoundary<'_>,
    manifest: Option<&StateMigrationManifest>,
    store: Option<&AuthenticatedSnapshotStore<StateMigrationManifestSpec, StateMigrationManifest>>,
) -> Result<()> {
    verify_transaction_root_binding(
        preflight,
        transaction.root,
        transaction.binding,
        transaction.identity,
    )?;
    verify_all_legacy_locks(preflight, locks)?;
    transaction.lock.verify_direct_binding(transaction.root)?;
    revalidate_exact_state_root_inventory(preflight, locks, false, false)?;
    revalidate_preflight(preflight)?;
    revalidate_retired_tombstones(repo_path, preflight, manifest)?;
    let observed = load_transaction_if_present(preflight)?
        .context("migration transaction disappeared while its lock was held")?;
    if &observed.root_identity != transaction.identity || &observed.value != transaction.expected {
        bail!("migration transaction changed while its lock was held");
    }
    if let Some(store) = store {
        verify_migration_authenticator_binding(preflight, store.authenticator())?;
        let snapshot = store.current();
        AuthenticatedSnapshotStore::<
            StateMigrationManifestSpec,
            StateMigrationManifest,
        >::verify_locator_anchor(
            store.authenticator(),
            MANIFEST_INSTANCE_ID,
            store.identity(),
            snapshot.generation,
        )?;
    }
    transaction.lock.verify_direct_binding(transaction.root)?;
    verify_transaction_root_binding(
        preflight,
        transaction.root,
        transaction.binding,
        transaction.identity,
    )?;
    preflight.state_root.verify()?;
    transaction.root.verify()
}

fn revalidate_exact_state_root_inventory(
    preflight: &LegacyPreflight,
    locks: &[MigrationHeldLock],
    allow_auth_bootstrap_entries: bool,
    allow_manifest_entries: bool,
) -> Result<()> {
    let mut expected = expected_state_root_inventory(preflight, locks)?;
    let mut observed = BTreeMap::new();
    for name in preflight
        .state_root
        .direct_child_names_bounded(MAX_STATE_ENTRIES)?
    {
        let name = name
            .into_string()
            .map_err(|_| anyhow::anyhow!("migration state entry name is not UTF-8"))?;
        let path = preflight.state_root.direct_child(&name)?;
        let metadata = fs::symlink_metadata(&path)?;
        if is_known_state_directory(&name) {
            validate_owned_directory(&metadata, &path)?;
        } else if is_known_state_file(&name) {
            validate_owned_regular_file(&metadata, &path, file_bound(&name))?;
        } else {
            bail!("unknown entry in migration state root: {name}");
        }
        let identity = identity_for_path(&path)?;
        let allowed_auth_entry = allow_auth_bootstrap_entries
            && matches!(
                name.as_str(),
                AUTH_KEY_FILE | AUTH_EPOCH_FILE | AUTH_KEY_LOCK
            );
        let allowed_manifest_entry = allow_manifest_entries
            && matches!(name.as_str(), MANIFEST_ROOT_NAME | ".state-migrations.lock");
        if !expected.contains_key(&name) && (allowed_auth_entry || allowed_manifest_entry) {
            expected.insert(name.clone(), identity.clone());
        }
        if observed.insert(name, identity).is_some() {
            bail!("migration state root contains a duplicate entry name");
        }
    }
    preflight.state_root.verify()?;
    if observed != expected {
        bail!("migration state root inventory changed after preflight");
    }
    Ok(())
}

fn expected_state_root_inventory(
    preflight: &LegacyPreflight,
    locks: &[MigrationHeldLock],
) -> Result<BTreeMap<String, FileIdentity>> {
    let mut expected = preflight.root_entries.clone();
    for lock in locks {
        if let Some(previous) = expected.insert(lock.name.clone(), lock.identity.clone()) {
            if previous != lock.identity {
                bail!("held migration lock does not match its preflight inventory identity");
            }
        }
    }
    Ok(expected)
}

fn revalidate_retired_tombstones(
    repo_path: &Path,
    preflight: &LegacyPreflight,
    manifest: Option<&StateMigrationManifest>,
) -> Result<()> {
    for entry in &preflight.entries {
        if !preflight.retired_tombstones.contains_key(&entry.file) {
            continue;
        }
        if manifest.is_some_and(|manifest| !manifest.entries.contains(entry)) {
            bail!("signed migration manifest lost a retired legacy entry");
        }
        let bytes = BoundedRegularReader::read_direct(
            &preflight.state_root,
            &entry.file,
            MAX_LEGACY_STATE_BYTES,
        )?;
        verify_retired_tombstone_binding(repo_path, &entry.store, &entry.file, &bytes, entry)?;
    }
    Ok(())
}

fn verify_migration_receipt(
    root: &SafeRoot,
    manifest: &StateMigrationManifest,
    generation: u64,
    token: u64,
) -> Result<()> {
    let bytes = BoundedRegularReader::read_direct(root, RECEIPT_FILE, MAX_TRANSACTION_BYTES)?;
    let receipt: MigrationReceipt =
        serde_json::from_slice(&bytes).context("migration receipt is malformed")?;
    let manifest_bytes = serde_json::to_vec(manifest)?;
    if receipt.version != MIGRATION_VERSION
        || receipt.manifest_generation != generation
        || receipt.manifest_token != token
        || receipt.manifest_sha256 != sha256_hex(&manifest_bytes)
        || receipt.entries != manifest.entries
    {
        bail!("migration receipt does not bind the signed manifest");
    }
    root.verify()
}

fn write_receipt(
    root: &SafeRoot,
    lock: &KernelStateLock,
    manifest: &StateMigrationManifest,
    generation: u64,
    token: u64,
) -> Result<()> {
    let manifest_bytes = serde_json::to_vec(manifest)?;
    let receipt = MigrationReceipt {
        version: MIGRATION_VERSION,
        manifest_generation: generation,
        manifest_token: token,
        manifest_sha256: sha256_hex(&manifest_bytes),
        entries: manifest.entries.clone(),
    };
    let mut bytes = serde_json::to_vec_pretty(&receipt)?;
    bytes.push(b'\n');
    AtomicStateWriter::scavenge_direct_temps(root, RECEIPT_FILE)?;
    AtomicStateWriter::write_direct_fenced(root, RECEIPT_FILE, &bytes, || {
        lock.verify_direct_binding(root)
    })
}

#[cfg(unix)]
fn harden_state(preflight: &LegacyPreflight, locks: &[MigrationHeldLock]) -> Result<()> {
    verify_preflight_repository_binding(preflight)?;
    revalidate_preflight(preflight)?;
    revalidate_exact_state_root_inventory(preflight, locks, false, false)?;
    let expected = expected_state_root_inventory(preflight, locks)?;
    for (name, identity) in &expected {
        let (kind, mode) = if is_known_state_directory(name) {
            (DirectChildType::Directory, 0o700)
        } else if is_known_state_file(name) {
            (DirectChildType::SingleLinkRegularFile, 0o600)
        } else {
            bail!("unknown state entry appeared during permission hardening: {name}");
        };
        let binding = preflight
            .state_root
            .bind_owned_direct_child(name, identity, kind)?;
        run_migration_after_child_bind_hook(name);
        binding.set_permissions_fenced(&preflight.state_root, mode)?;
    }
    preflight
        .state_root
        .set_directory_permissions_fenced(0o700)?;
    preflight.state_root.sync_directory_fenced()?;
    for lock in locks {
        lock.verify(&preflight.state_root)?;
    }
    revalidate_exact_state_root_inventory(preflight, locks, false, false)?;
    revalidate_preflight(preflight)?;
    verify_preflight_repository_binding(preflight)?;
    ensure_hardened_state(preflight, locks)
}

#[cfg(not(unix))]
fn harden_state(_preflight: &LegacyPreflight, _locks: &[MigrationHeldLock]) -> Result<()> {
    bail!("state permission hardening is unsupported on this platform")
}

fn ensure_hardened_state(preflight: &LegacyPreflight, locks: &[MigrationHeldLock]) -> Result<()> {
    if !state_is_hardened(preflight, locks)? {
        bail!("migration transaction says permissions are hardened but state is not private");
    }
    Ok(())
}

fn state_is_hardened(preflight: &LegacyPreflight, locks: &[MigrationHeldLock]) -> Result<bool> {
    verify_preflight_repository_binding(preflight)?;
    revalidate_exact_state_root_inventory(preflight, locks, false, false)?;
    let state_metadata = fs::symlink_metadata(preflight.state_root.path())?;
    validate_owned_directory(&state_metadata, preflight.state_root.path())?;
    if file_mode(&state_metadata) != 0o700 {
        return Ok(false);
    }
    for (name, identity) in expected_state_root_inventory(preflight, locks)? {
        let path = preflight.state_root.direct_child(&name)?;
        let metadata = fs::symlink_metadata(&path)?;
        if is_known_state_directory(&name) {
            validate_owned_directory(&metadata, &path)?;
            if identity_for_path(&path)? != identity || file_mode(&metadata) != 0o700 {
                return Ok(false);
            }
        } else if is_known_state_file(&name) {
            validate_owned_regular_file(&metadata, &path, file_bound(&name))?;
            if identity_for_path(&path)? != identity || file_mode(&metadata) != 0o600 {
                return Ok(false);
            }
        } else {
            bail!("unknown entry in hardened migration state root: {name}");
        }
    }
    revalidate_exact_state_root_inventory(preflight, locks, false, false)?;
    verify_preflight_repository_binding(preflight)?;
    Ok(true)
}

fn rollback_error<T>(
    error: anyhow::Error,
    preflight: &LegacyPreflight,
    transaction_root: &SafeRoot,
    transaction_lock: &KernelStateLock,
    transaction: &MigrationTransaction,
    locks: &[MigrationHeldLock],
) -> Result<T> {
    match rollback_permissions(preflight, transaction, locks) {
        Ok(()) => {
            let mut reset = transaction.clone();
            reset.phase = MigrationPhase::Planned;
            if let Err(reset_error) =
                write_transaction(transaction_root, transaction_lock, &mut reset)
            {
                return Err(error.context(format!(
                    "state migration rolled back, but its transaction could not be reset: {reset_error:#}"
                )));
            }
            Err(error.context("state migration rolled back before authentication publication"))
        }
        Err(rollback_error) => Err(error.context(format!(
            "state migration also failed to roll back safely: {rollback_error:#}"
        ))),
    }
}

#[cfg(unix)]
fn rollback_permissions(
    preflight: &LegacyPreflight,
    transaction: &MigrationTransaction,
    locks: &[MigrationHeldLock],
) -> Result<()> {
    for (name, mode) in &transaction.original_file_modes {
        let identity = preflight
            .root_entries
            .get(name)
            .with_context(|| format!("rollback state entry was absent from preflight: {name}"))?;
        let binding = preflight.state_root.bind_owned_direct_child(
            name,
            identity,
            DirectChildType::SingleLinkRegularFile,
        )?;
        binding.set_permissions_fenced(&preflight.state_root, *mode)?;
    }
    for name in &transaction.created_locks {
        let lock = locks
            .iter()
            .find(|lock| &lock.name == name)
            .with_context(|| format!("created migration lock is no longer held: {name}"))?;
        lock.verify(&preflight.state_root)?;
        let binding = preflight.state_root.bind_owned_direct_child(
            name,
            &lock.identity,
            DirectChildType::SingleLinkRegularFile,
        )?;
        binding.unlink_fenced(&preflight.state_root)?;
    }
    preflight
        .state_root
        .set_directory_permissions_fenced(transaction.original_state_mode)?;
    preflight.state_root.sync_directory_fenced()?;
    verify_preflight_repository_binding(preflight)
}

#[cfg(not(unix))]
fn rollback_permissions(
    _preflight: &LegacyPreflight,
    _transaction: &MigrationTransaction,
    _locks: &[MigrationHeldLock],
) -> Result<()> {
    bail!("state permission rollback is unsupported on this platform")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MigrationFaultPoint {
    AfterPermissions,
    AfterManifest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum MigrationFaultAction {
    Error,
    Crash,
}

#[cfg(test)]
thread_local! {
    static MIGRATION_FAULT: std::cell::Cell<Option<(MigrationFaultPoint, MigrationFaultAction)>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn set_migration_fault(point: MigrationFaultPoint, action: MigrationFaultAction) {
    MIGRATION_FAULT.with(|slot| slot.set(Some((point, action))));
}

#[cfg(test)]
fn take_migration_fault(point: MigrationFaultPoint) -> Option<MigrationFaultAction> {
    MIGRATION_FAULT.with(|slot| {
        let value = slot.get();
        if value.is_some_and(|(candidate, _)| candidate == point) {
            slot.set(None);
            value.map(|(_, action)| action)
        } else {
            None
        }
    })
}

#[cfg(not(test))]
fn take_migration_fault(_point: MigrationFaultPoint) -> Option<MigrationFaultAction> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{semantic_coord::SemanticIntentStore, sync::ClaimToken, sync_store::SyncStore};
    use tempfile::TempDir;

    const ISSUE33_CLAIMS_V1: &[u8] =
        include_bytes!("../tests/fixtures/issue33/agent-files-claims-v1.json");
    const ISSUE33_CLAIMS_V1_SHA256: &str =
        "58076fb067d6bbc560926628b8930075d0674eae025b945619f0890000995291";

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn repository_with_claims() -> (TempDir, PathBuf, PathBuf) {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("repo");
        let repository = Repository::init(&path).expect("repository");
        let state = repository.commondir().join("maco/state");
        let state_root = SafeRoot::open_or_create(&state).expect("state root");
        let binding = expected_bindings_for(&path).repository_state;
        let mut claims = LegacyClaimsState {
            version: 2,
            checksum: String::new(),
            repository: binding,
            next_token: 2,
            claims: vec![PathClaim {
                token: ClaimToken::from_u64(1),
                agent_id: "migration-test".to_string(),
                paths: vec![PathBuf::from("src")],
            }],
        };
        claims.checksum = stable_checksum(
            &serde_json::to_vec(&(
                claims.version,
                &claims.repository,
                claims.next_token,
                &claims.claims,
            ))
            .expect("claims checksum payload"),
        );
        AtomicStateWriter::write_direct(
            &state_root,
            "claims.json",
            &serde_json::to_vec_pretty(&claims).expect("claims JSON"),
        )
        .expect("claims state");
        KernelStateLock::acquire_direct(&state_root, "claims.lock").expect("claims lock");
        (temp, path, state)
    }

    fn empty_repository_state() -> (TempDir, PathBuf, SafeRoot) {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("repo");
        let repository = Repository::init(&path).expect("repository");
        let state = SafeRoot::open_or_create(repository.commondir().join("maco/state"))
            .expect("state root");
        (temp, path, state)
    }

    fn repository_with_checksumless_claims_v1() -> (TempDir, PathBuf, PathBuf) {
        let (temp, path, state) = empty_repository_state();
        AtomicStateWriter::write_direct(&state, "claims.json", ISSUE33_CLAIMS_V1)
            .expect("literal checksum-less claims-v1 fixture");
        (temp, path, state.path().to_path_buf())
    }

    fn repository_with_checksumless_semantic() -> (TempDir, PathBuf, PathBuf, SemanticIntent) {
        let (temp, path, state) = empty_repository_state();
        let intent = SemanticIntent {
            token: SemanticIntentToken::from_u64(1),
            agent_id: "migration-semantic".to_string(),
            paths: vec![PathBuf::from("src/lib.rs")],
            symbols: Vec::new(),
            modules: Vec::new(),
            impacted_files: Vec::new(),
            task_digest: None,
            task_excerpt: None,
            notes: Vec::new(),
            warnings: Vec::new(),
        };
        let bytes = serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "next_token": 2,
            "intents": [&intent],
        }))
        .expect("checksum-less semantic JSON");
        AtomicStateWriter::write_direct(&state, "semantic_intents.json", &bytes)
            .expect("checksum-less semantic state");
        (temp, path, state.path().to_path_buf(), intent)
    }

    fn expected_bindings_for(path: &Path) -> ExpectedLegacyBindings {
        let repository = crate::git_repository::open(path).expect("repository");
        let common = SafeRoot::open_existing(repository.commondir()).expect("common root");
        let primary =
            SafeRoot::open_existing(common.path().parent().expect("embedded primary workdir"))
                .expect("primary root");
        ExpectedLegacyBindings {
            repository_state: LegacyRepositoryBinding {
                common_dir_path_checksum: stable_checksum(&filesystem_path_bytes(common.path())),
                common_dir_identity: common.identity().clone(),
            },
            managed_repository: Some(ManagedRepositoryBindingWire {
                common_dir: encode_persisted_path_wire(common.path()).expect("common path"),
                common_dir_identity: common.identity().clone(),
                repository_workdir: encode_persisted_path_wire(primary.path())
                    .expect("primary path"),
                repository_workdir_identity: primary.identity().clone(),
            }),
        }
    }

    #[cfg(unix)]
    fn make_legacy_permissions(state: &Path) {
        fs::set_permissions(state, fs::Permissions::from_mode(0o755)).expect("state mode");
        for name in ["claims.json", "claims.lock"] {
            fs::set_permissions(state.join(name), fs::Permissions::from_mode(0o644))
                .expect("legacy file mode");
        }
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    }

    #[cfg(unix)]
    fn owned_directory_attributes(hard_link_count: u64) -> OwnedDirectoryAttributes {
        OwnedDirectoryAttributes {
            is_symlink: false,
            is_directory: true,
            owner: unsafe { libc::geteuid() },
            hard_link_count,
            mode: 0o700,
        }
    }

    #[cfg(unix)]
    #[test]
    fn owned_directory_validation_accepts_drvfs_link_count_one_and_rejects_zero() {
        let owner = unsafe { libc::geteuid() };
        assert!(owned_directory_attributes(1).are_safe_for(owner));
        assert!(!owned_directory_attributes(0).are_safe_for(owner));
    }

    #[test]
    fn literal_issue33_claims_v1_fixture_matches_the_pinned_writer_bytes() {
        assert_eq!(ISSUE33_CLAIMS_V1.len(), 524);
        assert_eq!(sha256_hex(ISSUE33_CLAIMS_V1), ISSUE33_CLAIMS_V1_SHA256);
        assert_eq!(
            include_str!("../tests/fixtures/issue33/agent-files-claims-v1.sha256"),
            format!("{ISSUE33_CLAIMS_V1_SHA256}  agent-files-claims-v1.json\n")
        );

        let decoded =
            decode_checksumless_legacy_claims_state(ISSUE33_CLAIMS_V1).expect("strict fixture");
        assert_eq!(decoded.next_token, 67);
        assert_eq!(
            decoded
                .claims
                .iter()
                .map(|claim| claim.token.get())
                .collect::<Vec<_>>(),
            vec![20, 44, 66]
        );
    }

    #[test]
    fn claims_v1_migration_options_require_a_coherent_lowercase_digest_pair() {
        assert!(validate_migration_options(&StateMigrationOptions {
            acknowledge_unauthenticated_claims_v1: false,
            expected_claims_v1_sha256: Some(ISSUE33_CLAIMS_V1_SHA256.to_string()),
        })
        .is_err());
        assert!(validate_migration_options(&StateMigrationOptions {
            acknowledge_unauthenticated_claims_v1: true,
            expected_claims_v1_sha256: None,
        })
        .is_err());
        assert!(validate_migration_options(&StateMigrationOptions {
            acknowledge_unauthenticated_claims_v1: true,
            expected_claims_v1_sha256: Some(ISSUE33_CLAIMS_V1_SHA256.to_uppercase()),
        })
        .is_err());
        validate_migration_options(&StateMigrationOptions {
            acknowledge_unauthenticated_claims_v1: true,
            expected_claims_v1_sha256: Some(ISSUE33_CLAIMS_V1_SHA256.to_string()),
        })
        .expect("coherent acknowledgement and lowercase SHA-256");
    }

    #[test]
    fn checksumless_claims_v1_decoder_rejects_noncanonical_or_ambiguous_state() {
        let mut cases = Vec::new();

        let mut low_next_token: serde_json::Value =
            serde_json::from_slice(ISSUE33_CLAIMS_V1).expect("fixture JSON");
        low_next_token["next_token"] = serde_json::json!(66);
        cases.push(("next token", low_next_token));

        let mut duplicate_token: serde_json::Value =
            serde_json::from_slice(ISSUE33_CLAIMS_V1).expect("fixture JSON");
        duplicate_token["claims"][1]["token"] = serde_json::json!(20);
        cases.push(("duplicate token", duplicate_token));

        let mut noncanonical_path: serde_json::Value =
            serde_json::from_slice(ISSUE33_CLAIMS_V1).expect("fixture JSON");
        noncanonical_path["claims"][0]["paths"][0] = serde_json::json!("src/../README.md");
        cases.push(("noncanonical path", noncanonical_path));

        let mut unknown_field: serde_json::Value =
            serde_json::from_slice(ISSUE33_CLAIMS_V1).expect("fixture JSON");
        unknown_field["claims"][0]["unexpected"] = serde_json::json!(true);
        cases.push(("unknown field", unknown_field));

        for (name, value) in cases {
            let bytes = serde_json::to_vec_pretty(&value).expect("case JSON");
            assert!(
                decode_checksumless_legacy_claims_state(&bytes).is_err(),
                "{name} must fail"
            );
        }
    }

    #[test]
    fn legacy_entry_without_provenance_keeps_the_pre_provenance_wire_shape() {
        let legacy = serde_json::json!({
            "store": "claims",
            "file": "claims.json",
            "present": false,
            "size": 0,
            "sha256": null,
            "legacy_checksum": null,
            "file_identity": null
        });
        let entry: LegacyStateEntry =
            serde_json::from_value(legacy.clone()).expect("pre-provenance entry");
        assert_eq!(entry.provenance, None);
        assert_eq!(
            serde_json::to_value(entry).expect("entry serialization"),
            legacy
        );
    }

    #[cfg(unix)]
    #[test]
    fn claims_v1_migration_requires_exact_operator_attestation_and_signs_it() {
        let (_temp, path, state) = repository_with_checksumless_claims_v1();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o755)).expect("state mode");
        fs::set_permissions(state.join("claims.json"), fs::Permissions::from_mode(0o644))
            .expect("claims mode");
        let repository = crate::git_repository::open(&path).expect("repository");
        let transaction_root = repository.commondir().join(TRANSACTION_ROOT_NAME);

        let unauthenticated = migrate_repository_state(&path, false)
            .expect_err("checksum-less claims-v1 needs acknowledgement");
        let unauthenticated_message = format!("{unauthenticated:#}");
        assert!(unauthenticated_message.contains("unauthenticated"));
        assert!(unauthenticated_message.contains(ISSUE33_CLAIMS_V1_SHA256));
        assert_eq!(mode(&state), 0o755);
        assert_eq!(mode(&state.join("claims.json")), 0o644);
        assert!(!transaction_root.exists());
        assert!(!state.join(AUTH_KEY_FILE).exists());

        let wrong = StateMigrationOptions {
            acknowledge_unauthenticated_claims_v1: true,
            expected_claims_v1_sha256: Some("0".repeat(64)),
        };
        let mismatch = migrate_repository_state_with_options(&path, false, &wrong)
            .expect_err("wrong digest must fail");
        assert!(mismatch.to_string().contains("SHA-256 mismatch"));
        assert!(!transaction_root.exists());
        assert!(!state.join(AUTH_KEY_FILE).exists());

        let options = StateMigrationOptions {
            acknowledge_unauthenticated_claims_v1: true,
            expected_claims_v1_sha256: Some(ISSUE33_CLAIMS_V1_SHA256.to_string()),
        };
        let dry = migrate_repository_state_with_options(&path, false, &options)
            .expect("attested dry run");
        let claims_entry = dry
            .entries
            .iter()
            .find(|entry| entry.store == "claims")
            .expect("claims entry");
        assert_eq!(dry.status, StateMigrationStatus::Ready);
        assert_eq!(
            claims_entry.sha256.as_deref(),
            Some(ISSUE33_CLAIMS_V1_SHA256)
        );
        assert_eq!(claims_entry.legacy_checksum, None);
        assert_eq!(
            claims_entry.provenance,
            Some(LegacyStateProvenance::OperatorAttestedUnauthenticatedImport)
        );
        assert!(!transaction_root.exists());
        assert!(!state.join(AUTH_KEY_FILE).exists());

        let applied =
            migrate_repository_state_with_options(&path, true, &options).expect("attested apply");
        assert_eq!(applied.status, StateMigrationStatus::Applied);
        assert_eq!(applied.manifest_generation, Some(1));
        assert_eq!(
            applied
                .entries
                .iter()
                .find(|entry| entry.store == "claims")
                .expect("applied claims entry")
                .provenance,
            Some(LegacyStateProvenance::OperatorAttestedUnauthenticatedImport)
        );

        let repeated = migrate_repository_state_with_options(&path, true, &options)
            .expect("idempotent attested apply");
        assert_eq!(repeated.status, StateMigrationStatus::AlreadyApplied);
    }

    #[cfg(unix)]
    #[test]
    fn signed_claims_v1_without_attested_provenance_is_refused() {
        let (_temp, path, _state) = repository_with_checksumless_claims_v1();
        let options = StateMigrationOptions {
            acknowledge_unauthenticated_claims_v1: true,
            expected_claims_v1_sha256: Some(ISSUE33_CLAIMS_V1_SHA256.to_string()),
        };
        migrate_repository_state_with_options(&path, true, &options)
            .expect("signed operator-attested migration");

        let authenticator =
            repository_authenticator_key_only(&path).expect("repository authenticator");
        let mut manifest_store = AuthenticatedSnapshotStore::<
            StateMigrationManifestSpec,
            StateMigrationManifest,
        >::open_instance(authenticator, MANIFEST_INSTANCE_ID)
        .expect("manifest store");
        let mut manifest = manifest_store.current().value.clone();
        manifest
            .entries
            .iter_mut()
            .find(|entry| entry.store == "claims")
            .expect("claims entry")
            .provenance = None;
        manifest_store
            .commit(2, manifest)
            .expect("signed misclassified manifest");
        drop(manifest_store);

        let error = authenticated_legacy_adoption(&path, "claims", "claims.json")
            .expect_err("claims-v1 without provenance must fail closed");
        let chain = format!("{error:#}");
        assert!(
            chain.contains("lacks its operator-attested"),
            "unexpected error: {chain}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn migration_preflight_accepts_isolated_legacy_state_directory() {
        let (_temp, path, state) = repository_with_claims();
        make_legacy_permissions(&state);
        let repository = crate::git_repository::open(&path).expect("repository");

        let preflight = preflight_legacy_state(
            &path,
            repository.commondir(),
            &state,
            &StateMigrationOptions::default(),
        )
        .expect("isolated legacy state preflight");

        assert_eq!(preflight.state_root.path(), state);
        assert!(preflight.entries.iter().any(|entry| entry.present));
    }

    #[cfg(unix)]
    #[test]
    fn dry_run_is_non_mutating_and_apply_is_signed_and_idempotent() {
        let (_temp, path, state) = repository_with_claims();
        make_legacy_permissions(&state);
        let repo = crate::git_repository::open(&path).expect("repo");
        let transaction_root = repo.commondir().join(TRANSACTION_ROOT_NAME);

        let dry = migrate_repository_state(&path, false).expect("dry run");
        assert_eq!(dry.status, StateMigrationStatus::Ready);
        assert!(!dry.hardened);
        assert_eq!(mode(&state), 0o755);
        assert_eq!(mode(&state.join("claims.json")), 0o644);
        assert!(!transaction_root.exists());

        let applied = migrate_repository_state(&path, true).expect("apply");
        assert_eq!(applied.status, StateMigrationStatus::Applied);
        assert_eq!(applied.manifest_generation, Some(1));
        assert!(applied
            .entries
            .iter()
            .any(|entry| entry.store == "managed_worktrees" && !entry.present));
        assert_eq!(mode(&state), 0o700);
        for name in [
            "claims.json",
            "claims.lock",
            "semantic_intents.lock",
            "managed_worktrees.lock",
        ] {
            assert_eq!(mode(&state.join(name)), 0o600);
        }
        assert!(transaction_root.join(RECEIPT_FILE).is_file());

        let repeated = migrate_repository_state(&path, true).expect("idempotent apply");
        assert_eq!(repeated.status, StateMigrationStatus::AlreadyApplied);
        assert_eq!(repeated.transaction_phase, Some(MigrationPhase::Completed));
    }

    #[cfg(unix)]
    #[test]
    fn registered_authenticated_consumer_roots_and_state_locks_migrate_across_all_modes() {
        let (_temp, path, state) = empty_repository_state();
        let writer = repository_auth_writer(&path).expect("bootstrap repository authentication");
        drop(writer);

        let binding = expected_bindings_for(&path).repository_state;
        let mut claims = LegacyClaimsState {
            version: 2,
            checksum: String::new(),
            repository: binding,
            next_token: 2,
            claims: vec![PathClaim {
                token: ClaimToken::from_u64(1),
                agent_id: "registered-consumer-migration-test".to_string(),
                paths: vec![PathBuf::from("src")],
            }],
        };
        claims.checksum = stable_checksum(
            &serde_json::to_vec(&(
                claims.version,
                &claims.repository,
                claims.next_token,
                &claims.claims,
            ))
            .expect("claims checksum payload"),
        );
        AtomicStateWriter::write_direct(
            &state,
            "claims.json",
            &serde_json::to_vec_pretty(&claims).expect("claims JSON"),
        )
        .expect("claims state");
        KernelStateLock::acquire_direct(&state, "claims.lock").expect("claims lock");

        let sources = crate::artifacts::state_auth::authenticated_state_consumers();
        assert_eq!(sources.len(), 9, "all authenticated consumer sources");
        let registered_roots = sources
            .iter()
            .map(|source| source.root_name)
            .collect::<BTreeSet<_>>();
        for required in [
            "authenticated-field-guide-state-v1",
            "authenticated-megafile-history-v1",
            "authenticated-generated-follow-up-queues-v1",
        ] {
            assert!(
                registered_roots.contains(required),
                "missing authenticated consumer root {required}"
            );
        }
        let registered_state_root_locks = sources
            .iter()
            .flat_map(|source| source.state_root_lock_names.iter().copied())
            .collect::<BTreeSet<_>>();
        for required in [
            ".authenticated-field-guide.lock",
            "field-guide-operation-v1.lock",
            ".authenticated-megafile-history.lock",
            "megafile-history-operation-v1.lock",
            ".generated-follow-up-queues.lock",
        ] {
            assert!(
                registered_state_root_locks.contains(required),
                "missing authenticated consumer state-root lock {required}"
            );
        }

        for source in sources {
            SafeRoot::open_or_create(state.path().join(source.root_name))
                .expect("registered authenticated consumer root");
            for lock_name in source.state_root_lock_names {
                KernelStateLock::acquire_direct(&state, lock_name)
                    .expect("registered authenticated consumer state-root lock");
            }
        }
        make_legacy_permissions(state.path());

        let dry = migrate_repository_state(&path, false).expect("registered-source dry run");
        assert_eq!(dry.status, StateMigrationStatus::Ready);
        assert_eq!(dry.mode, StateMigrationMode::DryRun);

        let applied = migrate_repository_state(&path, true).expect("registered-source apply");
        assert_eq!(applied.status, StateMigrationStatus::Applied);
        assert_eq!(applied.mode, StateMigrationMode::Apply);

        let repeated_dry =
            migrate_repository_state(&path, false).expect("registered-source repeated dry run");
        assert_eq!(repeated_dry.status, StateMigrationStatus::AlreadyApplied);
        assert_eq!(repeated_dry.mode, StateMigrationMode::DryRun);

        let repeated_apply =
            migrate_repository_state(&path, true).expect("registered-source repeated apply");
        assert_eq!(repeated_apply.status, StateMigrationStatus::AlreadyApplied);
        assert_eq!(repeated_apply.mode, StateMigrationMode::Apply);
    }

    #[cfg(unix)]
    #[test]
    fn publication_transaction_journals_are_inventoried_and_retired_across_all_modes() {
        let (_temp, path, state) = repository_with_claims();
        let journals = state.join(LEGACY_PUBLICATION_TRANSACTIONS_DIR).join("legacy");
        fs::create_dir_all(&journals).expect("legacy publication journals");
        let record = journals.join("00000000000000000001.json");
        fs::write(&record, b"legacy plaintext must remain untouched\n").expect("legacy record");
        make_legacy_permissions(&state);

        assert!(
            !legacy_publication_journals_are_retired(&path).expect("pre-migration retirement query"),
            "unsigned leftover journals are not retired"
        );

        let dry = migrate_repository_state(&path, false).expect("publication-journal dry run");
        assert_eq!(dry.status, StateMigrationStatus::Ready);
        assert_eq!(dry.mode, StateMigrationMode::DryRun);
        assert!(
            !legacy_publication_journals_are_retired(&path).expect("dry-run retirement query"),
            "dry-run must not retire leftover journals"
        );

        let applied = migrate_repository_state(&path, true).expect("publication-journal apply");
        assert_eq!(applied.status, StateMigrationStatus::Applied);
        assert_eq!(applied.mode, StateMigrationMode::Apply);
        assert!(
            legacy_publication_journals_are_retired(&path)
                .expect("applied retirement query"),
            "signed migration must retire leftover publication journals"
        );
        assert_eq!(
            fs::read(&record).expect("legacy record remains after apply"),
            b"legacy plaintext must remain untouched\n"
        );

        let repeated_dry =
            migrate_repository_state(&path, false).expect("publication-journal repeated dry run");
        assert_eq!(repeated_dry.status, StateMigrationStatus::AlreadyApplied);
        let repeated_apply =
            migrate_repository_state(&path, true).expect("publication-journal repeated apply");
        assert_eq!(repeated_apply.status, StateMigrationStatus::AlreadyApplied);
        assert!(legacy_publication_journals_are_retired(&path).expect("repeated retirement query"));
        assert_eq!(
            fs::read(&record).expect("legacy record remains after re-verify"),
            b"legacy plaintext must remain untouched\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn checksumless_semantic_requires_offline_manifest_then_adopts_authenticated_snapshot() {
        let (_temp, path, state, expected_intent) = repository_with_checksumless_semantic();
        let repository = crate::git_repository::open(&path).expect("repository");
        let transaction_root = repository.commondir().join(TRANSACTION_ROOT_NAME);

        let direct_error = SemanticIntentStore::open(&path)
            .expect_err("normal runtime must reject unmanifested checksum-less state");
        assert!(direct_error
            .to_string()
            .contains("signed migration manifest"));
        assert!(!state.join(SemanticSnapshotSpec::ROOT_NAME).exists());

        let dry = migrate_repository_state(&path, false).expect("checksum-less dry run");
        assert_eq!(dry.status, StateMigrationStatus::Ready);
        assert_eq!(dry.mode, StateMigrationMode::DryRun);
        assert!(!transaction_root.exists());
        assert!(!state.join(MANIFEST_ROOT_NAME).exists());

        let applied = migrate_repository_state(&path, true).expect("offline migration apply");
        assert_eq!(applied.status, StateMigrationStatus::Applied);
        assert_eq!(applied.manifest_generation, Some(1));

        let store = SemanticIntentStore::open(&path)
            .expect("signed checksum-less state must adopt into authenticated storage");
        assert_eq!(
            store.snapshot().expect("authenticated snapshot"),
            vec![expected_intent]
        );
        assert!(state.join(SemanticSnapshotSpec::ROOT_NAME).is_dir());
        let tombstone: serde_json::Value = serde_json::from_slice(
            &fs::read(state.join("semantic_intents.json")).expect("active tombstone"),
        )
        .expect("tombstone JSON");
        assert_eq!(tombstone["version"], 3);
        assert_eq!(tombstone["phase"], "active");

        let repeated =
            migrate_repository_state(&path, false).expect("post-adoption manifest verification");
        assert_eq!(repeated.status, StateMigrationStatus::AlreadyApplied);
    }

    #[test]
    fn checksumless_semantic_decoder_is_strict_and_bounded() {
        let (_temp, path, state) = empty_repository_state();
        let invalid_states = [
            serde_json::json!({
                "version": 1,
                "next_token": 1,
                "intents": [],
                "unexpected": true,
            }),
            serde_json::json!({
                "version": 1,
                "next_token": 0,
                "intents": [],
            }),
            serde_json::json!({
                "version": 2,
                "next_token": 1,
                "intents": [],
            }),
        ];
        let repository = crate::git_repository::open(&path).expect("repository");
        let transaction_root = repository.commondir().join(TRANSACTION_ROOT_NAME);

        for value in invalid_states {
            AtomicStateWriter::write_direct(
                &state,
                "semantic_intents.json",
                &serde_json::to_vec_pretty(&value).expect("invalid semantic JSON"),
            )
            .expect("replace invalid semantic state");
            assert!(migrate_repository_state(&path, false).is_err());
            assert!(!transaction_root.exists());
            assert!(!state.path().join(MANIFEST_ROOT_NAME).exists());
        }
    }

    #[test]
    fn checksumless_semantic_decoder_rejects_unknown_nested_intent_fields() {
        let (_temp, path, state) = empty_repository_state();
        let intent = serde_json::json!({
            "token": 1,
            "agent_id": "migration-semantic",
            "paths": ["src/lib.rs"],
            "symbols": [],
            "modules": [],
            "impacted_files": [],
            "task_digest": null,
            "task_excerpt": null,
            "notes": [],
            "warnings": [],
            "unexpected": true,
        });
        AtomicStateWriter::write_direct(
            &state,
            "semantic_intents.json",
            &serde_json::to_vec_pretty(&serde_json::json!({
                "version": 1,
                "next_token": 2,
                "intents": [intent],
            }))
            .expect("invalid nested semantic JSON"),
        )
        .expect("invalid nested semantic state");

        let error = migrate_repository_state(&path, false)
            .expect_err("unknown nested fields must fail closed");
        assert!(error.to_string().contains("strict checksum-less"));
    }

    #[cfg(unix)]
    #[test]
    fn post_adoption_dry_run_and_apply_verify_original_manifest_and_active_tombstone() {
        let (_temp, path, state) = repository_with_claims();
        make_legacy_permissions(&state);
        migrate_repository_state(&path, true).expect("publish signed migration manifest");

        let store = SyncStore::open(&path).expect("adopt signed legacy claims");
        let claims = store.snapshot().expect("authenticated claims");
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].agent_id, "migration-test");
        let tombstone: serde_json::Value =
            serde_json::from_slice(&fs::read(state.join("claims.json")).expect("active tombstone"))
                .expect("tombstone JSON");
        assert_eq!(tombstone["version"], 3);
        assert_eq!(tombstone["phase"], "active");

        let dry = migrate_repository_state(&path, false).expect("post-adoption dry run");
        assert_eq!(dry.status, StateMigrationStatus::AlreadyApplied);
        assert_eq!(dry.transaction_phase, Some(MigrationPhase::Completed));
        let repeated = migrate_repository_state(&path, true).expect("post-adoption apply");
        assert_eq!(repeated.status, StateMigrationStatus::AlreadyApplied);
        assert_eq!(repeated.transaction_phase, Some(MigrationPhase::Completed));
    }

    #[cfg(unix)]
    #[test]
    fn existing_manifest_refuses_transaction_root_replacement_after_preflight() {
        let (_temp, path, state) = repository_with_claims();
        make_legacy_permissions(&state);
        migrate_repository_state(&path, true).expect("publish signed migration manifest");
        let repo = crate::git_repository::open(&path).expect("repo");
        let transaction_root = repo.commondir().join(TRANSACTION_ROOT_NAME);
        let original_root = repo.commondir().join("maco-state-migration-v1.original");
        set_migration_after_preflight_hook({
            let transaction_root = transaction_root.clone();
            let original_root = original_root.clone();
            move || {
                fs::rename(&transaction_root, &original_root).expect("move transaction root");
                fs::create_dir(&transaction_root).expect("replacement transaction root");
                fs::set_permissions(&transaction_root, fs::Permissions::from_mode(0o700))
                    .expect("replacement root mode");
                for name in [TRANSACTION_FILE, RECEIPT_FILE, TRANSACTION_LOCK] {
                    fs::copy(original_root.join(name), transaction_root.join(name))
                        .expect("copy transaction evidence");
                    fs::set_permissions(
                        transaction_root.join(name),
                        fs::Permissions::from_mode(0o600),
                    )
                    .expect("replacement evidence mode");
                }
            }
        });

        let error = migrate_repository_state(&path, false)
            .expect_err("transaction root replacement must fail closed");
        let chain = format!("{error:#}");
        assert!(
            chain.contains("identity changed")
                || chain.contains("no longer identifies")
                || chain.contains("transaction root"),
            "unexpected error: {chain}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn initial_apply_refuses_common_directory_replacement_with_same_state_inode() {
        let (_temp, path, state) = repository_with_claims();
        make_legacy_permissions(&state);
        let repository = crate::git_repository::open(&path).expect("repository");
        let common_dir = repository.commondir().to_path_buf();
        let displaced_common = path.join("displaced-common-dir");
        let state_identity = identity_for_path(&state).expect("state identity");
        set_migration_after_preflight_hook({
            let common_dir = common_dir.clone();
            let displaced_common = displaced_common.clone();
            move || {
                fs::rename(&common_dir, &displaced_common).expect("displace original common dir");
                fs::create_dir(&common_dir).expect("replacement common dir");
                fs::set_permissions(&common_dir, fs::Permissions::from_mode(0o700))
                    .expect("replacement common mode");
                fs::create_dir(common_dir.join("maco")).expect("replacement state parent");
                fs::set_permissions(common_dir.join("maco"), fs::Permissions::from_mode(0o700))
                    .expect("replacement state parent mode");
                fs::rename(
                    displaced_common.join("maco/state"),
                    common_dir.join("maco/state"),
                )
                .expect("return the same state inode under the replacement common dir");
            }
        });

        let error = migrate_repository_state(&path, true)
            .expect_err("common-directory replacement must fail closed");
        let chain = format!("{error:#}");
        assert!(
            chain.contains("common") || chain.contains("safe root path was replaced"),
            "unexpected error: {chain}"
        );
        assert_eq!(
            identity_for_path(common_dir.join("maco/state")).expect("returned state identity"),
            state_identity
        );
        assert!(!common_dir.join(TRANSACTION_ROOT_NAME).exists());
    }

    #[cfg(unix)]
    #[test]
    fn completed_apply_refuses_common_replacement_with_same_state_and_transaction_inodes() {
        let (_temp, path, state) = repository_with_claims();
        make_legacy_permissions(&state);
        let repository = crate::git_repository::open(&path).expect("repository");
        let common_dir = repository.commondir().to_path_buf();
        let displaced_common = path.join("post-manifest-displaced-common");
        let state_identity = identity_for_path(&state).expect("state identity");
        let transaction_identity = std::rc::Rc::new(std::cell::RefCell::new(None));
        set_migration_before_final_verification_hook({
            let common_dir = common_dir.clone();
            let displaced_common = displaced_common.clone();
            let transaction_identity = std::rc::Rc::clone(&transaction_identity);
            move || {
                *transaction_identity.borrow_mut() = Some(
                    identity_for_path(common_dir.join(TRANSACTION_ROOT_NAME))
                        .expect("transaction identity"),
                );
                fs::rename(&common_dir, &displaced_common).expect("displace original common dir");
                fs::create_dir(&common_dir).expect("replacement common dir");
                fs::set_permissions(&common_dir, fs::Permissions::from_mode(0o700))
                    .expect("replacement common mode");
                fs::create_dir(common_dir.join("maco")).expect("replacement state parent");
                fs::set_permissions(common_dir.join("maco"), fs::Permissions::from_mode(0o700))
                    .expect("replacement state parent mode");
                fs::rename(
                    displaced_common.join("maco/state"),
                    common_dir.join("maco/state"),
                )
                .expect("return state inode");
                fs::rename(
                    displaced_common.join(TRANSACTION_ROOT_NAME),
                    common_dir.join(TRANSACTION_ROOT_NAME),
                )
                .expect("return transaction inode");
            }
        });

        let error = migrate_repository_state(&path, true)
            .expect_err("post-manifest common replacement must fail closed");
        let chain = format!("{error:#}");
        assert!(
            chain.contains("safe root path was replaced") || chain.contains("common"),
            "unexpected error: {chain}"
        );
        assert_eq!(
            identity_for_path(common_dir.join("maco/state")).expect("returned state"),
            state_identity
        );
        assert_eq!(
            identity_for_path(common_dir.join(TRANSACTION_ROOT_NAME))
                .expect("returned transaction"),
            transaction_identity
                .borrow()
                .clone()
                .expect("captured transaction identity")
        );
        let transaction: MigrationTransaction = serde_json::from_slice(
            &fs::read(
                common_dir
                    .join(TRANSACTION_ROOT_NAME)
                    .join(TRANSACTION_FILE),
            )
            .expect("completed transaction"),
        )
        .expect("transaction JSON");
        assert_eq!(transaction.phase, MigrationPhase::Completed);
        assert!(common_dir
            .join(TRANSACTION_ROOT_NAME)
            .join(RECEIPT_FILE)
            .is_file());
    }

    #[cfg(unix)]
    #[test]
    fn hardening_refuses_child_replacement_without_chmodding_replacement() {
        let (_temp, path, state) = repository_with_claims();
        make_legacy_permissions(&state);
        let claims = state.join("claims.json");
        let displaced = state.join("claims.json.displaced");
        set_migration_after_child_bind_hook("claims.json", {
            let claims = claims.clone();
            let displaced = displaced.clone();
            move || {
                fs::rename(&claims, &displaced).expect("displace bound claims file");
                fs::write(&claims, b"replacement").expect("replacement claims file");
                fs::set_permissions(&claims, fs::Permissions::from_mode(0o660))
                    .expect("replacement claims mode");
            }
        });

        let error = migrate_repository_state(&path, true)
            .expect_err("child pathname replacement must fail closed");
        let chain = format!("{error:#}");
        assert!(
            chain.contains("binding") || chain.contains("identity"),
            "unexpected error: {chain}"
        );
        assert_eq!(mode(&claims), 0o660);
        assert_eq!(mode(&displaced), 0o644);
        assert!(!state.join(AUTH_KEY_FILE).exists());
    }

    #[cfg(unix)]
    #[test]
    fn hardened_state_check_rejects_special_or_unknown_entries() {
        let (_temp, path, state) = repository_with_claims();
        make_legacy_permissions(&state);
        set_migration_after_preflight_hook({
            let special = state.join("unexpected-special");
            move || {
                let name =
                    std::ffi::CString::new(special.as_os_str().as_bytes()).expect("special path");
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            }
        });

        let error = migrate_repository_state(&path, false)
            .expect_err("special state entry must fail closed");
        assert!(error.to_string().contains("unknown entry"));
    }

    #[cfg(unix)]
    #[test]
    fn existing_manifest_refuses_legacy_lock_rebind_without_advancing_transaction() {
        let (_temp, path, state) = repository_with_claims();
        make_legacy_permissions(&state);
        set_migration_fault(
            MigrationFaultPoint::AfterManifest,
            MigrationFaultAction::Crash,
        );
        migrate_repository_state(&path, true).expect_err("crash after manifest publication");
        let repo = crate::git_repository::open(&path).expect("repo");
        let transaction_root = repo.commondir().join(TRANSACTION_ROOT_NAME);
        assert!(!transaction_root.join(RECEIPT_FILE).exists());
        let lock_path = state.join("claims.lock");
        let original_lock = state.join("claims.lock.preflight-original");
        set_migration_after_preflight_hook({
            let lock_path = lock_path.clone();
            let original_lock = original_lock.clone();
            move || {
                fs::rename(&lock_path, &original_lock).expect("move held legacy lock");
                fs::write(&lock_path, b"").expect("replacement legacy lock");
                fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))
                    .expect("replacement lock mode");
            }
        });

        let error = migrate_repository_state(&path, true)
            .expect_err("legacy lock rebind must fence manifest completion");
        let chain = format!("{error:#}");
        assert!(
            chain.contains("rebound") || chain.contains("opened descriptor"),
            "unexpected error: {chain}"
        );
        assert!(!transaction_root.join(RECEIPT_FILE).exists());
        let transaction: MigrationTransaction = serde_json::from_slice(
            &fs::read(transaction_root.join(TRANSACTION_FILE)).expect("transaction"),
        )
        .expect("transaction JSON");
        assert_eq!(transaction.phase, MigrationPhase::ManifestPublished);
    }

    #[cfg(unix)]
    #[test]
    fn existing_manifest_refuses_tombstone_change_after_preflight_without_rewriting_evidence() {
        let (_temp, path, state) = repository_with_claims();
        make_legacy_permissions(&state);
        migrate_repository_state(&path, true).expect("publish manifest");
        drop(SyncStore::open(&path).expect("adopt claims"));
        let repo = crate::git_repository::open(&path).expect("repo");
        let transaction_root = repo.commondir().join(TRANSACTION_ROOT_NAME);
        let transaction_before =
            fs::read(transaction_root.join(TRANSACTION_FILE)).expect("transaction before");
        let receipt_before = fs::read(transaction_root.join(RECEIPT_FILE)).expect("receipt before");
        let tombstone_path = state.join("claims.json");
        set_migration_after_preflight_hook({
            let tombstone_path = tombstone_path.clone();
            move || {
                let mut bytes = fs::read(&tombstone_path).expect("active tombstone");
                bytes.push(b'\n');
                fs::write(&tombstone_path, bytes).expect("change tombstone bytes");
            }
        });

        let error = migrate_repository_state(&path, false)
            .expect_err("post-preflight tombstone change must fail closed");
        assert!(error.to_string().contains("tombstone changed"));
        assert_eq!(
            fs::read(transaction_root.join(TRANSACTION_FILE)).expect("transaction after"),
            transaction_before
        );
        assert_eq!(
            fs::read(transaction_root.join(RECEIPT_FILE)).expect("receipt after"),
            receipt_before
        );
    }

    #[cfg(unix)]
    #[test]
    fn signed_nonempty_claims_forward_recover_at_every_retirement_fault() {
        for fault in [
            LegacyRetirementFaultPoint::Sidecar,
            LegacyRetirementFaultPoint::Intent,
            LegacyRetirementFaultPoint::PendingTombstone,
            LegacyRetirementFaultPoint::ActiveTombstone,
        ] {
            let (_temp, path, state) = repository_with_claims();
            make_legacy_permissions(&state);
            migrate_repository_state(&path, true).expect("signed migration manifest");
            set_legacy_retirement_fault(fault);
            let error = SyncStore::open(&path).expect_err("retirement fault");
            assert!(error
                .to_string()
                .contains("injected legacy retirement fault"));

            let bytes = fs::read(state.join("claims.json")).expect("legacy filename");
            let value: serde_json::Value = serde_json::from_slice(&bytes).expect("state JSON");
            if matches!(
                fault,
                LegacyRetirementFaultPoint::PendingTombstone
                    | LegacyRetirementFaultPoint::ActiveTombstone
            ) {
                assert_eq!(value["version"], 3);
                assert!(serde_json::from_slice::<LegacyClaimsState>(&bytes).is_err());
            } else {
                assert_eq!(value["version"], 2);
            }

            let store = SyncStore::open(&path).expect("forward recover signed claims");
            let claims = store.snapshot().expect("recovered claims");
            assert_eq!(claims.len(), 1);
            assert_eq!(claims[0].agent_id, "migration-test");
            assert_eq!(claims[0].paths, vec![PathBuf::from("src")]);
        }
    }

    #[cfg(unix)]
    #[test]
    fn corrupt_checksum_refuses_without_any_change() {
        let (_temp, path, state) = repository_with_claims();
        make_legacy_permissions(&state);
        let claims = state.join("claims.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&claims).expect("claims")).expect("JSON");
        value["next_token"] = serde_json::json!(999);
        fs::write(&claims, serde_json::to_vec_pretty(&value).expect("encode"))
            .expect("tamper checksum");
        fs::set_permissions(&claims, fs::Permissions::from_mode(0o644)).expect("mode");

        let error = migrate_repository_state(&path, false).expect_err("checksum mismatch");
        assert!(error.to_string().contains("checksum mismatch"));
        assert_eq!(mode(&state), 0o755);
        let repo = crate::git_repository::open(&path).expect("repo");
        assert!(!repo.commondir().join(TRANSACTION_ROOT_NAME).exists());
    }

    #[cfg(unix)]
    #[test]
    fn active_legacy_lock_refuses_without_changes() {
        let (_temp, path, state) = repository_with_claims();
        let root = SafeRoot::open_existing(&state).expect("state root");
        let _held = KernelStateLock::acquire_direct(&root, "claims.lock").expect("held lock");
        let error = migrate_repository_state(&path, false).expect_err("active lock refusal");
        assert!(error.to_string().contains("active"));
        assert_eq!(mode(&state), 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn normal_fault_rolls_back_while_crash_fault_recovers_forward() {
        let (_temp, path, state) = repository_with_claims();
        make_legacy_permissions(&state);
        set_migration_fault(
            MigrationFaultPoint::AfterPermissions,
            MigrationFaultAction::Error,
        );
        migrate_repository_state(&path, true).expect_err("normal injected failure");
        assert_eq!(mode(&state), 0o755);
        assert_eq!(mode(&state.join("claims.json")), 0o644);
        assert!(!state.join(AUTH_KEY_FILE).exists());

        set_migration_fault(
            MigrationFaultPoint::AfterPermissions,
            MigrationFaultAction::Crash,
        );
        migrate_repository_state(&path, true).expect_err("crash injected failure");
        assert_eq!(mode(&state), 0o700);
        assert_eq!(mode(&state.join("claims.json")), 0o600);
        let recovered = migrate_repository_state(&path, true).expect("forward recovery");
        assert_eq!(recovered.status, StateMigrationStatus::Applied);
    }

    #[test]
    fn foreign_claims_state_is_refused_even_with_a_valid_checksum() {
        let (_source_temp, _source_path, source_state) = repository_with_claims();
        let (_target_temp, target_path, target_state) = empty_repository_state();
        AtomicStateWriter::write_direct(
            &target_state,
            "claims.json",
            &fs::read(source_state.join("claims.json")).expect("source claims"),
        )
        .expect("copy foreign claims");
        let error = migrate_repository_state(&target_path, false)
            .expect_err("foreign claims binding must fail");
        assert!(error.to_string().contains("repository binding"));
    }

    #[test]
    fn foreign_semantic_state_is_refused_even_with_a_valid_checksum() {
        let (_source_temp, source_path, _source_state) = repository_with_claims();
        let source_binding = expected_bindings_for(&source_path).repository_state;
        let mut foreign = LegacySemanticState {
            version: 2,
            checksum: String::new(),
            repository: source_binding,
            next_token: 1,
            intents: Vec::new(),
        };
        foreign.checksum = stable_checksum(
            &serde_json::to_vec(&(
                foreign.version,
                &foreign.repository,
                foreign.next_token,
                &foreign.intents,
            ))
            .expect("semantic checksum payload"),
        );
        let (_target_temp, target_path, target_state) = empty_repository_state();
        AtomicStateWriter::write_direct(
            &target_state,
            "semantic_intents.json",
            &serde_json::to_vec_pretty(&foreign).expect("semantic state"),
        )
        .expect("write foreign semantic state");
        let error = migrate_repository_state(&target_path, false)
            .expect_err("foreign semantic binding must fail");
        assert!(error.to_string().contains("repository binding"));
    }

    #[test]
    fn foreign_managed_registry_is_refused_even_with_a_valid_checksum() {
        let (_source_temp, source_path, _source_state) = repository_with_claims();
        let source_repository = expected_bindings_for(&source_path)
            .managed_repository
            .expect("managed source binding");
        let mut foreign = ManagedWorktreeRegistryWire {
            version: 2,
            checksum: String::new(),
            repository: source_repository,
            records: BTreeMap::new(),
            operations: BTreeMap::new(),
        };
        foreign.checksum = stable_checksum(
            &serde_json::to_vec(&(
                foreign.version,
                &foreign.repository,
                &foreign.records,
                &foreign.operations,
            ))
            .expect("managed checksum payload"),
        );
        let (_target_temp, target_path, target_state) = empty_repository_state();
        AtomicStateWriter::write_direct(
            &target_state,
            "managed_worktrees.json",
            &serde_json::to_vec_pretty(&foreign).expect("managed state"),
        )
        .expect("write foreign managed registry");
        let error = migrate_repository_state(&target_path, false)
            .expect_err("foreign managed binding must fail");
        assert!(error.to_string().contains("repository binding"));
    }
}
