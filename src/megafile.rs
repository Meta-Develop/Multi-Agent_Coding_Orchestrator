//! Bounded repository-authenticated history for language-agnostic megafile signals.
//!
//! This state is authoritative for megafile telemetry. Event-journal copies may
//! improve observability, but callers must not use them in place of this store.

use crate::{
    artifacts::{
        repository_auth_writer, repository_authenticator_key_only,
        state_auth::{
            AuthenticationDomain, BoundStateLock, RepositoryAuthBinding, RepositoryAuthenticator,
        },
    },
    authenticated_snapshot::{AuthenticatedSnapshotStore, SnapshotSpec},
    safe_state::SafeRoot,
    state_journal::JournalSpec,
    sync::{normalize_repo_relative_path, PathClaim},
    sync_store::validate_state_path,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

const STATE_VERSION: u32 = 1;
const RECORD_VERSION: u32 = 1;
const ASSESSMENT_VERSION: u32 = 1;
const REPORT_VERSION: u32 = 1;
const MAX_MEGAFILE_STATE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_MEGAFILE_RECORD_BYTES: u64 = 9 * 1024 * 1024;
const MAX_HISTORY_RECORDS: usize = 16_384;
const MAX_EVENTS_PER_UPDATE: usize = 4_096;
const MAX_REPLACEMENT_PATHS: usize = 1_024;
/// A directory claim may fan out only to this many authenticated file
/// subjects. The claim remains durable and telemetry fails closed rather than
/// silently truncating a broader expansion.
pub const MAX_CLAIM_TELEMETRY_TARGETS: usize = 1_024;
const MAX_SNAPSHOT_ENVELOPE_BYTES: u64 = 64 * 1024;
const MAX_ACCOUNTED_PHYSICAL_BYTES: u64 = 120 * 1024 * 1024;
const MEGAFILE_LOGICAL_ID: &str = "megafile-history";
const MEGAFILE_OPERATION_LOCK: &str = "megafile-history-operation-v1.lock";

pub(crate) enum MegafileSnapshotSpec {}

impl JournalSpec for MegafileSnapshotSpec {
    const FORMAT_VERSION: u32 = 1;
    const NAMESPACE: &'static str = "authenticated_megafile_history";
    const ROOT_NAME: &'static str = "authenticated-megafile-history-v1";
    const ROOT_LOCK_NAME: &'static str = ".authenticated-megafile-history.lock";
    const INSTANCE_LOCK_NAME: &'static str = ".megafile-snapshot.lock";
    const HEAD_FILE_NAME: &'static str = ".head.json";
    const RECORD_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0authenticated-megafile-record\0v1\0");
    const HEAD_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0authenticated-megafile-head\0v1\0");
    const MAX_RECORDS: usize = 4_096;
    const MAX_RECORD_BYTES: u64 = MAX_MEGAFILE_RECORD_BYTES;
    const MAX_TOTAL_BYTES: u64 = 128 * 1024 * 1024;
    const MAX_PHASE_BYTES: usize = 32;
    const MAX_SUBJECT_BYTES: usize = 64;
    const MAX_INSTANCE_ID_BYTES: usize = 128;
}

impl SnapshotSpec for MegafileSnapshotSpec {
    const SNAPSHOT_FORMAT_VERSION: u32 = 1;
    const LOCATOR_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0authenticated-megafile-locator\0v1\0");
}

/// Describes where a threshold set came from. The built-in defaults are
/// deliberately labelled provisional rather than presented as calibrated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MegafileThresholdCalibration {
    BootstrapProvisional,
    Configured,
}

/// Language-agnostic threshold inputs. Every threshold is inclusive.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MegafileThresholds {
    pub calibration: MegafileThresholdCalibration,
    pub file_bytes: u64,
    pub file_lines: u64,
    pub growth_bytes: u64,
    pub growth_lines: u64,
    pub claim_count: u64,
    pub collision_count: u64,
    pub activity_window_records: usize,
}

impl MegafileThresholds {
    /// Bootstrap-only defaults. These values are operational starting points,
    /// not empirically calibrated limits.
    pub fn provisional_bootstrap() -> Self {
        Self {
            calibration: MegafileThresholdCalibration::BootstrapProvisional,
            file_bytes: 512 * 1024,
            file_lines: 4_000,
            growth_bytes: 128 * 1024,
            growth_lines: 1_000,
            claim_count: 8,
            collision_count: 2,
            activity_window_records: 2_048,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.file_bytes == 0
            || self.file_lines == 0
            || self.growth_bytes == 0
            || self.growth_lines == 0
            || self.claim_count == 0
            || self.collision_count == 0
            || self.activity_window_records == 0
            || self.activity_window_records > MAX_HISTORY_RECORDS
        {
            bail!(
                "megafile thresholds must be nonzero and the activity window must not exceed {} records",
                MAX_HISTORY_RECORDS
            );
        }
        Ok(())
    }
}

impl Default for MegafileThresholds {
    fn default() -> Self {
        Self::provisional_bootstrap()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileSizeSample {
    pub path: PathBuf,
    pub bytes: u64,
    pub lines: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum MegafileRecordKind {
    SizeSample { bytes: u64, lines: u64 },
    Claim { claim_token: u64 },
    Collision,
    AcceptedDecomposition { replacement_paths: Vec<PathBuf> },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MegafileRecord {
    pub version: u32,
    pub sequence: u64,
    pub path: PathBuf,
    pub kind: MegafileRecordKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MegafileSignal {
    FileBytes { observed: u64, threshold: u64 },
    FileLines { observed: u64, threshold: u64 },
    GrowthBytes { observed: u64, threshold: u64 },
    GrowthLines { observed: u64, threshold: u64 },
    ClaimCount { observed: u64, threshold: u64 },
    CollisionCount { observed: u64, threshold: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MegafileAssessment {
    pub version: u32,
    pub path: PathBuf,
    pub is_megafile: bool,
    pub signals: Vec<MegafileSignal>,
    pub latest_sample: Option<FileSizeSample>,
    pub previous_sample: Option<FileSizeSample>,
    pub growth_bytes: u64,
    pub growth_lines: u64,
    pub claims_in_window: u64,
    pub collisions_in_window: u64,
    pub accepted_decompositions: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MegafileReport {
    pub version: u32,
    pub thresholds: MegafileThresholds,
    pub record_limit: usize,
    pub state_byte_limit: u64,
    pub serialized_state_bytes: u64,
    pub physical_snapshot_record_limit: usize,
    pub physical_snapshot_records: u64,
    pub physical_snapshot_byte_limit: u64,
    pub physical_snapshot_bytes: u64,
    pub retained_records: usize,
    pub first_retained_sequence: Option<u64>,
    pub next_record_sequence: u64,
    pub records: Vec<MegafileRecord>,
    pub assessments: Vec<MegafileAssessment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedMegafileState {
    version: u32,
    snapshot_revision: u64,
    repository: RepositoryAuthBinding,
    next_record_sequence: u64,
    records: Vec<MegafileRecord>,
    physical_snapshot_records: u64,
    physical_snapshot_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct MegafileStore {
    repo_path: PathBuf,
    thresholds: MegafileThresholds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaimPathState {
    ExistingDirectory,
    ExistingNonDirectory,
    Missing,
}

impl MegafileStore {
    pub fn open(repo_path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_thresholds(repo_path, MegafileThresholds::provisional_bootstrap())
    }

    pub fn open_with_thresholds(
        repo_path: impl AsRef<Path>,
        thresholds: MegafileThresholds,
    ) -> Result<Self> {
        thresholds.validate()?;
        let repo = git2::Repository::discover(repo_path.as_ref()).with_context(|| {
            format!(
                "failed to discover repository from {}",
                repo_path.as_ref().display()
            )
        })?;
        let store = Self {
            repo_path: repo.workdir().unwrap_or_else(|| repo.path()).to_path_buf(),
            thresholds,
        };
        store.ensure_initialized()?;
        Ok(store)
    }

    /// Opens existing telemetry without creating an authentication key,
    /// namespace, locks, or initial snapshot. The returned handle continues to
    /// use read-only authenticated snapshot access for queries.
    pub fn open_existing(repo_path: impl AsRef<Path>) -> Result<Option<Self>> {
        Self::open_existing_with_thresholds(repo_path, MegafileThresholds::provisional_bootstrap())
    }

    pub fn open_existing_with_thresholds(
        repo_path: impl AsRef<Path>,
        thresholds: MegafileThresholds,
    ) -> Result<Option<Self>> {
        thresholds.validate()?;
        let repo = git2::Repository::discover(repo_path.as_ref()).with_context(|| {
            format!(
                "failed to discover repository from {}",
                repo_path.as_ref().display()
            )
        })?;
        let common_root = SafeRoot::open_existing(repo.commondir())
            .context("Git common directory is not safely reachable for megafile query")?;
        let state_path = common_root.path().join("maco").join("state");
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
        let state_root = SafeRoot::open_existing(&state_path)
            .context("repository state root is unsafe for megafile query")?;
        if !state_root.direct_child_exists(MegafileSnapshotSpec::ROOT_NAME)? {
            return Ok(None);
        }
        common_root.verify()?;
        state_root.verify()?;
        let store = Self {
            repo_path: repo.workdir().unwrap_or_else(|| repo.path()).to_path_buf(),
            thresholds,
        };
        store.read_snapshot()?;
        Ok(Some(store))
    }

    pub fn thresholds(&self) -> &MegafileThresholds {
        &self.thresholds
    }

    pub fn record_file_samples<I>(&self, samples: I) -> Result<Vec<MegafileAssessment>>
    where
        I: IntoIterator<Item = FileSizeSample>,
    {
        let mut paths = Vec::new();
        let mut events = Vec::new();
        for sample in samples {
            let path = normalize_telemetry_path(&sample.path)?;
            paths.push(path.clone());
            events.push((
                path,
                MegafileRecordKind::SizeSample {
                    bytes: sample.bytes,
                    lines: sample.lines,
                },
            ));
        }
        self.record_events_and_assess(events, paths)
    }

    pub fn record_claim(&self, claim: &PathClaim) -> Result<Vec<MegafileAssessment>> {
        run_record_claim_fault()?;
        let authenticator = repository_authenticator_key_only(&self.repo_path)?;
        let state_root = authenticator.state_root().clone();
        let operation_lock = BoundStateLock::acquire(&state_root, MEGAFILE_OPERATION_LOCK)?;
        let result = (|| {
            let store = self.open_store_with_authenticator(authenticator)?;
            let targets =
                self.claim_telemetry_targets(&store.current().value.records, &claim.paths)?;
            let mut paths = Vec::new();
            let mut events = Vec::new();
            for path in targets {
                paths.push(path.clone());
                events.push((
                    path,
                    MegafileRecordKind::Claim {
                        claim_token: claim.token.get(),
                    },
                ));
            }
            self.record_events_and_assess_in_store(store, events, paths)
        })();
        finish_operation(result, operation_lock.verify(&state_root))
    }

    fn claim_telemetry_targets(
        &self,
        records: &[MegafileRecord],
        claimed_paths: &[PathBuf],
    ) -> Result<Vec<PathBuf>> {
        let mut active_sampled_paths = BTreeSet::new();
        for record in records {
            match &record.kind {
                MegafileRecordKind::SizeSample { .. } => {
                    active_sampled_paths.insert(record.path.clone());
                }
                MegafileRecordKind::AcceptedDecomposition { .. } => {
                    active_sampled_paths.remove(&record.path);
                }
                MegafileRecordKind::Claim { .. } | MegafileRecordKind::Collision => {}
            }
        }

        let mut normalized_claims = claimed_paths
            .iter()
            .map(|path| normalize_telemetry_path(path))
            .collect::<Result<Vec<_>>>()?;
        normalized_claims.sort();
        normalized_claims.dedup();

        let mut targets = BTreeSet::new();
        for claimed_path in normalized_claims {
            let exact_sample = active_sampled_paths.contains(&claimed_path);
            let descendants = active_sampled_paths
                .iter()
                .filter(|sampled_path| {
                    sampled_path.as_path() != claimed_path
                        && sampled_path.starts_with(&claimed_path)
                })
                .cloned()
                .collect::<Vec<_>>();
            // Current filesystem type is authoritative without walking the
            // claimed subtree. Only a missing path needs history inference:
            // exact evidence means file, descendant evidence means directory,
            // neither preserves exact fallback, and both are ambiguous.
            let inferred_targets = match self.claim_path_state(&claimed_path)? {
                ClaimPathState::ExistingDirectory => descendants,
                ClaimPathState::ExistingNonDirectory => vec![claimed_path.clone()],
                ClaimPathState::Missing if exact_sample && !descendants.is_empty() => {
                    bail!(
                        "missing claimed path '{}' is ambiguous because authenticated megafile telemetry contains both an exact file subject and descendant file subjects",
                        claimed_path.display()
                    );
                }
                ClaimPathState::Missing if exact_sample => vec![claimed_path.clone()],
                ClaimPathState::Missing if !descendants.is_empty() => descendants,
                ClaimPathState::Missing => vec![claimed_path.clone()],
            };

            for target in inferred_targets {
                targets.insert(target);
                if targets.len() > MAX_CLAIM_TELEMETRY_TARGETS {
                    bail!(
                        "megafile claim telemetry expansion exceeds its {}-target limit",
                        MAX_CLAIM_TELEMETRY_TARGETS
                    );
                }
            }
        }
        Ok(targets.into_iter().collect())
    }

    fn claim_path_state(&self, path: &Path) -> Result<ClaimPathState> {
        let absolute = self.repo_path.join(path);
        match fs::symlink_metadata(&absolute) {
            Ok(metadata) if metadata.file_type().is_dir() => Ok(ClaimPathState::ExistingDirectory),
            Ok(_) => Ok(ClaimPathState::ExistingNonDirectory),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(ClaimPathState::Missing)
            }
            Err(error) => Err(error).with_context(|| {
                format!(
                    "failed to distinguish claimed file from directory at {}",
                    absolute.display()
                )
            }),
        }
    }

    pub fn record_collision_paths<I, P>(&self, paths: I) -> Result<Vec<MegafileAssessment>>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let mut affected = Vec::new();
        let mut events = Vec::new();
        for path in paths {
            let path = normalize_telemetry_path(path.as_ref())?;
            affected.push(path.clone());
            events.push((path, MegafileRecordKind::Collision));
        }
        self.record_events_and_assess(events, affected)
    }

    pub fn record_accepted_decomposition<I, P>(
        &self,
        path: impl AsRef<Path>,
        replacement_paths: I,
    ) -> Result<MegafileAssessment>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let path = normalize_telemetry_path(path.as_ref())?;
        let mut replacements = replacement_paths
            .into_iter()
            .map(|replacement| normalize_telemetry_path(replacement.as_ref()))
            .collect::<Result<Vec<_>>>()?;
        replacements.sort();
        replacements.dedup();
        if replacements.len() > MAX_REPLACEMENT_PATHS {
            bail!(
                "accepted decomposition exceeds its replacement path budget of {}",
                MAX_REPLACEMENT_PATHS
            );
        }
        let assessments = self.record_events_and_assess(
            vec![(
                path.clone(),
                MegafileRecordKind::AcceptedDecomposition {
                    replacement_paths: replacements,
                },
            )],
            vec![path],
        )?;
        assessments
            .into_iter()
            .next()
            .context("accepted decomposition lost its assessment")
    }

    pub fn assess_path(&self, path: impl AsRef<Path>) -> Result<Option<MegafileAssessment>> {
        let path = normalize_telemetry_path(path.as_ref())?;
        let snapshot = self.read_snapshot()?;
        let assessment = assess_path(&snapshot.records, &path, &self.thresholds);
        Ok(assessment)
    }

    pub fn report(&self) -> Result<MegafileReport> {
        build_report(&self.read_snapshot()?, self.thresholds.clone())
    }

    fn record_events_and_assess(
        &self,
        events: Vec<(PathBuf, MegafileRecordKind)>,
        affected_paths: Vec<PathBuf>,
    ) -> Result<Vec<MegafileAssessment>> {
        if events.is_empty() {
            return Ok(Vec::new());
        }
        if events.len() > MAX_EVENTS_PER_UPDATE {
            bail!(
                "megafile update exceeds its event budget of {}",
                MAX_EVENTS_PER_UPDATE
            );
        }
        let authenticator = repository_authenticator_key_only(&self.repo_path)?;
        let state_root = authenticator.state_root().clone();
        let operation_lock = BoundStateLock::acquire(&state_root, MEGAFILE_OPERATION_LOCK)?;
        let result = (|| {
            let store = self.open_store_with_authenticator(authenticator)?;
            self.record_events_and_assess_in_store(store, events, affected_paths)
        })();
        finish_operation(result, operation_lock.verify(&state_root))
    }

    fn record_events_and_assess_in_store(
        &self,
        mut store: AuthenticatedSnapshotStore<MegafileSnapshotSpec, AuthenticatedMegafileState>,
        events: Vec<(PathBuf, MegafileRecordKind)>,
        mut affected_paths: Vec<PathBuf>,
    ) -> Result<Vec<MegafileAssessment>> {
        if events.is_empty() {
            return Ok(Vec::new());
        }
        if events.len() > MAX_EVENTS_PER_UPDATE {
            bail!(
                "megafile update exceeds its event budget of {}",
                MAX_EVENTS_PER_UPDATE
            );
        }
        let mut value = store.current().value.clone();
        let revision = value
            .snapshot_revision
            .checked_add(1)
            .context("authenticated megafile snapshot revision exhausted")?;
        for (path, kind) in events {
            validate_record_kind(&kind)?;
            let sequence = value.next_record_sequence;
            value.next_record_sequence = sequence
                .checked_add(1)
                .context("megafile record sequence exhausted")?;
            value.records.push(MegafileRecord {
                version: RECORD_VERSION,
                sequence,
                path,
                kind,
            });
        }
        if value.records.len() > MAX_HISTORY_RECORDS {
            let remove = value.records.len() - MAX_HISTORY_RECORDS;
            value.records.drain(..remove);
        }
        value.snapshot_revision = revision;
        let rollover = prepare_physical_accounting(
            &mut value,
            store.current().value.physical_snapshot_records,
            store.current().value.physical_snapshot_bytes,
        )?;
        validate_state(&value)?;
        if rollover {
            let authenticator = repository_authenticator_key_only(&self.repo_path)?;
            store = store.rollover(authenticator, revision, value)?;
        } else {
            store.commit(revision, value)?;
        }
        self.validate_store(&store)?;
        affected_paths.sort();
        affected_paths.dedup();
        Ok(affected_paths
            .iter()
            .filter_map(|path| assess_path(&store.current().value.records, path, &self.thresholds))
            .collect())
    }

    fn ensure_initialized(&self) -> Result<()> {
        // The writer performs the centralized first-key consumer preflight.
        // This prevents an orphaned megafile namespace from being silently
        // adopted into a replacement key epoch.
        let writer = repository_auth_writer(&self.repo_path)?;
        let authenticator = writer.into_authenticator()?;
        let state_root = authenticator.state_root().clone();
        let operation_lock = BoundStateLock::acquire(&state_root, MEGAFILE_OPERATION_LOCK)?;
        let result = (|| {
            if AuthenticatedSnapshotStore::<
                MegafileSnapshotSpec,
                AuthenticatedMegafileState,
            >::initialized(&authenticator, MEGAFILE_LOGICAL_ID)?
            {
                let store = AuthenticatedSnapshotStore::<
                    MegafileSnapshotSpec,
                    AuthenticatedMegafileState,
                >::open_instance(authenticator, MEGAFILE_LOGICAL_ID)?;
                return self.validate_store(&store);
            }
            let mut initial = AuthenticatedMegafileState {
                version: STATE_VERSION,
                snapshot_revision: 1,
                repository: authenticator.binding().clone(),
                next_record_sequence: 1,
                records: Vec::new(),
                physical_snapshot_records: 0,
                physical_snapshot_bytes: 0,
            };
            set_physical_accounting(&mut initial, 1, 0)?;
            let store = AuthenticatedSnapshotStore::<
                MegafileSnapshotSpec,
                AuthenticatedMegafileState,
            >::create(authenticator, MEGAFILE_LOGICAL_ID, 1, initial)?;
            self.validate_store(&store)
        })();
        finish_operation(result, operation_lock.verify(&state_root))
    }

    fn open_store_with_authenticator(
        &self,
        authenticator: RepositoryAuthenticator,
    ) -> Result<AuthenticatedSnapshotStore<MegafileSnapshotSpec, AuthenticatedMegafileState>> {
        let store = AuthenticatedSnapshotStore::open_instance(authenticator, MEGAFILE_LOGICAL_ID)?;
        self.validate_store(&store)?;
        Ok(store)
    }

    fn read_snapshot(&self) -> Result<AuthenticatedMegafileState> {
        let authenticator = repository_authenticator_key_only(&self.repo_path)?;
        let repository = authenticator.binding().clone();
        let snapshot = AuthenticatedSnapshotStore::<
            MegafileSnapshotSpec,
            AuthenticatedMegafileState,
        >::read_existing_current(authenticator, MEGAFILE_LOGICAL_ID)?;
        validate_snapshot(&snapshot, &repository)?;
        Ok(snapshot.value)
    }

    fn validate_store(
        &self,
        store: &AuthenticatedSnapshotStore<MegafileSnapshotSpec, AuthenticatedMegafileState>,
    ) -> Result<()> {
        validate_snapshot(store.current(), &store.identity().repository)
    }
}

fn finish_operation<T>(result: Result<T>, verification: Result<()>) -> Result<T> {
    match (result, verification) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(lock_error)) => Err(lock_error),
        (Err(error), Err(lock_error)) => Err(error.context(format!(
            "megafile operation also lost its stable lock-path binding: {lock_error:#}"
        ))),
    }
}

fn validate_snapshot(
    snapshot: &crate::authenticated_snapshot::AuthenticatedSnapshot<AuthenticatedMegafileState>,
    repository: &RepositoryAuthBinding,
) -> Result<()> {
    if snapshot.value.version != STATE_VERSION
        || snapshot.value.snapshot_revision != snapshot.generation
        || snapshot.value.snapshot_revision != snapshot.token
        || &snapshot.value.repository != repository
    {
        bail!("authenticated megafile snapshot binding or revision is inconsistent");
    }
    validate_state(&snapshot.value)
}

fn normalize_telemetry_path(path: &Path) -> Result<PathBuf> {
    let normalized = normalize_repo_relative_path(path)?;
    validate_state_path(&normalized)?;
    Ok(normalized)
}

fn validate_record_kind(kind: &MegafileRecordKind) -> Result<()> {
    if let MegafileRecordKind::AcceptedDecomposition { replacement_paths } = kind {
        if replacement_paths.len() > MAX_REPLACEMENT_PATHS {
            bail!(
                "accepted decomposition exceeds its replacement path budget of {}",
                MAX_REPLACEMENT_PATHS
            );
        }
        for path in replacement_paths {
            validate_state_path(path)?;
        }
    }
    Ok(())
}

fn validate_state(state: &AuthenticatedMegafileState) -> Result<()> {
    if state.version != STATE_VERSION
        || state.snapshot_revision == 0
        || state.next_record_sequence == 0
        || state.physical_snapshot_records == 0
        || state.physical_snapshot_records
            > u64::try_from(MegafileSnapshotSpec::MAX_RECORDS).unwrap_or(u64::MAX)
        || state.physical_snapshot_bytes == 0
        || state.physical_snapshot_bytes > MAX_ACCOUNTED_PHYSICAL_BYTES
    {
        bail!("authenticated megafile state has invalid version, sequence, or physical bounds");
    }
    if state.records.len() > MAX_HISTORY_RECORDS {
        bail!(
            "authenticated megafile state exceeds its history budget of {} records",
            MAX_HISTORY_RECORDS
        );
    }
    let mut previous_sequence = None;
    for record in &state.records {
        if record.version != RECORD_VERSION || record.sequence == 0 {
            bail!("authenticated megafile history contains an invalid record version or sequence");
        }
        if let Some(previous) = previous_sequence {
            if record.sequence != previous + 1 {
                bail!("authenticated megafile history contains a sequence gap or reorder");
            }
        }
        if record.sequence >= state.next_record_sequence {
            bail!("authenticated megafile record reaches or exceeds the next sequence");
        }
        validate_state_path(&record.path)?;
        validate_record_kind(&record.kind)?;
        previous_sequence = Some(record.sequence);
    }
    let encoded =
        serde_json::to_vec(state).context("failed to size authenticated megafile state")?;
    if u64::try_from(encoded.len()).unwrap_or(u64::MAX) > MAX_MEGAFILE_STATE_BYTES {
        bail!(
            "authenticated megafile state exceeds its {} byte bound",
            MAX_MEGAFILE_STATE_BYTES
        );
    }
    Ok(())
}

fn prepare_physical_accounting(
    state: &mut AuthenticatedMegafileState,
    current_records: u64,
    current_bytes: u64,
) -> Result<bool> {
    let projected_records = current_records
        .checked_add(1)
        .context("megafile physical snapshot record count exhausted")?;
    set_physical_accounting(state, projected_records, current_bytes)?;
    let record_limit = u64::try_from(MegafileSnapshotSpec::MAX_RECORDS).unwrap_or(u64::MAX);
    if state.physical_snapshot_records > record_limit
        || state.physical_snapshot_bytes > MAX_ACCOUNTED_PHYSICAL_BYTES
    {
        set_physical_accounting(state, 1, 0)?;
        return Ok(true);
    }
    Ok(false)
}

fn set_physical_accounting(
    state: &mut AuthenticatedMegafileState,
    records: u64,
    previous_bytes: u64,
) -> Result<()> {
    state.physical_snapshot_records = records;
    let mut total = previous_bytes;
    for _ in 0..8 {
        state.physical_snapshot_bytes = total;
        let payload_bytes = u64::try_from(
            serde_json::to_vec(state)
                .context("failed to account authenticated megafile snapshot")?
                .len(),
        )
        .context("authenticated megafile snapshot length overflowed")?;
        let next = previous_bytes
            .checked_add(payload_bytes)
            .and_then(|value| value.checked_add(MAX_SNAPSHOT_ENVELOPE_BYTES))
            .context("authenticated megafile physical byte accounting overflowed")?;
        if next == total {
            return Ok(());
        }
        total = next;
    }
    bail!("authenticated megafile physical byte accounting did not converge")
}

fn build_report(
    state: &AuthenticatedMegafileState,
    thresholds: MegafileThresholds,
) -> Result<MegafileReport> {
    thresholds.validate()?;
    let paths = state
        .records
        .iter()
        .map(|record| record.path.clone())
        .collect::<BTreeSet<_>>();
    let assessments = paths
        .iter()
        .filter_map(|path| assess_path(&state.records, path, &thresholds))
        .collect();
    Ok(MegafileReport {
        version: REPORT_VERSION,
        thresholds,
        record_limit: MAX_HISTORY_RECORDS,
        state_byte_limit: MAX_MEGAFILE_STATE_BYTES,
        serialized_state_bytes: u64::try_from(
            serde_json::to_vec(state)
                .context("failed to size megafile report state")?
                .len(),
        )
        .context("megafile report state length overflowed")?,
        physical_snapshot_record_limit: MegafileSnapshotSpec::MAX_RECORDS,
        physical_snapshot_records: state.physical_snapshot_records,
        physical_snapshot_byte_limit: MAX_ACCOUNTED_PHYSICAL_BYTES,
        physical_snapshot_bytes: state.physical_snapshot_bytes,
        retained_records: state.records.len(),
        first_retained_sequence: state.records.first().map(|record| record.sequence),
        next_record_sequence: state.next_record_sequence,
        records: state.records.clone(),
        assessments,
    })
}

#[cfg(test)]
thread_local! {
    static RECORD_CLAIM_FAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn set_record_claim_fault() {
    RECORD_CLAIM_FAULT.with(|fault| fault.set(true));
}

#[cfg(test)]
fn run_record_claim_fault() -> Result<()> {
    if RECORD_CLAIM_FAULT.with(|fault| fault.replace(false)) {
        bail!("injected authenticated megafile claim-recording fault");
    }
    Ok(())
}

#[cfg(not(test))]
fn run_record_claim_fault() -> Result<()> {
    Ok(())
}

fn assess_path(
    records: &[MegafileRecord],
    path: &Path,
    thresholds: &MegafileThresholds,
) -> Option<MegafileAssessment> {
    let matching = records
        .iter()
        .filter(|record| record.path == path)
        .collect::<Vec<_>>();
    if matching.is_empty() {
        return None;
    }
    let last_decomposition_sequence = matching.iter().rev().find_map(|record| {
        matches!(
            record.kind,
            MegafileRecordKind::AcceptedDecomposition { .. }
        )
        .then_some(record.sequence)
    });
    let activity_start = records
        .len()
        .saturating_sub(thresholds.activity_window_records);
    let window = &records[activity_start..];
    let in_active_epoch = |record: &&MegafileRecord| {
        record.path == path
            && last_decomposition_sequence
                .map(|sequence| record.sequence > sequence)
                .unwrap_or(true)
    };
    let claims_in_window = u64::try_from(
        window
            .iter()
            .filter(in_active_epoch)
            .filter(|record| matches!(record.kind, MegafileRecordKind::Claim { .. }))
            .count(),
    )
    .unwrap_or(u64::MAX);
    let collisions_in_window = u64::try_from(
        window
            .iter()
            .filter(in_active_epoch)
            .filter(|record| matches!(record.kind, MegafileRecordKind::Collision))
            .count(),
    )
    .unwrap_or(u64::MAX);
    let accepted_decompositions = u64::try_from(
        matching
            .iter()
            .filter(|record| {
                matches!(
                    record.kind,
                    MegafileRecordKind::AcceptedDecomposition { .. }
                )
            })
            .count(),
    )
    .unwrap_or(u64::MAX);
    let mut samples = matching
        .iter()
        .filter(|record| {
            last_decomposition_sequence
                .map(|sequence| record.sequence > sequence)
                .unwrap_or(true)
        })
        .filter_map(|record| match record.kind {
            MegafileRecordKind::SizeSample { bytes, lines } => Some(FileSizeSample {
                path: path.to_path_buf(),
                bytes,
                lines,
            }),
            _ => None,
        });
    let mut previous_sample = None;
    let mut latest_sample = None;
    for sample in samples.by_ref() {
        previous_sample = latest_sample.replace(sample);
    }
    let growth_bytes = match (&previous_sample, &latest_sample) {
        (Some(previous), Some(latest)) => latest.bytes.saturating_sub(previous.bytes),
        _ => 0,
    };
    let growth_lines = match (&previous_sample, &latest_sample) {
        (Some(previous), Some(latest)) => latest.lines.saturating_sub(previous.lines),
        _ => 0,
    };
    let mut signals = Vec::new();
    if let Some(sample) = &latest_sample {
        if sample.bytes >= thresholds.file_bytes {
            signals.push(MegafileSignal::FileBytes {
                observed: sample.bytes,
                threshold: thresholds.file_bytes,
            });
        }
        if sample.lines >= thresholds.file_lines {
            signals.push(MegafileSignal::FileLines {
                observed: sample.lines,
                threshold: thresholds.file_lines,
            });
        }
    }
    if growth_bytes >= thresholds.growth_bytes {
        signals.push(MegafileSignal::GrowthBytes {
            observed: growth_bytes,
            threshold: thresholds.growth_bytes,
        });
    }
    if growth_lines >= thresholds.growth_lines {
        signals.push(MegafileSignal::GrowthLines {
            observed: growth_lines,
            threshold: thresholds.growth_lines,
        });
    }
    if claims_in_window >= thresholds.claim_count {
        signals.push(MegafileSignal::ClaimCount {
            observed: claims_in_window,
            threshold: thresholds.claim_count,
        });
    }
    if collisions_in_window >= thresholds.collision_count {
        signals.push(MegafileSignal::CollisionCount {
            observed: collisions_in_window,
            threshold: thresholds.collision_count,
        });
    }
    Some(MegafileAssessment {
        version: ASSESSMENT_VERSION,
        path: path.to_path_buf(),
        is_megafile: !signals.is_empty(),
        signals,
        latest_sample,
        previous_sample,
        growth_bytes,
        growth_lines,
        claims_in_window,
        collisions_in_window,
        accepted_decompositions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        artifacts::state_auth::authentication_key_file_name, sync::ClaimToken,
        worktree::WorktreeManager,
    };
    use tempfile::TempDir;

    fn test_store(repo_path: &Path, mut thresholds: MegafileThresholds) -> Result<MegafileStore> {
        thresholds.calibration = MegafileThresholdCalibration::Configured;
        MegafileStore::open_with_thresholds(repo_path, thresholds)
    }

    #[test]
    fn records_language_agnostic_samples_and_growth_across_reopen() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let thresholds = MegafileThresholds {
            file_bytes: 1_000,
            file_lines: 100,
            growth_bytes: 200,
            growth_lines: 20,
            claim_count: 10,
            collision_count: 10,
            activity_window_records: 64,
            ..MegafileThresholds::provisional_bootstrap()
        };
        let store = test_store(&repo_path, thresholds.clone()).expect("open store");
        store
            .record_file_samples([FileSizeSample {
                path: PathBuf::from("src/module.py"),
                bytes: 800,
                lines: 80,
            }])
            .expect("first sample");
        drop(store);

        let reopened = test_store(&repo_path, thresholds).expect("reopen store");
        let assessment = reopened
            .record_file_samples([FileSizeSample {
                path: PathBuf::from("src/module.py"),
                bytes: 1_100,
                lines: 105,
            }])
            .expect("second sample")
            .pop()
            .expect("assessment");

        assert!(assessment.is_megafile);
        assert_eq!(assessment.growth_bytes, 300);
        assert_eq!(assessment.growth_lines, 25);
        assert_eq!(assessment.signals.len(), 4);
    }

    #[test]
    fn claim_collision_and_accepted_decomposition_are_typed_and_bounded() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let thresholds = MegafileThresholds {
            file_bytes: u64::MAX,
            file_lines: u64::MAX,
            growth_bytes: u64::MAX,
            growth_lines: u64::MAX,
            claim_count: 2,
            collision_count: 1,
            activity_window_records: 64,
            ..MegafileThresholds::provisional_bootstrap()
        };
        let store = test_store(&repo_path, thresholds).expect("open store");
        let first = PathClaim {
            token: ClaimToken::from_u64(1),
            agent_id: "agent-a".to_string(),
            paths: vec![PathBuf::from("src/large.c")],
        };
        let second = PathClaim {
            token: ClaimToken::from_u64(2),
            agent_id: "agent-b".to_string(),
            paths: vec![PathBuf::from("src/large.c")],
        };
        assert!(!store.record_claim(&first).expect("first claim")[0].is_megafile);
        assert!(store.record_claim(&second).expect("second claim")[0].is_megafile);
        assert!(
            store
                .record_collision_paths(["src/large.c"])
                .expect("collision")[0]
                .is_megafile
        );

        let completed = store
            .record_accepted_decomposition(
                "src/large.c",
                ["src/large/parser.c", "src/large/writer.c"],
            )
            .expect("accepted decomposition");
        assert!(!completed.is_megafile);
        assert_eq!(completed.claims_in_window, 0);
        assert_eq!(completed.collisions_in_window, 0);
        assert_eq!(completed.accepted_decompositions, 1);
    }

    #[test]
    fn exact_file_fallback_excludes_existing_empty_directories() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        fs::create_dir_all(repo_path.join("src/empty")).expect("create empty directory");
        fs::write(repo_path.join("src/new.rs"), b"fn new() {}\n").expect("write exact file");
        let thresholds = MegafileThresholds {
            file_bytes: u64::MAX,
            file_lines: u64::MAX,
            growth_bytes: u64::MAX,
            growth_lines: u64::MAX,
            claim_count: 1,
            collision_count: u64::MAX,
            activity_window_records: 64,
            ..MegafileThresholds::provisional_bootstrap()
        };
        let store = test_store(&repo_path, thresholds).expect("open store");

        let directory = PathClaim {
            token: ClaimToken::from_u64(1),
            agent_id: "directory-agent".to_string(),
            paths: vec![PathBuf::from("src/empty")],
        };
        assert!(store
            .record_claim(&directory)
            .expect("record directory claim")
            .is_empty());
        assert!(store
            .assess_path("src/empty")
            .expect("assess directory")
            .is_none());

        let file = PathClaim {
            token: ClaimToken::from_u64(2),
            agent_id: "file-agent".to_string(),
            paths: vec![PathBuf::from("src/new.rs")],
        };
        let assessments = store.record_claim(&file).expect("record exact file claim");
        assert_eq!(assessments.len(), 1);
        assert_eq!(assessments[0].path, PathBuf::from("src/new.rs"));
        assert_eq!(assessments[0].claims_in_window, 1);
        assert!(assessments[0].is_megafile);
    }

    #[test]
    fn directory_to_file_type_churn_uses_current_exact_file_only() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        fs::create_dir_all(repo_path.join("src")).expect("create former directory");
        fs::write(repo_path.join("src/item.rs"), b"former child\n").expect("write former child");
        let thresholds = MegafileThresholds {
            file_bytes: u64::MAX,
            file_lines: u64::MAX,
            growth_bytes: u64::MAX,
            growth_lines: u64::MAX,
            claim_count: 1,
            collision_count: u64::MAX,
            activity_window_records: 64,
            ..MegafileThresholds::provisional_bootstrap()
        };
        let store = test_store(&repo_path, thresholds).expect("open store");
        store
            .record_file_samples([FileSizeSample {
                path: PathBuf::from("src/item.rs"),
                bytes: 13,
                lines: 1,
            }])
            .expect("record former descendant");

        fs::remove_file(repo_path.join("src/item.rs")).expect("remove former child");
        fs::remove_dir(repo_path.join("src")).expect("remove former directory");
        fs::write(repo_path.join("src"), b"current file\n").expect("replace directory with file");
        let claim = PathClaim {
            token: ClaimToken::from_u64(1),
            agent_id: "file-agent".to_string(),
            paths: vec![PathBuf::from("src")],
        };

        let assessments = store
            .record_claim(&claim)
            .expect("record current file claim");
        assert_eq!(assessments.len(), 1);
        assert_eq!(assessments[0].path, PathBuf::from("src"));
        assert_eq!(assessments[0].claims_in_window, 1);
        assert_eq!(
            store
                .assess_path("src/item.rs")
                .expect("assess stale descendant")
                .expect("retained former sample")
                .claims_in_window,
            0
        );
    }

    #[test]
    fn missing_path_inference_is_deterministic_and_ambiguous_history_fails_closed() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let thresholds = MegafileThresholds {
            file_bytes: u64::MAX,
            file_lines: u64::MAX,
            growth_bytes: u64::MAX,
            growth_lines: u64::MAX,
            claim_count: 1,
            collision_count: u64::MAX,
            activity_window_records: 64,
            ..MegafileThresholds::provisional_bootstrap()
        };
        let store = test_store(&repo_path, thresholds).expect("open store");
        store
            .record_file_samples([
                FileSizeSample {
                    path: PathBuf::from("missing-exact"),
                    bytes: 1,
                    lines: 1,
                },
                FileSizeSample {
                    path: PathBuf::from("missing-directory/child.rs"),
                    bytes: 1,
                    lines: 1,
                },
                FileSizeSample {
                    path: PathBuf::from("missing-ambiguous"),
                    bytes: 1,
                    lines: 1,
                },
                FileSizeSample {
                    path: PathBuf::from("missing-ambiguous/child.rs"),
                    bytes: 1,
                    lines: 1,
                },
            ])
            .expect("record missing-path evidence");

        for (token, claimed, expected) in [
            (1, "missing-exact", "missing-exact"),
            (2, "missing-directory", "missing-directory/child.rs"),
            (3, "missing-new", "missing-new"),
        ] {
            let claim = PathClaim {
                token: ClaimToken::from_u64(token),
                agent_id: format!("agent-{token}"),
                paths: vec![PathBuf::from(claimed)],
            };
            let assessments = store.record_claim(&claim).expect("record inferred claim");
            assert_eq!(assessments.len(), 1);
            assert_eq!(assessments[0].path, PathBuf::from(expected));
        }

        let before = store.report().expect("report before ambiguous claim");
        let ambiguous = PathClaim {
            token: ClaimToken::from_u64(4),
            agent_id: "ambiguous-agent".to_string(),
            paths: vec![PathBuf::from("missing-ambiguous")],
        };
        let error = store
            .record_claim(&ambiguous)
            .expect_err("ambiguous missing path must fail closed");
        assert!(error.to_string().contains(
            "authenticated megafile telemetry contains both an exact file subject and descendant file subjects"
        ));
        let after = store.report().expect("report after ambiguous claim");
        assert_eq!(after.next_record_sequence, before.next_record_sequence);
        assert_eq!(after.retained_records, before.retained_records);
    }

    #[test]
    fn provisional_defaults_are_explicit_and_config_validation_is_fail_closed() {
        let defaults = MegafileThresholds::default();
        assert_eq!(
            defaults.calibration,
            MegafileThresholdCalibration::BootstrapProvisional
        );
        let mut invalid = defaults;
        invalid.activity_window_records = MAX_HISTORY_RECORDS + 1;
        assert!(invalid
            .validate()
            .expect_err("oversized window")
            .to_string()
            .contains("activity window"));
    }

    #[test]
    fn absent_read_only_open_does_not_create_authentication_or_namespace_state() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let state_root = repo_path.join(".git/maco/state");

        assert!(MegafileStore::open_existing(&repo_path)
            .expect("read-only query")
            .is_none());
        assert!(!state_root.join(authentication_key_file_name()).exists());
        assert!(!state_root.join(MegafileSnapshotSpec::ROOT_NAME).exists());
    }

    #[test]
    fn physical_snapshot_accounting_rolls_before_journal_total_byte_limit() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let store = MegafileStore::open(&repo_path).expect("open store");
        let mut state = store.read_snapshot().expect("authenticated state");

        let rollover = prepare_physical_accounting(
            &mut state,
            u64::try_from(MegafileSnapshotSpec::MAX_RECORDS).expect("record bound"),
            MAX_ACCOUNTED_PHYSICAL_BYTES,
        )
        .expect("account next snapshot");

        assert!(rollover);
        assert_eq!(state.physical_snapshot_records, 1);
        assert!(state.physical_snapshot_bytes < MAX_ACCOUNTED_PHYSICAL_BYTES);
        let report = build_report(&state, MegafileThresholds::default()).expect("report");
        assert_eq!(report.state_byte_limit, MAX_MEGAFILE_STATE_BYTES);
        assert!(report.serialized_state_bytes <= report.state_byte_limit);
    }
}
