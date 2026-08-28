//! Deterministic, observation-only replay of recorded execution runs.
//!
//! This module deliberately has no filesystem, process, Git, worktree, clock,
//! random-number, provider, or forge dependency. Replay reconstructs only
//! recorded state, observations, terminal work outcomes, and external-effect
//! evidence. It never re-executes work or an external effect.
//!
//! # Boundary contract
//!
//! [`ReplayBoundaryContract::observation_only`] is the only replay mode. It
//! replays recorded state, observations, work outcomes, and external-effect
//! evidence, and it does not re-execute work or external effects. Git
//! mutations, worktree creation, provider calls, and forge calls stay disarmed
//! unless a caller supplies an exact one-shot [`EffectRearmCapability`].
//! Forking copies recorded evidence, including publication receipts stored in
//! effect outcomes, onto a new child lineage and leaves the parent archive
//! untouched.
//!
//! Pending, uncertain, or ambiguous points are refused with stable
//! [`ReplayError`] codes rather than skipped. Supervisor resume of pending or
//! uncertain execution is owned by `supervise` and is already a typed
//! refusal; this module does not call or mutate that path.

use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

mod journal;
mod taxonomy;

pub const EXECUTION_REPLAY_VERSION: u32 = 1;
pub const MAX_ARCHIVE_JSON_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_VALUE_JSON_BYTES: usize = 64 * 1024;
pub const MAX_RUNS: usize = 1024;
pub const MAX_EVENTS_PER_RUN: usize = 4096;
pub const MAX_TOTAL_EVENTS: usize = 65_536;
pub const MAX_SNAPSHOT_ENTRIES: usize = 4096;
pub const MAX_REARM_CAPABILITIES: usize = 4096;

const MAX_ID_BYTES: usize = 128;
const MAX_ACTION_BYTES: usize = 192;
const MAX_STATE_KEY_BYTES: usize = 256;
const MAX_MESSAGE_BYTES: usize = 16 * 1024;
const MAX_TAG_BYTES: usize = 512;

macro_rules! bounded_string_type {
    ($name:ident, $field:literal, $max:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ReplayError> {
                let value = value.into();
                validate_bounded_name($field, &value, $max)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(D::Error::custom)
            }
        }
    };
}

bounded_string_type!(RunId, "run_id", MAX_ID_BYTES);
bounded_string_type!(WorkId, "work_id", MAX_ID_BYTES);
bounded_string_type!(ObservationId, "observation_id", MAX_ID_BYTES);
bounded_string_type!(EffectId, "effect_id", MAX_ID_BYTES);
bounded_string_type!(CapabilityId, "capability_id", MAX_ID_BYTES);
bounded_string_type!(JournalId, "journal_id", MAX_ID_BYTES);
bounded_string_type!(StateKey, "state_key", MAX_STATE_KEY_BYTES);
bounded_string_type!(EffectAction, "effect_action", MAX_ACTION_BYTES);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineagePoint {
    pub run_id: RunId,
    pub sequence: u64,
}

impl LineagePoint {
    pub fn new(run_id: RunId, sequence: u64) -> Self {
        Self { run_id, sequence }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParentLineage {
    pub branch_point: LineagePoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectCategory {
    GitMutation,
    WorktreeCreation,
    ProviderCall,
    ForgeCall,
    ExternalProcess,
    FilesystemMutation,
    OtherNamedExternalEffect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectDescriptor {
    pub effect_id: EffectId,
    pub action: EffectAction,
    pub category: EffectCategory,
}

impl EffectDescriptor {
    pub fn new(effect_id: EffectId, action: EffectAction, category: EffectCategory) -> Self {
        Self {
            effect_id,
            action,
            category,
        }
    }
}

impl RecordedEffectEvidence {
    /// Transaction id copied from a recorded publication receipt, if present.
    ///
    /// Replay never synthesizes a new receipt; forks inherit this exact value.
    pub fn recorded_receipt_transaction_id(&self) -> Option<&str> {
        match &self.outcome {
            ExternalEffectOutcome::Completed { outcome } => outcome
                .get("publication_receipt")
                .and_then(|value| value.get("transaction_id"))
                .or_else(|| outcome.get("transaction_id"))
                .and_then(Value::as_str),
            ExternalEffectOutcome::Failed { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkOutcome {
    Completed { outcome: Value },
    Failed { error: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExternalEffectOutcome {
    Completed { outcome: Value },
    Failed { error: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedEffectEvidence {
    pub version: u32,
    pub descriptor: EffectDescriptor,
    pub observation: Option<Value>,
    pub outcome: ExternalEffectOutcome,
}

/// A binding copied only after another component has authenticated a journal.
///
/// This type performs structural and bounds validation only; it does **not**
/// authenticate a tag. A future adapter to `state_journal` must construct this
/// value only after a read-only authenticated journal open and must preserve
/// the exact point, journal id, record sequence, and record tag checked there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedCheckpointEvidence {
    version: u32,
    point: LineagePoint,
    journal_id: JournalId,
    record_sequence: u64,
    record_tag: String,
}

impl AuthenticatedCheckpointEvidence {
    pub fn from_authenticated_record(
        point: LineagePoint,
        journal_id: JournalId,
        record_sequence: u64,
        record_tag: impl Into<String>,
    ) -> Result<Self, ReplayError> {
        let evidence = Self {
            version: EXECUTION_REPLAY_VERSION,
            point,
            journal_id,
            record_sequence,
            record_tag: record_tag.into(),
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn point(&self) -> &LineagePoint {
        &self.point
    }

    pub fn journal_id(&self) -> &JournalId {
        &self.journal_id
    }

    pub fn record_sequence(&self) -> u64 {
        self.record_sequence
    }

    pub fn record_tag(&self) -> &str {
        &self.record_tag
    }

    fn validate(&self) -> Result<(), ReplayError> {
        validate_version("checkpoint_evidence", self.version)?;
        validate_bounded_text("record_tag", &self.record_tag, MAX_TAG_BYTES)?;
        if self.record_sequence == 0 || self.record_sequence != self.point.sequence {
            return Err(ReplayError::InconsistentLineage {
                run_id: self.point.run_id.clone(),
                detail: LineageInconsistency::CheckpointPointBinding,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaySnapshot {
    pub version: u32,
    pub state: BTreeMap<StateKey, Value>,
    pub observations: BTreeMap<ObservationId, Value>,
    pub work_outcomes: BTreeMap<WorkId, WorkOutcome>,
    pub effect_evidence: BTreeMap<EffectId, RecordedEffectEvidence>,
    pub checkpoint_evidence: Option<AuthenticatedCheckpointEvidence>,
}

impl ReplaySnapshot {
    pub fn empty() -> Self {
        Self {
            version: EXECUTION_REPLAY_VERSION,
            state: BTreeMap::new(),
            observations: BTreeMap::new(),
            work_outcomes: BTreeMap::new(),
            effect_evidence: BTreeMap::new(),
            checkpoint_evidence: None,
        }
    }

    fn validate(&self) -> Result<(), ReplayError> {
        validate_version("snapshot", self.version)?;
        validate_map_count("snapshot.state", self.state.len())?;
        validate_map_count("snapshot.observations", self.observations.len())?;
        validate_map_count("snapshot.work_outcomes", self.work_outcomes.len())?;
        validate_map_count("snapshot.effect_evidence", self.effect_evidence.len())?;
        for value in self.state.values() {
            validate_value("snapshot.state.value", value)?;
        }
        for value in self.observations.values() {
            validate_value("snapshot.observations.value", value)?;
        }
        for outcome in self.work_outcomes.values() {
            validate_work_outcome(outcome)?;
        }
        for (effect_id, evidence) in &self.effect_evidence {
            validate_recorded_effect(evidence)?;
            if effect_id != &evidence.descriptor.effect_id {
                return Err(ReplayError::InvalidTransition {
                    run_id: None,
                    sequence: 0,
                    subject: effect_id.as_str().to_string(),
                    transition: TransitionViolation::EffectIdentityMismatch,
                });
            }
        }
        if let Some(evidence) = &self.checkpoint_evidence {
            evidence.validate()?;
        }
        Ok(())
    }
}

impl Default for ReplaySnapshot {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReplayEventKind {
    StateSet {
        key: StateKey,
        value: Value,
    },
    StateRemoved {
        key: StateKey,
    },
    ObservationRecorded {
        observation_id: ObservationId,
        value: Value,
    },
    WorkPlanned {
        work_id: WorkId,
    },
    WorkStarted {
        work_id: WorkId,
    },
    WorkCompleted {
        work_id: WorkId,
        outcome: Value,
    },
    WorkFailed {
        work_id: WorkId,
        error: String,
    },
    ExternalEffectPlanned {
        effect: EffectDescriptor,
    },
    ExternalEffectStarted {
        effect_id: EffectId,
    },
    ExternalEffectObserved {
        effect_id: EffectId,
        observation: Value,
    },
    ExternalEffectCompleted {
        effect_id: EffectId,
        outcome: Value,
    },
    ExternalEffectFailed {
        effect_id: EffectId,
        error: String,
    },
    CheckpointEvidenceRecorded {
        evidence: AuthenticatedCheckpointEvidence,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayEvent {
    pub version: u32,
    pub sequence: u64,
    pub event: ReplayEventKind,
}

impl ReplayEvent {
    pub fn new(sequence: u64, event: ReplayEventKind) -> Self {
        Self {
            version: EXECUTION_REPLAY_VERSION,
            sequence,
            event,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunLineage {
    pub version: u32,
    pub run_id: RunId,
    pub parent: Option<ParentLineage>,
    pub base_snapshot: ReplaySnapshot,
    pub events: Vec<ReplayEvent>,
}

impl RunLineage {
    pub fn root(run_id: RunId, base_snapshot: ReplaySnapshot) -> Self {
        Self {
            version: EXECUTION_REPLAY_VERSION,
            run_id,
            parent: None,
            base_snapshot,
            events: Vec::new(),
        }
    }

    pub fn child(run_id: RunId, branch_point: LineagePoint, base_snapshot: ReplaySnapshot) -> Self {
        Self {
            version: EXECUTION_REPLAY_VERSION,
            run_id,
            parent: Some(ParentLineage { branch_point }),
            base_snapshot,
            events: Vec::new(),
        }
    }

    pub fn latest_point(&self) -> Result<LineagePoint, ReplayError> {
        let sequence =
            u64::try_from(self.events.len()).map_err(|_| ReplayError::BoundExceeded {
                field: "run.events",
                limit: MAX_EVENTS_PER_RUN,
                actual: self.events.len(),
            })?;
        Ok(LineagePoint::new(self.run_id.clone(), sequence))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionReplayArchive {
    pub version: u32,
    pub runs: Vec<RunLineage>,
}

impl ExecutionReplayArchive {
    pub fn new(mut runs: Vec<RunLineage>) -> Result<Self, ReplayError> {
        runs.sort_by(|left, right| left.run_id.cmp(&right.run_id));
        let archive = Self {
            version: EXECUTION_REPLAY_VERSION,
            runs,
        };
        archive.validate()?;
        Ok(archive)
    }

    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, ReplayError> {
        if bytes.is_empty() || bytes.len() > MAX_ARCHIVE_JSON_BYTES {
            return Err(ReplayError::BoundExceeded {
                field: "archive_json_bytes",
                limit: MAX_ARCHIVE_JSON_BYTES,
                actual: bytes.len(),
            });
        }
        let archive: Self = serde_json::from_slice(bytes).map_err(|_| ReplayError::Parse {
            entity: "execution_replay_archive",
        })?;
        archive.validate()?;
        Ok(archive)
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>, ReplayError> {
        self.validate()?;
        bounded_json_bytes(
            "execution_replay_archive",
            "archive_json_bytes",
            self,
            MAX_ARCHIVE_JSON_BYTES,
        )
    }

    pub fn validate(&self) -> Result<(), ReplayError> {
        validate_version("archive", self.version)?;
        if self.runs.len() > MAX_RUNS {
            return Err(ReplayError::BoundExceeded {
                field: "archive.runs",
                limit: MAX_RUNS,
                actual: self.runs.len(),
            });
        }
        let index = self.build_index()?;
        let mut total_events = 0_usize;
        for run in &self.runs {
            validate_version("run_lineage", run.version)?;
            run.base_snapshot.validate()?;
            if run.events.len() > MAX_EVENTS_PER_RUN {
                return Err(ReplayError::BoundExceeded {
                    field: "run.events",
                    limit: MAX_EVENTS_PER_RUN,
                    actual: run.events.len(),
                });
            }
            total_events =
                total_events
                    .checked_add(run.events.len())
                    .ok_or(ReplayError::BoundExceeded {
                        field: "archive.total_events",
                        limit: MAX_TOTAL_EVENTS,
                        actual: usize::MAX,
                    })?;
            if total_events > MAX_TOTAL_EVENTS {
                return Err(ReplayError::BoundExceeded {
                    field: "archive.total_events",
                    limit: MAX_TOTAL_EVENTS,
                    actual: total_events,
                });
            }
            validate_run_events(run, None)?;
        }
        self.validate_lineage(&index)?;
        bounded_json_bytes(
            "execution_replay_archive",
            "archive_json_bytes",
            self,
            MAX_ARCHIVE_JSON_BYTES,
        )?;
        Ok(())
    }

    /// Inspects `point` without mutating this archive or any live run.
    pub fn inspect_at(&self, point: &LineagePoint) -> Result<InspectionResult, ReplayError> {
        self.validate()?;
        let index = self.build_index()?;
        inspect_point(&index, point)
    }

    pub fn replay_at(&self, point: &LineagePoint) -> Result<ReplayResult, ReplayError> {
        let inspection = self.inspect_at(point)?;
        Ok(ReplayResult {
            version: EXECUTION_REPLAY_VERSION,
            contract: ReplayBoundaryContract::observation_only(),
            inspection,
        })
    }

    /// Creates a new archive containing a child run and leaves `self` untouched.
    pub fn fork(
        &self,
        branch_point: &LineagePoint,
        child_run_id: RunId,
    ) -> Result<Self, ReplayError> {
        self.validate()?;
        if child_run_id == branch_point.run_id
            || self.runs.iter().any(|run| run.run_id == child_run_id)
        {
            return Err(ReplayError::DuplicateRun {
                run_id: child_run_id,
            });
        }
        let inspection = self.inspect_at(branch_point)?;
        let child = RunLineage::child(
            child_run_id.clone(),
            branch_point.clone(),
            inspection.snapshot,
        );
        let mut forked = self.clone();
        let insertion = forked
            .runs
            .binary_search_by(|run| run.run_id.cmp(&child_run_id))
            .unwrap_or_else(|index| index);
        forked.runs.insert(insertion, child);
        forked.validate()?;
        Ok(forked)
    }

    pub fn fork_run(
        &self,
        child_run_id: RunId,
        branch_point: &LineagePoint,
    ) -> Result<RunLineage, ReplayError> {
        let forked = self.fork(branch_point, child_run_id.clone())?;
        forked
            .runs
            .into_iter()
            .find(|run| run.run_id == child_run_id)
            .ok_or_else(|| ReplayError::MissingPoint {
                point: LineagePoint::new(child_run_id, 0),
            })
    }

    pub fn children_of(&self, parent_run_id: &RunId) -> Result<Vec<&RunLineage>, ReplayError> {
        self.validate()?;
        if !self.runs.iter().any(|run| &run.run_id == parent_run_id) {
            return Err(ReplayError::MissingPoint {
                point: LineagePoint::new(parent_run_id.clone(), 0),
            });
        }
        Ok(self
            .runs
            .iter()
            .filter(|run| match run.parent.as_ref() {
                Some(parent) => &parent.branch_point.run_id == parent_run_id,
                None => false,
            })
            .collect())
    }

    fn build_index(&self) -> Result<BTreeMap<RunId, &RunLineage>, ReplayError> {
        let mut index = BTreeMap::new();
        let mut previous: Option<&RunId> = None;
        for run in &self.runs {
            if let Some(previous) = previous {
                if previous == &run.run_id {
                    return Err(ReplayError::DuplicateRun {
                        run_id: run.run_id.clone(),
                    });
                }
                if previous > &run.run_id {
                    return Err(ReplayError::InconsistentLineage {
                        run_id: run.run_id.clone(),
                        detail: LineageInconsistency::NonCanonicalRunOrder,
                    });
                }
            }
            if index.insert(run.run_id.clone(), run).is_some() {
                return Err(ReplayError::DuplicateRun {
                    run_id: run.run_id.clone(),
                });
            }
            previous = Some(&run.run_id);
        }
        Ok(index)
    }

    fn validate_lineage(&self, index: &BTreeMap<RunId, &RunLineage>) -> Result<(), ReplayError> {
        for run in &self.runs {
            if let Some(parent) = &run.parent {
                if parent.branch_point.run_id == run.run_id {
                    return Err(ReplayError::LineageCycle {
                        run_id: run.run_id.clone(),
                    });
                }
                let parent_run = index.get(&parent.branch_point.run_id).ok_or_else(|| {
                    ReplayError::MissingParent {
                        run_id: run.run_id.clone(),
                        parent_run_id: parent.branch_point.run_id.clone(),
                    }
                })?;
                let maximum = u64::try_from(parent_run.events.len()).map_err(|_| {
                    ReplayError::BoundExceeded {
                        field: "run.events",
                        limit: MAX_EVENTS_PER_RUN,
                        actual: parent_run.events.len(),
                    }
                })?;
                if parent.branch_point.sequence > maximum {
                    return Err(ReplayError::MissingPoint {
                        point: parent.branch_point.clone(),
                    });
                }
            }
        }
        detect_cycles(index)?;
        for run in &self.runs {
            if let Some(parent) = &run.parent {
                let inherited = inspect_point(index, &parent.branch_point)?.snapshot;
                if inherited != run.base_snapshot {
                    return Err(ReplayError::InconsistentLineage {
                        run_id: run.run_id.clone(),
                        detail: LineageInconsistency::BaseSnapshotMismatch,
                    });
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayedMaterial {
    RecordedState,
    RecordedObservations,
    RecordedWorkOutcomes,
    RecordedExternalEffectEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotReexecutedMaterial {
    Work,
    ExternalEffects,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayMode {
    ObservationOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayBoundaryContract {
    pub version: u32,
    pub mode: ReplayMode,
    pub replayed: BTreeSet<ReplayedMaterial>,
    pub not_reexecuted: BTreeSet<NotReexecutedMaterial>,
    pub effects_disarmed: bool,
}

impl ReplayBoundaryContract {
    pub fn observation_only() -> Self {
        Self {
            version: EXECUTION_REPLAY_VERSION,
            mode: ReplayMode::ObservationOnly,
            replayed: BTreeSet::from([
                ReplayedMaterial::RecordedState,
                ReplayedMaterial::RecordedObservations,
                ReplayedMaterial::RecordedWorkOutcomes,
                ReplayedMaterial::RecordedExternalEffectEvidence,
            ]),
            not_reexecuted: BTreeSet::from([
                NotReexecutedMaterial::Work,
                NotReexecutedMaterial::ExternalEffects,
            ]),
            effects_disarmed: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InspectionResult {
    pub version: u32,
    pub point: LineagePoint,
    pub snapshot: ReplaySnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayResult {
    pub version: u32,
    pub contract: ReplayBoundaryContract,
    pub inspection: InspectionResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectRequest {
    pub version: u32,
    pub point: LineagePoint,
    pub effect_id: EffectId,
    pub action: EffectAction,
    pub category: EffectCategory,
}

impl EffectRequest {
    pub fn new(point: LineagePoint, descriptor: EffectDescriptor) -> Self {
        Self {
            version: EXECUTION_REPLAY_VERSION,
            point,
            effect_id: descriptor.effect_id,
            action: descriptor.action,
            category: descriptor.category,
        }
    }

    fn validate(&self) -> Result<(), ReplayError> {
        validate_version("effect_request", self.version)?;
        validate_lineage_point(&self.point)
    }
}

/// Explicit, exact, one-shot authorization material for an effect guard.
///
/// The capability is intentionally neither `Copy` nor `Clone`; callers must
/// move it into `EffectGuard::authorize`. Capability ids are supplied by the
/// trusted caller because this pure module does not use a clock or randomness.
#[derive(Debug, PartialEq, Eq)]
pub struct EffectRearmCapability {
    capability_id: CapabilityId,
    request: EffectRequest,
}

impl EffectRearmCapability {
    pub fn new(capability_id: CapabilityId, request: EffectRequest) -> Result<Self, ReplayError> {
        request.validate()?;
        Ok(Self {
            capability_id,
            request,
        })
    }

    pub fn capability_id(&self) -> &CapabilityId {
        &self.capability_id
    }
}

/// Opaque proof that one exact request was authorized. It performs no effect.
#[derive(Debug, PartialEq, Eq)]
pub struct EffectPermit {
    capability_id: CapabilityId,
    request: EffectRequest,
}

impl EffectPermit {
    pub fn capability_id(&self) -> &CapabilityId {
        &self.capability_id
    }

    pub fn request(&self) -> &EffectRequest {
        &self.request
    }
}

#[derive(Debug, Default)]
pub struct EffectGuard {
    consumed_capability_ids: BTreeSet<CapabilityId>,
}

impl EffectGuard {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn authorize(
        &mut self,
        request: &EffectRequest,
        capability: Option<EffectRearmCapability>,
    ) -> Result<EffectPermit, ReplayError> {
        request.validate()?;
        let capability = capability.ok_or_else(|| ReplayError::EffectDisarmed {
            request: request.clone(),
        })?;
        let capability_id = capability.capability_id;
        if self.consumed_capability_ids.contains(&capability_id) {
            return Err(ReplayError::RearmReused { capability_id });
        }
        if self.consumed_capability_ids.len() >= MAX_REARM_CAPABILITIES {
            return Err(ReplayError::BoundExceeded {
                field: "effect_guard.consumed_capabilities",
                limit: MAX_REARM_CAPABILITIES,
                actual: self.consumed_capability_ids.len(),
            });
        }
        self.consumed_capability_ids.insert(capability_id.clone());
        if capability.request != *request {
            return Err(ReplayError::RearmMismatch { capability_id });
        }
        Ok(EffectPermit {
            capability_id,
            request: capability.request,
        })
    }

    pub fn has_consumed(&self, capability_id: &CapabilityId) -> bool {
        self.consumed_capability_ids.contains(capability_id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineageInconsistency {
    NonCanonicalRunOrder,
    BaseSnapshotMismatch,
    CheckpointPointBinding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionViolation {
    DuplicateObservation,
    MissingStateKey,
    WorkAlreadyKnown,
    WorkStartWithoutPlan,
    WorkOutcomeWithoutUniqueStart,
    EffectAlreadyKnown,
    EffectStartWithoutPlan,
    EffectObservationWithoutStart,
    EffectOutcomeWithoutObservation,
    EffectFailureWithoutStart,
    EffectIdentityMismatch,
    CheckpointPointMismatch,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReplayError {
    #[error("replay point does not exist")]
    MissingPoint { point: LineagePoint },
    #[error("lineage parent does not exist")]
    MissingParent { run_id: RunId, parent_run_id: RunId },
    #[error("run id is duplicated")]
    DuplicateRun { run_id: RunId },
    #[error("event sequence is duplicated")]
    DuplicateSequence { run_id: RunId, sequence: u64 },
    #[error("event sequence is out of order")]
    OutOfOrderSequence {
        run_id: RunId,
        expected: u64,
        actual: u64,
    },
    #[error("event sequence has a gap")]
    SequenceGap {
        run_id: RunId,
        expected: u64,
        actual: u64,
    },
    #[error("lineage is inconsistent")]
    InconsistentLineage {
        run_id: RunId,
        detail: LineageInconsistency,
    },
    #[error("lineage contains a cycle")]
    LineageCycle { run_id: RunId },
    #[error("recorded lifecycle transition is invalid")]
    InvalidTransition {
        run_id: Option<RunId>,
        sequence: u64,
        subject: String,
        transition: TransitionViolation,
    },
    #[error("execution is still planned or pending")]
    PendingExecution {
        point: LineagePoint,
        subject: String,
    },
    #[error("started execution has no durable outcome")]
    UncertainExecution {
        point: LineagePoint,
        subject: String,
    },
    #[error("observed external effect has no durable terminal outcome")]
    AmbiguousExternalEffect {
        point: LineagePoint,
        effect_id: EffectId,
    },
    #[error("external effects are disarmed")]
    EffectDisarmed { request: EffectRequest },
    #[error("effect re-arm capability does not exactly match the request")]
    RearmMismatch { capability_id: CapabilityId },
    #[error("effect re-arm capability id was already consumed")]
    RearmReused { capability_id: CapabilityId },
    #[error("serialized replay state is malformed")]
    Parse { entity: &'static str },
    #[error("a bounded replay field exceeds its limit")]
    BoundExceeded {
        field: &'static str,
        limit: usize,
        actual: usize,
    },
    #[error("a replay identifier is not canonical")]
    InvalidIdentifier { field: &'static str },
    #[error("serialized replay state has an unsupported version")]
    UnsupportedVersion {
        entity: &'static str,
        expected: u32,
        actual: u32,
    },
}

impl ReplayError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingPoint { .. } => "replay_missing_point",
            Self::MissingParent { .. } => "replay_missing_parent",
            Self::DuplicateRun { .. } => "replay_duplicate_run",
            Self::DuplicateSequence { .. } => "replay_duplicate_sequence",
            Self::OutOfOrderSequence { .. } => "replay_out_of_order_sequence",
            Self::SequenceGap { .. } => "replay_sequence_gap",
            Self::InconsistentLineage { .. } => "replay_inconsistent_lineage",
            Self::LineageCycle { .. } => "replay_lineage_cycle",
            Self::InvalidTransition { .. } => "replay_invalid_transition",
            Self::PendingExecution { .. } => "replay_pending_execution",
            Self::UncertainExecution { .. } => "replay_uncertain_execution",
            Self::AmbiguousExternalEffect { .. } => "replay_ambiguous_external_effect",
            Self::EffectDisarmed { .. } => "replay_effect_disarmed",
            Self::RearmMismatch { .. } => "replay_rearm_mismatch",
            Self::RearmReused { .. } => "replay_rearm_reused",
            Self::Parse { .. } => "replay_parse_error",
            Self::BoundExceeded { .. } => "replay_bound_exceeded",
            Self::InvalidIdentifier { .. } => "replay_invalid_identifier",
            Self::UnsupportedVersion { .. } => "replay_unsupported_version",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WorkLifecycle {
    Planned,
    Started,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EffectLifecycle {
    Planned(EffectDescriptor),
    Started(EffectDescriptor),
    Observed(EffectDescriptor, Value),
}

#[derive(Debug, Clone)]
struct ReplayAccumulator {
    snapshot: ReplaySnapshot,
    work: BTreeMap<WorkId, WorkLifecycle>,
    effects: BTreeMap<EffectId, EffectLifecycle>,
}

impl ReplayAccumulator {
    fn new(snapshot: ReplaySnapshot) -> Self {
        Self {
            snapshot,
            work: BTreeMap::new(),
            effects: BTreeMap::new(),
        }
    }

    fn apply(&mut self, run_id: &RunId, event: &ReplayEvent) -> Result<(), ReplayError> {
        validate_version("replay_event", event.version)?;
        match &event.event {
            ReplayEventKind::StateSet { key, value } => {
                validate_value("event.state.value", value)?;
                self.snapshot.state.insert(key.clone(), value.clone());
            }
            ReplayEventKind::StateRemoved { key } => {
                if self.snapshot.state.remove(key).is_none() {
                    return Err(invalid_transition(
                        run_id,
                        event.sequence,
                        key.as_str(),
                        TransitionViolation::MissingStateKey,
                    ));
                }
            }
            ReplayEventKind::ObservationRecorded {
                observation_id,
                value,
            } => {
                validate_value("event.observation.value", value)?;
                if self
                    .snapshot
                    .observations
                    .insert(observation_id.clone(), value.clone())
                    .is_some()
                {
                    return Err(invalid_transition(
                        run_id,
                        event.sequence,
                        observation_id.as_str(),
                        TransitionViolation::DuplicateObservation,
                    ));
                }
            }
            ReplayEventKind::WorkPlanned { work_id } => {
                if self.snapshot.work_outcomes.contains_key(work_id)
                    || self
                        .work
                        .insert(work_id.clone(), WorkLifecycle::Planned)
                        .is_some()
                {
                    return Err(invalid_transition(
                        run_id,
                        event.sequence,
                        work_id.as_str(),
                        TransitionViolation::WorkAlreadyKnown,
                    ));
                }
            }
            ReplayEventKind::WorkStarted { work_id } => match self.work.get_mut(work_id) {
                Some(state @ WorkLifecycle::Planned) => *state = WorkLifecycle::Started,
                _ => {
                    return Err(invalid_transition(
                        run_id,
                        event.sequence,
                        work_id.as_str(),
                        TransitionViolation::WorkStartWithoutPlan,
                    ))
                }
            },
            ReplayEventKind::WorkCompleted { work_id, outcome } => {
                validate_value("event.work.outcome", outcome)?;
                self.finish_work(
                    run_id,
                    event.sequence,
                    work_id,
                    WorkOutcome::Completed {
                        outcome: outcome.clone(),
                    },
                )?;
            }
            ReplayEventKind::WorkFailed { work_id, error } => {
                validate_bounded_text("event.work.error", error, MAX_MESSAGE_BYTES)?;
                self.finish_work(
                    run_id,
                    event.sequence,
                    work_id,
                    WorkOutcome::Failed {
                        error: error.clone(),
                    },
                )?;
            }
            ReplayEventKind::ExternalEffectPlanned { effect } => {
                if self
                    .snapshot
                    .effect_evidence
                    .contains_key(&effect.effect_id)
                    || self
                        .effects
                        .insert(
                            effect.effect_id.clone(),
                            EffectLifecycle::Planned(effect.clone()),
                        )
                        .is_some()
                {
                    return Err(invalid_transition(
                        run_id,
                        event.sequence,
                        effect.effect_id.as_str(),
                        TransitionViolation::EffectAlreadyKnown,
                    ));
                }
            }
            ReplayEventKind::ExternalEffectStarted { effect_id } => {
                match self.effects.get_mut(effect_id) {
                    Some(state @ EffectLifecycle::Planned(_)) => {
                        let descriptor = match state {
                            EffectLifecycle::Planned(descriptor) => descriptor.clone(),
                            _ => {
                                return Err(invalid_transition(
                                    run_id,
                                    event.sequence,
                                    effect_id.as_str(),
                                    TransitionViolation::EffectStartWithoutPlan,
                                ))
                            }
                        };
                        *state = EffectLifecycle::Started(descriptor);
                    }
                    _ => {
                        return Err(invalid_transition(
                            run_id,
                            event.sequence,
                            effect_id.as_str(),
                            TransitionViolation::EffectStartWithoutPlan,
                        ))
                    }
                }
            }
            ReplayEventKind::ExternalEffectObserved {
                effect_id,
                observation,
            } => {
                validate_value("event.effect.observation", observation)?;
                match self.effects.get_mut(effect_id) {
                    Some(state @ EffectLifecycle::Started(_)) => {
                        let descriptor = match state {
                            EffectLifecycle::Started(descriptor) => descriptor.clone(),
                            _ => {
                                return Err(invalid_transition(
                                    run_id,
                                    event.sequence,
                                    effect_id.as_str(),
                                    TransitionViolation::EffectObservationWithoutStart,
                                ))
                            }
                        };
                        *state = EffectLifecycle::Observed(descriptor, observation.clone());
                    }
                    _ => {
                        return Err(invalid_transition(
                            run_id,
                            event.sequence,
                            effect_id.as_str(),
                            TransitionViolation::EffectObservationWithoutStart,
                        ))
                    }
                }
            }
            ReplayEventKind::ExternalEffectCompleted { effect_id, outcome } => {
                validate_value("event.effect.outcome", outcome)?;
                let lifecycle = self.effects.remove(effect_id).ok_or_else(|| {
                    invalid_transition(
                        run_id,
                        event.sequence,
                        effect_id.as_str(),
                        TransitionViolation::EffectOutcomeWithoutObservation,
                    )
                })?;
                let (descriptor, observation) = match lifecycle {
                    EffectLifecycle::Observed(descriptor, observation) => (descriptor, observation),
                    other => {
                        self.effects.insert(effect_id.clone(), other);
                        return Err(invalid_transition(
                            run_id,
                            event.sequence,
                            effect_id.as_str(),
                            TransitionViolation::EffectOutcomeWithoutObservation,
                        ));
                    }
                };
                self.snapshot.effect_evidence.insert(
                    effect_id.clone(),
                    RecordedEffectEvidence {
                        version: EXECUTION_REPLAY_VERSION,
                        descriptor,
                        observation: Some(observation),
                        outcome: ExternalEffectOutcome::Completed {
                            outcome: outcome.clone(),
                        },
                    },
                );
            }
            ReplayEventKind::ExternalEffectFailed { effect_id, error } => {
                validate_bounded_text("event.effect.error", error, MAX_MESSAGE_BYTES)?;
                let lifecycle = self.effects.remove(effect_id).ok_or_else(|| {
                    invalid_transition(
                        run_id,
                        event.sequence,
                        effect_id.as_str(),
                        TransitionViolation::EffectFailureWithoutStart,
                    )
                })?;
                let descriptor = match lifecycle {
                    EffectLifecycle::Started(descriptor) => descriptor,
                    other => {
                        self.effects.insert(effect_id.clone(), other);
                        return Err(invalid_transition(
                            run_id,
                            event.sequence,
                            effect_id.as_str(),
                            TransitionViolation::EffectFailureWithoutStart,
                        ));
                    }
                };
                self.snapshot.effect_evidence.insert(
                    effect_id.clone(),
                    RecordedEffectEvidence {
                        version: EXECUTION_REPLAY_VERSION,
                        descriptor,
                        observation: None,
                        outcome: ExternalEffectOutcome::Failed {
                            error: error.clone(),
                        },
                    },
                );
            }
            ReplayEventKind::CheckpointEvidenceRecorded { evidence } => {
                evidence.validate()?;
                if evidence.point.run_id != *run_id || evidence.point.sequence != event.sequence {
                    return Err(invalid_transition(
                        run_id,
                        event.sequence,
                        evidence.journal_id.as_str(),
                        TransitionViolation::CheckpointPointMismatch,
                    ));
                }
                self.snapshot.checkpoint_evidence = Some(evidence.clone());
            }
        }
        validate_map_count("snapshot.state", self.snapshot.state.len())?;
        validate_map_count("snapshot.observations", self.snapshot.observations.len())?;
        validate_map_count("snapshot.work_outcomes", self.snapshot.work_outcomes.len())?;
        validate_map_count(
            "snapshot.effect_evidence",
            self.snapshot.effect_evidence.len(),
        )?;
        Ok(())
    }

    fn finish_work(
        &mut self,
        run_id: &RunId,
        sequence: u64,
        work_id: &WorkId,
        outcome: WorkOutcome,
    ) -> Result<(), ReplayError> {
        match self.work.remove(work_id) {
            Some(WorkLifecycle::Started) => {
                self.snapshot.work_outcomes.insert(work_id.clone(), outcome);
                Ok(())
            }
            Some(other) => {
                self.work.insert(work_id.clone(), other);
                Err(invalid_transition(
                    run_id,
                    sequence,
                    work_id.as_str(),
                    TransitionViolation::WorkOutcomeWithoutUniqueStart,
                ))
            }
            None => Err(invalid_transition(
                run_id,
                sequence,
                work_id.as_str(),
                TransitionViolation::WorkOutcomeWithoutUniqueStart,
            )),
        }
    }

    fn ensure_inspectable(&self, point: &LineagePoint) -> Result<(), ReplayError> {
        if let Some((work_id, state)) = self.work.iter().next() {
            return match state {
                WorkLifecycle::Planned => Err(ReplayError::PendingExecution {
                    point: point.clone(),
                    subject: work_id.as_str().to_string(),
                }),
                WorkLifecycle::Started => Err(ReplayError::UncertainExecution {
                    point: point.clone(),
                    subject: work_id.as_str().to_string(),
                }),
            };
        }
        if let Some((effect_id, state)) = self.effects.iter().next() {
            return match state {
                EffectLifecycle::Planned(_) => Err(ReplayError::PendingExecution {
                    point: point.clone(),
                    subject: effect_id.as_str().to_string(),
                }),
                EffectLifecycle::Started(_) => Err(ReplayError::UncertainExecution {
                    point: point.clone(),
                    subject: effect_id.as_str().to_string(),
                }),
                EffectLifecycle::Observed(_, _) => Err(ReplayError::AmbiguousExternalEffect {
                    point: point.clone(),
                    effect_id: effect_id.clone(),
                }),
            };
        }
        Ok(())
    }
}

fn validate_run_events(
    run: &RunLineage,
    through_sequence: Option<u64>,
) -> Result<ReplayAccumulator, ReplayError> {
    let mut accumulator = ReplayAccumulator::new(run.base_snapshot.clone());
    let mut expected = 1_u64;
    let mut all_sequences = BTreeSet::new();
    for event in &run.events {
        if !all_sequences.insert(event.sequence) {
            return Err(ReplayError::DuplicateSequence {
                run_id: run.run_id.clone(),
                sequence: event.sequence,
            });
        }
    }
    for (index, event) in run.events.iter().enumerate() {
        if event.sequence < expected {
            return Err(ReplayError::OutOfOrderSequence {
                run_id: run.run_id.clone(),
                expected,
                actual: event.sequence,
            });
        }
        if event.sequence > expected {
            let next_index = index.checked_add(1).ok_or(ReplayError::BoundExceeded {
                field: "run.events",
                limit: MAX_EVENTS_PER_RUN,
                actual: run.events.len(),
            })?;
            let expected_appears_later = match run.events.get(next_index..) {
                Some(later_events) => later_events.iter().any(|later| later.sequence == expected),
                None => false,
            };
            return if expected_appears_later {
                Err(ReplayError::OutOfOrderSequence {
                    run_id: run.run_id.clone(),
                    expected,
                    actual: event.sequence,
                })
            } else {
                Err(ReplayError::SequenceGap {
                    run_id: run.run_id.clone(),
                    expected,
                    actual: event.sequence,
                })
            };
        }
        let should_apply = match through_sequence {
            Some(through) => event.sequence <= through,
            None => true,
        };
        if should_apply {
            accumulator.apply(&run.run_id, event)?;
        }
        expected = expected.checked_add(1).ok_or(ReplayError::BoundExceeded {
            field: "event.sequence",
            limit: MAX_EVENTS_PER_RUN,
            actual: usize::MAX,
        })?;
    }
    Ok(accumulator)
}

fn inspect_point(
    index: &BTreeMap<RunId, &RunLineage>,
    point: &LineagePoint,
) -> Result<InspectionResult, ReplayError> {
    let run = index
        .get(&point.run_id)
        .ok_or_else(|| ReplayError::MissingPoint {
            point: point.clone(),
        })?;
    let maximum = u64::try_from(run.events.len()).map_err(|_| ReplayError::BoundExceeded {
        field: "run.events",
        limit: MAX_EVENTS_PER_RUN,
        actual: run.events.len(),
    })?;
    if point.sequence > maximum {
        return Err(ReplayError::MissingPoint {
            point: point.clone(),
        });
    }
    let accumulator = validate_run_events(run, Some(point.sequence))?;
    accumulator.ensure_inspectable(point)?;
    Ok(InspectionResult {
        version: EXECUTION_REPLAY_VERSION,
        point: point.clone(),
        snapshot: accumulator.snapshot,
    })
}

fn detect_cycles(index: &BTreeMap<RunId, &RunLineage>) -> Result<(), ReplayError> {
    for run_id in index.keys() {
        let mut path = BTreeSet::new();
        let mut current = Some(run_id);
        while let Some(id) = current {
            if !path.insert(id.clone()) {
                return Err(ReplayError::LineageCycle { run_id: id.clone() });
            }
            current = index
                .get(id)
                .and_then(|run| run.parent.as_ref())
                .map(|parent| &parent.branch_point.run_id);
        }
    }
    Ok(())
}

fn invalid_transition(
    run_id: &RunId,
    sequence: u64,
    subject: &str,
    transition: TransitionViolation,
) -> ReplayError {
    ReplayError::InvalidTransition {
        run_id: Some(run_id.clone()),
        sequence,
        subject: subject.to_string(),
        transition,
    }
}

fn validate_version(entity: &'static str, actual: u32) -> Result<(), ReplayError> {
    if actual != EXECUTION_REPLAY_VERSION {
        return Err(ReplayError::UnsupportedVersion {
            entity,
            expected: EXECUTION_REPLAY_VERSION,
            actual,
        });
    }
    Ok(())
}

fn validate_lineage_point(_point: &LineagePoint) -> Result<(), ReplayError> {
    Ok(())
}

fn bounded_json_bytes<T: Serialize>(
    entity: &'static str,
    field: &'static str,
    value: &T,
    limit: usize,
) -> Result<Vec<u8>, ReplayError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ReplayError::Parse { entity })?;
    if bytes.len() > limit {
        return Err(ReplayError::BoundExceeded {
            field,
            limit,
            actual: bytes.len(),
        });
    }
    Ok(bytes)
}

fn validate_bounded_name(
    field: &'static str,
    value: &str,
    limit: usize,
) -> Result<(), ReplayError> {
    validate_bounded_text(field, value, limit)?;
    if matches!(value, "." | "..")
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
    {
        return Err(ReplayError::InvalidIdentifier { field });
    }
    Ok(())
}

fn validate_bounded_text(
    field: &'static str,
    value: &str,
    limit: usize,
) -> Result<(), ReplayError> {
    if value.is_empty() || value.len() > limit {
        return Err(ReplayError::BoundExceeded {
            field,
            limit,
            actual: value.len(),
        });
    }
    if value.contains('\0') {
        return Err(ReplayError::InvalidIdentifier { field });
    }
    Ok(())
}

fn validate_map_count(field: &'static str, actual: usize) -> Result<(), ReplayError> {
    if actual > MAX_SNAPSHOT_ENTRIES {
        return Err(ReplayError::BoundExceeded {
            field,
            limit: MAX_SNAPSHOT_ENTRIES,
            actual,
        });
    }
    Ok(())
}

fn validate_value(field: &'static str, value: &Value) -> Result<(), ReplayError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ReplayError::Parse { entity: field })?;
    if bytes.len() > MAX_VALUE_JSON_BYTES {
        return Err(ReplayError::BoundExceeded {
            field,
            limit: MAX_VALUE_JSON_BYTES,
            actual: bytes.len(),
        });
    }
    Ok(())
}

fn validate_work_outcome(outcome: &WorkOutcome) -> Result<(), ReplayError> {
    match outcome {
        WorkOutcome::Completed { outcome } => validate_value("work_outcome.value", outcome),
        WorkOutcome::Failed { error } => {
            validate_bounded_text("work_outcome.error", error, MAX_MESSAGE_BYTES)
        }
    }
}

fn validate_recorded_effect(evidence: &RecordedEffectEvidence) -> Result<(), ReplayError> {
    validate_version("recorded_effect_evidence", evidence.version)?;
    if let Some(observation) = &evidence.observation {
        validate_value("effect_evidence.observation", observation)?;
    }
    match &evidence.outcome {
        ExternalEffectOutcome::Completed { outcome } => {
            if evidence.observation.is_none() {
                return Err(ReplayError::InvalidTransition {
                    run_id: None,
                    sequence: 0,
                    subject: evidence.descriptor.effect_id.as_str().to_string(),
                    transition: TransitionViolation::EffectOutcomeWithoutObservation,
                });
            }
            validate_value("effect_evidence.outcome", outcome)
        }
        ExternalEffectOutcome::Failed { error } => {
            if evidence.observation.is_some() {
                return Err(ReplayError::InvalidTransition {
                    run_id: None,
                    sequence: 0,
                    subject: evidence.descriptor.effect_id.as_str().to_string(),
                    transition: TransitionViolation::EffectFailureWithoutStart,
                });
            }
            validate_bounded_text("effect_evidence.error", error, MAX_MESSAGE_BYTES)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn run_id(value: &str) -> RunId {
        RunId::new(value).expect("valid run id")
    }

    fn work_id(value: &str) -> WorkId {
        WorkId::new(value).expect("valid work id")
    }

    fn effect_id(value: &str) -> EffectId {
        EffectId::new(value).expect("valid effect id")
    }

    fn event(sequence: u64, event: ReplayEventKind) -> ReplayEvent {
        ReplayEvent::new(sequence, event)
    }

    fn direct_archive(runs: Vec<RunLineage>) -> ExecutionReplayArchive {
        ExecutionReplayArchive {
            version: EXECUTION_REPLAY_VERSION,
            runs,
        }
    }

    #[test]
    fn serde_is_strict_versioned_bounded_and_deterministic() {
        let archive = ExecutionReplayArchive::new(Vec::new()).expect("empty archive");
        let first = archive.to_json_bytes().expect("encode archive");
        let second = archive.to_json_bytes().expect("encode archive again");
        assert_eq!(first, second);
        assert_eq!(
            ExecutionReplayArchive::from_json_bytes(&first).expect("decode archive"),
            archive
        );

        let unknown = br#"{"version":1,"runs":[],"unknown":true}"#;
        assert_eq!(
            ExecutionReplayArchive::from_json_bytes(unknown)
                .expect_err("unknown field must fail")
                .code(),
            "replay_parse_error"
        );
        let wrong_version = br#"{"version":2,"runs":[]}"#;
        assert!(matches!(
            ExecutionReplayArchive::from_json_bytes(wrong_version),
            Err(ReplayError::UnsupportedVersion {
                entity: "archive",
                expected: 1,
                actual: 2
            })
        ));
        assert!(matches!(
            RunId::new("x".repeat(MAX_ID_BYTES + 1)),
            Err(ReplayError::BoundExceeded {
                field: "run_id",
                ..
            })
        ));
        assert!(matches!(
            StateKey::new("not allowed"),
            Err(ReplayError::InvalidIdentifier { field: "state_key" })
        ));
        assert!(matches!(
            ExecutionReplayArchive::from_json_bytes(&vec![b' '; MAX_ARCHIVE_JSON_BYTES + 1]),
            Err(ReplayError::BoundExceeded {
                field: "archive_json_bytes",
                ..
            })
        ));
    }

    #[test]
    fn supplied_event_order_is_never_sorted_into_validity() {
        let duplicate = RunLineage {
            version: 1,
            run_id: run_id("duplicate"),
            parent: None,
            base_snapshot: ReplaySnapshot::empty(),
            events: vec![
                event(
                    1,
                    ReplayEventKind::StateSet {
                        key: StateKey::new("a").expect("key"),
                        value: json!(1),
                    },
                ),
                event(
                    1,
                    ReplayEventKind::StateSet {
                        key: StateKey::new("b").expect("key"),
                        value: json!(2),
                    },
                ),
            ],
        };
        assert!(matches!(
            direct_archive(vec![duplicate]).validate(),
            Err(ReplayError::DuplicateSequence { sequence: 1, .. })
        ));

        let out_of_order = RunLineage {
            version: 1,
            run_id: run_id("out-of-order"),
            parent: None,
            base_snapshot: ReplaySnapshot::empty(),
            events: vec![
                event(
                    2,
                    ReplayEventKind::StateSet {
                        key: StateKey::new("a").expect("key"),
                        value: json!(1),
                    },
                ),
                event(
                    1,
                    ReplayEventKind::StateSet {
                        key: StateKey::new("b").expect("key"),
                        value: json!(2),
                    },
                ),
            ],
        };
        assert!(matches!(
            direct_archive(vec![out_of_order]).validate(),
            Err(ReplayError::OutOfOrderSequence {
                expected: 1,
                actual: 2,
                ..
            })
        ));

        let gap = RunLineage {
            version: 1,
            run_id: run_id("gap"),
            parent: None,
            base_snapshot: ReplaySnapshot::empty(),
            events: vec![event(
                2,
                ReplayEventKind::StateSet {
                    key: StateKey::new("a").expect("key"),
                    value: json!(1),
                },
            )],
        };
        assert!(matches!(
            direct_archive(vec![gap]).validate(),
            Err(ReplayError::SequenceGap {
                expected: 1,
                actual: 2,
                ..
            })
        ));
    }

    #[test]
    fn lineage_validation_refuses_duplicates_missing_links_mismatch_and_cycles() {
        let root = RunLineage::root(run_id("root"), ReplaySnapshot::empty());
        assert!(matches!(
            direct_archive(vec![root.clone(), root.clone()]).validate(),
            Err(ReplayError::DuplicateRun { .. })
        ));

        let missing_parent = RunLineage::child(
            run_id("child"),
            LineagePoint::new(run_id("missing"), 0),
            ReplaySnapshot::empty(),
        );
        assert!(matches!(
            ExecutionReplayArchive::new(vec![missing_parent]),
            Err(ReplayError::MissingParent { .. })
        ));

        let missing_point = RunLineage::child(
            run_id("child"),
            LineagePoint::new(run_id("root"), 1),
            ReplaySnapshot::empty(),
        );
        assert!(matches!(
            ExecutionReplayArchive::new(vec![root.clone(), missing_point]),
            Err(ReplayError::MissingPoint { .. })
        ));

        let mut wrong_base = ReplaySnapshot::empty();
        wrong_base
            .state
            .insert(StateKey::new("wrong").expect("key"), json!(true));
        let mismatched_child = RunLineage::child(
            run_id("child"),
            LineagePoint::new(run_id("root"), 0),
            wrong_base,
        );
        assert!(matches!(
            ExecutionReplayArchive::new(vec![root, mismatched_child]),
            Err(ReplayError::InconsistentLineage {
                detail: LineageInconsistency::BaseSnapshotMismatch,
                ..
            })
        ));

        let cycle_a = RunLineage::child(
            run_id("a"),
            LineagePoint::new(run_id("b"), 0),
            ReplaySnapshot::empty(),
        );
        let cycle_b = RunLineage::child(
            run_id("b"),
            LineagePoint::new(run_id("a"), 0),
            ReplaySnapshot::empty(),
        );
        assert!(matches!(
            ExecutionReplayArchive::new(vec![cycle_a, cycle_b]),
            Err(ReplayError::LineageCycle { .. })
        ));
    }

    fn completed_run() -> RunLineage {
        let descriptor = EffectDescriptor::new(
            effect_id("git-commit"),
            EffectAction::new("git.commit").expect("action"),
            EffectCategory::GitMutation,
        );
        RunLineage {
            version: EXECUTION_REPLAY_VERSION,
            run_id: run_id("root"),
            parent: None,
            base_snapshot: ReplaySnapshot::empty(),
            events: vec![
                event(
                    1,
                    ReplayEventKind::StateSet {
                        key: StateKey::new("phase").expect("key"),
                        value: json!("planned"),
                    },
                ),
                event(
                    2,
                    ReplayEventKind::ObservationRecorded {
                        observation_id: ObservationId::new("repo-head").expect("observation id"),
                        value: json!({"oid": "abc"}),
                    },
                ),
                event(
                    3,
                    ReplayEventKind::WorkPlanned {
                        work_id: work_id("compile"),
                    },
                ),
                event(
                    4,
                    ReplayEventKind::WorkStarted {
                        work_id: work_id("compile"),
                    },
                ),
                event(
                    5,
                    ReplayEventKind::WorkCompleted {
                        work_id: work_id("compile"),
                        outcome: json!({"status": 0}),
                    },
                ),
                event(
                    6,
                    ReplayEventKind::ExternalEffectPlanned { effect: descriptor },
                ),
                event(
                    7,
                    ReplayEventKind::ExternalEffectStarted {
                        effect_id: effect_id("git-commit"),
                    },
                ),
                event(
                    8,
                    ReplayEventKind::ExternalEffectObserved {
                        effect_id: effect_id("git-commit"),
                        observation: json!({"head": "def"}),
                    },
                ),
                event(
                    9,
                    ReplayEventKind::ExternalEffectCompleted {
                        effect_id: effect_id("git-commit"),
                        outcome: json!({"commit": "def"}),
                    },
                ),
            ],
        }
    }

    #[test]
    fn inspection_and_replay_are_deterministic_and_observation_only() {
        let archive = ExecutionReplayArchive::new(vec![completed_run()]).expect("archive");
        let point = LineagePoint::new(run_id("root"), 9);
        let first = archive.replay_at(&point).expect("replay");
        let second = archive.replay_at(&point).expect("repeat replay");
        assert_eq!(first, second);
        assert_eq!(first.contract.mode, ReplayMode::ObservationOnly);
        assert!(first.contract.effects_disarmed);
        assert_eq!(
            first.contract.replayed,
            BTreeSet::from([
                ReplayedMaterial::RecordedState,
                ReplayedMaterial::RecordedObservations,
                ReplayedMaterial::RecordedWorkOutcomes,
                ReplayedMaterial::RecordedExternalEffectEvidence,
            ])
        );
        assert_eq!(
            first.contract.not_reexecuted,
            BTreeSet::from([
                NotReexecutedMaterial::Work,
                NotReexecutedMaterial::ExternalEffects,
            ])
        );
        assert_eq!(
            first
                .inspection
                .snapshot
                .state
                .get(&StateKey::new("phase").expect("key")),
            Some(&json!("planned"))
        );
        assert_eq!(first.inspection.snapshot.work_outcomes.len(), 1);
        assert_eq!(first.inspection.snapshot.effect_evidence.len(), 1);

        let encoded = archive.to_json_bytes().expect("encode");
        let decoded = ExecutionReplayArchive::from_json_bytes(&encoded).expect("decode");
        assert_eq!(decoded.replay_at(&point).expect("decoded replay"), first);
    }

    #[test]
    fn historical_pending_uncertain_and_ambiguous_points_are_refused() {
        let archive = ExecutionReplayArchive::new(vec![completed_run()]).expect("archive");
        let pending_work = LineagePoint::new(run_id("root"), 3);
        assert!(matches!(
            archive.inspect_at(&pending_work),
            Err(ReplayError::PendingExecution { .. })
        ));
        assert!(matches!(
            archive.replay_at(&pending_work),
            Err(ReplayError::PendingExecution { .. })
        ));

        let uncertain_work = LineagePoint::new(run_id("root"), 4);
        assert!(matches!(
            archive.inspect_at(&uncertain_work),
            Err(ReplayError::UncertainExecution { .. })
        ));
        assert!(matches!(
            archive.replay_at(&uncertain_work),
            Err(ReplayError::UncertainExecution { .. })
        ));

        let pending_effect = LineagePoint::new(run_id("root"), 6);
        assert!(matches!(
            archive.inspect_at(&pending_effect),
            Err(ReplayError::PendingExecution { .. })
        ));
        let uncertain_effect = LineagePoint::new(run_id("root"), 7);
        assert!(matches!(
            archive.inspect_at(&uncertain_effect),
            Err(ReplayError::UncertainExecution { .. })
        ));
        let ambiguous_effect = LineagePoint::new(run_id("root"), 8);
        assert!(matches!(
            archive.inspect_at(&ambiguous_effect),
            Err(ReplayError::AmbiguousExternalEffect { .. })
        ));
        assert!(matches!(
            archive.replay_at(&ambiguous_effect),
            Err(ReplayError::AmbiguousExternalEffect { .. })
        ));
    }

    #[test]
    fn lifecycle_requires_unique_exact_transitions() {
        let invalid_work = RunLineage {
            version: 1,
            run_id: run_id("work"),
            parent: None,
            base_snapshot: ReplaySnapshot::empty(),
            events: vec![event(
                1,
                ReplayEventKind::WorkCompleted {
                    work_id: work_id("compile"),
                    outcome: json!(0),
                },
            )],
        };
        assert!(matches!(
            ExecutionReplayArchive::new(vec![invalid_work]),
            Err(ReplayError::InvalidTransition {
                transition: TransitionViolation::WorkOutcomeWithoutUniqueStart,
                ..
            })
        ));

        let invalid_effect = RunLineage {
            version: 1,
            run_id: run_id("effect"),
            parent: None,
            base_snapshot: ReplaySnapshot::empty(),
            events: vec![event(
                1,
                ReplayEventKind::ExternalEffectObserved {
                    effect_id: effect_id("provider"),
                    observation: json!("maybe"),
                },
            )],
        };
        assert!(matches!(
            ExecutionReplayArchive::new(vec![invalid_effect]),
            Err(ReplayError::InvalidTransition {
                transition: TransitionViolation::EffectObservationWithoutStart,
                ..
            })
        ));
    }

    #[test]
    fn fork_is_pure_and_inherits_the_exact_inspected_snapshot() {
        let mut root = RunLineage::root(run_id("root"), ReplaySnapshot::empty());
        root.events = vec![
            event(
                1,
                ReplayEventKind::StateSet {
                    key: StateKey::new("phase").expect("key"),
                    value: json!("one"),
                },
            ),
            event(
                2,
                ReplayEventKind::ObservationRecorded {
                    observation_id: ObservationId::new("head").expect("observation id"),
                    value: json!("abc"),
                },
            ),
            event(
                3,
                ReplayEventKind::StateSet {
                    key: StateKey::new("phase").expect("key"),
                    value: json!("three"),
                },
            ),
        ];
        let source = ExecutionReplayArchive::new(vec![root]).expect("source archive");
        let source_clone = source.clone();
        let source_bytes = source.to_json_bytes().expect("source bytes");
        let branch_point = LineagePoint::new(run_id("root"), 2);
        let inherited = source
            .inspect_at(&branch_point)
            .expect("branch inspection")
            .snapshot;

        let forked = source
            .fork(&branch_point, run_id("child"))
            .expect("fork archive");
        assert_eq!(source, source_clone);
        assert_eq!(
            source.to_json_bytes().expect("source bytes after fork"),
            source_bytes
        );
        let child = forked
            .runs
            .iter()
            .find(|run| run.run_id == run_id("child"))
            .expect("child run");
        assert_eq!(
            child.parent,
            Some(ParentLineage {
                branch_point: branch_point.clone()
            })
        );
        assert_eq!(child.base_snapshot, inherited);
        assert!(child.events.is_empty());
        assert_eq!(
            forked
                .inspect_at(&LineagePoint::new(run_id("child"), 0))
                .expect("child base")
                .snapshot,
            inherited
        );
    }

    fn request_at(
        run: &str,
        sequence: u64,
        effect: &str,
        action: &str,
        category: EffectCategory,
    ) -> EffectRequest {
        EffectRequest::new(
            LineagePoint::new(run_id(run), sequence),
            EffectDescriptor::new(
                effect_id(effect),
                EffectAction::new(action).expect("action"),
                category,
            ),
        )
    }

    #[test]
    fn every_external_category_is_disarmed_by_default() {
        let categories = [
            EffectCategory::GitMutation,
            EffectCategory::WorktreeCreation,
            EffectCategory::ProviderCall,
            EffectCategory::ForgeCall,
            EffectCategory::ExternalProcess,
            EffectCategory::FilesystemMutation,
            EffectCategory::OtherNamedExternalEffect,
        ];
        let mut guard = EffectGuard::new();
        for (index, category) in categories.into_iter().enumerate() {
            let request = request_at(
                "root",
                u64::try_from(index + 1).expect("small sequence"),
                &format!("effect-{index}"),
                &format!("action.{index}"),
                category,
            );
            assert!(matches!(
                guard.authorize(&request, None),
                Err(ReplayError::EffectDisarmed { .. })
            ));
        }
    }

    #[test]
    fn rearm_is_exact_one_shot_and_isolated_across_forks() {
        let source = request_at(
            "root",
            4,
            "commit",
            "git.commit",
            EffectCategory::GitMutation,
        );
        let child = request_at(
            "child",
            0,
            "commit",
            "git.commit",
            EffectCategory::GitMutation,
        );
        let mut guard = EffectGuard::new();

        let fork_capability_id = CapabilityId::new("cap-fork").expect("capability id");
        let source_capability =
            EffectRearmCapability::new(fork_capability_id.clone(), source.clone())
                .expect("capability");
        assert!(matches!(
            guard.authorize(&child, Some(source_capability)),
            Err(ReplayError::RearmMismatch { .. })
        ));
        assert!(guard.has_consumed(&fork_capability_id));
        let replacement = EffectRearmCapability::new(fork_capability_id.clone(), child.clone())
            .expect("replacement capability");
        assert!(matches!(
            guard.authorize(&child, Some(replacement)),
            Err(ReplayError::RearmReused { capability_id }) if capability_id == fork_capability_id
        ));

        let exact_id = CapabilityId::new("cap-exact").expect("capability id");
        let exact =
            EffectRearmCapability::new(exact_id.clone(), source.clone()).expect("exact capability");
        let permit = guard
            .authorize(&source, Some(exact))
            .expect("exact authorization");
        assert_eq!(permit.capability_id(), &exact_id);
        assert_eq!(permit.request(), &source);
        let reused =
            EffectRearmCapability::new(exact_id.clone(), source.clone()).expect("reused token");
        assert!(matches!(
            guard.authorize(&source, Some(reused)),
            Err(ReplayError::RearmReused { capability_id }) if capability_id == exact_id
        ));

        let action_mismatch = request_at(
            "root",
            4,
            "commit",
            "git.reset",
            EffectCategory::GitMutation,
        );
        let action_cap = EffectRearmCapability::new(
            CapabilityId::new("cap-action").expect("capability id"),
            source.clone(),
        )
        .expect("capability");
        assert!(matches!(
            guard.authorize(&action_mismatch, Some(action_cap)),
            Err(ReplayError::RearmMismatch { .. })
        ));

        let category_mismatch =
            request_at("root", 4, "commit", "git.commit", EffectCategory::ForgeCall);
        let category_cap = EffectRearmCapability::new(
            CapabilityId::new("cap-category").expect("capability id"),
            source.clone(),
        )
        .expect("capability");
        assert!(matches!(
            guard.authorize(&category_mismatch, Some(category_cap)),
            Err(ReplayError::RearmMismatch { .. })
        ));

        let effect_mismatch = request_at(
            "root",
            4,
            "other-effect",
            "git.commit",
            EffectCategory::GitMutation,
        );
        let effect_cap = EffectRearmCapability::new(
            CapabilityId::new("cap-effect").expect("capability id"),
            source,
        )
        .expect("capability");
        assert!(matches!(
            guard.authorize(&effect_mismatch, Some(effect_cap)),
            Err(ReplayError::RearmMismatch { .. })
        ));
    }

    #[test]
    fn authenticated_checkpoint_evidence_requires_exact_record_binding() {
        let point = LineagePoint::new(run_id("root"), 1);
        assert!(matches!(
            AuthenticatedCheckpointEvidence::from_authenticated_record(
                point.clone(),
                JournalId::new("journal").expect("journal id"),
                2,
                "tag"
            ),
            Err(ReplayError::InconsistentLineage {
                detail: LineageInconsistency::CheckpointPointBinding,
                ..
            })
        ));
        let evidence = AuthenticatedCheckpointEvidence::from_authenticated_record(
            point.clone(),
            JournalId::new("journal").expect("journal id"),
            1,
            "authenticated-tag",
        )
        .expect("bound evidence");
        let mut root = RunLineage::root(run_id("root"), ReplaySnapshot::empty());
        root.events.push(event(
            1,
            ReplayEventKind::CheckpointEvidenceRecorded {
                evidence: evidence.clone(),
            },
        ));
        let archive = ExecutionReplayArchive::new(vec![root]).expect("archive");
        assert_eq!(
            archive
                .inspect_at(&point)
                .expect("inspection")
                .snapshot
                .checkpoint_evidence,
            Some(evidence)
        );
    }

    #[test]
    fn an_exact_started_then_failed_external_lifecycle_is_terminal() {
        let descriptor = EffectDescriptor::new(
            effect_id("provider"),
            EffectAction::new("provider.invoke").expect("action"),
            EffectCategory::ProviderCall,
        );
        let mut root = RunLineage::root(run_id("root"), ReplaySnapshot::empty());
        root.events = vec![
            event(
                1,
                ReplayEventKind::ExternalEffectPlanned { effect: descriptor },
            ),
            event(
                2,
                ReplayEventKind::ExternalEffectStarted {
                    effect_id: effect_id("provider"),
                },
            ),
            event(
                3,
                ReplayEventKind::ExternalEffectFailed {
                    effect_id: effect_id("provider"),
                    error: "recorded failure".to_string(),
                },
            ),
        ];
        let archive = ExecutionReplayArchive::new(vec![root]).expect("archive");
        let snapshot = archive
            .inspect_at(&LineagePoint::new(run_id("root"), 3))
            .expect("terminal failed inspection")
            .snapshot;
        assert!(matches!(
            snapshot.effect_evidence.get(&effect_id("provider")),
            Some(RecordedEffectEvidence {
                observation: None,
                outcome: ExternalEffectOutcome::Failed { .. },
                ..
            })
        ));
    }

    fn forge_receipt_run() -> RunLineage {
        let descriptor = EffectDescriptor::new(
            effect_id("publish-pr"),
            EffectAction::new("publication-push").expect("action"),
            EffectCategory::ForgeCall,
        );
        RunLineage {
            version: EXECUTION_REPLAY_VERSION,
            run_id: run_id("root"),
            parent: None,
            base_snapshot: ReplaySnapshot::empty(),
            events: vec![
                event(
                    1,
                    ReplayEventKind::ExternalEffectPlanned { effect: descriptor },
                ),
                event(
                    2,
                    ReplayEventKind::ExternalEffectStarted {
                        effect_id: effect_id("publish-pr"),
                    },
                ),
                event(
                    3,
                    ReplayEventKind::ExternalEffectObserved {
                        effect_id: effect_id("publish-pr"),
                        observation: json!({"remote_ref": "refs/heads/topic"}),
                    },
                ),
                event(
                    4,
                    ReplayEventKind::ExternalEffectCompleted {
                        effect_id: effect_id("publish-pr"),
                        outcome: json!({
                            "publication_receipt": {
                                "version": 1,
                                "transaction_id": "tx-recorded-1",
                                "sequence": 1
                            }
                        }),
                    },
                ),
            ],
        }
    }

    #[test]
    fn fork_inherits_recorded_publication_receipts_and_does_not_repeat_forge_effects() {
        let source = ExecutionReplayArchive::new(vec![forge_receipt_run()]).expect("source");
        let before = source.to_json_bytes().expect("source bytes");
        let branch_point = LineagePoint::new(run_id("root"), 4);
        let parent_snapshot = source
            .inspect_at(&branch_point)
            .expect("inspect parent")
            .snapshot;
        assert_eq!(
            parent_snapshot
                .effect_evidence
                .get(&effect_id("publish-pr"))
                .and_then(RecordedEffectEvidence::recorded_receipt_transaction_id),
            Some("tx-recorded-1")
        );

        let forked = source
            .fork(&branch_point, run_id("child"))
            .expect("fork child");
        assert_eq!(source.to_json_bytes().expect("source after fork"), before);
        let child_snapshot = forked
            .inspect_at(&LineagePoint::new(run_id("child"), 0))
            .expect("inspect child")
            .snapshot;
        assert_eq!(
            child_snapshot.effect_evidence,
            parent_snapshot.effect_evidence
        );
        assert_eq!(
            forked
                .children_of(&run_id("root"))
                .expect("children")
                .iter()
                .map(|run| run.run_id.as_str())
                .collect::<Vec<_>>(),
            vec!["child"]
        );

        let replay = forked
            .replay_at(&LineagePoint::new(run_id("child"), 0))
            .expect("child replay");
        assert!(replay.contract.effects_disarmed);
        let mut guard = EffectGuard::new();
        let request = request_at(
            "child",
            0,
            "publish-pr",
            "publication-push",
            EffectCategory::ForgeCall,
        );
        assert_eq!(
            request.taxonomy_reversibility(),
            crate::mutation_taxonomy::MutationReversibility::Irreversible
        );
        assert!(matches!(
            guard.authorize(&request, None),
            Err(ReplayError::EffectDisarmed { .. })
        ));
    }

    #[test]
    fn inspect_does_not_mutate_the_archive() {
        let archive = ExecutionReplayArchive::new(vec![completed_run()]).expect("archive");
        let before = archive.to_json_bytes().expect("before");
        let _ = archive
            .inspect_at(&LineagePoint::new(run_id("root"), 9))
            .expect("inspect");
        let _ = archive
            .replay_at(&LineagePoint::new(run_id("root"), 5))
            .expect("replay completed work");
        assert_eq!(archive.to_json_bytes().expect("after"), before);
    }
}
