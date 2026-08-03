//! Authenticated, bounded queue state for licensed-breakage follow-up runs.
//!
//! Enqueue is a two-step durable transaction: immutable item records are staged
//! individually, then one commit record makes the complete batch dispatchable.
//! A crash during staging therefore exposes no partial pending batch. Dispatch
//! is also fail-closed: once its durable start marker exists, replay treats the
//! effect as ambiguous and never returns the item to pending automatically.

#![allow(dead_code)]

use crate::{
    artifacts::state_auth::{sha256_hex, AuthenticationDomain, RepositoryAuthenticator},
    external_agent::EnvironmentFailure,
    gate_denial::{ExternalSideEffectState, GateDenial},
    state_journal::{AuthenticatedStateJournal, JournalRecord, JournalSpec},
    supervise::{
        load_supervisor_plan_file, GeneratedFollowUpDispatchStatus, GeneratedFollowUpTaskRecord,
        SupervisorPlan,
    },
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io::Write};

pub(crate) const GENERATED_FOLLOW_UP_QUEUE_ROOT_NAME: &str =
    "authenticated-generated-follow-up-queues-v1";

const QUEUE_FORMAT_VERSION: u32 = 1;
const GENERATED_CASCADE_DEPTH: u8 = 1;
const SOURCE_CASCADE_DEPTH: u8 = 0;
const MAX_QUEUE_ITEMS: usize = 64;
const MAX_SOURCE_GROUPS: usize = 64;
const MAX_SOURCE_RUN_ID_BYTES: usize = 128;
const MAX_CANONICAL_TASK_BYTES: usize = 7 * 1024 * 1024;
const MAX_ENQUEUED_TASK_BYTES: usize = 64 * 1024 * 1024;
const ITEM_ID_DOMAIN: &[u8] = b"MACO\0generated-follow-up-queue-item\0v1\0";
const QUEUE_ID_DOMAIN: &[u8] = b"MACO\0generated-follow-up-queue-instance\0v1\0";
const BATCH_ID_DOMAIN: &[u8] = b"MACO\0generated-follow-up-queue-batch\0v1\0";

enum GeneratedFollowUpQueueJournalSpec {}

impl JournalSpec for GeneratedFollowUpQueueJournalSpec {
    const FORMAT_VERSION: u32 = QUEUE_FORMAT_VERSION;
    const NAMESPACE: &'static str = "generated_follow_up_queue";
    const ROOT_NAME: &'static str = GENERATED_FOLLOW_UP_QUEUE_ROOT_NAME;
    const ROOT_LOCK_NAME: &'static str = ".generated-follow-up-queues.lock";
    const INSTANCE_LOCK_NAME: &'static str = ".generated-follow-up-queue.lock";
    const HEAD_FILE_NAME: &'static str = ".head.json";
    const RECORD_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0generated-follow-up-queue-record\0v1\0");
    const HEAD_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0generated-follow-up-queue-head\0v1\0");
    const MAX_RECORDS: usize = 512;
    const MAX_RECORD_BYTES: u64 = 8 * 1024 * 1024;
    const MAX_TOTAL_BYTES: u64 = 128 * 1024 * 1024;
    const MAX_PHASE_BYTES: usize = 32;
    const MAX_SUBJECT_BYTES: usize = 128;
    const MAX_INSTANCE_ID_BYTES: usize = 96;
}

type QueueJournal = AuthenticatedStateJournal<GeneratedFollowUpQueueJournalSpec>;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GeneratedFollowUpQueueSource {
    source_supervisor_run_id: String,
    cascade_depth: u8,
}

impl GeneratedFollowUpQueueSource {
    pub(crate) fn root(source_supervisor_run_id: impl Into<String>) -> Result<Self> {
        let source = Self {
            source_supervisor_run_id: source_supervisor_run_id.into(),
            cascade_depth: SOURCE_CASCADE_DEPTH,
        };
        source.validate()?;
        Ok(source)
    }

    pub(crate) fn generated(
        source_supervisor_run_id: impl Into<String>,
        cascade_depth: u8,
    ) -> Result<Self> {
        let source = Self {
            source_supervisor_run_id: source_supervisor_run_id.into(),
            cascade_depth,
        };
        source.validate()?;
        Ok(source)
    }

    pub(crate) fn source_supervisor_run_id(&self) -> &str {
        &self.source_supervisor_run_id
    }

    pub(crate) fn cascade_depth(&self) -> u8 {
        self.cascade_depth
    }

    fn validate(&self) -> Result<()> {
        validate_source_run_id(&self.source_supervisor_run_id)?;
        if self.cascade_depth != SOURCE_CASCADE_DEPTH {
            bail!(
                "generated follow-up queue refuses second-generation work at cascade depth {}",
                self.cascade_depth
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GeneratedFollowUpQueueBounds {
    declared_dependents: usize,
    validated_dependents: usize,
    capacity: usize,
}

impl GeneratedFollowUpQueueBounds {
    /// Computes one round's exact item capacity from per-source-assignment
    /// declared and validated dependent counts. Both totals use checked
    /// arithmetic; validated failures may be a subset of declarations.
    pub(crate) fn from_source_dependents(
        declared_per_assignment: &[usize],
        validated_per_assignment: &[usize],
    ) -> Result<Self> {
        if declared_per_assignment.is_empty()
            || declared_per_assignment.len() != validated_per_assignment.len()
            || declared_per_assignment.len() > MAX_SOURCE_GROUPS
        {
            bail!(
                "generated follow-up queue source counts must contain 1..={MAX_SOURCE_GROUPS} aligned assignment groups"
            );
        }
        let mut declared_dependents = 0_usize;
        let mut validated_dependents = 0_usize;
        for (declared, validated) in declared_per_assignment
            .iter()
            .copied()
            .zip(validated_per_assignment.iter().copied())
        {
            declared_dependents = declared_dependents
                .checked_add(declared)
                .context("generated follow-up declared-dependent count overflowed")?;
            validated_dependents = validated_dependents
                .checked_add(validated)
                .context("generated follow-up validated-dependent count overflowed")?;
            if validated > declared {
                bail!("generated follow-up validated dependents exceed the source declaration");
            }
        }
        if validated_dependents == 0 || validated_dependents > MAX_QUEUE_ITEMS {
            bail!("generated follow-up queue capacity must be between 1 and {MAX_QUEUE_ITEMS}");
        }
        let bounds = Self {
            declared_dependents,
            validated_dependents,
            capacity: validated_dependents,
        };
        bounds.validate()?;
        Ok(bounds)
    }

    pub(crate) fn declared_dependents(&self) -> usize {
        self.declared_dependents
    }

    pub(crate) fn validated_dependents(&self) -> usize {
        self.validated_dependents
    }

    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    fn validate(&self) -> Result<()> {
        if self.declared_dependents < self.validated_dependents
            || self.validated_dependents == 0
            || self.validated_dependents > MAX_QUEUE_ITEMS
            || self.capacity != self.validated_dependents
        {
            bail!("generated follow-up queue bounds are malformed or unsupported");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GeneratedFollowUpQueuePhase {
    Enqueued,
    Claimed,
    DispatchStarted,
    DispatchObserved,
    AcknowledgedTerminal,
    HeldAmbiguous,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GeneratedFollowUpDispatchObservation {
    observed_subordinate_run_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gate_denial: Option<GateDenial>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    environment_failures: Vec<EnvironmentFailure>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    external_side_effect_state: Option<ExternalSideEffectState>,
}

impl GeneratedFollowUpDispatchObservation {
    pub(crate) fn new(
        observed_subordinate_run_id: impl Into<String>,
        gate_denial: Option<GateDenial>,
        environment_failures: Vec<EnvironmentFailure>,
        external_side_effect_state: Option<ExternalSideEffectState>,
    ) -> Result<Self> {
        let observation = Self {
            observed_subordinate_run_id: observed_subordinate_run_id.into(),
            gate_denial,
            environment_failures,
            external_side_effect_state,
        };
        observation.validate(None)?;
        Ok(observation)
    }

    pub(crate) fn observed_subordinate_run_id(&self) -> &str {
        &self.observed_subordinate_run_id
    }

    pub(crate) fn gate_denial(&self) -> Option<&GateDenial> {
        self.gate_denial.as_ref()
    }

    pub(crate) fn environment_failures(&self) -> &[EnvironmentFailure] {
        &self.environment_failures
    }

    pub(crate) fn external_side_effect_state(&self) -> Option<ExternalSideEffectState> {
        self.external_side_effect_state
    }

    fn validate(&self, expected_run_id: Option<&str>) -> Result<()> {
        validate_source_run_id(&self.observed_subordinate_run_id)
            .context("observed subordinate run identity is invalid")?;
        if expected_run_id.is_some_and(|expected| expected != self.observed_subordinate_run_id) {
            bail!("dispatch observation names a different subordinate run");
        }
        if self.external_side_effect_state == Some(ExternalSideEffectState::Ambiguous) {
            bail!("ambiguous dispatch evidence must use the held_ambiguous queue transition");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ImmutableEnqueueRecord {
    item_id: String,
    task: GeneratedFollowUpTaskRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
enum QueueJournalEvent {
    Created {
        source: GeneratedFollowUpQueueSource,
        bounds: GeneratedFollowUpQueueBounds,
    },
    EnqueueStaged {
        item: ImmutableEnqueueRecord,
    },
    Enqueued {
        item_ids: Vec<String>,
        batch_sha256: String,
    },
    Claimed {
        item_id: String,
    },
    ReleasedBeforeDispatch {
        item_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        gate_denial: Option<GateDenial>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        environment_failures: Vec<EnvironmentFailure>,
    },
    DispatchStarted {
        item_id: String,
        subordinate_run_id: String,
    },
    DispatchObserved {
        item_id: String,
        subordinate_run_id: String,
        observation: GeneratedFollowUpDispatchObservation,
    },
    AcknowledgedTerminal {
        item_id: String,
        subordinate_run_id: String,
    },
    HeldAmbiguous {
        item_id: String,
        subordinate_run_id: String,
        external_side_effect_state: ExternalSideEffectState,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        gate_denial: Option<GateDenial>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        environment_failures: Vec<EnvironmentFailure>,
    },
}

impl QueueJournalEvent {
    fn phase(&self) -> &'static str {
        match self {
            Self::Created { .. } => "created",
            Self::EnqueueStaged { .. } => "enqueue_staged",
            Self::Enqueued { .. } => "enqueued",
            Self::Claimed { .. } => "claimed",
            Self::ReleasedBeforeDispatch { .. } => "released_before_dispatch",
            Self::DispatchStarted { .. } => "dispatch_started",
            Self::DispatchObserved { .. } => "dispatch_observed",
            Self::AcknowledgedTerminal { .. } => "acknowledged_terminal",
            Self::HeldAmbiguous { .. } => "held_ambiguous",
        }
    }

    fn subject(&self) -> Option<&str> {
        match self {
            Self::Created { .. } | Self::Enqueued { .. } => None,
            Self::EnqueueStaged { item } => Some(&item.item_id),
            Self::Claimed { item_id }
            | Self::ReleasedBeforeDispatch { item_id, .. }
            | Self::DispatchStarted { item_id, .. }
            | Self::DispatchObserved { item_id, .. }
            | Self::AcknowledgedTerminal { item_id, .. }
            | Self::HeldAmbiguous { item_id, .. } => Some(item_id),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct GeneratedFollowUpQueueEventData {
    pub version: u32,
    pub queue_instance_id: String,
    pub source_supervisor_run_id: String,
    pub phase: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub item_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subordinate_run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate_denial: Option<GateDenial>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub environment_failures: Vec<EnvironmentFailure>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_side_effect_state: Option<ExternalSideEffectState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GeneratedFollowUpQueueItemSnapshot {
    enqueue: ImmutableEnqueueRecord,
    phase: GeneratedFollowUpQueuePhase,
    subordinate_run_id: Option<String>,
    observation: Option<GeneratedFollowUpDispatchObservation>,
    last_gate_denial: Option<GateDenial>,
    last_environment_failures: Vec<EnvironmentFailure>,
    external_side_effect_state: Option<ExternalSideEffectState>,
}

impl GeneratedFollowUpQueueItemSnapshot {
    pub(crate) fn item_id(&self) -> &str {
        &self.enqueue.item_id
    }

    pub(crate) fn task(&self) -> &GeneratedFollowUpTaskRecord {
        &self.enqueue.task
    }

    pub(crate) fn phase(&self) -> GeneratedFollowUpQueuePhase {
        self.phase
    }

    pub(crate) fn subordinate_run_id(&self) -> Option<&str> {
        self.subordinate_run_id.as_deref()
    }

    pub(crate) fn observation(&self) -> Option<&GeneratedFollowUpDispatchObservation> {
        self.observation.as_ref()
    }

    pub(crate) fn last_gate_denial(&self) -> Option<&GateDenial> {
        self.last_gate_denial.as_ref()
    }

    pub(crate) fn last_environment_failures(&self) -> &[EnvironmentFailure] {
        &self.last_environment_failures
    }

    pub(crate) fn external_side_effect_state(&self) -> Option<ExternalSideEffectState> {
        self.external_side_effect_state
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GeneratedFollowUpQueueSnapshot {
    queue_instance_id: String,
    source: GeneratedFollowUpQueueSource,
    bounds: GeneratedFollowUpQueueBounds,
    enqueue_committed: bool,
    staged: BTreeMap<String, ImmutableEnqueueRecord>,
    items: BTreeMap<String, GeneratedFollowUpQueueItemSnapshot>,
}

impl GeneratedFollowUpQueueSnapshot {
    pub(crate) fn queue_instance_id(&self) -> &str {
        &self.queue_instance_id
    }

    pub(crate) fn source(&self) -> &GeneratedFollowUpQueueSource {
        &self.source
    }

    pub(crate) fn bounds(&self) -> &GeneratedFollowUpQueueBounds {
        &self.bounds
    }

    pub(crate) fn enqueue_committed(&self) -> bool {
        self.enqueue_committed
    }

    pub(crate) fn staged_count(&self) -> usize {
        self.staged.len()
    }

    pub(crate) fn items(&self) -> &BTreeMap<String, GeneratedFollowUpQueueItemSnapshot> {
        &self.items
    }

    pub(crate) fn item(&self, item_id: &str) -> Option<&GeneratedFollowUpQueueItemSnapshot> {
        self.items.get(item_id)
    }

    pub(crate) fn pending_item_ids(&self) -> Vec<&str> {
        self.items
            .values()
            .filter(|item| item.phase == GeneratedFollowUpQueuePhase::Enqueued)
            .map(GeneratedFollowUpQueueItemSnapshot::item_id)
            .collect()
    }
}

pub(crate) struct GeneratedFollowUpQueue {
    journal: QueueJournal,
    snapshot: GeneratedFollowUpQueueSnapshot,
}

impl GeneratedFollowUpQueue {
    pub(crate) fn create(
        authenticator: RepositoryAuthenticator,
        source: GeneratedFollowUpQueueSource,
        bounds: GeneratedFollowUpQueueBounds,
    ) -> Result<Self> {
        source.validate()?;
        bounds.validate()?;
        let instance_id = queue_instance_id(&source)?;
        let mut journal = QueueJournal::create(authenticator, &instance_id)?;
        let created = QueueJournalEvent::Created {
            source: source.clone(),
            bounds: bounds.clone(),
        };
        journal.append(created.phase(), None, &created)?;
        let snapshot = replay_queue_records(&instance_id, journal.records())?;
        Ok(Self { journal, snapshot })
    }

    pub(crate) fn open(
        authenticator: RepositoryAuthenticator,
        source: &GeneratedFollowUpQueueSource,
    ) -> Result<Self> {
        source.validate()?;
        let instance_id = queue_instance_id(source)?;
        let journal = QueueJournal::open_instance(authenticator, &instance_id)?;
        let snapshot = replay_queue_records(&instance_id, journal.records())?;
        if &snapshot.source != source {
            bail!("generated follow-up queue source identity changed across reopen");
        }
        Ok(Self { journal, snapshot })
    }

    pub(crate) fn snapshot(&self) -> &GeneratedFollowUpQueueSnapshot {
        &self.snapshot
    }

    pub(crate) fn replay_snapshot(&self) -> Result<GeneratedFollowUpQueueSnapshot> {
        replay_queue_records(self.journal.instance_id(), self.journal.records())
    }

    /// Stages every immutable task before committing the complete batch. An
    /// interrupted call can be resumed with the exact same batch; staged
    /// records never become pending until the commit record is durable.
    pub(crate) fn enqueue_all_before_dispatch(
        &mut self,
        tasks: &[GeneratedFollowUpTaskRecord],
    ) -> Result<Vec<GeneratedFollowUpQueueEventData>> {
        let prepared = prepare_enqueue_records(&self.snapshot.source, tasks)?;
        if prepared.len() != self.snapshot.bounds.capacity {
            bail!(
                "generated follow-up enqueue count {} does not match the validated capacity {}",
                prepared.len(),
                self.snapshot.bounds.capacity
            );
        }
        let total_bytes = prepared.values().try_fold(0_usize, |total, item| {
            let bytes = serde_json::to_vec(item)
                .context("failed to size generated follow-up enqueue record")?;
            total
                .checked_add(bytes.len())
                .context("generated follow-up enqueue byte total overflowed")
        })?;
        if total_bytes > MAX_ENQUEUED_TASK_BYTES {
            bail!("generated follow-up enqueue batch exceeds its fixed byte bound");
        }

        if self.snapshot.enqueue_committed {
            if committed_items_match(&self.snapshot, &prepared) {
                return Ok(Vec::new());
            }
            bail!("generated follow-up queue already committed a different immutable batch");
        }
        for (item_id, staged) in &self.snapshot.staged {
            let Some(candidate) = prepared.get(item_id) else {
                bail!("resumed enqueue batch omits an already staged item id");
            };
            if candidate != staged {
                bail!("resumed enqueue batch conflicts with an immutable staged item id");
            }
        }

        let mut events = Vec::new();
        for (item_id, item) in &prepared {
            if self.snapshot.staged.contains_key(item_id) {
                continue;
            }
            events
                .push(self.append_event(QueueJournalEvent::EnqueueStaged { item: item.clone() })?);
        }
        let item_ids = prepared.keys().cloned().collect::<Vec<_>>();
        let batch_sha256 = batch_sha256(&item_ids)?;
        events.push(self.append_event(QueueJournalEvent::Enqueued {
            item_ids,
            batch_sha256,
        })?);
        Ok(events)
    }

    pub(crate) fn claim(&mut self, item_id: &str) -> Result<GeneratedFollowUpQueueEventData> {
        self.append_event(QueueJournalEvent::Claimed {
            item_id: item_id.to_string(),
        })
    }

    pub(crate) fn release_before_dispatch(
        &mut self,
        item_id: &str,
        gate_denial: Option<GateDenial>,
        environment_failures: Vec<EnvironmentFailure>,
    ) -> Result<GeneratedFollowUpQueueEventData> {
        self.append_event(QueueJournalEvent::ReleasedBeforeDispatch {
            item_id: item_id.to_string(),
            gate_denial,
            environment_failures,
        })
    }

    pub(crate) fn mark_dispatch_started(
        &mut self,
        item_id: &str,
    ) -> Result<GeneratedFollowUpQueueEventData> {
        let subordinate_run_id = subordinate_run_id(item_id)?;
        self.append_event(QueueJournalEvent::DispatchStarted {
            item_id: item_id.to_string(),
            subordinate_run_id,
        })
    }

    pub(crate) fn mark_dispatch_observed(
        &mut self,
        item_id: &str,
        observation: GeneratedFollowUpDispatchObservation,
    ) -> Result<GeneratedFollowUpQueueEventData> {
        let subordinate_run_id = self
            .snapshot
            .item(item_id)
            .and_then(GeneratedFollowUpQueueItemSnapshot::subordinate_run_id)
            .context("generated follow-up item has no durable dispatch start")?
            .to_string();
        observation.validate(Some(&subordinate_run_id))?;
        self.append_event(QueueJournalEvent::DispatchObserved {
            item_id: item_id.to_string(),
            subordinate_run_id,
            observation,
        })
    }

    pub(crate) fn acknowledge_terminal(
        &mut self,
        item_id: &str,
    ) -> Result<GeneratedFollowUpQueueEventData> {
        let subordinate_run_id = self
            .snapshot
            .item(item_id)
            .and_then(GeneratedFollowUpQueueItemSnapshot::subordinate_run_id)
            .context("generated follow-up item has no observed subordinate run")?
            .to_string();
        self.append_event(QueueJournalEvent::AcknowledgedTerminal {
            item_id: item_id.to_string(),
            subordinate_run_id,
        })
    }

    pub(crate) fn mark_held_ambiguous(
        &mut self,
        item_id: &str,
        gate_denial: Option<GateDenial>,
        environment_failures: Vec<EnvironmentFailure>,
    ) -> Result<GeneratedFollowUpQueueEventData> {
        let subordinate_run_id = self
            .snapshot
            .item(item_id)
            .and_then(GeneratedFollowUpQueueItemSnapshot::subordinate_run_id)
            .context("generated follow-up item has no durable dispatch start")?
            .to_string();
        self.append_event(QueueJournalEvent::HeldAmbiguous {
            item_id: item_id.to_string(),
            subordinate_run_id,
            external_side_effect_state: ExternalSideEffectState::Ambiguous,
            gate_denial,
            environment_failures,
        })
    }

    fn append_event(
        &mut self,
        event: QueueJournalEvent,
    ) -> Result<GeneratedFollowUpQueueEventData> {
        let next = apply_queue_event(self.snapshot.clone(), &event)?;
        let event_data = queue_event_data(&self.snapshot, &event);
        self.journal
            .append(event.phase(), event.subject(), &event)?;
        self.snapshot = next;
        Ok(event_data)
    }
}

fn replay_queue_records(
    instance_id: &str,
    records: &[JournalRecord],
) -> Result<GeneratedFollowUpQueueSnapshot> {
    let first = records
        .first()
        .context("generated follow-up queue has no authenticated creation record")?;
    let first_event: QueueJournalEvent = serde_json::from_value(first.payload.clone())
        .context("generated follow-up queue creation payload is malformed")?;
    if first.phase != first_event.phase() || first.subject.as_deref() != first_event.subject() {
        bail!("generated follow-up queue journal phase or subject is inconsistent");
    }
    let QueueJournalEvent::Created { source, bounds } = first_event else {
        bail!("generated follow-up queue must begin with its creation record");
    };
    source.validate()?;
    bounds.validate()?;
    if queue_instance_id(&source)? != instance_id {
        bail!("generated follow-up queue instance id is not bound to its source run");
    }
    let mut snapshot = GeneratedFollowUpQueueSnapshot {
        queue_instance_id: instance_id.to_string(),
        source,
        bounds,
        enqueue_committed: false,
        staged: BTreeMap::new(),
        items: BTreeMap::new(),
    };
    for record in records.iter().skip(1) {
        let event: QueueJournalEvent = serde_json::from_value(record.payload.clone())
            .context("generated follow-up queue journal payload is malformed")?;
        if record.phase != event.phase() || record.subject.as_deref() != event.subject() {
            bail!("generated follow-up queue journal phase or subject is inconsistent");
        }
        snapshot = apply_queue_event(snapshot, &event)?;
    }
    Ok(snapshot)
}

fn apply_queue_event(
    mut snapshot: GeneratedFollowUpQueueSnapshot,
    event: &QueueJournalEvent,
) -> Result<GeneratedFollowUpQueueSnapshot> {
    match event {
        QueueJournalEvent::Created { .. } => {
            bail!("generated follow-up queue creation record cannot repeat")
        }
        QueueJournalEvent::EnqueueStaged { item } => {
            if snapshot.enqueue_committed {
                bail!("generated follow-up queue cannot stage after enqueue commit");
            }
            let expected_id = generated_follow_up_item_id(&snapshot.source, &item.task)?;
            if item.item_id != expected_id {
                bail!("generated follow-up item id does not match its immutable task record");
            }
            if let Some(existing) = snapshot.staged.get(&item.item_id) {
                if existing == item {
                    bail!("generated follow-up enqueue transition repeated");
                }
                bail!("generated follow-up item id conflicts with another immutable record");
            }
            if snapshot.staged.len() >= snapshot.bounds.capacity {
                bail!("generated follow-up queue exceeds its validated item capacity");
            }
            snapshot.staged.insert(item.item_id.clone(), item.clone());
        }
        QueueJournalEvent::Enqueued {
            item_ids,
            batch_sha256: observed_batch_sha256,
        } => {
            if snapshot.enqueue_committed {
                bail!("generated follow-up enqueue commit repeated");
            }
            let expected_ids = snapshot.staged.keys().cloned().collect::<Vec<_>>();
            if item_ids != &expected_ids
                || item_ids.len() != snapshot.bounds.capacity
                || batch_sha256(item_ids)? != observed_batch_sha256.as_str()
            {
                bail!("generated follow-up enqueue commit is incomplete or content-mismatched");
            }
            for (item_id, enqueue) in std::mem::take(&mut snapshot.staged) {
                snapshot.items.insert(
                    item_id,
                    GeneratedFollowUpQueueItemSnapshot {
                        enqueue,
                        phase: GeneratedFollowUpQueuePhase::Enqueued,
                        subordinate_run_id: None,
                        observation: None,
                        last_gate_denial: None,
                        last_environment_failures: Vec::new(),
                        external_side_effect_state: None,
                    },
                );
            }
            snapshot.enqueue_committed = true;
        }
        QueueJournalEvent::Claimed { item_id } => {
            let item = queue_item_mut(&mut snapshot, item_id)?;
            require_phase(item, GeneratedFollowUpQueuePhase::Enqueued, "claim")?;
            item.phase = GeneratedFollowUpQueuePhase::Claimed;
            item.last_gate_denial = None;
            item.last_environment_failures.clear();
            item.external_side_effect_state = None;
        }
        QueueJournalEvent::ReleasedBeforeDispatch {
            item_id,
            gate_denial,
            environment_failures,
        } => {
            let item = queue_item_mut(&mut snapshot, item_id)?;
            require_phase(
                item,
                GeneratedFollowUpQueuePhase::Claimed,
                "release before dispatch",
            )?;
            if item.subordinate_run_id.is_some() {
                bail!("generated follow-up item with a dispatch marker cannot be released");
            }
            item.phase = GeneratedFollowUpQueuePhase::Enqueued;
            item.last_gate_denial = gate_denial.clone();
            item.last_environment_failures = environment_failures.clone();
            item.external_side_effect_state = None;
        }
        QueueJournalEvent::DispatchStarted {
            item_id,
            subordinate_run_id: observed_run_id,
        } => {
            let expected_run_id = subordinate_run_id(item_id)?;
            if observed_run_id != &expected_run_id {
                bail!("generated follow-up dispatch marker has a non-deterministic run id");
            }
            let item = queue_item_mut(&mut snapshot, item_id)?;
            require_phase(item, GeneratedFollowUpQueuePhase::Claimed, "dispatch start")?;
            item.phase = GeneratedFollowUpQueuePhase::DispatchStarted;
            item.subordinate_run_id = Some(expected_run_id);
            item.external_side_effect_state = Some(ExternalSideEffectState::Ambiguous);
        }
        QueueJournalEvent::DispatchObserved {
            item_id,
            subordinate_run_id: observed_run_id,
            observation,
        } => {
            let item = queue_item_mut(&mut snapshot, item_id)?;
            if !matches!(
                item.phase,
                GeneratedFollowUpQueuePhase::DispatchStarted
                    | GeneratedFollowUpQueuePhase::HeldAmbiguous
            ) {
                bail!("generated follow-up dispatch observation skips or repeats a transition");
            }
            let expected_run_id = item
                .subordinate_run_id
                .as_deref()
                .context("generated follow-up observation has no dispatch marker")?;
            if observed_run_id != expected_run_id {
                bail!("generated follow-up observation names a different subordinate run");
            }
            observation.validate(Some(expected_run_id))?;
            item.phase = GeneratedFollowUpQueuePhase::DispatchObserved;
            item.observation = Some(observation.clone());
            item.last_gate_denial = observation.gate_denial.clone();
            item.last_environment_failures = observation.environment_failures.clone();
            item.external_side_effect_state = observation.external_side_effect_state;
        }
        QueueJournalEvent::AcknowledgedTerminal {
            item_id,
            subordinate_run_id: observed_run_id,
        } => {
            let item = queue_item_mut(&mut snapshot, item_id)?;
            require_phase(
                item,
                GeneratedFollowUpQueuePhase::DispatchObserved,
                "terminal acknowledgement",
            )?;
            if item.subordinate_run_id.as_deref() != Some(observed_run_id) {
                bail!("generated follow-up acknowledgement names a different subordinate run");
            }
            item.phase = GeneratedFollowUpQueuePhase::AcknowledgedTerminal;
        }
        QueueJournalEvent::HeldAmbiguous {
            item_id,
            subordinate_run_id: observed_run_id,
            external_side_effect_state,
            gate_denial,
            environment_failures,
        } => {
            if *external_side_effect_state != ExternalSideEffectState::Ambiguous {
                bail!("held generated follow-up must use the existing ambiguous effect state");
            }
            let item = queue_item_mut(&mut snapshot, item_id)?;
            require_phase(
                item,
                GeneratedFollowUpQueuePhase::DispatchStarted,
                "ambiguous hold",
            )?;
            if item.subordinate_run_id.as_deref() != Some(observed_run_id) {
                bail!("generated follow-up ambiguous hold names a different subordinate run");
            }
            item.phase = GeneratedFollowUpQueuePhase::HeldAmbiguous;
            item.last_gate_denial = gate_denial.clone();
            item.last_environment_failures = environment_failures.clone();
            item.external_side_effect_state = Some(ExternalSideEffectState::Ambiguous);
        }
    }
    Ok(snapshot)
}

fn queue_item_mut<'a>(
    snapshot: &'a mut GeneratedFollowUpQueueSnapshot,
    item_id: &str,
) -> Result<&'a mut GeneratedFollowUpQueueItemSnapshot> {
    if !snapshot.enqueue_committed {
        bail!("generated follow-up batch is not completely enqueued");
    }
    snapshot
        .items
        .get_mut(item_id)
        .context("generated follow-up queue item is unknown")
}

fn require_phase(
    item: &GeneratedFollowUpQueueItemSnapshot,
    expected: GeneratedFollowUpQueuePhase,
    transition: &str,
) -> Result<()> {
    if item.phase != expected {
        bail!(
            "generated follow-up {transition} transition would skip or repeat from {:?}",
            item.phase
        );
    }
    Ok(())
}

fn prepare_enqueue_records(
    source: &GeneratedFollowUpQueueSource,
    tasks: &[GeneratedFollowUpTaskRecord],
) -> Result<BTreeMap<String, ImmutableEnqueueRecord>> {
    let mut prepared = BTreeMap::new();
    for task in tasks {
        let item_id = generated_follow_up_item_id(source, task)?;
        let item = ImmutableEnqueueRecord {
            item_id: item_id.clone(),
            task: task.clone(),
        };
        if let Some(existing) = prepared.insert(item_id.clone(), item.clone()) {
            if existing != item {
                bail!("generated follow-up item id conflicts inside the enqueue batch");
            }
            bail!("generated follow-up enqueue batch repeats an identical task");
        }
    }
    Ok(prepared)
}

fn generated_follow_up_item_id(
    source: &GeneratedFollowUpQueueSource,
    task: &GeneratedFollowUpTaskRecord,
) -> Result<String> {
    source.validate()?;
    let canonical_task = canonical_validated_task_bytes(task)?;
    domain_separated_sha256(
        ITEM_ID_DOMAIN,
        &[
            source.source_supervisor_run_id.as_bytes(),
            canonical_task.as_slice(),
        ],
    )
}

fn canonical_validated_task_bytes(task: &GeneratedFollowUpTaskRecord) -> Result<Vec<u8>> {
    validate_generated_follow_up_task(task)?;
    let canonical = serde_json::to_vec(task)
        .context("failed to serialize generated follow-up task canonically")?;
    if canonical.len() > MAX_CANONICAL_TASK_BYTES {
        bail!("generated follow-up task exceeds its fixed canonical byte bound");
    }
    let decoded: GeneratedFollowUpTaskRecord = serde_json::from_slice(&canonical)
        .context("generated follow-up task failed its canonical round trip")?;
    if &decoded != task {
        bail!("generated follow-up task changed across its canonical round trip");
    }
    let reencoded = serde_json::to_vec(&decoded)
        .context("failed to re-encode generated follow-up task canonically")?;
    if reencoded != canonical {
        bail!("generated follow-up task serialization is not canonical and stable");
    }
    Ok(canonical)
}

fn validate_generated_follow_up_task(task: &GeneratedFollowUpTaskRecord) -> Result<()> {
    let plan = &task.supervisor_plan;
    let context = &plan.generated_follow_up;
    let assignment = plan
        .assignments
        .first()
        .filter(|_| plan.assignments.len() == 1)
        .context("generated follow-up task must contain exactly one assignment")?;
    if task.breaking_assignment_id != context.breaking_assignment_id
        || task.breaking_change != context.breaking_change
        || task.declaration_sha256 != context.declaration_sha256
        || task.failure_signature != context.failure_signature
        || task.migration_rationale != context.migration_rationale
        || task.cascade_depth != context.cascade_depth
        || task.dispatch_status != context.dispatch_status
        || task.handoff != context.handoff
        || task.cascade_depth != GENERATED_CASCADE_DEPTH
        || task.dispatch_status != GeneratedFollowUpDispatchStatus::DeferredForPlannedRun
        || task.breaking_assignment_id != task.breaking_change.agent_id
        || task.handoff.trim().is_empty()
        || assignment.licensed_breakage.is_some()
    {
        bail!("generated follow-up task provenance or cascade binding is invalid");
    }

    let mut plan_file = tempfile::Builder::new()
        .prefix("maco-generated-follow-up-plan-")
        .suffix(".json")
        .tempfile()
        .context("failed to create a private generated-plan validation file")?;
    serde_json::to_writer(plan_file.as_file_mut(), plan)
        .context("failed to write generated plan for ordinary loader validation")?;
    plan_file
        .as_file_mut()
        .flush()
        .context("failed to flush generated plan before validation")?;
    let loaded = load_supervisor_plan_file(plan_file.path())
        .context("generated follow-up task failed the ordinary supervisor plan loader")?;
    if loaded != ordinary_plan_from_generated(plan) {
        bail!("ordinary supervisor plan loader changed the generated follow-up task");
    }
    Ok(())
}

fn ordinary_plan_from_generated(
    plan: &crate::supervise::GeneratedFollowUpSupervisorPlan,
) -> SupervisorPlan {
    SupervisorPlan {
        version: plan.version,
        task: plan.task.clone(),
        task_file: plan.task_file.clone(),
        max_depth: plan.max_depth,
        max_child_assignments: plan.max_child_assignments,
        max_child_retries: plan.max_child_retries,
        max_gate_corrections: plan.max_gate_corrections,
        child_timeout_seconds: plan.child_timeout_seconds,
        semantic_coordination: plan.semantic_coordination,
        role_models: plan.role_models.clone(),
        model_pricing: plan.model_pricing.clone(),
        review_lenses: plan.review_lenses.clone(),
        review_aggregation_policy: plan.review_aggregation_policy,
        assignments: plan.assignments.clone(),
    }
}

fn queue_instance_id(source: &GeneratedFollowUpQueueSource) -> Result<String> {
    source.validate()?;
    let digest = domain_separated_sha256(
        QUEUE_ID_DOMAIN,
        &[source.source_supervisor_run_id.as_bytes()],
    )?;
    Ok(format!("follow-up-{digest}"))
}

fn subordinate_run_id(item_id: &str) -> Result<String> {
    validate_sha256_id(item_id, "generated follow-up item id")?;
    Ok(format!("follow-up-{item_id}"))
}

fn batch_sha256(item_ids: &[String]) -> Result<String> {
    if item_ids.is_empty() || item_ids.len() > MAX_QUEUE_ITEMS {
        bail!("generated follow-up enqueue batch id list is out of bounds");
    }
    let mut previous = None;
    let mut parts = Vec::with_capacity(item_ids.len());
    for item_id in item_ids {
        validate_sha256_id(item_id, "generated follow-up item id")?;
        if previous.is_some_and(|value: &String| value >= item_id) {
            bail!("generated follow-up enqueue batch item ids are not unique and sorted");
        }
        previous = Some(item_id);
        parts.push(item_id.as_bytes());
    }
    domain_separated_sha256(BATCH_ID_DOMAIN, &parts)
}

fn domain_separated_sha256(domain: &[u8], parts: &[&[u8]]) -> Result<String> {
    let mut capacity = domain.len();
    for part in parts {
        capacity = capacity
            .checked_add(std::mem::size_of::<u64>())
            .and_then(|value| value.checked_add(part.len()))
            .context("generated follow-up identity input length overflowed")?;
    }
    let mut framed = Vec::with_capacity(capacity);
    framed.extend_from_slice(domain);
    for part in parts {
        let length = u64::try_from(part.len())
            .context("generated follow-up identity field length overflowed")?;
        framed.extend_from_slice(&length.to_be_bytes());
        framed.extend_from_slice(part);
    }
    Ok(sha256_hex(&framed))
}

fn validate_source_run_id(run_id: &str) -> Result<()> {
    if run_id.is_empty()
        || run_id.len() > MAX_SOURCE_RUN_ID_BYTES
        || matches!(run_id, "." | "..")
        || !run_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("generated follow-up source run id is not a bounded canonical identifier");
    }
    Ok(())
}

fn validate_sha256_id(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} is not canonical lowercase SHA-256 hex");
    }
    Ok(())
}

fn committed_items_match(
    snapshot: &GeneratedFollowUpQueueSnapshot,
    prepared: &BTreeMap<String, ImmutableEnqueueRecord>,
) -> bool {
    snapshot.items.len() == prepared.len()
        && snapshot.items.iter().all(|(item_id, existing)| {
            prepared
                .get(item_id)
                .is_some_and(|candidate| candidate == &existing.enqueue)
        })
}

fn queue_event_data(
    snapshot: &GeneratedFollowUpQueueSnapshot,
    event: &QueueJournalEvent,
) -> GeneratedFollowUpQueueEventData {
    let (item_ids, subordinate_run_id, gate_denial, environment_failures, effect_state) =
        match event {
            QueueJournalEvent::Created { .. } => (Vec::new(), None, None, Vec::new(), None),
            QueueJournalEvent::EnqueueStaged { item } => {
                (vec![item.item_id.clone()], None, None, Vec::new(), None)
            }
            QueueJournalEvent::Enqueued { item_ids, .. } => {
                (item_ids.clone(), None, None, Vec::new(), None)
            }
            QueueJournalEvent::Claimed { item_id } => {
                (vec![item_id.clone()], None, None, Vec::new(), None)
            }
            QueueJournalEvent::ReleasedBeforeDispatch {
                item_id,
                gate_denial,
                environment_failures,
            } => (
                vec![item_id.clone()],
                None,
                gate_denial.clone(),
                environment_failures.clone(),
                None,
            ),
            QueueJournalEvent::DispatchStarted {
                item_id,
                subordinate_run_id,
            } => (
                vec![item_id.clone()],
                Some(subordinate_run_id.clone()),
                None,
                Vec::new(),
                Some(ExternalSideEffectState::Ambiguous),
            ),
            QueueJournalEvent::DispatchObserved {
                item_id,
                subordinate_run_id,
                observation,
            } => (
                vec![item_id.clone()],
                Some(subordinate_run_id.clone()),
                observation.gate_denial.clone(),
                observation.environment_failures.clone(),
                observation.external_side_effect_state,
            ),
            QueueJournalEvent::AcknowledgedTerminal {
                item_id,
                subordinate_run_id,
            } => (
                vec![item_id.clone()],
                Some(subordinate_run_id.clone()),
                None,
                Vec::new(),
                snapshot
                    .item(item_id)
                    .and_then(GeneratedFollowUpQueueItemSnapshot::external_side_effect_state),
            ),
            QueueJournalEvent::HeldAmbiguous {
                item_id,
                subordinate_run_id,
                external_side_effect_state,
                gate_denial,
                environment_failures,
            } => (
                vec![item_id.clone()],
                Some(subordinate_run_id.clone()),
                gate_denial.clone(),
                environment_failures.clone(),
                Some(*external_side_effect_state),
            ),
        };
    GeneratedFollowUpQueueEventData {
        version: QUEUE_FORMAT_VERSION,
        queue_instance_id: snapshot.queue_instance_id.clone(),
        source_supervisor_run_id: snapshot.source.source_supervisor_run_id.clone(),
        phase: event.phase().to_string(),
        item_ids,
        subordinate_run_id,
        gate_denial,
        environment_failures,
        external_side_effect_state: effect_state,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        artifacts::repository_auth_writer,
        merge::CandidateValidationBinding,
        orchestrator::SemanticCoordinationMode,
        review::{
            ReviewAggregationPolicy, ReviewInformationScope, ReviewLensBackendConfig,
            ReviewLensConfig,
        },
        supervise::{
            AgentRole, AssignmentScheduleEntry, GeneratedFollowUpOperatorDefault,
            GeneratedFollowUpPlanContext, GeneratedFollowUpSupervisorPlan, OrchestratorAssignment,
            RunBudgetLimits, SupervisorBudgetConfig, SupervisorConsultantPlan,
        },
    };
    use git2::Repository;
    use std::{collections::BTreeMap, fs, path::Path};
    use tempfile::TempDir;

    fn repository() -> (TempDir, std::path::PathBuf) {
        let temp = TempDir::new().expect("temporary directory");
        let repo = temp.path().join("repo");
        Repository::init(&repo).expect("initialize repository");
        (temp, repo)
    }

    fn authenticator(repo: &Path) -> RepositoryAuthenticator {
        repository_auth_writer(repo)
            .expect("repository auth writer")
            .into_authenticator()
            .expect("repository authenticator")
    }

    fn source(run_id: &str) -> GeneratedFollowUpQueueSource {
        GeneratedFollowUpQueueSource::root(run_id).expect("valid queue source")
    }

    fn bounds(count: usize) -> GeneratedFollowUpQueueBounds {
        GeneratedFollowUpQueueBounds::from_source_dependents(&[count], &[count])
            .expect("valid queue bounds")
    }

    fn generated_task(suffix: &str) -> GeneratedFollowUpTaskRecord {
        let assignment_id = format!("child-a-licensed-update-{suffix}");
        let failure_signature = format!("dependent failure {suffix}");
        let handoff = "dispatch through the ordinary supervisor plan loader".to_string();
        let breaking_change = CandidateValidationBinding {
            version: 1,
            agent_id: "child-a".to_string(),
            primary_head: None,
            agent_head: None,
            merge_base: None,
            diff_oid: "1".repeat(40),
        };
        let operator_defaults = vec![
            GeneratedFollowUpOperatorDefault {
                field: "task_file".to_string(),
                value: "null".to_string(),
                rationale: "the journaled generated plan document is the authoritative inline task source"
                    .to_string(),
            },
            GeneratedFollowUpOperatorDefault {
                field: "spec_fragment_ids".to_string(),
                value: "[]".to_string(),
                rationale: "the dependent failure and breaking candidate binding provide traceability; no operator-authored spec fragment mapping exists"
                    .to_string(),
            },
        ];
        let generated_follow_up = GeneratedFollowUpPlanContext {
            breaking_assignment_id: "child-a".to_string(),
            breaking_change: breaking_change.clone(),
            declaration_sha256: "a".repeat(64),
            failure_signature: failure_signature.clone(),
            migration_rationale: "update the declared dependent".to_string(),
            cascade_depth: GENERATED_CASCADE_DEPTH,
            dispatch_status: GeneratedFollowUpDispatchStatus::DeferredForPlannedRun,
            handoff: handoff.clone(),
            operator_defaults,
        };
        let assignments = vec![OrchestratorAssignment {
            id: assignment_id.clone(),
            role: AgentRole::ChildOrchestrator,
            assigned_paths: vec![std::path::PathBuf::from(format!("src/{suffix}.rs"))],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            task: Some(format!("update dependent {suffix}")),
            worker_assignments: Vec::new(),
            environment_requirements: Vec::new(),
            licensed_breakage: None,
            notes: Some("generated follow-up".to_string()),
        }];
        let review_lenses = vec![ReviewLensConfig {
            id: "parent-acceptance".to_string(),
            backend: ReviewLensBackendConfig::Model {
                backend_id: "openai".to_string(),
                model: "gpt-5.6-sol".to_string(),
                reasoning_effort: Some("xhigh".to_string()),
            },
            information_scope: ReviewInformationScope::FullChildTranscript,
        }];
        let run_budget = SupervisorBudgetConfig {
            limits: RunBudgetLimits {
                soft_tokens: Some(2),
                hard_tokens: Some(2),
                soft_cost_usd: None,
                hard_cost_usd: None,
            },
            role_token_reservations: BTreeMap::from([
                (AgentRole::ChildOrchestrator, 1),
                (AgentRole::Auditor, 1),
            ]),
        };
        let supervisor_plan = GeneratedFollowUpSupervisorPlan {
            version: 1,
            task: format!("dispatch dependent update {suffix}"),
            task_file: None,
            max_depth: 2,
            max_child_assignments: 1,
            max_child_retries: 0,
            max_gate_corrections: 0,
            child_timeout_seconds: 10,
            semantic_coordination: SemanticCoordinationMode::Off,
            role_models: BTreeMap::new(),
            model_pricing: BTreeMap::new(),
            review_lenses,
            review_aggregation_policy: ReviewAggregationPolicy::AllMustAccept,
            assignments,
            spec_fragment_ids: Vec::new(),
            assignment_schedule: vec![AssignmentScheduleEntry {
                assignment_id,
                parent_assignment_id: None,
                depth: 2,
                flattened_index: 0,
            }],
            run_budget,
            consultant: SupervisorConsultantPlan::default(),
            generated_follow_up,
        };
        GeneratedFollowUpTaskRecord {
            supervisor_plan,
            breaking_assignment_id: "child-a".to_string(),
            breaking_change,
            declaration_sha256: "a".repeat(64),
            failure_signature,
            migration_rationale: "update the declared dependent".to_string(),
            cascade_depth: GENERATED_CASCADE_DEPTH,
            dispatch_status: GeneratedFollowUpDispatchStatus::DeferredForPlannedRun,
            handoff,
        }
    }

    #[test]
    fn legal_lifecycle_exposes_queue_state_before_during_and_after_dispatch() {
        let (_temp, repo) = repository();
        let source = source("source-legal");
        let mut queue = GeneratedFollowUpQueue::create(authenticator(&repo), source, bounds(1))
            .expect("create queue");
        assert!(!queue.snapshot().enqueue_committed());
        assert!(queue.snapshot().items().is_empty());

        queue
            .enqueue_all_before_dispatch(&[generated_task("01")])
            .expect("enqueue complete batch");
        let item_id = queue.snapshot().pending_item_ids()[0].to_string();
        queue.claim(&item_id).expect("claim");
        assert_eq!(
            queue.snapshot().item(&item_id).expect("item").phase(),
            GeneratedFollowUpQueuePhase::Claimed
        );
        let started = queue
            .mark_dispatch_started(&item_id)
            .expect("dispatch started");
        let subordinate_run_id = started.subordinate_run_id.expect("subordinate run id");
        assert_eq!(
            queue
                .snapshot()
                .item(&item_id)
                .expect("item")
                .external_side_effect_state(),
            Some(ExternalSideEffectState::Ambiguous)
        );
        queue
            .mark_dispatch_observed(
                &item_id,
                GeneratedFollowUpDispatchObservation::new(
                    subordinate_run_id,
                    None,
                    Vec::new(),
                    Some(ExternalSideEffectState::Completed),
                )
                .expect("observation"),
            )
            .expect("dispatch observed");
        queue
            .acknowledge_terminal(&item_id)
            .expect("terminal acknowledgement");
        assert_eq!(
            queue.snapshot().item(&item_id).expect("item").phase(),
            GeneratedFollowUpQueuePhase::AcknowledgedTerminal
        );
        assert!(queue.snapshot().pending_item_ids().is_empty());
    }

    #[test]
    fn exact_duplicate_enqueue_is_idempotent_after_commit() {
        let (_temp, repo) = repository();
        let source = source("source-idempotent");
        let task = generated_task("01");
        let mut queue = GeneratedFollowUpQueue::create(authenticator(&repo), source, bounds(1))
            .expect("create queue");
        queue
            .enqueue_all_before_dispatch(std::slice::from_ref(&task))
            .expect("first enqueue");
        let record_count = queue.journal.records().len();
        let events = queue
            .enqueue_all_before_dispatch(std::slice::from_ref(&task))
            .expect("idempotent enqueue");
        assert!(events.is_empty());
        assert_eq!(queue.journal.records().len(), record_count);
    }

    #[test]
    fn conflicting_duplicate_item_id_is_refused_during_replay() {
        let (_temp, repo) = repository();
        let source = source("source-conflict");
        let mut queue =
            GeneratedFollowUpQueue::create(authenticator(&repo), source.clone(), bounds(1))
                .expect("create queue");
        let first_task = generated_task("01");
        let item_id = generated_follow_up_item_id(&source, &first_task).expect("item id");
        let first = QueueJournalEvent::EnqueueStaged {
            item: ImmutableEnqueueRecord {
                item_id: item_id.clone(),
                task: first_task,
            },
        };
        queue
            .journal
            .append(first.phase(), first.subject(), &first)
            .expect("append first staged record");
        let conflicting = QueueJournalEvent::EnqueueStaged {
            item: ImmutableEnqueueRecord {
                item_id,
                task: generated_task("02"),
            },
        };
        queue
            .journal
            .append(conflicting.phase(), conflicting.subject(), &conflicting)
            .expect("append authenticated conflicting record");
        let error = queue
            .replay_snapshot()
            .expect_err("conflicting item id must fail replay");
        assert!(format!("{error:#}").contains("item id does not match"));
    }

    #[test]
    fn skipped_and_repeated_transitions_are_refused() {
        let (_temp, repo) = repository();
        let source = source("source-transition-skip");
        let mut queue = GeneratedFollowUpQueue::create(authenticator(&repo), source, bounds(1))
            .expect("create queue");
        queue
            .enqueue_all_before_dispatch(&[generated_task("01")])
            .expect("enqueue");
        let item_id = queue.snapshot().pending_item_ids()[0].to_string();
        let skipped = QueueJournalEvent::DispatchStarted {
            subordinate_run_id: subordinate_run_id(&item_id).expect("run id"),
            item_id,
        };
        queue
            .journal
            .append(skipped.phase(), skipped.subject(), &skipped)
            .expect("append authenticated skipped transition");
        assert!(queue.replay_snapshot().is_err());

        let (_temp, repo) = repository();
        let source = source("source-transition-repeat");
        let mut queue = GeneratedFollowUpQueue::create(authenticator(&repo), source, bounds(1))
            .expect("create queue");
        queue
            .enqueue_all_before_dispatch(&[generated_task("02")])
            .expect("enqueue");
        let item_id = queue.snapshot().pending_item_ids()[0].to_string();
        queue.claim(&item_id).expect("first claim");
        let repeated = QueueJournalEvent::Claimed { item_id };
        queue
            .journal
            .append(repeated.phase(), repeated.subject(), &repeated)
            .expect("append authenticated repeated transition");
        assert!(queue.replay_snapshot().is_err());
    }

    #[test]
    fn cascade_and_second_generation_refuse_before_any_dispatch_marker() {
        let (_temp, repo) = repository();
        let generated_source = GeneratedFollowUpQueueSource::generated("source-second", 1)
            .expect_err("second generation must be refused");
        assert!(format!("{generated_source:#}").contains("second-generation"));

        let source = source("source-cascade");
        let mut queue = GeneratedFollowUpQueue::create(authenticator(&repo), source, bounds(1))
            .expect("create queue");
        let mut task = generated_task("01");
        task.cascade_depth = 2;
        task.supervisor_plan.generated_follow_up.cascade_depth = 2;
        assert!(queue.enqueue_all_before_dispatch(&[task]).is_err());
        assert!(queue
            .journal
            .records()
            .iter()
            .all(|record| record.phase != "dispatch_started"));
        assert_eq!(queue.journal.records().len(), 1);
    }

    #[test]
    fn capacity_and_checked_overflow_refuse_before_dispatch() {
        let overflow =
            GeneratedFollowUpQueueBounds::from_source_dependents(&[usize::MAX, 1], &[0, 0])
                .expect_err("declared total overflow must fail");
        assert!(format!("{overflow:#}").contains("overflowed"));
        assert!(GeneratedFollowUpQueueBounds::from_source_dependents(
            &[MAX_QUEUE_ITEMS + 1],
            &[MAX_QUEUE_ITEMS + 1],
        )
        .is_err());

        let (_temp, repo) = repository();
        let source = source("source-capacity");
        let mut queue = GeneratedFollowUpQueue::create(authenticator(&repo), source, bounds(2))
            .expect("create queue");
        assert!(queue
            .enqueue_all_before_dispatch(&[generated_task("01")])
            .is_err());
        assert!(queue
            .journal
            .records()
            .iter()
            .all(|record| record.phase != "dispatch_started"));
    }

    #[test]
    fn authenticated_reopen_replays_committed_queue() {
        let (_temp, repo) = repository();
        let source = source("source-reopen");
        let mut queue =
            GeneratedFollowUpQueue::create(authenticator(&repo), source.clone(), bounds(1))
                .expect("create queue");
        queue
            .enqueue_all_before_dispatch(&[generated_task("01")])
            .expect("enqueue");
        let item_id = queue.snapshot().pending_item_ids()[0].to_string();
        drop(queue);

        let reopened = GeneratedFollowUpQueue::open(authenticator(&repo), &source)
            .expect("authenticated reopen");
        assert!(reopened.snapshot().enqueue_committed());
        assert_eq!(
            reopened.snapshot().item(&item_id).expect("item").phase(),
            GeneratedFollowUpQueuePhase::Enqueued
        );
    }

    #[test]
    fn authenticated_record_tampering_is_refused() {
        let (_temp, repo) = repository();
        let source = source("source-tamper");
        let queue = GeneratedFollowUpQueue::create(authenticator(&repo), source.clone(), bounds(1))
            .expect("create queue");
        let first_record = queue
            .journal
            .root()
            .path()
            .join(queue.journal.instance_id())
            .join("00000000000000000001.json");
        drop(queue);
        let mut bytes = fs::read(&first_record).expect("read authenticated record");
        let position = bytes
            .windows(b"source-tamper".len())
            .position(|window| window == b"source-tamper")
            .expect("source id in record");
        bytes[position] = b'S';
        fs::write(&first_record, bytes).expect("tamper record");
        assert!(GeneratedFollowUpQueue::open(authenticator(&repo), &source).is_err());
    }

    #[test]
    fn pending_and_claimed_items_survive_crash_replay_without_loss() {
        let (_temp, repo) = repository();
        let source = source("source-claimed-replay");
        let mut queue =
            GeneratedFollowUpQueue::create(authenticator(&repo), source.clone(), bounds(2))
                .expect("create queue");
        queue
            .enqueue_all_before_dispatch(&[generated_task("01"), generated_task("02")])
            .expect("enqueue");
        let ids = queue.snapshot().items().keys().cloned().collect::<Vec<_>>();
        queue.claim(&ids[0]).expect("claim first item");
        drop(queue);

        let reopened = GeneratedFollowUpQueue::open(authenticator(&repo), &source)
            .expect("reopen claimed queue");
        assert_eq!(
            reopened.snapshot().item(&ids[0]).expect("claimed").phase(),
            GeneratedFollowUpQueuePhase::Claimed
        );
        assert_eq!(
            reopened.snapshot().item(&ids[1]).expect("pending").phase(),
            GeneratedFollowUpQueuePhase::Enqueued
        );
    }

    #[test]
    fn dispatch_started_replay_remains_ambiguous_and_never_pending() {
        let (_temp, repo) = repository();
        let source = source("source-started-replay");
        let mut queue =
            GeneratedFollowUpQueue::create(authenticator(&repo), source.clone(), bounds(1))
                .expect("create queue");
        queue
            .enqueue_all_before_dispatch(&[generated_task("01")])
            .expect("enqueue");
        let item_id = queue.snapshot().pending_item_ids()[0].to_string();
        queue.claim(&item_id).expect("claim");
        queue
            .mark_dispatch_started(&item_id)
            .expect("dispatch start");
        drop(queue);

        let mut reopened = GeneratedFollowUpQueue::open(authenticator(&repo), &source)
            .expect("reopen started queue");
        let item = reopened.snapshot().item(&item_id).expect("item");
        assert_eq!(item.phase(), GeneratedFollowUpQueuePhase::DispatchStarted);
        assert_eq!(
            item.external_side_effect_state(),
            Some(ExternalSideEffectState::Ambiguous)
        );
        assert!(reopened.snapshot().pending_item_ids().is_empty());
        assert!(reopened.claim(&item_id).is_err());
        assert!(reopened
            .release_before_dispatch(&item_id, None, Vec::new())
            .is_err());
        reopened
            .mark_held_ambiguous(&item_id, None, Vec::new())
            .expect("hold ambiguous dispatch");
        assert_eq!(
            reopened.snapshot().item(&item_id).expect("held").phase(),
            GeneratedFollowUpQueuePhase::HeldAmbiguous
        );
    }
}
