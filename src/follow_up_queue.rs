//! Authenticated, bounded queue state for licensed-breakage follow-up runs.
//!
//! Enqueue is a two-step durable transaction: immutable item records are staged
//! individually, then one commit record makes the complete batch dispatchable.
//! A crash during staging therefore exposes no partial pending batch. Dispatch
//! is also fail-closed: once its durable start marker exists, replay treats the
//! effect as ambiguous and never returns the item to pending automatically.

#![allow(dead_code)]

pub(crate) mod graph;
pub(crate) mod lease;

#[cfg(test)]
use crate::supervise::AssignmentPhase;
use crate::{
    artifacts::state_auth::{sha256_hex, AuthenticationDomain, RepositoryAuthenticator},
    external_agent::EnvironmentFailure,
    gate_denial::{ExternalSideEffectState, GateDenial},
    machine_global::{machine_global_config_content_binding, MachineGlobalRetentionBinding},
    safe_state::FileIdentity,
    state_journal::{AuthenticatedStateJournal, JournalRecord, JournalSpec},
    supervise::{
        validate_generated_follow_up_plan_document, AuthenticatedGeneratedFollowUpTerminal,
        GeneratedFollowUpDispatchStatus, GeneratedFollowUpTaskRecord, SupervisorPlan,
        LICENSED_BREAKAGE_CASCADE_DEPTH, MAX_LICENSED_BREAKAGE_DEPENDENTS,
    },
};
use anyhow::{bail, Context, Result};
use graph::{
    replay_graph_events, DurableGraphDefinition, DurableGraphEvent, DurableGraphNodeKind,
    DurableGraphRuntimeState, GraphBranchId,
};
use lease::{LeaseEvent, LeaseIdentity, LeasePhase, LeaseProof, LeaseState, WorkerIdentity};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const GENERATED_FOLLOW_UP_QUEUE_ROOT_NAME: &str =
    "authenticated-generated-follow-up-queues-v1";
pub(crate) const GENERATED_FOLLOW_UP_QUEUE_ROOT_LOCK: &str = ".generated-follow-up-queues.lock";

const QUEUE_FORMAT_VERSION: u32 = 1;
const SOURCE_CASCADE_DEPTH: u8 = 0;
// This is an authenticated-state storage ceiling, not an execution budget.
// Per-assignment work remains bounded by the licensed-breakage constants and
// each generated plan's derived run budget.
const MAX_STORED_QUEUE_ITEMS: usize = 64;
const MAX_SOURCE_RUN_ID_BYTES: usize = 128;
const MAX_CANONICAL_TASK_BYTES: usize = 7 * 1024 * 1024;
const MAX_ENQUEUED_TASK_BYTES: usize = 64 * 1024 * 1024;
// Every graph transition consumes one record in this authenticated journal.
// This deliberately makes the queue's smaller limit, rather than graph.rs's
// storage-agnostic ceiling, the effective durable history bound. The child
// module does not expose its validated loop-membership-based worst-case count,
// so root admission cannot soundly pre-compute remaining capacity; append and
// replay therefore remain the fail-closed enforcement point.
const MAX_AUTHENTICATED_QUEUE_RECORDS: usize = 512;
const ITEM_ID_DOMAIN: &[u8] = b"MACO\0generated-follow-up-queue-item\0v1\0";
const QUEUE_ID_DOMAIN: &[u8] = b"MACO\0generated-follow-up-queue-instance\0v1\0";
const QUEUE_SLOT_ID_DOMAIN: &[u8] = b"MACO\0generated-follow-up-queue-slot\0v2\0";
const BATCH_ID_DOMAIN: &[u8] = b"MACO\0generated-follow-up-queue-batch\0v1\0";

enum GeneratedFollowUpQueueJournalSpec {}

impl JournalSpec for GeneratedFollowUpQueueJournalSpec {
    const FORMAT_VERSION: u32 = QUEUE_FORMAT_VERSION;
    const NAMESPACE: &'static str = "generated_follow_up_queue";
    const ROOT_NAME: &'static str = GENERATED_FOLLOW_UP_QUEUE_ROOT_NAME;
    const ROOT_LOCK_NAME: &'static str = GENERATED_FOLLOW_UP_QUEUE_ROOT_LOCK;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GeneratedFollowUpQueueEntrypoint {
    SuperviseRun,
    AutopilotRun,
}

impl GeneratedFollowUpQueueEntrypoint {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::SuperviseRun => "supervise_run",
            Self::AutopilotRun => "autopilot_run",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GeneratedFollowUpRetentionBinding {
    config_content_sha256: String,
    config_file_identity: FileIdentity,
    root_id: String,
    owner: String,
    correction_correlation_id: String,
    binding_sha256: String,
}

impl GeneratedFollowUpRetentionBinding {
    pub(crate) fn from_machine_global(binding: &MachineGlobalRetentionBinding) -> Result<Self> {
        let (config_content_sha256, config_file_identity) =
            machine_global_config_content_binding(&binding.config)?;
        let binding_sha256 = domain_separated_sha256(
            b"MACO\0generated-follow-up-retention-binding\0v1\0",
            &[
                config_content_sha256.as_bytes(),
                binding.root_id.as_bytes(),
                binding.owner.as_bytes(),
                binding.correction_correlation_id.as_bytes(),
                &config_file_identity.device.to_be_bytes(),
                &config_file_identity.file.to_be_bytes(),
            ],
        )?;
        let retained = Self {
            config_content_sha256,
            config_file_identity,
            root_id: binding.root_id.clone(),
            owner: binding.owner.clone(),
            correction_correlation_id: binding.correction_correlation_id.clone(),
            binding_sha256,
        };
        retained.validate()?;
        Ok(retained)
    }

    pub(crate) fn binding_sha256(&self) -> &str {
        &self.binding_sha256
    }

    pub(crate) fn root_id(&self) -> &str {
        &self.root_id
    }

    fn validate(&self) -> Result<()> {
        validate_sha256_id(
            &self.config_content_sha256,
            "machine-global config content digest",
        )?;
        validate_sha256_id(
            &self.binding_sha256,
            "machine-global retention binding digest",
        )?;
        if self.config_file_identity.device == 0 || self.config_file_identity.file == 0 {
            bail!("machine-global config file identity is incomplete");
        }
        validate_source_run_id(&self.root_id)
            .context("machine-global runtime root identity is invalid")?;
        validate_bounded_text(&self.owner, "machine-global retention owner", 256)?;
        validate_bounded_text(
            &self.correction_correlation_id,
            "machine-global correction correlation id",
            256,
        )?;
        let expected = domain_separated_sha256(
            b"MACO\0generated-follow-up-retention-binding\0v1\0",
            &[
                self.config_content_sha256.as_bytes(),
                self.root_id.as_bytes(),
                self.owner.as_bytes(),
                self.correction_correlation_id.as_bytes(),
                &self.config_file_identity.device.to_be_bytes(),
                &self.config_file_identity.file.to_be_bytes(),
            ],
        )?;
        if self.binding_sha256 != expected {
            bail!("machine-global retention binding digest does not match its exact fields");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GeneratedFollowUpQueueSource {
    source_supervisor_run_id: String,
    source_normalized_plan_sha256: String,
    source_report_accepted: bool,
    source_report_publishable: bool,
    outer_entrypoint: GeneratedFollowUpQueueEntrypoint,
    outer_command_run_id: String,
    repository_id: String,
    whole_primary_baseline_sha256: String,
    machine_global_retention: GeneratedFollowUpRetentionBinding,
    cascade_depth: u8,
}

pub(crate) struct GeneratedFollowUpQueueRootInput {
    pub(crate) source_supervisor_run_id: String,
    pub(crate) source_normalized_plan_sha256: String,
    pub(crate) source_report_accepted: bool,
    pub(crate) source_report_publishable: bool,
    pub(crate) outer_entrypoint: GeneratedFollowUpQueueEntrypoint,
    pub(crate) outer_command_run_id: String,
    pub(crate) repository_id: String,
    pub(crate) whole_primary_baseline_sha256: String,
    pub(crate) machine_global_retention: GeneratedFollowUpRetentionBinding,
}

impl GeneratedFollowUpQueueSource {
    pub(crate) fn root(input: GeneratedFollowUpQueueRootInput) -> Result<Self> {
        let source = Self {
            source_supervisor_run_id: input.source_supervisor_run_id,
            source_normalized_plan_sha256: input.source_normalized_plan_sha256,
            source_report_accepted: input.source_report_accepted,
            source_report_publishable: input.source_report_publishable,
            outer_entrypoint: input.outer_entrypoint,
            outer_command_run_id: input.outer_command_run_id,
            repository_id: input.repository_id,
            whole_primary_baseline_sha256: input.whole_primary_baseline_sha256,
            machine_global_retention: input.machine_global_retention,
            cascade_depth: SOURCE_CASCADE_DEPTH,
        };
        source.validate()?;
        Ok(source)
    }

    pub(crate) fn generated(mut source: Self, cascade_depth: u8) -> Result<Self> {
        source.cascade_depth = cascade_depth;
        source.validate()?;
        Ok(source)
    }

    pub(crate) fn source_supervisor_run_id(&self) -> &str {
        &self.source_supervisor_run_id
    }

    pub(crate) fn cascade_depth(&self) -> u8 {
        self.cascade_depth
    }

    pub(crate) fn source_normalized_plan_sha256(&self) -> &str {
        &self.source_normalized_plan_sha256
    }

    pub(crate) fn source_report_accepted(&self) -> bool {
        self.source_report_accepted
    }

    pub(crate) fn source_report_publishable(&self) -> bool {
        self.source_report_publishable
    }

    pub(crate) fn outer_entrypoint(&self) -> GeneratedFollowUpQueueEntrypoint {
        self.outer_entrypoint
    }

    pub(crate) fn outer_command_run_id(&self) -> &str {
        &self.outer_command_run_id
    }

    pub(crate) fn repository_id(&self) -> &str {
        &self.repository_id
    }

    pub(crate) fn whole_primary_baseline_sha256(&self) -> &str {
        &self.whole_primary_baseline_sha256
    }

    pub(crate) fn retention_binding_sha256(&self) -> &str {
        self.machine_global_retention.binding_sha256()
    }

    pub(crate) fn machine_global_runtime_root_id(&self) -> &str {
        self.machine_global_retention.root_id()
    }

    /// The outer command is provenance, not execution identity. A source
    /// supervisor run may first be entered through Autopilot and later resumed
    /// through `supervise run`; every field that can change what is dispatched
    /// must still match exactly before that resume reuses the durable queue.
    fn has_same_execution_basis(&self, other: &Self) -> bool {
        self.source_supervisor_run_id == other.source_supervisor_run_id
            && self.source_normalized_plan_sha256 == other.source_normalized_plan_sha256
            && self.source_report_accepted == other.source_report_accepted
            && self.source_report_publishable == other.source_report_publishable
            && self.repository_id == other.repository_id
            && self.whole_primary_baseline_sha256 == other.whole_primary_baseline_sha256
            && self.machine_global_retention == other.machine_global_retention
            && self.cascade_depth == other.cascade_depth
    }

    fn validate(&self) -> Result<()> {
        validate_source_run_id(&self.source_supervisor_run_id)?;
        validate_source_run_id(&self.outer_command_run_id)
            .context("generated follow-up outer command run identity is invalid")?;
        validate_sha256_id(
            &self.source_normalized_plan_sha256,
            "source normalized supervisor plan digest",
        )?;
        if !self.source_report_accepted || !self.source_report_publishable {
            bail!("generated follow-up queue source must be observed accepted and publishable");
        }
        validate_sha256_id(&self.repository_id, "repository authentication identity")?;
        validate_sha256_id(
            &self.whole_primary_baseline_sha256,
            "whole-primary baseline binding",
        )?;
        self.machine_global_retention.validate()?;
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
    /// Derives the queue's storage capacity from the accepted source plan and
    /// the complete set of generated records that plan actually produced.
    /// The source declarations retain the established per-assignment bound;
    /// this queue adds only a fixed authenticated-storage ceiling.
    pub(crate) fn from_validated_source_plan_and_tasks(
        source_plan: &SupervisorPlan,
        tasks: &[GeneratedFollowUpTaskRecord],
    ) -> Result<Self> {
        if tasks.is_empty() {
            bail!("generated follow-up queue requires at least one validated task");
        }
        let mut declared_by_assignment = BTreeMap::new();
        for assignment in &source_plan.assignments {
            let Some(declaration) = assignment.licensed_breakage.as_ref() else {
                continue;
            };
            if declaration.dependents.is_empty()
                || declaration.dependents.len() > MAX_LICENSED_BREAKAGE_DEPENDENTS
            {
                bail!(
                    "generated follow-up source assignment '{}' exceeds the established licensed-dependent bound",
                    assignment.id
                );
            }
            if declared_by_assignment
                .insert(assignment.id.clone(), declaration.dependents.clone())
                .is_some()
            {
                bail!("generated follow-up source plan repeats an assignment id");
            }
        }
        if declared_by_assignment.is_empty() {
            bail!("generated follow-up source plan has no licensed-breakage declarations");
        }

        let mut validated_by_assignment = BTreeMap::<String, usize>::new();
        let mut represented_dependents = BTreeSet::<(String, String)>::new();
        for task in tasks {
            canonical_validated_task_bytes(task)?;
            let Some(dependents) = declared_by_assignment.get(&task.breaking_assignment_id) else {
                bail!(
                    "generated follow-up task names a breaking assignment absent from the validated source plan"
                );
            };
            let assignment = task
                .supervisor_plan
                .assignments
                .first()
                .filter(|_| task.supervisor_plan.assignments.len() == 1)
                .context("generated follow-up task must contain one dependent assignment")?;
            let matched = dependents
                .iter()
                .enumerate()
                .find(|(index, dependent)| {
                    let ordinal = index.saturating_add(1);
                    assignment.id
                        == format!(
                            "{}-licensed-update-{ordinal:02}",
                            task.breaking_assignment_id
                        )
                        && assignment.assigned_paths == dependent.paths
                        && assignment.semantic_symbols == dependent.interfaces
                })
                .map(|(_, dependent)| dependent)
                .context(
                    "generated follow-up assignment does not exactly match one declared dependent scope",
                )?;
            if !represented_dependents.insert((
                task.breaking_assignment_id.clone(),
                matched.dependent_id.clone(),
            )) {
                bail!("generated follow-up task set represents one declared dependent twice");
            }
            let count = validated_by_assignment
                .entry(task.breaking_assignment_id.clone())
                .or_default();
            *count = count
                .checked_add(1)
                .context("generated follow-up validated-dependent count overflowed")?;
        }

        let mut declared_counts = Vec::with_capacity(declared_by_assignment.len());
        let mut validated_counts = Vec::with_capacity(declared_by_assignment.len());
        for (assignment_id, dependents) in declared_by_assignment {
            let validated = validated_by_assignment
                .remove(&assignment_id)
                .unwrap_or_default();
            declared_counts.push(dependents.len());
            validated_counts.push(validated);
        }
        if !validated_by_assignment.is_empty() {
            bail!("generated follow-up validated tasks escaped their source declarations");
        }
        Self::from_validated_counts(&declared_counts, &validated_counts)
    }

    /// Computes one round's exact item capacity from per-source-assignment
    /// declared and validated dependent counts. Both totals use checked
    /// arithmetic; validated failures may be a subset of declarations.
    fn from_validated_counts(
        declared_per_assignment: &[usize],
        validated_per_assignment: &[usize],
    ) -> Result<Self> {
        if declared_per_assignment.is_empty()
            || declared_per_assignment.len() != validated_per_assignment.len()
            || declared_per_assignment.len() > MAX_STORED_QUEUE_ITEMS
        {
            bail!(
                "generated follow-up queue source counts must contain 1..={MAX_STORED_QUEUE_ITEMS} aligned assignment groups"
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
        }
        for (declared, validated) in declared_per_assignment
            .iter()
            .copied()
            .zip(validated_per_assignment.iter().copied())
        {
            if declared > MAX_LICENSED_BREAKAGE_DEPENDENTS {
                bail!(
                    "generated follow-up source assignment exceeds the established licensed-dependent bound of {MAX_LICENSED_BREAKAGE_DEPENDENTS}"
                );
            }
            if validated > declared {
                bail!("generated follow-up validated dependents exceed the source declaration");
            }
        }
        if validated_dependents == 0 || validated_dependents > MAX_STORED_QUEUE_ITEMS {
            bail!(
                "generated follow-up queue storage capacity must be between 1 and {MAX_STORED_QUEUE_ITEMS}"
            );
        }
        let bounds = Self {
            declared_dependents,
            validated_dependents,
            capacity: validated_dependents,
        };
        bounds.validate()?;
        Ok(bounds)
    }

    #[cfg(test)]
    fn from_source_dependents(
        declared_per_assignment: &[usize],
        validated_per_assignment: &[usize],
    ) -> Result<Self> {
        Self::from_validated_counts(declared_per_assignment, validated_per_assignment)
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
            || self.validated_dependents > MAX_STORED_QUEUE_ITEMS
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

/// Immutable, authenticated mapping between a graph task branch and its queue
/// item. Callers must not infer this relationship from equal-looking strings.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DurableGraphQueueItemBinding {
    branch_id: GraphBranchId,
    item_id: String,
}

impl DurableGraphQueueItemBinding {
    pub(crate) fn new(branch_id: GraphBranchId, item_id: impl Into<String>) -> Result<Self> {
        let binding = Self {
            branch_id,
            item_id: item_id.into(),
        };
        validate_sha256_id(&binding.item_id, "graph-bound queue item id")?;
        Ok(binding)
    }

    pub(crate) fn branch_id(&self) -> &GraphBranchId {
        &self.branch_id
    }

    pub(crate) fn item_id(&self) -> &str {
        &self.item_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
enum QueueJournalEvent {
    Created {
        source: GeneratedFollowUpQueueSource,
        bounds: GeneratedFollowUpQueueBounds,
    },
    EnqueueStaged {
        item: Box<ImmutableEnqueueRecord>,
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
    GraphDefinedAndBound {
        graph_event: DurableGraphEvent,
        bindings: Vec<DurableGraphQueueItemBinding>,
    },
    GraphTransition {
        graph_event: DurableGraphEvent,
    },
    LeaseClaimed {
        item_id: String,
        lease_event: LeaseEvent,
        graph_event: DurableGraphEvent,
    },
    LeaseHeartbeat {
        item_id: String,
        lease_event: LeaseEvent,
    },
    LeaseReleasedBeforeDispatch {
        item_id: String,
        lease_event: LeaseEvent,
        graph_event: DurableGraphEvent,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        gate_denial: Option<GateDenial>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        environment_failures: Vec<EnvironmentFailure>,
    },
    LeaseReclaimed {
        item_id: String,
        lease_event: LeaseEvent,
    },
    LeaseEffectStarted {
        item_id: String,
        subordinate_run_id: String,
        lease_event: LeaseEvent,
    },
    LeaseTerminalAcknowledged {
        item_id: String,
        subordinate_run_id: String,
        observation: GeneratedFollowUpDispatchObservation,
        lease_event: LeaseEvent,
        graph_event: DurableGraphEvent,
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
            Self::GraphDefinedAndBound { .. } => "graph_defined_bound",
            Self::GraphTransition { .. } => "graph_transition",
            Self::LeaseClaimed { .. } => "lease_claimed",
            Self::LeaseHeartbeat { .. } => "lease_heartbeat",
            Self::LeaseReleasedBeforeDispatch { .. } => "lease_released",
            Self::LeaseReclaimed { .. } => "lease_reclaimed",
            Self::LeaseEffectStarted { .. } => "lease_effect_started",
            Self::LeaseTerminalAcknowledged { .. } => "lease_terminal_ack",
        }
    }

    fn subject(&self) -> Option<&str> {
        match self {
            Self::Created { .. } | Self::Enqueued { .. } | Self::GraphDefinedAndBound { .. } => {
                None
            }
            Self::EnqueueStaged { item } => Some(&item.item_id),
            Self::Claimed { item_id }
            | Self::ReleasedBeforeDispatch { item_id, .. }
            | Self::DispatchStarted { item_id, .. }
            | Self::DispatchObserved { item_id, .. }
            | Self::AcknowledgedTerminal { item_id, .. }
            | Self::HeldAmbiguous { item_id, .. }
            | Self::LeaseClaimed { item_id, .. }
            | Self::LeaseHeartbeat { item_id, .. }
            | Self::LeaseReleasedBeforeDispatch { item_id, .. }
            | Self::LeaseReclaimed { item_id, .. }
            | Self::LeaseEffectStarted { item_id, .. }
            | Self::LeaseTerminalAcknowledged { item_id, .. } => Some(item_id),
            Self::GraphTransition { graph_event } => graph_event.subject(),
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
    graph: Option<DurableGraphRuntimeState>,
    graph_events: Vec<DurableGraphEvent>,
    graph_event_count: usize,
    branch_to_item: BTreeMap<GraphBranchId, String>,
    item_to_branch: BTreeMap<String, GraphBranchId>,
    leases: BTreeMap<String, LeaseState>,
    lease_identity_items: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct GeneratedFollowUpQueueSummary {
    pub version: u32,
    pub queue_instance_id: String,
    pub source_supervisor_run_id: String,
    pub outer_entrypoint: GeneratedFollowUpQueueEntrypoint,
    pub outer_command_run_id: String,
    pub cascade_depth: u8,
    pub capacity: usize,
    pub staged: usize,
    pub enqueued: usize,
    pub claimed: usize,
    pub dispatch_started: usize,
    pub dispatch_observed: usize,
    pub acknowledged_terminal: usize,
    pub held_ambiguous: usize,
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

    pub(crate) fn graph(&self) -> Option<&DurableGraphRuntimeState> {
        self.graph.as_ref()
    }

    pub(crate) fn graph_event_count(&self) -> usize {
        self.graph_event_count
    }

    pub(crate) fn branch_item_id(&self, branch_id: &GraphBranchId) -> Option<&str> {
        self.branch_to_item.get(branch_id).map(String::as_str)
    }

    pub(crate) fn item_branch_id(&self, item_id: &str) -> Option<&GraphBranchId> {
        self.item_to_branch.get(item_id)
    }

    pub(crate) fn lease(&self, item_id: &str) -> Option<&LeaseState> {
        self.leases.get(item_id)
    }

    pub(crate) fn lease_phase(&self, item_id: &str) -> Option<LeasePhase> {
        self.lease(item_id).map(LeaseState::phase)
    }

    pub(crate) fn pending_item_ids(&self) -> Vec<&str> {
        self.items
            .values()
            .filter(|item| self.item_is_pending(item))
            .map(GeneratedFollowUpQueueItemSnapshot::item_id)
            .collect()
    }

    fn item_is_pending(&self, item: &GeneratedFollowUpQueueItemSnapshot) -> bool {
        if item.phase != GeneratedFollowUpQueuePhase::Enqueued {
            return false;
        }
        let Some(branch_id) = self.item_to_branch.get(item.item_id()) else {
            return true;
        };
        let Some(graph) = self.graph.as_ref() else {
            return false;
        };
        if graph.termination().is_some() {
            return false;
        }
        let Some(task_node) = graph.definition().nodes().iter().find(|node| {
            matches!(
                node.kind(),
                DurableGraphNodeKind::Task {
                    branch_id: candidate,
                    ..
                } if candidate == branch_id
            )
        }) else {
            return false;
        };
        if !graph
            .active_node_ids()
            .any(|node_id| node_id == task_node.id())
        {
            return false;
        }
        let Some(current_visit) = graph.node_visit(task_node.id()) else {
            return false;
        };
        let Some(branch) = graph.branch(branch_id) else {
            return false;
        };
        if branch.attempt_in_progress().is_some() {
            return false;
        }
        if branch.retry_scheduled() {
            return true;
        }
        branch
            .attempts()
            .last()
            .is_none_or(|attempt| attempt.visit() < current_visit)
    }

    pub(crate) fn summary(&self) -> GeneratedFollowUpQueueSummary {
        let mut summary = GeneratedFollowUpQueueSummary {
            version: QUEUE_FORMAT_VERSION,
            queue_instance_id: self.queue_instance_id.clone(),
            source_supervisor_run_id: self.source.source_supervisor_run_id.clone(),
            outer_entrypoint: self.source.outer_entrypoint,
            outer_command_run_id: self.source.outer_command_run_id.clone(),
            cascade_depth: self.source.cascade_depth,
            capacity: self.bounds.capacity,
            staged: self.staged.len(),
            enqueued: 0,
            claimed: 0,
            dispatch_started: 0,
            dispatch_observed: 0,
            acknowledged_terminal: 0,
            held_ambiguous: 0,
        };
        for item in self.items.values() {
            match item.phase {
                GeneratedFollowUpQueuePhase::Enqueued => summary.enqueued += 1,
                GeneratedFollowUpQueuePhase::Claimed => summary.claimed += 1,
                GeneratedFollowUpQueuePhase::DispatchStarted => summary.dispatch_started += 1,
                GeneratedFollowUpQueuePhase::DispatchObserved => summary.dispatch_observed += 1,
                GeneratedFollowUpQueuePhase::AcknowledgedTerminal => {
                    summary.acknowledged_terminal += 1;
                }
                GeneratedFollowUpQueuePhase::HeldAmbiguous => summary.held_ambiguous += 1,
            }
        }
        summary
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
        Self::create_or_open(authenticator, source, bounds)
    }

    pub(crate) fn create_or_open(
        authenticator: RepositoryAuthenticator,
        source: GeneratedFollowUpQueueSource,
        bounds: GeneratedFollowUpQueueBounds,
    ) -> Result<Self> {
        source.validate()?;
        bounds.validate()?;
        verify_source_repository_binding(&authenticator, &source)?;
        let journal_slot_id = queue_journal_slot_id(&source)?;
        let mut journal = QueueJournal::open_or_initialize(authenticator, &journal_slot_id)?;
        if journal.records().is_empty() {
            let created = QueueJournalEvent::Created {
                source: source.clone(),
                bounds: bounds.clone(),
            };
            journal.append(created.phase(), None, &created)?;
        }
        let snapshot = replay_queue_records(&journal_slot_id, journal.records())?;
        if !snapshot.source.has_same_execution_basis(&source) || snapshot.bounds != bounds {
            bail!("generated follow-up queue execution basis changed across create-or-open");
        }
        Ok(Self { journal, snapshot })
    }

    pub(crate) fn open(
        authenticator: RepositoryAuthenticator,
        source: &GeneratedFollowUpQueueSource,
    ) -> Result<Self> {
        source.validate()?;
        verify_source_repository_binding(&authenticator, source)?;
        let journal_slot_id = queue_journal_slot_id(source)?;
        let journal = QueueJournal::open_instance(authenticator, &journal_slot_id)?;
        let snapshot = replay_queue_records(&journal_slot_id, journal.records())?;
        if &snapshot.source != source {
            bail!("generated follow-up queue source identity changed across reopen");
        }
        Ok(Self { journal, snapshot })
    }

    /// Opens the queue identified by the immutable source execution identity,
    /// if that queue has been durably created.
    ///
    /// This read path intentionally does not initialize an absent queue. It is
    /// used after a cascade error to distinguish a conclusively pre-dispatch
    /// failure from an already-started generated effect without manufacturing
    /// new queue state while reporting the failure.
    pub(crate) fn open_existing_for_source_execution(
        authenticator: RepositoryAuthenticator,
        source_supervisor_run_id: &str,
        source_normalized_plan_sha256: &str,
    ) -> Result<Option<Self>> {
        validate_source_run_id(source_supervisor_run_id)?;
        validate_sha256_id(
            source_normalized_plan_sha256,
            "source normalized supervisor plan digest",
        )?;
        authenticator.verify_epoch()?;
        let repository_id = authenticator.binding().repository_id.clone();
        validate_sha256_id(&repository_id, "repository authentication identity")?;
        let journal_slot_id = queue_journal_slot_id_for_source_execution(
            source_supervisor_run_id,
            source_normalized_plan_sha256,
            &repository_id,
        )?;
        if !authenticator
            .state_root()
            .direct_child_exists(GENERATED_FOLLOW_UP_QUEUE_ROOT_NAME)?
        {
            return Ok(None);
        }
        let journal_root = QueueJournal::existing_root(&authenticator)?;
        if !journal_root.direct_child_exists(&journal_slot_id)? {
            return Ok(None);
        }
        let journal = QueueJournal::open_instance(authenticator, &journal_slot_id)?;
        let snapshot = replay_queue_records(&journal_slot_id, journal.records())?;
        if snapshot.source.source_supervisor_run_id() != source_supervisor_run_id
            || snapshot.source.source_normalized_plan_sha256() != source_normalized_plan_sha256
            || snapshot.source.repository_id() != repository_id
        {
            bail!("generated follow-up queue source execution identity changed across reopen");
        }
        Ok(Some(Self { journal, snapshot }))
    }

    pub(crate) fn snapshot(&self) -> &GeneratedFollowUpQueueSnapshot {
        &self.snapshot
    }

    pub(crate) fn replay_snapshot(&self) -> Result<GeneratedFollowUpQueueSnapshot> {
        replay_queue_records(self.journal.instance_id(), self.journal.records())
    }

    pub(crate) fn summary(&self) -> GeneratedFollowUpQueueSummary {
        self.snapshot.summary()
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
            events.push(self.append_event(QueueJournalEvent::EnqueueStaged {
                item: Box::new(item.clone()),
            })?);
        }
        let item_ids = prepared.keys().cloned().collect::<Vec<_>>();
        let batch_sha256 = batch_sha256(&item_ids)?;
        events.push(self.append_event(QueueJournalEvent::Enqueued {
            item_ids,
            batch_sha256,
        })?);
        Ok(events)
    }

    /// Completes an interrupted staged batch only when the caller presents the
    /// exact immutable task set. Existing staged records are checked before
    /// the missing suffix and single commit record are appended.
    pub(crate) fn complete_staged_batch(
        &mut self,
        tasks: &[GeneratedFollowUpTaskRecord],
    ) -> Result<Vec<GeneratedFollowUpQueueEventData>> {
        if self.snapshot.enqueue_committed || self.snapshot.staged.is_empty() {
            bail!("generated follow-up queue has no incomplete staged batch to recover");
        }
        self.enqueue_all_before_dispatch(tasks)
    }

    /// Enables typed graph/lease execution in one authenticated definition and
    /// binding record. Once this succeeds, identityless mutation APIs fail
    /// closed for every bound item.
    pub(crate) fn define_graph(
        &mut self,
        definition: DurableGraphDefinition,
        mut bindings: Vec<DurableGraphQueueItemBinding>,
    ) -> Result<GeneratedFollowUpQueueEventData> {
        bindings.sort();
        self.append_event(QueueJournalEvent::GraphDefinedAndBound {
            graph_event: DurableGraphEvent::Defined { definition },
            bindings,
        })
    }

    /// Applies a non-worker graph driver transition. Worker attempt start and
    /// completion are deliberately accepted only by the lease-bound composite
    /// APIs below.
    pub(crate) fn apply_graph_transition(
        &mut self,
        graph_event: DurableGraphEvent,
    ) -> Result<GeneratedFollowUpQueueEventData> {
        self.append_event(QueueJournalEvent::GraphTransition { graph_event })
    }

    pub(crate) fn claim_with_lease(
        &mut self,
        item_id: &str,
        worker: WorkerIdentity,
        lease_id: LeaseIdentity,
        observed_at: u64,
        expires_at: u64,
        graph_attempt: DurableGraphEvent,
    ) -> Result<(GeneratedFollowUpQueueEventData, LeaseProof)> {
        let generation = self
            .snapshot
            .lease(item_id)
            .context("graph-bound queue item has no lease state")?
            .generation()
            .checked_add(1)
            .context("queue lease generation overflowed during claim")?;
        let proof = LeaseProof::new(worker, lease_id, generation)?;
        let lease_event = LeaseEvent::claimed(proof.clone(), observed_at, expires_at)?;
        let data = self.append_event(QueueJournalEvent::LeaseClaimed {
            item_id: item_id.to_string(),
            lease_event,
            graph_event: graph_attempt,
        })?;
        Ok((data, proof))
    }

    pub(crate) fn heartbeat_lease(
        &mut self,
        item_id: &str,
        proof: LeaseProof,
        observed_at: u64,
        expires_at: u64,
    ) -> Result<GeneratedFollowUpQueueEventData> {
        self.append_event(QueueJournalEvent::LeaseHeartbeat {
            item_id: item_id.to_string(),
            lease_event: LeaseEvent::heartbeat(proof, observed_at, expires_at)?,
        })
    }

    pub(crate) fn release_lease_before_dispatch(
        &mut self,
        item_id: &str,
        proof: LeaseProof,
        observed_at: u64,
        graph_completion: DurableGraphEvent,
        gate_denial: Option<GateDenial>,
        environment_failures: Vec<EnvironmentFailure>,
    ) -> Result<GeneratedFollowUpQueueEventData> {
        self.append_event(QueueJournalEvent::LeaseReleasedBeforeDispatch {
            item_id: item_id.to_string(),
            lease_event: LeaseEvent::released(proof, observed_at)?,
            graph_event: graph_completion,
            gate_denial,
            environment_failures,
        })
    }

    /// Reclaim inputs contain only the new identities and trusted monotonic
    /// observation. The predecessor proof/expiry and successor generation are
    /// derived from replayed state, never accepted from the caller.
    pub(crate) fn reclaim_expired_lease(
        &mut self,
        item_id: &str,
        observed_at: u64,
        successor_worker: WorkerIdentity,
        successor_lease_id: LeaseIdentity,
        successor_expires_at: u64,
    ) -> Result<(GeneratedFollowUpQueueEventData, LeaseProof)> {
        let lease = self
            .snapshot
            .lease(item_id)
            .context("graph-bound queue item has no lease state")?;
        let predecessor = lease
            .active_proof()
            .context("queue lease reclaim has no active predecessor")?
            .clone();
        let predecessor_expires_at = lease
            .expires_at()
            .context("queue lease reclaim predecessor has no expiry")?;
        let successor_generation = predecessor
            .generation()
            .checked_add(1)
            .context("queue lease generation overflowed during reclaim")?;
        let successor =
            LeaseProof::new(successor_worker, successor_lease_id, successor_generation)?;
        let lease_event = LeaseEvent::reclaimed(
            predecessor,
            predecessor_expires_at,
            observed_at,
            successor.clone(),
            successor_expires_at,
        )?;
        let data = self.append_event(QueueJournalEvent::LeaseReclaimed {
            item_id: item_id.to_string(),
            lease_event,
        })?;
        Ok((data, successor))
    }

    pub(crate) fn mark_leased_effect_started(
        &mut self,
        item_id: &str,
        proof: LeaseProof,
        observed_at: u64,
    ) -> Result<GeneratedFollowUpQueueEventData> {
        let subordinate_run_id = subordinate_run_id(item_id)?;
        self.append_event(QueueJournalEvent::LeaseEffectStarted {
            item_id: item_id.to_string(),
            subordinate_run_id,
            lease_event: LeaseEvent::effect_started(proof, observed_at)?,
        })
    }

    /// Consumes an authenticated terminal capability and atomically installs
    /// queue acknowledgement, lease acknowledgement, and the bound graph
    /// attempt result in one journal record. Capability construction remains
    /// confined to the supervisor cascade; root queue tests exercise the same
    /// private reducer because those capability fields are intentionally
    /// opaque outside that authentication boundary.
    pub(crate) fn apply_leased_authenticated_terminal(
        &mut self,
        authenticated: AuthenticatedGeneratedFollowUpTerminal,
        proof: LeaseProof,
        observed_at: u64,
        graph_completion: DurableGraphEvent,
    ) -> Result<GeneratedFollowUpQueueEventData> {
        let (queue_instance_id, item_id, observation) = authenticated.into_parts();
        if queue_instance_id != self.snapshot.queue_instance_id {
            bail!("authenticated generated follow-up terminal belongs to a different queue");
        }
        self.append_leased_terminal_observation(
            &item_id,
            observation,
            proof,
            observed_at,
            graph_completion,
        )
    }

    fn append_leased_terminal_observation(
        &mut self,
        item_id: &str,
        observation: GeneratedFollowUpDispatchObservation,
        proof: LeaseProof,
        observed_at: u64,
        graph_completion: DurableGraphEvent,
    ) -> Result<GeneratedFollowUpQueueEventData> {
        let subordinate_run_id = self
            .snapshot
            .item(item_id)
            .and_then(GeneratedFollowUpQueueItemSnapshot::subordinate_run_id)
            .context("generated follow-up item has no durable leased dispatch start")?
            .to_string();
        self.append_event(QueueJournalEvent::LeaseTerminalAcknowledged {
            item_id: item_id.to_string(),
            subordinate_run_id,
            observation,
            lease_event: LeaseEvent::acknowledged(proof, observed_at)?,
            graph_event: graph_completion,
        })
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

    /// Releases every crash-surviving claim that has no durable dispatch
    /// marker. DispatchStarted items are excluded by phase and remain
    /// ambiguous until the caller supplies stronger subordinate-run evidence.
    pub(crate) fn release_claimed_before_dispatch(
        &mut self,
    ) -> Result<Vec<GeneratedFollowUpQueueEventData>> {
        let claimed = self
            .snapshot
            .items
            .values()
            .filter(|item| item.phase == GeneratedFollowUpQueuePhase::Claimed)
            .map(|item| item.item_id().to_string())
            .collect::<Vec<_>>();
        let mut events = Vec::with_capacity(claimed.len());
        for item_id in claimed {
            events.push(self.release_before_dispatch(&item_id, None, Vec::new())?);
        }
        Ok(events)
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

    fn mark_dispatch_observed(
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

    fn acknowledge_terminal(&mut self, item_id: &str) -> Result<GeneratedFollowUpQueueEventData> {
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

    /// Applies the observation and acknowledgement reducers only when the
    /// cascade has authenticated the finalized report and matched its exact
    /// normalized plan to this immutable queued item. The capability is
    /// non-cloneable, consumed here, and bound to both the queue instance and
    /// item so it cannot authorize a sibling transition.
    pub(crate) fn apply_authenticated_terminal(
        &mut self,
        authenticated: AuthenticatedGeneratedFollowUpTerminal,
    ) -> Result<Vec<GeneratedFollowUpQueueEventData>> {
        let (queue_instance_id, item_id, observation) = authenticated.into_parts();
        if queue_instance_id != self.snapshot.queue_instance_id {
            bail!("authenticated generated follow-up terminal belongs to a different queue");
        }
        let phase = self
            .snapshot
            .item(&item_id)
            .context("authenticated generated follow-up item disappeared")?
            .phase();
        let mut events = Vec::with_capacity(2);
        if matches!(
            phase,
            GeneratedFollowUpQueuePhase::DispatchStarted
                | GeneratedFollowUpQueuePhase::HeldAmbiguous
        ) {
            events.push(self.mark_dispatch_observed(&item_id, observation)?);
        } else if phase == GeneratedFollowUpQueuePhase::DispatchObserved {
            let existing = self
                .snapshot
                .item(&item_id)
                .and_then(GeneratedFollowUpQueueItemSnapshot::observation)
                .context("observed generated follow-up has no durable observation")?;
            if existing != &observation {
                bail!("authenticated generated follow-up terminal differs from its durable observation");
            }
        } else {
            bail!(
                "generated follow-up authenticated terminal transition began from a non-observable queue phase"
            );
        }
        events.push(self.acknowledge_terminal(&item_id)?);
        Ok(events)
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
        if self.journal.records().len() >= MAX_AUTHENTICATED_QUEUE_RECORDS {
            bail!("generated follow-up queue exhausted its authenticated record bound");
        }
        let next = apply_queue_event(self.snapshot.clone(), &event)?;
        let event_data = queue_event_data(&self.snapshot, &event);
        self.journal
            .append(event.phase(), event.subject(), &event)?;
        self.snapshot = next;
        Ok(event_data)
    }
}

fn replay_queue_records(
    journal_slot_id: &str,
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
    if queue_journal_slot_id(&source)? != journal_slot_id {
        bail!("generated follow-up queue journal slot is not bound to its source run");
    }
    let instance_id = queue_instance_id(&source)?;
    let mut snapshot = GeneratedFollowUpQueueSnapshot {
        queue_instance_id: instance_id,
        source,
        bounds,
        enqueue_committed: false,
        staged: BTreeMap::new(),
        items: BTreeMap::new(),
        graph: None,
        graph_events: Vec::new(),
        graph_event_count: 0,
        branch_to_item: BTreeMap::new(),
        item_to_branch: BTreeMap::new(),
        leases: BTreeMap::new(),
        lease_identity_items: BTreeMap::new(),
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
                if existing == item.as_ref() {
                    bail!("generated follow-up enqueue transition repeated");
                }
                bail!("generated follow-up item id conflicts with another immutable record");
            }
            if snapshot.staged.len() >= snapshot.bounds.capacity {
                bail!("generated follow-up queue exceeds its validated item capacity");
            }
            snapshot
                .staged
                .insert(item.item_id.clone(), item.as_ref().clone());
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
            require_legacy_mutation_allowed(&snapshot, item_id)?;
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
            require_legacy_mutation_allowed(&snapshot, item_id)?;
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
            require_legacy_mutation_allowed(&snapshot, item_id)?;
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
            require_legacy_mutation_allowed(&snapshot, item_id)?;
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
            require_legacy_mutation_allowed(&snapshot, item_id)?;
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
            require_legacy_mutation_allowed(&snapshot, item_id)?;
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
        QueueJournalEvent::GraphDefinedAndBound {
            graph_event,
            bindings,
        } => {
            if snapshot.graph.is_some()
                || !snapshot.graph_events.is_empty()
                || !snapshot.branch_to_item.is_empty()
                || !snapshot.item_to_branch.is_empty()
                || !snapshot.leases.is_empty()
                || !snapshot.lease_identity_items.is_empty()
            {
                bail!("durable queue graph definition or item binding cannot repeat");
            }
            if !snapshot.enqueue_committed {
                bail!("durable queue graph cannot be defined before enqueue commit");
            }
            validate_clean_graph_migration(&snapshot)?;
            let DurableGraphEvent::Defined { definition } = graph_event else {
                bail!("durable queue graph must begin with its definition event");
            };
            validate_graph_bindings(&snapshot, definition, bindings)?;
            apply_embedded_graph_event(&mut snapshot, graph_event)?;
            for binding in bindings {
                snapshot
                    .branch_to_item
                    .insert(binding.branch_id.clone(), binding.item_id.clone());
                snapshot
                    .item_to_branch
                    .insert(binding.item_id.clone(), binding.branch_id.clone());
                snapshot
                    .leases
                    .insert(binding.item_id.clone(), LeaseState::initial());
            }
        }
        QueueJournalEvent::GraphTransition { graph_event } => {
            if matches!(
                graph_event,
                DurableGraphEvent::Defined { .. }
                    | DurableGraphEvent::BranchAttemptStarted { .. }
                    | DurableGraphEvent::BranchAttemptCompleted { .. }
            ) {
                bail!(
                    "graph definition and worker attempt transitions require their typed composite queue APIs"
                );
            }
            apply_embedded_graph_event(&mut snapshot, graph_event)?;
        }
        QueueJournalEvent::LeaseClaimed {
            item_id,
            lease_event,
            graph_event,
        } => {
            if !matches!(lease_event, LeaseEvent::Claimed(_)) {
                bail!("lease claim queue record contains the wrong lease transition");
            }
            bind_lease_identity(&mut snapshot, item_id, lease_event)?;
            require_phase(
                queue_item(&snapshot, item_id)?,
                GeneratedFollowUpQueuePhase::Enqueued,
                "lease claim",
            )?;
            apply_item_lease_event(&mut snapshot, item_id, lease_event)?;
            require_bound_worker_graph_event(&snapshot, item_id, graph_event, true)?;
            apply_embedded_graph_event(&mut snapshot, graph_event)?;
            let item = queue_item_mut(&mut snapshot, item_id)?;
            item.phase = GeneratedFollowUpQueuePhase::Claimed;
            item.last_gate_denial = None;
            item.last_environment_failures.clear();
            item.external_side_effect_state = None;
        }
        QueueJournalEvent::LeaseHeartbeat {
            item_id,
            lease_event,
        } => {
            if !matches!(lease_event, LeaseEvent::Heartbeat(_)) {
                bail!("lease heartbeat queue record contains the wrong lease transition");
            }
            require_bound_lease_identity(&snapshot, item_id, lease_event)?;
            require_phase(
                queue_item(&snapshot, item_id)?,
                GeneratedFollowUpQueuePhase::Claimed,
                "lease heartbeat",
            )?;
            apply_item_lease_event(&mut snapshot, item_id, lease_event)?;
        }
        QueueJournalEvent::LeaseReleasedBeforeDispatch {
            item_id,
            lease_event,
            graph_event,
            gate_denial,
            environment_failures,
        } => {
            if !matches!(lease_event, LeaseEvent::Released(_)) {
                bail!("lease release queue record contains the wrong lease transition");
            }
            require_bound_lease_identity(&snapshot, item_id, lease_event)?;
            require_phase(
                queue_item(&snapshot, item_id)?,
                GeneratedFollowUpQueuePhase::Claimed,
                "lease release before dispatch",
            )?;
            if !bound_branch_attempt_in_progress(&snapshot, item_id)? {
                bail!("graph attempt completion cannot be released when no attempt is active");
            }
            require_bound_worker_graph_event(&snapshot, item_id, graph_event, false)?;
            apply_embedded_graph_event(&mut snapshot, graph_event)?;
            apply_item_lease_event(&mut snapshot, item_id, lease_event)?;
            let item = queue_item_mut(&mut snapshot, item_id)?;
            if item.subordinate_run_id.is_some() {
                bail!("generated follow-up item with a dispatch marker cannot be released");
            }
            item.phase = GeneratedFollowUpQueuePhase::Enqueued;
            item.last_gate_denial = gate_denial.clone();
            item.last_environment_failures = environment_failures.clone();
            item.external_side_effect_state = None;
        }
        QueueJournalEvent::LeaseReclaimed {
            item_id,
            lease_event,
        } => {
            if !matches!(lease_event, LeaseEvent::Reclaimed(_)) {
                bail!("lease reclaim queue record contains the wrong lease transition");
            }
            bind_lease_identity(&mut snapshot, item_id, lease_event)?;
            require_phase(
                queue_item(&snapshot, item_id)?,
                GeneratedFollowUpQueuePhase::Claimed,
                "lease reclaim",
            )?;
            apply_item_lease_event(&mut snapshot, item_id, lease_event)?;
        }
        QueueJournalEvent::LeaseEffectStarted {
            item_id,
            subordinate_run_id: observed_run_id,
            lease_event,
        } => {
            if !matches!(lease_event, LeaseEvent::EffectStarted(_)) {
                bail!("lease effect-start queue record contains the wrong lease transition");
            }
            require_bound_lease_identity(&snapshot, item_id, lease_event)?;
            require_phase(
                queue_item(&snapshot, item_id)?,
                GeneratedFollowUpQueuePhase::Claimed,
                "leased dispatch start",
            )?;
            if !bound_branch_attempt_in_progress(&snapshot, item_id)? {
                bail!("leased effect start requires the bound graph attempt to be in progress");
            }
            let expected_run_id = subordinate_run_id(item_id)?;
            if observed_run_id != &expected_run_id {
                bail!("leased dispatch marker has a non-deterministic run id");
            }
            apply_item_lease_event(&mut snapshot, item_id, lease_event)?;
            let item = queue_item_mut(&mut snapshot, item_id)?;
            item.phase = GeneratedFollowUpQueuePhase::DispatchStarted;
            item.subordinate_run_id = Some(expected_run_id);
            item.external_side_effect_state = Some(ExternalSideEffectState::Ambiguous);
        }
        QueueJournalEvent::LeaseTerminalAcknowledged {
            item_id,
            subordinate_run_id: observed_run_id,
            observation,
            lease_event,
            graph_event,
        } => {
            if !matches!(lease_event, LeaseEvent::Acknowledged(_)) {
                bail!("lease terminal queue record contains the wrong lease transition");
            }
            if matches!(
                graph_event,
                DurableGraphEvent::BranchAttemptCompleted {
                    outcome: graph::BranchOutcome::RetryableFailure { .. },
                    ..
                }
            ) {
                bail!(
                    "effect-fenced terminal acknowledgement cannot schedule a retry; use the pre-effect release composite"
                );
            }
            require_bound_lease_identity(&snapshot, item_id, lease_event)?;
            let item = queue_item(&snapshot, item_id)?;
            if !matches!(
                item.phase,
                GeneratedFollowUpQueuePhase::DispatchStarted
                    | GeneratedFollowUpQueuePhase::HeldAmbiguous
            ) {
                bail!("leased terminal acknowledgement skips or repeats a queue transition");
            }
            let expected_run_id = item
                .subordinate_run_id
                .as_deref()
                .context("leased terminal acknowledgement has no dispatch marker")?
                .to_string();
            require_bound_worker_graph_event(&snapshot, item_id, graph_event, false)?;
            apply_item_lease_event(&mut snapshot, item_id, lease_event)?;
            apply_embedded_graph_event(&mut snapshot, graph_event)?;
            if observed_run_id != &expected_run_id {
                bail!("leased terminal acknowledgement names a different subordinate run");
            }
            observation.validate(Some(&expected_run_id))?;
            let item = queue_item_mut(&mut snapshot, item_id)?;
            item.phase = GeneratedFollowUpQueuePhase::AcknowledgedTerminal;
            item.observation = Some(observation.clone());
            item.last_gate_denial = observation.gate_denial.clone();
            item.last_environment_failures = observation.environment_failures.clone();
            item.external_side_effect_state = observation.external_side_effect_state;
        }
    }
    Ok(snapshot)
}

fn require_legacy_mutation_allowed(
    snapshot: &GeneratedFollowUpQueueSnapshot,
    item_id: &str,
) -> Result<()> {
    if snapshot.leases.contains_key(item_id) {
        bail!(
            "identityless queue mutation cannot operate on a graph/lease-enforced item; use the typed lease API"
        );
    }
    Ok(())
}

fn queue_item<'a>(
    snapshot: &'a GeneratedFollowUpQueueSnapshot,
    item_id: &str,
) -> Result<&'a GeneratedFollowUpQueueItemSnapshot> {
    if !snapshot.enqueue_committed {
        bail!("generated follow-up batch is not completely enqueued");
    }
    snapshot
        .items
        .get(item_id)
        .context("generated follow-up queue item is unknown")
}

fn validate_clean_graph_migration(snapshot: &GeneratedFollowUpQueueSnapshot) -> Result<()> {
    for item in snapshot.items.values() {
        if item.phase != GeneratedFollowUpQueuePhase::Enqueued
            || item.subordinate_run_id.is_some()
            || item.observation.is_some()
            || item.external_side_effect_state.is_some()
        {
            bail!(
                "durable graph/lease mode requires every legacy queue item to be cleanly enqueued without dispatch or effect evidence"
            );
        }
    }
    Ok(())
}

fn validate_graph_bindings(
    snapshot: &GeneratedFollowUpQueueSnapshot,
    definition: &DurableGraphDefinition,
    bindings: &[DurableGraphQueueItemBinding],
) -> Result<()> {
    if bindings.is_empty() || bindings.len() != snapshot.items.len() {
        bail!("durable graph bindings must cover every committed queue item exactly once");
    }
    if !bindings.windows(2).all(|pair| pair[0] < pair[1]) {
        bail!("durable graph bindings are not canonical, sorted, and unique");
    }
    let task_branches = definition
        .nodes()
        .iter()
        .filter_map(|node| match node.kind() {
            DurableGraphNodeKind::Task { branch_id, .. } => Some(branch_id.clone()),
            DurableGraphNodeKind::Fork
            | DurableGraphNodeKind::Choice
            | DurableGraphNodeKind::Join { .. }
            | DurableGraphNodeKind::Loop { .. }
            | DurableGraphNodeKind::Terminate { .. } => None,
        })
        .collect::<BTreeSet<_>>();
    let bound_branches = bindings
        .iter()
        .map(|binding| binding.branch_id.clone())
        .collect::<BTreeSet<_>>();
    let bound_items = bindings
        .iter()
        .map(|binding| binding.item_id.clone())
        .collect::<BTreeSet<_>>();
    if task_branches.len() != bindings.len()
        || bound_branches.len() != bindings.len()
        || bound_items.len() != bindings.len()
        || bound_branches != task_branches
        || bound_items != snapshot.items.keys().cloned().collect()
    {
        bail!("durable graph bindings do not exactly match graph task branches and queue items");
    }
    Ok(())
}

fn apply_embedded_graph_event(
    snapshot: &mut GeneratedFollowUpQueueSnapshot,
    graph_event: &DurableGraphEvent,
) -> Result<()> {
    if snapshot.graph_event_count >= MAX_AUTHENTICATED_QUEUE_RECORDS {
        bail!("durable graph exhausted the queue's authenticated record bound");
    }
    let mut events = snapshot.graph_events.clone();
    events.push(graph_event.clone());
    let next = replay_graph_events(&events)?;
    snapshot.graph = Some(next);
    snapshot.graph_events = events;
    snapshot.graph_event_count = snapshot.graph_events.len();
    Ok(())
}

fn apply_item_lease_event(
    snapshot: &mut GeneratedFollowUpQueueSnapshot,
    item_id: &str,
    lease_event: &LeaseEvent,
) -> Result<()> {
    queue_item(snapshot, item_id)?;
    let lease = snapshot
        .leases
        .get_mut(item_id)
        .context("queue item is not graph/lease-enforced")?;
    lease.apply(lease_event)
}

fn bind_lease_identity(
    snapshot: &mut GeneratedFollowUpQueueSnapshot,
    item_id: &str,
    lease_event: &LeaseEvent,
) -> Result<()> {
    queue_item(snapshot, item_id)?;
    let lease_id = lease_event.resulting_proof().lease_id().as_str();
    if let Some(existing_item_id) = snapshot.lease_identity_items.get(lease_id) {
        if existing_item_id != item_id {
            bail!("lease identity is already durably bound to a different queue item");
        }
        return Ok(());
    }
    snapshot
        .lease_identity_items
        .insert(lease_id.to_string(), item_id.to_string());
    Ok(())
}

fn require_bound_lease_identity(
    snapshot: &GeneratedFollowUpQueueSnapshot,
    item_id: &str,
    lease_event: &LeaseEvent,
) -> Result<()> {
    let lease_id = lease_event.resulting_proof().lease_id().as_str();
    if snapshot
        .lease_identity_items
        .get(lease_id)
        .map(String::as_str)
        != Some(item_id)
    {
        bail!("lease proof identity is not durably bound to this queue item");
    }
    Ok(())
}

fn require_bound_worker_graph_event(
    snapshot: &GeneratedFollowUpQueueSnapshot,
    item_id: &str,
    graph_event: &DurableGraphEvent,
    starting: bool,
) -> Result<()> {
    let event_branch = match (starting, graph_event) {
        (true, DurableGraphEvent::BranchAttemptStarted { branch_id, .. })
        | (false, DurableGraphEvent::BranchAttemptCompleted { branch_id, .. }) => branch_id,
        (true, _) => bail!("leased queue claim requires a graph branch-attempt start event"),
        (false, _) => {
            bail!(
                "leased terminal acknowledgement requires a graph branch-attempt completion event"
            )
        }
    };
    let expected_branch = snapshot
        .item_to_branch
        .get(item_id)
        .context("queue item has no immutable graph branch binding")?;
    if event_branch != expected_branch
        || snapshot
            .branch_to_item
            .get(event_branch)
            .map(String::as_str)
            != Some(item_id)
    {
        bail!("worker graph event does not match the queue item's immutable branch binding");
    }
    Ok(())
}

fn bound_branch_attempt_in_progress(
    snapshot: &GeneratedFollowUpQueueSnapshot,
    item_id: &str,
) -> Result<bool> {
    let branch_id = snapshot
        .item_to_branch
        .get(item_id)
        .context("queue item has no immutable graph branch binding")?;
    let graph = snapshot
        .graph
        .as_ref()
        .context("queue item binding has no replay-derived graph state")?;
    Ok(graph
        .branch(branch_id)
        .context("queue item binding names an unknown graph branch")?
        .attempt_in_progress()
        .is_some())
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
    let queue_instance_id = queue_instance_id(source)?;
    domain_separated_sha256(
        ITEM_ID_DOMAIN,
        &[queue_instance_id.as_bytes(), canonical_task.as_slice()],
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
        || task.cascade_depth != LICENSED_BREAKAGE_CASCADE_DEPTH
        || task.dispatch_status != GeneratedFollowUpDispatchStatus::DeferredForPlannedRun
        || task.breaking_assignment_id != task.breaking_change.agent_id
        || task.handoff.trim().is_empty()
        || assignment.licensed_breakage.is_some()
    {
        bail!("generated follow-up task provenance or cascade binding is invalid");
    }

    let loaded = validate_generated_follow_up_plan_document(plan)?;
    if loaded != ordinary_plan_from_generated(plan) {
        bail!("ordinary supervisor plan loader changed the generated follow-up task");
    }
    Ok(())
}

fn ordinary_plan_from_generated(
    plan: &crate::supervise::GeneratedFollowUpSupervisorPlan,
) -> SupervisorPlan {
    plan.ordinary_plan()
}

fn queue_instance_id(source: &GeneratedFollowUpQueueSource) -> Result<String> {
    source.validate()?;
    let digest = domain_separated_sha256(
        QUEUE_ID_DOMAIN,
        &[
            source.source_supervisor_run_id.as_bytes(),
            source.source_normalized_plan_sha256.as_bytes(),
            b"accepted",
            b"publishable",
            source.outer_entrypoint.as_str().as_bytes(),
            source.outer_command_run_id.as_bytes(),
            source.repository_id.as_bytes(),
            source.whole_primary_baseline_sha256.as_bytes(),
            source.machine_global_retention.binding_sha256.as_bytes(),
            source.machine_global_retention.root_id.as_bytes(),
            &[source.cascade_depth],
        ],
    )?;
    Ok(format!("follow-up-{digest}"))
}

fn queue_journal_slot_id(source: &GeneratedFollowUpQueueSource) -> Result<String> {
    source.validate()?;
    queue_journal_slot_id_for_source_execution(
        source.source_supervisor_run_id(),
        source.source_normalized_plan_sha256(),
        source.repository_id(),
    )
}

fn queue_journal_slot_id_for_source_execution(
    source_supervisor_run_id: &str,
    source_normalized_plan_sha256: &str,
    repository_id: &str,
) -> Result<String> {
    validate_source_run_id(source_supervisor_run_id)?;
    validate_sha256_id(
        source_normalized_plan_sha256,
        "source normalized supervisor plan digest",
    )?;
    validate_sha256_id(repository_id, "repository authentication identity")?;
    let digest = domain_separated_sha256(
        QUEUE_SLOT_ID_DOMAIN,
        &[
            source_supervisor_run_id.as_bytes(),
            source_normalized_plan_sha256.as_bytes(),
            repository_id.as_bytes(),
        ],
    )?;
    Ok(format!("follow-up-{digest}"))
}

fn verify_source_repository_binding(
    authenticator: &RepositoryAuthenticator,
    source: &GeneratedFollowUpQueueSource,
) -> Result<()> {
    authenticator.verify_epoch()?;
    if authenticator.binding().repository_id != source.repository_id {
        bail!("generated follow-up source repository identity does not match the authenticator");
    }
    Ok(())
}

fn subordinate_run_id(item_id: &str) -> Result<String> {
    validate_sha256_id(item_id, "generated follow-up item id")?;
    Ok(format!("follow-up-{item_id}"))
}

fn batch_sha256(item_ids: &[String]) -> Result<String> {
    if item_ids.is_empty() || item_ids.len() > MAX_STORED_QUEUE_ITEMS {
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

fn validate_bounded_text(value: &str, label: &str, max_bytes: usize) -> Result<()> {
    if value.is_empty()
        || value.trim() != value
        || value.len() > max_bytes
        || value.chars().any(char::is_control)
    {
        bail!("{label} is not bounded canonical text");
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
            QueueJournalEvent::GraphDefinedAndBound { .. }
            | QueueJournalEvent::GraphTransition { .. } => {
                (Vec::new(), None, None, Vec::new(), None)
            }
            QueueJournalEvent::LeaseClaimed { item_id, .. }
            | QueueJournalEvent::LeaseHeartbeat { item_id, .. }
            | QueueJournalEvent::LeaseReclaimed { item_id, .. } => {
                (vec![item_id.clone()], None, None, Vec::new(), None)
            }
            QueueJournalEvent::LeaseReleasedBeforeDispatch {
                item_id,
                gate_denial,
                environment_failures,
                ..
            } => (
                vec![item_id.clone()],
                None,
                gate_denial.clone(),
                environment_failures.clone(),
                None,
            ),
            QueueJournalEvent::LeaseEffectStarted {
                item_id,
                subordinate_run_id,
                ..
            } => (
                vec![item_id.clone()],
                Some(subordinate_run_id.clone()),
                None,
                Vec::new(),
                Some(ExternalSideEffectState::Ambiguous),
            ),
            QueueJournalEvent::LeaseTerminalAcknowledged {
                item_id,
                subordinate_run_id,
                observation,
                ..
            } => (
                vec![item_id.clone()],
                Some(subordinate_run_id.clone()),
                observation.gate_denial.clone(),
                observation.environment_failures.clone(),
                observation.external_side_effect_state,
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
            GeneratedFollowUpPlanContext, GeneratedFollowUpSupervisorPlan,
            LicensedBreakageDeclaration, LicensedBreakageDependentScope, OrchestratorAssignment,
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

    fn retained_machine_global() -> GeneratedFollowUpRetentionBinding {
        let config_file_identity = FileIdentity {
            device: 11,
            file: 22,
        };
        let config_content_sha256 = "4".repeat(64);
        let root_id = "runtime-root".to_string();
        let owner = "supervise-run".to_string();
        let correction_correlation_id = "correction-01".to_string();
        let binding_sha256 = domain_separated_sha256(
            b"MACO\0generated-follow-up-retention-binding\0v1\0",
            &[
                config_content_sha256.as_bytes(),
                root_id.as_bytes(),
                owner.as_bytes(),
                correction_correlation_id.as_bytes(),
                &config_file_identity.device.to_be_bytes(),
                &config_file_identity.file.to_be_bytes(),
            ],
        )
        .expect("retention digest");
        GeneratedFollowUpRetentionBinding {
            config_content_sha256,
            config_file_identity,
            root_id,
            owner,
            correction_correlation_id,
            binding_sha256,
        }
    }

    fn source(repo: &Path, run_id: &str) -> GeneratedFollowUpQueueSource {
        let repository_id = authenticator(repo).binding().repository_id.clone();
        GeneratedFollowUpQueueSource::root(GeneratedFollowUpQueueRootInput {
            source_supervisor_run_id: run_id.to_string(),
            source_normalized_plan_sha256: "1".repeat(64),
            source_report_accepted: true,
            source_report_publishable: true,
            outer_entrypoint: GeneratedFollowUpQueueEntrypoint::SuperviseRun,
            outer_command_run_id: format!("outer-{run_id}"),
            repository_id,
            whole_primary_baseline_sha256: "3".repeat(64),
            machine_global_retention: retained_machine_global(),
        })
        .expect("valid queue source")
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
            cascade_depth: LICENSED_BREAKAGE_CASCADE_DEPTH,
            dispatch_status: GeneratedFollowUpDispatchStatus::DeferredForPlannedRun,
            handoff: handoff.clone(),
            operator_defaults,
        };
        let assignments = vec![OrchestratorAssignment {
            id: assignment_id.clone(),
            phase: AssignmentPhase::Execution,
            runtime: None,
            role: AgentRole::ChildOrchestrator,
            role_category: None,
            selection_source: None,
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
            cascade_depth: LICENSED_BREAKAGE_CASCADE_DEPTH,
            dispatch_status: GeneratedFollowUpDispatchStatus::DeferredForPlannedRun,
            handoff,
        }
    }

    fn licensed_source_plan(dependent_count: usize) -> SupervisorPlan {
        let template = generated_task("01").supervisor_plan;
        let dependents = (1..=dependent_count)
            .map(|ordinal| LicensedBreakageDependentScope {
                dependent_id: format!("dependent-{ordinal:02}"),
                paths: vec![std::path::PathBuf::from(format!("src/{ordinal:02}.rs"))],
                interfaces: Vec::new(),
            })
            .collect();
        SupervisorPlan {
            version: template.version,
            task: "licensed breaking source".to_string(),
            task_file: None,
            max_depth: template.max_depth,
            max_child_assignments: 1,
            max_child_retries: template.max_child_retries,
            max_gate_corrections: template.max_gate_corrections,
            child_timeout_seconds: template.child_timeout_seconds,
            semantic_coordination: template.semantic_coordination,
            role_models: template.role_models,
            model_pricing: template.model_pricing,
            review_lenses: template.review_lenses,
            review_aggregation_policy: template.review_aggregation_policy,
            assignments: vec![OrchestratorAssignment {
                id: "child-a".to_string(),
                phase: AssignmentPhase::Execution,
                runtime: None,
                role: AgentRole::ChildOrchestrator,
                role_category: None,
                selection_source: None,
                assigned_paths: vec![std::path::PathBuf::from("src/breaking.rs")],
                semantic_symbols: Vec::new(),
                semantic_modules: Vec::new(),
                task: Some("make licensed breaking change".to_string()),
                worker_assignments: Vec::new(),
                environment_requirements: Vec::new(),
                licensed_breakage: Some(LicensedBreakageDeclaration {
                    migration_rationale: "migrate declared dependents".to_string(),
                    dependents,
                }),
                notes: None,
            }],
        }
    }

    #[test]
    fn legal_lifecycle_exposes_queue_state_before_during_and_after_dispatch() {
        let (_temp, repo) = repository();
        let source = source(&repo, "source-legal");
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
        let source = source(&repo, "source-idempotent");
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
    fn source_plan_bounds_bind_each_generated_task_to_one_declared_dependent() {
        let plan = licensed_source_plan(2);
        let first = generated_task("01");
        let second = generated_task("02");
        let bounds = GeneratedFollowUpQueueBounds::from_validated_source_plan_and_tasks(
            &plan,
            &[first.clone(), second],
        )
        .expect("derive exact bounds");
        assert_eq!(bounds.declared_dependents(), 2);
        assert_eq!(bounds.validated_dependents(), 2);

        let mut duplicate = first;
        duplicate.failure_signature = "different failure signature".to_string();
        duplicate
            .supervisor_plan
            .generated_follow_up
            .failure_signature = duplicate.failure_signature.clone();
        let error = GeneratedFollowUpQueueBounds::from_validated_source_plan_and_tasks(
            &plan,
            &[generated_task("01"), duplicate],
        )
        .expect_err("one dependent cannot be represented twice");
        assert!(format!("{error:#}").contains("represents one declared dependent twice"));
    }

    #[test]
    fn altered_generated_budget_and_metadata_refuse_before_enqueue_record() {
        let (_temp, repo) = repository();
        let source = source(&repo, "source-noncanonical");
        let mut queue = GeneratedFollowUpQueue::create(authenticator(&repo), source, bounds(1))
            .expect("create queue");
        let mut altered_budget = generated_task("01");
        altered_budget.supervisor_plan.run_budget.limits.soft_tokens = Some(3);
        altered_budget.supervisor_plan.run_budget.limits.hard_tokens = Some(3);
        assert!(queue
            .enqueue_all_before_dispatch(&[altered_budget])
            .is_err());

        let mut altered_metadata = generated_task("01");
        altered_metadata
            .supervisor_plan
            .generated_follow_up
            .operator_defaults
            .reverse();
        assert!(queue
            .enqueue_all_before_dispatch(&[altered_metadata])
            .is_err());
        assert_eq!(queue.journal.records().len(), 1);
    }

    #[test]
    fn create_or_open_recovers_empty_reservation_and_initializes_once() {
        let (_temp, repo) = repository();
        let source = source(&repo, "source-create-gap");
        let slot = queue_journal_slot_id(&source).expect("queue slot");
        let empty = QueueJournal::open_or_initialize(authenticator(&repo), &slot)
            .expect("reserve empty deterministic journal");
        assert!(empty.records().is_empty());
        drop(empty);

        let queue =
            GeneratedFollowUpQueue::create_or_open(authenticator(&repo), source.clone(), bounds(1))
                .expect("recover and initialize queue");
        assert_eq!(queue.journal.records().len(), 1);
        drop(queue);
        let reopened =
            GeneratedFollowUpQueue::create_or_open(authenticator(&repo), source, bounds(1))
                .expect("open existing initialized queue");
        assert_eq!(reopened.journal.records().len(), 1);
    }

    #[test]
    fn source_execution_lookup_observes_only_an_existing_authenticated_queue() {
        let (_temp, repo) = repository();
        let source = source(&repo, "source-observation");
        let source_run_id = source.source_supervisor_run_id().to_string();
        let source_plan_sha256 = source.source_normalized_plan_sha256().to_string();

        assert!(GeneratedFollowUpQueue::open_existing_for_source_execution(
            authenticator(&repo),
            &source_run_id,
            &source_plan_sha256,
        )
        .expect("observe absent queue without creating it")
        .is_none());

        let created =
            GeneratedFollowUpQueue::create_or_open(authenticator(&repo), source, bounds(1))
                .expect("create authenticated queue");
        let expected_instance_id = created.snapshot().queue_instance_id().to_string();
        drop(created);

        let observed = GeneratedFollowUpQueue::open_existing_for_source_execution(
            authenticator(&repo),
            &source_run_id,
            &source_plan_sha256,
        )
        .expect("observe authenticated queue")
        .expect("existing queue");
        assert_eq!(
            observed.snapshot().queue_instance_id(),
            expected_instance_id
        );
    }

    #[test]
    fn create_or_open_reuses_original_queue_across_outer_entrypoints() {
        let (_temp, repo) = repository();
        let mut autopilot_source = source(&repo, "source-cross-entrypoint");
        autopilot_source.outer_entrypoint = GeneratedFollowUpQueueEntrypoint::AutopilotRun;
        autopilot_source.outer_command_run_id = "autopilot-outer-run".to_string();
        let mut created = GeneratedFollowUpQueue::create_or_open(
            authenticator(&repo),
            autopilot_source.clone(),
            bounds(1),
        )
        .expect("create Autopilot-origin queue");
        created
            .enqueue_all_before_dispatch(&[generated_task("01")])
            .expect("enqueue one Autopilot-origin task");
        let original_queue_id = created.snapshot().queue_instance_id().to_string();
        let original_item_id = created.snapshot().pending_item_ids()[0].to_string();
        drop(created);

        let mut direct_source = autopilot_source.clone();
        direct_source.outer_entrypoint = GeneratedFollowUpQueueEntrypoint::SuperviseRun;
        direct_source.outer_command_run_id = direct_source.source_supervisor_run_id.clone();
        let reopened =
            GeneratedFollowUpQueue::create_or_open(authenticator(&repo), direct_source, bounds(1))
                .expect("resume Autopilot-origin queue through supervise run");

        assert_eq!(reopened.snapshot().queue_instance_id(), original_queue_id);
        assert_eq!(
            reopened.snapshot().pending_item_ids(),
            vec![original_item_id.as_str()]
        );
        assert_eq!(
            reopened.snapshot().source().outer_entrypoint(),
            GeneratedFollowUpQueueEntrypoint::AutopilotRun
        );
        assert_eq!(
            reopened.snapshot().source().outer_command_run_id(),
            "autopilot-outer-run"
        );
    }

    #[test]
    fn cross_entrypoint_reopen_refuses_primary_or_retention_basis_drift() {
        let (_temp, repo) = repository();
        let mut autopilot_source = source(&repo, "source-cross-entrypoint-drift");
        autopilot_source.outer_entrypoint = GeneratedFollowUpQueueEntrypoint::AutopilotRun;
        autopilot_source.outer_command_run_id = "autopilot-outer-drift".to_string();
        let created = GeneratedFollowUpQueue::create_or_open(
            authenticator(&repo),
            autopilot_source.clone(),
            bounds(1),
        )
        .expect("create queue before cross-entrypoint drift");
        drop(created);

        let mut primary_drift = autopilot_source.clone();
        primary_drift.outer_entrypoint = GeneratedFollowUpQueueEntrypoint::SuperviseRun;
        primary_drift.outer_command_run_id = primary_drift.source_supervisor_run_id.clone();
        primary_drift.whole_primary_baseline_sha256 = "5".repeat(64);
        let primary_error =
            GeneratedFollowUpQueue::create_or_open(authenticator(&repo), primary_drift, bounds(1))
                .err()
                .expect("whole-primary drift must not fork or reopen the queue");
        assert!(format!("{primary_error:#}").contains("execution basis changed"));

        let mut retention_drift = autopilot_source;
        retention_drift.outer_entrypoint = GeneratedFollowUpQueueEntrypoint::SuperviseRun;
        retention_drift.outer_command_run_id = retention_drift.source_supervisor_run_id.clone();
        retention_drift.machine_global_retention.owner = "different-owner".to_string();
        retention_drift.machine_global_retention.binding_sha256 = domain_separated_sha256(
            b"MACO\0generated-follow-up-retention-binding\0v1\0",
            &[
                retention_drift
                    .machine_global_retention
                    .config_content_sha256
                    .as_bytes(),
                retention_drift.machine_global_retention.root_id.as_bytes(),
                retention_drift.machine_global_retention.owner.as_bytes(),
                retention_drift
                    .machine_global_retention
                    .correction_correlation_id
                    .as_bytes(),
                &retention_drift
                    .machine_global_retention
                    .config_file_identity
                    .device
                    .to_be_bytes(),
                &retention_drift
                    .machine_global_retention
                    .config_file_identity
                    .file
                    .to_be_bytes(),
            ],
        )
        .expect("recompute alternate valid retention binding");
        let retention_error = GeneratedFollowUpQueue::create_or_open(
            authenticator(&repo),
            retention_drift,
            bounds(1),
        )
        .err()
        .expect("retention drift must not fork or reopen the queue");
        assert!(format!("{retention_error:#}").contains("execution basis changed"));
    }

    #[test]
    fn incomplete_staging_and_claimed_items_have_explicit_recovery() {
        let (_temp, repo) = repository();
        let source = source(&repo, "source-recovery");
        let tasks = vec![generated_task("01"), generated_task("02")];
        let mut queue =
            GeneratedFollowUpQueue::create(authenticator(&repo), source.clone(), bounds(2))
                .expect("create queue");
        let prepared = prepare_enqueue_records(&source, &tasks).expect("prepare batch");
        let first = prepared.values().next().expect("first staged item").clone();
        queue
            .append_event(QueueJournalEvent::EnqueueStaged {
                item: Box::new(first),
            })
            .expect("stage one item");
        drop(queue);

        let mut reopened = GeneratedFollowUpQueue::open(authenticator(&repo), &source)
            .expect("reopen staged queue");
        assert_eq!(reopened.snapshot().staged_count(), 1);
        reopened
            .complete_staged_batch(&tasks)
            .expect("complete exact staged batch");
        let first_id = reopened.snapshot().pending_item_ids()[0].to_string();
        reopened.claim(&first_id).expect("claim item");
        drop(reopened);

        let mut recovered = GeneratedFollowUpQueue::open(authenticator(&repo), &source)
            .expect("reopen claimed queue");
        assert_eq!(
            recovered
                .release_claimed_before_dispatch()
                .expect("release")
                .len(),
            1
        );
        assert_eq!(
            recovered.snapshot().item(&first_id).expect("item").phase(),
            GeneratedFollowUpQueuePhase::Enqueued
        );
        recovered.claim(&first_id).expect("reclaim released item");
    }

    #[test]
    fn conflicting_duplicate_item_id_is_refused_during_replay() {
        let (_temp, repo) = repository();
        let source = source(&repo, "source-conflict");
        let mut queue =
            GeneratedFollowUpQueue::create(authenticator(&repo), source.clone(), bounds(1))
                .expect("create queue");
        let first_task = generated_task("01");
        let item_id = generated_follow_up_item_id(&source, &first_task).expect("item id");
        let first = QueueJournalEvent::EnqueueStaged {
            item: Box::new(ImmutableEnqueueRecord {
                item_id: item_id.clone(),
                task: first_task,
            }),
        };
        queue
            .journal
            .append(first.phase(), first.subject(), &first)
            .expect("append first staged record");
        let conflicting = QueueJournalEvent::EnqueueStaged {
            item: Box::new(ImmutableEnqueueRecord {
                item_id,
                task: generated_task("02"),
            }),
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
        let skip_source = source(&repo, "source-transition-skip");
        let mut queue =
            GeneratedFollowUpQueue::create(authenticator(&repo), skip_source, bounds(1))
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
        let repeat_source = source(&repo, "source-transition-repeat");
        let mut queue =
            GeneratedFollowUpQueue::create(authenticator(&repo), repeat_source, bounds(1))
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
        let generated_source =
            GeneratedFollowUpQueueSource::generated(source(&repo, "source-second"), 1)
                .expect_err("second generation must be refused");
        assert!(format!("{generated_source:#}").contains("second-generation"));

        let source = source(&repo, "source-cascade");
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
            &[MAX_STORED_QUEUE_ITEMS + 1],
            &[MAX_STORED_QUEUE_ITEMS + 1],
        )
        .is_err());

        let (_temp, repo) = repository();
        let source = source(&repo, "source-capacity");
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
        let source = source(&repo, "source-reopen");
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
        let source = source(&repo, "source-tamper");
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
        let source = source(&repo, "source-claimed-replay");
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
        let source = source(&repo, "source-started-replay");
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

    fn graph_id(value: &str) -> graph::DurableGraphId {
        graph::DurableGraphId::new(value).expect("graph id")
    }

    fn node_id(value: &str) -> graph::GraphNodeId {
        graph::GraphNodeId::new(value).expect("node id")
    }

    fn edge_id(value: &str) -> graph::GraphEdgeId {
        graph::GraphEdgeId::new(value).expect("edge id")
    }

    fn branch_id(value: &str) -> GraphBranchId {
        GraphBranchId::new(value).expect("branch id")
    }

    fn durable_text(value: &str) -> graph::DurableText {
        graph::DurableText::new(value).expect("durable text")
    }

    fn graph_node(value: &str, kind: graph::DurableGraphNodeKind) -> graph::DurableGraphNode {
        graph::DurableGraphNode::new(node_id(value), kind)
    }

    fn graph_edge(
        value: &str,
        from: &str,
        to: &str,
        kind: graph::DurableGraphEdgeKind,
        condition: graph::DurableEdgeCondition,
    ) -> graph::DurableGraphEdge {
        graph::DurableGraphEdge::new(edge_id(value), node_id(from), node_id(to), kind, condition)
    }

    fn graph_success(result_ref: &str, write_refs: &[&str]) -> graph::BranchOutcome {
        graph::BranchOutcome::Success {
            success: graph::BranchSuccess::new(
                durable_text(result_ref),
                write_refs.iter().map(|value| durable_text(value)).collect(),
            )
            .expect("branch success"),
        }
    }

    fn graph_retryable(error: &str) -> graph::BranchOutcome {
        graph::BranchOutcome::RetryableFailure {
            error: durable_text(error),
        }
    }

    fn graph_failure(error: &str) -> graph::BranchOutcome {
        graph::BranchOutcome::Failure {
            error: durable_text(error),
        }
    }

    fn conditional_graph_definition() -> DurableGraphDefinition {
        let branch = branch_id("branch-main");
        DurableGraphDefinition::new(
            graph_id("queue-conditional"),
            node_id("n00-task"),
            vec![
                graph_node(
                    "n00-task",
                    DurableGraphNodeKind::Task {
                        branch_id: branch.clone(),
                        max_attempts: 3,
                    },
                ),
                graph_node(
                    "n10-success",
                    DurableGraphNodeKind::Terminate {
                        outcome: graph::GraphTermination::Success,
                    },
                ),
                graph_node(
                    "n20-failure",
                    DurableGraphNodeKind::Terminate {
                        outcome: graph::GraphTermination::Failure,
                    },
                ),
            ],
            vec![
                graph_edge(
                    "e00-success",
                    "n00-task",
                    "n10-success",
                    graph::DurableGraphEdgeKind::Forward,
                    graph::DurableEdgeCondition::BranchLatestOutcome {
                        branch_id: branch.clone(),
                        outcome: graph::BranchOutcomeClass::Success,
                    },
                ),
                graph_edge(
                    "e10-failure",
                    "n00-task",
                    "n20-failure",
                    graph::DurableGraphEdgeKind::Forward,
                    graph::DurableEdgeCondition::BranchLatestOutcome {
                        branch_id: branch,
                        outcome: graph::BranchOutcomeClass::Failure,
                    },
                ),
            ],
        )
        .expect("conditional graph")
    }

    fn fan_in_graph_definition(graph_name: &str) -> DurableGraphDefinition {
        let branch_a = branch_id("branch-a");
        let branch_b = branch_id("branch-b");
        let join = node_id("n30-join");
        DurableGraphDefinition::new(
            graph_id(graph_name),
            node_id("n00-fork"),
            vec![
                graph_node("n00-fork", DurableGraphNodeKind::Fork),
                graph_node(
                    "n10-a",
                    DurableGraphNodeKind::Task {
                        branch_id: branch_a.clone(),
                        max_attempts: 3,
                    },
                ),
                graph_node(
                    "n20-b",
                    DurableGraphNodeKind::Task {
                        branch_id: branch_b.clone(),
                        max_attempts: 3,
                    },
                ),
                graph_node(
                    "n30-join",
                    DurableGraphNodeKind::Join {
                        branches: vec![branch_a.clone(), branch_b.clone()],
                    },
                ),
                graph_node(
                    "n40-all",
                    DurableGraphNodeKind::Terminate {
                        outcome: graph::GraphTermination::Success,
                    },
                ),
                graph_node(
                    "n50-partial",
                    DurableGraphNodeKind::Terminate {
                        outcome: graph::GraphTermination::PartialSuccess,
                    },
                ),
                graph_node(
                    "n60-failure",
                    DurableGraphNodeKind::Terminate {
                        outcome: graph::GraphTermination::Failure,
                    },
                ),
            ],
            vec![
                graph_edge(
                    "e00-a",
                    "n00-fork",
                    "n10-a",
                    graph::DurableGraphEdgeKind::Forward,
                    graph::DurableEdgeCondition::Always,
                ),
                graph_edge(
                    "e01-b",
                    "n00-fork",
                    "n20-b",
                    graph::DurableGraphEdgeKind::Forward,
                    graph::DurableEdgeCondition::Always,
                ),
                graph_edge(
                    "e10-join",
                    "n10-a",
                    "n30-join",
                    graph::DurableGraphEdgeKind::JoinArrival {
                        branch_id: branch_a,
                    },
                    graph::DurableEdgeCondition::Always,
                ),
                graph_edge(
                    "e20-join",
                    "n20-b",
                    "n30-join",
                    graph::DurableGraphEdgeKind::JoinArrival {
                        branch_id: branch_b,
                    },
                    graph::DurableEdgeCondition::Always,
                ),
                graph_edge(
                    "e30-all",
                    "n30-join",
                    "n40-all",
                    graph::DurableGraphEdgeKind::Forward,
                    graph::DurableEdgeCondition::JoinResult {
                        join_node_id: join.clone(),
                        result: graph::FanInResult::AllSuccess,
                    },
                ),
                graph_edge(
                    "e31-partial",
                    "n30-join",
                    "n50-partial",
                    graph::DurableGraphEdgeKind::Forward,
                    graph::DurableEdgeCondition::JoinResult {
                        join_node_id: join.clone(),
                        result: graph::FanInResult::PartialSuccess,
                    },
                ),
                graph_edge(
                    "e32-failure",
                    "n30-join",
                    "n60-failure",
                    graph::DurableGraphEdgeKind::Forward,
                    graph::DurableEdgeCondition::JoinResult {
                        join_node_id: join,
                        result: graph::FanInResult::Failure,
                    },
                ),
            ],
        )
        .expect("fan-in graph")
    }

    fn loop_graph_definition() -> DurableGraphDefinition {
        let loop_node = node_id("n00-loop");
        DurableGraphDefinition::new(
            graph_id("queue-loop"),
            loop_node.clone(),
            vec![
                graph_node("n00-loop", DurableGraphNodeKind::Loop { max_iterations: 3 }),
                graph_node(
                    "n10-task",
                    DurableGraphNodeKind::Task {
                        branch_id: branch_id("branch-loop"),
                        max_attempts: 2,
                    },
                ),
                graph_node(
                    "n20-exit",
                    DurableGraphNodeKind::Terminate {
                        outcome: graph::GraphTermination::Success,
                    },
                ),
            ],
            vec![
                graph_edge(
                    "e00-body",
                    "n00-loop",
                    "n10-task",
                    graph::DurableGraphEdgeKind::LoopBody {
                        loop_node_id: loop_node.clone(),
                    },
                    graph::DurableEdgeCondition::LoopDecision {
                        loop_node_id: loop_node.clone(),
                        decision: graph::LoopDecision::Continue,
                    },
                ),
                graph_edge(
                    "e10-back",
                    "n10-task",
                    "n00-loop",
                    graph::DurableGraphEdgeKind::LoopBack {
                        loop_node_id: loop_node.clone(),
                    },
                    graph::DurableEdgeCondition::Always,
                ),
                graph_edge(
                    "e20-exit",
                    "n00-loop",
                    "n20-exit",
                    graph::DurableGraphEdgeKind::Forward,
                    graph::DurableEdgeCondition::LoopDecision {
                        loop_node_id: loop_node,
                        decision: graph::LoopDecision::Exit,
                    },
                ),
            ],
        )
        .expect("loop graph")
    }

    fn reopen_typed_queue(
        repo: &Path,
        source: &GeneratedFollowUpQueueSource,
        queue: GeneratedFollowUpQueue,
    ) -> GeneratedFollowUpQueue {
        drop(queue);
        GeneratedFollowUpQueue::open(authenticator(repo), source).expect("reopen typed queue")
    }

    fn worker(value: &str) -> WorkerIdentity {
        WorkerIdentity::new(value).expect("worker identity")
    }

    fn lease_id(value: &str) -> LeaseIdentity {
        LeaseIdentity::new(value).expect("lease identity")
    }

    #[test]
    fn leased_graph_lifecycle_replays_reclaim_lineage_and_effect_fence() {
        let (_temp, repo) = repository();
        let source = source(&repo, "source-leased-lifecycle");
        let task = generated_task("01");
        let item_id = generated_follow_up_item_id(&source, &task).expect("item id");
        let mut queue =
            GeneratedFollowUpQueue::create(authenticator(&repo), source.clone(), bounds(1))
                .expect("create queue");
        queue
            .enqueue_all_before_dispatch(&[task])
            .expect("enqueue task");
        queue
            .define_graph(
                conditional_graph_definition(),
                vec![
                    DurableGraphQueueItemBinding::new(branch_id("branch-main"), item_id.clone())
                        .expect("binding"),
                ],
            )
            .expect("define and bind graph");
        queue = reopen_typed_queue(&repo, &source, queue);
        assert_eq!(queue.snapshot().graph_event_count(), 1);
        assert_eq!(
            queue.snapshot().branch_item_id(&branch_id("branch-main")),
            Some(item_id.as_str())
        );
        assert_eq!(
            queue.snapshot().lease_phase(&item_id),
            Some(LeasePhase::Available)
        );

        let before = queue.snapshot().clone();
        let records = queue.journal.records().len();
        assert!(queue.claim(&item_id).is_err());
        assert_eq!(queue.snapshot(), &before);
        assert_eq!(queue.journal.records().len(), records);

        let (_, predecessor) = queue
            .claim_with_lease(
                &item_id,
                worker("worker-a"),
                lease_id("lease-a"),
                1,
                5,
                DurableGraphEvent::BranchAttemptStarted {
                    branch_id: branch_id("branch-main"),
                    visit: 1,
                    attempt: 1,
                },
            )
            .expect("claim lease and start attempt");
        queue = reopen_typed_queue(&repo, &source, queue);
        assert_eq!(
            queue.snapshot().lease_phase(&item_id),
            Some(LeasePhase::Active)
        );
        assert_eq!(
            queue.snapshot().item(&item_id).expect("item").phase(),
            GeneratedFollowUpQueuePhase::Claimed
        );

        queue
            .heartbeat_lease(&item_id, predecessor.clone(), 2, 6)
            .expect("heartbeat");
        queue = reopen_typed_queue(&repo, &source, queue);
        assert_eq!(
            queue
                .snapshot()
                .lease(&item_id)
                .and_then(LeaseState::expires_at),
            Some(6)
        );

        let (_, successor) = queue
            .reclaim_expired_lease(&item_id, 6, worker("worker-b"), lease_id("lease-b"), 12)
            .expect("reclaim expired predecessor");
        queue = reopen_typed_queue(&repo, &source, queue);
        let lineage = queue
            .snapshot()
            .lease(&item_id)
            .and_then(LeaseState::last_reclaim)
            .expect("reclaim lineage");
        assert_eq!(lineage.predecessor(), &predecessor);
        assert_eq!(lineage.successor(), &successor);
        assert_eq!(lineage.predecessor_expires_at(), 6);
        assert_eq!(lineage.reclaimed_at(), 6);

        let before = queue.snapshot().clone();
        let records = queue.journal.records().len();
        assert!(queue
            .heartbeat_lease(&item_id, predecessor.clone(), 7, 12)
            .is_err());
        assert_eq!(queue.snapshot(), &before);
        assert_eq!(queue.journal.records().len(), records);

        queue
            .mark_leased_effect_started(&item_id, successor.clone(), 7)
            .expect("durable effect fence");
        queue = reopen_typed_queue(&repo, &source, queue);
        assert_eq!(
            queue.snapshot().lease_phase(&item_id),
            Some(LeasePhase::EffectFenced)
        );
        assert_eq!(
            queue.snapshot().item(&item_id).expect("item").phase(),
            GeneratedFollowUpQueuePhase::DispatchStarted
        );

        for rejected in ["heartbeat", "release", "reclaim", "second-effect"] {
            let before = queue.snapshot().clone();
            let records = queue.journal.records().len();
            let result = match rejected {
                "heartbeat" => queue
                    .heartbeat_lease(&item_id, successor.clone(), 8, 13)
                    .map(|_| ()),
                "release" => queue
                    .release_lease_before_dispatch(
                        &item_id,
                        successor.clone(),
                        8,
                        DurableGraphEvent::BranchAttemptCompleted {
                            branch_id: branch_id("branch-main"),
                            visit: 1,
                            attempt: 1,
                            outcome: graph_failure("must-not-release"),
                        },
                        None,
                        Vec::new(),
                    )
                    .map(|_| ()),
                "reclaim" => queue
                    .reclaim_expired_lease(
                        &item_id,
                        12,
                        worker("worker-c"),
                        lease_id("lease-c"),
                        20,
                    )
                    .map(|_| ()),
                "second-effect" => queue
                    .mark_leased_effect_started(&item_id, successor.clone(), 8)
                    .map(|_| ()),
                _ => unreachable!(),
            };
            assert!(result.is_err(), "{rejected} crossed the effect fence");
            assert_eq!(queue.snapshot(), &before);
            assert_eq!(queue.journal.records().len(), records);
        }

        let run_id = queue
            .snapshot()
            .item(&item_id)
            .and_then(GeneratedFollowUpQueueItemSnapshot::subordinate_run_id)
            .expect("subordinate run")
            .to_string();
        queue
            .append_leased_terminal_observation(
                &item_id,
                GeneratedFollowUpDispatchObservation::new(
                    run_id,
                    None,
                    Vec::new(),
                    Some(ExternalSideEffectState::Completed),
                )
                .expect("observation"),
                successor.clone(),
                8,
                DurableGraphEvent::BranchAttemptCompleted {
                    branch_id: branch_id("branch-main"),
                    visit: 1,
                    attempt: 1,
                    outcome: graph_success("result-main", &["write-main"]),
                },
            )
            .expect("atomic terminal acknowledgement");
        queue = reopen_typed_queue(&repo, &source, queue);
        assert_eq!(
            queue.snapshot().lease_phase(&item_id),
            Some(LeasePhase::Acknowledged)
        );
        assert_eq!(
            queue.snapshot().item(&item_id).expect("item").phase(),
            GeneratedFollowUpQueuePhase::AcknowledgedTerminal
        );

        let before = queue.snapshot().clone();
        let records = queue.journal.records().len();
        assert!(queue
            .mark_leased_effect_started(&item_id, successor, 9)
            .is_err());
        assert_eq!(queue.snapshot(), &before);
        assert_eq!(queue.journal.records().len(), records);

        queue
            .apply_graph_transition(DurableGraphEvent::EdgesSelected {
                source_node_id: node_id("n00-task"),
                visit: 1,
                edge_ids: vec![edge_id("e00-success")],
            })
            .expect("conditional success route");
        queue = reopen_typed_queue(&repo, &source, queue);
        assert!(queue
            .snapshot()
            .graph()
            .expect("graph")
            .reached(&node_id("n10-success")));
        queue
            .apply_graph_transition(DurableGraphEvent::Terminated {
                node_id: node_id("n10-success"),
                outcome: graph::GraphTermination::Success,
            })
            .expect("explicit termination");
        queue = reopen_typed_queue(&repo, &source, queue);
        assert_eq!(
            queue
                .snapshot()
                .graph()
                .and_then(|graph| graph.termination()),
            Some(graph::GraphTermination::Success)
        );
    }

    #[test]
    fn effect_fenced_terminal_retry_is_rejected_without_consuming_the_attempt() {
        let (_temp, repo) = repository();
        let source = source(&repo, "source-terminal-retry-fence");
        let task = generated_task("01");
        let item_id = generated_follow_up_item_id(&source, &task).expect("item id");
        let mut queue =
            GeneratedFollowUpQueue::create(authenticator(&repo), source.clone(), bounds(1))
                .expect("create queue");
        queue.enqueue_all_before_dispatch(&[task]).expect("enqueue");
        queue
            .define_graph(
                conditional_graph_definition(),
                vec![
                    DurableGraphQueueItemBinding::new(branch_id("branch-main"), item_id.clone())
                        .expect("binding"),
                ],
            )
            .expect("define graph");
        let (_, proof) = queue
            .claim_with_lease(
                &item_id,
                worker("worker-terminal"),
                lease_id("lease-terminal"),
                1,
                10,
                DurableGraphEvent::BranchAttemptStarted {
                    branch_id: branch_id("branch-main"),
                    visit: 1,
                    attempt: 1,
                },
            )
            .expect("claim attempt");
        queue
            .mark_leased_effect_started(&item_id, proof.clone(), 2)
            .expect("effect fence");
        let run_id = queue
            .snapshot()
            .item(&item_id)
            .and_then(GeneratedFollowUpQueueItemSnapshot::subordinate_run_id)
            .expect("subordinate run")
            .to_string();

        let before = queue.snapshot().clone();
        let records = queue.journal.records().len();
        assert!(queue
            .append_leased_terminal_observation(
                &item_id,
                GeneratedFollowUpDispatchObservation::new(
                    run_id.clone(),
                    None,
                    Vec::new(),
                    Some(ExternalSideEffectState::Completed),
                )
                .expect("retryable observation"),
                proof.clone(),
                3,
                DurableGraphEvent::BranchAttemptCompleted {
                    branch_id: branch_id("branch-main"),
                    visit: 1,
                    attempt: 1,
                    outcome: graph_retryable("cannot retry after the effect fence"),
                },
            )
            .is_err());
        assert_eq!(queue.snapshot(), &before);
        assert_eq!(queue.journal.records().len(), records);

        queue = reopen_typed_queue(&repo, &source, queue);
        assert_eq!(queue.journal.records().len(), records);
        assert_eq!(
            queue.snapshot().item(&item_id).expect("item").phase(),
            GeneratedFollowUpQueuePhase::DispatchStarted
        );
        assert_eq!(
            queue.snapshot().lease_phase(&item_id),
            Some(LeasePhase::EffectFenced)
        );
        assert_eq!(
            queue
                .snapshot()
                .graph()
                .and_then(|state| state.branch(&branch_id("branch-main")))
                .and_then(graph::BranchRuntimeState::attempt_in_progress),
            Some(1)
        );

        queue
            .append_leased_terminal_observation(
                &item_id,
                GeneratedFollowUpDispatchObservation::new(
                    run_id,
                    None,
                    Vec::new(),
                    Some(ExternalSideEffectState::Completed),
                )
                .expect("terminal failure observation"),
                proof,
                3,
                DurableGraphEvent::BranchAttemptCompleted {
                    branch_id: branch_id("branch-main"),
                    visit: 1,
                    attempt: 1,
                    outcome: graph_failure("terminal failure after effect"),
                },
            )
            .expect("terminal failure acknowledgement");
        queue = reopen_typed_queue(&repo, &source, queue);
        assert_eq!(
            queue.snapshot().item(&item_id).expect("item").phase(),
            GeneratedFollowUpQueuePhase::AcknowledgedTerminal
        );
        assert_eq!(
            queue.snapshot().lease_phase(&item_id),
            Some(LeasePhase::Acknowledged)
        );
        assert_eq!(
            queue
                .snapshot()
                .graph()
                .and_then(|state| state.branch(&branch_id("branch-main")))
                .and_then(|branch| branch.attempts().last())
                .map(|attempt| attempt.outcome().class()),
            Some(graph::BranchOutcomeClass::Failure)
        );
        queue
            .apply_graph_transition(DurableGraphEvent::EdgesSelected {
                source_node_id: node_id("n00-task"),
                visit: 1,
                edge_ids: vec![edge_id("e10-failure")],
            })
            .expect("route terminal failure");
        queue
            .apply_graph_transition(DurableGraphEvent::Terminated {
                node_id: node_id("n20-failure"),
                outcome: graph::GraphTermination::Failure,
            })
            .expect("terminate failed graph");
        queue = reopen_typed_queue(&repo, &source, queue);
        assert_eq!(
            queue
                .snapshot()
                .graph()
                .and_then(DurableGraphRuntimeState::termination),
            Some(graph::GraphTermination::Failure)
        );
        assert!(queue.snapshot().pending_item_ids().is_empty());
    }

    #[test]
    fn composite_rejections_leave_snapshot_and_journal_unchanged() {
        let (_temp, repo) = repository();
        let source = source(&repo, "source-composite-atomic");
        let task = generated_task("01");
        let item_id = generated_follow_up_item_id(&source, &task).expect("item id");
        let mut queue =
            GeneratedFollowUpQueue::create(authenticator(&repo), source.clone(), bounds(1))
                .expect("create queue");
        queue.enqueue_all_before_dispatch(&[task]).expect("enqueue");
        queue
            .define_graph(
                conditional_graph_definition(),
                vec![
                    DurableGraphQueueItemBinding::new(branch_id("branch-main"), item_id.clone())
                        .expect("binding"),
                ],
            )
            .expect("define graph");

        let before = queue.snapshot().clone();
        let records = queue.journal.records().len();
        assert!(queue
            .claim_with_lease(
                &item_id,
                worker("worker-a"),
                lease_id("lease-a"),
                1,
                10,
                DurableGraphEvent::BranchAttemptStarted {
                    branch_id: branch_id("wrong-branch"),
                    visit: 1,
                    attempt: 1,
                },
            )
            .is_err());
        assert_eq!(queue.snapshot(), &before);
        assert_eq!(queue.journal.records().len(), records);

        let (_, proof) = queue
            .claim_with_lease(
                &item_id,
                worker("worker-a"),
                lease_id("lease-a"),
                1,
                10,
                DurableGraphEvent::BranchAttemptStarted {
                    branch_id: branch_id("branch-main"),
                    visit: 1,
                    attempt: 1,
                },
            )
            .expect("valid claim");

        let before = queue.snapshot().clone();
        let records = queue.journal.records().len();
        let wrong_proof =
            LeaseProof::new(worker("worker-x"), lease_id("lease-x"), 1).expect("wrong proof");
        assert!(queue.heartbeat_lease(&item_id, wrong_proof, 2, 10).is_err());
        assert_eq!(queue.snapshot(), &before);
        assert_eq!(queue.journal.records().len(), records);

        queue
            .mark_leased_effect_started(&item_id, proof.clone(), 2)
            .expect("effect fence");
        let before = queue.snapshot().clone();
        let records = queue.journal.records().len();
        assert!(queue
            .append_leased_terminal_observation(
                &item_id,
                GeneratedFollowUpDispatchObservation::new(
                    "wrong-subordinate-run",
                    None,
                    Vec::new(),
                    Some(ExternalSideEffectState::Completed),
                )
                .expect("well-formed wrong observation"),
                proof,
                3,
                DurableGraphEvent::BranchAttemptCompleted {
                    branch_id: branch_id("branch-main"),
                    visit: 1,
                    attempt: 1,
                    outcome: graph_success("would-be-result", &[]),
                },
            )
            .is_err());
        assert_eq!(queue.snapshot(), &before);
        assert_eq!(queue.journal.records().len(), records);

        let before = queue.snapshot().clone();
        let records = queue.journal.records().len();
        assert!(queue
            .apply_graph_transition(DurableGraphEvent::EdgesSelected {
                source_node_id: node_id("n00-task"),
                visit: 1,
                edge_ids: vec![edge_id("e00-success")],
            })
            .is_err());
        assert_eq!(queue.snapshot(), &before);
        assert_eq!(queue.journal.records().len(), records);
    }

    #[test]
    fn authenticated_fan_in_covers_all_outcomes_and_reuses_successful_sibling() {
        let cases = [
            (
                "all",
                graph_success("result-a", &["write-a"]),
                graph_success("result-b", &["write-b"]),
                graph::FanInResult::AllSuccess,
                "e30-all",
                "n40-all",
                graph::GraphTermination::Success,
            ),
            (
                "partial",
                graph_success("result-a", &["write-a-1", "write-a-2"]),
                graph_failure("terminal-b"),
                graph::FanInResult::PartialSuccess,
                "e31-partial",
                "n50-partial",
                graph::GraphTermination::PartialSuccess,
            ),
            (
                "failure",
                graph_failure("terminal-a"),
                graph_failure("terminal-b"),
                graph::FanInResult::Failure,
                "e32-failure",
                "n60-failure",
                graph::GraphTermination::Failure,
            ),
        ];

        for (suffix, outcome_a, outcome_b, fan_in, join_edge, terminal_node, termination) in cases {
            let (_temp, repo) = repository();
            let source = source(&repo, &format!("source-fan-{suffix}"));
            let task_a = generated_task("01");
            let task_b = generated_task("02");
            let item_a = generated_follow_up_item_id(&source, &task_a).expect("item a");
            let item_b = generated_follow_up_item_id(&source, &task_b).expect("item b");
            let mut queue =
                GeneratedFollowUpQueue::create(authenticator(&repo), source.clone(), bounds(2))
                    .expect("create fan queue");
            queue
                .enqueue_all_before_dispatch(&[task_a, task_b])
                .expect("enqueue fan tasks");
            queue
                .define_graph(
                    fan_in_graph_definition(&format!("queue-fan-{suffix}")),
                    vec![
                        DurableGraphQueueItemBinding::new(branch_id("branch-a"), item_a.clone())
                            .expect("bind a"),
                        DurableGraphQueueItemBinding::new(branch_id("branch-b"), item_b.clone())
                            .expect("bind b"),
                    ],
                )
                .expect("define fan graph");
            queue
                .apply_graph_transition(DurableGraphEvent::EdgesSelected {
                    source_node_id: node_id("n00-fork"),
                    visit: 1,
                    edge_ids: vec![edge_id("e00-a"), edge_id("e01-b")],
                })
                .expect("fork");
            queue = reopen_typed_queue(&repo, &source, queue);

            let (_, proof_a) = queue
                .claim_with_lease(
                    &item_a,
                    worker("worker-a"),
                    lease_id("lease-a1"),
                    1,
                    10,
                    DurableGraphEvent::BranchAttemptStarted {
                        branch_id: branch_id("branch-a"),
                        visit: 1,
                        attempt: 1,
                    },
                )
                .expect("claim a");
            queue
                .release_lease_before_dispatch(
                    &item_a,
                    proof_a,
                    2,
                    DurableGraphEvent::BranchAttemptCompleted {
                        branch_id: branch_id("branch-a"),
                        visit: 1,
                        attempt: 1,
                        outcome: outcome_a,
                    },
                    None,
                    Vec::new(),
                )
                .expect("complete a without effect");
            queue = reopen_typed_queue(&repo, &source, queue);
            assert_eq!(
                queue.snapshot().lease_phase(&item_a),
                Some(LeasePhase::Available)
            );
            assert!(!queue
                .snapshot()
                .pending_item_ids()
                .contains(&item_a.as_str()));
            queue
                .apply_graph_transition(DurableGraphEvent::EdgesSelected {
                    source_node_id: node_id("n10-a"),
                    visit: 1,
                    edge_ids: vec![edge_id("e10-join")],
                })
                .expect("route a to join");
            queue = reopen_typed_queue(&repo, &source, queue);

            if suffix == "partial" {
                let preserved = queue
                    .snapshot()
                    .graph()
                    .and_then(|state| state.branch(&branch_id("branch-a")))
                    .and_then(graph::BranchRuntimeState::successful_outcome)
                    .cloned()
                    .expect("preserved a success");
                let (_, first_b) = queue
                    .claim_with_lease(
                        &item_b,
                        worker("worker-b1"),
                        lease_id("lease-b1"),
                        1,
                        10,
                        DurableGraphEvent::BranchAttemptStarted {
                            branch_id: branch_id("branch-b"),
                            visit: 1,
                            attempt: 1,
                        },
                    )
                    .expect("claim first b attempt");
                queue
                    .release_lease_before_dispatch(
                        &item_b,
                        first_b,
                        2,
                        DurableGraphEvent::BranchAttemptCompleted {
                            branch_id: branch_id("branch-b"),
                            visit: 1,
                            attempt: 1,
                            outcome: graph_retryable("transient-b"),
                        },
                        None,
                        Vec::new(),
                    )
                    .expect("release retryable b");
                queue = reopen_typed_queue(&repo, &source, queue);
                assert!(!queue
                    .snapshot()
                    .pending_item_ids()
                    .contains(&item_b.as_str()));
                queue
                    .apply_graph_transition(DurableGraphEvent::BranchRetryScheduled {
                        branch_id: branch_id("branch-b"),
                        visit: 1,
                        next_attempt: 2,
                    })
                    .expect("schedule b retry");
                queue = reopen_typed_queue(&repo, &source, queue);
                assert_eq!(queue.snapshot().pending_item_ids(), vec![item_b.as_str()]);
                assert_eq!(
                    queue
                        .snapshot()
                        .graph()
                        .and_then(|state| state.branch(&branch_id("branch-a")))
                        .and_then(graph::BranchRuntimeState::successful_outcome),
                    Some(&preserved)
                );
                assert_eq!(preserved.result_ref().as_str(), "result-a");
                assert_eq!(
                    preserved
                        .write_refs()
                        .iter()
                        .map(graph::DurableText::as_str)
                        .collect::<Vec<_>>(),
                    vec!["write-a-1", "write-a-2"]
                );
                let (_, second_b) = queue
                    .claim_with_lease(
                        &item_b,
                        worker("worker-b2"),
                        lease_id("lease-b2"),
                        3,
                        10,
                        DurableGraphEvent::BranchAttemptStarted {
                            branch_id: branch_id("branch-b"),
                            visit: 1,
                            attempt: 2,
                        },
                    )
                    .expect("claim second b attempt");
                assert!(queue.snapshot().pending_item_ids().is_empty());
                queue
                    .release_lease_before_dispatch(
                        &item_b,
                        second_b,
                        4,
                        DurableGraphEvent::BranchAttemptCompleted {
                            branch_id: branch_id("branch-b"),
                            visit: 1,
                            attempt: 2,
                            outcome: outcome_b,
                        },
                        None,
                        Vec::new(),
                    )
                    .expect("complete second b attempt");
                queue = reopen_typed_queue(&repo, &source, queue);
                assert!(queue.snapshot().pending_item_ids().is_empty());
            } else {
                let (_, proof_b) = queue
                    .claim_with_lease(
                        &item_b,
                        worker("worker-b"),
                        lease_id("lease-b1"),
                        1,
                        10,
                        DurableGraphEvent::BranchAttemptStarted {
                            branch_id: branch_id("branch-b"),
                            visit: 1,
                            attempt: 1,
                        },
                    )
                    .expect("claim b");
                queue
                    .release_lease_before_dispatch(
                        &item_b,
                        proof_b,
                        2,
                        DurableGraphEvent::BranchAttemptCompleted {
                            branch_id: branch_id("branch-b"),
                            visit: 1,
                            attempt: 1,
                            outcome: outcome_b,
                        },
                        None,
                        Vec::new(),
                    )
                    .expect("complete b without effect");
                queue = reopen_typed_queue(&repo, &source, queue);
                assert!(queue.snapshot().pending_item_ids().is_empty());
            }
            queue
                .apply_graph_transition(DurableGraphEvent::EdgesSelected {
                    source_node_id: node_id("n20-b"),
                    visit: 1,
                    edge_ids: vec![edge_id("e20-join")],
                })
                .expect("route b to join");
            queue
                .apply_graph_transition(DurableGraphEvent::JoinResolved {
                    join_node_id: node_id("n30-join"),
                    result: fan_in,
                })
                .expect("resolve fan-in");
            queue = reopen_typed_queue(&repo, &source, queue);
            assert_eq!(
                queue
                    .snapshot()
                    .graph()
                    .and_then(|state| state.join_result(&node_id("n30-join"))),
                Some(fan_in)
            );
            let graph = queue.snapshot().graph().expect("graph");
            assert_eq!(
                graph
                    .branch(&branch_id("branch-a"))
                    .and_then(|branch| branch.attempts().last())
                    .map(|attempt| attempt.outcome().class()),
                Some(match fan_in {
                    graph::FanInResult::AllSuccess | graph::FanInResult::PartialSuccess => {
                        graph::BranchOutcomeClass::Success
                    }
                    graph::FanInResult::Failure => graph::BranchOutcomeClass::Failure,
                })
            );
            assert_eq!(
                graph
                    .branch(&branch_id("branch-b"))
                    .and_then(|branch| branch.attempts().last())
                    .map(|attempt| attempt.outcome().class()),
                Some(match fan_in {
                    graph::FanInResult::AllSuccess => graph::BranchOutcomeClass::Success,
                    graph::FanInResult::PartialSuccess | graph::FanInResult::Failure => {
                        graph::BranchOutcomeClass::Failure
                    }
                })
            );
            queue
                .apply_graph_transition(DurableGraphEvent::EdgesSelected {
                    source_node_id: node_id("n30-join"),
                    visit: 1,
                    edge_ids: vec![edge_id(join_edge)],
                })
                .expect("route fan-in result");
            queue
                .apply_graph_transition(DurableGraphEvent::Terminated {
                    node_id: node_id(terminal_node),
                    outcome: termination,
                })
                .expect("terminate fan graph");
            queue = reopen_typed_queue(&repo, &source, queue);
            assert_eq!(
                queue
                    .snapshot()
                    .graph()
                    .and_then(|state| state.termination()),
                Some(termination)
            );
            assert!(queue.snapshot().pending_item_ids().is_empty());
        }
    }

    #[test]
    fn bounded_loop_transitions_and_attempt_leases_survive_each_reopen() {
        let (_temp, repo) = repository();
        let source = source(&repo, "source-loop-replay");
        let task = generated_task("01");
        let item_id = generated_follow_up_item_id(&source, &task).expect("item id");
        let mut queue =
            GeneratedFollowUpQueue::create(authenticator(&repo), source.clone(), bounds(1))
                .expect("create loop queue");
        queue
            .enqueue_all_before_dispatch(&[task])
            .expect("enqueue loop task");
        queue
            .define_graph(
                loop_graph_definition(),
                vec![
                    DurableGraphQueueItemBinding::new(branch_id("branch-loop"), item_id.clone())
                        .expect("loop binding"),
                ],
            )
            .expect("define loop graph");

        for iteration in [1_u16, 2] {
            queue
                .apply_graph_transition(DurableGraphEvent::LoopIterationCompleted {
                    loop_node_id: node_id("n00-loop"),
                    iteration,
                    decision: graph::LoopDecision::Continue,
                })
                .expect("continue loop");
            queue
                .apply_graph_transition(DurableGraphEvent::EdgesSelected {
                    source_node_id: node_id("n00-loop"),
                    visit: iteration,
                    edge_ids: vec![edge_id("e00-body")],
                })
                .expect("enter loop body");
            queue = reopen_typed_queue(&repo, &source, queue);
            assert_eq!(queue.snapshot().pending_item_ids(), vec![item_id.as_str()]);
            let (_, proof) = queue
                .claim_with_lease(
                    &item_id,
                    worker(&format!("worker-loop-{iteration}")),
                    lease_id(&format!("lease-loop-{iteration}")),
                    u64::from(iteration) * 10,
                    u64::from(iteration) * 10 + 8,
                    DurableGraphEvent::BranchAttemptStarted {
                        branch_id: branch_id("branch-loop"),
                        visit: iteration,
                        attempt: 1,
                    },
                )
                .expect("claim loop attempt");
            assert!(queue.snapshot().pending_item_ids().is_empty());
            queue
                .release_lease_before_dispatch(
                    &item_id,
                    proof,
                    u64::from(iteration) * 10 + 1,
                    DurableGraphEvent::BranchAttemptCompleted {
                        branch_id: branch_id("branch-loop"),
                        visit: iteration,
                        attempt: 1,
                        outcome: graph_success(&format!("loop-result-{iteration}"), &[]),
                    },
                    None,
                    Vec::new(),
                )
                .expect("complete loop attempt");
            queue = reopen_typed_queue(&repo, &source, queue);
            assert!(queue.snapshot().pending_item_ids().is_empty());
            queue
                .apply_graph_transition(DurableGraphEvent::EdgesSelected {
                    source_node_id: node_id("n10-task"),
                    visit: iteration,
                    edge_ids: vec![edge_id("e10-back")],
                })
                .expect("loop back");
            queue = reopen_typed_queue(&repo, &source, queue);
            assert!(queue.snapshot().pending_item_ids().is_empty());
        }

        let before = queue.snapshot().clone();
        let records = queue.journal.records().len();
        assert!(queue
            .apply_graph_transition(DurableGraphEvent::LoopIterationCompleted {
                loop_node_id: node_id("n00-loop"),
                iteration: 3,
                decision: graph::LoopDecision::Continue,
            })
            .is_err());
        assert_eq!(queue.snapshot(), &before);
        assert_eq!(queue.journal.records().len(), records);

        queue
            .apply_graph_transition(DurableGraphEvent::LoopIterationCompleted {
                loop_node_id: node_id("n00-loop"),
                iteration: 3,
                decision: graph::LoopDecision::Exit,
            })
            .expect("exit loop");
        queue
            .apply_graph_transition(DurableGraphEvent::EdgesSelected {
                source_node_id: node_id("n00-loop"),
                visit: 3,
                edge_ids: vec![edge_id("e20-exit")],
            })
            .expect("route loop exit");
        queue
            .apply_graph_transition(DurableGraphEvent::Terminated {
                node_id: node_id("n20-exit"),
                outcome: graph::GraphTermination::Success,
            })
            .expect("terminate loop graph");
        queue = reopen_typed_queue(&repo, &source, queue);
        let graph = queue.snapshot().graph().expect("loop graph");
        assert_eq!(graph.loop_iterations(&node_id("n00-loop")), Some(3));
        assert_eq!(graph.termination(), Some(graph::GraphTermination::Success));
        assert!(queue.snapshot().pending_item_ids().is_empty());
        assert_eq!(
            graph
                .branch(&branch_id("branch-loop"))
                .expect("loop branch")
                .attempts()
                .iter()
                .map(|attempt| (attempt.visit(), attempt.attempt()))
                .collect::<Vec<_>>(),
            vec![(1, 1), (2, 1)]
        );
    }

    #[test]
    fn graph_migration_rejects_legacy_progress_and_accepts_clean_release() {
        for legacy_state in [
            "claimed",
            "dispatch_started",
            "dispatch_observed",
            "acknowledged_terminal",
            "held_ambiguous",
        ] {
            let (_temp, repo) = repository();
            let source = source(&repo, &format!("source-migration-{legacy_state}"));
            let task = generated_task("01");
            let item_id = generated_follow_up_item_id(&source, &task).expect("item id");
            let mut queue =
                GeneratedFollowUpQueue::create(authenticator(&repo), source.clone(), bounds(1))
                    .expect("create migration queue");
            queue.enqueue_all_before_dispatch(&[task]).expect("enqueue");
            queue.claim(&item_id).expect("legacy claim");
            if legacy_state != "claimed" {
                let started = queue
                    .mark_dispatch_started(&item_id)
                    .expect("legacy dispatch start");
                if legacy_state == "held_ambiguous" {
                    queue
                        .mark_held_ambiguous(&item_id, None, Vec::new())
                        .expect("legacy ambiguous hold");
                } else if matches!(legacy_state, "dispatch_observed" | "acknowledged_terminal") {
                    queue
                        .mark_dispatch_observed(
                            &item_id,
                            GeneratedFollowUpDispatchObservation::new(
                                started
                                    .subordinate_run_id
                                    .expect("legacy subordinate run id"),
                                None,
                                Vec::new(),
                                Some(ExternalSideEffectState::Completed),
                            )
                            .expect("legacy observation"),
                        )
                        .expect("legacy dispatch observation");
                    if legacy_state == "acknowledged_terminal" {
                        queue
                            .acknowledge_terminal(&item_id)
                            .expect("legacy terminal acknowledgement");
                    }
                }
            }

            let before = queue.snapshot().clone();
            let records = queue.journal.records().len();
            assert!(queue
                .define_graph(
                    conditional_graph_definition(),
                    vec![DurableGraphQueueItemBinding::new(
                        branch_id("branch-main"),
                        item_id.clone(),
                    )
                    .expect("migration binding")],
                )
                .is_err());
            assert_eq!(queue.snapshot(), &before);
            assert_eq!(queue.journal.records().len(), records);

            queue = reopen_typed_queue(&repo, &source, queue);
            let before = queue.snapshot().clone();
            let records = queue.journal.records().len();
            assert!(queue
                .define_graph(
                    conditional_graph_definition(),
                    vec![
                        DurableGraphQueueItemBinding::new(branch_id("branch-main"), item_id,)
                            .expect("reopened migration binding")
                    ],
                )
                .is_err());
            assert_eq!(queue.snapshot(), &before);
            assert_eq!(queue.journal.records().len(), records);
        }

        let (_temp, repo) = repository();
        let source = source(&repo, "source-migration-clean-release");
        let task = generated_task("01");
        let item_id = generated_follow_up_item_id(&source, &task).expect("item id");
        let mut queue =
            GeneratedFollowUpQueue::create(authenticator(&repo), source.clone(), bounds(1))
                .expect("create clean migration queue");
        queue.enqueue_all_before_dispatch(&[task]).expect("enqueue");
        queue.claim(&item_id).expect("legacy claim");
        queue
            .release_before_dispatch(&item_id, None, Vec::new())
            .expect("clean legacy release");
        queue
            .define_graph(
                conditional_graph_definition(),
                vec![
                    DurableGraphQueueItemBinding::new(branch_id("branch-main"), item_id)
                        .expect("clean migration binding"),
                ],
            )
            .expect("clean release migrates");
        queue = reopen_typed_queue(&repo, &source, queue);
        assert!(queue.snapshot().graph().is_some());
    }

    #[test]
    fn lease_identity_capabilities_are_item_bound_across_reopen() {
        let (_temp, repo) = repository();
        let source = source(&repo, "source-cross-item-lease");
        let task_a = generated_task("01");
        let task_b = generated_task("02");
        let item_a = generated_follow_up_item_id(&source, &task_a).expect("item a");
        let item_b = generated_follow_up_item_id(&source, &task_b).expect("item b");
        let mut queue =
            GeneratedFollowUpQueue::create(authenticator(&repo), source.clone(), bounds(2))
                .expect("create cross-item queue");
        queue
            .enqueue_all_before_dispatch(&[task_a, task_b])
            .expect("enqueue cross-item tasks");
        queue
            .define_graph(
                fan_in_graph_definition("queue-cross-item"),
                vec![
                    DurableGraphQueueItemBinding::new(branch_id("branch-a"), item_a.clone())
                        .expect("bind a"),
                    DurableGraphQueueItemBinding::new(branch_id("branch-b"), item_b.clone())
                        .expect("bind b"),
                ],
            )
            .expect("define cross-item graph");
        queue
            .apply_graph_transition(DurableGraphEvent::EdgesSelected {
                source_node_id: node_id("n00-fork"),
                visit: 1,
                edge_ids: vec![edge_id("e00-a"), edge_id("e01-b")],
            })
            .expect("activate both tasks");

        let shared_worker = worker("worker-shared");
        let shared_lease = lease_id("lease-shared");
        let (_, proof_a) = queue
            .claim_with_lease(
                &item_a,
                shared_worker.clone(),
                shared_lease.clone(),
                1,
                10,
                DurableGraphEvent::BranchAttemptStarted {
                    branch_id: branch_id("branch-a"),
                    visit: 1,
                    attempt: 1,
                },
            )
            .expect("claim a with shared capability");

        for reopened in [false, true] {
            if reopened {
                queue = reopen_typed_queue(&repo, &source, queue);
            }
            let before = queue.snapshot().clone();
            let records = queue.journal.records().len();
            assert!(queue
                .claim_with_lease(
                    &item_b,
                    shared_worker.clone(),
                    shared_lease.clone(),
                    1,
                    10,
                    DurableGraphEvent::BranchAttemptStarted {
                        branch_id: branch_id("branch-b"),
                        visit: 1,
                        attempt: 1,
                    },
                )
                .is_err());
            assert_eq!(queue.snapshot(), &before);
            assert_eq!(queue.journal.records().len(), records);
        }

        let (_, successor_a) = queue
            .reclaim_expired_lease(
                &item_a,
                10,
                worker("worker-a-successor"),
                lease_id("lease-a-successor"),
                20,
            )
            .expect("reclaim a capability");
        queue
            .release_lease_before_dispatch(
                &item_a,
                successor_a,
                11,
                DurableGraphEvent::BranchAttemptCompleted {
                    branch_id: branch_id("branch-a"),
                    visit: 1,
                    attempt: 1,
                    outcome: graph_retryable("a awaits an explicit retry schedule"),
                },
                None,
                Vec::new(),
            )
            .expect("release reclaimed a capability");
        queue = reopen_typed_queue(&repo, &source, queue);
        assert!(!queue
            .snapshot()
            .pending_item_ids()
            .contains(&item_a.as_str()));
        for (cross_worker, cross_lease) in [
            (shared_worker.clone(), shared_lease.clone()),
            (worker("worker-a-successor"), lease_id("lease-a-successor")),
        ] {
            let before = queue.snapshot().clone();
            let records = queue.journal.records().len();
            assert!(queue
                .claim_with_lease(
                    &item_b,
                    cross_worker,
                    cross_lease,
                    1,
                    10,
                    DurableGraphEvent::BranchAttemptStarted {
                        branch_id: branch_id("branch-b"),
                        visit: 1,
                        attempt: 1,
                    },
                )
                .is_err());
            assert_eq!(queue.snapshot(), &before);
            assert_eq!(queue.journal.records().len(), records);
        }

        let (_, proof_b) = queue
            .claim_with_lease(
                &item_b,
                worker("worker-b"),
                lease_id("lease-b-distinct"),
                2,
                12,
                DurableGraphEvent::BranchAttemptStarted {
                    branch_id: branch_id("branch-b"),
                    visit: 1,
                    attempt: 1,
                },
            )
            .expect("claim b with distinct capability");
        queue = reopen_typed_queue(&repo, &source, queue);

        let before = queue.snapshot().clone();
        let records = queue.journal.records().len();
        assert!(queue
            .heartbeat_lease(&item_b, proof_a.clone(), 3, 11)
            .is_err());
        assert_eq!(queue.snapshot(), &before);
        assert_eq!(queue.journal.records().len(), records);

        let before = queue.snapshot().clone();
        let records = queue.journal.records().len();
        assert!(queue
            .release_lease_before_dispatch(
                &item_b,
                proof_a.clone(),
                3,
                DurableGraphEvent::BranchAttemptCompleted {
                    branch_id: branch_id("branch-b"),
                    visit: 1,
                    attempt: 1,
                    outcome: graph_failure("wrong item release"),
                },
                None,
                Vec::new(),
            )
            .is_err());
        assert_eq!(queue.snapshot(), &before);
        assert_eq!(queue.journal.records().len(), records);

        let before = queue.snapshot().clone();
        let records = queue.journal.records().len();
        assert!(queue
            .mark_leased_effect_started(&item_b, proof_a.clone(), 3)
            .is_err());
        assert_eq!(queue.snapshot(), &before);
        assert_eq!(queue.journal.records().len(), records);

        queue
            .mark_leased_effect_started(&item_b, proof_b.clone(), 3)
            .expect("valid b effect fence");
        queue = reopen_typed_queue(&repo, &source, queue);
        let run_id = queue
            .snapshot()
            .item(&item_b)
            .and_then(GeneratedFollowUpQueueItemSnapshot::subordinate_run_id)
            .expect("b subordinate run")
            .to_string();
        let before = queue.snapshot().clone();
        let records = queue.journal.records().len();
        assert!(queue
            .append_leased_terminal_observation(
                &item_b,
                GeneratedFollowUpDispatchObservation::new(
                    run_id,
                    None,
                    Vec::new(),
                    Some(ExternalSideEffectState::Completed),
                )
                .expect("b observation"),
                proof_a,
                4,
                DurableGraphEvent::BranchAttemptCompleted {
                    branch_id: branch_id("branch-b"),
                    visit: 1,
                    attempt: 1,
                    outcome: graph_success("must-not-ack", &[]),
                },
            )
            .is_err());
        assert_eq!(queue.snapshot(), &before);
        assert_eq!(queue.journal.records().len(), records);
    }

    #[test]
    fn semantically_invalid_authenticated_events_refuse_reopen_without_live_mutation() {
        let (_temp, repo) = repository();
        let heartbeat_source = source(&repo, "source-raw-heartbeat-before-claim");
        let task = generated_task("01");
        let item_id = generated_follow_up_item_id(&heartbeat_source, &task).expect("item id");
        let mut queue = GeneratedFollowUpQueue::create(
            authenticator(&repo),
            heartbeat_source.clone(),
            bounds(1),
        )
        .expect("create heartbeat queue");
        queue.enqueue_all_before_dispatch(&[task]).expect("enqueue");
        queue
            .define_graph(
                conditional_graph_definition(),
                vec![
                    DurableGraphQueueItemBinding::new(branch_id("branch-main"), item_id.clone())
                        .expect("heartbeat binding"),
                ],
            )
            .expect("define heartbeat graph");
        let heartbeat = QueueJournalEvent::LeaseHeartbeat {
            item_id: item_id.clone(),
            lease_event: LeaseEvent::heartbeat(
                LeaseProof::new(worker("worker-raw"), lease_id("lease-raw"), 1).expect("raw proof"),
                1,
                10,
            )
            .expect("raw heartbeat"),
        };
        let accepted = queue.snapshot().clone();
        queue
            .journal
            .append(heartbeat.phase(), heartbeat.subject(), &heartbeat)
            .expect("append correctly described invalid heartbeat");
        assert_eq!(queue.snapshot(), &accepted);
        drop(queue);
        assert!(GeneratedFollowUpQueue::open(authenticator(&repo), &heartbeat_source).is_err());

        let (_temp, repo) = repository();
        let retry_source = source(&repo, "source-raw-retry-before-attempt");
        let task = generated_task("01");
        let item_id = generated_follow_up_item_id(&retry_source, &task).expect("item id");
        let mut queue =
            GeneratedFollowUpQueue::create(authenticator(&repo), retry_source.clone(), bounds(1))
                .expect("create retry queue");
        queue.enqueue_all_before_dispatch(&[task]).expect("enqueue");
        queue
            .define_graph(
                conditional_graph_definition(),
                vec![
                    DurableGraphQueueItemBinding::new(branch_id("branch-main"), item_id)
                        .expect("retry binding"),
                ],
            )
            .expect("define retry graph");
        let retry = QueueJournalEvent::GraphTransition {
            graph_event: DurableGraphEvent::BranchRetryScheduled {
                branch_id: branch_id("branch-main"),
                visit: 1,
                next_attempt: 2,
            },
        };
        let accepted = queue.snapshot().clone();
        queue
            .journal
            .append(retry.phase(), retry.subject(), &retry)
            .expect("append correctly described invalid retry");
        assert_eq!(queue.snapshot(), &accepted);
        drop(queue);
        assert!(GeneratedFollowUpQueue::open(authenticator(&repo), &retry_source).is_err());
    }

    #[test]
    fn graph_binding_and_event_order_fail_closed_before_append() {
        let (_temp, repo) = repository();
        let source = source(&repo, "source-binding-order");
        let task = generated_task("01");
        let item_id = generated_follow_up_item_id(&source, &task).expect("item id");
        let mut queue = GeneratedFollowUpQueue::create(authenticator(&repo), source, bounds(1))
            .expect("create queue");
        queue
            .enqueue_all_before_dispatch(&[task])
            .expect("enqueue task");

        let before = queue.snapshot().clone();
        let records = queue.journal.records().len();
        assert!(queue
            .define_graph(
                conditional_graph_definition(),
                vec![DurableGraphQueueItemBinding::new(
                    branch_id("unrelated-branch"),
                    item_id.clone(),
                )
                .expect("well-formed wrong binding")],
            )
            .is_err());
        assert_eq!(queue.snapshot(), &before);
        assert_eq!(queue.journal.records().len(), records);

        queue
            .define_graph(
                conditional_graph_definition(),
                vec![
                    DurableGraphQueueItemBinding::new(branch_id("branch-main"), item_id.clone())
                        .expect("binding"),
                ],
            )
            .expect("define graph");

        let invalid_events = [
            DurableGraphEvent::Defined {
                definition: conditional_graph_definition(),
            },
            DurableGraphEvent::BranchAttemptCompleted {
                branch_id: branch_id("branch-main"),
                visit: 1,
                attempt: 1,
                outcome: graph_failure("completion-before-start"),
            },
            DurableGraphEvent::EdgesSelected {
                source_node_id: node_id("n00-task"),
                visit: 1,
                edge_ids: vec![edge_id("e10-failure")],
            },
        ];
        for invalid in invalid_events {
            let before = queue.snapshot().clone();
            let records = queue.journal.records().len();
            assert!(queue.apply_graph_transition(invalid).is_err());
            assert_eq!(queue.snapshot(), &before);
            assert_eq!(queue.journal.records().len(), records);
        }

        let (_, proof) = queue
            .claim_with_lease(
                &item_id,
                worker("worker-order"),
                lease_id("lease-order"),
                1,
                10,
                DurableGraphEvent::BranchAttemptStarted {
                    branch_id: branch_id("branch-main"),
                    visit: 1,
                    attempt: 1,
                },
            )
            .expect("valid claim");
        let before = queue.snapshot().clone();
        let records = queue.journal.records().len();
        assert!(queue
            .claim_with_lease(
                &item_id,
                worker("worker-duplicate"),
                lease_id("lease-duplicate"),
                2,
                10,
                DurableGraphEvent::BranchAttemptStarted {
                    branch_id: branch_id("branch-main"),
                    visit: 1,
                    attempt: 1,
                },
            )
            .is_err());
        assert_eq!(queue.snapshot(), &before);
        assert_eq!(queue.journal.records().len(), records);

        let before = queue.snapshot().clone();
        let records = queue.journal.records().len();
        assert!(queue
            .release_lease_before_dispatch(
                &item_id,
                proof,
                2,
                DurableGraphEvent::BranchAttemptCompleted {
                    branch_id: branch_id("branch-main"),
                    visit: 1,
                    attempt: 2,
                    outcome: graph_failure("skipped-attempt"),
                },
                None,
                Vec::new(),
            )
            .is_err());
        assert_eq!(queue.snapshot(), &before);
        assert_eq!(queue.journal.records().len(), records);
    }

    #[test]
    fn authenticated_outer_metadata_and_nested_graph_or_lease_tampering_refuses_reopen() {
        for (run_suffix, wrong_phase, wrong_subject) in
            [("phase", true, false), ("subject", false, true)]
        {
            let (_temp, repo) = repository();
            let source = source(&repo, &format!("source-outer-{run_suffix}"));
            let task = generated_task("01");
            let item_id = generated_follow_up_item_id(&source, &task).expect("item id");
            let mut queue =
                GeneratedFollowUpQueue::create(authenticator(&repo), source.clone(), bounds(1))
                    .expect("create queue");
            queue.enqueue_all_before_dispatch(&[task]).expect("enqueue");
            queue
                .define_graph(
                    conditional_graph_definition(),
                    vec![DurableGraphQueueItemBinding::new(
                        branch_id("branch-main"),
                        item_id.clone(),
                    )
                    .expect("binding")],
                )
                .expect("define graph");
            let event = QueueJournalEvent::LeaseClaimed {
                item_id: item_id.clone(),
                lease_event: LeaseEvent::claimed(
                    LeaseProof::new(worker("worker-meta"), lease_id("lease-meta"), 1)
                        .expect("proof"),
                    1,
                    10,
                )
                .expect("lease event"),
                graph_event: DurableGraphEvent::BranchAttemptStarted {
                    branch_id: branch_id("branch-main"),
                    visit: 1,
                    attempt: 1,
                },
            };
            let phase = if wrong_phase {
                "wrong_phase"
            } else {
                event.phase()
            };
            let subject = if wrong_subject {
                Some("f".repeat(64))
            } else {
                event.subject().map(str::to_string)
            };
            queue
                .journal
                .append(phase, subject.as_deref(), &event)
                .expect("append authenticated inconsistent metadata");
            let accepted = queue.snapshot().clone();
            assert!(queue.replay_snapshot().is_err());
            assert_eq!(queue.snapshot(), &accepted);
        }

        let (_temp, repo) = repository();
        let graph_source = source(&repo, "source-nested-tamper");
        let task = generated_task("01");
        let item_id = generated_follow_up_item_id(&graph_source, &task).expect("item id");
        let mut queue =
            GeneratedFollowUpQueue::create(authenticator(&repo), graph_source.clone(), bounds(1))
                .expect("create queue");
        queue.enqueue_all_before_dispatch(&[task]).expect("enqueue");
        queue
            .define_graph(
                conditional_graph_definition(),
                vec![
                    DurableGraphQueueItemBinding::new(branch_id("branch-main"), item_id)
                        .expect("binding"),
                ],
            )
            .expect("define graph");
        let record_ordinal = queue.journal.records().len();
        let record = queue
            .journal
            .root()
            .path()
            .join(queue.journal.instance_id())
            .join(format!("{record_ordinal:020}.json"));
        drop(queue);
        let mut bytes = fs::read(&record).expect("read graph record");
        let needle = b"queue-conditional";
        let position = bytes
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("nested graph id in record");
        bytes[position] = b'Q';
        fs::write(&record, bytes).expect("tamper nested graph payload");
        assert!(GeneratedFollowUpQueue::open(authenticator(&repo), &graph_source).is_err());

        let (_temp, repo) = repository();
        let lease_source = source(&repo, "source-nested-lease-tamper");
        let task = generated_task("01");
        let item_id = generated_follow_up_item_id(&lease_source, &task).expect("item id");
        let mut queue =
            GeneratedFollowUpQueue::create(authenticator(&repo), lease_source.clone(), bounds(1))
                .expect("create lease tamper queue");
        queue.enqueue_all_before_dispatch(&[task]).expect("enqueue");
        queue
            .define_graph(
                conditional_graph_definition(),
                vec![
                    DurableGraphQueueItemBinding::new(branch_id("branch-main"), item_id.clone())
                        .expect("lease tamper binding"),
                ],
            )
            .expect("define lease tamper graph");
        queue
            .claim_with_lease(
                &item_id,
                worker("worker-nested"),
                lease_id("lease-nested"),
                1,
                10,
                DurableGraphEvent::BranchAttemptStarted {
                    branch_id: branch_id("branch-main"),
                    visit: 1,
                    attempt: 1,
                },
            )
            .expect("claim nested lease");
        let record_ordinal = queue.journal.records().len();
        let record = queue
            .journal
            .root()
            .path()
            .join(queue.journal.instance_id())
            .join(format!("{record_ordinal:020}.json"));
        drop(queue);
        let mut bytes = fs::read(&record).expect("read lease record");
        let needle = b"lease-nested";
        let position = bytes
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("nested lease id in record");
        bytes[position] = b'L';
        fs::write(&record, bytes).expect("tamper nested lease payload");
        assert!(GeneratedFollowUpQueue::open(authenticator(&repo), &lease_source).is_err());
    }
}
