//! Typed, durable, deterministic turn-taking layered on messaging.
//!
//! This module deliberately does not authenticate speakers or confer authority.
//! Participants retain the [`RoleCategory`] supplied by the coordinator, and a
//! caller must authenticate through the message-envelope layer before invoking a
//! turn operation. Participant ordering affects only scheduling.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    hierarchy_ledger::RoleCategory,
    safe_state::{AtomicStateWriter, BoundedRegularReader, KernelStateLock, SafeRoot},
};

pub const TURN_PROTOCOL_STATE_VERSION: u32 = 1;

const TURN_PROTOCOL_LOCK_FILE: &str = ".maco-turn-protocol.lock";
const TURN_STATE_CHECKSUM_DOMAIN: &[u8] = b"MACO\0turn-protocol-state\0v1\0";
const HARD_MAX_PARTICIPANTS: usize = 4_096;
const HARD_MAX_GRAPH_EDGES: usize = 262_144;
const HARD_MAX_IDENTIFIER_BYTES: usize = 256;
const HARD_MAX_TERMINATION_REASON_BYTES: usize = 4_096;
const HARD_MAX_TURNS: u64 = 1_000_000;
const HARD_MAX_STATE_BYTES: u64 = 128 * 1024 * 1024;

/// Resource ceilings persisted as part of the immutable protocol definition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TurnProtocolLimits {
    pub max_participants: usize,
    pub max_graph_edges: usize,
    pub max_identifier_bytes: usize,
    pub max_termination_reason_bytes: usize,
    pub max_turns: u64,
    pub max_state_bytes: u64,
}

impl Default for TurnProtocolLimits {
    fn default() -> Self {
        Self {
            max_participants: 1_024,
            max_graph_edges: 65_536,
            max_identifier_bytes: HARD_MAX_IDENTIFIER_BYTES,
            max_termination_reason_bytes: 1_024,
            max_turns: 100_000,
            max_state_bytes: 16 * 1024 * 1024,
        }
    }
}

impl TurnProtocolLimits {
    pub fn validate(&self) -> Result<(), TurnDefinitionError> {
        validate_limit(
            "max_participants",
            self.max_participants as u64,
            HARD_MAX_PARTICIPANTS as u64,
        )?;
        validate_limit(
            "max_graph_edges",
            self.max_graph_edges as u64,
            HARD_MAX_GRAPH_EDGES as u64,
        )?;
        validate_limit(
            "max_identifier_bytes",
            self.max_identifier_bytes as u64,
            HARD_MAX_IDENTIFIER_BYTES as u64,
        )?;
        validate_limit(
            "max_termination_reason_bytes",
            self.max_termination_reason_bytes as u64,
            HARD_MAX_TERMINATION_REASON_BYTES as u64,
        )?;
        validate_limit("max_turns", self.max_turns, HARD_MAX_TURNS)?;
        validate_limit(
            "max_state_bytes",
            self.max_state_bytes,
            HARD_MAX_STATE_BYTES,
        )?;
        Ok(())
    }
}

/// An eligible speaker plus its immutable authority category.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TurnParticipant {
    agent_id: String,
    role_category: RoleCategory,
}

impl TurnParticipant {
    pub fn new(agent_id: impl Into<String>, role_category: RoleCategory) -> Self {
        Self {
            agent_id: agent_id.into(),
            role_category,
        }
    }

    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    pub const fn role_category(&self) -> RoleCategory {
        self.role_category
    }
}

/// A bounded directed speaker graph. Edges retain caller order only for
/// diagnostics; a graph-selected transition succeeds automatically only when
/// there is exactly one eligible outgoing edge.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpeakerGraph {
    initial_speaker: String,
    transitions: BTreeMap<String, Vec<String>>,
}

impl SpeakerGraph {
    pub fn new(
        initial_speaker: impl Into<String>,
        transitions: BTreeMap<String, Vec<String>>,
    ) -> Self {
        Self {
            initial_speaker: initial_speaker.into(),
            transitions,
        }
    }

    pub fn initial_speaker(&self) -> &str {
        &self.initial_speaker
    }

    pub fn transitions(&self) -> &BTreeMap<String, Vec<String>> {
        &self.transitions
    }
}

/// Serializable scheduling policy. Model-selected and free-form policies use
/// [`TurnProtocolStore::select_speaker`] as their explicit deterministic input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TurnPolicy {
    RoundRobin,
    ModelSelected,
    GraphSelected { graph: SpeakerGraph },
    FreeForm,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnPolicyKind {
    RoundRobin,
    ModelSelected,
    GraphSelected,
    FreeForm,
}

impl TurnPolicy {
    pub const fn kind(&self) -> TurnPolicyKind {
        match self {
            Self::RoundRobin => TurnPolicyKind::RoundRobin,
            Self::ModelSelected => TurnPolicyKind::ModelSelected,
            Self::GraphSelected { .. } => TurnPolicyKind::GraphSelected,
            Self::FreeForm => TurnPolicyKind::FreeForm,
        }
    }
}

/// Immutable durable protocol configuration checked in full on reopen.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TurnProtocolDefinition {
    session_id: String,
    protocol_id: String,
    participants: Vec<TurnParticipant>,
    policy: TurnPolicy,
    max_turns: u64,
    limits: TurnProtocolLimits,
}

impl TurnProtocolDefinition {
    pub fn new(
        session_id: impl Into<String>,
        protocol_id: impl Into<String>,
        participants: Vec<TurnParticipant>,
        policy: TurnPolicy,
        max_turns: u64,
        limits: TurnProtocolLimits,
    ) -> Result<Self, TurnDefinitionError> {
        let definition = Self {
            session_id: session_id.into(),
            protocol_id: protocol_id.into(),
            participants,
            policy,
            max_turns,
            limits,
        };
        definition.validate()?;
        Ok(definition)
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn protocol_id(&self) -> &str {
        &self.protocol_id
    }

    pub fn participants(&self) -> &[TurnParticipant] {
        &self.participants
    }

    pub fn policy(&self) -> &TurnPolicy {
        &self.policy
    }

    pub const fn max_turns(&self) -> u64 {
        self.max_turns
    }

    pub fn limits(&self) -> &TurnProtocolLimits {
        &self.limits
    }

    fn validate(&self) -> Result<(), TurnDefinitionError> {
        self.limits.validate()?;
        validate_identifier("session_id", &self.session_id, &self.limits)?;
        validate_identifier("protocol_id", &self.protocol_id, &self.limits)?;
        if self.participants.is_empty() {
            return Err(TurnDefinitionError::EmptyParticipants);
        }
        if self.participants.len() > self.limits.max_participants {
            return Err(TurnDefinitionError::TooManyParticipants {
                actual: self.participants.len(),
                max: self.limits.max_participants,
            });
        }
        let mut participant_ids = BTreeSet::new();
        for participant in &self.participants {
            validate_identifier("participant_id", participant.agent_id(), &self.limits).map_err(
                |_| TurnDefinitionError::InvalidParticipant {
                    participant_id: participant.agent_id.clone(),
                },
            )?;
            if !participant_ids.insert(participant.agent_id.clone()) {
                return Err(TurnDefinitionError::DuplicateParticipant {
                    participant_id: participant.agent_id.clone(),
                });
            }
        }
        if self.max_turns == 0 || self.max_turns > self.limits.max_turns {
            return Err(TurnDefinitionError::InvalidMaximumTurns {
                requested: self.max_turns,
                max: self.limits.max_turns,
            });
        }
        if let TurnPolicy::GraphSelected { graph } = &self.policy {
            validate_graph(graph, &participant_ids, &self.limits)?;
        }
        Ok(())
    }

    fn contains_participant(&self, participant_id: &str) -> bool {
        self.participants
            .iter()
            .any(|participant| participant.agent_id() == participant_id)
    }

    fn participant_index(&self, participant_id: &str) -> Option<usize> {
        self.participants
            .iter()
            .position(|participant| participant.agent_id() == participant_id)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnCompletionReason {
    MaximumTurnsReached,
}

/// Durable lifecycle status. Explicit termination and maximum-turn completion
/// are different terminal states.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum TurnProtocolStatus {
    Active,
    Terminated { reason: String },
    Completed { reason: TurnCompletionReason },
}

impl TurnProtocolStatus {
    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }
}

/// Compare-and-swap coordinates presented with every state mutation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TurnExpectation {
    pub completed_turns: u64,
    pub generation: u64,
}

impl TurnExpectation {
    pub const fn new(completed_turns: u64, generation: u64) -> Self {
        Self {
            completed_turns,
            generation,
        }
    }
}

/// Receipt retained for exact duplicate classification after recovery.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TurnCompletionReceipt {
    speaker_id: String,
    expected: TurnExpectation,
    completed_turns_after: u64,
    generation_after: u64,
}

impl TurnCompletionReceipt {
    pub fn speaker_id(&self) -> &str {
        &self.speaker_id
    }

    pub const fn expected(&self) -> TurnExpectation {
        self.expected
    }

    pub const fn completed_turns_after(&self) -> u64 {
        self.completed_turns_after
    }

    pub const fn generation_after(&self) -> u64 {
        self.generation_after
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TurnSelectionOutcome {
    pub selected_speaker: String,
    pub completed_turns: u64,
    pub generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TurnCompletionOutcome {
    pub receipt: TurnCompletionReceipt,
    pub status: TurnProtocolStatus,
    pub next_speaker: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TurnTerminationOutcome {
    pub status: TurnProtocolStatus,
    pub completed_turns: u64,
    pub generation: u64,
}

/// Fully serializable durable state. Mutation is intentionally available only
/// through [`TurnProtocolStore`] so accepting a completion cannot be separated
/// from atomic persistence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TurnProtocolState {
    definition: TurnProtocolDefinition,
    status: TurnProtocolStatus,
    selected_speaker: Option<String>,
    current_speaker: Option<String>,
    last_speaker: Option<String>,
    completed_turns: u64,
    selection_count: u64,
    generation: u64,
    last_completion: Option<TurnCompletionReceipt>,
}

impl TurnProtocolState {
    fn initial(definition: TurnProtocolDefinition) -> Self {
        let initial = match &definition.policy {
            TurnPolicy::RoundRobin => definition
                .participants
                .first()
                .map(|participant| participant.agent_id.clone()),
            TurnPolicy::GraphSelected { graph } => Some(graph.initial_speaker.clone()),
            TurnPolicy::ModelSelected | TurnPolicy::FreeForm => None,
        };
        Self {
            definition,
            status: TurnProtocolStatus::Active,
            selected_speaker: initial.clone(),
            current_speaker: initial,
            last_speaker: None,
            completed_turns: 0,
            selection_count: 0,
            generation: 0,
            last_completion: None,
        }
    }

    pub fn definition(&self) -> &TurnProtocolDefinition {
        &self.definition
    }

    pub fn status(&self) -> &TurnProtocolStatus {
        &self.status
    }

    pub fn selected_speaker(&self) -> Option<&str> {
        self.selected_speaker.as_deref()
    }

    pub fn current_speaker(&self) -> Option<&str> {
        self.current_speaker.as_deref()
    }

    pub fn last_speaker(&self) -> Option<&str> {
        self.last_speaker.as_deref()
    }

    pub const fn completed_turns(&self) -> u64 {
        self.completed_turns
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn expectation(&self) -> TurnExpectation {
        TurnExpectation::new(self.completed_turns, self.generation)
    }

    pub fn last_completion(&self) -> Option<&TurnCompletionReceipt> {
        self.last_completion.as_ref()
    }

    pub fn participant_role(&self, participant_id: &str) -> Option<RoleCategory> {
        self.definition
            .participants
            .iter()
            .find(|participant| participant.agent_id() == participant_id)
            .map(TurnParticipant::role_category)
    }

    fn validate(&self) -> Result<(), TurnProtocolError> {
        if let Err(error) = self.definition.validate() {
            return Err(TurnProtocolError::CorruptState {
                detail: format!("invalid persisted definition: {error}"),
            });
        }
        if self.selected_speaker != self.current_speaker {
            return Err(TurnProtocolError::CorruptState {
                detail: "selected and current speaker differ".to_string(),
            });
        }
        for (field, speaker) in [
            ("selected_speaker", self.selected_speaker.as_deref()),
            ("current_speaker", self.current_speaker.as_deref()),
            ("last_speaker", self.last_speaker.as_deref()),
        ] {
            if let Some(speaker) = speaker {
                if !self.definition.contains_participant(speaker) {
                    return Err(TurnProtocolError::CorruptState {
                        detail: format!("{field} is not an eligible participant"),
                    });
                }
            }
        }
        if self.completed_turns > self.definition.max_turns {
            return Err(counter_status_error(self));
        }
        match &self.status {
            TurnProtocolStatus::Active | TurnProtocolStatus::Terminated { .. }
                if self.completed_turns >= self.definition.max_turns =>
            {
                return Err(counter_status_error(self));
            }
            TurnProtocolStatus::Completed {
                reason: TurnCompletionReason::MaximumTurnsReached,
            } if self.completed_turns != self.definition.max_turns => {
                return Err(counter_status_error(self));
            }
            _ => {}
        }
        let termination_increment =
            u64::from(matches!(self.status, TurnProtocolStatus::Terminated { .. }));
        let expected_generation = self
            .completed_turns
            .checked_add(self.selection_count)
            .and_then(|value| value.checked_add(termination_increment))
            .ok_or_else(|| TurnProtocolError::CorruptState {
                detail: "generation components overflow".to_string(),
            })?;
        if self.generation != expected_generation {
            return Err(TurnProtocolError::CorruptState {
                detail: format!(
                    "generation {} is inconsistent with {} completions, {} selections, and status {:?}",
                    self.generation, self.completed_turns, self.selection_count, self.status
                ),
            });
        }
        if let TurnProtocolStatus::Terminated { reason } = &self.status {
            validate_termination_reason(reason, &self.definition.limits).map_err(|_| {
                TurnProtocolError::CorruptState {
                    detail: "persisted termination reason is invalid".to_string(),
                }
            })?;
        }
        if !self.status.is_active()
            && (self.selected_speaker.is_some() || self.current_speaker.is_some())
        {
            return Err(TurnProtocolError::CorruptState {
                detail: "terminal state retains an active speaker".to_string(),
            });
        }
        if self.completed_turns == 0 {
            if self.last_speaker.is_some() || self.last_completion.is_some() {
                return Err(TurnProtocolError::CorruptState {
                    detail: "zero-turn state retains completion history".to_string(),
                });
            }
        } else {
            let Some(receipt) = &self.last_completion else {
                return Err(TurnProtocolError::CorruptState {
                    detail: "completed state lacks its last completion receipt".to_string(),
                });
            };
            let expected_receipt_generation = match self.definition.policy.kind() {
                TurnPolicyKind::RoundRobin | TurnPolicyKind::GraphSelected => {
                    receipt.completed_turns_after
                }
                TurnPolicyKind::ModelSelected | TurnPolicyKind::FreeForm => receipt
                    .completed_turns_after
                    .checked_mul(2)
                    .ok_or_else(|| TurnProtocolError::CorruptState {
                        detail: "last completion receipt generation overflows".to_string(),
                    })?,
            };
            if receipt.completed_turns_after != self.completed_turns
                || receipt.expected.completed_turns.checked_add(1)
                    != Some(receipt.completed_turns_after)
                || receipt.expected.generation.checked_add(1) != Some(receipt.generation_after)
                || receipt.generation_after != expected_receipt_generation
                || self.last_speaker.as_deref() != Some(receipt.speaker_id.as_str())
                || !self.definition.contains_participant(&receipt.speaker_id)
            {
                return Err(TurnProtocolError::CorruptState {
                    detail: "last completion receipt is inconsistent with durable counters"
                        .to_string(),
                });
            }
        }
        self.validate_policy_state()
    }

    fn validate_policy_state(&self) -> Result<(), TurnProtocolError> {
        match &self.definition.policy {
            TurnPolicy::RoundRobin => {
                if self.selection_count != 0 {
                    return Err(TurnProtocolError::CorruptState {
                        detail: "round-robin state contains explicit selections".to_string(),
                    });
                }
                let count = usize::try_from(self.completed_turns).map_err(|_| {
                    TurnProtocolError::CorruptState {
                        detail: "round-robin counter cannot index participants".to_string(),
                    }
                })?;
                let participants = &self.definition.participants;
                let expected_current = if self.status.is_active() {
                    participants
                        .get(count % participants.len())
                        .map(|participant| participant.agent_id.as_str())
                } else {
                    None
                };
                let expected_last = if count == 0 {
                    None
                } else {
                    participants
                        .get((count - 1) % participants.len())
                        .map(|participant| participant.agent_id.as_str())
                };
                if self.current_speaker() != expected_current
                    || self.last_speaker() != expected_last
                {
                    return Err(TurnProtocolError::CorruptState {
                        detail: "round-robin speakers are inconsistent with the turn counter"
                            .to_string(),
                    });
                }
            }
            TurnPolicy::ModelSelected | TurnPolicy::FreeForm => {
                let pending_selection_count =
                    self.completed_turns.checked_add(1).ok_or_else(|| {
                        TurnProtocolError::CorruptState {
                            detail: "selection-driven turn counter overflows".to_string(),
                        }
                    })?;
                let selection_count_is_reachable = match self.status {
                    TurnProtocolStatus::Active | TurnProtocolStatus::Terminated { .. } => {
                        self.selection_count == self.completed_turns
                            || self.selection_count == pending_selection_count
                    }
                    TurnProtocolStatus::Completed { .. } => {
                        self.selection_count == self.completed_turns
                    }
                };
                if !selection_count_is_reachable {
                    return Err(TurnProtocolError::CorruptState {
                        detail: "selection-driven policy has an inconsistent selection count"
                            .to_string(),
                    });
                }
                if self.status.is_active() {
                    let has_pending_selection = self.selection_count == pending_selection_count;
                    if has_pending_selection != self.current_speaker.is_some() {
                        return Err(TurnProtocolError::CorruptState {
                            detail:
                                "selection-driven current speaker disagrees with selection count"
                                    .to_string(),
                        });
                    }
                }
            }
            TurnPolicy::GraphSelected { graph } => {
                if self.selection_count != 0 {
                    return Err(TurnProtocolError::CorruptState {
                        detail: "graph-selected state contains explicit selections".to_string(),
                    });
                }
                let (derived_last, derived_current) =
                    derive_graph_speakers(graph, self.completed_turns, &self.status)?;
                if self.last_speaker() != derived_last.as_deref()
                    || self.current_speaker() != derived_current.as_deref()
                {
                    return Err(TurnProtocolError::CorruptState {
                        detail: "graph-selected speakers are inconsistent with the turn counter"
                            .to_string(),
                    });
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum TurnDefinitionError {
    #[error("turn protocol limit {field}={requested} is outside 1..={hard_max}")]
    InvalidLimit {
        field: &'static str,
        requested: u64,
        hard_max: u64,
    },
    #[error("turn protocol {field} is not a bounded canonical identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("turn protocol participants must be nonempty")]
    EmptyParticipants,
    #[error("turn protocol has {actual} participants; limit is {max}")]
    TooManyParticipants { actual: usize, max: usize },
    #[error("turn protocol participant {participant_id:?} is invalid")]
    InvalidParticipant { participant_id: String },
    #[error("turn protocol participant {participant_id:?} is duplicated")]
    DuplicateParticipant { participant_id: String },
    #[error("turn protocol maximum turn count {requested} is outside 1..={max}")]
    InvalidMaximumTurns { requested: u64, max: u64 },
    #[error("graph initial speaker {speaker_id:?} is not an eligible participant")]
    InvalidGraphInitialSpeaker { speaker_id: String },
    #[error("graph contains {actual} transitions; limit is {max}")]
    TooManyGraphTransitions { actual: usize, max: usize },
    #[error("graph transition source {speaker_id:?} is not an eligible participant")]
    InvalidGraphSource { speaker_id: String },
    #[error("graph transition {from:?} -> {to:?} is not between eligible participants")]
    InvalidGraphTransition { from: String, to: String },
    #[error("graph transition {from:?} -> {to:?} is duplicated")]
    DuplicateGraphTransition { from: String, to: String },
}

/// Typed state-machine refusals and fail-closed persistence errors.
#[derive(Debug, Error)]
pub enum TurnProtocolError {
    #[error(transparent)]
    InvalidDefinition(#[from] TurnDefinitionError),
    #[error("turn protocol state already exists at {path}")]
    StateAlreadyExists { path: PathBuf },
    #[error("turn protocol state is missing at {path}")]
    StateMissing { path: PathBuf },
    #[error("turn protocol store path is invalid: {path}")]
    InvalidStorePath { path: PathBuf },
    #[error("turn protocol state version {found} is incompatible; expected {expected}")]
    IncompatibleStateVersion { found: u64, expected: u32 },
    #[error("turn protocol state checksum is invalid")]
    ChecksumMismatch,
    #[error("turn protocol state is corrupt: {detail}")]
    CorruptState { detail: String },
    #[error(
        "turn protocol counter/status inconsistency: completed={completed_turns}, max={max_turns}, status={status:?}"
    )]
    CounterStatusInconsistency {
        completed_turns: u64,
        max_turns: u64,
        status: TurnProtocolStatus,
    },
    #[error("turn protocol state does not match the expected immutable definition")]
    DefinitionMismatch,
    #[error("turn protocol store is poisoned after an uncertain write; reopen it")]
    Poisoned,
    #[error("turn protocol persistence failed while {operation}: {source}")]
    Persistence {
        operation: &'static str,
        #[source]
        source: anyhow::Error,
    },
    #[error("turn protocol serialization failed: {0}")]
    Serialization(#[source] serde_json::Error),
    #[error("serialized turn protocol state uses {actual} bytes; limit is {max}")]
    StateByteLimitExceeded { actual: usize, max: u64 },
    #[error("turn protocol is not active: {status:?}")]
    NotActive { status: TurnProtocolStatus },
    #[error("turn completion by {speaker_id:?} is an exact duplicate")]
    DoubleCompletion {
        speaker_id: String,
        expected: TurnExpectation,
    },
    #[error("expected generation {expected} is stale; current generation is {actual}")]
    StaleGeneration { expected: u64, actual: u64 },
    #[error("expected completed-turn counter {expected} is stale; current counter is {actual}")]
    StaleCompletedTurnCounter { expected: u64, actual: u64 },
    #[error("participant {participant_id:?} is not eligible for this turn protocol")]
    InvalidSelection { participant_id: String },
    #[error("policy {policy:?} does not accept explicit speaker selection")]
    SelectionNotAllowed { policy: TurnPolicyKind },
    #[error("speaker {speaker_id:?} is already selected for the current turn")]
    SpeakerAlreadySelected { speaker_id: String },
    #[error("no speaker has been selected for the current turn")]
    NoSpeakerSelected,
    #[error("only selected speaker {selected_speaker:?} may complete; got {actual_speaker:?}")]
    WrongSpeaker {
        selected_speaker: String,
        actual_speaker: String,
    },
    #[error("graph speaker {from:?} has no outgoing transition")]
    MissingGraphTransition { from: String },
    #[error("graph speaker {from:?} has ambiguous outgoing transitions: {choices:?}")]
    AmbiguousGraphTransition { from: String, choices: Vec<String> },
    #[error("graph transition {from:?} -> {to:?} is invalid")]
    InvalidGraphTransition { from: String, to: String },
    #[error("turn protocol counter is exhausted")]
    CounterExhausted,
    #[error("turn protocol generation is exhausted")]
    GenerationExhausted,
    #[error("turn protocol explicit selection counter is exhausted")]
    SelectionCounterExhausted,
    #[error("termination reason must contain bounded, non-control text")]
    InvalidTerminationReason,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedTurnProtocolState {
    version: u32,
    state: TurnProtocolState,
    checksum: String,
}

/// Lock-serialized handle for one atomic durable turn snapshot.
pub struct TurnProtocolStore {
    root: SafeRoot,
    state_file: OsString,
    state_path: PathBuf,
    expected_definition: TurnProtocolDefinition,
    state: TurnProtocolState,
    poisoned: bool,
}

impl TurnProtocolStore {
    pub fn create(
        path: impl AsRef<Path>,
        definition: TurnProtocolDefinition,
    ) -> Result<Self, TurnProtocolError> {
        definition.validate()?;
        let (root, state_file, state_path) = store_binding(path.as_ref(), true)?;
        let lock = acquire_lock(&root)?;
        if root
            .direct_child_exists(&state_file)
            .map_err(|source| persistence_error("checking state existence", source))?
        {
            return Err(TurnProtocolError::StateAlreadyExists { path: state_path });
        }
        let state = TurnProtocolState::initial(definition.clone());
        state.validate()?;
        write_state(&root, &state_file, &lock, &state)?;
        Ok(Self {
            root,
            state_file,
            state_path,
            expected_definition: definition,
            state,
            poisoned: false,
        })
    }

    /// Reopens only the exact immutable protocol definition requested by the
    /// caller. Persisted bytes and invariants are validated before comparison
    /// with caller input.
    pub fn open(
        path: impl AsRef<Path>,
        expected_definition: &TurnProtocolDefinition,
    ) -> Result<Self, TurnProtocolError> {
        let (root, state_file, state_path) = store_binding(path.as_ref(), false)?;
        let lock = acquire_lock(&root)?;
        let state = read_state(&root, &state_file, &state_path, &lock)?;
        expected_definition.validate()?;
        if state.definition != *expected_definition {
            return Err(TurnProtocolError::DefinitionMismatch);
        }
        Ok(Self {
            root,
            state_file,
            state_path,
            expected_definition: expected_definition.clone(),
            state,
            poisoned: false,
        })
    }

    pub fn state(&self) -> &TurnProtocolState {
        &self.state
    }

    /// Reloads and validates the newest snapshot under the protocol lock.
    pub fn refresh(&mut self) -> Result<&TurnProtocolState, TurnProtocolError> {
        self.ensure_not_poisoned()?;
        let lock = acquire_lock(&self.root)?;
        self.reload_locked(&lock)?;
        Ok(&self.state)
    }

    /// Checks only a snapshot of the participant selected in the newest durable
    /// turn state. This read-only gate does not authenticate the caller and
    /// MUST NOT authorize a later side effect after it returns, because the
    /// protocol lock has already been released. Use
    /// [`Self::with_authorized_speaker`] to compose authorization with a side
    /// effect. No state is persisted and no counter advances on success or
    /// refusal.
    pub fn authorize_speaker(
        &mut self,
        speaker_id: &str,
        expected: TurnExpectation,
    ) -> Result<(), TurnProtocolError> {
        self.ensure_not_poisoned()?;
        let lock = acquire_lock(&self.root)?;
        self.reload_locked(&lock)?;
        validate_authorized_speaker(&self.state, speaker_id, expected)?;
        Ok(())
    }

    /// Runs `operation` while the newest durable turn snapshot remains locked
    /// and authorizes `speaker_id`. The caller must authenticate and perform the
    /// protected side effect inside `operation`; for example, an operation that
    /// returns `Result<T, MessagingError>` remains nested inside this method's
    /// `Result<_, TurnProtocolError>`.
    ///
    /// This closes the authorization-to-operation turn-state race but is not a
    /// cross-store atomic transaction. A successful message append is durable
    /// even if a later turn completion or other persistence step fails.
    pub fn with_authorized_speaker<T>(
        &mut self,
        speaker_id: &str,
        expected: TurnExpectation,
        operation: impl FnOnce() -> T,
    ) -> Result<T, TurnProtocolError> {
        self.ensure_not_poisoned()?;
        let lock = acquire_lock(&self.root)?;
        self.reload_locked(&lock)?;
        validate_authorized_speaker(&self.state, speaker_id, expected)?;
        Ok(operation())
    }

    /// Persists one explicit eligible selection. This method does not
    /// authenticate the selecting caller; authentication belongs to messaging.
    pub fn select_speaker(
        &mut self,
        participant_id: &str,
        expected: TurnExpectation,
    ) -> Result<TurnSelectionOutcome, TurnProtocolError> {
        self.ensure_not_poisoned()?;
        let lock = acquire_lock(&self.root)?;
        self.reload_locked(&lock)?;
        ensure_active(&self.state)?;
        validate_expectation(&self.state, expected)?;
        match self.state.definition.policy.kind() {
            TurnPolicyKind::ModelSelected | TurnPolicyKind::FreeForm => {}
            policy => return Err(TurnProtocolError::SelectionNotAllowed { policy }),
        }
        if !self.state.definition.contains_participant(participant_id) {
            return Err(TurnProtocolError::InvalidSelection {
                participant_id: participant_id.to_string(),
            });
        }
        if let Some(selected) = self.state.selected_speaker() {
            return Err(TurnProtocolError::SpeakerAlreadySelected {
                speaker_id: selected.to_string(),
            });
        }
        let mut candidate = self.state.clone();
        candidate.selection_count = candidate
            .selection_count
            .checked_add(1)
            .ok_or(TurnProtocolError::SelectionCounterExhausted)?;
        candidate.generation = candidate
            .generation
            .checked_add(1)
            .ok_or(TurnProtocolError::GenerationExhausted)?;
        candidate.selected_speaker = Some(participant_id.to_string());
        candidate.current_speaker = Some(participant_id.to_string());
        candidate.validate()?;
        self.persist_locked(&lock, candidate)?;
        Ok(TurnSelectionOutcome {
            selected_speaker: participant_id.to_string(),
            completed_turns: self.state.completed_turns,
            generation: self.state.generation,
        })
    }

    /// Atomically records exactly one accepted completion and its deterministic
    /// successor. An exact retry is classified before terminal/stale checks.
    pub fn complete_turn(
        &mut self,
        speaker_id: &str,
        expected: TurnExpectation,
    ) -> Result<TurnCompletionOutcome, TurnProtocolError> {
        self.ensure_not_poisoned()?;
        let lock = acquire_lock(&self.root)?;
        self.reload_locked(&lock)?;
        if self
            .state
            .last_completion
            .as_ref()
            .is_some_and(|receipt| receipt.speaker_id == speaker_id && receipt.expected == expected)
        {
            return Err(TurnProtocolError::DoubleCompletion {
                speaker_id: speaker_id.to_string(),
                expected,
            });
        }
        ensure_active(&self.state)?;
        validate_expectation(&self.state, expected)?;
        if !self.state.definition.contains_participant(speaker_id) {
            return Err(TurnProtocolError::InvalidSelection {
                participant_id: speaker_id.to_string(),
            });
        }
        let selected = self
            .state
            .selected_speaker()
            .ok_or(TurnProtocolError::NoSpeakerSelected)?;
        if selected != speaker_id {
            return Err(TurnProtocolError::WrongSpeaker {
                selected_speaker: selected.to_string(),
                actual_speaker: speaker_id.to_string(),
            });
        }
        let completed_turns_after = self
            .state
            .completed_turns
            .checked_add(1)
            .ok_or(TurnProtocolError::CounterExhausted)?;
        let generation_after = self
            .state
            .generation
            .checked_add(1)
            .ok_or(TurnProtocolError::GenerationExhausted)?;
        let receipt = TurnCompletionReceipt {
            speaker_id: speaker_id.to_string(),
            expected,
            completed_turns_after,
            generation_after,
        };
        let mut candidate = self.state.clone();
        candidate.completed_turns = completed_turns_after;
        candidate.generation = generation_after;
        candidate.last_speaker = Some(speaker_id.to_string());
        candidate.last_completion = Some(receipt.clone());

        if completed_turns_after == candidate.definition.max_turns {
            candidate.status = TurnProtocolStatus::Completed {
                reason: TurnCompletionReason::MaximumTurnsReached,
            };
            candidate.selected_speaker = None;
            candidate.current_speaker = None;
        } else {
            let successor = next_speaker(&candidate, speaker_id)?;
            candidate.selected_speaker = successor.clone();
            candidate.current_speaker = successor;
        }
        candidate.validate()?;
        self.persist_locked(&lock, candidate)?;
        Ok(TurnCompletionOutcome {
            receipt,
            status: self.state.status.clone(),
            next_speaker: self.state.current_speaker.clone(),
        })
    }

    pub fn terminate(
        &mut self,
        reason: impl Into<String>,
        expected: TurnExpectation,
    ) -> Result<TurnTerminationOutcome, TurnProtocolError> {
        self.ensure_not_poisoned()?;
        let lock = acquire_lock(&self.root)?;
        self.reload_locked(&lock)?;
        ensure_active(&self.state)?;
        validate_expectation(&self.state, expected)?;
        let reason = reason.into();
        validate_termination_reason(&reason, &self.state.definition.limits)?;
        let mut candidate = self.state.clone();
        candidate.generation = candidate
            .generation
            .checked_add(1)
            .ok_or(TurnProtocolError::GenerationExhausted)?;
        candidate.status = TurnProtocolStatus::Terminated { reason };
        candidate.selected_speaker = None;
        candidate.current_speaker = None;
        candidate.validate()?;
        self.persist_locked(&lock, candidate)?;
        Ok(TurnTerminationOutcome {
            status: self.state.status.clone(),
            completed_turns: self.state.completed_turns,
            generation: self.state.generation,
        })
    }

    fn ensure_not_poisoned(&self) -> Result<(), TurnProtocolError> {
        if self.poisoned {
            Err(TurnProtocolError::Poisoned)
        } else {
            Ok(())
        }
    }

    fn reload_locked(&mut self, lock: &KernelStateLock) -> Result<(), TurnProtocolError> {
        let state = read_state(&self.root, &self.state_file, &self.state_path, lock)?;
        if state.definition != self.expected_definition {
            return Err(TurnProtocolError::DefinitionMismatch);
        }
        self.state = state;
        Ok(())
    }

    fn persist_locked(
        &mut self,
        lock: &KernelStateLock,
        candidate: TurnProtocolState,
    ) -> Result<(), TurnProtocolError> {
        if let Err(error) = write_state(&self.root, &self.state_file, lock, &candidate) {
            self.poisoned = true;
            return Err(error);
        }
        self.state = candidate;
        Ok(())
    }
}

fn validate_limit(
    field: &'static str,
    requested: u64,
    hard_max: u64,
) -> Result<(), TurnDefinitionError> {
    if requested == 0 || requested > hard_max {
        return Err(TurnDefinitionError::InvalidLimit {
            field,
            requested,
            hard_max,
        });
    }
    Ok(())
}

fn validate_identifier(
    field: &'static str,
    value: &str,
    limits: &TurnProtocolLimits,
) -> Result<(), TurnDefinitionError> {
    if value.is_empty()
        || value.len() > limits.max_identifier_bytes
        || !value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | ':')
        })
    {
        return Err(TurnDefinitionError::InvalidIdentifier { field });
    }
    Ok(())
}

fn validate_graph(
    graph: &SpeakerGraph,
    participant_ids: &BTreeSet<String>,
    limits: &TurnProtocolLimits,
) -> Result<(), TurnDefinitionError> {
    if !participant_ids.contains(&graph.initial_speaker) {
        return Err(TurnDefinitionError::InvalidGraphInitialSpeaker {
            speaker_id: graph.initial_speaker.clone(),
        });
    }
    let mut edge_count = 0_usize;
    for (from, choices) in &graph.transitions {
        if !participant_ids.contains(from) {
            return Err(TurnDefinitionError::InvalidGraphSource {
                speaker_id: from.clone(),
            });
        }
        let mut unique = BTreeSet::new();
        for to in choices {
            edge_count =
                edge_count
                    .checked_add(1)
                    .ok_or(TurnDefinitionError::TooManyGraphTransitions {
                        actual: usize::MAX,
                        max: limits.max_graph_edges,
                    })?;
            if edge_count > limits.max_graph_edges {
                return Err(TurnDefinitionError::TooManyGraphTransitions {
                    actual: edge_count,
                    max: limits.max_graph_edges,
                });
            }
            if !participant_ids.contains(to) {
                return Err(TurnDefinitionError::InvalidGraphTransition {
                    from: from.clone(),
                    to: to.clone(),
                });
            }
            if !unique.insert(to) {
                return Err(TurnDefinitionError::DuplicateGraphTransition {
                    from: from.clone(),
                    to: to.clone(),
                });
            }
        }
    }
    Ok(())
}

fn validate_termination_reason(
    reason: &str,
    limits: &TurnProtocolLimits,
) -> Result<(), TurnProtocolError> {
    if reason.is_empty()
        || reason != reason.trim()
        || reason.len() > limits.max_termination_reason_bytes
        || reason.chars().any(char::is_control)
    {
        return Err(TurnProtocolError::InvalidTerminationReason);
    }
    Ok(())
}

fn ensure_active(state: &TurnProtocolState) -> Result<(), TurnProtocolError> {
    if state.status.is_active() {
        Ok(())
    } else {
        Err(TurnProtocolError::NotActive {
            status: state.status.clone(),
        })
    }
}

fn validate_expectation(
    state: &TurnProtocolState,
    expected: TurnExpectation,
) -> Result<(), TurnProtocolError> {
    if expected.generation != state.generation {
        return Err(TurnProtocolError::StaleGeneration {
            expected: expected.generation,
            actual: state.generation,
        });
    }
    if expected.completed_turns != state.completed_turns {
        return Err(TurnProtocolError::StaleCompletedTurnCounter {
            expected: expected.completed_turns,
            actual: state.completed_turns,
        });
    }
    Ok(())
}

fn validate_authorized_speaker(
    state: &TurnProtocolState,
    speaker_id: &str,
    expected: TurnExpectation,
) -> Result<(), TurnProtocolError> {
    ensure_active(state)?;
    validate_expectation(state, expected)?;
    if !state.definition.contains_participant(speaker_id) {
        return Err(TurnProtocolError::InvalidSelection {
            participant_id: speaker_id.to_string(),
        });
    }
    let selected = state
        .selected_speaker()
        .ok_or(TurnProtocolError::NoSpeakerSelected)?;
    if selected != speaker_id {
        return Err(TurnProtocolError::WrongSpeaker {
            selected_speaker: selected.to_string(),
            actual_speaker: speaker_id.to_string(),
        });
    }
    Ok(())
}

fn next_speaker(
    state: &TurnProtocolState,
    completed_speaker: &str,
) -> Result<Option<String>, TurnProtocolError> {
    match &state.definition.policy {
        TurnPolicy::RoundRobin => {
            let completed_index = state
                .definition
                .participant_index(completed_speaker)
                .ok_or_else(|| TurnProtocolError::InvalidSelection {
                    participant_id: completed_speaker.to_string(),
                })?;
            let next_index = (completed_index + 1) % state.definition.participants.len();
            Ok(state
                .definition
                .participants
                .get(next_index)
                .map(|participant| participant.agent_id.clone()))
        }
        TurnPolicy::ModelSelected | TurnPolicy::FreeForm => Ok(None),
        TurnPolicy::GraphSelected { graph } => {
            graph_successor(graph, completed_speaker, &state.definition)
        }
    }
}

fn graph_successor(
    graph: &SpeakerGraph,
    from: &str,
    definition: &TurnProtocolDefinition,
) -> Result<Option<String>, TurnProtocolError> {
    let choices = graph
        .transitions
        .get(from)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    match choices {
        [] => Err(TurnProtocolError::MissingGraphTransition {
            from: from.to_string(),
        }),
        [to] if definition.contains_participant(to) => Ok(Some(to.clone())),
        [to] => Err(TurnProtocolError::InvalidGraphTransition {
            from: from.to_string(),
            to: to.clone(),
        }),
        _ => Err(TurnProtocolError::AmbiguousGraphTransition {
            from: from.to_string(),
            choices: choices.to_vec(),
        }),
    }
}

fn derive_graph_speakers(
    graph: &SpeakerGraph,
    completed_turns: u64,
    status: &TurnProtocolStatus,
) -> Result<(Option<String>, Option<String>), TurnProtocolError> {
    let mut current = graph.initial_speaker.clone();
    let mut last = None;
    for step in 0..completed_turns {
        last = Some(current.clone());
        let accepted_turn_requires_successor =
            step + 1 < completed_turns || !matches!(status, TurnProtocolStatus::Completed { .. });
        if accepted_turn_requires_successor {
            let choices = graph
                .transitions
                .get(&current)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            current = match choices {
                [next] => next.clone(),
                [] => {
                    return Err(TurnProtocolError::CorruptState {
                        detail: format!(
                            "accepted graph turn from {current:?} lacks its durable successor"
                        ),
                    })
                }
                _ => {
                    return Err(TurnProtocolError::CorruptState {
                        detail: format!(
                            "accepted graph turn from {current:?} has an ambiguous successor"
                        ),
                    })
                }
            };
        }
    }
    Ok((last, status.is_active().then_some(current)))
}

fn counter_status_error(state: &TurnProtocolState) -> TurnProtocolError {
    TurnProtocolError::CounterStatusInconsistency {
        completed_turns: state.completed_turns,
        max_turns: state.definition.max_turns,
        status: state.status.clone(),
    }
}

fn store_binding(
    path: &Path,
    create_parent: bool,
) -> Result<(SafeRoot, OsString, PathBuf), TurnProtocolError> {
    let state_path = path.to_path_buf();
    let state_file = path
        .file_name()
        .filter(|name| {
            *name != OsStr::new("")
                && *name != OsStr::new(".")
                && *name != OsStr::new("..")
                && *name != OsStr::new(TURN_PROTOCOL_LOCK_FILE)
        })
        .map(OsStr::to_os_string)
        .ok_or_else(|| TurnProtocolError::InvalidStorePath {
            path: state_path.clone(),
        })?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let root = if create_parent {
        SafeRoot::open_or_create_managed(parent)
    } else {
        SafeRoot::open_existing(parent)
    }
    .map_err(|source| persistence_error("binding state directory", source))?;
    let normalized_path = root
        .direct_child(&state_file)
        .map_err(|source| persistence_error("resolving state path", source))?;
    Ok((root, state_file, normalized_path))
}

fn acquire_lock(root: &SafeRoot) -> Result<KernelStateLock, TurnProtocolError> {
    KernelStateLock::acquire_direct(root, TURN_PROTOCOL_LOCK_FILE)
        .map_err(|source| persistence_error("acquiring state lock", source))
}

fn read_state(
    root: &SafeRoot,
    state_file: &OsStr,
    state_path: &Path,
    lock: &KernelStateLock,
) -> Result<TurnProtocolState, TurnProtocolError> {
    lock.verify_direct_binding(root)
        .map_err(|source| persistence_error("verifying state lock before read", source))?;
    if !root
        .direct_child_exists(state_file)
        .map_err(|source| persistence_error("checking state existence", source))?
    {
        return Err(TurnProtocolError::StateMissing {
            path: state_path.to_path_buf(),
        });
    }
    let bytes = BoundedRegularReader::read_direct(root, state_file, HARD_MAX_STATE_BYTES)
        .map_err(|source| persistence_error("reading bounded state", source))?;
    lock.verify_direct_binding(root)
        .map_err(|source| persistence_error("verifying state lock after read", source))?;
    let document: PersistedTurnProtocolState =
        serde_json::from_slice(&bytes).map_err(|error| TurnProtocolError::CorruptState {
            detail: format!("state document is malformed: {error}"),
        })?;
    if document.version != TURN_PROTOCOL_STATE_VERSION {
        return Err(TurnProtocolError::IncompatibleStateVersion {
            found: u64::from(document.version),
            expected: TURN_PROTOCOL_STATE_VERSION,
        });
    }
    let state_bytes =
        serde_json::to_vec(&document.state).map_err(TurnProtocolError::Serialization)?;
    if checksum(&state_bytes) != document.checksum {
        return Err(TurnProtocolError::ChecksumMismatch);
    }
    document.state.validate()?;
    let actual = bytes.len();
    if actual as u64 > document.state.definition.limits.max_state_bytes {
        return Err(TurnProtocolError::StateByteLimitExceeded {
            actual,
            max: document.state.definition.limits.max_state_bytes,
        });
    }
    Ok(document.state)
}

fn write_state(
    root: &SafeRoot,
    state_file: &OsStr,
    lock: &KernelStateLock,
    state: &TurnProtocolState,
) -> Result<(), TurnProtocolError> {
    state.validate()?;
    let state_bytes = serde_json::to_vec(state).map_err(TurnProtocolError::Serialization)?;
    let document = PersistedTurnProtocolState {
        version: TURN_PROTOCOL_STATE_VERSION,
        checksum: checksum(&state_bytes),
        state: state.clone(),
    };
    let mut contents = serde_json::to_vec(&document).map_err(TurnProtocolError::Serialization)?;
    contents.push(b'\n');
    let actual = contents.len();
    if actual as u64 > state.definition.limits.max_state_bytes {
        return Err(TurnProtocolError::StateByteLimitExceeded {
            actual,
            max: state.definition.limits.max_state_bytes,
        });
    }
    lock.verify_direct_binding(root)
        .map_err(|source| persistence_error("verifying state lock before write", source))?;
    AtomicStateWriter::write_direct_fenced(root, state_file, &contents, || {
        lock.verify_direct_binding(root)
    })
    .map_err(|source| persistence_error("atomically replacing state", source))?;
    Ok(())
}

fn checksum(bytes: &[u8]) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in TURN_STATE_CHECKSUM_DOMAIN.iter().chain(bytes) {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

fn persistence_error(operation: &'static str, source: anyhow::Error) -> TurnProtocolError {
    TurnProtocolError::Persistence { operation, source }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn participant(id: &str, role: RoleCategory) -> TurnParticipant {
        TurnParticipant::new(id, role)
    }

    fn participants() -> Vec<TurnParticipant> {
        vec![
            participant("coordinator", RoleCategory::DelegatingCoordinator),
            participant("worker-a", RoleCategory::NonDelegatingTerminalWorker),
            participant("auditor", RoleCategory::ReadOnlyReviewAuditor),
        ]
    }

    fn definition(policy: TurnPolicy, max_turns: u64) -> TurnProtocolDefinition {
        TurnProtocolDefinition::new(
            "session-1",
            "protocol-1",
            participants(),
            policy,
            max_turns,
            TurnProtocolLimits::default(),
        )
        .expect("valid definition")
    }

    fn store_path(temp: &TempDir) -> PathBuf {
        temp.path().join("turn-state.json")
    }

    fn graph(transitions: &[(&str, &[&str])]) -> SpeakerGraph {
        SpeakerGraph::new(
            "coordinator",
            transitions
                .iter()
                .map(|(from, to)| {
                    (
                        (*from).to_string(),
                        to.iter().map(|value| (*value).to_string()).collect(),
                    )
                })
                .collect(),
        )
    }

    #[test]
    fn round_robin_rotates_without_changing_authority() {
        let temp = TempDir::new().expect("temp");
        let definition = definition(TurnPolicy::RoundRobin, 4);
        let mut store =
            TurnProtocolStore::create(store_path(&temp), definition).expect("create store");

        assert_eq!(store.state().current_speaker(), Some("coordinator"));
        let first = store
            .complete_turn("coordinator", TurnExpectation::new(0, 0))
            .expect("first completion");
        assert_eq!(first.next_speaker.as_deref(), Some("worker-a"));
        let second = store
            .complete_turn("worker-a", TurnExpectation::new(1, 1))
            .expect("second completion");
        assert_eq!(second.next_speaker.as_deref(), Some("auditor"));
        assert_eq!(
            store.state().participant_role("worker-a"),
            Some(RoleCategory::NonDelegatingTerminalWorker)
        );
        assert_eq!(
            store.state().participant_role("auditor"),
            Some(RoleCategory::ReadOnlyReviewAuditor)
        );
    }

    #[test]
    fn model_selected_requires_an_explicit_eligible_speaker() {
        let temp = TempDir::new().expect("temp");
        let definition = definition(TurnPolicy::ModelSelected, 2);
        let mut store =
            TurnProtocolStore::create(store_path(&temp), definition).expect("create store");

        assert!(matches!(
            store.complete_turn("worker-a", TurnExpectation::new(0, 0)),
            Err(TurnProtocolError::NoSpeakerSelected)
        ));
        assert!(matches!(
            store.select_speaker("outsider", TurnExpectation::new(0, 0)),
            Err(TurnProtocolError::InvalidSelection { .. })
        ));
        let selection = store
            .select_speaker("worker-a", TurnExpectation::new(0, 0))
            .expect("select worker");
        assert_eq!(selection.generation, 1);
        let completion = store
            .complete_turn("worker-a", TurnExpectation::new(0, 1))
            .expect("complete selected turn");
        assert_eq!(completion.next_speaker, None);
        assert_eq!(store.state().current_speaker(), None);
    }

    #[test]
    fn speaker_authorization_is_read_only_and_requires_current_selection() {
        let temp = TempDir::new().expect("temp");
        let path = store_path(&temp);
        let definition = definition(TurnPolicy::ModelSelected, 2);
        let mut store = TurnProtocolStore::create(&path, definition).expect("create store");
        let initial_bytes = std::fs::read(&path).expect("read initial state");
        let initial_expectation = store.state().expectation();

        assert!(matches!(
            store.authorize_speaker("worker-a", initial_expectation),
            Err(TurnProtocolError::NoSpeakerSelected)
        ));
        assert_eq!(std::fs::read(&path).expect("reread state"), initial_bytes);
        assert_eq!(store.state().expectation(), initial_expectation);

        store
            .select_speaker("worker-a", initial_expectation)
            .expect("select worker");
        let selected_expectation = store.state().expectation();
        let selected_bytes = std::fs::read(&path).expect("read selected state");
        assert!(matches!(
            store.authorize_speaker("auditor", selected_expectation),
            Err(TurnProtocolError::WrongSpeaker {
                selected_speaker,
                actual_speaker,
            }) if selected_speaker == "worker-a" && actual_speaker == "auditor"
        ));
        assert_eq!(
            std::fs::read(&path).expect("reread refused state"),
            selected_bytes
        );
        assert_eq!(store.state().expectation(), selected_expectation);

        store
            .authorize_speaker("worker-a", selected_expectation)
            .expect("authorize selected speaker");
        assert_eq!(
            std::fs::read(&path).expect("reread authorized state"),
            selected_bytes
        );
        assert_eq!(store.state().expectation(), selected_expectation);
    }

    #[test]
    fn free_form_requires_an_explicit_eligible_speaker() {
        let temp = TempDir::new().expect("temp");
        let definition = definition(TurnPolicy::FreeForm, 2);
        let mut store =
            TurnProtocolStore::create(store_path(&temp), definition).expect("create store");
        store
            .select_speaker("auditor", TurnExpectation::new(0, 0))
            .expect("select auditor");
        store
            .complete_turn("auditor", TurnExpectation::new(0, 1))
            .expect("complete free-form turn");
        store
            .select_speaker("coordinator", TurnExpectation::new(1, 2))
            .expect("select coordinator");
        let outcome = store
            .complete_turn("coordinator", TurnExpectation::new(1, 3))
            .expect("complete final turn");
        assert_eq!(
            outcome.status,
            TurnProtocolStatus::Completed {
                reason: TurnCompletionReason::MaximumTurnsReached
            }
        );
    }

    #[test]
    fn graph_selected_follows_one_deterministic_transition() {
        let temp = TempDir::new().expect("temp");
        let graph = graph(&[
            ("coordinator", &["worker-a"]),
            ("worker-a", &["auditor"]),
            ("auditor", &["coordinator"]),
        ]);
        let definition = definition(TurnPolicy::GraphSelected { graph }, 3);
        let mut store =
            TurnProtocolStore::create(store_path(&temp), definition).expect("create store");
        let first = store
            .complete_turn("coordinator", TurnExpectation::new(0, 0))
            .expect("graph completion");
        assert_eq!(first.next_speaker.as_deref(), Some("worker-a"));
        let second = store
            .complete_turn("worker-a", TurnExpectation::new(1, 1))
            .expect("graph completion");
        assert_eq!(second.next_speaker.as_deref(), Some("auditor"));
    }

    #[test]
    fn graph_missing_and_ambiguous_transitions_are_distinct() {
        let missing_temp = TempDir::new().expect("temp");
        let missing_definition = definition(TurnPolicy::GraphSelected { graph: graph(&[]) }, 2);
        let mut missing = TurnProtocolStore::create(store_path(&missing_temp), missing_definition)
            .expect("create missing graph store");
        assert!(matches!(
            missing.complete_turn("coordinator", TurnExpectation::new(0, 0)),
            Err(TurnProtocolError::MissingGraphTransition { .. })
        ));
        assert_eq!(missing.state().completed_turns(), 0);

        let ambiguous_temp = TempDir::new().expect("temp");
        let ambiguous_definition = definition(
            TurnPolicy::GraphSelected {
                graph: graph(&[("coordinator", &["worker-a", "auditor"])]),
            },
            2,
        );
        let mut ambiguous =
            TurnProtocolStore::create(store_path(&ambiguous_temp), ambiguous_definition)
                .expect("create ambiguous graph store");
        assert!(matches!(
            ambiguous.complete_turn("coordinator", TurnExpectation::new(0, 0)),
            Err(TurnProtocolError::AmbiguousGraphTransition { .. })
        ));
        assert_eq!(ambiguous.state().completed_turns(), 0);
    }

    #[test]
    fn invalid_graph_transition_and_participants_are_typed() {
        let invalid_graph = graph(&[("coordinator", &["outsider"])]);
        let error = TurnProtocolDefinition::new(
            "session-1",
            "protocol-1",
            participants(),
            TurnPolicy::GraphSelected {
                graph: invalid_graph,
            },
            2,
            TurnProtocolLimits::default(),
        )
        .expect_err("invalid graph");
        assert!(matches!(
            error,
            TurnDefinitionError::InvalidGraphTransition { .. }
        ));

        let duplicate = TurnProtocolDefinition::new(
            "session-1",
            "protocol-1",
            vec![
                participant("same", RoleCategory::DelegatingCoordinator),
                participant("same", RoleCategory::NonDelegatingTerminalWorker),
            ],
            TurnPolicy::RoundRobin,
            2,
            TurnProtocolLimits::default(),
        )
        .expect_err("duplicate participant");
        assert!(matches!(
            duplicate,
            TurnDefinitionError::DuplicateParticipant { .. }
        ));
    }

    #[test]
    fn wrong_speaker_stale_generation_and_stale_counter_are_distinct() {
        let temp = TempDir::new().expect("temp");
        let definition = definition(TurnPolicy::RoundRobin, 3);
        let mut store =
            TurnProtocolStore::create(store_path(&temp), definition).expect("create store");
        assert!(matches!(
            store.complete_turn("worker-a", TurnExpectation::new(0, 0)),
            Err(TurnProtocolError::WrongSpeaker { .. })
        ));
        assert!(matches!(
            store.complete_turn("coordinator", TurnExpectation::new(0, 1)),
            Err(TurnProtocolError::StaleGeneration {
                expected: 1,
                actual: 0
            })
        ));
        assert!(matches!(
            store.complete_turn("coordinator", TurnExpectation::new(1, 0)),
            Err(TurnProtocolError::StaleCompletedTurnCounter {
                expected: 1,
                actual: 0
            })
        ));
    }

    #[test]
    fn accepted_completion_is_not_repeated_after_reopen() {
        let temp = TempDir::new().expect("temp");
        let path = store_path(&temp);
        let definition = definition(TurnPolicy::RoundRobin, 3);
        {
            let mut store =
                TurnProtocolStore::create(&path, definition.clone()).expect("create store");
            store
                .complete_turn("coordinator", TurnExpectation::new(0, 0))
                .expect("complete first turn");
        }

        let mut reopened = TurnProtocolStore::open(&path, &definition).expect("reopen");
        assert_eq!(reopened.state().completed_turns(), 1);
        assert_eq!(reopened.state().current_speaker(), Some("worker-a"));
        assert!(matches!(
            reopened.complete_turn("coordinator", TurnExpectation::new(0, 0)),
            Err(TurnProtocolError::DoubleCompletion { .. })
        ));
        assert_eq!(reopened.state().completed_turns(), 1);
    }

    #[test]
    fn explicit_termination_is_durable_and_typed() {
        let temp = TempDir::new().expect("temp");
        let path = store_path(&temp);
        let definition = definition(TurnPolicy::RoundRobin, 3);
        let mut store = TurnProtocolStore::create(&path, definition.clone()).expect("create store");
        let terminated = store
            .terminate("operator requested stop", TurnExpectation::new(0, 0))
            .expect("terminate");
        assert!(matches!(
            terminated.status,
            TurnProtocolStatus::Terminated { .. }
        ));
        drop(store);

        let mut reopened = TurnProtocolStore::open(&path, &definition).expect("reopen");
        assert!(matches!(
            reopened.complete_turn("coordinator", TurnExpectation::new(0, 1)),
            Err(TurnProtocolError::NotActive {
                status: TurnProtocolStatus::Terminated { .. }
            })
        ));
    }

    #[test]
    fn maximum_turn_completion_is_durable_even_without_graph_successor() {
        let temp = TempDir::new().expect("temp");
        let path = store_path(&temp);
        let definition = definition(TurnPolicy::GraphSelected { graph: graph(&[]) }, 1);
        let mut store = TurnProtocolStore::create(&path, definition.clone()).expect("create store");
        let outcome = store
            .complete_turn("coordinator", TurnExpectation::new(0, 0))
            .expect("final completion");
        assert_eq!(
            outcome.status,
            TurnProtocolStatus::Completed {
                reason: TurnCompletionReason::MaximumTurnsReached
            }
        );
        drop(store);
        let reopened = TurnProtocolStore::open(&path, &definition).expect("reopen");
        assert_eq!(reopened.state().completed_turns(), 1);
        assert_eq!(reopened.state().current_speaker(), None);
    }

    #[test]
    fn completed_selection_driven_state_rejects_a_pending_selection_count() {
        let definition = definition(TurnPolicy::ModelSelected, 1);
        let mut state = TurnProtocolState::initial(definition);
        state.status = TurnProtocolStatus::Completed {
            reason: TurnCompletionReason::MaximumTurnsReached,
        };
        state.selected_speaker = None;
        state.current_speaker = None;
        state.last_speaker = Some("worker-a".to_string());
        state.completed_turns = 1;
        state.selection_count = 2;
        state.generation = 3;
        state.last_completion = Some(TurnCompletionReceipt {
            speaker_id: "worker-a".to_string(),
            expected: TurnExpectation::new(0, 1),
            completed_turns_after: 1,
            generation_after: 2,
        });

        assert!(matches!(
            state.validate(),
            Err(TurnProtocolError::CorruptState { detail })
                if detail.contains("selection count")
        ));
    }

    #[test]
    fn selection_driven_receipt_generation_is_exact_after_later_selection_and_termination() {
        let temp = TempDir::new().expect("temp");
        let definition = definition(TurnPolicy::FreeForm, 3);
        let mut store =
            TurnProtocolStore::create(store_path(&temp), definition).expect("create store");
        store
            .select_speaker("worker-a", TurnExpectation::new(0, 0))
            .expect("select first speaker");
        store
            .complete_turn("worker-a", TurnExpectation::new(0, 1))
            .expect("complete first speaker");
        store
            .select_speaker("auditor", TurnExpectation::new(1, 2))
            .expect("select pending speaker");
        store
            .terminate("operator stop", TurnExpectation::new(1, 3))
            .expect("terminate with pending speaker");

        let mut state = store.state().clone();
        let receipt = state
            .last_completion
            .as_mut()
            .expect("completed state receipt");
        receipt.expected.generation = 2;
        receipt.generation_after = 3;

        assert!(matches!(
            state.validate(),
            Err(TurnProtocolError::CorruptState { detail })
                if detail.contains("last completion receipt")
        ));
    }

    #[test]
    fn terminated_graph_state_requires_the_last_accepted_successor() {
        let definition = definition(TurnPolicy::GraphSelected { graph: graph(&[]) }, 2);
        let mut state = TurnProtocolState::initial(definition);
        state.status = TurnProtocolStatus::Terminated {
            reason: "operator stop".to_string(),
        };
        state.selected_speaker = None;
        state.current_speaker = None;
        state.last_speaker = Some("coordinator".to_string());
        state.completed_turns = 1;
        state.generation = 2;
        state.last_completion = Some(TurnCompletionReceipt {
            speaker_id: "coordinator".to_string(),
            expected: TurnExpectation::new(0, 0),
            completed_turns_after: 1,
            generation_after: 1,
        });

        assert!(matches!(
            state.validate(),
            Err(TurnProtocolError::CorruptState { detail })
                if detail.contains("lacks its durable successor")
        ));
    }

    #[test]
    fn corrupt_checksum_and_counter_status_are_distinct() {
        let checksum_temp = TempDir::new().expect("temp");
        let checksum_path = store_path(&checksum_temp);
        let definition = definition(TurnPolicy::RoundRobin, 2);
        TurnProtocolStore::create(&checksum_path, definition.clone()).expect("create store");
        let mut bytes = std::fs::read(&checksum_path).expect("read state");
        let position = bytes
            .iter()
            .position(|byte| *byte == b's')
            .expect("state byte");
        bytes[position] = b'x';
        std::fs::write(&checksum_path, bytes).expect("corrupt checksum");
        assert!(matches!(
            TurnProtocolStore::open(&checksum_path, &definition),
            Err(TurnProtocolError::CorruptState { .. }) | Err(TurnProtocolError::ChecksumMismatch)
        ));

        let counter_temp = TempDir::new().expect("temp");
        let counter_path = store_path(&counter_temp);
        TurnProtocolStore::create(&counter_path, definition.clone()).expect("create store");
        let bytes = std::fs::read(&counter_path).expect("read state");
        let mut document: PersistedTurnProtocolState =
            serde_json::from_slice(&bytes).expect("parse document");
        document.state.completed_turns = document.state.definition.max_turns;
        let state_bytes = serde_json::to_vec(&document.state).expect("serialize state");
        document.checksum = checksum(&state_bytes);
        std::fs::write(
            &counter_path,
            serde_json::to_vec(&document).expect("serialize document"),
        )
        .expect("write inconsistent document");
        assert!(matches!(
            TurnProtocolStore::open(&counter_path, &definition),
            Err(TurnProtocolError::CounterStatusInconsistency { .. })
        ));

        let terminated_temp = TempDir::new().expect("temp");
        let terminated_path = store_path(&terminated_temp);
        TurnProtocolStore::create(&terminated_path, definition.clone()).expect("create store");
        let bytes = std::fs::read(&terminated_path).expect("read state");
        let mut document: PersistedTurnProtocolState =
            serde_json::from_slice(&bytes).expect("parse document");
        document.state.completed_turns = document.state.definition.max_turns;
        document.state.generation = document.state.completed_turns + 1;
        document.state.status = TurnProtocolStatus::Terminated {
            reason: "corrupt terminal state".to_string(),
        };
        let state_bytes = serde_json::to_vec(&document.state).expect("serialize state");
        document.checksum = checksum(&state_bytes);
        std::fs::write(
            &terminated_path,
            serde_json::to_vec(&document).expect("serialize document"),
        )
        .expect("write inconsistent terminated document");
        assert!(matches!(
            TurnProtocolStore::open(&terminated_path, &definition),
            Err(TurnProtocolError::CounterStatusInconsistency { .. })
        ));
    }

    #[test]
    fn strict_document_rejects_unknown_fields_and_reserved_lock_name() {
        let temp = TempDir::new().expect("temp");
        let path = store_path(&temp);
        let definition = definition(TurnPolicy::RoundRobin, 2);
        TurnProtocolStore::create(&path, definition.clone()).expect("create store");
        let bytes = std::fs::read(&path).expect("read state");
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).expect("parse JSON");
        value
            .as_object_mut()
            .expect("document object")
            .insert("unknown".to_string(), serde_json::json!(true));
        std::fs::write(&path, serde_json::to_vec(&value).expect("serialize JSON"))
            .expect("write unknown field");
        assert!(matches!(
            TurnProtocolStore::open(&path, &definition),
            Err(TurnProtocolError::CorruptState { .. })
        ));

        let reserved = temp.path().join(TURN_PROTOCOL_LOCK_FILE);
        assert!(matches!(
            TurnProtocolStore::create(reserved, definition),
            Err(TurnProtocolError::InvalidStorePath { .. })
        ));
    }

    #[test]
    fn incompatible_version_and_definition_mismatch_fail_closed() {
        let temp = TempDir::new().expect("temp");
        let path = store_path(&temp);
        let definition = definition(TurnPolicy::RoundRobin, 2);
        TurnProtocolStore::create(&path, definition.clone()).expect("create store");

        let alternate = TurnProtocolDefinition::new(
            "session-2",
            "protocol-1",
            participants(),
            TurnPolicy::RoundRobin,
            2,
            TurnProtocolLimits::default(),
        )
        .expect("alternate definition");
        assert!(matches!(
            TurnProtocolStore::open(&path, &alternate),
            Err(TurnProtocolError::DefinitionMismatch)
        ));

        let bytes = std::fs::read(&path).expect("read state");
        let mut document: PersistedTurnProtocolState =
            serde_json::from_slice(&bytes).expect("parse document");
        document.version += 1;
        std::fs::write(
            &path,
            serde_json::to_vec(&document).expect("serialize document"),
        )
        .expect("write version");
        assert!(matches!(
            TurnProtocolStore::open(&path, &definition),
            Err(TurnProtocolError::IncompatibleStateVersion { .. })
        ));
    }

    #[test]
    fn concurrent_handles_reload_latest_snapshot_before_mutation() {
        let temp = TempDir::new().expect("temp");
        let path = store_path(&temp);
        let definition = definition(TurnPolicy::RoundRobin, 3);
        let mut first = TurnProtocolStore::create(&path, definition.clone()).expect("create store");
        let mut stale = TurnProtocolStore::open(&path, &definition).expect("second handle");
        first
            .complete_turn("coordinator", TurnExpectation::new(0, 0))
            .expect("complete first");
        assert!(matches!(
            stale.complete_turn("worker-a", TurnExpectation::new(0, 0)),
            Err(TurnProtocolError::StaleGeneration {
                expected: 0,
                actual: 1
            })
        ));
        assert_eq!(stale.state().completed_turns(), 1);
    }
}
