//! Provider-neutral coordination records reconstructed from complete forge threads.
//!
//! This module is an optional remote coordination substrate. It neither replaces
//! the local [`crate::sync_store::SyncStore`] nor chooses a forge provider.

use super::forge_transport::{
    AppendCommentEffect, ForgeActor, ForgeComment, ForgeEffectRequest, ForgeItem, ForgeTimestamp,
    ItemThreadObservation, ProviderObjectId, ProviderObjectKind,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};

const MARKER: &str = "<!-- maco:forge-coordination:v1 -->";
const END_MARKER: &str = "<!-- /maco:forge-coordination:v1 -->";
const MARKER_START: &str = "<!-- maco:forge-coordination";
const END_MARKER_START: &str = "<!-- /maco:forge-coordination";
const MARKER_TOKEN: &str = "maco:forge-coordination";
const SCHEMA: &str = "maco.forge-coordination";
const VERSION: u32 = 1;
const MAX_TRUSTED_ACTORS: usize = 64;
const MAX_COORDINATION_RECORDS: usize = 512;
const MAX_RECORD_BODY_BYTES: usize = 16 * 1024;
const MAX_ID_BYTES: usize = 96;
const MAX_SCOPE_COUNT: usize = 64;
const MAX_SCOPE_BYTES: usize = 256;
const MAX_RELEASE_REASON_BYTES: usize = 512;
const MAX_STATE_MESSAGE_BYTES: usize = 2 * 1024;
const MIN_STALE_AFTER_SECONDS: u64 = 60;
const MAX_STALE_AFTER_SECONDS: u64 = 7 * 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentPhase {
    Starting,
    Working,
    Blocked,
    Complete,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoordinationRecord {
    schema: &'static str,
    version: u32,
    repository_id: ProviderObjectId,
    item_id: ProviderObjectId,
    event_id: String,
    action: CoordinationAction,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CoordinationRecordWire {
    schema: String,
    version: u32,
    repository_id: ProviderObjectId,
    item_id: ProviderObjectId,
    event_id: String,
    action: CoordinationActionWire,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum CoordinationAction {
    Claim {
        claim_id: String,
        agent_id: String,
        activation_nonce: String,
        scopes: Vec<String>,
        stale_after_seconds: u64,
        supersedes: Option<String>,
    },
    Heartbeat {
        claim_id: String,
        agent_id: String,
        activation_nonce: String,
    },
    Release {
        claim_id: String,
        agent_id: String,
        activation_nonce: String,
        reason: String,
    },
    AgentState {
        agent_id: String,
        activation_nonce: String,
        sequence: u64,
        phase: AgentPhase,
        message: Option<String>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum CoordinationActionWire {
    Claim {
        claim_id: String,
        agent_id: String,
        activation_nonce: String,
        scopes: Vec<String>,
        stale_after_seconds: u64,
        #[serde(deserialize_with = "required_nullable")]
        supersedes: Option<String>,
    },
    Heartbeat {
        claim_id: String,
        agent_id: String,
        activation_nonce: String,
    },
    Release {
        claim_id: String,
        agent_id: String,
        activation_nonce: String,
        reason: String,
    },
    AgentState {
        agent_id: String,
        activation_nonce: String,
        sequence: u64,
        phase: AgentPhase,
        #[serde(deserialize_with = "required_nullable")]
        message: Option<String>,
    },
}

impl CoordinationRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn claim(
        item: &ForgeItem,
        event_id: impl Into<String>,
        claim_id: impl Into<String>,
        agent_id: impl Into<String>,
        activation_nonce: impl Into<String>,
        scopes: Vec<String>,
        stale_after_seconds: u64,
        supersedes: Option<String>,
    ) -> Result<Self> {
        Self::new(
            item,
            event_id,
            CoordinationAction::Claim {
                claim_id: claim_id.into(),
                agent_id: agent_id.into(),
                activation_nonce: activation_nonce.into(),
                scopes,
                stale_after_seconds,
                supersedes,
            },
        )
    }

    pub fn heartbeat(
        item: &ForgeItem,
        event_id: impl Into<String>,
        claim_id: impl Into<String>,
        agent_id: impl Into<String>,
        activation_nonce: impl Into<String>,
    ) -> Result<Self> {
        Self::new(
            item,
            event_id,
            CoordinationAction::Heartbeat {
                claim_id: claim_id.into(),
                agent_id: agent_id.into(),
                activation_nonce: activation_nonce.into(),
            },
        )
    }

    pub fn release(
        item: &ForgeItem,
        event_id: impl Into<String>,
        claim_id: impl Into<String>,
        agent_id: impl Into<String>,
        activation_nonce: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<Self> {
        Self::new(
            item,
            event_id,
            CoordinationAction::Release {
                claim_id: claim_id.into(),
                agent_id: agent_id.into(),
                activation_nonce: activation_nonce.into(),
                reason: reason.into(),
            },
        )
    }

    pub fn agent_state(
        item: &ForgeItem,
        event_id: impl Into<String>,
        agent_id: impl Into<String>,
        activation_nonce: impl Into<String>,
        sequence: u64,
        phase: AgentPhase,
        message: Option<String>,
    ) -> Result<Self> {
        Self::new(
            item,
            event_id,
            CoordinationAction::AgentState {
                agent_id: agent_id.into(),
                activation_nonce: activation_nonce.into(),
                sequence,
                phase,
                message,
            },
        )
    }

    fn new(
        item: &ForgeItem,
        event_id: impl Into<String>,
        action: CoordinationAction,
    ) -> Result<Self> {
        let value = Self {
            schema: SCHEMA,
            version: VERSION,
            repository_id: item.repository().provider_repository_id().clone(),
            item_id: item.provider_item_id().clone(),
            event_id: event_id.into(),
            action,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    pub fn render(&self) -> Result<String> {
        self.validate()?;
        let json = serde_json::to_string(self).context("failed to render coordination record")?;
        let body = format!("{MARKER}\n{json}\n{END_MARKER}");
        if body.len() > MAX_RECORD_BODY_BYTES {
            bail!("coordination record exceeds its body byte limit");
        }
        Ok(body)
    }

    fn from_wire(wire: CoordinationRecordWire) -> Result<Self> {
        if wire.schema != SCHEMA || wire.version != VERSION {
            bail!("coordination record has an unsupported schema or version");
        }
        let action = match wire.action {
            CoordinationActionWire::Claim {
                claim_id,
                agent_id,
                activation_nonce,
                scopes,
                stale_after_seconds,
                supersedes,
            } => CoordinationAction::Claim {
                claim_id,
                agent_id,
                activation_nonce,
                scopes,
                stale_after_seconds,
                supersedes,
            },
            CoordinationActionWire::Heartbeat {
                claim_id,
                agent_id,
                activation_nonce,
            } => CoordinationAction::Heartbeat {
                claim_id,
                agent_id,
                activation_nonce,
            },
            CoordinationActionWire::Release {
                claim_id,
                agent_id,
                activation_nonce,
                reason,
            } => CoordinationAction::Release {
                claim_id,
                agent_id,
                activation_nonce,
                reason,
            },
            CoordinationActionWire::AgentState {
                agent_id,
                activation_nonce,
                sequence,
                phase,
                message,
            } => CoordinationAction::AgentState {
                agent_id,
                activation_nonce,
                sequence,
                phase,
                message,
            },
        };
        let value = Self {
            schema: SCHEMA,
            version: VERSION,
            repository_id: wire.repository_id,
            item_id: wire.item_id,
            event_id: wire.event_id,
            action,
        };
        value.validate()?;
        Ok(value)
    }

    fn parse(body: &str) -> Result<Option<Self>> {
        if !body.starts_with(MARKER_START) && !body.starts_with(END_MARKER_START) {
            return Ok(None);
        }
        if body.len() > MAX_RECORD_BODY_BYTES {
            bail!("coordination marker body exceeds its byte limit");
        }
        let json = body
            .strip_prefix(MARKER)
            .and_then(|value| value.strip_prefix('\n'))
            .and_then(|value| value.strip_suffix(END_MARKER))
            .and_then(|value| value.strip_suffix('\n'))
            .context("coordination marker envelope is not canonical")?;
        if json.is_empty() || json.contains('\n') || json.as_bytes().contains(&0) {
            bail!("coordination marker payload is empty or non-canonical");
        }
        let wire: CoordinationRecordWire = serde_json::from_str(json)
            .context("coordination marker payload is not strict valid JSON")?;
        let record = Self::from_wire(wire)?;
        if record.render()? != body {
            bail!("coordination marker JSON is not in canonical form");
        }
        Ok(Some(record))
    }

    fn validate(&self) -> Result<()> {
        if self.schema != SCHEMA || self.version != VERSION {
            bail!("coordination record has an unsupported schema or version");
        }
        if self.repository_id.kind() != ProviderObjectKind::Repository
            || self.item_id.kind() != ProviderObjectKind::Item
            || self.repository_id.provider_id() != self.item_id.provider_id()
        {
            bail!("coordination record target is not one provider-bound repository item");
        }
        validate_id(&self.event_id, "coordination event id")?;
        match &self.action {
            CoordinationAction::Claim {
                claim_id,
                agent_id,
                activation_nonce,
                scopes,
                stale_after_seconds,
                supersedes,
            } => {
                validate_id(claim_id, "claim id")?;
                validate_id(agent_id, "claim agent id")?;
                validate_id(activation_nonce, "claim activation nonce")?;
                validate_scopes(scopes)?;
                if !(MIN_STALE_AFTER_SECONDS..=MAX_STALE_AFTER_SECONDS)
                    .contains(stale_after_seconds)
                {
                    bail!("claim stale threshold is outside its bounded range");
                }
                if let Some(predecessor) = supersedes {
                    validate_id(predecessor, "superseded claim id")?;
                    if predecessor == claim_id {
                        bail!("claim cannot supersede itself");
                    }
                }
            }
            CoordinationAction::Heartbeat {
                claim_id,
                agent_id,
                activation_nonce,
            } => validate_claim_reference(claim_id, agent_id, activation_nonce)?,
            CoordinationAction::Release {
                claim_id,
                agent_id,
                activation_nonce,
                reason,
            } => {
                validate_claim_reference(claim_id, agent_id, activation_nonce)?;
                validate_text(reason, "release reason", MAX_RELEASE_REASON_BYTES, false)?;
            }
            CoordinationAction::AgentState {
                agent_id,
                activation_nonce,
                sequence,
                message,
                ..
            } => {
                validate_id(agent_id, "state agent id")?;
                validate_id(activation_nonce, "state activation nonce")?;
                if *sequence == 0 {
                    bail!("agent state sequence must be positive");
                }
                if let Some(message) = message {
                    validate_text(
                        message,
                        "agent state message",
                        MAX_STATE_MESSAGE_BYTES,
                        true,
                    )?;
                }
            }
        }
        Ok(())
    }

    fn require_target(&self, item: &ForgeItem) -> Result<()> {
        if self.repository_id != *item.repository().provider_repository_id()
            || self.item_id != *item.provider_item_id()
        {
            bail!("coordination record targets a different stable repository item");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordProvenance {
    provider_comment_id: ProviderObjectId,
    actor: ForgeActor,
    created_at: ForgeTimestamp,
    url: String,
}

impl RecordProvenance {
    pub fn provider_comment_id(&self) -> &ProviderObjectId {
        &self.provider_comment_id
    }

    pub fn actor(&self) -> &ForgeActor {
        &self.actor
    }

    pub fn created_at(&self) -> &ForgeTimestamp {
        &self.created_at
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    fn from_comment(comment: &ForgeComment) -> Self {
        Self {
            provider_comment_id: comment.provider_comment_id().clone(),
            actor: comment.author().clone(),
            created_at: comment.created_at().clone(),
            url: comment.url().to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimStatus {
    Active,
    Released,
    Superseded,
    Conflict,
    InvalidTakeover,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgeClaimState {
    claim_id: String,
    agent_id: String,
    activation_nonce: String,
    scopes: Vec<String>,
    stale_after_seconds: u64,
    supersedes: Option<String>,
    superseded_by: Option<String>,
    status: ClaimStatus,
    conflicts_with: Option<String>,
    activation: RecordProvenance,
    last_heartbeat: RecordProvenance,
    terminal: Option<RecordProvenance>,
    stale_at_observation: bool,
}

impl ForgeClaimState {
    pub fn claim_id(&self) -> &str {
        &self.claim_id
    }

    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    pub fn activation_nonce(&self) -> &str {
        &self.activation_nonce
    }

    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    pub fn stale_after_seconds(&self) -> u64 {
        self.stale_after_seconds
    }

    pub fn supersedes(&self) -> Option<&str> {
        self.supersedes.as_deref()
    }

    pub fn superseded_by(&self) -> Option<&str> {
        self.superseded_by.as_deref()
    }

    pub fn status(&self) -> ClaimStatus {
        self.status
    }

    pub fn conflicts_with(&self) -> Option<&str> {
        self.conflicts_with.as_deref()
    }

    pub fn activation(&self) -> &RecordProvenance {
        &self.activation
    }

    pub fn last_heartbeat(&self) -> &RecordProvenance {
        &self.last_heartbeat
    }

    pub fn terminal(&self) -> Option<&RecordProvenance> {
        self.terminal.as_ref()
    }

    pub fn is_stale_at_observation(&self) -> bool {
        self.stale_at_observation
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgeAgentState {
    agent_id: String,
    activation_nonce: String,
    sequence: u64,
    phase: AgentPhase,
    message: Option<String>,
    provenance: RecordProvenance,
}

impl ForgeAgentState {
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    pub fn activation_nonce(&self) -> &str {
        &self.activation_nonce
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn phase(&self) -> AgentPhase {
        self.phase
    }

    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    pub fn provenance(&self) -> &RecordProvenance {
        &self.provenance
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinationSnapshot {
    observed_at: ForgeTimestamp,
    claims: Vec<ForgeClaimState>,
    agents: Vec<ForgeAgentState>,
    records: Vec<AcceptedRecord>,
    dispositions: Vec<RecordDisposition>,
}

impl CoordinationSnapshot {
    pub fn observed_at(&self) -> &ForgeTimestamp {
        &self.observed_at
    }

    pub fn claims(&self) -> &[ForgeClaimState] {
        &self.claims
    }

    pub fn agents(&self) -> &[ForgeAgentState] {
        &self.agents
    }

    pub fn accepted_record_count(&self) -> usize {
        self.records.len()
    }

    pub fn records(&self) -> &[AcceptedRecord] {
        &self.records
    }

    pub fn replayed_record_count(&self) -> usize {
        self.dispositions
            .iter()
            .filter(|disposition| disposition.kind == RecordDispositionKind::Replay)
            .count()
    }

    pub fn ignored_losing_nonce_count(&self) -> usize {
        self.dispositions
            .iter()
            .filter(|disposition| disposition.kind == RecordDispositionKind::LosingActivationNonce)
            .count()
    }

    pub fn dispositions(&self) -> &[RecordDisposition] {
        &self.dispositions
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedRecord {
    event_id: String,
    provenance: RecordProvenance,
}

impl AcceptedRecord {
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    pub fn provenance(&self) -> &RecordProvenance {
        &self.provenance
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordDispositionKind {
    Replay,
    LosingActivationNonce,
    ObsoleteLineageMutation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordDisposition {
    kind: RecordDispositionKind,
    event_id: String,
    provenance: RecordProvenance,
}

impl RecordDisposition {
    pub fn kind(&self) -> RecordDispositionKind {
        self.kind
    }

    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    pub fn provenance(&self) -> &RecordProvenance {
        &self.provenance
    }
}

#[derive(Debug, Clone)]
pub struct ForgeCoordinationEngine {
    provider_id: String,
    trusted_actors: BTreeMap<ProviderObjectId, ForgeActor>,
}

impl ForgeCoordinationEngine {
    pub fn new(trusted_actors: Vec<ForgeActor>) -> Result<Self> {
        if trusted_actors.is_empty() || trusted_actors.len() > MAX_TRUSTED_ACTORS {
            bail!("forge coordination requires a bounded non-empty trusted actor allowlist");
        }
        let provider_id = trusted_actors
            .first()
            .map(|actor| actor.provider_id().to_string())
            .context("trusted actor allowlist unexpectedly became empty")?;
        let mut actors = BTreeMap::new();
        for actor in trusted_actors {
            if actor.provider_id() != provider_id {
                bail!("trusted actors must belong to one exact forge provider");
            }
            match actors.entry(actor.provider_actor_id().clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(actor);
                }
                Entry::Occupied(entry) if entry.get() == &actor => {
                    bail!("trusted actor allowlist contains a duplicate actor");
                }
                Entry::Occupied(_) => {
                    bail!("trusted actor allowlist is ambiguous for one provider actor id");
                }
            }
        }
        Ok(Self {
            provider_id,
            trusted_actors: actors,
        })
    }

    pub fn prepare_effect(
        &self,
        item: ForgeItem,
        expected_actor: ForgeActor,
        record: &CoordinationRecord,
    ) -> Result<ForgeEffectRequest> {
        self.require_trusted_actor(&expected_actor)?;
        if item.repository().provider_id() != self.provider_id {
            bail!("coordination effect item belongs to a different forge provider");
        }
        record.require_target(&item)?;
        let body = record.render()?;
        let effect_binding = serde_json::to_vec(&(
            SCHEMA,
            VERSION,
            &record.repository_id,
            &record.item_id,
            record.event_id(),
        ))
        .context("failed to bind coordination effect identity")?;
        let effect_identity = crate::artifacts::state_auth::sha256_hex(&effect_binding);
        let effect = AppendCommentEffect::new(
            format!("coord-v1:{effect_identity}"),
            item,
            expected_actor,
            body,
        )?;
        ForgeEffectRequest::append_comment(effect)
    }

    pub fn reconstruct(&self, observation: &ItemThreadObservation) -> Result<CoordinationSnapshot> {
        if observation.item().repository().provider_id() != self.provider_id {
            bail!("coordination observation belongs to a different forge provider");
        }
        let (records, mut dispositions) = self.parse_records(observation)?;
        let claim_model = ClaimModel::new(&records)?;
        let (mut claims, claim_dispositions) = reduce_claims(&records, &claim_model)?;
        dispositions.extend(claim_dispositions);
        let observed_seconds = timestamp_seconds(observation.observed_at())?;
        for claim in claims.values_mut() {
            claim.stale_at_observation = claim.status == ClaimStatus::Active
                && elapsed_at_least(
                    timestamp_seconds(&claim.last_heartbeat.created_at)?,
                    observed_seconds,
                    claim.stale_after_seconds,
                )?;
        }
        let (agents, state_dispositions) = reduce_agent_states(&records, &claim_model, &claims)?;
        dispositions.extend(state_dispositions);
        dispositions.sort_by(|left, right| {
            provenance_key(&left.provenance)
                .cmp(&provenance_key(&right.provenance))
                .then_with(|| left.event_id.cmp(&right.event_id))
        });
        let mut accepted_records = records
            .iter()
            .map(|record| AcceptedRecord {
                event_id: record.record.event_id.clone(),
                provenance: record.provenance.clone(),
            })
            .collect::<Vec<_>>();
        accepted_records.sort_by(|left, right| {
            provenance_key(&left.provenance)
                .cmp(&provenance_key(&right.provenance))
                .then_with(|| left.event_id.cmp(&right.event_id))
        });
        Ok(CoordinationSnapshot {
            observed_at: observation.observed_at().clone(),
            claims: claims.into_values().collect(),
            agents: agents.into_values().collect(),
            records: accepted_records,
            dispositions,
        })
    }

    fn require_trusted_actor(&self, actor: &ForgeActor) -> Result<()> {
        if self
            .trusted_actors
            .get(actor.provider_actor_id())
            .is_none_or(|trusted| trusted != actor)
        {
            bail!("coordination record actor is not in the exact trusted actor allowlist");
        }
        Ok(())
    }

    fn parse_records(
        &self,
        observation: &ItemThreadObservation,
    ) -> Result<(Vec<ObservedRecord>, Vec<RecordDisposition>)> {
        let mut by_event = BTreeMap::<String, ObservedRecord>::new();
        let mut dispositions = Vec::new();
        let mut marker_count = 0_usize;
        for comment in observation.comments() {
            let Some(record) = CoordinationRecord::parse(comment.body())? else {
                continue;
            };
            record.require_target(observation.item())?;
            marker_count = marker_count.saturating_add(1);
            if marker_count > MAX_COORDINATION_RECORDS {
                bail!("coordination thread exceeds its record count limit");
            }
            self.require_trusted_actor(comment.author())?;
            let observed = ObservedRecord {
                record,
                provenance: RecordProvenance::from_comment(comment),
            };
            match by_event.entry(observed.record.event_id.clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(observed);
                }
                Entry::Occupied(mut entry)
                    if entry.get().record == observed.record
                        && entry.get().provenance.actor == observed.provenance.actor =>
                {
                    if provenance_key(&observed.provenance)
                        < provenance_key(&entry.get().provenance)
                    {
                        let replay = entry.insert(observed);
                        dispositions.push(RecordDisposition {
                            kind: RecordDispositionKind::Replay,
                            event_id: replay.record.event_id.clone(),
                            provenance: replay.provenance,
                        });
                    } else {
                        dispositions.push(RecordDisposition {
                            kind: RecordDispositionKind::Replay,
                            event_id: observed.record.event_id.clone(),
                            provenance: observed.provenance,
                        });
                    }
                }
                Entry::Occupied(_) => {
                    bail!("coordination event id is ambiguously reused");
                }
            }
        }
        Ok((by_event.into_values().collect(), dispositions))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ObservedRecord {
    record: CoordinationRecord,
    provenance: RecordProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClaimDefinition {
    agent_id: String,
    scopes: Vec<String>,
    stale_after_seconds: u64,
    supersedes: Option<String>,
    winning_nonce: String,
}

#[derive(Debug)]
struct ClaimModel {
    definitions: BTreeMap<String, ClaimDefinition>,
    activations: BTreeMap<(String, String), ObservedRecord>,
    replay_dispositions: Vec<RecordDisposition>,
}

impl ClaimModel {
    fn new(records: &[ObservedRecord]) -> Result<Self> {
        let mut definitions = BTreeMap::<String, ClaimDefinition>::new();
        let mut activations = BTreeMap::<(String, String), ObservedRecord>::new();
        let mut replay_dispositions = Vec::new();
        for observed in records {
            let CoordinationAction::Claim {
                claim_id,
                agent_id,
                activation_nonce,
                scopes,
                stale_after_seconds,
                supersedes,
            } = &observed.record.action
            else {
                continue;
            };
            let candidate = ClaimDefinition {
                agent_id: agent_id.clone(),
                scopes: scopes.clone(),
                stale_after_seconds: *stale_after_seconds,
                supersedes: supersedes.clone(),
                winning_nonce: activation_nonce.clone(),
            };
            match definitions.entry(claim_id.clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(candidate);
                }
                Entry::Occupied(mut entry) => {
                    let current = entry.get_mut();
                    if current.agent_id != candidate.agent_id
                        || current.scopes != candidate.scopes
                        || current.stale_after_seconds != candidate.stale_after_seconds
                        || current.supersedes != candidate.supersedes
                    {
                        bail!("one claim id has ambiguous activation definitions");
                    }
                    if candidate.winning_nonce < current.winning_nonce {
                        current.winning_nonce = candidate.winning_nonce;
                    }
                }
            }
            let key = (claim_id.clone(), activation_nonce.clone());
            match activations.entry(key) {
                Entry::Vacant(entry) => {
                    entry.insert(observed.clone());
                }
                Entry::Occupied(mut entry)
                    if entry.get().record.action == observed.record.action
                        && entry.get().provenance.actor == observed.provenance.actor =>
                {
                    if provenance_key(&observed.provenance)
                        < provenance_key(&entry.get().provenance)
                    {
                        let replay = entry.insert(observed.clone());
                        replay_dispositions.push(RecordDisposition {
                            kind: RecordDispositionKind::Replay,
                            event_id: replay.record.event_id,
                            provenance: replay.provenance,
                        });
                    } else {
                        replay_dispositions.push(RecordDisposition {
                            kind: RecordDispositionKind::Replay,
                            event_id: observed.record.event_id.clone(),
                            provenance: observed.provenance.clone(),
                        });
                    }
                }
                Entry::Occupied(_) => {
                    bail!("one claim activation nonce has ambiguous records");
                }
            }
        }
        for observed in records {
            match &observed.record.action {
                CoordinationAction::Heartbeat {
                    claim_id,
                    agent_id,
                    activation_nonce,
                }
                | CoordinationAction::Release {
                    claim_id,
                    agent_id,
                    activation_nonce,
                    ..
                } => {
                    let definition = definitions.get(claim_id).with_context(|| {
                        format!("claim reference `{claim_id}` has no activation")
                    })?;
                    if &definition.agent_id != agent_id {
                        bail!("claim reference agent does not match its activation");
                    }
                    if !activations.contains_key(&(claim_id.clone(), activation_nonce.clone())) {
                        bail!("claim reference uses an unknown activation nonce");
                    }
                }
                CoordinationAction::Claim { .. } | CoordinationAction::AgentState { .. } => {}
            }
        }
        Ok(Self {
            definitions,
            activations,
            replay_dispositions,
        })
    }
}

fn reduce_claims(
    records: &[ObservedRecord],
    model: &ClaimModel,
) -> Result<(BTreeMap<String, ForgeClaimState>, Vec<RecordDisposition>)> {
    let mut claims = BTreeMap::<String, ForgeClaimState>::new();
    let mut dispositions = model.replay_dispositions.clone();
    for ((claim_id, nonce), activation) in &model.activations {
        let definition = model
            .definitions
            .get(claim_id)
            .context("claim activation lost its definition")?;
        if nonce != &definition.winning_nonce {
            dispositions.push(RecordDisposition {
                kind: RecordDispositionKind::LosingActivationNonce,
                event_id: activation.record.event_id.clone(),
                provenance: activation.provenance.clone(),
            });
        }
    }
    let mut timestamps = BTreeSet::new();
    for observed in records {
        if !matches!(
            observed.record.action,
            CoordinationAction::AgentState { .. }
        ) {
            timestamps.insert(observed.provenance.created_at.clone());
        }
    }
    for timestamp in timestamps {
        let at = timestamp_seconds(&timestamp)?;
        let (mut references, replay_dispositions) =
            canonical_claim_references(records, &timestamp)?;
        dispositions.extend(replay_dispositions);
        references.sort_by_key(record_order_key);
        for observed in references {
            let (claim_id, agent_id, nonce, release) = match &observed.record.action {
                CoordinationAction::Heartbeat {
                    claim_id,
                    agent_id,
                    activation_nonce,
                } => (claim_id, agent_id, activation_nonce, false),
                CoordinationAction::Release {
                    claim_id,
                    agent_id,
                    activation_nonce,
                    ..
                } => (claim_id, agent_id, activation_nonce, true),
                CoordinationAction::Claim { .. } | CoordinationAction::AgentState { .. } => {
                    continue;
                }
            };
            let definition = model
                .definitions
                .get(claim_id)
                .context("validated claim reference lost its definition")?;
            if nonce != &definition.winning_nonce {
                dispositions.push(RecordDisposition {
                    kind: RecordDispositionKind::LosingActivationNonce,
                    event_id: observed.record.event_id.clone(),
                    provenance: observed.provenance.clone(),
                });
                continue;
            }
            let activation = model
                .activations
                .get(&(claim_id.clone(), nonce.clone()))
                .context("winning claim activation is missing")?;
            if observed.provenance.created_at < activation.provenance.created_at {
                bail!("claim mutation precedes its winning activation");
            }
            let claim = claims
                .get_mut(claim_id)
                .context("claim mutation appears before its activation timestamp")?;
            if &claim.agent_id != agent_id
                || &claim.activation_nonce != nonce
                || claim.activation.actor != observed.provenance.actor
            {
                bail!("claim mutation is not bound to its exact activation owner");
            }
            if release {
                if claim.status == ClaimStatus::Active {
                    claim.status = ClaimStatus::Released;
                    claim.terminal = Some(observed.provenance.clone());
                } else {
                    dispositions.push(RecordDisposition {
                        kind: RecordDispositionKind::ObsoleteLineageMutation,
                        event_id: observed.record.event_id.clone(),
                        provenance: observed.provenance.clone(),
                    });
                }
            } else if claim.status == ClaimStatus::Active {
                claim.last_heartbeat = observed.provenance.clone();
            } else {
                dispositions.push(RecordDisposition {
                    kind: RecordDispositionKind::ObsoleteLineageMutation,
                    event_id: observed.record.event_id.clone(),
                    provenance: observed.provenance.clone(),
                });
            }
        }

        let mut activations = model
            .activations
            .iter()
            .filter(|((claim_id, nonce), observed)| {
                observed.provenance.created_at == timestamp
                    && model
                        .definitions
                        .get(claim_id)
                        .is_some_and(|definition| &definition.winning_nonce == nonce)
            })
            .map(|((claim_id, _), observed)| (claim_id.clone(), observed))
            .collect::<Vec<_>>();
        activations.sort_by(|left, right| left.0.cmp(&right.0));
        for (claim_id, observed) in activations {
            let definition = model
                .definitions
                .get(&claim_id)
                .context("claim activation lost its definition")?;
            let conflicting = active_conflict(&claims, &definition.scopes, Some(&claim_id));
            let mut status = ClaimStatus::Active;
            let mut conflict = None;
            if let Some(predecessor_id) = &definition.supersedes {
                let predecessor = claims.get(predecessor_id);
                let valid_lineage =
                    predecessor.is_some_and(|claim| claim.scopes == definition.scopes);
                if !valid_lineage {
                    status = ClaimStatus::InvalidTakeover;
                    conflict = Some(predecessor_id.clone());
                } else {
                    let predecessor = predecessor.context("validated predecessor disappeared")?;
                    let predecessor_stale = predecessor.status == ClaimStatus::Active
                        && elapsed_at_least(
                            timestamp_seconds(&predecessor.last_heartbeat.created_at)?,
                            at,
                            predecessor.stale_after_seconds,
                        )?;
                    let predecessor_released = predecessor.status == ClaimStatus::Released;
                    if !(predecessor_stale || predecessor_released) {
                        status = ClaimStatus::InvalidTakeover;
                        conflict = Some(predecessor_id.clone());
                    } else if conflicting
                        .as_ref()
                        .is_some_and(|active| active != predecessor_id)
                    {
                        status = ClaimStatus::Conflict;
                        conflict = conflicting;
                    } else if predecessor_stale {
                        let predecessor = claims
                            .get_mut(predecessor_id)
                            .context("stale predecessor disappeared")?;
                        predecessor.status = ClaimStatus::Superseded;
                        predecessor.superseded_by = Some(claim_id.clone());
                        predecessor.terminal = Some(observed.provenance.clone());
                    }
                }
            } else if let Some(active) = conflicting {
                status = ClaimStatus::Conflict;
                conflict = Some(active);
            }
            claims.insert(
                claim_id.clone(),
                ForgeClaimState {
                    claim_id,
                    agent_id: definition.agent_id.clone(),
                    activation_nonce: definition.winning_nonce.clone(),
                    scopes: definition.scopes.clone(),
                    stale_after_seconds: definition.stale_after_seconds,
                    supersedes: definition.supersedes.clone(),
                    superseded_by: None,
                    status,
                    conflicts_with: conflict,
                    activation: observed.provenance.clone(),
                    last_heartbeat: observed.provenance.clone(),
                    terminal: None,
                    stale_at_observation: false,
                },
            );
        }
    }
    Ok((claims, dispositions))
}

fn canonical_claim_references<'a>(
    records: &'a [ObservedRecord],
    timestamp: &ForgeTimestamp,
) -> Result<(Vec<&'a ObservedRecord>, Vec<RecordDisposition>)> {
    let mut by_reference = BTreeMap::<(u8, String, String), &'a ObservedRecord>::new();
    let mut kinds = BTreeMap::<(String, String), BTreeSet<u8>>::new();
    let mut dispositions = Vec::new();
    for observed in records
        .iter()
        .filter(|record| &record.provenance.created_at == timestamp)
    {
        let (kind, claim_id, nonce) = match &observed.record.action {
            CoordinationAction::Heartbeat {
                claim_id,
                activation_nonce,
                ..
            } => (0_u8, claim_id, activation_nonce),
            CoordinationAction::Release {
                claim_id,
                activation_nonce,
                ..
            } => (1_u8, claim_id, activation_nonce),
            CoordinationAction::Claim { .. } | CoordinationAction::AgentState { .. } => continue,
        };
        kinds
            .entry((claim_id.clone(), nonce.clone()))
            .or_default()
            .insert(kind);
        let key = (kind, claim_id.clone(), nonce.clone());
        match by_reference.entry(key) {
            Entry::Vacant(entry) => {
                entry.insert(observed);
            }
            Entry::Occupied(mut entry)
                if entry.get().record.action == observed.record.action
                    && entry.get().provenance.actor == observed.provenance.actor =>
            {
                let replay = if provenance_key(&observed.provenance)
                    < provenance_key(&entry.get().provenance)
                {
                    entry.insert(observed)
                } else {
                    observed
                };
                dispositions.push(RecordDisposition {
                    kind: RecordDispositionKind::Replay,
                    event_id: replay.record.event_id.clone(),
                    provenance: replay.provenance.clone(),
                });
            }
            Entry::Occupied(_) => {
                bail!("same-second claim mutation has ambiguous payloads or actors");
            }
        }
    }
    if kinds.values().any(|present| present.len() > 1) {
        bail!("same-second heartbeat and release for one lineage are ambiguous");
    }
    Ok((by_reference.into_values().collect(), dispositions))
}

fn reduce_agent_states(
    records: &[ObservedRecord],
    model: &ClaimModel,
    claims: &BTreeMap<String, ForgeClaimState>,
) -> Result<(
    BTreeMap<(String, String), ForgeAgentState>,
    Vec<RecordDisposition>,
)> {
    let mut sequences = BTreeMap::<(String, String), BTreeMap<u64, ObservedRecord>>::new();
    let mut dispositions = Vec::new();
    let mut lineages = BTreeMap::<(String, String), &ForgeClaimState>::new();
    for claim in claims.values().filter(|claim| {
        matches!(
            claim.status,
            ClaimStatus::Active | ClaimStatus::Released | ClaimStatus::Superseded
        )
    }) {
        if lineages
            .insert(
                (claim.agent_id.clone(), claim.activation_nonce.clone()),
                claim,
            )
            .is_some()
        {
            bail!("accepted claims ambiguously reuse one agent activation lineage");
        }
    }
    for observed in records {
        let CoordinationAction::AgentState {
            agent_id,
            activation_nonce,
            sequence,
            ..
        } = &observed.record.action
        else {
            continue;
        };
        let lineage = lineages
            .get(&(agent_id.clone(), activation_nonce.clone()))
            .context("agent state does not bind an accepted winning claim lineage")?;
        if observed.provenance.actor != lineage.activation.actor
            || observed.provenance.created_at < lineage.activation.created_at
        {
            bail!("agent state is not bound to its activation actor and provider time");
        }
        if let Some(terminal) = &lineage.terminal {
            match observed.provenance.created_at.cmp(&terminal.created_at) {
                std::cmp::Ordering::Greater => {
                    dispositions.push(RecordDisposition {
                        kind: RecordDispositionKind::ObsoleteLineageMutation,
                        event_id: observed.record.event_id.clone(),
                        provenance: observed.provenance.clone(),
                    });
                    continue;
                }
                std::cmp::Ordering::Equal => {
                    bail!("same-second agent state and lineage termination are ambiguous");
                }
                std::cmp::Ordering::Less => {}
            }
        }
        let states = sequences
            .entry((agent_id.clone(), activation_nonce.clone()))
            .or_default();
        match states.entry(*sequence) {
            Entry::Vacant(entry) => {
                entry.insert(observed.clone());
            }
            Entry::Occupied(mut entry) if entry.get().record.action == observed.record.action => {
                if entry.get().provenance.actor != observed.provenance.actor {
                    bail!("agent state sequence is replayed by a different actor");
                }
                if provenance_key(&observed.provenance) < provenance_key(&entry.get().provenance) {
                    let replay = entry.insert(observed.clone());
                    dispositions.push(RecordDisposition {
                        kind: RecordDispositionKind::Replay,
                        event_id: replay.record.event_id,
                        provenance: replay.provenance,
                    });
                } else {
                    dispositions.push(RecordDisposition {
                        kind: RecordDispositionKind::Replay,
                        event_id: observed.record.event_id.clone(),
                        provenance: observed.provenance.clone(),
                    });
                }
            }
            Entry::Occupied(_) => {
                bail!("agent state sequence has ambiguous payloads");
            }
        }
    }
    let mut result = BTreeMap::new();
    for ((agent_id, activation_nonce), states) in sequences {
        let lineage = lineages
            .get(&(agent_id.clone(), activation_nonce.clone()))
            .context("validated agent state lineage disappeared")?;
        let definition = model
            .definitions
            .get(&lineage.claim_id)
            .context("agent state lineage lost its claim definition")?;
        if definition.winning_nonce != activation_nonce {
            bail!("agent state is not bound to the winning claim activation nonce");
        }
        let mut expected_sequence = 1_u64;
        let mut actor = None::<ForgeActor>;
        let mut prior_provenance = None::<RecordProvenance>;
        let mut latest = None::<ForgeAgentState>;
        for (sequence, observed) in states {
            if sequence != expected_sequence {
                bail!("agent state history is incomplete or has a sequence gap");
            }
            expected_sequence = expected_sequence
                .checked_add(1)
                .context("agent state sequence overflowed")?;
            if actor
                .as_ref()
                .is_some_and(|owner| owner != &observed.provenance.actor)
            {
                bail!("agent state history changes its trusted writer");
            }
            if prior_provenance
                .as_ref()
                .is_some_and(|prior| observed.provenance.created_at < prior.created_at)
            {
                bail!("agent state sequence rolls provider time backward");
            }
            actor = Some(observed.provenance.actor.clone());
            prior_provenance = Some(observed.provenance.clone());
            let CoordinationAction::AgentState { phase, message, .. } = &observed.record.action
            else {
                bail!("agent state reducer received a non-state record");
            };
            latest = Some(ForgeAgentState {
                agent_id: agent_id.clone(),
                activation_nonce: activation_nonce.clone(),
                sequence,
                phase: *phase,
                message: message.clone(),
                provenance: observed.provenance.clone(),
            });
        }
        result.insert(
            (agent_id, activation_nonce),
            latest.context("agent state history unexpectedly had no records")?,
        );
    }
    Ok((result, dispositions))
}

fn active_conflict(
    claims: &BTreeMap<String, ForgeClaimState>,
    scopes: &[String],
    except: Option<&str>,
) -> Option<String> {
    claims
        .values()
        .filter(|claim| claim.status == ClaimStatus::Active)
        .filter(|claim| except != Some(claim.claim_id.as_str()))
        .find(|claim| scopes_overlap(&claim.scopes, scopes))
        .map(|claim| claim.claim_id.clone())
}

fn scopes_overlap(left: &[String], right: &[String]) -> bool {
    let mut left_index = 0_usize;
    let mut right_index = 0_usize;
    while left_index < left.len() && right_index < right.len() {
        match left[left_index].cmp(&right[right_index]) {
            std::cmp::Ordering::Less => left_index = left_index.saturating_add(1),
            std::cmp::Ordering::Greater => right_index = right_index.saturating_add(1),
            std::cmp::Ordering::Equal => return true,
        }
    }
    false
}

fn record_order_key(record: &&ObservedRecord) -> (String, String, String) {
    let (claim_id, nonce) = match &record.record.action {
        CoordinationAction::Heartbeat {
            claim_id,
            activation_nonce,
            ..
        }
        | CoordinationAction::Release {
            claim_id,
            activation_nonce,
            ..
        }
        | CoordinationAction::Claim {
            claim_id,
            activation_nonce,
            ..
        } => (claim_id.as_str(), activation_nonce.as_str()),
        CoordinationAction::AgentState { .. } => ("", ""),
    };
    (
        claim_id.to_string(),
        nonce.to_string(),
        record.record.event_id().to_string(),
    )
}

fn provenance_key(provenance: &RecordProvenance) -> (&ForgeTimestamp, &ProviderObjectId) {
    (&provenance.created_at, &provenance.provider_comment_id)
}

fn validate_claim_reference(claim_id: &str, agent_id: &str, nonce: &str) -> Result<()> {
    validate_id(claim_id, "claim reference id")?;
    validate_id(agent_id, "claim reference agent id")?;
    validate_id(nonce, "claim reference activation nonce")
}

fn validate_id(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || matches!(value, "." | "..")
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
    {
        bail!("{label} is not a canonical bounded identifier");
    }
    Ok(())
}

fn validate_scopes(scopes: &[String]) -> Result<()> {
    if scopes.is_empty() || scopes.len() > MAX_SCOPE_COUNT {
        bail!("claim scopes must be a bounded non-empty collection");
    }
    let mut prior = None::<&str>;
    for scope in scopes {
        validate_text(scope, "claim scope", MAX_SCOPE_BYTES, false)?;
        if scope.starts_with('/')
            || scope.ends_with('/')
            || scope.contains("//")
            || scope
                .split('/')
                .any(|component| matches!(component, "." | ".."))
            || scope.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            bail!("claim scope is not a canonical opaque resource key");
        }
        if prior.is_some_and(|previous| previous >= scope.as_str()) {
            bail!("claim scopes must be strictly sorted and unique");
        }
        prior = Some(scope);
    }
    Ok(())
}

fn validate_text(value: &str, label: &str, limit: usize, allow_empty: bool) -> Result<()> {
    if (!allow_empty && value.is_empty())
        || value.len() > limit
        || value.contains("-->")
        || value.contains(MARKER_TOKEN)
        || value.contains(SCHEMA)
        || value
            .bytes()
            .any(|byte| byte == 0 || (byte.is_ascii_control() && byte != b'\n' && byte != b'\t'))
    {
        bail!("{label} is malformed or exceeds its byte limit");
    }
    Ok(())
}

fn timestamp_seconds(timestamp: &ForgeTimestamp) -> Result<u64> {
    let value = timestamp.as_str();
    let component = |range: std::ops::Range<usize>, label: &str| -> Result<u64> {
        value
            .get(range)
            .context("forge timestamp shape changed unexpectedly")?
            .parse::<u64>()
            .with_context(|| format!("forge timestamp {label} was invalid"))
    };
    let year = component(0..4, "year")?;
    let month = component(5..7, "month")?;
    let day = component(8..10, "day")?;
    let hour = component(11..13, "hour")?;
    let minute = component(14..16, "minute")?;
    let second = component(17..19, "second")?;
    let prior_year = year
        .checked_sub(1)
        .context("forge timestamp year cannot be zero")?;
    let mut days = 365_u64
        .checked_mul(prior_year)
        .and_then(|value| value.checked_add(prior_year / 4))
        .and_then(|value| value.checked_sub(prior_year / 100))
        .and_then(|value| value.checked_add(prior_year / 400))
        .context("forge timestamp day count overflowed")?;
    const DAYS_BEFORE_MONTH: [u64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let month_index = usize::try_from(month.checked_sub(1).context("month cannot be zero")?)
        .context("forge timestamp month index overflowed")?;
    days = days
        .checked_add(
            *DAYS_BEFORE_MONTH
                .get(month_index)
                .context("forge timestamp month is outside its range")?,
        )
        .context("forge timestamp day count overflowed")?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    if leap && month > 2 {
        days = days
            .checked_add(1)
            .context("forge timestamp leap day overflowed")?;
    }
    days = days
        .checked_add(day.checked_sub(1).context("day cannot be zero")?)
        .context("forge timestamp day count overflowed")?;
    days.checked_mul(86_400)
        .and_then(|value| value.checked_add(hour.checked_mul(3_600)?))
        .and_then(|value| value.checked_add(minute.checked_mul(60)?))
        .and_then(|value| value.checked_add(second))
        .context("forge timestamp second count overflowed")
}

fn elapsed_at_least(start: u64, end: u64, threshold: u64) -> Result<bool> {
    Ok(end
        .checked_sub(start)
        .context("coordination provider time moved backward")?
        >= threshold)
}

fn required_nullable<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::publication::forge_transport::{
        FakeForgeTransport, ForgeComment, ForgeItemKind, ForgeObservation, ForgeObservationRequest,
        ForgeRepository, ForgeTransport, ProviderObjectKind, ReportedActorKind,
    };
    use serde_json::Value;

    const T0: &str = "2026-08-16T00:00:00Z";
    const T30: &str = "2026-08-16T00:00:30Z";
    const T60: &str = "2026-08-16T00:01:00Z";
    const T90: &str = "2026-08-16T00:01:30Z";
    const T120: &str = "2026-08-16T00:02:00Z";

    fn object(kind: ProviderObjectKind, id: &str) -> ProviderObjectId {
        ProviderObjectId::new("github", kind, id).expect("valid provider object")
    }

    fn actor(id: &str, handle: &str) -> ForgeActor {
        ForgeActor::new(
            "github",
            object(ProviderObjectKind::Actor, id),
            handle,
            ReportedActorKind::Bot,
        )
        .expect("valid actor")
    }

    fn item() -> ForgeItem {
        item_with_id("I_issue", 89)
    }

    fn item_with_id(provider_id: &str, number: u64) -> ForgeItem {
        let repository = ForgeRepository::new(
            "github",
            "github.com/meta-develop/maco",
            object(ProviderObjectKind::Repository, "R_repo"),
        )
        .expect("valid repository");
        ForgeItem::new(
            repository,
            ForgeItemKind::Issue,
            number,
            object(ProviderObjectKind::Item, provider_id),
            "revision:1",
            None,
            None,
        )
        .expect("valid item")
    }

    fn comment(
        id: &str,
        author: &ForgeActor,
        timestamp: &str,
        record: &CoordinationRecord,
    ) -> ForgeComment {
        raw_comment(
            id,
            author,
            timestamp,
            &record.render().expect("render record"),
        )
    }

    fn raw_comment(id: &str, author: &ForgeActor, timestamp: &str, body: &str) -> ForgeComment {
        ForgeComment::new(
            object(ProviderObjectKind::Comment, id),
            author.clone(),
            body,
            format!("https://github.com/meta-develop/maco/issues/89#issuecomment-{id}"),
            ForgeTimestamp::new(timestamp).expect("valid timestamp"),
        )
        .expect("valid comment")
    }

    fn observation(at: &str, comments: Vec<ForgeComment>) -> ItemThreadObservation {
        ItemThreadObservation::new(
            item(),
            ForgeTimestamp::new(at).expect("valid timestamp"),
            comments,
        )
        .expect("valid observation")
    }

    fn engine(writer: &ForgeActor) -> ForgeCoordinationEngine {
        ForgeCoordinationEngine::new(vec![writer.clone()]).expect("valid engine")
    }

    fn claim(
        event: &str,
        claim_id: &str,
        agent_id: &str,
        nonce: &str,
        supersedes: Option<&str>,
    ) -> CoordinationRecord {
        CoordinationRecord::claim(
            &item(),
            event,
            claim_id,
            agent_id,
            nonce,
            vec!["path:src/publication.rs".to_string()],
            60,
            supersedes.map(str::to_string),
        )
        .expect("valid claim")
    }

    #[test]
    fn canonical_envelope_round_trips_and_rejects_noncanonical_json() {
        let record = claim("event-1", "claim-a", "agent-a", "nonce-a", None);
        let rendered = record.render().expect("render");
        assert_eq!(
            CoordinationRecord::parse(&rendered)
                .expect("parse")
                .expect("marker"),
            record
        );
        let pretty = serde_json::to_string_pretty(&record).expect("pretty JSON");
        let noncanonical = format!("{MARKER}\n{pretty}\n{END_MARKER}");
        assert!(CoordinationRecord::parse(&noncanonical).is_err());
        assert!(CoordinationRecord::parse("ordinary discussion")
            .expect("ignore")
            .is_none());
        assert!(CoordinationRecord::parse(
            "quoted prose mentions maco:forge-coordination without starting a marker"
        )
        .expect("ignore quoted marker")
        .is_none());
        assert!(
            CoordinationRecord::parse(&format!("```text\n{MARKER}\n```"))
                .expect("ignore fenced marker")
                .is_none()
        );

        let mut future: Value = serde_json::to_value(&record).expect("record JSON");
        future["version"] = Value::from(2);
        let body = format!(
            "{MARKER}\n{}\n{END_MARKER}",
            serde_json::to_string(&future).expect("future JSON")
        );
        assert!(CoordinationRecord::parse(&body).is_err());
        assert!(CoordinationRecord::release(
            &item(),
            "event-release-injection",
            "claim-a",
            "agent-a",
            "nonce-a",
            "close marker --> injected",
        )
        .is_err());
        assert!(CoordinationRecord::agent_state(
            &item(),
            "event-state-injection",
            "agent-a",
            "nonce-a",
            1,
            AgentPhase::Working,
            Some("maco:forge-coordination".to_string()),
        )
        .is_err());
    }

    #[test]
    fn typed_effect_executes_idempotently_with_fake_transport() {
        let writer = actor("B_writer", "writer-bot");
        let engine = engine(&writer);
        let record = claim("event-effect", "claim-a", "agent-a", "nonce-a", None);
        let request = engine
            .prepare_effect(item(), writer, &record)
            .expect("typed request");
        let fake = FakeForgeTransport::new();
        let first = fake.execute(&request).expect("first effect");
        let replay = fake.execute(&request).expect("idempotent retry");
        assert_eq!(first, replay);
        assert_eq!(
            request.as_append_comment().body(),
            record.render().expect("body")
        );
        assert!(request
            .as_append_comment()
            .effect_id()
            .starts_with("coord-v1:"));

        let equivocation = claim(
            "event-effect",
            "claim-other",
            "agent-other",
            "nonce-other",
            None,
        );
        let divergent_request = engine
            .prepare_effect(item(), actor("B_writer", "writer-bot"), &equivocation)
            .expect("divergent typed request");
        assert_eq!(
            request.as_append_comment().effect_id(),
            divergent_request.as_append_comment().effect_id()
        );
        assert!(fake.execute(&divergent_request).is_err());

        let other_item = item_with_id("I_other", 90);
        assert!(engine
            .prepare_effect(other_item, actor("B_writer", "writer-bot"), &record)
            .is_err());
    }

    #[test]
    fn reconstruction_is_input_order_independent_and_claim_id_breaks_same_second_race() {
        let writer = actor("B_writer", "writer-bot");
        let early = claim("event-z", "claim-z", "agent-z", "nonce-z", None);
        let winner = claim("event-a", "claim-a", "agent-a", "nonce-a", None);
        let forward = observation(
            T30,
            vec![
                comment("C_z", &writer, T0, &early),
                comment("C_a", &writer, T0, &winner),
            ],
        );
        let reverse = observation(
            T30,
            vec![
                comment("C_a", &writer, T0, &winner),
                comment("C_z", &writer, T0, &early),
            ],
        );
        let first = engine(&writer).reconstruct(&forward).expect("reconstruct");
        let second = engine(&writer).reconstruct(&reverse).expect("reconstruct");
        assert_eq!(first, second);
        assert_eq!(first.claims()[0].claim_id(), "claim-a");
        assert_eq!(first.claims()[0].status(), ClaimStatus::Active);
        assert_eq!(first.claims()[1].claim_id(), "claim-z");
        assert_eq!(first.claims()[1].status(), ClaimStatus::Conflict);
        assert_eq!(first.claims()[1].conflicts_with(), Some("claim-a"));
    }

    #[test]
    fn lexicographically_first_activation_nonce_wins_and_loser_mutations_are_inert() {
        let writer = actor("B_writer", "writer-bot");
        let losing = claim("event-nonce-z", "claim-a", "agent-a", "nonce-z", None);
        let winning = claim("event-nonce-a", "claim-a", "agent-a", "nonce-a", None);
        let losing_release = CoordinationRecord::release(
            &item(),
            "event-release-z",
            "claim-a",
            "agent-a",
            "nonce-z",
            "loser exits",
        )
        .expect("release");
        let snapshot = engine(&writer)
            .reconstruct(&observation(
                T30,
                vec![
                    comment("C_z", &writer, T0, &losing),
                    comment("C_a", &writer, T0, &winning),
                    comment("C_release_z", &writer, T30, &losing_release),
                ],
            ))
            .expect("reconstruct");
        assert_eq!(snapshot.claims().len(), 1);
        assert_eq!(snapshot.claims()[0].activation_nonce(), "nonce-a");
        assert_eq!(snapshot.claims()[0].status(), ClaimStatus::Active);
        assert_eq!(snapshot.ignored_losing_nonce_count(), 2);
    }

    #[test]
    fn provider_heartbeat_controls_staleness_and_late_owner_release_cannot_release_takeover() {
        let writer = actor("B_writer", "writer-bot");
        let first = claim("event-first", "claim-a", "agent-a", "nonce-a", None);
        let heartbeat = CoordinationRecord::heartbeat(
            &item(),
            "event-heartbeat",
            "claim-a",
            "agent-a",
            "nonce-a",
        )
        .expect("heartbeat");
        let premature = claim(
            "event-premature",
            "claim-b",
            "agent-b",
            "nonce-b",
            Some("claim-a"),
        );
        let takeover = claim(
            "event-takeover",
            "claim-c",
            "agent-c",
            "nonce-c",
            Some("claim-a"),
        );
        let late_release = CoordinationRecord::release(
            &item(),
            "event-late-release",
            "claim-a",
            "agent-a",
            "nonce-a",
            "stale owner exits",
        )
        .expect("release");
        let snapshot = engine(&writer)
            .reconstruct(&observation(
                T120,
                vec![
                    comment("C_first", &writer, T0, &first),
                    comment("C_heartbeat", &writer, T30, &heartbeat),
                    comment("C_premature", &writer, T60, &premature),
                    comment("C_takeover", &writer, T90, &takeover),
                    comment("C_late_release", &writer, T120, &late_release),
                ],
            ))
            .expect("reconstruct");
        let predecessor = &snapshot.claims()[0];
        let rejected = &snapshot.claims()[1];
        let successor = &snapshot.claims()[2];
        assert_eq!(predecessor.status(), ClaimStatus::Superseded);
        assert_eq!(predecessor.superseded_by(), Some("claim-c"));
        assert_eq!(rejected.status(), ClaimStatus::InvalidTakeover);
        assert_eq!(successor.status(), ClaimStatus::Active);
        assert_eq!(successor.supersedes(), Some("claim-a"));
        assert_eq!(predecessor.last_heartbeat().created_at().as_str(), T30);
        assert_eq!(successor.activation().created_at().as_str(), T90);
    }

    #[test]
    fn explicit_release_allows_bound_successor_and_preserves_terminal_provenance() {
        let writer = actor("B_writer", "writer-bot");
        let first = claim("event-first", "claim-a", "agent-a", "nonce-a", None);
        let release = CoordinationRecord::release(
            &item(),
            "event-release",
            "claim-a",
            "agent-a",
            "nonce-a",
            "handoff",
        )
        .expect("release");
        let successor = claim(
            "event-successor",
            "claim-b",
            "agent-b",
            "nonce-b",
            Some("claim-a"),
        );
        let snapshot = engine(&writer)
            .reconstruct(&observation(
                T60,
                vec![
                    comment("C_first", &writer, T0, &first),
                    comment("C_release", &writer, T30, &release),
                    comment("C_successor", &writer, T30, &successor),
                ],
            ))
            .expect("reconstruct");
        assert_eq!(snapshot.claims()[0].status(), ClaimStatus::Released);
        assert_eq!(
            snapshot.claims()[0]
                .terminal()
                .expect("terminal")
                .provider_comment_id()
                .stable_id(),
            "C_release"
        );
        assert_eq!(snapshot.claims()[1].status(), ClaimStatus::Active);
    }

    #[test]
    fn agent_state_requires_contiguous_unambiguous_history_and_preserves_provenance() {
        let writer = actor("B_writer", "writer-bot");
        let lineage = claim("event-claim", "claim-a", "agent-a", "run-a", None);
        let starting = CoordinationRecord::agent_state(
            &item(),
            "event-state-1",
            "agent-a",
            "run-a",
            1,
            AgentPhase::Starting,
            None,
        )
        .expect("state");
        let working = CoordinationRecord::agent_state(
            &item(),
            "event-state-2",
            "agent-a",
            "run-a",
            2,
            AgentPhase::Working,
            Some("focused work".to_string()),
        )
        .expect("state");
        let snapshot = engine(&writer)
            .reconstruct(&observation(
                T60,
                vec![
                    comment("C_claim", &writer, T0, &lineage),
                    comment("C_state_2", &writer, T30, &working),
                    comment("C_state_1", &writer, T0, &starting),
                ],
            ))
            .expect("reconstruct");
        assert_eq!(snapshot.agents().len(), 1);
        assert_eq!(snapshot.agents()[0].sequence(), 2);
        assert_eq!(snapshot.agents()[0].phase(), AgentPhase::Working);
        assert_eq!(snapshot.agents()[0].message(), Some("focused work"));
        assert_eq!(
            snapshot.agents()[0]
                .provenance()
                .provider_comment_id()
                .stable_id(),
            "C_state_2"
        );

        let gap = CoordinationRecord::agent_state(
            &item(),
            "event-state-3",
            "agent-b",
            "run-b",
            2,
            AgentPhase::Working,
            None,
        )
        .expect("state");
        let gap_lineage = claim("event-gap-claim", "claim-b", "agent-b", "run-b", None);
        assert!(engine(&writer)
            .reconstruct(&observation(
                T60,
                vec![
                    comment("C_gap_claim", &writer, T0, &gap_lineage),
                    comment("C_gap", &writer, T30, &gap),
                ],
            ))
            .is_err());
    }

    #[test]
    fn malformed_untrusted_replayed_and_ambiguous_records_fail_closed_as_specified() {
        let writer = actor("B_writer", "writer-bot");
        let outsider = actor("B_outsider", "outsider-bot");
        let same_handle_impostor = actor("B_impostor", "writer-bot");
        let record = claim("event-a", "claim-a", "agent-a", "nonce-a", None);
        let untrusted = observation(T30, vec![comment("C_untrusted", &outsider, T0, &record)]);
        assert!(engine(&writer).reconstruct(&untrusted).is_err());
        let same_handle_untrusted = observation(
            T30,
            vec![comment("C_same_handle", &same_handle_impostor, T0, &record)],
        );
        assert!(engine(&writer).reconstruct(&same_handle_untrusted).is_err());

        let malformed = observation(
            T30,
            vec![raw_comment(
                "C_malformed",
                &writer,
                T0,
                "<!-- maco:forge-coordination:v1 malformed",
            )],
        );
        assert!(engine(&writer).reconstruct(&malformed).is_err());

        let replay = observation(
            T30,
            vec![
                comment("C_replay_1", &writer, T0, &record),
                comment("C_replay_2", &writer, T0, &record),
            ],
        );
        let snapshot = engine(&writer).reconstruct(&replay).expect("exact replay");
        assert_eq!(snapshot.replayed_record_count(), 1);
        assert_eq!(snapshot.claims().len(), 1);

        let conflicting = claim("event-a", "claim-b", "agent-b", "nonce-b", None);
        let ambiguous = observation(
            T30,
            vec![
                comment("C_ambiguous_1", &writer, T0, &record),
                comment("C_ambiguous_2", &writer, T0, &conflicting),
            ],
        );
        assert!(engine(&writer).reconstruct(&ambiguous).is_err());
    }

    #[test]
    fn bounds_and_complete_observation_contract_reject_adversarial_inputs() {
        assert!(CoordinationRecord::claim(
            &item(),
            "event-a",
            "claim-a",
            "agent-a",
            "nonce-a",
            vec!["path:b".to_string(), "path:a".to_string()],
            60,
            None,
        )
        .is_err());
        assert!(CoordinationRecord::claim(
            &item(),
            "event-a",
            "claim-a",
            "agent-a",
            "nonce-a",
            vec!["path:a".to_string()],
            MAX_STALE_AFTER_SECONDS + 1,
            None,
        )
        .is_err());
        assert!(CoordinationRecord::agent_state(
            &item(),
            "event-a",
            "agent-a",
            "nonce-a",
            0,
            AgentPhase::Working,
            None,
        )
        .is_err());

        let writer = actor("B_writer", "writer-bot");
        let future = comment(
            "C_future",
            &writer,
            T60,
            &claim("event-future", "claim-a", "agent-a", "nonce-a", None),
        );
        assert!(ItemThreadObservation::new(
            item(),
            ForgeTimestamp::new(T30).expect("timestamp"),
            vec![future],
        )
        .is_err());

        let request = ForgeObservationRequest::item_thread(item()).expect("request");
        let observed = ForgeObservation::ItemThread(observation(T30, Vec::new()));
        let mut fake = FakeForgeTransport::new();
        fake.register_observation(request.clone(), observed)
            .expect("complete observation");
        let ForgeObservation::ItemThread(thread) = fake.observe(&request).expect("observe") else {
            panic!("expected item thread");
        };
        assert!(engine(&writer)
            .reconstruct(&thread)
            .expect("empty snapshot")
            .claims()
            .is_empty());
    }

    #[test]
    fn same_second_divergent_mutations_and_cross_item_records_fail_closed() {
        let writer = actor("B_writer", "writer-bot");
        let activation = claim("event-claim", "claim-a", "agent-a", "nonce-a", None);
        let release_one = CoordinationRecord::release(
            &item(),
            "event-release-one",
            "claim-a",
            "agent-a",
            "nonce-a",
            "reason one",
        )
        .expect("release");
        let release_two = CoordinationRecord::release(
            &item(),
            "event-release-two",
            "claim-a",
            "agent-a",
            "nonce-a",
            "reason two",
        )
        .expect("release");
        let divergent_release = observation(
            T60,
            vec![
                comment("C_claim", &writer, T0, &activation),
                comment("C_release_one", &writer, T30, &release_one),
                comment("C_release_two", &writer, T30, &release_two),
            ],
        );
        assert!(engine(&writer).reconstruct(&divergent_release).is_err());

        let heartbeat = CoordinationRecord::heartbeat(
            &item(),
            "event-heartbeat",
            "claim-a",
            "agent-a",
            "nonce-a",
        )
        .expect("heartbeat");
        let heartbeat_and_release = observation(
            T60,
            vec![
                comment("C_claim", &writer, T0, &activation),
                comment("C_heartbeat", &writer, T30, &heartbeat),
                comment("C_release", &writer, T30, &release_one),
            ],
        );
        assert!(engine(&writer).reconstruct(&heartbeat_and_release).is_err());

        let other_item = item_with_id("I_other", 90);
        let cross_item = ItemThreadObservation::new(
            other_item,
            ForgeTimestamp::new(T30).expect("timestamp"),
            vec![comment("C_cross_item", &writer, T0, &activation)],
        )
        .expect("foundation-valid cross-item observation");
        assert!(engine(&writer).reconstruct(&cross_item).is_err());
    }

    #[test]
    fn post_terminal_agent_state_is_obsolete_and_cannot_replace_current_state() {
        let writer = actor("B_writer", "writer-bot");
        let activation = claim("event-claim", "claim-a", "agent-a", "nonce-a", None);
        let working = CoordinationRecord::agent_state(
            &item(),
            "event-working",
            "agent-a",
            "nonce-a",
            1,
            AgentPhase::Working,
            None,
        )
        .expect("state");
        let release = CoordinationRecord::release(
            &item(),
            "event-release",
            "claim-a",
            "agent-a",
            "nonce-a",
            "finished",
        )
        .expect("release");
        let late = CoordinationRecord::agent_state(
            &item(),
            "event-late-state",
            "agent-a",
            "nonce-a",
            2,
            AgentPhase::Failed,
            Some("late stale writer".to_string()),
        )
        .expect("state");
        let snapshot = engine(&writer)
            .reconstruct(&observation(
                T120,
                vec![
                    comment("C_claim", &writer, T0, &activation),
                    comment("C_working", &writer, T30, &working),
                    comment("C_release", &writer, T60, &release),
                    comment("C_late", &writer, T90, &late),
                ],
            ))
            .expect("reconstruct");
        assert_eq!(snapshot.agents().len(), 1);
        assert_eq!(snapshot.agents()[0].phase(), AgentPhase::Working);
        assert!(snapshot.dispositions().iter().any(|disposition| {
            disposition.kind() == RecordDispositionKind::ObsoleteLineageMutation
                && disposition.event_id() == "event-late-state"
        }));
    }
}
