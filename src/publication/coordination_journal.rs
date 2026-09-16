//! Deterministic CAS journal coordination over authenticated forge comments.
//!
//! This module is one bounded unit of remote admission (#410). It does not enable
//! production remote mode by itself and does not replace the local
//! [`crate::sync_store::SyncStore`].
//!
//! **Parent adapter obligation:** [`TrustedFiniteJournalHistory`] may be assembled
//! only through [`TrustedFiniteJournalHistory::from_transport_verified_entries`]
//! inside this crate after finite transport verification. [`AuthenticatedCommentEvidence`]
//! and [`VerifiedJournalEntry`] have no public constructors. Parsing JSON from an intent
//! comment body is not a verified transport receipt.

use super::coordination_effect::{
    effect_reconciliation_is_bound, verify_bound_effect_complete_for_replay,
    HistoricalEffectReplayContext, PublicationEffectDescriptorV1,
};
use super::forge_transport::{
    ForgeActor, ForgeComment, ForgeItem, ForgeTimestamp, ProviderObjectId, ProviderObjectKind,
};
use crate::{artifacts::state_auth::sha256_hex, orchestrator::RunId, sync_store::ClaimTiming};
use anyhow::{bail, Context, Result};
use git2::Oid;
use serde::{Deserialize, Serialize};
use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};

const MARKER: &str = "<!-- maco:forge-coordination-journal:v1 -->";
const END_MARKER: &str = "<!-- /maco:forge-coordination-journal:v1 -->";
const MARKER_START: &str = "<!-- maco:forge-coordination-journal";
const END_MARKER_START: &str = "<!-- /maco:forge-coordination-journal";
const MARKER_TOKEN: &str = "maco:forge-coordination-journal";
const SCHEMA: &str = "maco.forge-coordination-journal";
const VERSION: u32 = 1;
const MAX_TRUSTED_ACTORS: usize = 64;
pub(crate) const MAX_JOURNAL_ENTRIES: usize = 512;
pub(crate) const MAX_POINTER_FILE_BYTES: usize = 4096;
const MAX_RECORD_BODY_BYTES: usize = 16 * 1024;
const MAX_ID_BYTES: usize = 96;
const MAX_SCOPE_COUNT: usize = 64;
const MAX_SCOPE_BYTES: usize = 256;
const MAX_RELEASE_REASON_BYTES: usize = 512;
const MAX_EFFECT_ID_BYTES: usize = 128;
const MAX_RUN_ID_BYTES: usize = 256;

/// Operator-bound journal configuration for one repository item and CAS ref.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinationJournalConfig {
    anchor_item: ForgeItem,
    journal_ref: String,
    anchor_commit_oid: String,
    trusted_actors: BTreeMap<ProviderObjectId, ForgeActor>,
    timing: ClaimTiming,
}

impl CoordinationJournalConfig {
    pub fn new(
        anchor_item: ForgeItem,
        journal_ref: impl Into<String>,
        anchor_commit_oid: impl Into<String>,
        trusted_actors: Vec<ForgeActor>,
        timing: ClaimTiming,
    ) -> Result<Self> {
        let journal_ref = journal_ref.into();
        validate_journal_ref(&journal_ref)?;
        let anchor_commit_oid = anchor_commit_oid.into();
        validate_git_oid(&anchor_commit_oid, "journal anchor commit")?;
        if trusted_actors.is_empty() || trusted_actors.len() > MAX_TRUSTED_ACTORS {
            bail!("coordination journal requires a bounded non-empty trusted actor allowlist");
        }
        let provider_id = anchor_item.repository().provider_id();
        let mut actors = BTreeMap::new();
        for actor in trusted_actors {
            if actor.provider_id() != provider_id {
                bail!("trusted actors must belong to the anchor item forge provider");
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
            anchor_item,
            journal_ref,
            anchor_commit_oid,
            trusted_actors: actors,
            timing,
        })
    }

    pub fn anchor_item(&self) -> &ForgeItem {
        &self.anchor_item
    }

    pub fn journal_ref(&self) -> &str {
        &self.journal_ref
    }

    pub fn anchor_commit_oid(&self) -> &str {
        &self.anchor_commit_oid
    }

    pub fn timing(&self) -> ClaimTiming {
        self.timing
    }

    pub fn is_trusted_actor(&self, actor: &ForgeActor) -> bool {
        self.trusted_actors
            .get(actor.provider_actor_id())
            .is_some_and(|trusted| trusted == actor)
    }
}

/// Global owner identity: repo-bound run identity plus activation nonce.
///
/// Local [`crate::sync::ClaimToken`] counters are never global identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinationOwnerIdentity {
    run_identity: String,
    activation_nonce: String,
}

impl CoordinationOwnerIdentity {
    pub fn new(run_identity: impl AsRef<str>, activation_nonce: impl Into<String>) -> Result<Self> {
        let run_identity = run_identity.as_ref();
        if run_identity.len() > MAX_RUN_ID_BYTES {
            bail!("coordination run identity exceeds its byte limit");
        }
        RunId::new(run_identity).context("coordination run identity is invalid")?;
        let value = Self {
            run_identity: run_identity.to_string(),
            activation_nonce: activation_nonce.into(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn run_identity(&self) -> &str {
        &self.run_identity
    }

    pub fn activation_nonce(&self) -> &str {
        &self.activation_nonce
    }

    fn validate(&self) -> Result<()> {
        validate_id(&self.activation_nonce, "owner activation nonce")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimLeasePolicy {
    pub heartbeat_interval_seconds: u64,
    pub stale_after_seconds: u64,
}

impl ClaimLeasePolicy {
    fn from_timing(timing: ClaimTiming) -> Self {
        Self {
            heartbeat_interval_seconds: timing.heartbeat_interval_seconds,
            stale_after_seconds: timing.stale_after_seconds,
        }
    }

    fn validate(&self) -> Result<()> {
        ClaimTiming::new(self.heartbeat_interval_seconds, self.stale_after_seconds)?;
        Ok(())
    }
}

/// CAS journal pointer stored outside the hashed intent body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalPointer {
    event_nonce: String,
    provider_comment_id: ProviderObjectId,
    body_sha256: String,
    expected_parent_oid: String,
}

impl JournalPointer {
    pub fn new(
        event_nonce: impl Into<String>,
        provider_comment_id: ProviderObjectId,
        body_sha256: impl Into<String>,
        expected_parent_oid: impl Into<String>,
    ) -> Result<Self> {
        let value = Self {
            event_nonce: event_nonce.into(),
            provider_comment_id,
            body_sha256: body_sha256.into(),
            expected_parent_oid: expected_parent_oid.into(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn event_nonce(&self) -> &str {
        &self.event_nonce
    }

    pub fn provider_comment_id(&self) -> &ProviderObjectId {
        &self.provider_comment_id
    }

    pub fn body_sha256(&self) -> &str {
        &self.body_sha256
    }

    pub fn expected_parent_oid(&self) -> &str {
        &self.expected_parent_oid
    }

    fn validate(&self) -> Result<()> {
        validate_id(&self.event_nonce, "journal event nonce")?;
        if self.provider_comment_id.kind() != ProviderObjectKind::Comment {
            bail!("journal pointer provider id must name a comment");
        }
        validate_sha256_hex(&self.body_sha256, "journal intent body digest")?;
        validate_git_oid(&self.expected_parent_oid, "journal expected parent")?;
        Ok(())
    }

    pub(crate) fn render_pointer_file(&self) -> Result<String> {
        self.validate()?;
        let json = serde_json::to_string(self).context("failed to render journal pointer file")?;
        if json.len() > MAX_POINTER_FILE_BYTES {
            bail!("journal pointer file exceeds its byte limit");
        }
        Ok(json)
    }

    pub(crate) fn parse_pointer_file(body: &str) -> Result<Self> {
        if body.is_empty() || body.len() > MAX_POINTER_FILE_BYTES || body.contains('\0') {
            bail!("journal pointer file is empty or exceeds its byte limit");
        }
        let value: Self =
            serde_json::from_str(body).context("journal pointer file is not strict JSON")?;
        value.validate()?;
        Ok(value)
    }
}

/// Transport-authenticated comment observation used by the pure reducer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedCommentEvidence {
    item: ForgeItem,
    provider_comment_id: ProviderObjectId,
    author: ForgeActor,
    created_at: ForgeTimestamp,
    body: String,
}

impl AuthenticatedCommentEvidence {
    pub(crate) fn from_verified_transport(
        comment: &ForgeComment,
        item: &ForgeItem,
    ) -> Result<Self> {
        if comment.provider_comment_id().kind() != ProviderObjectKind::Comment {
            bail!("authenticated comment evidence requires a comment provider id");
        }
        Ok(Self {
            item: item.clone(),
            provider_comment_id: comment.provider_comment_id().clone(),
            author: comment.author().clone(),
            created_at: comment.created_at().clone(),
            body: comment.body().to_string(),
        })
    }

    pub fn item(&self) -> &ForgeItem {
        &self.item
    }

    pub fn provider_comment_id(&self) -> &ProviderObjectId {
        &self.provider_comment_id
    }

    pub fn author(&self) -> &ForgeActor {
        &self.author
    }

    pub fn created_at(&self) -> &ForgeTimestamp {
        &self.created_at
    }

    pub fn body(&self) -> &str {
        &self.body
    }
}

/// One verified CAS commit binding a pointer to authenticated comment evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedJournalEntry {
    pointer: JournalPointer,
    commit_oid: String,
    parent_oid: String,
    comment: AuthenticatedCommentEvidence,
}

impl VerifiedJournalEntry {
    pub(crate) fn new(
        pointer: JournalPointer,
        commit_oid: impl Into<String>,
        parent_oid: impl Into<String>,
        comment: AuthenticatedCommentEvidence,
    ) -> Result<Self> {
        let commit_oid = commit_oid.into();
        let parent_oid = parent_oid.into();
        validate_git_oid(&commit_oid, "journal commit")?;
        validate_git_oid(&parent_oid, "journal parent")?;
        Ok(Self {
            pointer,
            commit_oid,
            parent_oid,
            comment,
        })
    }

    pub fn pointer(&self) -> &JournalPointer {
        &self.pointer
    }

    pub fn commit_oid(&self) -> &str {
        &self.commit_oid
    }

    pub fn parent_oid(&self) -> &str {
        &self.parent_oid
    }

    pub fn comment(&self) -> &AuthenticatedCommentEvidence {
        &self.comment
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifiedJournalHistory {
    entries: Vec<VerifiedJournalEntry>,
}

impl VerifiedJournalHistory {
    fn new(entries: Vec<VerifiedJournalEntry>) -> Result<Self> {
        if entries.len() > MAX_JOURNAL_ENTRIES {
            bail!("coordination journal history exceeds its entry limit");
        }
        Ok(Self { entries })
    }

    fn entries(&self) -> &[VerifiedJournalEntry] {
        &self.entries
    }
}

/// Linear journal history whose completeness was attested by finite transport verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedFiniteJournalHistory {
    inner: VerifiedJournalHistory,
}

impl TrustedFiniteJournalHistory {
    /// Assemble only after the publication transport adapter has verified a complete
    /// linear CAS chain from the configured anchor through bounded observation.
    pub(crate) fn from_transport_verified_entries(
        config: &CoordinationJournalConfig,
        entries: Vec<VerifiedJournalEntry>,
    ) -> Result<Self> {
        let inner = VerifiedJournalHistory::new(entries)?;
        let mut prior_head = config.anchor_commit_oid().to_string();
        for entry in inner.entries() {
            if entry.parent_oid() != prior_head {
                bail!("transport verified journal history is not linear from configured anchor");
            }
            prior_head = entry.commit_oid().to_string();
        }
        Ok(Self { inner })
    }

    pub fn entry_count(&self) -> usize {
        self.inner.entries().len()
    }

    pub fn head_oid(&self) -> Option<&str> {
        self.inner
            .entries()
            .last()
            .map(VerifiedJournalEntry::commit_oid)
    }

    pub(crate) fn verified_entries(&self) -> &[VerifiedJournalEntry] {
        self.inner.entries()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoordinationIntent {
    schema: &'static str,
    version: u32,
    repository_id: ProviderObjectId,
    item_id: ProviderObjectId,
    event_nonce: String,
    expected_parent_oid: String,
    owner: CoordinationOwnerIdentity,
    action: CoordinationIntentAction,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CoordinationIntentWire {
    schema: String,
    version: u32,
    repository_id: ProviderObjectId,
    item_id: ProviderObjectId,
    event_nonce: String,
    expected_parent_oid: String,
    owner: CoordinationOwnerIdentity,
    action: CoordinationIntentActionWire,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CoordinationIntentAction {
    Claim {
        scopes: Vec<String>,
        lease: ClaimLeasePolicy,
    },
    Heartbeat,
    Takeover {
        predecessor: CoordinationOwnerIdentity,
        scopes: Vec<String>,
        lease: ClaimLeasePolicy,
    },
    Release {
        reason: String,
    },
    EffectReserve {
        effect_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        publication_effect: Option<Box<PublicationEffectDescriptorV1>>,
    },
    EffectComplete {
        effect_id: String,
        reconciliation: Box<EffectReconciliationReceipt>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum CoordinationIntentActionWire {
    Claim {
        scopes: Vec<String>,
        lease: ClaimLeasePolicy,
    },
    Heartbeat,
    Takeover {
        predecessor: CoordinationOwnerIdentity,
        scopes: Vec<String>,
        lease: ClaimLeasePolicy,
    },
    Release {
        reason: String,
    },
    EffectReserve {
        effect_id: String,
        #[serde(default)]
        publication_effect: Option<Box<PublicationEffectDescriptorV1>>,
    },
    EffectComplete {
        effect_id: String,
        reconciliation: Box<EffectReconciliationReceipt>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum EffectReconciliationOutcome {
    Completed,
    ProvenNoEffect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectReconciliationReceipt {
    effect_id: String,
    outcome: EffectReconciliationOutcome,
    verified_material_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    parent_observed_material:
        Option<super::coordination_effect::ParentObservedPublicationMaterialV1>,
}

impl EffectReconciliationReceipt {
    pub fn new(
        effect_id: impl Into<String>,
        outcome: EffectReconciliationOutcome,
        verified_material_sha256: impl Into<String>,
    ) -> Result<Self> {
        let value = Self {
            effect_id: effect_id.into(),
            outcome,
            verified_material_sha256: verified_material_sha256.into(),
            parent_observed_material: None,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn new_bound(
        effect_id: impl Into<String>,
        outcome: EffectReconciliationOutcome,
        parent_observed_material: super::coordination_effect::ParentObservedPublicationMaterialV1,
    ) -> Result<Self> {
        let verified_material_sha256 = parent_observed_material
            .canonical_material_digest()
            .to_string();
        let value = Self {
            effect_id: effect_id.into(),
            outcome,
            verified_material_sha256,
            parent_observed_material: Some(parent_observed_material),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn effect_id(&self) -> &str {
        &self.effect_id
    }

    pub fn outcome(&self) -> EffectReconciliationOutcome {
        self.outcome
    }

    pub fn verified_material_sha256(&self) -> &str {
        &self.verified_material_sha256
    }

    pub fn parent_observed_material(
        &self,
    ) -> Option<&super::coordination_effect::ParentObservedPublicationMaterialV1> {
        self.parent_observed_material.as_ref()
    }

    fn validate(&self) -> Result<()> {
        validate_id(&self.effect_id, "effect id")?;
        if self.effect_id.len() > MAX_EFFECT_ID_BYTES {
            bail!("effect id exceeds its byte limit");
        }
        validate_sha256_hex(
            &self.verified_material_sha256,
            "effect reconciliation digest",
        )?;
        if let Some(material) = &self.parent_observed_material {
            if effect_reconciliation_is_bound(self) {
                material.validate()?;
                if self.outcome != EffectReconciliationOutcome::Completed {
                    bail!("bound effect reconciliation supports only completed outcomes");
                }
                if self.verified_material_sha256 != material.canonical_material_digest() {
                    bail!("bound effect reconciliation digest does not match parent material");
                }
                if self.effect_id != material.descriptor().effect_id() {
                    bail!("bound effect reconciliation effect id does not match descriptor");
                }
            } else {
                bail!("effect reconciliation parent material is malformed");
            }
        }
        Ok(())
    }
}

/// Parent-supplied verification for cross-host effect completion material.
pub trait EffectReconciliationVerifier {
    fn verify_reconciliation(
        &self,
        owner: &CoordinationOwnerIdentity,
        reserve_effect_id: &str,
        receipt: &EffectReconciliationReceipt,
    ) -> bool;
}

impl CoordinationIntent {
    pub fn claim(
        item: &ForgeItem,
        event_nonce: impl Into<String>,
        expected_parent_oid: impl Into<String>,
        owner: CoordinationOwnerIdentity,
        scopes: Vec<String>,
        timing: ClaimTiming,
    ) -> Result<Self> {
        Self::new(
            item,
            event_nonce,
            expected_parent_oid,
            owner,
            CoordinationIntentAction::Claim {
                scopes,
                lease: ClaimLeasePolicy::from_timing(timing),
            },
        )
    }

    pub fn heartbeat(
        item: &ForgeItem,
        event_nonce: impl Into<String>,
        expected_parent_oid: impl Into<String>,
        owner: CoordinationOwnerIdentity,
    ) -> Result<Self> {
        Self::new(
            item,
            event_nonce,
            expected_parent_oid,
            owner,
            CoordinationIntentAction::Heartbeat,
        )
    }

    pub fn takeover(
        item: &ForgeItem,
        event_nonce: impl Into<String>,
        expected_parent_oid: impl Into<String>,
        owner: CoordinationOwnerIdentity,
        predecessor: CoordinationOwnerIdentity,
        scopes: Vec<String>,
        timing: ClaimTiming,
    ) -> Result<Self> {
        Self::new(
            item,
            event_nonce,
            expected_parent_oid,
            owner,
            CoordinationIntentAction::Takeover {
                predecessor,
                scopes,
                lease: ClaimLeasePolicy::from_timing(timing),
            },
        )
    }

    pub fn release(
        item: &ForgeItem,
        event_nonce: impl Into<String>,
        expected_parent_oid: impl Into<String>,
        owner: CoordinationOwnerIdentity,
        reason: impl Into<String>,
    ) -> Result<Self> {
        Self::new(
            item,
            event_nonce,
            expected_parent_oid,
            owner,
            CoordinationIntentAction::Release {
                reason: reason.into(),
            },
        )
    }

    pub fn effect_reserve(
        item: &ForgeItem,
        event_nonce: impl Into<String>,
        expected_parent_oid: impl Into<String>,
        owner: CoordinationOwnerIdentity,
        effect_id: impl Into<String>,
    ) -> Result<Self> {
        Self::effect_reserve_with_descriptor(
            item,
            event_nonce,
            expected_parent_oid,
            owner,
            effect_id,
            None,
        )
    }

    pub fn effect_reserve_bound(
        item: &ForgeItem,
        event_nonce: impl Into<String>,
        expected_parent_oid: impl Into<String>,
        owner: CoordinationOwnerIdentity,
        publication_effect: PublicationEffectDescriptorV1,
    ) -> Result<Self> {
        let effect_id = publication_effect.effect_id().to_string();
        Self::effect_reserve_with_descriptor(
            item,
            event_nonce,
            expected_parent_oid,
            owner,
            effect_id,
            Some(publication_effect),
        )
    }

    fn effect_reserve_with_descriptor(
        item: &ForgeItem,
        event_nonce: impl Into<String>,
        expected_parent_oid: impl Into<String>,
        owner: CoordinationOwnerIdentity,
        effect_id: impl Into<String>,
        publication_effect: Option<PublicationEffectDescriptorV1>,
    ) -> Result<Self> {
        let effect_id = effect_id.into();
        if let Some(descriptor) = &publication_effect {
            descriptor.validate()?;
            if descriptor.effect_id() != effect_id {
                bail!("publication effect descriptor disagrees with reserved effect id");
            }
        }
        Self::new(
            item,
            event_nonce,
            expected_parent_oid,
            owner,
            CoordinationIntentAction::EffectReserve {
                effect_id,
                publication_effect: publication_effect.map(Box::new),
            },
        )
    }

    pub fn effect_complete(
        item: &ForgeItem,
        event_nonce: impl Into<String>,
        expected_parent_oid: impl Into<String>,
        owner: CoordinationOwnerIdentity,
        effect_id: impl Into<String>,
        reconciliation: EffectReconciliationReceipt,
    ) -> Result<Self> {
        Self::new(
            item,
            event_nonce,
            expected_parent_oid,
            owner,
            CoordinationIntentAction::EffectComplete {
                effect_id: effect_id.into(),
                reconciliation: Box::new(reconciliation),
            },
        )
    }

    fn new(
        item: &ForgeItem,
        event_nonce: impl Into<String>,
        expected_parent_oid: impl Into<String>,
        owner: CoordinationOwnerIdentity,
        action: CoordinationIntentAction,
    ) -> Result<Self> {
        let value = Self {
            schema: SCHEMA,
            version: VERSION,
            repository_id: item.repository().provider_repository_id().clone(),
            item_id: item.provider_item_id().clone(),
            event_nonce: event_nonce.into(),
            expected_parent_oid: expected_parent_oid.into(),
            owner,
            action,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn event_nonce(&self) -> &str {
        &self.event_nonce
    }

    pub fn expected_parent_oid(&self) -> &str {
        &self.expected_parent_oid
    }

    pub fn owner(&self) -> &CoordinationOwnerIdentity {
        &self.owner
    }

    pub fn action(&self) -> &CoordinationIntentAction {
        &self.action
    }

    pub fn canonical_body_sha256(&self) -> Result<String> {
        Ok(sha256_hex(self.render()?.as_bytes()))
    }

    pub fn render(&self) -> Result<String> {
        self.validate()?;
        let json = serde_json::to_string(self).context("failed to render coordination intent")?;
        let body = format!("{MARKER}\n{json}\n{END_MARKER}");
        if body.len() > MAX_RECORD_BODY_BYTES {
            bail!("coordination intent exceeds its body byte limit");
        }
        Ok(body)
    }

    pub fn parse(body: &str) -> Result<Option<Self>> {
        if !body.starts_with(MARKER_START) && !body.starts_with(END_MARKER_START) {
            return Ok(None);
        }
        if body.len() > MAX_RECORD_BODY_BYTES {
            bail!("coordination intent body exceeds its byte limit");
        }
        let json = body
            .strip_prefix(MARKER)
            .and_then(|value| value.strip_prefix('\n'))
            .and_then(|value| value.strip_suffix(END_MARKER))
            .and_then(|value| value.strip_suffix('\n'))
            .context("coordination intent envelope is not canonical")?;
        if json.is_empty() || json.contains('\n') || json.as_bytes().contains(&0) {
            bail!("coordination intent payload is empty or non-canonical");
        }
        let wire: CoordinationIntentWire = serde_json::from_str(json)
            .context("coordination intent payload is not strict valid JSON")?;
        let intent = Self::from_wire(wire)?;
        if intent.render()? != body {
            bail!("coordination intent JSON is not in canonical form");
        }
        Ok(Some(intent))
    }

    fn from_wire(wire: CoordinationIntentWire) -> Result<Self> {
        if wire.schema != SCHEMA || wire.version != VERSION {
            bail!("coordination intent has an unsupported schema or version");
        }
        let action = match wire.action {
            CoordinationIntentActionWire::Claim { scopes, lease } => {
                CoordinationIntentAction::Claim { scopes, lease }
            }
            CoordinationIntentActionWire::Heartbeat => CoordinationIntentAction::Heartbeat,
            CoordinationIntentActionWire::Takeover {
                predecessor,
                scopes,
                lease,
            } => CoordinationIntentAction::Takeover {
                predecessor,
                scopes,
                lease,
            },
            CoordinationIntentActionWire::Release { reason } => {
                CoordinationIntentAction::Release { reason }
            }
            CoordinationIntentActionWire::EffectReserve {
                effect_id,
                publication_effect,
            } => CoordinationIntentAction::EffectReserve {
                effect_id,
                publication_effect,
            },
            CoordinationIntentActionWire::EffectComplete {
                effect_id,
                reconciliation,
            } => CoordinationIntentAction::EffectComplete {
                effect_id,
                reconciliation,
            },
        };
        let value = Self {
            schema: SCHEMA,
            version: VERSION,
            repository_id: wire.repository_id,
            item_id: wire.item_id,
            event_nonce: wire.event_nonce,
            expected_parent_oid: wire.expected_parent_oid,
            owner: wire.owner,
            action,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<()> {
        if self.schema != SCHEMA || self.version != VERSION {
            bail!("coordination intent has an unsupported schema or version");
        }
        if self.repository_id.kind() != ProviderObjectKind::Repository
            || self.item_id.kind() != ProviderObjectKind::Item
            || self.repository_id.provider_id() != self.item_id.provider_id()
        {
            bail!("coordination intent target is not one provider-bound repository item");
        }
        validate_id(&self.event_nonce, "coordination event nonce")?;
        validate_git_oid(&self.expected_parent_oid, "coordination expected parent")?;
        self.owner.validate()?;
        match &self.action {
            CoordinationIntentAction::Claim { scopes, lease } => {
                validate_scopes(scopes)?;
                lease.validate()?;
            }
            CoordinationIntentAction::Heartbeat => {}
            CoordinationIntentAction::Takeover {
                predecessor,
                scopes,
                lease,
            } => {
                predecessor.validate()?;
                validate_scopes(scopes)?;
                lease.validate()?;
                if predecessor == &self.owner {
                    bail!("takeover predecessor must differ from successor owner");
                }
            }
            CoordinationIntentAction::Release { reason } => {
                validate_text(reason, "release reason", MAX_RELEASE_REASON_BYTES, false)?;
            }
            CoordinationIntentAction::EffectReserve {
                effect_id,
                publication_effect,
            } => {
                validate_id(effect_id, "effect id")?;
                if effect_id.len() > MAX_EFFECT_ID_BYTES {
                    bail!("effect id exceeds its byte limit");
                }
                if let Some(descriptor) = publication_effect {
                    descriptor.validate()?;
                    if descriptor.effect_id() != effect_id {
                        bail!("publication effect descriptor disagrees with reserved effect id");
                    }
                }
            }
            CoordinationIntentAction::EffectComplete {
                effect_id,
                reconciliation,
            } => {
                validate_id(effect_id, "effect id")?;
                reconciliation.validate()?;
                if effect_id != reconciliation.effect_id() {
                    bail!("effect completion action disagrees with its reconciliation receipt");
                }
            }
        }
        Ok(())
    }

    pub(crate) fn require_target(&self, item: &ForgeItem) -> Result<()> {
        if self.repository_id != *item.repository().provider_repository_id()
            || self.item_id != *item.provider_item_id()
        {
            bail!("coordination intent targets a different stable repository item");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveOwnerRecord {
    owner: CoordinationOwnerIdentity,
    bound_claim_actor: ForgeActor,
    scopes: Vec<String>,
    lease: ClaimLeasePolicy,
    activation_at: ForgeTimestamp,
    last_heartbeat_at: ForgeTimestamp,
    activation_event_nonce: String,
}

impl ActiveOwnerRecord {
    pub fn owner(&self) -> &CoordinationOwnerIdentity {
        &self.owner
    }

    pub fn bound_claim_actor(&self) -> &ForgeActor {
        &self.bound_claim_actor
    }

    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    pub fn lease(&self) -> ClaimLeasePolicy {
        self.lease
    }

    pub fn activation_at(&self) -> &ForgeTimestamp {
        &self.activation_at
    }

    pub fn last_heartbeat_at(&self) -> &ForgeTimestamp {
        &self.last_heartbeat_at
    }

    pub fn activation_event_nonce(&self) -> &str {
        &self.activation_event_nonce
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingEffectReservation {
    effect_id: String,
    owner: CoordinationOwnerIdentity,
    reserved_at: ForgeTimestamp,
    reserve_event_nonce: String,
    publication_effect: Option<PublicationEffectDescriptorV1>,
}

impl PendingEffectReservation {
    pub fn effect_id(&self) -> &str {
        &self.effect_id
    }

    pub fn owner(&self) -> &CoordinationOwnerIdentity {
        &self.owner
    }

    pub fn reserved_at(&self) -> &ForgeTimestamp {
        &self.reserved_at
    }

    pub fn reserve_event_nonce(&self) -> &str {
        &self.reserve_event_nonce
    }

    pub fn publication_effect(&self) -> Option<&PublicationEffectDescriptorV1> {
        self.publication_effect.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedEventIndex {
    event_nonce: String,
    commit_oid: String,
    parent_oid: String,
    owner: CoordinationOwnerIdentity,
}

impl CommittedEventIndex {
    pub fn event_nonce(&self) -> &str {
        &self.event_nonce
    }

    pub fn commit_oid(&self) -> &str {
        &self.commit_oid
    }

    pub fn parent_oid(&self) -> &str {
        &self.parent_oid
    }

    pub fn owner(&self) -> &CoordinationOwnerIdentity {
        &self.owner
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoritySnapshot {
    journal_head_oid: String,
    active_owners: Vec<ActiveOwnerRecord>,
    pending_reservations: Vec<PendingEffectReservation>,
    committed_events: Vec<CommittedEventIndex>,
}

impl AuthoritySnapshot {
    pub fn journal_head_oid(&self) -> &str {
        &self.journal_head_oid
    }

    pub fn active_owners(&self) -> &[ActiveOwnerRecord] {
        &self.active_owners
    }

    pub fn pending_reservations(&self) -> &[PendingEffectReservation] {
        &self.pending_reservations
    }

    pub fn committed_events(&self) -> &[CommittedEventIndex] {
        &self.committed_events
    }

    pub fn locate_event_nonce(&self, event_nonce: &str) -> CasNonceLocation {
        self.committed_events
            .iter()
            .find(|entry| entry.event_nonce == event_nonce)
            .map(|entry| CasNonceLocation::Committed {
                commit_oid: entry.commit_oid.clone(),
                parent_oid: entry.parent_oid.clone(),
                owner: entry.owner.clone(),
            })
            .unwrap_or(CasNonceLocation::Absent)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CasNonceLocation {
    Committed {
        commit_oid: String,
        parent_oid: String,
        owner: CoordinationOwnerIdentity,
    },
    Absent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalAuthorityResult {
    Authoritative(AuthoritySnapshot),
    Refused(JournalRefusal),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalRefusal {
    InvalidEntry(String),
}

pub struct TrustedJournalReductionInput<'a> {
    pub config: CoordinationJournalConfig,
    pub history: &'a TrustedFiniteJournalHistory,
    pub effect_reconciliation: Option<&'a dyn EffectReconciliationVerifier>,
}

impl TrustedJournalReductionInput<'_> {
    pub fn reduce(&self) -> JournalAuthorityResult {
        match reduce_trusted_journal_history(self) {
            Ok(snapshot) => JournalAuthorityResult::Authoritative(snapshot),
            Err(error) => {
                JournalAuthorityResult::Refused(JournalRefusal::InvalidEntry(error.to_string()))
            }
        }
    }
}

pub(crate) fn verify_journal_entry_contract(
    config: &CoordinationJournalConfig,
    entry: &VerifiedJournalEntry,
    expected_parent: &str,
) -> Result<CoordinationIntent> {
    if entry.parent_oid() != expected_parent {
        bail!("journal entry parent OID does not match the supplied linear predecessor");
    }
    if entry.pointer().expected_parent_oid() != expected_parent {
        bail!("journal pointer expected parent does not match the verified parent OID");
    }
    if !config.is_trusted_actor(entry.comment().author()) {
        bail!("journal comment author is not in the trusted actor allowlist");
    }
    if entry.comment().item() != config.anchor_item() {
        bail!("journal comment is not bound to the configured anchor item");
    }
    if entry.comment().provider_comment_id() != entry.pointer().provider_comment_id() {
        bail!("journal pointer comment id does not match authenticated comment evidence");
    }
    let intent = CoordinationIntent::parse(entry.comment().body())?
        .context("journal comment body is not a coordination intent")?;
    intent.require_target(config.anchor_item())?;
    if intent.event_nonce() != entry.pointer().event_nonce() {
        bail!("journal pointer event nonce does not match intent body");
    }
    if intent.expected_parent_oid() != entry.pointer().expected_parent_oid() {
        bail!("journal pointer parent expectation does not match intent body");
    }
    let digest = sha256_hex(entry.comment().body().as_bytes());
    if digest != entry.pointer().body_sha256() {
        bail!("journal pointer body digest does not match authenticated comment body");
    }
    Ok(intent)
}

pub fn reduce_trusted_journal_history(
    input: &TrustedJournalReductionInput<'_>,
) -> Result<AuthoritySnapshot> {
    let config = &input.config;
    let mut prior_head = config.anchor_commit_oid.clone();
    let mut seen_nonces = BTreeSet::new();
    let mut active_owners = BTreeMap::<CoordinationOwnerIdentity, ActiveOwnerRecord>::new();
    let mut pending = BTreeMap::<String, PendingEffectReservation>::new();
    let mut committed = Vec::new();

    for entry in input.history.verified_entries() {
        if !seen_nonces.insert(entry.pointer().event_nonce().to_string()) {
            bail!("duplicate event nonce in committed journal history");
        }
        let intent = verify_journal_entry_contract(config, entry, &prior_head)?;
        apply_intent(
            config,
            &intent,
            entry,
            &mut active_owners,
            &mut pending,
            input.effect_reconciliation,
        )?;
        committed.push(CommittedEventIndex {
            event_nonce: intent.event_nonce().to_string(),
            commit_oid: entry.commit_oid().to_string(),
            parent_oid: entry.parent_oid().to_string(),
            owner: intent.owner().clone(),
        });
        prior_head = entry.commit_oid().to_string();
    }

    Ok(AuthoritySnapshot {
        journal_head_oid: prior_head,
        active_owners: active_owners.into_values().collect(),
        pending_reservations: pending.into_values().collect(),
        committed_events: committed,
    })
}

fn apply_intent(
    config: &CoordinationJournalConfig,
    intent: &CoordinationIntent,
    entry: &VerifiedJournalEntry,
    active_owners: &mut BTreeMap<CoordinationOwnerIdentity, ActiveOwnerRecord>,
    pending: &mut BTreeMap<String, PendingEffectReservation>,
    effect_reconciliation: Option<&dyn EffectReconciliationVerifier>,
) -> Result<()> {
    let created_at = entry.comment().created_at();
    match &intent.action {
        CoordinationIntentAction::Claim { scopes, lease } => {
            ensure_lease_matches_config(lease, config.timing())?;
            if active_owners.contains_key(intent.owner()) {
                bail!("claim owner activation is already live");
            }
            if let Some(conflict) = active_scope_conflict(active_owners, scopes, None) {
                bail!("claim scopes overlap active owner {conflict}");
            }
            active_owners.insert(
                intent.owner().clone(),
                ActiveOwnerRecord {
                    owner: intent.owner().clone(),
                    bound_claim_actor: entry.comment().author().clone(),
                    scopes: scopes.clone(),
                    lease: *lease,
                    activation_at: created_at.clone(),
                    last_heartbeat_at: created_at.clone(),
                    activation_event_nonce: intent.event_nonce().to_string(),
                },
            );
        }
        CoordinationIntentAction::Heartbeat => {
            let owner = active_owner_mut(active_owners, intent.owner())?;
            require_exact_bound_actor(owner, entry)?;
            if created_at < &owner.last_heartbeat_at {
                bail!("heartbeat provider time moved backward");
            }
            if owner_has_blocking_reserve(pending, intent.owner()) {
                // Heartbeats remain allowed while reserved; reserve blocks takeover/release only.
            }
            owner.last_heartbeat_at = created_at.clone();
        }
        CoordinationIntentAction::Takeover {
            predecessor,
            scopes,
            lease,
        } => {
            ensure_lease_matches_config(lease, config.timing())?;
            let predecessor_record = active_owners
                .get(predecessor)
                .context("takeover predecessor is not an active owner")?
                .clone();
            if predecessor_record.scopes != *scopes {
                bail!("takeover scopes must exactly match predecessor scopes");
            }
            if owner_has_blocking_reserve(pending, predecessor) {
                bail!("takeover blocked by active effect reservation");
            }
            let at = timestamp_seconds(created_at)?;
            let heartbeat_at = timestamp_seconds(&predecessor_record.last_heartbeat_at)?;
            if !elapsed_strictly_after(
                heartbeat_at,
                at,
                predecessor_record.lease.stale_after_seconds,
            )? {
                bail!("takeover provider time is not past predecessor lease duration");
            }
            if let Some(conflict) = active_scope_conflict(active_owners, scopes, Some(predecessor))
            {
                bail!("takeover scopes overlap a different active owner {conflict}");
            }
            active_owners.remove(predecessor);
            if active_owners.contains_key(intent.owner()) {
                bail!("takeover successor activation is already live");
            }
            active_owners.insert(
                intent.owner().clone(),
                ActiveOwnerRecord {
                    owner: intent.owner().clone(),
                    bound_claim_actor: entry.comment().author().clone(),
                    scopes: scopes.clone(),
                    lease: *lease,
                    activation_at: created_at.clone(),
                    last_heartbeat_at: created_at.clone(),
                    activation_event_nonce: intent.event_nonce().to_string(),
                },
            );
        }
        CoordinationIntentAction::Release { .. } => {
            let owner = active_owner_mut(active_owners, intent.owner())?;
            require_exact_bound_actor(owner, entry)?;
            if owner_has_blocking_reserve(pending, intent.owner()) {
                bail!("release blocked by active effect reservation");
            }
            active_owners.remove(intent.owner());
        }
        CoordinationIntentAction::EffectReserve {
            effect_id,
            publication_effect,
        } => {
            let owner = active_owner_mut(active_owners, intent.owner())?;
            require_exact_bound_actor(owner, entry)?;
            if pending.contains_key(effect_id) {
                bail!("effect id is already reserved");
            }
            let at = timestamp_seconds(created_at)?;
            let heartbeat_at = timestamp_seconds(&owner.last_heartbeat_at)?;
            if elapsed_strictly_after(heartbeat_at, at, owner.lease.stale_after_seconds)? {
                bail!("effect reserve requires a current lease proof from this intent timestamp");
            }
            pending.insert(
                effect_id.clone(),
                PendingEffectReservation {
                    effect_id: effect_id.clone(),
                    owner: intent.owner().clone(),
                    reserved_at: created_at.clone(),
                    reserve_event_nonce: intent.event_nonce().to_string(),
                    publication_effect: publication_effect.as_deref().cloned(),
                },
            );
        }
        CoordinationIntentAction::EffectComplete {
            effect_id,
            reconciliation,
        } => {
            let owner = active_owner_mut(active_owners, intent.owner())?;
            require_exact_bound_actor(owner, entry)?;
            let reserve = pending
                .get(effect_id)
                .context("effect completion names an unknown reservation")?;
            if reserve.owner != *intent.owner() {
                bail!("effect completion owner does not match reservation owner");
            }
            if effect_reconciliation_is_bound(reconciliation.as_ref()) {
                let descriptor = reserve
                    .publication_effect
                    .as_ref()
                    .context("bound effect completion requires a matching bound reservation")?;
                verify_bound_effect_complete_for_replay(
                    HistoricalEffectReplayContext::journal_replay(),
                    &reserve.reserve_event_nonce,
                    descriptor,
                    reconciliation.as_ref(),
                )?;
            } else {
                if reserve.publication_effect.is_some() {
                    bail!("bound effect reservation cannot complete with opaque reconciliation");
                }
                let verifier = effect_reconciliation
                    .context("effect completion lacks parent-verified reconciliation")?;
                if !verifier.verify_reconciliation(
                    intent.owner(),
                    effect_id,
                    reconciliation.as_ref(),
                ) {
                    bail!("effect completion reconciliation was rejected by parent verifier");
                }
            }
            pending.remove(effect_id);
        }
    }
    Ok(())
}

fn require_exact_bound_actor(
    owner: &ActiveOwnerRecord,
    entry: &VerifiedJournalEntry,
) -> Result<()> {
    if entry.comment().author() != &owner.bound_claim_actor {
        bail!("coordination intent actor does not match the bound claim activation actor");
    }
    Ok(())
}

fn active_owner_mut<'a>(
    active: &'a mut BTreeMap<CoordinationOwnerIdentity, ActiveOwnerRecord>,
    owner: &CoordinationOwnerIdentity,
) -> Result<&'a mut ActiveOwnerRecord> {
    active
        .get_mut(owner)
        .context("coordination intent owner is not the active matching owner")
}

fn owner_has_blocking_reserve(
    pending: &BTreeMap<String, PendingEffectReservation>,
    owner: &CoordinationOwnerIdentity,
) -> bool {
    pending.values().any(|reserve| &reserve.owner == owner)
}

fn ensure_lease_matches_config(lease: &ClaimLeasePolicy, timing: ClaimTiming) -> Result<()> {
    if lease.heartbeat_interval_seconds != timing.heartbeat_interval_seconds
        || lease.stale_after_seconds != timing.stale_after_seconds
    {
        bail!("intent lease policy does not match configured claim timing");
    }
    Ok(())
}

fn active_scope_conflict(
    active: &BTreeMap<CoordinationOwnerIdentity, ActiveOwnerRecord>,
    scopes: &[String],
    except: Option<&CoordinationOwnerIdentity>,
) -> Option<String> {
    active
        .iter()
        .filter(|(owner, _)| except != Some(*owner))
        .find(|(_, record)| scopes_overlap(&record.scopes, scopes))
        .map(|(owner, _)| format!("{}:{}", owner.run_identity(), owner.activation_nonce()))
}

fn scopes_overlap(left: &[String], right: &[String]) -> bool {
    left.iter().any(|left_scope| {
        right
            .iter()
            .any(|right_scope| scope_keys_overlap(left_scope, right_scope))
    })
}

fn scope_keys_overlap(left: &str, right: &str) -> bool {
    left == right
        || left
            .strip_prefix(right)
            .is_some_and(|suffix| suffix.starts_with('/'))
        || right
            .strip_prefix(left)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

/// Normalize repo-relative paths into canonical coordination scope keys.
pub(crate) fn normalize_coordination_scopes<I, P>(paths: I) -> Result<Vec<String>>
where
    I: IntoIterator<Item = P>,
    P: AsRef<std::path::Path>,
{
    use crate::sync::normalize_repo_relative_path;
    use std::collections::BTreeSet;
    let mut scopes = BTreeSet::new();
    for path in paths {
        let normalized = normalize_repo_relative_path(path)?;
        let posix = normalized
            .components()
            .map(|component| component.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        scopes.insert(format!("path:{posix}"));
    }
    let scopes: Vec<String> = scopes.into_iter().collect();
    validate_scopes(&scopes)?;
    Ok(scopes)
}

fn validate_journal_ref(value: &str) -> Result<()> {
    if !value.starts_with("refs/heads/") {
        bail!("journal ref must be an exact refs/heads namespace");
    }
    if value.starts_with("refs/heads/refs/")
        || value.contains("//")
        || value.ends_with('/')
        || value == "refs/heads"
        || value.contains("refs/remotes/")
        || value.contains("refs/tags/")
    {
        bail!("journal ref is not a canonical local heads reference");
    }
    Ok(())
}

fn validate_git_oid(value: &str, label: &str) -> Result<()> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("{label} must be a canonical lowercase 40-character Git OID");
    }
    Oid::from_str(value).with_context(|| format!("{label} is not a Git OID"))?;
    Ok(())
}

fn validate_sha256_hex(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("{label} must be a canonical lowercase SHA-256 hex digest");
    }
    Ok(())
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
    for (index, scope) in scopes.iter().enumerate() {
        validate_text(scope, "claim scope", MAX_SCOPE_BYTES, false)?;
        if scope.starts_with('/')
            || scope.ends_with('/')
            || scope.contains("//")
            || scope.contains('\\')
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
        if scopes[..index]
            .iter()
            .any(|previous| scope_keys_overlap(previous, scope))
        {
            bail!("claim scopes cannot contain redundant ancestor and descendant keys");
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

fn elapsed_strictly_after(start: u64, end: u64, threshold: u64) -> Result<bool> {
    Ok(end
        .checked_sub(start)
        .context("coordination provider time moved backward")?
        > threshold)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::publication::forge_transport::{
        ForgeComment, ForgeItemKind, ForgeRepository, ReportedActorKind,
    };

    const ANCHOR: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const T0: &str = "2026-08-16T00:00:00Z";
    const T30: &str = "2026-08-16T00:00:30Z";
    const T60: &str = "2026-08-16T00:01:00Z";
    const T90: &str = "2026-08-16T00:01:30Z";

    struct TestReconciler {
        digest: String,
    }

    impl EffectReconciliationVerifier for TestReconciler {
        fn verify_reconciliation(
            &self,
            _owner: &CoordinationOwnerIdentity,
            reserve_effect_id: &str,
            receipt: &EffectReconciliationReceipt,
        ) -> bool {
            reserve_effect_id == receipt.effect_id()
                && receipt.verified_material_sha256() == self.digest
        }
    }

    fn oid(byte: u8) -> String {
        format!("{byte:02x}{:0>38}", 0)
    }

    fn object(kind: ProviderObjectKind, id: &str) -> ProviderObjectId {
        ProviderObjectId::new("github", kind, id).expect("valid provider object")
    }

    fn actor(id: &str) -> ForgeActor {
        ForgeActor::new(
            "github",
            object(ProviderObjectKind::Actor, id),
            format!("bot-{id}"),
            ReportedActorKind::Bot,
        )
        .expect("valid actor")
    }

    fn item() -> ForgeItem {
        let repository = ForgeRepository::new(
            "github",
            "github.com/meta-develop/maco",
            object(ProviderObjectKind::Repository, "R_repo"),
        )
        .expect("valid repository");
        ForgeItem::new(
            repository,
            ForgeItemKind::Issue,
            89,
            object(ProviderObjectKind::Item, "I_issue"),
            "revision:1",
            None,
            None,
        )
        .expect("valid item")
    }

    fn config() -> CoordinationJournalConfig {
        CoordinationJournalConfig::new(
            item(),
            "refs/heads/maco/coordination/journal",
            ANCHOR,
            vec![actor("trusted-a"), actor("trusted-b")],
            ClaimTiming::new(10, 30).expect("timing"),
        )
        .expect("config")
    }

    fn trusted_actor_a() -> ForgeActor {
        actor("trusted-a")
    }

    fn trusted_actor_b() -> ForgeActor {
        actor("trusted-b")
    }

    fn owner(run: &str, nonce: &str) -> CoordinationOwnerIdentity {
        CoordinationOwnerIdentity::new(run, nonce).expect("owner")
    }

    fn comment(id: &str, author: &ForgeActor, timestamp: &str, body: &str) -> ForgeComment {
        ForgeComment::new(
            object(ProviderObjectKind::Comment, id),
            author.clone(),
            body,
            format!("https://example.com/issues/89#issuecomment-{id}"),
            ForgeTimestamp::new(timestamp).expect("timestamp"),
        )
        .expect("comment")
    }

    fn verified_entry(
        parent: &str,
        commit: &str,
        event: &str,
        intent: &CoordinationIntent,
        author: &ForgeActor,
        timestamp: &str,
        comment_id: &str,
    ) -> VerifiedJournalEntry {
        let body = intent.render().expect("render");
        let pointer = JournalPointer::new(
            event,
            object(ProviderObjectKind::Comment, comment_id),
            sha256_hex(body.as_bytes()),
            parent,
        )
        .expect("pointer");
        let forge_comment = comment(comment_id, author, timestamp, &body);
        let evidence =
            AuthenticatedCommentEvidence::from_verified_transport(&forge_comment, &item())
                .expect("evidence");
        VerifiedJournalEntry::new(pointer, commit, parent, evidence).expect("entry")
    }

    fn trusted_history(entries: Vec<VerifiedJournalEntry>) -> TrustedFiniteJournalHistory {
        TrustedFiniteJournalHistory::from_transport_verified_entries(&config(), entries)
            .expect("trusted finite history")
    }

    fn reduce_history(
        entries: Vec<VerifiedJournalEntry>,
        reconciler: Option<&dyn EffectReconciliationVerifier>,
    ) -> AuthoritySnapshot {
        let history = trusted_history(entries);
        let input = TrustedJournalReductionInput {
            config: config(),
            history: &history,
            effect_reconciliation: reconciler,
        };
        match input.reduce() {
            JournalAuthorityResult::Authoritative(snapshot) => snapshot,
            JournalAuthorityResult::Refused(reason) => {
                panic!("expected authoritative snapshot, got refusal {reason:?}")
            }
        }
    }

    fn reduce_entries_result(
        entries: Vec<VerifiedJournalEntry>,
        reconciler: Option<&dyn EffectReconciliationVerifier>,
    ) -> Result<AuthoritySnapshot> {
        let history = trusted_history(entries);
        reduce_trusted_journal_history(&TrustedJournalReductionInput {
            config: config(),
            history: &history,
            effect_reconciliation: reconciler,
        })
    }

    #[test]
    fn concurrent_same_parent_winner_and_loser_validation() {
        let cfg = config();
        let parent = ANCHOR;
        let winner_commit = oid(1);
        let loser_commit = oid(2);
        let winner = CoordinationIntent::claim(
            cfg.anchor_item(),
            "evt-claim-a",
            parent,
            owner("run-a", "nonce-a"),
            vec!["path:src/a".to_string()],
            cfg.timing(),
        )
        .expect("winner intent");
        let loser = CoordinationIntent::claim(
            cfg.anchor_item(),
            "evt-claim-b",
            parent,
            owner("run-b", "nonce-b"),
            vec!["path:src/a".to_string()],
            cfg.timing(),
        )
        .expect("loser intent");
        let trusted = trusted_actor_a();
        let winner_entry = verified_entry(
            parent,
            &winner_commit,
            "evt-claim-a",
            &winner,
            &trusted,
            T0,
            "c-win",
        );
        let loser_entry = verified_entry(
            parent,
            &loser_commit,
            "evt-claim-b",
            &loser,
            &trusted,
            T0,
            "c-lose",
        );
        let winner_snapshot = reduce_history(vec![winner_entry.clone()], None);
        assert_eq!(winner_snapshot.active_owners().len(), 1);
        assert!(verify_journal_entry_contract(&cfg, &loser_entry, parent).is_ok());
        assert!(
            TrustedFiniteJournalHistory::from_transport_verified_entries(
                &cfg,
                vec![winner_entry, loser_entry],
            )
            .is_err()
        );
    }

    #[test]
    fn hierarchical_path_boundary_blocks_overlapping_claim() {
        let cfg = config();
        let first = verified_entry(
            ANCHOR,
            &oid(1),
            "evt-root",
            &CoordinationIntent::claim(
                cfg.anchor_item(),
                "evt-root",
                ANCHOR,
                owner("run-root", "nonce-root"),
                vec!["path:src".to_string()],
                cfg.timing(),
            )
            .expect("claim"),
            &trusted_actor_a(),
            T0,
            "c-root",
        );
        let second = verified_entry(
            &oid(1),
            &oid(2),
            "evt-child",
            &CoordinationIntent::claim(
                cfg.anchor_item(),
                "evt-child",
                oid(1),
                owner("run-child", "nonce-child"),
                vec!["path:src/publication".to_string()],
                cfg.timing(),
            )
            .expect("claim"),
            &trusted_actor_a(),
            T30,
            "c-child",
        );
        assert!(reduce_entries_result(vec![first, second], None).is_err());
    }

    #[test]
    fn colliding_local_token_values_do_not_collide_across_activation_identities() {
        let cfg = config();
        let first = verified_entry(
            ANCHOR,
            &oid(1),
            "evt-a",
            &CoordinationIntent::claim(
                cfg.anchor_item(),
                "evt-a",
                ANCHOR,
                owner("run-shared", "activation-one"),
                vec!["path:src/a".to_string()],
                cfg.timing(),
            )
            .expect("claim"),
            &trusted_actor_a(),
            T0,
            "c-a",
        );
        let second = verified_entry(
            &oid(1),
            &oid(2),
            "evt-b",
            &CoordinationIntent::claim(
                cfg.anchor_item(),
                "evt-b",
                oid(1),
                owner("run-shared", "activation-two"),
                vec!["path:src/b".to_string()],
                cfg.timing(),
            )
            .expect("claim"),
            &trusted_actor_a(),
            T30,
            "c-b",
        );
        let snapshot = reduce_history(vec![first, second], None);
        assert_eq!(snapshot.active_owners().len(), 2);
    }

    #[test]
    fn fresh_host_replay_is_deterministic() {
        let cfg = config();
        let entries = vec![
            verified_entry(
                ANCHOR,
                &oid(1),
                "evt-claim",
                &CoordinationIntent::claim(
                    cfg.anchor_item(),
                    "evt-claim",
                    ANCHOR,
                    owner("run", "nonce"),
                    vec!["path:src/a".to_string()],
                    cfg.timing(),
                )
                .expect("claim"),
                &trusted_actor_a(),
                T0,
                "c-claim",
            ),
            verified_entry(
                &oid(1),
                &oid(2),
                "evt-heartbeat",
                &CoordinationIntent::heartbeat(
                    cfg.anchor_item(),
                    "evt-heartbeat",
                    oid(1),
                    owner("run", "nonce"),
                )
                .expect("heartbeat"),
                &trusted_actor_a(),
                T30,
                "c-heartbeat",
            ),
        ];
        let first = reduce_history(entries.clone(), None);
        let second = reduce_history(entries, None);
        assert_eq!(first, second);
    }

    #[test]
    fn truncated_history_refuses_transport_assembly() {
        let cfg = config();
        let claim = verified_entry(
            ANCHOR,
            &oid(1),
            "evt-claim",
            &CoordinationIntent::claim(
                cfg.anchor_item(),
                "evt-claim",
                ANCHOR,
                owner("run", "nonce"),
                vec!["path:src/a".to_string()],
                cfg.timing(),
            )
            .expect("claim"),
            &trusted_actor_a(),
            T0,
            "c-claim",
        );
        let gap = verified_entry(
            &oid(9),
            &oid(2),
            "evt-gap",
            &CoordinationIntent::heartbeat(
                cfg.anchor_item(),
                "evt-gap",
                oid(9),
                owner("run", "nonce"),
            )
            .expect("heartbeat"),
            &trusted_actor_a(),
            T30,
            "c-gap",
        );
        assert!(
            TrustedFiniteJournalHistory::from_transport_verified_entries(&cfg, vec![claim, gap])
                .is_err()
        );
    }

    #[test]
    fn counterfeit_heartbeat_from_second_trusted_actor_is_rejected() {
        let cfg = config();
        let claim = verified_entry(
            ANCHOR,
            &oid(1),
            "evt-claim",
            &CoordinationIntent::claim(
                cfg.anchor_item(),
                "evt-claim",
                ANCHOR,
                owner("run", "nonce"),
                vec!["path:src/a".to_string()],
                cfg.timing(),
            )
            .expect("claim"),
            &trusted_actor_a(),
            T0,
            "c-claim",
        );
        let counterfeit = verified_entry(
            &oid(1),
            &oid(2),
            "evt-heartbeat",
            &CoordinationIntent::heartbeat(
                cfg.anchor_item(),
                "evt-heartbeat",
                oid(1),
                owner("run", "nonce"),
            )
            .expect("heartbeat"),
            &trusted_actor_b(),
            T30,
            "c-heartbeat",
        );
        assert!(reduce_entries_result(vec![claim, counterfeit], None).is_err());
    }

    #[test]
    fn edited_comment_actor_parent_or_digest_mismatch_is_rejected() {
        let cfg = config();
        let intent = CoordinationIntent::claim(
            cfg.anchor_item(),
            "evt-claim",
            ANCHOR,
            owner("run", "nonce"),
            vec!["path:src/a".to_string()],
            cfg.timing(),
        )
        .expect("claim");
        let body = intent.render().expect("render");
        let pointer = JournalPointer::new(
            "evt-claim",
            object(ProviderObjectKind::Comment, "c-claim"),
            sha256_hex(body.as_bytes()),
            ANCHOR,
        )
        .expect("pointer");
        let tampered = comment("c-claim", &trusted_actor_a(), T0, &body);
        let mut evidence =
            AuthenticatedCommentEvidence::from_verified_transport(&tampered, &item()).expect("ev");
        evidence.body.push(' ');
        let entry = VerifiedJournalEntry::new(pointer, oid(1), ANCHOR, evidence).expect("entry");
        assert!(verify_journal_entry_contract(&cfg, &entry, ANCHOR).is_err());

        let wrong_actor = verified_entry(
            ANCHOR,
            &oid(2),
            "evt-claim",
            &intent,
            &actor("intruder"),
            T0,
            "c-other",
        );
        assert!(verify_journal_entry_contract(&cfg, &wrong_actor, ANCHOR).is_err());

        let wrong_parent = verified_entry(
            &oid(9),
            &oid(3),
            "evt-claim",
            &intent,
            &trusted_actor_a(),
            T0,
            "c-parent",
        );
        assert!(verify_journal_entry_contract(&cfg, &wrong_parent, ANCHOR).is_err());
    }

    #[test]
    fn stale_takeover_is_rejected() {
        let cfg = config();
        let claim = verified_entry(
            ANCHOR,
            &oid(1),
            "evt-claim",
            &CoordinationIntent::claim(
                cfg.anchor_item(),
                "evt-claim",
                ANCHOR,
                owner("run-old", "nonce-old"),
                vec!["path:src/a".to_string()],
                cfg.timing(),
            )
            .expect("claim"),
            &trusted_actor_a(),
            T0,
            "c-claim",
        );
        let heartbeat = verified_entry(
            &oid(1),
            &oid(2),
            "evt-heartbeat",
            &CoordinationIntent::heartbeat(
                cfg.anchor_item(),
                "evt-heartbeat",
                oid(1),
                owner("run-old", "nonce-old"),
            )
            .expect("heartbeat"),
            &trusted_actor_a(),
            T30,
            "c-heartbeat",
        );
        let takeover = verified_entry(
            &oid(2),
            &oid(3),
            "evt-takeover",
            &CoordinationIntent::takeover(
                cfg.anchor_item(),
                "evt-takeover",
                oid(2),
                owner("run-new", "nonce-new"),
                owner("run-old", "nonce-old"),
                vec!["path:src/a".to_string()],
                cfg.timing(),
            )
            .expect("takeover"),
            &trusted_actor_a(),
            T60,
            "c-takeover",
        );
        assert!(reduce_entries_result(vec![claim, heartbeat, takeover], None).is_err());
    }

    #[test]
    fn reserve_blocks_expired_owner_takeover_and_release() {
        let cfg = config();
        let claim = verified_entry(
            ANCHOR,
            &oid(1),
            "evt-claim",
            &CoordinationIntent::claim(
                cfg.anchor_item(),
                "evt-claim",
                ANCHOR,
                owner("run-old", "nonce-old"),
                vec!["path:src/a".to_string()],
                cfg.timing(),
            )
            .expect("claim"),
            &trusted_actor_a(),
            T0,
            "c-claim",
        );
        let reserve = verified_entry(
            &oid(1),
            &oid(2),
            "evt-reserve",
            &CoordinationIntent::effect_reserve(
                cfg.anchor_item(),
                "evt-reserve",
                oid(1),
                owner("run-old", "nonce-old"),
                "effect-1",
            )
            .expect("reserve"),
            &trusted_actor_a(),
            T30,
            "c-reserve",
        );
        let takeover = verified_entry(
            &oid(2),
            &oid(3),
            "evt-takeover",
            &CoordinationIntent::takeover(
                cfg.anchor_item(),
                "evt-takeover",
                oid(2),
                owner("run-new", "nonce-new"),
                owner("run-old", "nonce-old"),
                vec!["path:src/a".to_string()],
                cfg.timing(),
            )
            .expect("takeover"),
            &trusted_actor_a(),
            T90,
            "c-takeover",
        );
        assert!(reduce_entries_result(vec![claim.clone(), reserve, takeover], None).is_err());
        let reserve2 = verified_entry(
            &oid(1),
            &oid(5),
            "evt-reserve-2",
            &CoordinationIntent::effect_reserve(
                cfg.anchor_item(),
                "evt-reserve-2",
                oid(1),
                owner("run-old", "nonce-old"),
                "effect-2",
            )
            .expect("reserve"),
            &trusted_actor_a(),
            T30,
            "c-reserve-2",
        );
        let release = verified_entry(
            &oid(5),
            &oid(6),
            "evt-release",
            &CoordinationIntent::release(
                cfg.anchor_item(),
                "evt-release",
                oid(5),
                owner("run-old", "nonce-old"),
                "done",
            )
            .expect("release"),
            &trusted_actor_a(),
            T90,
            "c-release",
        );
        assert!(reduce_entries_result(vec![claim, reserve2, release], None).is_err());
    }

    #[test]
    fn fresh_host_bound_effect_replay_without_opaque_verifier() {
        use crate::publication::coordination_effect::{
            canonical_git_push_publication_fixture, GitPushParentObservationV1,
            ParentObservedPublicationMaterialV1, ParentObservedPublicationObservationV1,
        };
        let cfg = config();
        let descriptor = canonical_git_push_publication_fixture().expect("descriptor");
        let effect_id = descriptor.effect_id();
        let claim = verified_entry(
            ANCHOR,
            &oid(1),
            "evt-claim",
            &CoordinationIntent::claim(
                cfg.anchor_item(),
                "evt-claim",
                ANCHOR,
                owner("run", "nonce"),
                vec!["path:src/a".to_string()],
                cfg.timing(),
            )
            .expect("claim"),
            &trusted_actor_a(),
            T0,
            "c-claim",
        );
        let reserve = verified_entry(
            &oid(1),
            &oid(2),
            "evt-reserve",
            &CoordinationIntent::effect_reserve_bound(
                cfg.anchor_item(),
                "evt-reserve",
                oid(1),
                owner("run", "nonce"),
                descriptor.clone(),
            )
            .expect("reserve"),
            &trusted_actor_a(),
            T30,
            "c-reserve",
        );
        let material = ParentObservedPublicationMaterialV1::try_new(
            "evt-reserve",
            descriptor.clone(),
            ParentObservedPublicationObservationV1::GitPush(
                GitPushParentObservationV1::try_new("refs/heads/maco/effects/abcd", "d".repeat(40))
                    .expect("git observation"),
            ),
        )
        .expect("material");
        let receipt = EffectReconciliationReceipt::new_bound(
            effect_id,
            EffectReconciliationOutcome::Completed,
            material,
        )
        .expect("receipt");
        let complete = verified_entry(
            &oid(2),
            &oid(3),
            "evt-complete",
            &CoordinationIntent::effect_complete(
                cfg.anchor_item(),
                "evt-complete",
                oid(2),
                owner("run", "nonce"),
                effect_id,
                receipt,
            )
            .expect("complete"),
            &trusted_actor_a(),
            T60,
            "c-complete",
        );
        let snapshot = reduce_history(vec![claim, reserve, complete], None);
        assert!(snapshot.pending_reservations().is_empty());
    }

    #[test]
    fn false_effect_completion_is_rejected_without_verifier() {
        let cfg = config();
        let claim = verified_entry(
            ANCHOR,
            &oid(1),
            "evt-claim",
            &CoordinationIntent::claim(
                cfg.anchor_item(),
                "evt-claim",
                ANCHOR,
                owner("run", "nonce"),
                vec!["path:src/a".to_string()],
                cfg.timing(),
            )
            .expect("claim"),
            &trusted_actor_a(),
            T0,
            "c-claim",
        );
        let reserve = verified_entry(
            &oid(1),
            &oid(2),
            "evt-reserve",
            &CoordinationIntent::effect_reserve(
                cfg.anchor_item(),
                "evt-reserve",
                oid(1),
                owner("run", "nonce"),
                "effect-1",
            )
            .expect("reserve"),
            &trusted_actor_a(),
            T30,
            "c-reserve",
        );
        let receipt = EffectReconciliationReceipt::new(
            "effect-1",
            EffectReconciliationOutcome::Completed,
            "c".repeat(64),
        )
        .expect("receipt");
        let complete = verified_entry(
            &oid(2),
            &oid(3),
            "evt-complete",
            &CoordinationIntent::effect_complete(
                cfg.anchor_item(),
                "evt-complete",
                oid(2),
                owner("run", "nonce"),
                "effect-1",
                receipt,
            )
            .expect("complete"),
            &trusted_actor_a(),
            T60,
            "c-complete",
        );
        assert!(reduce_entries_result(
            vec![claim.clone(), reserve.clone(), complete.clone()],
            None
        )
        .is_err());
        let reconciler = TestReconciler {
            digest: "c".repeat(64),
        };
        let snapshot = reduce_history(vec![claim, reserve, complete], Some(&reconciler));
        assert!(snapshot.pending_reservations().is_empty());
    }

    #[test]
    fn uncertain_cas_finds_ancestor_nonce_not_only_tip() {
        let cfg = config();
        let claim = verified_entry(
            ANCHOR,
            &oid(1),
            "evt-claim",
            &CoordinationIntent::claim(
                cfg.anchor_item(),
                "evt-claim",
                ANCHOR,
                owner("run", "nonce"),
                vec!["path:src/a".to_string()],
                cfg.timing(),
            )
            .expect("claim"),
            &trusted_actor_a(),
            T0,
            "c-claim",
        );
        let heartbeat = verified_entry(
            &oid(1),
            &oid(2),
            "evt-heartbeat",
            &CoordinationIntent::heartbeat(
                cfg.anchor_item(),
                "evt-heartbeat",
                oid(1),
                owner("run", "nonce"),
            )
            .expect("heartbeat"),
            &trusted_actor_a(),
            T30,
            "c-heartbeat",
        );
        let snapshot = reduce_history(vec![claim, heartbeat], None);
        assert_eq!(snapshot.journal_head_oid(), oid(2));
        match snapshot.locate_event_nonce("evt-claim") {
            CasNonceLocation::Committed { commit_oid, .. } => assert_eq!(commit_oid, oid(1)),
            other => panic!("expected ancestor lookup, got {other:?}"),
        }
        assert!(matches!(
            snapshot.locate_event_nonce("evt-missing"),
            CasNonceLocation::Absent
        ));
    }

    #[test]
    fn journal_config_rejects_non_heads_refs() {
        assert!(CoordinationJournalConfig::new(
            item(),
            "refs/remotes/origin/main",
            ANCHOR,
            vec![actor("trusted-a")],
            ClaimTiming::new(10, 30).expect("timing"),
        )
        .is_err());
    }

    #[test]
    fn unbound_comment_has_no_effect_on_reduction() {
        let raw = "plain discussion with no marker";
        let forge_comment = comment("c-plain", &trusted_actor_a(), T0, raw);
        let evidence =
            AuthenticatedCommentEvidence::from_verified_transport(&forge_comment, &item())
                .expect("evidence");
        assert!(CoordinationIntent::parse(evidence.body())
            .expect("parse")
            .is_none());
    }
}
