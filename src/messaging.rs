//! Authenticated, durable inter-agent message transport.
//!
//! The broker implements explicit at-least-once delivery. A successful receive
//! durably records a delivery attempt before returning the envelope; the same
//! recipient can receive it again until a durable acknowledgement is recorded.
//! Sender roles are always read from the hierarchy authority binding captured
//! when the broker is created. Presented credentials and their secrets are
//! intentionally memory-only and never enter envelopes or store events.

pub mod envelope;
pub mod store;
pub mod turn;

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::Path,
};

use serde_json::Value;
use thiserror::Error;

use crate::{
    artifacts::state_auth::{random_identifier, sha256_hex},
    hierarchy_ledger::{HierarchyLedgerSnapshot, RoleCategory},
};

pub use envelope::{
    DeliveryGuarantee, EnvelopeValidationError, GovernedChannel, MessageAddress, MessageEnvelope,
    MessageId, MessagingLimits, RecipientDeliveryState,
};
pub use turn::*;

use store::{
    absolute_normalized_store_path, MessagingStore, StoreError, StoreEvent, StoreIntegrityKey,
};

const MAX_CREDENTIAL_SECRET_BYTES: usize = 4_096;
const MAX_CREDENTIALS_HARD_LIMIT: usize = 4_096;
const MAX_IDENTIFIER_BYTES: usize = 256;
// Substring exclusion remains fail-closed, but one attempted append may spend
// no more than this many bounded comparison-work units inspecting credentials.
const MAX_CREDENTIAL_INSPECTION_WORK: usize = 64 * 1024 * 1024;
const BROKER_ID_PREFIX: &str = "messaging-v1";
const BROKER_BINDING_DOMAIN: &[u8] = b"MACO\0messaging-broker-store-binding\0sha256\0v1\0";
const STORE_KEY_CREDENTIAL_DOMAIN: &[u8] = b"MACO\0messaging-store-integrity-key\0credential\0v1\0";
const STORE_KEY_AGGREGATE_DOMAIN: &[u8] = b"MACO\0messaging-store-integrity-key\0aggregate\0v1\0";

/// A caller-presented identity and secret.
///
/// The fields are private and `Debug` always redacts the secret. This value is
/// never serializable, and the broker never copies it into durable state.
#[derive(Clone, Eq, PartialEq)]
pub struct PresentedCredential {
    agent_id: String,
    secret: String,
}

impl PresentedCredential {
    pub fn new(
        agent_id: impl Into<String>,
        secret: impl Into<String>,
    ) -> Result<Self, MessagingError> {
        let agent_id = agent_id.into();
        let secret = secret.into();
        validate_identifier("credential agent id", &agent_id, MAX_IDENTIFIER_BYTES)?;
        validate_secret(&secret)?;
        Ok(Self { agent_id, secret })
    }

    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }
}

impl fmt::Debug for PresentedCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PresentedCredential")
            .field("agent_id", &self.agent_id)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// A bounded in-memory credential registry.
///
/// Registration returns a presentation value for convenience. Only agent ids
/// are exposed by `Debug`; secrets remain process-local and are not serialized.
#[derive(Clone)]
pub struct CredentialRegistry {
    max_credentials: usize,
    credentials: BTreeMap<String, String>,
}

impl CredentialRegistry {
    pub fn new(max_credentials: usize) -> Result<Self, MessagingError> {
        if max_credentials == 0 || max_credentials > MAX_CREDENTIALS_HARD_LIMIT {
            return Err(MessagingError::InvalidCredentialLimit {
                requested: max_credentials,
                hard_limit: MAX_CREDENTIALS_HARD_LIMIT,
            });
        }
        Ok(Self {
            max_credentials,
            credentials: BTreeMap::new(),
        })
    }

    pub fn register(
        &mut self,
        agent_id: impl Into<String>,
        secret: impl Into<String>,
    ) -> Result<PresentedCredential, MessagingError> {
        let presented = PresentedCredential::new(agent_id, secret)?;
        if let Some(existing) = self.credentials.get(presented.agent_id()) {
            if secrets_equal(existing.as_bytes(), presented.secret.as_bytes()) {
                return Err(MessagingError::DuplicateCredential {
                    agent_id: presented.agent_id.clone(),
                });
            }
            return Err(MessagingError::ConflictingCredential {
                agent_id: presented.agent_id.clone(),
            });
        }
        let mut secret_reused = false;
        for existing in self.credentials.values() {
            secret_reused |= secrets_equal(existing.as_bytes(), presented.secret.as_bytes());
        }
        if secret_reused {
            return Err(MessagingError::CredentialSecretReuse {
                agent_id: presented.agent_id.clone(),
            });
        }
        if self.credentials.len() >= self.max_credentials {
            return Err(MessagingError::CredentialCapacityExceeded {
                limit: self.max_credentials,
            });
        }
        self.credentials
            .insert(presented.agent_id.clone(), presented.secret.clone());
        Ok(presented)
    }

    pub fn from_limits(limits: &MessagingLimits) -> Result<Self, MessagingError> {
        Self::new(limits.max_credentials)
    }

    pub fn len(&self) -> usize {
        self.credentials.len()
    }

    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty()
    }

    pub fn contains_principal(&self, agent_id: &str) -> bool {
        self.credentials.contains_key(agent_id)
    }

    fn authenticate(&self, presented: &PresentedCredential) -> Result<(), MessagingError> {
        let Some(expected) = self.credentials.get(presented.agent_id()) else {
            return Err(MessagingError::UnknownCredential {
                agent_id: presented.agent_id.clone(),
            });
        };
        if !secrets_equal(expected.as_bytes(), presented.secret.as_bytes()) {
            return Err(MessagingError::BadCredential {
                agent_id: presented.agent_id.clone(),
            });
        }
        Ok(())
    }

    fn principals(&self) -> impl Iterator<Item = &str> {
        self.credentials.keys().map(String::as_str)
    }

    fn payload_contains_registered_secret(&self, payload: &Value) -> Result<bool, MessagingError> {
        self.payload_contains_registered_secret_with_budget(payload, MAX_CREDENTIAL_INSPECTION_WORK)
    }

    fn payload_contains_registered_secret_with_budget(
        &self,
        payload: &Value,
        max_work: usize,
    ) -> Result<bool, MessagingError> {
        let mut found = false;
        let mut pending = vec![payload];
        let mut work_used = 0_usize;
        while let Some(value) = pending.pop() {
            match value {
                Value::String(string) => {
                    found |=
                        self.string_contains_registered_secret(string, &mut work_used, max_work)?;
                }
                Value::Array(values) => pending.extend(values.iter()),
                Value::Object(entries) => {
                    for (key, value) in entries {
                        found |=
                            self.string_contains_registered_secret(key, &mut work_used, max_work)?;
                        pending.push(value);
                    }
                }
                Value::Null | Value::Bool(_) | Value::Number(_) => {}
            }
        }
        Ok(found)
    }

    fn string_contains_registered_secret(
        &self,
        value: &str,
        work_used: &mut usize,
        max_work: usize,
    ) -> Result<bool, MessagingError> {
        let mut found = false;
        for secret in self.credentials.values() {
            let work = credential_substring_scan_work(value.len(), secret.len())
                .ok_or(MessagingError::PayloadCredentialInspectionLimitExceeded { max_work })?;
            charge_credential_inspection(work_used, work, max_work)?;
            found |= contains_bytes_constant_time(value.as_bytes(), secret.as_bytes());
        }
        Ok(found)
    }
}

impl fmt::Debug for CredentialRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let principals: Vec<&str> = self.principals().collect();
        formatter
            .debug_struct("CredentialRegistry")
            .field("max_credentials", &self.max_credentials)
            .field("principals", &principals)
            .finish()
    }
}

/// Result of an authenticated durable acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcknowledgementOutcome {
    Acknowledged,
    AlreadyAcknowledged,
}

/// Typed refusals and persistence failures from the messaging broker.
#[derive(Debug, Error)]
pub enum MessagingError {
    #[error("credential registry bound {requested} is outside 1..={hard_limit}")]
    InvalidCredentialLimit { requested: usize, hard_limit: usize },
    #[error("credential secret must contain 1..={MAX_CREDENTIAL_SECRET_BYTES} bytes")]
    InvalidCredentialSecret,
    #[error("messaging store integrity key derivation failed")]
    IntegrityKeyDerivation,
    #[error("messaging broker store binding derivation failed")]
    BrokerBindingDerivation,
    #[error("messaging broker instance identity generation failed")]
    BrokerIdentityGeneration,
    #[error("{field} is malformed")]
    InvalidIdentifier { field: &'static str },
    #[error("credential registry reached its bound of {limit} principals")]
    CredentialCapacityExceeded { limit: usize },
    #[error("credential for principal {agent_id:?} is already registered")]
    DuplicateCredential { agent_id: String },
    #[error("credential for principal {agent_id:?} conflicts with an existing registration")]
    ConflictingCredential { agent_id: String },
    #[error("credential secret for principal {agent_id:?} is already bound to another principal")]
    CredentialSecretReuse { agent_id: String },
    #[error("credential principal {agent_id:?} is unknown")]
    UnknownCredential { agent_id: String },
    #[error("credential for principal {agent_id:?} is invalid")]
    BadCredential { agent_id: String },
    #[error("credential principal {agent_id:?} is absent from the hierarchy authority binding")]
    UnknownAuthorityPrincipal { agent_id: String },
    #[error("the credential registry contains no principals")]
    EmptyCredentialRegistry,
    #[error("principal {agent_id:?} is not a delegating coordinator")]
    UnauthorizedChannelCreator { agent_id: String },
    #[error("channel {channel_id:?} already exists")]
    DuplicateChannel { channel_id: String },
    #[error("governed channel capacity is exhausted at {limit} channels")]
    ChannelCapacityExceeded { limit: usize },
    #[error("channel {channel_id:?} has a duplicate member {agent_id:?}")]
    DuplicateChannelMember {
        channel_id: String,
        agent_id: String,
    },
    #[error("channel {channel_id:?} has a duplicate publisher {agent_id:?}")]
    DuplicateChannelPublisher {
        channel_id: String,
        agent_id: String,
    },
    #[error("channel {channel_id:?} exceeds its {limit}-member limit")]
    TooManyChannelMembers { channel_id: String, limit: usize },
    #[error("channel {channel_id:?} exceeds its {limit}-publisher limit")]
    TooManyChannelPublishers { channel_id: String, limit: usize },
    #[error("channel {channel_id:?} policy is invalid")]
    InvalidChannelPolicy { channel_id: String },
    #[error("channel {channel_id:?} is unknown")]
    UnknownChannel { channel_id: String },
    #[error("principal {agent_id:?} is not a member of channel {channel_id:?}")]
    NonMemberDelivery {
        channel_id: String,
        agent_id: String,
    },
    #[error("principal {agent_id:?} is not a member of channel {channel_id:?}")]
    NonMemberChannelOperation {
        channel_id: String,
        agent_id: String,
    },
    #[error("principal {agent_id:?} cannot publish to channel {channel_id:?}")]
    UnauthorizedBroadcastPublication {
        channel_id: String,
        agent_id: String,
    },
    #[error("direct recipient {recipient_id:?} is unknown")]
    UnknownRecipient { recipient_id: String },
    #[error("direct recipient {recipient_id:?} is known but not credential-addressable")]
    MisaddressedRecipient { recipient_id: String },
    #[error("principal {agent_id:?} is not a recipient of direct message {message_id}")]
    NonRecipientDelivery {
        message_id: MessageId,
        agent_id: String,
    },
    #[error("principal {agent_id:?} is not a recipient of message {message_id}")]
    NonRecipientAcknowledgement {
        message_id: MessageId,
        agent_id: String,
    },
    #[error(
        "principal {agent_id:?} is not a member of channel {channel_id:?} and cannot acknowledge message {message_id}"
    )]
    NonMemberAcknowledgement {
        channel_id: String,
        message_id: MessageId,
        agent_id: String,
    },
    #[error("message {message_id} is unknown")]
    UnknownMessage { message_id: MessageId },
    #[error("message sequence or identifier space is exhausted")]
    MessageSequenceExhausted,
    #[error("message capacity is exhausted at {limit} messages")]
    MessageCapacityExceeded { limit: usize },
    #[error("message {message_id} delivery attempts are exhausted for recipient {recipient_id:?}")]
    DeliveryAttemptLimitExceeded {
        message_id: MessageId,
        recipient_id: String,
    },
    #[error("message payload contains registered credential material")]
    PayloadContainsCredentialSecret,
    #[error("message payload credential inspection exceeds the {max_work}-work-unit safety limit")]
    PayloadCredentialInspectionLimitExceeded { max_work: usize },
    #[error("durable messaging state is inconsistent: {kind}")]
    InconsistentState { kind: &'static str },
    #[error("messaging envelope is invalid: {0}")]
    Envelope(#[from] EnvelopeValidationError),
    #[error("messaging store failed: {0}")]
    Store(#[from] StoreError),
}

/// Durable authenticated direct-message and governed-channel broker.
pub struct MessagingBroker {
    store: MessagingStore,
    credentials: CredentialRegistry,
    authority_binding: BTreeMap<String, RoleCategory>,
    limits: MessagingLimits,
    channels: BTreeMap<String, GovernedChannel>,
    messages: BTreeMap<MessageId, MessageEnvelope>,
    message_order: Vec<MessageId>,
    next_sequence: u64,
}

impl MessagingBroker {
    pub fn create(
        path: impl AsRef<Path>,
        credentials: CredentialRegistry,
        hierarchy: &HierarchyLedgerSnapshot,
        limits: MessagingLimits,
    ) -> Result<Self, MessagingError> {
        limits.validate()?;
        validate_registry_binding(&credentials, &hierarchy.effective_categories)?;
        validate_registry_limits(&credentials, &limits)?;
        let integrity_key = derive_store_integrity_key(&credentials)?;
        let path = absolute_normalized_store_path(path.as_ref())?;
        let broker_binding = broker_instance_binding(&path, &hierarchy.effective_categories)?;
        let generation =
            random_identifier().map_err(|_| MessagingError::BrokerIdentityGeneration)?;
        let broker_instance_id = format!("{broker_binding}-{generation}");
        let store = MessagingStore::create(
            &path,
            broker_instance_id,
            hierarchy.effective_categories.clone(),
            limits.clone(),
            integrity_key,
        )?;
        Self::from_store(store, credentials, hierarchy, limits)
    }

    pub fn open(
        path: impl AsRef<Path>,
        credentials: CredentialRegistry,
        hierarchy: &HierarchyLedgerSnapshot,
        limits: MessagingLimits,
    ) -> Result<Self, MessagingError> {
        limits.validate()?;
        validate_registry_binding(&credentials, &hierarchy.effective_categories)?;
        validate_registry_limits(&credentials, &limits)?;
        let integrity_key = derive_store_integrity_key(&credentials)?;
        let path = absolute_normalized_store_path(path.as_ref())?;
        let expected_broker_binding =
            broker_instance_binding(&path, &hierarchy.effective_categories)?;
        let store = MessagingStore::open(
            &path,
            &expected_broker_binding,
            &hierarchy.effective_categories,
            &limits,
            integrity_key,
        )?;
        Self::from_store(store, credentials, hierarchy, limits)
    }

    pub fn open_or_create(
        path: impl AsRef<Path>,
        credentials: CredentialRegistry,
        hierarchy: &HierarchyLedgerSnapshot,
        limits: MessagingLimits,
    ) -> Result<Self, MessagingError> {
        let path = absolute_normalized_store_path(path.as_ref())?;
        if MessagingStore::exists(&path) {
            Self::open(&path, credentials, hierarchy, limits)
        } else {
            Self::create(&path, credentials, hierarchy, limits)
        }
    }

    pub fn broker_instance_id(&self) -> &str {
        &self.store.header().broker_instance_id
    }

    pub fn create_channel<I, M, P, Q>(
        &mut self,
        credential: &PresentedCredential,
        channel_id: impl Into<String>,
        members: I,
        publishers: P,
    ) -> Result<GovernedChannel, MessagingError>
    where
        I: IntoIterator<Item = M>,
        M: Into<String>,
        P: IntoIterator<Item = Q>,
        Q: Into<String>,
    {
        let (creator_id, creator_role) = self.authenticate(credential)?;
        if creator_role != RoleCategory::DelegatingCoordinator {
            return Err(MessagingError::UnauthorizedChannelCreator {
                agent_id: creator_id.to_string(),
            });
        }

        let channel_id = channel_id.into();
        validate_identifier("channel id", &channel_id, self.limits.max_identifier_bytes)?;
        if self.channels.contains_key(&channel_id) {
            return Err(MessagingError::DuplicateChannel { channel_id });
        }
        if self.channels.len() >= self.limits.max_channels {
            return Err(MessagingError::ChannelCapacityExceeded {
                limit: self.limits.max_channels,
            });
        }
        let members = collect_unique_policy(
            &channel_id,
            members,
            self.limits.max_members_per_channel,
            self.limits.max_identifier_bytes,
            |channel_id, agent_id| MessagingError::DuplicateChannelMember {
                channel_id,
                agent_id,
            },
            |channel_id, limit| MessagingError::TooManyChannelMembers { channel_id, limit },
        )?;
        let publishers = collect_unique_policy(
            &channel_id,
            publishers,
            self.limits.max_publishers_per_channel,
            self.limits.max_identifier_bytes,
            |channel_id, agent_id| MessagingError::DuplicateChannelPublisher {
                channel_id,
                agent_id,
            },
            |channel_id, limit| MessagingError::TooManyChannelPublishers { channel_id, limit },
        )?;

        if !members.contains(&creator_id)
            || !publishers.contains(&creator_id)
            || publishers.is_empty()
            || members.is_empty()
            || !publishers.is_subset(&members)
        {
            return Err(MessagingError::InvalidChannelPolicy { channel_id });
        }
        for principal in members.iter().chain(publishers.iter()) {
            if !self.authority_binding.contains_key(principal) {
                return Err(MessagingError::UnknownRecipient {
                    recipient_id: principal.clone(),
                });
            }
            if !self.credentials.contains_principal(principal) {
                return Err(MessagingError::MisaddressedRecipient {
                    recipient_id: principal.clone(),
                });
            }
        }

        let channel = GovernedChannel::new(channel_id.clone(), members, publishers, &self.limits)
            .map_err(|_| MessagingError::InvalidChannelPolicy {
            channel_id: channel_id.clone(),
        })?;
        self.store.append(StoreEvent::ChannelCreated {
            channel: channel.clone(),
        })?;
        self.channels.insert(channel_id, channel.clone());
        Ok(channel)
    }

    pub fn send_direct(
        &mut self,
        credential: &PresentedCredential,
        recipient_id: impl Into<String>,
        payload: impl Into<Value>,
    ) -> Result<MessageEnvelope, MessagingError> {
        let (sender_id, sender_role) = self.authenticate(credential)?;
        let recipient_id = recipient_id.into();
        validate_identifier(
            "direct recipient id",
            &recipient_id,
            self.limits.max_identifier_bytes,
        )?;
        if !self.authority_binding.contains_key(&recipient_id) {
            return Err(MessagingError::UnknownRecipient { recipient_id });
        }
        if !self.credentials.contains_principal(&recipient_id) {
            return Err(MessagingError::MisaddressedRecipient { recipient_id });
        }
        let recipients = BTreeSet::from([recipient_id.clone()]);
        self.append_message(
            MessageAddress::Direct { recipient_id },
            &sender_id,
            sender_role,
            recipients,
            payload.into(),
        )
    }

    pub fn publish_channel(
        &mut self,
        credential: &PresentedCredential,
        channel_id: impl Into<String>,
        payload: impl Into<Value>,
    ) -> Result<MessageEnvelope, MessagingError> {
        let (sender_id, sender_role) = self.authenticate(credential)?;
        let channel_id = channel_id.into();
        validate_identifier("channel id", &channel_id, self.limits.max_identifier_bytes)?;
        let Some(channel) = self.channels.get(&channel_id) else {
            return Err(MessagingError::UnknownChannel { channel_id });
        };
        if !channel.members.contains(&sender_id) {
            return Err(MessagingError::NonMemberChannelOperation {
                channel_id,
                agent_id: sender_id,
            });
        }
        if !channel.publishers.contains(&sender_id) {
            return Err(MessagingError::UnauthorizedBroadcastPublication {
                channel_id,
                agent_id: sender_id,
            });
        }
        let recipients = channel.members.clone();
        self.append_message(
            MessageAddress::Channel {
                channel_id: channel_id.clone(),
            },
            &sender_id,
            sender_role,
            recipients,
            payload.into(),
        )
    }

    /// Returns the oldest unacknowledged message addressed to the caller.
    ///
    /// A delivery attempt is durably appended before the envelope is returned.
    pub fn receive_next(
        &mut self,
        credential: &PresentedCredential,
    ) -> Result<Option<MessageEnvelope>, MessagingError> {
        let (recipient_id, _) = self.authenticate(credential)?;
        let selected = self.message_order.iter().find_map(|message_id| {
            self.messages.get(message_id).and_then(|message| {
                message
                    .recipients
                    .get(&recipient_id)
                    .and_then(|state| (!state.acknowledged).then(|| message_id.clone()))
            })
        });
        selected
            .map(|message_id| self.record_delivery_attempt(&message_id, &recipient_id))
            .transpose()
    }

    /// Delivers one exact message to an authenticated intended recipient.
    ///
    /// Authorization and delivery eligibility are checked before the durable
    /// attempt is appended. An acknowledged recipient receives `None` and is
    /// never redelivered.
    pub fn receive_message(
        &mut self,
        credential: &PresentedCredential,
        message_id: &MessageId,
    ) -> Result<Option<MessageEnvelope>, MessagingError> {
        let (recipient_id, _) = self.authenticate(credential)?;
        message_id.validate(&self.limits)?;
        let Some(message) = self.messages.get(message_id) else {
            return Err(MessagingError::UnknownMessage {
                message_id: message_id.clone(),
            });
        };
        let Some(delivery) = message.recipients.get(&recipient_id) else {
            return match &message.address {
                MessageAddress::Direct { .. } => Err(MessagingError::NonRecipientDelivery {
                    message_id: message_id.clone(),
                    agent_id: recipient_id,
                }),
                MessageAddress::Channel { channel_id } => Err(MessagingError::NonMemberDelivery {
                    channel_id: channel_id.clone(),
                    agent_id: recipient_id,
                }),
            };
        };
        if delivery.acknowledged {
            return Ok(None);
        }
        self.record_delivery_attempt(message_id, &recipient_id)
            .map(Some)
    }

    /// Returns the oldest unacknowledged channel message for a member.
    ///
    /// Calling this method as a non-member is an explicit typed refusal rather
    /// than an empty receive result.
    pub fn receive_next_from_channel(
        &mut self,
        credential: &PresentedCredential,
        channel_id: impl Into<String>,
    ) -> Result<Option<MessageEnvelope>, MessagingError> {
        let (recipient_id, _) = self.authenticate(credential)?;
        let channel_id = channel_id.into();
        validate_identifier("channel id", &channel_id, self.limits.max_identifier_bytes)?;
        let Some(channel) = self.channels.get(&channel_id) else {
            return Err(MessagingError::UnknownChannel { channel_id });
        };
        if !channel.members.contains(&recipient_id) {
            return Err(MessagingError::NonMemberDelivery {
                channel_id,
                agent_id: recipient_id.to_string(),
            });
        }
        let selected = self.message_order.iter().find_map(|message_id| {
            self.messages.get(message_id).and_then(|message| {
                let belongs_to_channel = matches!(
                    &message.address,
                    MessageAddress::Channel { channel_id: message_channel }
                        if message_channel == &channel_id
                );
                if !belongs_to_channel {
                    return None;
                }
                message
                    .recipients
                    .get(&recipient_id)
                    .and_then(|state| (!state.acknowledged).then(|| message_id.clone()))
            })
        });
        selected
            .map(|message_id| self.record_delivery_attempt(&message_id, &recipient_id))
            .transpose()
    }

    pub fn acknowledge(
        &mut self,
        credential: &PresentedCredential,
        message_id: &MessageId,
    ) -> Result<AcknowledgementOutcome, MessagingError> {
        let (recipient_id, _) = self.authenticate(credential)?;
        message_id.validate(&self.limits)?;
        let Some(message) = self.messages.get(message_id) else {
            return Err(MessagingError::UnknownMessage {
                message_id: message_id.clone(),
            });
        };
        let Some(delivery) = message.recipients.get(&recipient_id) else {
            return match &message.address {
                MessageAddress::Channel { channel_id } => {
                    Err(MessagingError::NonMemberAcknowledgement {
                        channel_id: channel_id.clone(),
                        message_id: message_id.clone(),
                        agent_id: recipient_id,
                    })
                }
                MessageAddress::Direct { .. } => Err(MessagingError::NonRecipientAcknowledgement {
                    message_id: message_id.clone(),
                    agent_id: recipient_id,
                }),
            };
        };
        if delivery.acknowledged {
            return Ok(AcknowledgementOutcome::AlreadyAcknowledged);
        }
        if delivery.delivery_attempts == 0 {
            return Err(MessagingError::InconsistentState {
                kind: "acknowledgement before first delivery is forbidden",
            });
        }

        self.store.append(StoreEvent::Acknowledged {
            message_id: message_id.clone(),
            recipient_id: recipient_id.clone(),
        })?;
        let Some(message) = self.messages.get_mut(message_id) else {
            return Err(MessagingError::InconsistentState {
                kind: "message disappeared after acknowledgement append",
            });
        };
        let Some(delivery) = message.recipients.get_mut(&recipient_id) else {
            return Err(MessagingError::InconsistentState {
                kind: "recipient disappeared after acknowledgement append",
            });
        };
        if !delivery
            .acknowledge()
            .map_err(|_| MessagingError::InconsistentState {
                kind: "recipient became ineligible after acknowledgement append",
            })?
        {
            return Err(MessagingError::InconsistentState {
                kind: "recipient became acknowledged after acknowledgement append",
            });
        }
        Ok(AcknowledgementOutcome::Acknowledged)
    }

    pub fn channel(&self, channel_id: &str) -> Option<&GovernedChannel> {
        self.channels.get(channel_id)
    }

    #[cfg(test)]
    fn message_for_test(&self, message_id: &MessageId) -> Option<&MessageEnvelope> {
        self.messages.get(message_id)
    }

    fn from_store(
        store: MessagingStore,
        credentials: CredentialRegistry,
        hierarchy: &HierarchyLedgerSnapshot,
        limits: MessagingLimits,
    ) -> Result<Self, MessagingError> {
        if store.header().authority_binding != hierarchy.effective_categories {
            return Err(MessagingError::InconsistentState {
                kind: "persisted hierarchy authority binding changed",
            });
        }
        if store.header().limits != limits {
            return Err(MessagingError::InconsistentState {
                kind: "persisted messaging limits changed",
            });
        }

        let mut broker = Self {
            store,
            credentials,
            authority_binding: hierarchy.effective_categories.clone(),
            limits,
            channels: BTreeMap::new(),
            messages: BTreeMap::new(),
            message_order: Vec::new(),
            next_sequence: 1,
        };
        broker.replay()?;
        Ok(broker)
    }

    fn authenticate(
        &self,
        credential: &PresentedCredential,
    ) -> Result<(String, RoleCategory), MessagingError> {
        self.credentials.authenticate(credential)?;
        let Some(role) = self.authority_binding.get(credential.agent_id()).copied() else {
            return Err(MessagingError::UnknownAuthorityPrincipal {
                agent_id: credential.agent_id().to_string(),
            });
        };
        Ok((credential.agent_id().to_string(), role))
    }

    fn append_message(
        &mut self,
        address: MessageAddress,
        sender_id: &str,
        sender_role: RoleCategory,
        recipient_ids: BTreeSet<String>,
        payload: Value,
    ) -> Result<MessageEnvelope, MessagingError> {
        if let Err(error) = envelope::validate_payload(&payload, &self.limits) {
            envelope::drop_payload_iteratively(payload);
            return Err(error.into());
        }
        if self
            .credentials
            .payload_contains_registered_secret(&payload)?
        {
            return Err(MessagingError::PayloadContainsCredentialSecret);
        }
        if self.messages.len() >= self.limits.max_messages {
            return Err(MessagingError::MessageCapacityExceeded {
                limit: self.limits.max_messages,
            });
        }
        let sequence = self.next_sequence;
        let id = message_id(self.broker_instance_id(), sequence, &self.limits)?;
        let envelope = MessageEnvelope::new(
            id.clone(),
            address,
            sender_id,
            sender_role,
            sequence,
            payload,
            recipient_ids,
            &self.limits,
        )?;
        if self.messages.contains_key(&id) {
            return Err(MessagingError::InconsistentState {
                kind: "derived message id is duplicated",
            });
        }
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(MessagingError::MessageSequenceExhausted)?;

        self.store.append(StoreEvent::MessageSent {
            envelope: envelope.clone(),
        })?;
        self.messages.insert(id.clone(), envelope.clone());
        self.message_order.push(id);
        self.next_sequence = next_sequence;
        Ok(envelope)
    }

    fn record_delivery_attempt(
        &mut self,
        message_id: &MessageId,
        recipient_id: &str,
    ) -> Result<MessageEnvelope, MessagingError> {
        let Some(message) = self.messages.get(message_id) else {
            return Err(MessagingError::UnknownMessage {
                message_id: message_id.clone(),
            });
        };
        let Some(delivery) = message.recipients.get(recipient_id) else {
            return Err(MessagingError::InconsistentState {
                kind: "delivery selection chose a non-recipient",
            });
        };
        if delivery.acknowledged {
            return Err(MessagingError::InconsistentState {
                kind: "delivery selection chose an acknowledged recipient",
            });
        }
        let mut preview = delivery.clone();
        let attempt = preview.record_delivery_attempt(&self.limits).map_err(|_| {
            MessagingError::DeliveryAttemptLimitExceeded {
                message_id: message_id.clone(),
                recipient_id: recipient_id.to_string(),
            }
        })?;

        self.store.append(StoreEvent::DeliveryAttempted {
            message_id: message_id.clone(),
            recipient_id: recipient_id.to_string(),
            attempt,
        })?;
        let Some(message) = self.messages.get_mut(message_id) else {
            return Err(MessagingError::InconsistentState {
                kind: "message disappeared after delivery append",
            });
        };
        let Some(delivery) = message.recipients.get_mut(recipient_id) else {
            return Err(MessagingError::InconsistentState {
                kind: "recipient disappeared after delivery append",
            });
        };
        *delivery = preview;
        Ok(message.clone())
    }

    fn replay(&mut self) -> Result<(), MessagingError> {
        let events = self.store.events().to_vec();
        for (index, event) in events.into_iter().enumerate() {
            match event {
                StoreEvent::Created {
                    broker_instance_id,
                    authority_binding,
                    limits,
                } => {
                    if index != 0
                        || broker_instance_id != self.store.header().broker_instance_id
                        || authority_binding != self.authority_binding
                        || limits != self.limits
                    {
                        return Err(MessagingError::InconsistentState {
                            kind: "store creation event does not match its header",
                        });
                    }
                }
                StoreEvent::ChannelCreated { channel } => {
                    if index == 0 || self.channels.contains_key(&channel.channel_id) {
                        return Err(MessagingError::InconsistentState {
                            kind: "channel creation is duplicated or precedes store creation",
                        });
                    }
                    if self.channels.len() >= self.limits.max_channels {
                        return Err(MessagingError::InconsistentState {
                            kind: "persisted channel count exceeds its configured bound",
                        });
                    }
                    self.validate_replayed_channel(&channel)?;
                    self.channels.insert(channel.channel_id.clone(), channel);
                }
                StoreEvent::MessageSent { envelope } => {
                    if index == 0 || envelope.sequence != self.next_sequence {
                        return Err(MessagingError::InconsistentState {
                            kind: "message sequence is missing, duplicated, or out of order",
                        });
                    }
                    if self.messages.len() >= self.limits.max_messages {
                        return Err(MessagingError::InconsistentState {
                            kind: "persisted message count exceeds its configured bound",
                        });
                    }
                    let expected_id =
                        message_id(self.broker_instance_id(), envelope.sequence, &self.limits)?;
                    if envelope.id != expected_id || self.messages.contains_key(&envelope.id) {
                        return Err(MessagingError::InconsistentState {
                            kind: "message id is duplicated or inconsistent with its sequence",
                        });
                    }
                    self.validate_replayed_message(&envelope)?;
                    self.next_sequence = self
                        .next_sequence
                        .checked_add(1)
                        .ok_or(MessagingError::MessageSequenceExhausted)?;
                    self.message_order.push(envelope.id.clone());
                    self.messages.insert(envelope.id.clone(), envelope);
                }
                StoreEvent::DeliveryAttempted {
                    message_id,
                    recipient_id,
                    attempt,
                } => {
                    let Some(message) = self.messages.get_mut(&message_id) else {
                        return Err(MessagingError::InconsistentState {
                            kind: "delivery attempt references an unknown message",
                        });
                    };
                    let Some(delivery) = message.recipients.get_mut(&recipient_id) else {
                        return Err(MessagingError::InconsistentState {
                            kind: "delivery attempt references a non-recipient",
                        });
                    };
                    let mut preview = delivery.clone();
                    let expected_attempt =
                        preview.record_delivery_attempt(&self.limits).map_err(|_| {
                            MessagingError::InconsistentState {
                                kind: "persisted delivery attempt exceeds its configured bound",
                            }
                        })?;
                    if expected_attempt != attempt {
                        return Err(MessagingError::InconsistentState {
                            kind: "delivery attempts are duplicated, out of order, or after acknowledgement",
                        });
                    }
                    *delivery = preview;
                }
                StoreEvent::Acknowledged {
                    message_id,
                    recipient_id,
                } => {
                    let Some(message) = self.messages.get_mut(&message_id) else {
                        return Err(MessagingError::InconsistentState {
                            kind: "acknowledgement references an unknown message",
                        });
                    };
                    let Some(delivery) = message.recipients.get_mut(&recipient_id) else {
                        return Err(MessagingError::InconsistentState {
                            kind: "acknowledgement references a non-recipient",
                        });
                    };
                    let first =
                        delivery
                            .acknowledge()
                            .map_err(|_| MessagingError::InconsistentState {
                                kind: "acknowledgement precedes delivery",
                            })?;
                    if !first {
                        return Err(MessagingError::InconsistentState {
                            kind: "acknowledgement is duplicated",
                        });
                    }
                }
            }
        }
        if self.store.events().is_empty() {
            return Err(MessagingError::InconsistentState {
                kind: "store has no creation event",
            });
        }
        Ok(())
    }

    fn validate_replayed_channel(&self, channel: &GovernedChannel) -> Result<(), MessagingError> {
        channel
            .validate(&self.limits)
            .map_err(|_| MessagingError::InconsistentState {
                kind: "persisted channel policy violates messaging bounds",
            })?;
        if channel.members.is_empty()
            || channel.publishers.is_empty()
            || !channel.publishers.is_subset(&channel.members)
            || channel
                .members
                .iter()
                .chain(channel.publishers.iter())
                .any(|principal| !self.authority_binding.contains_key(principal))
        {
            return Err(MessagingError::InconsistentState {
                kind: "persisted channel policy contains an unknown or unauthorized principal",
            });
        }
        if channel
            .members
            .iter()
            .chain(channel.publishers.iter())
            .any(|principal| !self.credentials.contains_principal(principal))
        {
            return Err(MessagingError::InconsistentState {
                kind: "persisted channel policy contains a known but non-addressable principal",
            });
        }
        Ok(())
    }

    fn validate_replayed_message(&self, envelope: &MessageEnvelope) -> Result<(), MessagingError> {
        envelope
            .validate(&self.limits)
            .map_err(|_| MessagingError::InconsistentState {
                kind: "persisted envelope violates messaging bounds",
            })?;
        if envelope.guarantee != DeliveryGuarantee::AtLeastOnce
            || envelope
                .recipients
                .values()
                .any(|delivery| delivery.delivery_attempts != 0 || delivery.acknowledged)
        {
            return Err(MessagingError::InconsistentState {
                kind: "new message contains an unsupported guarantee or pre-mutated delivery state",
            });
        }
        let Some(expected_role) = self.authority_binding.get(&envelope.sender_id).copied() else {
            return Err(MessagingError::InconsistentState {
                kind: "message sender is absent from the authority binding",
            });
        };
        if expected_role != envelope.sender_role {
            return Err(MessagingError::InconsistentState {
                kind: "message sender role differs from the authority binding",
            });
        }
        if envelope
            .recipients
            .keys()
            .any(|recipient| !self.credentials.contains_principal(recipient))
        {
            return Err(MessagingError::InconsistentState {
                kind: "persisted message recipient is no longer credential-addressable",
            });
        }
        match &envelope.address {
            MessageAddress::Direct { recipient_id } => {
                if !self.authority_binding.contains_key(recipient_id)
                    || envelope.recipients.len() != 1
                    || !envelope.recipients.contains_key(recipient_id)
                {
                    return Err(MessagingError::InconsistentState {
                        kind: "direct message recipients do not match its address",
                    });
                }
            }
            MessageAddress::Channel { channel_id } => {
                let Some(channel) = self.channels.get(channel_id) else {
                    return Err(MessagingError::InconsistentState {
                        kind: "channel message references an unknown channel",
                    });
                };
                if !channel.publishers.contains(&envelope.sender_id)
                    || !channel.members.contains(&envelope.sender_id)
                    || envelope.recipients.keys().ne(channel.members.iter())
                {
                    return Err(MessagingError::InconsistentState {
                        kind: "channel message violates persisted publisher or membership policy",
                    });
                }
            }
        }
        Ok(())
    }
}

fn validate_registry_binding(
    credentials: &CredentialRegistry,
    authority_binding: &BTreeMap<String, RoleCategory>,
) -> Result<(), MessagingError> {
    if credentials.is_empty() {
        return Err(MessagingError::EmptyCredentialRegistry);
    }
    for agent_id in credentials.principals() {
        if !authority_binding.contains_key(agent_id) {
            return Err(MessagingError::UnknownAuthorityPrincipal {
                agent_id: agent_id.to_string(),
            });
        }
    }
    Ok(())
}

fn validate_registry_limits(
    credentials: &CredentialRegistry,
    limits: &MessagingLimits,
) -> Result<(), MessagingError> {
    if credentials.len() > limits.max_credentials {
        return Err(MessagingError::CredentialCapacityExceeded {
            limit: limits.max_credentials,
        });
    }
    for principal in credentials.principals() {
        validate_identifier(
            "credential agent id",
            principal,
            limits.max_identifier_bytes,
        )?;
    }
    Ok(())
}

fn collect_unique_policy<I, S, F, G>(
    channel_id: &str,
    values: I,
    limit: usize,
    max_identifier_bytes: usize,
    duplicate: F,
    too_many: G,
) -> Result<BTreeSet<String>, MessagingError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
    F: Fn(String, String) -> MessagingError,
    G: Fn(String, usize) -> MessagingError,
{
    let mut collected = BTreeSet::new();
    for value in values {
        if collected.len() >= limit {
            return Err(too_many(channel_id.to_string(), limit));
        }
        let value = value.into();
        validate_identifier("channel principal id", &value, max_identifier_bytes)?;
        if !collected.insert(value.clone()) {
            return Err(duplicate(channel_id.to_string(), value));
        }
    }
    Ok(collected)
}

fn validate_identifier(
    field: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), MessagingError> {
    if value.is_empty()
        || value != value.trim()
        || value.len() > max_bytes
        || !value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | ':')
        })
    {
        return Err(MessagingError::InvalidIdentifier { field });
    }
    Ok(())
}

fn validate_secret(secret: &str) -> Result<(), MessagingError> {
    if secret.is_empty() || secret.len() > MAX_CREDENTIAL_SECRET_BYTES {
        return Err(MessagingError::InvalidCredentialSecret);
    }
    Ok(())
}

/// Temporary derived material is zeroed on every return path. Raw credential
/// secrets are hashed directly from the bounded registry string and are never
/// copied into an aggregate buffer.
struct SensitiveBytes(Vec<u8>);

impl SensitiveBytes {
    fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    fn empty() -> Self {
        Self(Vec::new())
    }

    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }
}

impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        self.0.fill(0);
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

fn derive_store_integrity_key(
    credentials: &CredentialRegistry,
) -> Result<StoreIntegrityKey, MessagingError> {
    let mut aggregate = SensitiveBytes::new(sha256_hex(STORE_KEY_AGGREGATE_DOMAIN).into_bytes());
    for (agent_id, secret) in &credentials.credentials {
        let secret_digest = SensitiveBytes::new(sha256_hex(secret.as_bytes()).into_bytes());
        let mut credential_frame = SensitiveBytes::empty();
        append_key_part(&mut credential_frame, STORE_KEY_CREDENTIAL_DOMAIN)?;
        append_key_part(&mut credential_frame, agent_id.as_bytes())?;
        append_key_part(&mut credential_frame, secret_digest.as_slice())?;
        let credential_digest =
            SensitiveBytes::new(sha256_hex(credential_frame.as_slice()).into_bytes());

        let mut aggregate_frame = SensitiveBytes::empty();
        append_key_part(&mut aggregate_frame, STORE_KEY_AGGREGATE_DOMAIN)?;
        append_key_part(&mut aggregate_frame, aggregate.as_slice())?;
        append_key_part(&mut aggregate_frame, agent_id.as_bytes())?;
        append_key_part(&mut aggregate_frame, credential_digest.as_slice())?;
        aggregate = SensitiveBytes::new(sha256_hex(aggregate_frame.as_slice()).into_bytes());
    }

    let key = decode_sha256_hex(aggregate.as_slice())?;
    Ok(StoreIntegrityKey::new(key))
}

fn append_key_part(frame: &mut SensitiveBytes, bytes: &[u8]) -> Result<(), MessagingError> {
    let length = u64::try_from(bytes.len()).map_err(|_| MessagingError::IntegrityKeyDerivation)?;
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(bytes);
    Ok(())
}

fn decode_sha256_hex(hex: &[u8]) -> Result<[u8; 32], MessagingError> {
    if hex.len() != 64 {
        return Err(MessagingError::IntegrityKeyDerivation);
    }
    let mut output = [0_u8; 32];
    for (index, pair) in hex.chunks_exact(2).enumerate() {
        let high = decode_hex_nibble(pair[0]).ok_or(MessagingError::IntegrityKeyDerivation)?;
        let low = decode_hex_nibble(pair[1]).ok_or(MessagingError::IntegrityKeyDerivation)?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn secrets_equal(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut difference = left.len() ^ right.len();
    for index in 0..max_len {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(left_byte ^ right_byte);
    }
    difference == 0
}

fn contains_bytes_constant_time(value: &[u8], secret: &[u8]) -> bool {
    if secret.is_empty() || secret.len() > value.len() {
        return false;
    }
    let mut found = false;
    for start in 0..=value.len() - secret.len() {
        let mut difference = 0_u8;
        for (offset, secret_byte) in secret.iter().enumerate() {
            difference |= value[start + offset] ^ *secret_byte;
        }
        found |= difference == 0;
    }
    found
}

fn credential_substring_scan_work(value_len: usize, secret_len: usize) -> Option<usize> {
    let comparisons = if secret_len == 0 || secret_len > value_len {
        0
    } else {
        value_len
            .checked_sub(secret_len)?
            .checked_add(1)?
            .checked_mul(secret_len)?
    };
    // Charge one unit even when there are no candidate windows so a payload
    // with many strings and many longer credentials is still bounded.
    comparisons.checked_add(1)
}

fn charge_credential_inspection(
    work_used: &mut usize,
    additional_work: usize,
    max_work: usize,
) -> Result<(), MessagingError> {
    let next = work_used
        .checked_add(additional_work)
        .ok_or(MessagingError::PayloadCredentialInspectionLimitExceeded { max_work })?;
    if next > max_work {
        return Err(MessagingError::PayloadCredentialInspectionLimitExceeded { max_work });
    }
    *work_used = next;
    Ok(())
}

fn broker_instance_binding(
    normalized_path: &Path,
    authority: &BTreeMap<String, RoleCategory>,
) -> Result<String, MessagingError> {
    let mut material = Vec::new();
    material.extend_from_slice(BROKER_BINDING_DOMAIN);
    append_broker_binding_part(
        &mut material,
        normalized_path.as_os_str().as_encoded_bytes(),
    )?;
    let authority_count =
        u64::try_from(authority.len()).map_err(|_| MessagingError::BrokerBindingDerivation)?;
    append_broker_binding_part(&mut material, &authority_count.to_be_bytes())?;
    for (agent_id, role) in authority {
        append_broker_binding_part(&mut material, agent_id.as_bytes())?;
        append_broker_binding_part(&mut material, role.as_str().as_bytes())?;
    }
    Ok(format!("{BROKER_ID_PREFIX}-{}", sha256_hex(&material)))
}

fn append_broker_binding_part(material: &mut Vec<u8>, bytes: &[u8]) -> Result<(), MessagingError> {
    let length = u64::try_from(bytes.len()).map_err(|_| MessagingError::BrokerBindingDerivation)?;
    material.extend_from_slice(&length.to_be_bytes());
    material.extend_from_slice(bytes);
    Ok(())
}

fn message_id(
    broker_instance_id: &str,
    sequence: u64,
    limits: &MessagingLimits,
) -> Result<MessageId, MessagingError> {
    if sequence == 0 {
        return Err(MessagingError::MessageSequenceExhausted);
    }
    MessageId::new_with_limits(format!("{broker_instance_id}-{sequence:020}"), limits)
        .map_err(MessagingError::from)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    fn hierarchy() -> HierarchyLedgerSnapshot {
        let mut snapshot = HierarchyLedgerSnapshot::default();
        snapshot.effective_categories.insert(
            "coordinator".to_string(),
            RoleCategory::DelegatingCoordinator,
        );
        snapshot.effective_categories.insert(
            "worker-a".to_string(),
            RoleCategory::NonDelegatingTerminalWorker,
        );
        snapshot.effective_categories.insert(
            "worker-b".to_string(),
            RoleCategory::NonDelegatingTerminalWorker,
        );
        snapshot
            .effective_categories
            .insert("outsider".to_string(), RoleCategory::ReadOnlyResearcher);
        snapshot
    }

    fn credentials() -> (
        CredentialRegistry,
        PresentedCredential,
        PresentedCredential,
        PresentedCredential,
        PresentedCredential,
    ) {
        let mut registry = CredentialRegistry::new(8).expect("registry");
        let coordinator = registry
            .register("coordinator", "coordinator-secret")
            .expect("coordinator");
        let worker_a = registry
            .register("worker-a", "worker-a-secret")
            .expect("worker a");
        let worker_b = registry
            .register("worker-b", "worker-b-secret")
            .expect("worker b");
        let outsider = registry
            .register("outsider", "outsider-secret")
            .expect("outsider");
        (registry, coordinator, worker_a, worker_b, outsider)
    }

    fn tail_anchor_for_test(path: &Path) -> std::path::PathBuf {
        let mut anchor = path.as_os_str().to_os_string();
        anchor.push(".tail-anchor");
        anchor.into()
    }

    #[test]
    fn open_rejects_authenticated_store_transplanted_from_another_path() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let source = temporary.path().join("source.jsonl");
        let target = temporary.path().join("target.jsonl");
        let snapshot = hierarchy();
        let limits = MessagingLimits::default();
        let (registry, _, _, _, _) = credentials();
        let broker = MessagingBroker::create(&source, registry, &snapshot, limits.clone())
            .expect("create source broker");
        drop(broker);

        std::fs::copy(&source, &target).expect("transplant authenticated journal");
        std::fs::copy(tail_anchor_for_test(&source), tail_anchor_for_test(&target))
            .expect("transplant authenticated tail anchor");

        let (registry, _, _, _, _) = credentials();
        assert!(matches!(
            MessagingBroker::open(&target, registry, &snapshot, limits),
            Err(MessagingError::Store(StoreError::BrokerBindingMismatch))
        ));
    }

    #[test]
    fn broker_binding_uses_one_absolute_lexically_normalized_store_path() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let canonical = temporary.path().join("messages.jsonl");
        let lexical_alias = temporary
            .path()
            .join("component-that-need-not-exist")
            .join("..")
            .join("messages.jsonl");
        let normalized_canonical =
            absolute_normalized_store_path(&canonical).expect("normalize canonical path");
        let normalized_alias =
            absolute_normalized_store_path(&lexical_alias).expect("normalize lexical alias");
        assert_eq!(normalized_alias, normalized_canonical);

        let snapshot = hierarchy();
        assert_eq!(
            broker_instance_binding(&normalized_alias, &snapshot.effective_categories)
                .expect("alias binding"),
            broker_instance_binding(&normalized_canonical, &snapshot.effective_categories)
                .expect("canonical binding")
        );

        let limits = MessagingLimits::default();
        let (registry, _, _, _, _) = credentials();
        let broker = MessagingBroker::create(&lexical_alias, registry, &snapshot, limits.clone())
            .expect("create through lexical alias");
        drop(broker);
        let (registry, _, _, _, _) = credentials();
        MessagingBroker::open(&canonical, registry, &snapshot, limits)
            .expect("open through canonical path");
    }

    #[test]
    fn broker_binding_separates_absolute_locations_with_identical_leaf_text() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let first =
            absolute_normalized_store_path(&temporary.path().join("first").join("messages.jsonl"))
                .expect("normalize first location");
        let second =
            absolute_normalized_store_path(&temporary.path().join("second").join("messages.jsonl"))
                .expect("normalize second location");
        let snapshot = hierarchy();

        assert_ne!(
            broker_instance_binding(&first, &snapshot.effective_categories).expect("first binding"),
            broker_instance_binding(&second, &snapshot.effective_categories)
                .expect("second binding")
        );
    }

    #[test]
    fn same_path_recreation_changes_ids_and_refuses_stale_acknowledgement() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("messages.jsonl");
        let snapshot = hierarchy();
        let limits = MessagingLimits::default();
        let (registry, coordinator, _, _, _) = credentials();
        let mut first = MessagingBroker::create(&path, registry, &snapshot, limits.clone())
            .expect("create first broker");
        let first_instance = first.broker_instance_id().to_string();
        let first_message = first
            .send_direct(&coordinator, "worker-a", "first generation")
            .expect("send first-generation message");
        drop(first);

        std::fs::remove_file(&path).expect("remove first journal");
        std::fs::remove_file(tail_anchor_for_test(&path)).expect("remove first tail anchor");

        let (registry, coordinator, worker_a, _, _) = credentials();
        let mut second = MessagingBroker::create(&path, registry, &snapshot, limits)
            .expect("recreate broker at same path");
        let second_message = second
            .send_direct(&coordinator, "worker-a", "second generation")
            .expect("send second-generation message");
        second
            .receive_message(&worker_a, &second_message.id)
            .expect("deliver second-generation message")
            .expect("message is pending");

        assert_ne!(second.broker_instance_id(), first_instance);
        assert_ne!(second_message.id, first_message.id);
        assert!(matches!(
            second.acknowledge(&worker_a, &first_message.id),
            Err(MessagingError::UnknownMessage { message_id }) if message_id == first_message.id
        ));
        assert!(second
            .receive_message(&worker_a, &second_message.id)
            .expect("stale acknowledgement did not alter the new message")
            .is_some());
    }

    #[test]
    fn credential_debug_is_redacted_and_authentication_errors_are_distinct() {
        let mut registry = CredentialRegistry::new(2).expect("registry");
        let credential = registry
            .register("worker-a", "a-secret-that-must-not-leak")
            .expect("credential");
        assert!(!format!("{credential:?}").contains("a-secret-that-must-not-leak"));
        assert!(!format!("{registry:?}").contains("a-secret-that-must-not-leak"));

        let unknown = PresentedCredential::new("unknown", "secret").expect("unknown");
        assert!(matches!(
            registry.authenticate(&unknown),
            Err(MessagingError::UnknownCredential { .. })
        ));
        let bad = PresentedCredential::new("worker-a", "bad").expect("bad");
        assert!(matches!(
            registry.authenticate(&bad),
            Err(MessagingError::BadCredential { .. })
        ));

        let reuse = registry
            .register("worker-b", "a-secret-that-must-not-leak")
            .expect_err("one secret cannot alias two principals");
        assert!(matches!(
            &reuse,
            MessagingError::CredentialSecretReuse { .. }
        ));
        assert!(!reuse.to_string().contains("a-secret-that-must-not-leak"));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn store_integrity_key_is_order_stable_secret_bound_and_not_persisted() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("messages.jsonl");
        let snapshot = hierarchy();
        let limits = MessagingLimits::default();

        let mut reverse_registry = CredentialRegistry::new(8).expect("registry");
        reverse_registry
            .register("outsider", "outsider-secret")
            .expect("outsider");
        reverse_registry
            .register("worker-b", "worker-b-secret")
            .expect("worker b");
        reverse_registry
            .register("worker-a", "worker-a-secret")
            .expect("worker a");
        let reverse_coordinator = reverse_registry
            .register("coordinator", "coordinator-secret")
            .expect("coordinator");
        let mut broker =
            MessagingBroker::create(&path, reverse_registry, &snapshot, limits.clone())
                .expect("create broker");
        broker
            .send_direct(
                &reverse_coordinator,
                "worker-a",
                "credential-free durable payload",
            )
            .expect("send durable envelope");
        drop(broker);

        let durable_bytes = std::fs::read(&path).expect("read journal");
        for secret in [
            b"coordinator-secret".as_slice(),
            b"worker-a-secret".as_slice(),
            b"worker-b-secret".as_slice(),
            b"outsider-secret".as_slice(),
        ] {
            assert!(!durable_bytes
                .windows(secret.len())
                .any(|window| window == secret));
        }

        let (registry, _, _, _, _) = credentials();
        let reopened = MessagingBroker::open(&path, registry, &snapshot, limits.clone())
            .expect("BTree principal order makes derivation stable");
        drop(reopened);

        let mut wrong_registry = CredentialRegistry::new(8).expect("registry");
        wrong_registry
            .register("coordinator", "wrong-coordinator-secret")
            .expect("coordinator");
        wrong_registry
            .register("worker-a", "worker-a-secret")
            .expect("worker a");
        wrong_registry
            .register("worker-b", "worker-b-secret")
            .expect("worker b");
        wrong_registry
            .register("outsider", "outsider-secret")
            .expect("outsider");
        assert!(matches!(
            MessagingBroker::open(&path, wrong_registry, &snapshot, limits),
            Err(MessagingError::Store(_))
        ));
    }

    #[test]
    fn direct_delivery_is_at_least_once_and_ack_survives_reopen() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("messages.jsonl");
        let snapshot = hierarchy();
        let limits = MessagingLimits::default();
        let (registry, coordinator, worker_a, _, _) = credentials();
        let mut broker = MessagingBroker::create(&path, registry, &snapshot, limits.clone())
            .expect("create broker");
        let sent = broker
            .send_direct(&coordinator, "worker-a", "do the bounded task")
            .expect("send");
        assert_eq!(sent.sender_role, RoleCategory::DelegatingCoordinator);

        let first = broker
            .receive_next(&worker_a)
            .expect("receive")
            .expect("message");
        let second = broker
            .receive_next(&worker_a)
            .expect("redelivery")
            .expect("message");
        assert_eq!(first.id, second.id);
        assert_eq!(second.recipients["worker-a"].delivery_attempts, 2);
        assert_eq!(
            broker.acknowledge(&worker_a, &sent.id).expect("ack"),
            AcknowledgementOutcome::Acknowledged
        );
        assert_eq!(
            broker.acknowledge(&worker_a, &sent.id).expect("repeat ack"),
            AcknowledgementOutcome::AlreadyAcknowledged
        );
        drop(broker);

        let (registry, _, worker_a, _, _) = credentials();
        let mut reopened =
            MessagingBroker::open(&path, registry, &snapshot, limits).expect("reopen broker");
        assert!(reopened
            .receive_next(&worker_a)
            .expect("receive after reopen")
            .is_none());
        assert_eq!(
            reopened
                .message_for_test(&sent.id)
                .expect("durable message")
                .recipients["worker-a"]
                .delivery_attempts,
            2
        );
    }

    #[test]
    fn governed_channel_fans_out_exactly_to_members() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("messages.jsonl");
        let snapshot = hierarchy();
        let (registry, coordinator, worker_a, worker_b, outsider) = credentials();
        let mut broker =
            MessagingBroker::create(&path, registry, &snapshot, MessagingLimits::default())
                .expect("create broker");
        broker
            .create_channel(
                &coordinator,
                "team",
                ["coordinator", "worker-a", "worker-b"],
                ["coordinator"],
            )
            .expect("channel");
        let sent = broker
            .publish_channel(&coordinator, "team", "broadcast")
            .expect("publish");
        assert_eq!(
            sent.recipients.keys().cloned().collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "coordinator".to_string(),
                "worker-a".to_string(),
                "worker-b".to_string()
            ])
        );
        let before_refusal = std::fs::metadata(&path).expect("journal metadata").len();
        assert!(matches!(
            broker.receive_message(&outsider, &sent.id),
            Err(MessagingError::NonMemberDelivery { .. })
        ));
        assert_eq!(
            std::fs::metadata(&path).expect("journal metadata").len(),
            before_refusal
        );
        assert!(broker
            .receive_next(&worker_a)
            .expect("worker receive")
            .is_some());
        assert!(matches!(
            broker.receive_next_from_channel(&outsider, "team"),
            Err(MessagingError::NonMemberDelivery { .. })
        ));
        assert!(matches!(
            broker.publish_channel(&outsider, "team", "not a member"),
            Err(MessagingError::NonMemberChannelOperation { .. })
        ));
        assert!(matches!(
            broker.publish_channel(&worker_b, "team", "not allowed"),
            Err(MessagingError::UnauthorizedBroadcastPublication { .. })
        ));
    }

    #[test]
    fn caller_cannot_claim_a_more_powerful_sender_role() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let snapshot = hierarchy();
        let (registry, _, worker_a, worker_b, _) = credentials();
        let mut broker = MessagingBroker::create(
            temporary.path().join("messages.jsonl"),
            registry,
            &snapshot,
            MessagingLimits::default(),
        )
        .expect("create broker");
        let sent = broker
            .send_direct(&worker_a, worker_b.agent_id(), "work")
            .expect("send");
        assert_eq!(sent.sender_role, RoleCategory::NonDelegatingTerminalWorker);
    }

    #[test]
    fn exact_direct_receive_refuses_non_recipient_without_append() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("messages.jsonl");
        let snapshot = hierarchy();
        let (registry, coordinator, worker_a, _, outsider) = credentials();
        let mut broker =
            MessagingBroker::create(&path, registry, &snapshot, MessagingLimits::default())
                .expect("create broker");
        let sent = broker
            .send_direct(&coordinator, "worker-a", "direct")
            .expect("send");

        let before_refusal = std::fs::metadata(&path).expect("journal metadata").len();
        assert!(matches!(
            broker.receive_message(&outsider, &sent.id),
            Err(MessagingError::NonRecipientDelivery { .. })
        ));
        assert_eq!(
            std::fs::metadata(&path).expect("journal metadata").len(),
            before_refusal
        );

        let delivered = broker
            .receive_message(&worker_a, &sent.id)
            .expect("receive exact message")
            .expect("unacknowledged delivery");
        assert_eq!(delivered.recipients["worker-a"].delivery_attempts, 1);
        broker
            .acknowledge(&worker_a, &sent.id)
            .expect("acknowledge exact message");
        let before_acknowledged_receive = std::fs::metadata(&path).expect("journal metadata").len();
        assert!(broker
            .receive_message(&worker_a, &sent.id)
            .expect("acknowledged receive")
            .is_none());
        assert_eq!(
            std::fs::metadata(&path).expect("journal metadata").len(),
            before_acknowledged_receive
        );
    }

    #[test]
    fn channel_policy_iterators_stop_at_their_configured_bound() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("messages.jsonl");
        let snapshot = hierarchy();
        let (registry, coordinator, _, _, _) = credentials();
        let limits = MessagingLimits {
            max_members_per_channel: 2,
            max_publishers_per_channel: 1,
            ..MessagingLimits::default()
        };
        let mut broker =
            MessagingBroker::create(&path, registry, &snapshot, limits).expect("create broker");
        let initial_bytes = std::fs::metadata(&path).expect("journal metadata").len();

        let member_pulls = Cell::new(0_usize);
        let members = std::iter::from_fn(|| {
            let index = member_pulls.get();
            member_pulls.set(index + 1);
            Some(match index {
                0 => "coordinator".to_string(),
                1 => "worker-a".to_string(),
                _ => format!("unbounded-member-{index}"),
            })
        });
        assert!(matches!(
            broker.create_channel(&coordinator, "too-many-members", members, ["coordinator"]),
            Err(MessagingError::TooManyChannelMembers { limit: 2, .. })
        ));
        assert_eq!(member_pulls.get(), 3);
        assert_eq!(
            std::fs::metadata(&path).expect("journal metadata").len(),
            initial_bytes
        );

        let publisher_pulls = Cell::new(0_usize);
        let publishers = std::iter::from_fn(|| {
            let index = publisher_pulls.get();
            publisher_pulls.set(index + 1);
            Some(if index == 0 {
                "coordinator".to_string()
            } else {
                "worker-a".to_string()
            })
        });
        assert!(matches!(
            broker.create_channel(
                &coordinator,
                "too-many-publishers",
                ["coordinator", "worker-a"],
                publishers
            ),
            Err(MessagingError::TooManyChannelPublishers { limit: 1, .. })
        ));
        assert_eq!(publisher_pulls.get(), 2);
        assert_eq!(
            std::fs::metadata(&path).expect("journal metadata").len(),
            initial_bytes
        );
    }

    #[test]
    fn replay_validation_requires_recipient_addressability() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let snapshot = hierarchy();
        let (registry, coordinator, _, _, _) = credentials();
        let mut broker = MessagingBroker::create(
            temporary.path().join("messages.jsonl"),
            registry,
            &snapshot,
            MessagingLimits::default(),
        )
        .expect("create broker");
        let channel = broker
            .create_channel(
                &coordinator,
                "team",
                ["coordinator", "worker-a"],
                ["coordinator"],
            )
            .expect("channel");
        let direct = broker
            .send_direct(&coordinator, "worker-a", "direct")
            .expect("direct message");

        broker.credentials.credentials.remove("worker-a");
        assert!(matches!(
            broker.validate_replayed_channel(&channel),
            Err(MessagingError::InconsistentState { .. })
        ));
        assert!(matches!(
            broker.validate_replayed_message(&direct),
            Err(MessagingError::InconsistentState { .. })
        ));
    }

    #[test]
    fn identifiers_match_ledger_alphabet_and_configured_byte_limit() {
        assert!(PresentedCredential::new("worker:one", "secret").is_ok());
        assert!(matches!(
            PresentedCredential::new("worker/one", "secret"),
            Err(MessagingError::InvalidIdentifier { .. })
        ));
        assert!(matches!(
            PresentedCredential::new("wørker", "secret"),
            Err(MessagingError::InvalidIdentifier { .. })
        ));

        let temporary = tempfile::tempdir().expect("temporary directory");
        let mut snapshot = HierarchyLedgerSnapshot::default();
        snapshot
            .effective_categories
            .insert("a".to_string(), RoleCategory::DelegatingCoordinator);
        snapshot
            .effective_categories
            .insert("b".to_string(), RoleCategory::NonDelegatingTerminalWorker);
        let mut registry = CredentialRegistry::new(2).expect("registry");
        let a = registry.register("a", "secret-a").expect("principal a");
        registry.register("b", "secret-b").expect("principal b");
        let limits = MessagingLimits {
            max_identifier_bytes: 1,
            ..MessagingLimits::default()
        };
        let mut broker = MessagingBroker::create(
            temporary.path().join("messages.jsonl"),
            registry,
            &snapshot,
            limits,
        )
        .expect("create broker");
        assert!(matches!(
            broker.send_direct(&a, "bb", "payload"),
            Err(MessagingError::InvalidIdentifier { .. })
        ));
    }

    #[test]
    fn credential_inspection_budget_has_an_exact_fail_closed_boundary() {
        let mut registry = CredentialRegistry::new(1).expect("registry");
        registry.register("worker", "abc").expect("credential");
        let payload = Value::String("xxxxx".to_string());
        let exact_work = credential_substring_scan_work(5, 3).expect("bounded work");
        assert_eq!(exact_work, 10);
        assert!(matches!(
            registry.payload_contains_registered_secret_with_budget(&payload, exact_work),
            Ok(false)
        ));
        assert!(matches!(
            registry.payload_contains_registered_secret_with_budget(&payload, exact_work - 1),
            Err(MessagingError::PayloadCredentialInspectionLimitExceeded { max_work })
                if max_work == exact_work - 1
        ));
    }

    #[test]
    fn credential_inspection_covers_nested_object_keys_and_string_values() {
        let mut registry = CredentialRegistry::new(1).expect("registry");
        registry
            .register("worker", "registered-secret")
            .expect("credential");
        let key_payload = serde_json::json!({
            "outer": [{"prefix-registered-secret-suffix": null}]
        });
        let value_payload = serde_json::json!({
            "outer": [{"value": "prefix-registered-secret-suffix"}]
        });
        assert!(matches!(
            registry.payload_contains_registered_secret(&key_payload),
            Ok(true)
        ));
        assert!(matches!(
            registry.payload_contains_registered_secret(&value_payload),
            Ok(true)
        ));
    }

    #[test]
    fn over_budget_credential_inspection_is_typed_and_append_free() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("messages.jsonl");
        let mut snapshot = HierarchyLedgerSnapshot::default();
        snapshot
            .effective_categories
            .insert("a".to_string(), RoleCategory::DelegatingCoordinator);
        snapshot
            .effective_categories
            .insert("b".to_string(), RoleCategory::NonDelegatingTerminalWorker);
        let mut registry = CredentialRegistry::new(2).expect("registry");
        let sender = registry
            .register("a", "a".repeat(256))
            .expect("sender credential");
        registry
            .register("b", "b".repeat(256))
            .expect("recipient credential");
        let limits = MessagingLimits {
            max_payload_bytes: 512 * 1024,
            ..MessagingLimits::default()
        };
        let mut broker =
            MessagingBroker::create(&path, registry, &snapshot, limits).expect("create broker");
        let before = std::fs::read(&path).expect("journal before refusal");

        let error = broker
            .send_direct(&sender, "b", "x".repeat(300_000))
            .expect_err("pathological scan work must be refused before append");
        assert!(matches!(
            error,
            MessagingError::PayloadCredentialInspectionLimitExceeded {
                max_work: MAX_CREDENTIAL_INSPECTION_WORK
            }
        ));
        assert_eq!(std::fs::read(&path).expect("journal after refusal"), before);
    }

    #[test]
    fn delivery_exhaustion_and_oversized_payload_are_explicit_and_append_free() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("messages.jsonl");
        let snapshot = hierarchy();
        let (registry, coordinator, worker_a, _, _) = credentials();
        let limits = MessagingLimits {
            max_delivery_attempts: 1,
            max_payload_bytes: 8,
            ..MessagingLimits::default()
        };
        let mut broker =
            MessagingBroker::create(&path, registry, &snapshot, limits).expect("create broker");
        let sent = broker
            .send_direct(&coordinator, "worker-a", "ok")
            .expect("send bounded payload");
        broker
            .receive_message(&worker_a, &sent.id)
            .expect("first delivery")
            .expect("pending message");

        let before_exhaustion = std::fs::metadata(&path).expect("journal metadata").len();
        assert!(matches!(
            broker.receive_message(&worker_a, &sent.id),
            Err(MessagingError::DeliveryAttemptLimitExceeded { .. })
        ));
        assert_eq!(
            std::fs::metadata(&path).expect("journal metadata").len(),
            before_exhaustion
        );
        assert_eq!(
            broker
                .message_for_test(&sent.id)
                .expect("message state")
                .recipients["worker-a"]
                .delivery_attempts,
            1
        );

        let before_payload_refusal = std::fs::metadata(&path).expect("journal metadata").len();
        assert!(matches!(
            broker.send_direct(&coordinator, "worker-a", "payload-too-large"),
            Err(MessagingError::Envelope(
                EnvelopeValidationError::PayloadTooLarge { .. }
            ))
        ));
        assert_eq!(
            std::fs::metadata(&path).expect("journal metadata").len(),
            before_payload_refusal
        );
    }

    #[test]
    fn reopened_exhaustion_identifies_message_for_acknowledgement_and_unblocks_order() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("messages.jsonl");
        let snapshot = hierarchy();
        let (registry, coordinator, worker_a, _, _) = credentials();
        let limits = MessagingLimits {
            max_delivery_attempts: 1,
            ..MessagingLimits::default()
        };
        let mut broker = MessagingBroker::create(&path, registry, &snapshot, limits.clone())
            .expect("create broker");
        let first = broker
            .send_direct(&coordinator, "worker-a", "first")
            .expect("send first");
        let second = broker
            .send_direct(&coordinator, "worker-a", "second")
            .expect("send second");
        let delivered = broker
            .receive_next(&worker_a)
            .expect("deliver first")
            .expect("first pending message");
        assert_eq!(delivered.id, first.id);
        drop(broker);

        let (registry, _, worker_a, _, _) = credentials();
        let mut reopened = MessagingBroker::open(&path, registry, &snapshot, limits)
            .expect("reopen broker after lost delivery return");
        let before_exhaustion = std::fs::read(&path).expect("journal before exhaustion");
        let error = reopened
            .receive_next(&worker_a)
            .expect_err("oldest message is durably exhausted");
        let exhausted_id = match error {
            MessagingError::DeliveryAttemptLimitExceeded {
                message_id,
                recipient_id,
            } => {
                assert_eq!(message_id, first.id);
                assert_eq!(recipient_id, "worker-a");
                message_id
            }
            other => panic!("unexpected receive error: {other:?}"),
        };
        assert_eq!(
            std::fs::read(&path).expect("journal after exhaustion"),
            before_exhaustion
        );

        assert_eq!(
            reopened
                .acknowledge(&worker_a, &exhausted_id)
                .expect("acknowledge exhausted message"),
            AcknowledgementOutcome::Acknowledged
        );
        let next = reopened
            .receive_next(&worker_a)
            .expect("receive after acknowledgement")
            .expect("second pending message");
        assert_eq!(next.id, second.id);
    }

    #[test]
    fn nested_payload_credential_secret_is_typed_redacted_and_append_free() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("messages.jsonl");
        let snapshot = hierarchy();
        let (registry, coordinator, _, _, _) = credentials();
        let mut broker =
            MessagingBroker::create(&path, registry, &snapshot, MessagingLimits::default())
                .expect("create broker");
        let credential_secret = "worker-a-secret";
        let mut secret_bearing_object = serde_json::Map::new();
        secret_bearing_object.insert(
            format!("key-prefix-{credential_secret}-suffix"),
            serde_json::json!({
                "nested": [
                    {"value": format!("value-prefix-{credential_secret}-suffix")}
                ]
            }),
        );
        let payload = serde_json::json!({
            "outer": [Value::Object(secret_bearing_object)]
        });
        let before_refusal = std::fs::read(&path).expect("journal before payload refusal");

        let error = broker
            .send_direct(&coordinator, "worker-a", payload)
            .expect_err("registered credential material must be refused");
        assert!(matches!(
            &error,
            MessagingError::PayloadContainsCredentialSecret
        ));
        assert!(!format!("{error:?}").contains(credential_secret));
        assert!(!error.to_string().contains(credential_secret));
        assert_eq!(
            std::fs::read(&path).expect("journal after payload refusal"),
            before_refusal
        );
    }
}
